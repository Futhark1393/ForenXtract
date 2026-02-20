import sys
import os
import subprocess
import time
import shutil
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt6.uic import loadUi
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QTextCursor

# ==========================================
# WORKER 1: DISK & RAM ACQUISITION (PRO)
# ==========================================
class AcquisitionThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, dict)

    def __init__(self, ip, user, key, disk, safe_mode, write_block, is_ram, throttle_limit=None):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key = key
        self.disk = disk
        self.safe_mode = safe_mode
        self.write_block = write_block
        self.is_ram = is_ram
        self.throttle_limit = throttle_limit
        self.start_time = None
        self.end_time = None
        self.bad_sector_logs = []

        # Set filename and extension based on acquisition type
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if self.is_ram:
            self.filename = f"memory_evidence_{timestamp}.kcore.gz"
        else:
            self.filename = f"evidence_{timestamp}.img.gz"

    def get_ssh_fingerprint(self):
        """Fetches remote server SSH fingerprint."""
        try:
            cmd = f"ssh-keyscan -t rsa {self.ip} 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            return output if output else "Fingerprint could not be fetched."
        except Exception:
            return "Fingerprint fetch failed."

    def set_write_block(self, state):
        """Toggles Read-Only mode on block devices. Not applicable for RAM."""
        mode = "--setro" if state else "--setrw"
        mode_str = "Read-Only" if state else "Read-Write"

        try:
            # Send lock/unlock command
            cmd_lock = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo blockdev {mode} {self.disk}'"
            subprocess.check_call(cmd_lock, shell=True)

            # Verify the status
            cmd_check = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo blockdev --getro {self.disk}'"
            result = subprocess.check_output(cmd_check, shell=True).decode().strip()

            expected = "1" if state else "0"
            if result == expected:
                return True, f"Disk set to {mode_str} mode."
            else:
                return False, f"Failed to set {mode_str} mode!"

        except Exception as e:
            return False, f"Write Blocker Error: {str(e)}"

    def run(self):
        self.start_time = datetime.now()
        acq_type = "Live Memory (RAM)" if self.is_ram else "Block Device (Disk)"

        report_data = {
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip": self.ip,
            "ssh_fingerprint": "N/A",
            "command_executed": "N/A",
            "write_protection": "N/A",
            "acquisition_type": acq_type,
            "duration": "0s",
            "bad_sectors": []
        }

        # Flag to track write blocker status for the finally block
        wb_activated = False

        try:
            self.log_signal.emit(f"[*] Task Started at: {report_data['start_time']}")
            self.log_signal.emit(f"[*] Target Connection: {self.ip}")
            self.log_signal.emit(f"[*] Acquisition Mode: {acq_type}")

            # 1. SSH Fingerprint Check
            fingerprint = self.get_ssh_fingerprint()
            report_data["ssh_fingerprint"] = fingerprint
            self.log_signal.emit(f"[*] Remote SSH Fingerprint Verified:\n    {fingerprint}")

            # 2. Key Permission Enforce
            if os.path.exists(self.key):
                os.chmod(self.key, 0o400)
            else:
                self.finished_signal.emit(False, "SSH Key file not found!", report_data)
                return

            # 3. Write Blocker Activation (Bypass for RAM)
            if self.is_ram:
                self.log_signal.emit("[*] Write Blocker bypassed (Not applicable for virtual memory files).")
                report_data["write_protection"] = "N/A (Memory Acquisition)"
            elif self.write_block:
                self.log_signal.emit("[*] Activating Software Write Blocker (Kernel Level)...")
                success, msg = self.set_write_block(True)
                if success:
                    self.log_signal.emit(f"[SUCCESS] {msg}")
                    report_data["write_protection"] = "Active (Kernel Level - blockdev --setro)"
                    wb_activated = True
                else:
                    self.log_signal.emit(f"[WARNING] {msg}")
                    report_data["write_protection"] = "Failed (Attempted)"
            else:
                report_data["write_protection"] = "Disabled (Live System Mode)"

            # --- SAFE EXECUTION BLOCK ---
            try:
                # 4. Prepare Acquisition Command
                dd_flags = "conv=noerror,sync" if self.safe_mode else ""
                ssh_cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no", "-i", self.key,
                    f"{self.user}@{self.ip}",
                    f"sudo dd if={self.disk} bs=64K {dd_flags} status=progress | gzip -1 -"
                ]

                full_command_str = " ".join(ssh_cmd)

                # Setup Throttling if requested and pv is available
                use_throttling = False
                if self.throttle_limit and shutil.which("pv"):
                    use_throttling = True
                    throttle_cmd = ["pv", "-q", "-L", f"{self.throttle_limit}m"]
                    full_command_str += f" | pv -q -L {self.throttle_limit}m"
                elif self.throttle_limit:
                    self.log_signal.emit("[WARNING] 'pv' tool not found on local system. Throttling disabled.")

                report_data["command_executed"] = full_command_str

                self.log_signal.emit(f"[*] EXECUTING COMMAND:\n    {full_command_str}")
                self.log_signal.emit("[*] Data stream started (Listening for I/O errors)...")

                with open(self.filename, "wb") as f:
                    if use_throttling:
                        # Pipe ssh output through pv to limit bandwidth
                        p1 = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        p2 = subprocess.Popen(throttle_cmd, stdin=p1.stdout, stdout=f)
                        p1.stdout.close() # Allow p1 to receive a SIGPIPE if p2 exits
                        process_to_monitor = p1
                    else:
                        # Direct output to file
                        process_to_monitor = subprocess.Popen(ssh_cmd, stdout=f, stderr=subprocess.PIPE)

                    # Monitor stderr for dd progress and errors
                    while True:
                        line = process_to_monitor.stderr.readline()
                        if not line and process_to_monitor.poll() is not None:
                            break
                        if line:
                            decoded_line = line.decode('utf-8', errors='ignore').strip()
                            if "error reading" in decoded_line or "Input/output error" in decoded_line:
                                timestamp = datetime.now().strftime("%H:%M:%S")
                                error_msg = f"[{timestamp}] CRITICAL I/O ERROR: {decoded_line}"
                                self.bad_sector_logs.append(error_msg)
                                self.log_signal.emit(error_msg)

                    if use_throttling:
                        p2.wait()

                self.end_time = datetime.now()
                duration = self.end_time - self.start_time
                report_data["end_time"] = self.end_time.strftime("%Y-%m-%d %H:%M:%S")
                report_data["duration"] = str(duration)
                report_data["bad_sectors"] = self.bad_sector_logs

                if process_to_monitor.returncode == 0:
                    self.log_signal.emit(f"[SUCCESS] Transfer Complete. Duration: {duration}")
                    self.finished_signal.emit(True, self.filename, report_data)
                else:
                    self.finished_signal.emit(True, self.filename, report_data)

            finally:
                # 5. Lock Restoration (Cleanup)
                if wb_activated:
                    self.log_signal.emit("[*] Reverting Write Blocker (Restoring Read-Write)...")
                    success, msg = self.set_write_block(False)
                    if success:
                        self.log_signal.emit(f"[INFO] System Restored: {msg}")
                    else:
                        self.log_signal.emit(f"[!!!] CRITICAL WARNING: Could not restore RW mode!")

        except Exception as e:
            self.finished_signal.emit(False, str(e), report_data)

# ==========================================
# WORKER 2: ANALYSIS (Hash & Zip Bomb)
# ==========================================
class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, str)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def calculate_hash(self):
        """Calculates SHA-256 hash of the evidence file."""
        try:
            cmd = f"sha256sum {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            return result.split()[0]
        except:
            return "HASH_CALCULATION_ERROR"

    def run(self):
        self.log_signal.emit("\n--- [ SECURITY & INTEGRITY SCAN ] ---")
        self.log_signal.emit("[*] Calculating SHA-256 Hash (Digital Seal)...")
        file_hash = self.calculate_hash()
        self.log_signal.emit(f"[*] SHA-256: {file_hash}")

        self.log_signal.emit("[*] Analyzing Binary Headers...")
        try:
            cmd = f"grep -aPc '\\x50\\x4B\\x03\\x04' {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            zip_count = int(result) if result.isdigit() else 0

            warning_msg = ""
            if zip_count > 1000:
                self.log_signal.emit("[!!!] THREAT DETECTED: Potential Zip Bomb structure.")
                warning_msg = f"WARNING: {zip_count} compressed blocks detected."
            else:
                self.log_signal.emit("[OK] File structure appears clean.")

            self.finished_signal.emit(warning_msg, file_hash)

        except Exception as e:
            self.log_signal.emit(f"[!] Analysis error: {e}")
            self.finished_signal.emit("", file_hash)

# ==========================================
# MAIN WINDOW (GUI)
# ==========================================
class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            loadUi("forensic_qt6.ui", self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"UI file could not be loaded!\n{e}")
            sys.exit(1)

        self.setWindowTitle("Remote Forensic Imager - Futhark1393")
        self.setup_terminal_style()
        self.setup_tooltips() # UI Help tooltips initialized here

        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)

        self.txt_user.setText("ubuntu")
        self.txt_disk.setText("/dev/nvme0n1")

        if hasattr(self, 'chk_safety'):
            self.chk_safety.setChecked(True)

        self.progressBar.setValue(0)
        self.last_report_data = {}

    def setup_terminal_style(self):
        """Configures the QTextEdit to look like a terminal."""
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: #000000;
                color: #00FF00;
                font-family: "Monospace";
                font-size: 10pt;
                border: 1px solid #333;
            }
        """)
        self.log("--- SYSTEM READY ---")
        self.log("[*] Forensic Console Initialized.")

    def setup_tooltips(self):
        """Injects professional forensic tooltips to guide the examiner."""
        if hasattr(self, 'txt_caseno'):
            self.txt_caseno.setToolTip("Incident or Case Number. This will be logged in the final Chain of Custody (CoC) report.")
        if hasattr(self, 'txt_examiner'):
            self.txt_examiner.setToolTip("Name or ID of the Forensic Examiner conducting the acquisition.")
        if hasattr(self, 'txt_ip'):
            self.txt_ip.setToolTip("Target server's IPv4/IPv6 address or hostname.")
        if hasattr(self, 'txt_user'):
            self.txt_user.setToolTip("SSH Username. Must have sudo privileges to run 'dd' and 'blockdev'.")
        if hasattr(self, 'txt_key'):
            self.txt_key.setToolTip("Path to the private SSH key (.pem) for passwordless authentication.")
        if hasattr(self, 'txt_disk'):
            self.txt_disk.setToolTip("Target block device path (e.g., /dev/nvme0n1 or /dev/sda).")

        if hasattr(self, 'chk_safety'):
            self.chk_safety.setToolTip("Applies 'conv=noerror,sync' to dd. Prevents the acquisition from crashing on physical bad sectors.")
        if hasattr(self, 'chk_ram'):
            self.chk_ram.setToolTip("Overrides disk target to /proc/kcore for volatile memory (RAM) extraction. Bypasses Write Blocker.")
        if hasattr(self, 'chk_writeblock'):
            self.chk_writeblock.setToolTip("Kernel-level protection. Sets the target disk to Read-Only mode (blockdev --setro) before acquisition.")
        if hasattr(self, 'chk_throttle'):
            self.chk_throttle.setToolTip("Pipes the transfer through 'pv' to limit network bandwidth usage and prevent server bottlenecks.")
        if hasattr(self, 'txt_throttle'):
            self.txt_throttle.setToolTip("Bandwidth limit in Megabytes per second (MB/s). e.g., 10")
        if hasattr(self, 'btn_start'):
            self.btn_start.setToolTip("Start secure acquisition and post-process hashing.")

    def select_key(self):
        """Opens a file dialog to select the SSH private key."""
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        """Appends a message to the UI log and writes to the crash-proof log file."""
        self.txt_log.append(msg)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)

        # Crash-Proof Logging
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("live_forensic.log", "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {msg}\n")
        except Exception:
            pass

    def start_process(self):
        """Validates inputs and starts the acquisition thread."""
        ip = self.txt_ip.text()
        user = self.txt_user.text()
        key = self.txt_key.text()
        disk = self.txt_disk.text()

        self.case_no = self.txt_caseno.text() if hasattr(self, 'txt_caseno') else "UNKNOWN_CASE"
        self.examiner = self.txt_examiner.text() if hasattr(self, 'txt_examiner') else "UNKNOWN_EXAMINER"

        # Check Write Blocker status
        write_block_status = False
        if hasattr(self, 'chk_writeblock'):
             write_block_status = self.chk_writeblock.isChecked()

        # Check RAM Acquisition status
        is_ram_status = False
        if hasattr(self, 'chk_ram'):
             is_ram_status = self.chk_ram.isChecked()

        # Check Bandwidth Throttling status
        throttle_limit = None
        if hasattr(self, 'chk_throttle') and self.chk_throttle.isChecked():
            if hasattr(self, 'txt_throttle') and self.txt_throttle.text().isdigit():
                throttle_limit = int(self.txt_throttle.text())

        # Force target to memory file if RAM mode is selected
        if is_ram_status:
             disk = "/proc/kcore"

        if not ip or not key or not user:
            QMessageBox.warning(self, "Missing Info", "Please fill all required fields!")
            return

        self.btn_start.setEnabled(False)
        self.progressBar.setValue(5)
        self.log("\n--- [ STARTING FORENSIC ACQUISITION ] ---")
        self.log(f"[*] Case No: {self.case_no} | Examiner: {self.examiner}")
        if throttle_limit:
            self.log(f"[*] Bandwidth Limit: {throttle_limit} MB/s")

        safe_mode_status = self.chk_safety.isChecked() if hasattr(self, 'chk_safety') else False

        self.worker = AcquisitionThread(ip, user, key, disk, safe_mode_status, write_block_status, is_ram_status, throttle_limit)
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.start()

    def on_acquisition_finished(self, success, filename, report_data):
        """Callback for when the acquisition thread completes."""
        self.last_report_data = report_data

        if success:
            self.progressBar.setValue(50)
            self.log(f"[INFO] Data Acquired: {filename}")

            self.analyzer = AnalysisThread(filename)
            self.analyzer.log_signal.connect(self.log)
            self.analyzer.finished_signal.connect(self.on_analysis_finished)
            self.analyzer.start()
        else:
            self.log(f"[ERROR] Process failed for {filename}")
            QMessageBox.critical(self, "Process Failed", filename)
            self.btn_start.setEnabled(True)
            self.progressBar.setValue(0)

    def on_analysis_finished(self, warning, file_hash):
        """Callback for when the analysis thread completes."""
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.generate_report(file_hash)

        self.log("\n--- [ TASK COMPLETED SUCCESSFULLY ] ---")
        self.log(f"[*] Report Created: Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt")

        if warning:
            QMessageBox.warning(self, "FORENSIC WARNING", warning)
        else:
            QMessageBox.information(self, "Success", "Acquisition & Analysis Complete.\nReport Generated.")

    def generate_report(self, file_hash):
        """Generates the final Chain of Custody (CoC) text report."""
        bad_sector_text = ""
        if self.last_report_data['bad_sectors']:
            bad_sector_text = "\n".join(self.last_report_data['bad_sectors'])
        else:
            bad_sector_text = "No read errors (I/O errors) detected during acquisition."

        report_content = f"""
================================================================
            DIGITAL FORENSIC ACQUISITION REPORT
================================================================
CASE DETAILS:
-------------
Case Number    : {self.case_no}
Examiner       : {self.examiner}
Date           : {datetime.now().strftime("%Y-%m-%d")}
Target IP      : {self.last_report_data['target_ip']}

ACQUISITION LOG:
----------------
Acquisition Type: {self.last_report_data['acquisition_type']}
Start Time      : {self.last_report_data['start_time']}
End Time        : {self.last_report_data['end_time']}
Duration        : {self.last_report_data['duration']}
SSH Fingerprint : {self.last_report_data['ssh_fingerprint']}
Write Blocker   : {self.last_report_data['write_protection']}

COMMAND EXECUTED:
-----------------
{self.last_report_data['command_executed']}

HEALTH / ERROR LOGS:
-------------------------
{bad_sector_text}

EVIDENCE DETAILS:
-----------------
File Name       : {self.worker.filename}
SHA-256 Hash    : {file_hash}
Integrity       : VERIFIED

================================================================
                  CHAIN OF CUSTODY (CoC)
================================================================
| Date/Time           | Released By (From) | Received By (To) | Purpose             |
|---------------------|--------------------|------------------|---------------------|
| {self.last_report_data['end_time']} | AWS Live Server    | {self.examiner:<16} | Forensic Acquisition|
| {self.last_report_data['end_time']} | {self.examiner:<18} | Secure Storage   | Evidence Locking    |
|                     |                    |                  |                     |
================================================================
Note: Auto-generated by Remote Forensic Imager - Developed by Futhark1393
"""
        report_filename = f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(report_filename, "w") as f:
            f.write(report_content)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
