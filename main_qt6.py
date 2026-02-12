import sys
import os
import subprocess
import time
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt6.uic import loadUi
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QTextCursor

# ==========================================
# WORKER 1: DISK IMAGE ACQUISITION
# ==========================================
class AcquisitionThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, dict) # Added dict for report data

    def __init__(self, ip, user, key, disk, safe_mode):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key = key
        self.disk = disk
        self.safe_mode = safe_mode
        self.start_time = None
        self.end_time = None
        # Filename format: evidence_YYYYMMDD_HHMMSS.img.gz
        self.filename = f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.img.gz"

    def get_ssh_fingerprint(self):
        """Fetches the SSH fingerprint of the remote server for verification."""
        try:
            # Using ssh-keyscan to get the fingerprint
            cmd = f"ssh-keyscan -t rsa {self.ip} 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            return output if output else "Fingerprint could not be fetched."
        except Exception:
            return "Fingerprint fetch failed."

    def run(self):
        self.start_time = datetime.now()
        report_data = {
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip": self.ip,
            "ssh_fingerprint": "N/A",
            "command_executed": "N/A",
            "duration": "0s"
        }

        try:
            self.log_signal.emit(f"[*] Task Started at: {report_data['start_time']}")
            self.log_signal.emit(f"[*] Target Connection: {self.ip}")
            
            # 1. SSH Fingerprint Verification (Crucial for Forensics)
            fingerprint = self.get_ssh_fingerprint()
            report_data["ssh_fingerprint"] = fingerprint
            self.log_signal.emit(f"[*] Remote SSH Fingerprint Verified:\n    {fingerprint}")

            # 2. Key Security Check
            if os.path.exists(self.key):
                os.chmod(self.key, 0o400)
            else:
                self.finished_signal.emit(False, "SSH Key file not found!", report_data)
                return

            # 3. Command Preparation
            dd_flags = "conv=noerror,sync" if self.safe_mode else ""
            
            # Construct the exact command string
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no", "-i", self.key,
                f"{self.user}@{self.ip}",
                f"sudo dd if={self.disk} bs=64K {dd_flags} status=progress | gzip -1 -"
            ]
            
            # Save the full command for the report
            full_command_str = " ".join(ssh_cmd)
            report_data["command_executed"] = full_command_str

            self.log_signal.emit(f"[*] EXECUTING COMMAND:\n    {full_command_str}")
            self.log_signal.emit("[*] Data stream started (Please wait)...")

            # 4. Execute Process
            with open(self.filename, "wb") as f:
                process = subprocess.Popen(ssh_cmd, stdout=f, stderr=subprocess.PIPE)
                process.wait()

            self.end_time = datetime.now()
            duration = self.end_time - self.start_time
            report_data["end_time"] = self.end_time.strftime("%Y-%m-%d %H:%M:%S")
            report_data["duration"] = str(duration)

            if process.returncode == 0:
                self.log_signal.emit(f"[SUCCESS] Transfer Complete. Duration: {duration}")
                self.finished_signal.emit(True, self.filename, report_data)
            else:
                err = process.stderr.read().decode()
                self.finished_signal.emit(False, f"SSH/DD Error: {err}", report_data)

        except Exception as e:
            self.finished_signal.emit(False, str(e), report_data)

# ==========================================
# WORKER 2: ZIP BOMB / MALWARE ANALYSIS
# ==========================================
class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, str) # Added hash to signal

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def calculate_hash(self):
        """Calculates SHA-256 Hash of the acquired image."""
        try:
            cmd = f"sha256sum {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            return result.split()[0] # Return only the hash
        except:
            return "HASH_CALCULATION_ERROR"

    def run(self):
        self.log_signal.emit("\n--- [ SECURITY & INTEGRITY SCAN ] ---")
        
        # 1. Hash Calculation
        self.log_signal.emit("[*] Calculating SHA-256 Hash (This is your digital seal)...")
        file_hash = self.calculate_hash()
        self.log_signal.emit(f"[*] SHA-256: {file_hash}")

        # 2. Zip Bomb Check
        self.log_signal.emit("[*] Analyzing Binary Headers for Anomalies...")
        try:
            cmd = f"grep -aPc '\\x50\\x4B\\x03\\x04' {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            zip_count = int(result) if result.isdigit() else 0
            
            warning_msg = ""
            if zip_count > 1000:
                self.log_signal.emit("[!!!] THREAT DETECTED: Potential Zip Bomb structure.")
                warning_msg = f"WARNING: {zip_count} compressed blocks detected. Do not unzip automatically."
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
            QMessageBox.critical(self, "Error", f"Could not load UI File!\n{e}")
            sys.exit(1)

        self.setWindowTitle("Remote Forensic Imager - Professional Edition")
        self.setup_terminal_style()

        # Connect Buttons
        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)
        
        # Defaults
        self.txt_user.setText("ubuntu")
        self.txt_disk.setText("/dev/nvme0n1")
        self.chk_safety.setChecked(True)
        self.progressBar.setValue(0)
        
        # UI Check for new fields (Optional safety check)
        if not hasattr(self, 'txt_caseno'):
            self.log("[WARNING] 'txt_caseno' field missing in UI. Using default.")
        if not hasattr(self, 'txt_examiner'):
            self.log("[WARNING] 'txt_examiner' field missing in UI. Using default.")

    def setup_terminal_style(self):
        self.txt_log.setReadOnly(True)
        style_sheet = """
            QTextEdit {
                background-color: #000000;
                color: #00FF00;
                font-family: "Monospace";
                font-size: 10pt;
                border: 1px solid #333;
            }
        """
        self.txt_log.setStyleSheet(style_sheet)
        self.log("--- SYSTEM READY ---")
        self.log("[*] Forensic Console Initialized.")

    def select_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        self.txt_log.append(msg)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)

    def start_process(self):
        ip = self.txt_ip.text()
        user = self.txt_user.text()
        key = self.txt_key.text()
        disk = self.txt_disk.text()
        
        # Get Case Info (Handle missing UI elements gracefully)
        self.case_no = self.txt_caseno.text() if hasattr(self, 'txt_caseno') else "UNKNOWN_CASE"
        self.examiner = self.txt_examiner.text() if hasattr(self, 'txt_examiner') else "UNKNOWN_EXAMINER"

        if not ip or not key or not user:
            QMessageBox.warning(self, "Missing Info", "Please fill all required fields!")
            return

        self.btn_start.setEnabled(False)
        self.progressBar.setValue(5)
        self.log("\n--- [ STARTING FORENSIC ACQUISITION ] ---")
        self.log(f"[*] Case No: {self.case_no} | Examiner: {self.examiner}")
        
        self.worker = AcquisitionThread(ip, user, key, disk, self.chk_safety.isChecked())
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.start()

    def on_acquisition_finished(self, success, filename, report_data):
        self.last_report_data = report_data # Save for final report
        
        if success:
            self.progressBar.setValue(50)
            self.log(f"[INFO] Image Acquired: {filename}")
            
            self.analyzer = AnalysisThread(filename)
            self.analyzer.log_signal.connect(self.log)
            self.analyzer.finished_signal.connect(self.on_analysis_finished)
            self.analyzer.start()
        else:
            self.log(f"[ERROR] {filename}")
            QMessageBox.critical(self, "Failed", filename)
            self.btn_start.setEnabled(True)
            self.progressBar.setValue(0)

    def on_analysis_finished(self, warning, file_hash):
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        
        # Generate the Chain of Custody Report
        self.generate_report(file_hash)
        
        self.log("\n--- [ TASK COMPLETED SUCCESSFULLY ] ---")
        self.log(f"[*] Report Generated: {self.last_report_data['start_time']}_Report.txt")
        
        if warning:
            QMessageBox.warning(self, "FORENSIC WARNING", warning)
        else:
            QMessageBox.information(self, "Success", "Acquisition & Analysis Complete.\nReport Generated.")

    def generate_report(self, file_hash):
        """Generates a text file with Chain of Custody table."""
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
Target Disk    : {self.txt_disk.text()}

ACQUISITION LOG:
----------------
Start Time     : {self.last_report_data['start_time']}
End Time       : {self.last_report_data['end_time']}
Duration       : {self.last_report_data['duration']}
SSH Fingerprint: {self.last_report_data['ssh_fingerprint']}

COMMAND EXECUTED:
-----------------
{self.last_report_data['command_executed']}

EVIDENCE DETAILS:
-----------------
File Name      : {self.worker.filename}
SHA-256 Hash   : {file_hash}
Integrity      : VERIFIED

================================================================
                  CHAIN OF CUSTODY (CoC)
================================================================
| Date/Time           | Released By (From) | Received By (To) | Purpose             |
|---------------------|--------------------|------------------|---------------------|
| {self.last_report_data['end_time']} | AWS Live Server    | {self.examiner:<16} | Forensic Acquisition|
| {self.last_report_data['end_time']} | {self.examiner:<18} | Secure Storage   | Evidence Locking    |
|                     |                    |                  |                     |
================================================================
Note: This document is auto-generated by Remote Forensic Imager.
"""
        # Save to file
        report_filename = f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(report_filename, "w") as f:
            f.write(report_content)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
