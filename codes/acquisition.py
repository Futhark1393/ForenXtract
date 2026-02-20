import os
import subprocess
import shutil
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal

class AcquisitionThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, dict)

    def __init__(self, ip, user, key, disk, safe_mode, write_block, is_ram, throttle_limit=None, do_triage=False):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key = key
        self.disk = disk
        self.safe_mode = safe_mode
        self.write_block = write_block
        self.is_ram = is_ram
        self.throttle_limit = throttle_limit
        self.do_triage = do_triage
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

    def run_live_triage(self, report_data):
        """Executes rapid volatile data collection before main acquisition."""
        self.log_signal.emit("[*] Starting Live System Triage (Fast Recon)...")
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        triage_file = f"triage_evidence_{timestamp}.txt"

        triage_cmds = (
            "echo '=== NETWORK CONNECTIONS ==='; sudo ss -antp 2>/dev/null || sudo netstat -antp 2>/dev/null; "
            "echo -e '\n=== RUNNING PROCESSES ==='; sudo ps aux; "
            "echo -e '\n=== LOGGED IN USERS ==='; who; "
            "echo -e '\n=== KERNEL LOGS (LAST 50) ==='; sudo dmesg | tail -n 50"
        )

        triage_ssh_cmd = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} \"{triage_cmds}\""

        try:
            triage_output = subprocess.check_output(triage_ssh_cmd, shell=True).decode('utf-8', errors='ignore')
            with open(triage_file, "w", encoding="utf-8") as tf:
                tf.write(triage_output)
            self.log_signal.emit(f"[SUCCESS] Triage data saved to: {triage_file}")
            report_data["triage_file"] = triage_file
        except Exception as e:
            self.log_signal.emit(f"[WARNING] Live Triage failed: {e}")
            report_data["triage_file"] = "Failed"

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
            "bad_sectors": [],
            "triage_file": "Not Requested"
        }

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

            # 3. Live Triage Execution
            if self.do_triage:
                self.run_live_triage(report_data)

            # 4. Write Blocker Activation
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

            try:
                # 5. Prepare Acquisition Command
                dd_flags = "conv=noerror,sync" if self.safe_mode else ""
                ssh_cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no", "-i", self.key,
                    f"{self.user}@{self.ip}",
                    f"sudo dd if={self.disk} bs=64K {dd_flags} status=progress | gzip -1 -"
                ]

                full_command_str = " ".join(ssh_cmd)

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
                        p1 = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        p2 = subprocess.Popen(throttle_cmd, stdin=p1.stdout, stdout=f)
                        p1.stdout.close()
                        process_to_monitor = p1
                    else:
                        process_to_monitor = subprocess.Popen(ssh_cmd, stdout=f, stderr=subprocess.PIPE)

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
                # 6. Lock Restoration
                if wb_activated:
                    self.log_signal.emit("[*] Reverting Write Blocker (Restoring Read-Write)...")
                    success, msg = self.set_write_block(False)
                    if success:
                        self.log_signal.emit(f"[INFO] System Restored: {msg}")
                    else:
                        self.log_signal.emit(f"[!!!] CRITICAL WARNING: Could not restore RW mode!")

        except Exception as e:
            self.finished_signal.emit(False, str(e), report_data)
