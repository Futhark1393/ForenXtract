import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

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
            # Using subprocess.run to gracefully handle exit codes 0 (found) and 1 (not found)
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if process.returncode in [0, 1]:
                zip_count = int(process.stdout.strip()) if process.stdout.strip().isdigit() else 0

                warning_msg = ""
                if zip_count > 1000:
                    self.log_signal.emit("[!!!] THREAT DETECTED: Potential Zip Bomb structure.")
                    warning_msg = f"WARNING: {zip_count} compressed blocks detected."
                else:
                    self.log_signal.emit("[OK] File structure appears clean. No Zip Bomb detected.")

                self.finished_signal.emit(warning_msg, file_hash)
            else:
                self.log_signal.emit(f"[!] Analysis error: Command failed with code {process.returncode}")
                self.finished_signal.emit("", file_hash)

        except Exception as e:
            self.log_signal.emit(f"[!] Analysis error: {str(e)}")
            self.finished_signal.emit("", file_hash)
