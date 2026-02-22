import hashlib
from PyQt6.QtCore import QThread, pyqtSignal

class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, str, str)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def run(self):
        self.log_signal.emit("[*] Starting Post-Acquisition Hash Verification...")
        sha256_hash = "SHA256_CALCULATION_ERROR"
        md5_hash = "MD5_CALCULATION_ERROR"
        warning = ""

        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()

            # Bellek sismemesi icin dosyayi 4MB'lik bloklar (chunks) halinde okur
            with open(self.filename, "rb") as f:
                for chunk in iter(lambda: f.read(4096 * 1024), b""):
                    sha256.update(chunk)
                    md5.update(chunk)

            sha256_hash = sha256.hexdigest()
            md5_hash = md5.hexdigest()

            self.log_signal.emit(f"[OK] SHA-256: {sha256_hash}")
            self.log_signal.emit(f"[OK] MD5: {md5_hash}")

        except Exception as e:
            warning = f"Hash calculation failed for {self.filename}: {str(e)}"
            self.log_signal.emit(f"[ERROR] {warning}")

        self.finished_signal.emit(warning, sha256_hash, md5_hash)
