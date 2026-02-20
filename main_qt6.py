import sys
from PyQt6.QtWidgets import QApplication
from codes.gui import ForensicApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
