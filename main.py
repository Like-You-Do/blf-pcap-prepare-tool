import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont
from gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("PCAP/BLF 对比工具")
    app.setApplicationVersion("1.0.0")
    app.setStyle("Fusion")
    
    font = QFont()
    font.setPointSize(10)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
