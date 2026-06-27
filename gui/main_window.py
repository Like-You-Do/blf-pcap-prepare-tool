from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QGroupBox,
    QMessageBox, QProgressBar, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QFont, QIcon

from parsers.pcap_parser import parse_pcap
from parsers.blf_parser import parse_blf
from comparator import compare_files
from gui.result_widget import ResultWidget
from gui.styles import MAIN_STYLE, FILE_SELECT_STYLE, COMPARE_BUTTON_STYLE


class CompareWorker(QThread):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, file1: str, file2: str):
        super().__init__()
        self.file1 = file1
        self.file2 = file2

    def run(self):
        try:
            someip1, can1 = self._parse_file(self.file1)
            someip2, can2 = self._parse_file(self.file2)

            result = compare_files(someip1, someip2, can1, can2)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

    def _parse_file(self, filepath: str):
        ext = Path(filepath).suffix.lower()
        if ext in (".pcap", ".pcapng"):
            return parse_pcap(filepath), set()
        elif ext == ".blf":
            return parse_blf(filepath)
        else:
            raise ValueError(f"不支持的文件格式: {ext}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PCAP/BLF 文件对比工具")
        self.setMinimumSize(800, 600)
        self._file1 = None
        self._file2 = None
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        self.setStyleSheet(MAIN_STYLE)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)

        file_group = QGroupBox("文件选择")
        file_layout = QVBoxLayout(file_group)
        file_layout.setSpacing(15)
        file_layout.setContentsMargins(20, 25, 20, 20)

        file1_layout = QHBoxLayout()
        file1_label = QLabel("文件1:")
        file1_label.setFixedWidth(60)
        file1_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.file1_path = QLabel("未选择文件")
        self.file1_path.setObjectName("file_path")
        self.file1_path.setProperty("selected", "false")
        file1_btn = QPushButton("选择文件")
        file1_btn.clicked.connect(lambda: self._select_file(1))
        file1_layout.addWidget(file1_label)
        file1_layout.addWidget(self.file1_path, stretch=1)
        file1_layout.addWidget(file1_btn)

        file2_layout = QHBoxLayout()
        file2_label = QLabel("文件2:")
        file2_label.setFixedWidth(60)
        file2_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.file2_path = QLabel("未选择文件")
        self.file2_path.setObjectName("file_path")
        self.file2_path.setProperty("selected", "false")
        file2_btn = QPushButton("选择文件")
        file2_btn.clicked.connect(lambda: self._select_file(2))
        file2_layout.addWidget(file2_label)
        file2_layout.addWidget(self.file2_path, stretch=1)
        file2_layout.addWidget(file2_btn)

        file_layout.addLayout(file1_layout)
        file_layout.addLayout(file2_layout)

        btn_layout = QHBoxLayout()
        self.compare_btn = QPushButton("开始对比")
        self.compare_btn.setObjectName("compare_btn")
        self.compare_btn.setEnabled(False)
        self.compare_btn.clicked.connect(self._start_compare)
        btn_layout.addStretch()
        btn_layout.addWidget(self.compare_btn)
        btn_layout.addStretch()
        file_layout.addLayout(btn_layout)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(8)
        file_layout.addWidget(self.progress)

        layout.addWidget(file_group)

        self.result_widget = ResultWidget()
        layout.addWidget(self.result_widget, stretch=1)

    def _select_file(self, which: int):
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            f"选择文件 {which}",
            "",
            "支持的文件 (*.pcap *.pcapng *.blf);;PCAP文件 (*.pcap *.pcapng);;BLF文件 (*.blf)"
        )

        if not filepath:
            return

        label = self.file1_path if which == 1 else self.file2_path
        label.setText(filepath)
        label.setProperty("selected", "true")
        label.setStyleSheet(FILE_SELECT_STYLE)

        if which == 1:
            self._file1 = filepath
        else:
            self._file2 = filepath

        self.compare_btn.setEnabled(
            self._file1 is not None and self._file2 is not None
        )

    def _start_compare(self):
        if not self._file1 or not self._file2:
            return

        if self._worker is not None:
            self._worker.quit()
            self._worker.wait()
            self._worker.deleteLater()
            self._worker = None

        self.compare_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)

        self._worker = CompareWorker(self._file1, self._file2)
        self._worker.finished.connect(self._on_compare_finished)
        self._worker.error.connect(self._on_compare_error)
        self._worker.finished.connect(self._cleanup_worker)
        self._worker.error.connect(self._cleanup_worker)
        self._worker.start()

    def _cleanup_worker(self):
        if self._worker is not None:
            self._worker.quit()
            self._worker.wait()
            self._worker.deleteLater()
            self._worker = None

    def _on_compare_finished(self, result):
        self.progress.setVisible(False)
        self.compare_btn.setEnabled(True)
        self.result_widget.set_files(self._file1, self._file2)
        self.result_widget.display_result(result)

    def _on_compare_error(self, error_msg):
        self.progress.setVisible(False)
        self.compare_btn.setEnabled(True)
        QMessageBox.critical(self, "对比失败", f"发生错误:\n{error_msg}")

    def closeEvent(self, event):
        if self._worker is not None and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait()
        event.accept()
