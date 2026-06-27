from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QLabel,
    QGroupBox, QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush, QFont

from comparator import CompareResult

COLOR_COMMON = QColor("#e8f5e9")
COLOR_ONLY1 = QColor("#ffebee")
COLOR_ONLY2 = QColor("#e3f2fd")
COLOR_BORDER = QColor("#e0e0e0")
COLOR_GREEN_TEXT = QColor("#2e7d32")
COLOR_RED_TEXT = QColor("#c62828")
COLOR_BLUE_TEXT = QColor("#1565c0")


def _create_diff_tree(headers: list[str]) -> QTreeWidget:
    tree = QTreeWidget()
    tree.setHeaderLabels(headers)
    tree.setAlternatingRowColors(False)
    tree.setRootIsDecorated(False)
    tree.setIndentation(0)
    tree.setAnimated(True)
    tree.setUniformRowHeights(True)
    tree.setSelectionMode(QTreeWidget.SelectionMode.NoSelection)
    header = tree.header()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    header.setStretchLastSection(True)
    font = tree.font()
    font.setPointSize(11)
    tree.setFont(font)
    return tree


def _fill_tree(tree: QTreeWidget, entries: list, headers: list[str], side: str):
    tree.clear()
    if not entries:
        item = QTreeWidgetItem(tree)
        item.setText(0, "无数据")
        font = item.font(0)
        font.setItalic(True)
        item.setFont(0, font)
        item.setForeground(0, QBrush(QColor("#9e9e9e")))
        return

    for entry, status in entries:
        item = QTreeWidgetItem(tree)
        if side == "someip":
            item.setText(0, f"0x{entry.service_id:04X}")
            item.setText(1, entry.ip_address)
        else:
            item.setText(0, f"0x{entry.can_id:03X}")
            item.setText(1, str(entry.channel_id))

        if status == "common":
            bg = COLOR_COMMON
            fg = COLOR_GREEN_TEXT
            label = "公共"
        elif status == "only1":
            bg = COLOR_ONLY1
            fg = COLOR_RED_TEXT
            label = "仅文件1"
        else:
            bg = COLOR_ONLY2
            fg = COLOR_BLUE_TEXT
            label = "仅文件2"

        item.setText(2, label)
        for col in range(len(headers)):
            item.setBackground(col, bg)
            item.setForeground(col, fg)


class DiffWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._syncing = False
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)

        self.someip_group = QGroupBox("Ethernet SomeIP 对比结果")
        someip_layout = QVBoxLayout(self.someip_group)
        someip_layout.setContentsMargins(15, 20, 15, 15)

        self.someip_left_label = QLabel("文件1")
        self.someip_left_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.someip_left_label.setObjectName("diff_file_label")
        self.someip_right_label = QLabel("文件2")
        self.someip_right_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.someip_right_label.setObjectName("diff_file_label")

        self.someip_left_tree = _create_diff_tree(["Service ID", "IP 地址", "状态"])
        self.someip_right_tree = _create_diff_tree(["Service ID", "IP 地址", "状态"])

        left_col = self._make_panel(self.someip_left_label, self.someip_left_tree)
        right_col = self._make_panel(self.someip_right_label, self.someip_right_tree)

        self.someip_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.someip_splitter.addWidget(left_col)
        self.someip_splitter.addWidget(right_col)
        self.someip_splitter.setHandleWidth(3)
        self.someip_splitter.setSizes([500, 500])

        someip_layout.addWidget(self.someip_splitter)

        self.someip_left_tree.verticalScrollBar().valueChanged.connect(
            lambda v: self._sync_scroll(self.someip_right_tree.verticalScrollBar(), v)
        )
        self.someip_right_tree.verticalScrollBar().valueChanged.connect(
            lambda v: self._sync_scroll(self.someip_left_tree.verticalScrollBar(), v)
        )

        self.can_group = QGroupBox("CAN 对比结果")
        self.can_group.setCheckable(True)
        self.can_group.setChecked(False)
        self.can_group.toggled.connect(self._on_can_toggle)
        can_layout = QVBoxLayout(self.can_group)
        can_layout.setContentsMargins(15, 20, 15, 15)

        self.can_left_label = QLabel("文件1")
        self.can_left_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.can_left_label.setObjectName("diff_file_label")
        self.can_right_label = QLabel("文件2")
        self.can_right_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.can_right_label.setObjectName("diff_file_label")

        self.can_left_tree = _create_diff_tree(["CAN ID", "通道 ID", "状态"])
        self.can_right_tree = _create_diff_tree(["CAN ID", "通道 ID", "状态"])

        can_left_col = self._make_panel(self.can_left_label, self.can_left_tree)
        can_right_col = self._make_panel(self.can_right_label, self.can_right_tree)

        self.can_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.can_splitter.addWidget(can_left_col)
        self.can_splitter.addWidget(can_right_col)
        self.can_splitter.setHandleWidth(3)
        self.can_splitter.setSizes([500, 500])

        can_layout.addWidget(self.can_splitter)

        self.can_left_tree.verticalScrollBar().valueChanged.connect(
            lambda v: self._sync_scroll(self.can_right_tree.verticalScrollBar(), v)
        )
        self.can_right_tree.verticalScrollBar().valueChanged.connect(
            lambda v: self._sync_scroll(self.can_left_tree.verticalScrollBar(), v)
        )

        layout.addWidget(self.someip_group)
        layout.addWidget(self.can_group)

        self.can_group.hide()

    def _make_panel(self, label: QLabel, tree: QTreeWidget) -> QWidget:
        panel = QWidget()
        v = QVBoxLayout(panel)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)
        v.addWidget(label)
        v.addWidget(tree, stretch=1)
        return panel

    def _sync_scroll(self, target_bar, value):
        if self._syncing:
            return
        self._syncing = True
        target_bar.setValue(value)
        self._syncing = False

    def _on_can_toggle(self, checked: bool):
        self.can_splitter.setVisible(checked)
        self.can_left_label.setVisible(checked)
        self.can_right_label.setVisible(checked)

    def display_result(self, result: CompareResult, file1: str, file2: str):
        from pathlib import Path
        self.someip_left_label.setText(Path(file1).name)
        self.someip_right_label.setText(Path(file2).name)
        self.can_left_label.setText(Path(file1).name)
        self.can_right_label.setText(Path(file2).name)

        self._fill_someip(result)
        self._fill_can(result)

        has_can = (
            len(result.common_can) > 0
            or len(result.only_can_in_file1) > 0
            or len(result.only_can_in_file2) > 0
        )
        if has_can:
            self.can_group.setChecked(True)
            self.can_group.setVisible(True)
        else:
            self.can_group.hide()

    def _fill_someip(self, result: CompareResult):
        left_entries = []
        right_entries = []

        for e1, e2 in result.common_someip:
            left_entries.append((e1, "common"))
            right_entries.append((e2, "common"))

        for e in result.only_in_file1:
            left_entries.append((e, "only1"))

        for e in result.only_in_file2:
            right_entries.append((e, "only2"))

        _fill_tree(self.someip_left_tree, left_entries, ["Service ID", "IP 地址", "状态"], "someip")
        _fill_tree(self.someip_right_tree, right_entries, ["Service ID", "IP 地址", "状态"], "someip")

    def _fill_can(self, result: CompareResult):
        left_entries = []
        right_entries = []

        for e1, e2 in result.common_can:
            left_entries.append((e1, "common"))
            right_entries.append((e2, "common"))

        for e in result.only_can_in_file1:
            left_entries.append((e, "only1"))

        for e in result.only_can_in_file2:
            right_entries.append((e, "only2"))

        _fill_tree(self.can_left_tree, left_entries, ["CAN ID", "通道 ID", "状态"], "can")
        _fill_tree(self.can_right_tree, right_entries, ["CAN ID", "通道 ID", "状态"], "can")
