from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QLabel, QGroupBox, QComboBox, QStackedWidget
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush, QFont

from comparator import CompareResult
from gui.diff_widget import DiffWidget


class TreeView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)

        self.someip_group = QGroupBox("Ethernet SomeIP 对比结果")
        self.someip_layout = QVBoxLayout(self.someip_group)
        self.someip_layout.setContentsMargins(15, 20, 15, 15)
        self.someip_tree = self._create_tree(["Service ID", "IP 地址", "状态"])
        self.someip_layout.addWidget(self.someip_tree)

        self.can_group = QGroupBox("CAN 对比结果")
        self.can_group.setCheckable(True)
        self.can_group.setChecked(False)
        self.can_layout = QVBoxLayout(self.can_group)
        self.can_layout.setContentsMargins(15, 20, 15, 15)
        self.can_tree = self._create_tree(["CAN ID", "通道 ID", "状态"])
        self.can_layout.addWidget(self.can_tree)
        self.can_group.toggled.connect(lambda c: self.can_tree.setVisible(c))

        layout.addWidget(self.someip_group)
        layout.addWidget(self.can_group)
        self.can_group.hide()

    def _create_tree(self, headers: list[str]) -> QTreeWidget:
        tree = QTreeWidget()
        tree.setHeaderLabels(headers)
        tree.setAlternatingRowColors(True)
        tree.setRootIsDecorated(True)
        tree.setIndentation(20)
        tree.setAnimated(True)
        tree.setUniformRowHeights(True)
        header = tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setStretchLastSection(True)
        font = tree.font()
        font.setPointSize(11)
        tree.setFont(font)
        return tree

    def display_result(self, result: CompareResult):
        self._display_someip(result)
        self._display_can(result)
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

    def _display_someip(self, result: CompareResult):
        self.someip_tree.clear()
        common_count = len(result.common_someip)
        only1_count = len(result.only_in_file1)
        only2_count = len(result.only_in_file2)

        if common_count == 0 and only1_count == 0 and only2_count == 0:
            no_data = QTreeWidgetItem(self.someip_tree)
            no_data.setText(0, "无 SomeIP 数据")
            font = no_data.font(0)
            font.setItalic(True)
            no_data.setFont(0, font)
            no_data.setForeground(0, QBrush(QColor("#9e9e9e")))
            return

        if common_count > 0:
            parent = QTreeWidgetItem(self.someip_tree)
            parent.setText(0, f"相同项 ({common_count} 条)")
            parent.setExpanded(True)
            parent.setForeground(0, QBrush(QColor("#2e7d32")))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for e1, e2 in result.common_someip:
                item = QTreeWidgetItem(parent)
                item.setText(0, f"0x{e1.service_id:04X}")
                item.setText(1, e1.ip_address)
                item.setText(2, "两个文件均有")
                item.setForeground(2, QBrush(QColor("#2e7d32")))

        if only1_count > 0:
            parent = QTreeWidgetItem(self.someip_tree)
            parent.setText(0, f"仅在文件1 ({only1_count} 条)")
            parent.setExpanded(True)
            parent.setForeground(0, QBrush(QColor("#c62828")))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for e in result.only_in_file1:
                item = QTreeWidgetItem(parent)
                item.setText(0, f"0x{e.service_id:04X}")
                item.setText(1, e.ip_address)
                item.setText(2, "仅文件1")
                item.setForeground(2, QBrush(QColor("#c62828")))

        if only2_count > 0:
            parent = QTreeWidgetItem(self.someip_tree)
            parent.setText(0, f"仅在文件2 ({only2_count} 条)")
            parent.setExpanded(True)
            parent.setForeground(0, QBrush(QColor("#1565c0")))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for e in result.only_in_file2:
                item = QTreeWidgetItem(parent)
                item.setText(0, f"0x{e.service_id:04X}")
                item.setText(1, e.ip_address)
                item.setText(2, "仅文件2")
                item.setForeground(2, QBrush(QColor("#1565c0")))

    def _display_can(self, result: CompareResult):
        self.can_tree.clear()
        common_count = len(result.common_can)
        only1_count = len(result.only_can_in_file1)
        only2_count = len(result.only_can_in_file2)

        if common_count == 0 and only1_count == 0 and only2_count == 0:
            return

        if common_count > 0:
            parent = QTreeWidgetItem(self.can_tree)
            parent.setText(0, f"相同项 ({common_count} 条)")
            parent.setExpanded(False)
            parent.setForeground(0, QBrush(QColor("#2e7d32")))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for e1, e2 in result.common_can:
                item = QTreeWidgetItem(parent)
                item.setText(0, f"0x{e1.can_id:03X}")
                item.setText(1, str(e1.channel_id))
                item.setText(2, "两个文件均有")
                item.setForeground(2, QBrush(QColor("#2e7d32")))

        if only1_count > 0:
            parent = QTreeWidgetItem(self.can_tree)
            parent.setText(0, f"仅在文件1 ({only1_count} 条)")
            parent.setExpanded(False)
            parent.setForeground(0, QBrush(QColor("#c62828")))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for e in result.only_can_in_file1:
                item = QTreeWidgetItem(parent)
                item.setText(0, f"0x{e.can_id:03X}")
                item.setText(1, str(e.channel_id))
                item.setText(2, "仅文件1")
                item.setForeground(2, QBrush(QColor("#c62828")))

        if only2_count > 0:
            parent = QTreeWidgetItem(self.can_tree)
            parent.setText(0, f"仅在文件2 ({only2_count} 条)")
            parent.setExpanded(False)
            parent.setForeground(0, QBrush(QColor("#1565c0")))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for e in result.only_can_in_file2:
                item = QTreeWidgetItem(parent)
                item.setText(0, f"0x{e.can_id:03X}")
                item.setText(1, str(e.channel_id))
                item.setText(2, "仅文件2")
                item.setForeground(2, QBrush(QColor("#1565c0")))


class ResultWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self._file1 = None
        self._file2 = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        view_label = QLabel("视图:")
        view_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        self.view_combo = QComboBox()
        self.view_combo.addItems(["对比视图", "树形视图"])
        self.view_combo.setFixedWidth(120)
        self.view_combo.currentIndexChanged.connect(self._on_view_changed)
        toolbar.addWidget(view_label)
        toolbar.addWidget(self.view_combo)
        toolbar.addStretch()

        self.stack = QStackedWidget()
        self.diff_view = DiffWidget()
        self.tree_view = TreeView()
        self.stack.addWidget(self.diff_view)
        self.stack.addWidget(self.tree_view)

        layout.addLayout(toolbar)
        layout.addWidget(self.stack, stretch=1)

    def set_files(self, file1: str, file2: str):
        self._file1 = file1
        self._file2 = file2

    def _on_view_changed(self, index: int):
        self.stack.setCurrentIndex(index)
        if self._result is not None:
            self._refresh_current_view()

    def _refresh_current_view(self):
        idx = self.view_combo.currentIndex()
        if idx == 0:
            self.diff_view.display_result(self._result, self._file1 or "", self._file2 or "")
        else:
            self.tree_view.display_result(self._result)

    def display_result(self, result: CompareResult):
        self._result = result
        self._refresh_current_view()
