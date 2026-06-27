from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QLabel, QGroupBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush, QFont

from comparator import CompareResult


class ResultWidget(QWidget):
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
        self.someip_tree = self._create_tree(
            ["Service ID", "IP 地址", "状态"]
        )
        self.someip_layout.addWidget(self.someip_tree)

        self.can_group = QGroupBox("CAN 对比结果")
        self.can_group.setCheckable(True)
        self.can_group.setChecked(False)
        self.can_layout = QVBoxLayout(self.can_group)
        self.can_layout.setContentsMargins(15, 20, 15, 15)
        self.can_tree = self._create_tree(
            ["CAN ID", "通道 ID", "状态"]
        )
        self.can_layout.addWidget(self.can_tree)

        self.can_group.toggled.connect(self._on_can_toggle)

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

    def _on_can_toggle(self, checked: bool):
        self.can_tree.setVisible(checked)

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
            common_parent = QTreeWidgetItem(self.someip_tree)
            common_parent.setText(0, f"相同项 ({common_count} 条)")
            common_parent.setExpanded(True)
            common_parent.setForeground(0, QBrush(QColor("#2e7d32")))
            font = common_parent.font(0)
            font.setBold(True)
            common_parent.setFont(0, font)

            for entry1, entry2 in result.common_someip:
                item = QTreeWidgetItem(common_parent)
                item.setText(0, f"0x{entry1.service_id:04X}")
                item.setText(1, entry1.ip_address)
                item.setText(2, "两个文件均有")
                item.setForeground(2, QBrush(QColor("#2e7d32")))

        if only1_count > 0:
            only1_parent = QTreeWidgetItem(self.someip_tree)
            only1_parent.setText(0, f"仅在文件1 ({only1_count} 条)")
            only1_parent.setExpanded(True)
            only1_parent.setForeground(0, QBrush(QColor("#c62828")))
            font = only1_parent.font(0)
            font.setBold(True)
            only1_parent.setFont(0, font)

            for entry in result.only_in_file1:
                item = QTreeWidgetItem(only1_parent)
                item.setText(0, f"0x{entry.service_id:04X}")
                item.setText(1, entry.ip_address)
                item.setText(2, "仅文件1")
                item.setForeground(2, QBrush(QColor("#c62828")))

        if only2_count > 0:
            only2_parent = QTreeWidgetItem(self.someip_tree)
            only2_parent.setText(0, f"仅在文件2 ({only2_count} 条)")
            only2_parent.setExpanded(True)
            only2_parent.setForeground(0, QBrush(QColor("#1565c0")))
            font = only2_parent.font(0)
            font.setBold(True)
            only2_parent.setFont(0, font)

            for entry in result.only_in_file2:
                item = QTreeWidgetItem(only2_parent)
                item.setText(0, f"0x{entry.service_id:04X}")
                item.setText(1, entry.ip_address)
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
            common_parent = QTreeWidgetItem(self.can_tree)
            common_parent.setText(0, f"相同项 ({common_count} 条)")
            common_parent.setExpanded(False)
            common_parent.setForeground(0, QBrush(QColor("#2e7d32")))
            font = common_parent.font(0)
            font.setBold(True)
            common_parent.setFont(0, font)

            for entry1, entry2 in result.common_can:
                item = QTreeWidgetItem(common_parent)
                item.setText(0, f"0x{entry1.can_id:03X}")
                item.setText(1, str(entry1.channel_id))
                item.setText(2, "两个文件均有")
                item.setForeground(2, QBrush(QColor("#2e7d32")))

        if only1_count > 0:
            only1_parent = QTreeWidgetItem(self.can_tree)
            only1_parent.setText(0, f"仅在文件1 ({only1_count} 条)")
            only1_parent.setExpanded(False)
            only1_parent.setForeground(0, QBrush(QColor("#c62828")))
            font = only1_parent.font(0)
            font.setBold(True)
            only1_parent.setFont(0, font)

            for entry in result.only_can_in_file1:
                item = QTreeWidgetItem(only1_parent)
                item.setText(0, f"0x{entry.can_id:03X}")
                item.setText(1, str(entry.channel_id))
                item.setText(2, "仅文件1")
                item.setForeground(2, QBrush(QColor("#c62828")))

        if only2_count > 0:
            only2_parent = QTreeWidgetItem(self.can_tree)
            only2_parent.setText(0, f"仅在文件2 ({only2_count} 条)")
            only2_parent.setExpanded(False)
            only2_parent.setForeground(0, QBrush(QColor("#1565c0")))
            font = only2_parent.font(0)
            font.setBold(True)
            only2_parent.setFont(0, font)

            for entry in result.only_can_in_file2:
                item = QTreeWidgetItem(only2_parent)
                item.setText(0, f"0x{entry.can_id:03X}")
                item.setText(1, str(entry.channel_id))
                item.setText(2, "仅文件2")
                item.setForeground(2, QBrush(QColor("#1565c0")))
