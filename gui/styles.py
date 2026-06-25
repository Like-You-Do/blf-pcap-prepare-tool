MAIN_STYLE = """
QMainWindow {
    background-color: #f5f5f5;
}

QGroupBox {
    font-weight: bold;
    font-size: 14px;
    border: 2px solid #e0e0e0;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 20px;
    background-color: white;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 0 8px;
    color: #1976d2;
}

QPushButton {
    background-color: #1976d2;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 6px;
    font-weight: bold;
    font-size: 13px;
    min-width: 100px;
}

QPushButton:hover {
    background-color: #1565c0;
}

QPushButton:pressed {
    background-color: #0d47a1;
}

QPushButton:disabled {
    background-color: #bdbdbd;
    color: #757575;
}

QPushButton#compare_btn {
    background-color: #4caf50;
    font-size: 15px;
    padding: 12px 30px;
    min-width: 140px;
}

QPushButton#compare_btn:hover {
    background-color: #43a047;
}

QPushButton#compare_btn:pressed {
    background-color: #388e3c;
}

QPushButton#compare_btn:disabled {
    background-color: #a5d6a7;
    color: white;
}

QLabel {
    color: #424242;
    font-size: 13px;
}

QLabel#file_path {
    padding: 8px 12px;
    background-color: #fafafa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    color: #757575;
}

QLabel#file_path[selected="true"] {
    color: #212121;
    background-color: white;
}

QProgressBar {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    text-align: center;
    height: 20px;
    background-color: #fafafa;
}

QProgressBar::chunk {
    background-color: #1976d2;
    border-radius: 3px;
}

QTreeWidget {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    background-color: white;
    alternate-background-color: #fafafa;
    font-size: 12px;
}

QTreeWidget::item {
    padding: 6px 4px;
    border-bottom: 1px solid #f0f0f0;
}

QTreeWidget::item:selected {
    background-color: #e3f2fd;
    color: #1976d2;
}

QTreeWidget::item:hover {
    background-color: #f5f5f5;
}

QHeaderView::section {
    background-color: #f5f5f5;
    color: #424242;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #1976d2;
    font-weight: bold;
    font-size: 12px;
}

QScrollBar:vertical {
    border: none;
    background-color: #f5f5f5;
    width: 10px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #bdbdbd;
    border-radius: 5px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #9e9e9e;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    border: none;
    background-color: #f5f5f5;
    height: 10px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: #bdbdbd;
    border-radius: 5px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #9e9e9e;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
"""

FILE_SELECT_STYLE = """
QLabel#file_path {
    padding: 8px 12px;
    background-color: #fafafa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    color: #757575;
    font-size: 12px;
}

QLabel#file_path[selected="true"] {
    color: #212121;
    background-color: white;
}
"""

COMPARE_BUTTON_STYLE = """
QPushButton#compare_btn {
    background-color: #4caf50;
    color: white;
    border: none;
    padding: 12px 30px;
    border-radius: 6px;
    font-weight: bold;
    font-size: 15px;
    min-width: 140px;
}

QPushButton#compare_btn:hover {
    background-color: #43a047;
}

QPushButton#compare_btn:pressed {
    background-color: #388e3c;
}

QPushButton#compare_btn:disabled {
    background-color: #a5d6a7;
    color: white;
}
"""