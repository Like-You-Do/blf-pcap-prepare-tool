# Pcap-prepare PCAP/BLF 对比工具

一个基于 PySide6 的跨平台网络抓包文件对比桌面应用，支持 Linux 和 Windows。专门用于汽车通信分析。

## 功能特性

- 支持 PCAP/PCAPNG 和 BLF 文件格式对比
- SomeIP 协议条目对比（基于 service_id + ip_address）
- CAN 协议消息对比（基于 can_id + channel_id）
- 跨格式对比（PCAP vs BLF）
- 三路差异显示：共同条目、仅文件1、仅文件2
- 颜色编码结果（绿色=共同、红色=仅文件1、蓝色=仅文件2）
- 非阻塞 GUI（QThread 后台处理）
- 测试数据生成脚本
- 中文界面

## 安装

```bash
pip install -r requirements.txt
```

或使用 pyproject.toml：

```bash
pip install .
```

## 运行

```bash
python main.py
```

## 依赖

| 库 | 用途 |
|---|---|
| scapy >= 2.5.0 | PCAP 解析、SomeIP/UDP/IP/Ethernet 包解析 |
| python-can >= 4.0.0 | BLF 文件读取 CAN 消息 |
| asammdf >= 7.0.0 | BLF Ethernet/SomeIP 提取 |
| PySide6 >= 6.5.0 | Qt6 GUI 框架 |

## 项目结构

```
Pcap-prepare/
├── main.py                    # 程序入口
├── comparator.py              # 核心对比逻辑（集合运算）
├── pyproject.toml             # 项目配置
├── .gitignore
├── parsers/                   # 协议文件解析器
│   ├── __init__.py
│   ├── models.py              # 数据模型：SomeIPEntry, CANEntry
│   ├── pcap_parser.py         # PCAP/PCAPNG 解析器
│   └── blf_parser.py          # BLF 解析器
├── gui/                       # PySide6 GUI 层
│   ├── __init__.py
│   ├── main_window.py         # 主窗口
│   ├── result_widget.py       # 结果显示组件
│   └── styles.py              # 样式表
├── test_compare.py            # CLI 测试脚本
├── generate_test_data.py      # 测试数据生成脚本
└── test_data/                 # 测试数据目录
```

## 系统要求

- Python >= 3.10
- PySide6 >= 6.5.0

## 许可证

MIT License
