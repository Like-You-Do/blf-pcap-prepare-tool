from parsers.pcap_parser import parse_pcap
from parsers.blf_parser import parse_blf
from comparator import compare_files


def print_someip_entries(entries, label):
    print(f"  {label} ({len(entries)} 条):")
    for e in sorted(entries, key=lambda x: (x.service_id, x.ip_address)):
        print(f"    Service ID: 0x{e.service_id:04X}, IP: {e.ip_address}")


def print_can_entries(entries, label):
    print(f"  {label} ({len(entries)} 条):")
    for e in sorted(entries, key=lambda x: (x.can_id, x.channel_id)):
        print(f"    CAN ID: 0x{e.can_id:03X}, Channel: {e.channel_id}")


def run_comparison(file1, file2, desc1, desc2):
    print(f"\n{'='*60}")
    print(f"对比: {desc1} vs {desc2}")
    print(f"  文件1: {file1}")
    print(f"  文件2: {file2}")
    print(f"{'='*60}")

    ext1 = file1.rsplit(".", 1)[-1].lower()
    ext2 = file2.rsplit(".", 1)[-1].lower()

    someip1, can1 = set(), set()
    someip2, can2 = set(), set()

    if ext1 in ("pcap", "pcapng"):
        someip1 = parse_pcap(file1)
    elif ext1 == "blf":
        someip1, can1 = parse_blf(file1)

    if ext2 in ("pcap", "pcapng"):
        someip2 = parse_pcap(file2)
    elif ext2 == "blf":
        someip2, can2 = parse_blf(file2)

    result = compare_files(someip1, someip2, can1, can2)

    print(f"\n--- 以太网 SomeIP 对比结果 ---")
    print_someip_entries([e1 for e1, _ in result.common_someip], "相同项")
    print_someip_entries(result.only_in_file1, "仅在文件1")
    print_someip_entries(result.only_in_file2, "仅在文件2")

    has_can = (
        len(result.common_can) > 0
        or len(result.only_can_in_file1) > 0
        or len(result.only_can_in_file2) > 0
    )
    if has_can:
        print(f"\n--- CAN 对比结果 ---")
        print_can_entries([e1 for e1, _ in result.common_can], "相同项")
        print_can_entries(result.only_can_in_file1, "仅在文件1")
        print_can_entries(result.only_can_in_file2, "仅在文件2")
    else:
        print(f"\n--- 无 CAN 数据 ---")


def main():
    print("PCAP/BLF 对比工具 - 测试验证")
    print("=" * 60)

    run_comparison(
        "test_data/test_common.pcap",
        "test_data/test_unique_a.pcap",
        "test_common.pcap",
        "test_unique_a.pcap",
    )

    run_comparison(
        "test_data/test_common.blf",
        "test_data/test_unique_a.blf",
        "test_common.blf",
        "test_unique_a.blf",
    )

    run_comparison(
        "test_data/test_common.pcap",
        "test_data/test_common.blf",
        "test_common.pcap",
        "test_common.blf",
    )

    run_comparison(
        "test_data/test_unique_a.pcap",
        "test_data/test_unique_b.pcap",
        "test_unique_a.pcap",
        "test_unique_b.pcap",
    )

    run_comparison(
        "test_data/test_unique_a.blf",
        "test_data/test_unique_b.blf",
        "test_unique_a.blf",
        "test_unique_b.blf",
    )


if __name__ == "__main__":
    main()
