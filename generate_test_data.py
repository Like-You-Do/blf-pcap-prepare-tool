import struct
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from scapy.contrib.automotive.someip import SOMEIP
from can import Message


def create_someip_packet(
    src_ip: str,
    dst_ip: str,
    service_id: int,
    method_id: int = 0x0001,
    session_id: int = 1,
):
    someip = SOMEIP(
        srv_id=service_id,
        sub_id=0,
        client_id=0x0001,
        session_id=session_id,
        proto_ver=1,
        iface_ver=1,
        msg_type=0,
        retcode=0,
    )
    pkt = (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=30490, dport=30490)
        / someip
        / Raw(b"\x00" * 16)
    )
    return pkt


def generate_pcap_common(path: str):
    packets = [
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0002),
        create_someip_packet("10.0.0.3", "10.0.0.4", 0x5678, 0x0001),
        create_someip_packet("10.0.0.5", "10.0.0.6", 0xAAAA, 0x0001),
    ]
    wrpcap(path, packets)


def generate_pcap_unique(path: str):
    packets = [
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        create_someip_packet("10.0.0.7", "10.0.0.8", 0xBBBB, 0x0001),
        create_someip_packet("10.0.0.9", "10.0.0.10", 0xCCCC, 0x0001),
    ]
    wrpcap(path, packets)


def generate_pcap_unique2(path: str):
    packets = [
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        create_someip_packet("10.0.0.11", "10.0.0.12", 0xDDDD, 0x0001),
    ]
    wrpcap(path, packets)


def create_blf_file(path: str, can_messages: list):
    from can.io.blf import BLFWriter

    with BLFWriter(path) as writer:
        for msg in can_messages:
            writer.on_message_received(msg)


def generate_blf_common(path: str):
    messages = [
        Message(arbitration_id=0x100, channel=0, data=b"\x01\x02\x03\x04"),
        Message(arbitration_id=0x200, channel=1, data=b"\x05\x06\x07\x08"),
        Message(arbitration_id=0x300, channel=0, data=b"\x09\x0A\x0B\x0C"),
    ]
    create_blf_file(path, messages)


def generate_blf_unique(path: str):
    messages = [
        Message(arbitration_id=0x100, channel=0, data=b"\x01\x02\x03\x04"),
        Message(arbitration_id=0x400, channel=2, data=b"\x0D\x0E\x0F\x10"),
    ]
    create_blf_file(path, messages)


def generate_blf_unique2(path: str):
    messages = [
        Message(arbitration_id=0x200, channel=1, data=b"\x05\x06\x07\x08"),
        Message(arbitration_id=0x500, channel=3, data=b"\x11\x12\x13\x14"),
    ]
    create_blf_file(path, messages)


def main():
    output_dir = Path(__file__).parent / "test_data"
    output_dir.mkdir(exist_ok=True)

    print("生成测试文件...")

    generate_pcap_common(str(output_dir / "test_common.pcap"))
    print(f"  已生成: {output_dir / 'test_common.pcap'}")

    generate_pcap_unique(str(output_dir / "test_unique_a.pcap"))
    print(f"  已生成: {output_dir / 'test_unique_a.pcap'}")

    generate_pcap_unique2(str(output_dir / "test_unique_b.pcap"))
    print(f"  已生成: {output_dir / 'test_unique_b.pcap'}")

    generate_blf_common(str(output_dir / "test_common.blf"))
    print(f"  已生成: {output_dir / 'test_common.blf'}")

    generate_blf_unique(str(output_dir / "test_unique_a.blf"))
    print(f"  已生成: {output_dir / 'test_unique_a.blf'}")

    generate_blf_unique2(str(output_dir / "test_unique_b.blf"))
    print(f"  已生成: {output_dir / 'test_unique_b.blf'}")

    print("\n测试文件说明:")
    print("=" * 60)
    print("PCAP文件 (SomeIP over UDP):")
    print("  test_common.pcap:     Service IDs: 0x1234, 0x5678, 0xAAAA")
    print("  test_unique_a.pcap:   Service IDs: 0x1234, 0xBBBB, 0xCCCC")
    print("  test_unique_b.pcap:   Service IDs: 0x1234, 0xDDDD")
    print()
    print("BLF文件 (CAN messages):")
    print("  test_common.blf:      CAN IDs: 0x100(ch0), 0x200(ch1), 0x300(ch0)")
    print("  test_unique_a.blf:    CAN IDs: 0x100(ch0), 0x400(ch2)")
    print("  test_unique_b.blf:    CAN IDs: 0x200(ch1), 0x500(ch3)")
    print()
    print("预期对比结果 (test_common.pcap vs test_unique_a.pcap):")
    print("  相同 SomeIP: (0x1234, 10.0.0.1), (0x1234, 10.0.0.2)")
    print("  仅文件1:     (0x5678, 10.0.0.4), (0x5678, 10.0.0.3), (0xAAAA, 10.0.0.6), (0xAAAA, 10.0.0.5)")
    print("  仅文件2:     (0xBBBB, 10.0.0.7), (0xBBBB, 10.0.0.8), (0xCCCC, 10.0.0.9), (0xCCCC, 10.0.0.10)")
    print()
    print("预期对比结果 (test_common.blf vs test_unique_a.blf):")
    print("  相同 CAN:    (0x100, ch0)")
    print("  仅文件1:     (0x200, ch1), (0x300, ch0)")
    print("  仅文件2:     (0x400, ch2)")


if __name__ == "__main__":
    main()
