import struct
import zlib
from pathlib import Path

from scapy.all import Ether, IP, UDP, Raw, wrpcap
from scapy.contrib.automotive.someip import SOMEIP
from can import Message
from can.io.blf import BLFWriter


def create_someip_packet(
    src_ip: str,
    dst_ip: str,
    service_id: int,
    method_id: int = 0x0001,
    session_id: int = 1,
):
    someip = SOMEIP(
        srv_id=service_id,
        sub_id=method_id,
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


def _make_someip_ethernet_raw(src_ip, dst_ip, service_id, method_id=0x0001):
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x00\x11\x22\x33\x44\x55' + b'\x08\x00'
    total_len = 20 + 8 + 16 + 16
    ip = b'\x45\x00'
    ip += struct.pack('>HH', total_len, 0)
    ip += b'\x40\x00'
    ip += b'\x40\x11\x00\x00'
    ip += bytes(int(x) for x in src_ip.split('.'))
    ip += bytes(int(x) for x in dst_ip.split('.'))
    udp_len = 8 + 16 + 16
    udp = struct.pack('>HH', 30490, 30490) + struct.pack('>H', udp_len) + b'\x00\x00'
    someip = struct.pack('>HH', service_id, method_id)
    someip += struct.pack('>HH', 0x0001, 0x0001)
    someip += struct.pack('>BBBB', 1, 1, 0, 0)
    someip += struct.pack('>I', 16)
    someip += b'\x00' * 16
    return eth + ip + udp + someip


def _make_eth_frame_lobject(raw_eth_data):
    header_size = 16
    obj_size = header_size + len(raw_eth_data)
    lobj = b'LOBJ'
    lobj += struct.pack('<H', header_size)
    lobj += struct.pack('<H', 1)
    lobj += struct.pack('<I', obj_size)
    lobj += struct.pack('<I', 71)
    lobj += raw_eth_data
    return lobj


def generate_pcap(path: str, packets):
    wrpcap(path, packets)


def generate_blf(path: str, can_messages, someip_eth_frames):
    temp_blf = path + ".tmp"

    with BLFWriter(temp_blf) as w:
        for m in can_messages:
            w.on_message_received(m)

    with open(temp_blf, "rb") as f:
        blf_data = f.read()

    offset = 144
    obj_size = struct.unpack_from("<I", blf_data, offset + 8)[0]
    cont_offset = offset + 16
    compression = struct.unpack_from("<H", blf_data, cont_offset)[0]
    comp_data = blf_data[cont_offset + 16:offset + obj_size]
    decompressed = zlib.decompress(comp_data) if compression == 2 else comp_data

    for ef in someip_eth_frames:
        decompressed += _make_eth_frame_lobject(ef)

    new_compressed = zlib.compress(decompressed)

    with open(path, "wb") as f:
        f.write(blf_data[:144])
        cont_struct = struct.pack('<H', 2) + b'\x00' * 6
        cont_struct += struct.pack('<I', len(decompressed)) + b'\x00' * 4
        container_payload = cont_struct + new_compressed
        container_obj_size = 16 + len(container_payload)
        f.write(b'LOBJ')
        f.write(struct.pack('<H', 16))
        f.write(struct.pack('<H', 1))
        f.write(struct.pack('<I', container_obj_size))
        f.write(struct.pack('<I', 10))
        f.write(container_payload)
        pad = (4 - (container_obj_size % 4)) % 4
        f.write(b'\x00' * pad)

    Path(temp_blf).unlink(missing_ok=True)


def main():
    output_dir = Path(__file__).parent / "test_data"
    output_dir.mkdir(exist_ok=True)

    print("生成测试文件...")

    # --- test_common ---
    pcap_common = [
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0002),
        create_someip_packet("10.0.0.3", "10.0.0.4", 0x5678, 0x0001),
        create_someip_packet("10.0.0.5", "10.0.0.6", 0xAAAA, 0x0001),
    ]
    generate_pcap(str(output_dir / "test_common.pcap"), pcap_common)

    blf_common_can = [
        Message(arbitration_id=0x100, channel=0, data=b"\x01\x02\x03\x04"),
        Message(arbitration_id=0x200, channel=1, data=b"\x05\x06\x07\x08"),
        Message(arbitration_id=0x300, channel=0, data=b"\x09\x0A\x0B\x0C"),
    ]
    blf_common_eth = [
        _make_someip_ethernet_raw("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        _make_someip_ethernet_raw("10.0.0.1", "10.0.0.2", 0x1234, 0x0002),
        _make_someip_ethernet_raw("10.0.0.3", "10.0.0.4", 0x5678, 0x0001),
        _make_someip_ethernet_raw("10.0.0.5", "10.0.0.6", 0xAAAA, 0x0001),
    ]
    generate_blf(str(output_dir / "test_common.blf"), blf_common_can, blf_common_eth)
    print(f"  已生成: {output_dir / 'test_common.pcap'}")
    print(f"  已生成: {output_dir / 'test_common.blf'}")

    # --- test_unique_a ---
    pcap_unique_a = [
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        create_someip_packet("10.0.0.7", "10.0.0.8", 0xBBBB, 0x0001),
        create_someip_packet("10.0.0.9", "10.0.0.10", 0xCCCC, 0x0001),
    ]
    generate_pcap(str(output_dir / "test_unique_a.pcap"), pcap_unique_a)

    blf_unique_a_can = [
        Message(arbitration_id=0x100, channel=0, data=b"\x01\x02\x03\x04"),
        Message(arbitration_id=0x400, channel=2, data=b"\x0D\x0E\x0F\x10"),
    ]
    blf_unique_a_eth = [
        _make_someip_ethernet_raw("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        _make_someip_ethernet_raw("10.0.0.7", "10.0.0.8", 0xBBBB, 0x0001),
        _make_someip_ethernet_raw("10.0.0.9", "10.0.0.10", 0xCCCC, 0x0001),
    ]
    generate_blf(str(output_dir / "test_unique_a.blf"), blf_unique_a_can, blf_unique_a_eth)
    print(f"  已生成: {output_dir / 'test_unique_a.pcap'}")
    print(f"  已生成: {output_dir / 'test_unique_a.blf'}")

    # --- test_unique_b ---
    pcap_unique_b = [
        create_someip_packet("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        create_someip_packet("10.0.0.11", "10.0.0.12", 0xDDDD, 0x0001),
    ]
    generate_pcap(str(output_dir / "test_unique_b.pcap"), pcap_unique_b)

    blf_unique_b_can = [
        Message(arbitration_id=0x200, channel=1, data=b"\x05\x06\x07\x08"),
        Message(arbitration_id=0x500, channel=3, data=b"\x11\x12\x13\x14"),
    ]
    blf_unique_b_eth = [
        _make_someip_ethernet_raw("10.0.0.1", "10.0.0.2", 0x1234, 0x0001),
        _make_someip_ethernet_raw("10.0.0.11", "10.0.0.12", 0xDDDD, 0x0001),
    ]
    generate_blf(str(output_dir / "test_unique_b.blf"), blf_unique_b_can, blf_unique_b_eth)
    print(f"  已生成: {output_dir / 'test_unique_b.pcap'}")
    print(f"  已生成: {output_dir / 'test_unique_b.blf'}")

    print("\n测试文件说明:")
    print("=" * 60)
    print("PCAP & BLF 共享相同 SomeIP 数据:")
    print("  test_common:    0x1234(10.0.0.1/2), 0x5678(10.0.0.3/4), 0xAAAA(10.0.0.5/6)")
    print("  test_unique_a:  0x1234(10.0.0.1/2), 0xBBBB(10.0.0.7/8), 0xCCCC(10.0.0.9/10)")
    print("  test_unique_b:  0x1234(10.0.0.1/2), 0xDDDD(10.0.0.11/12)")
    print()
    print("BLF 额外包含 CAN 数据:")
    print("  test_common:    0x100(ch0), 0x200(ch1), 0x300(ch0)")
    print("  test_unique_a:  0x100(ch0), 0x400(ch2)")
    print("  test_unique_b:  0x200(ch1), 0x500(ch3)")
    print()
    print("预期对比结果 (test_common vs test_unique_a):")
    print("  SomeIP 相同: 0x1234(10.0.0.1), 0x1234(10.0.0.2)")
    print("  SomeIP 仅文件1: 0x5678(10.0.0.3), 0x5678(10.0.0.4), 0xAAAA(10.0.0.5), 0xAAAA(10.0.0.6)")
    print("  SomeIP 仅文件2: 0xBBBB(10.0.0.7), 0xBBBB(10.0.0.8), 0xCCCC(10.0.0.9), 0xCCCC(10.0.0.10)")
    print("  CAN 相同: 0x100(ch0)")
    print("  CAN 仅文件1: 0x200(ch1), 0x300(ch0)")
    print("  CAN 仅文件2: 0x400(ch2)")


if __name__ == "__main__":
    main()
