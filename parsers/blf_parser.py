import logging
from can import BLFReader
from scapy.contrib.automotive.someip import SOMEIP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

from .models import SomeIPEntry, CANEntry

logger = logging.getLogger(__name__)


def parse_blf(filepath: str) -> tuple[set[SomeIPEntry], set[CANEntry]]:
    someip_entries = set()
    can_entries = set()

    can_entries = _parse_can(filepath)
    someip_entries = _parse_ethernet_with_asammdf(filepath)

    return someip_entries, can_entries


def _parse_can(filepath: str) -> set[CANEntry]:
    entries = set()
    try:
        reader = BLFReader(filepath)
        for msg in reader:
            if msg.is_fd:
                continue

            if msg.channel is not None and msg.arbitration_id is not None:
                entries.add(CANEntry(
                    can_id=msg.arbitration_id,
                    channel_id=msg.channel,
                    source=filepath,
                ))
    except Exception as e:
        logger.warning("CAN解析失败 %s: %s", filepath, e)

    return entries


def _parse_ethernet_with_asammdf(filepath: str) -> set[SomeIPEntry]:
    entries = set()
    try:
        from asammdf import MDF
        mdf = MDF(filepath)

        for group in mdf.groups:
            for channel in group.channels:
                if "ethernet" in channel.name.lower() or "someip" in channel.name.lower():
                    try:
                        data = mdf.get(channel.name)
                        if data is not None:
                            for sample in data.samples:
                                _try_parse_someip_from_bytes(sample, entries, filepath)
                    except Exception:
                        pass
    except ImportError:
        logger.info("asammdf未安装，回退到BLF二进制解析")
        _parse_blf_binary_fallback(filepath, entries)
    except Exception as e:
        logger.warning("asammdf以太网解析失败 %s: %s", filepath, e)
        _parse_blf_binary_fallback(filepath, entries)

    return entries


def _try_parse_someip_from_bytes(
    raw_data: bytes, entries: set[SomeIPEntry], filepath: str
):
    try:
        if len(raw_data) < 34:
            return

        pkt = Ether(raw_data)
        if pkt.haslayer(IP) and pkt.haslayer(SOMEIP):
            someip_layer = pkt.getlayer(SOMEIP)
            service_id = someip_layer.srv_id
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            entries.add(SomeIPEntry(
                service_id=service_id,
                ip_address=src_ip,
                source=filepath,
            ))
            entries.add(SomeIPEntry(
                service_id=service_id,
                ip_address=dst_ip,
                source=filepath,
            ))
    except Exception:
        pass


def _parse_blf_binary_fallback(filepath: str, entries: set[SomeIPEntry]):
    import struct

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        if len(data) < 14:
            return

        if data[:4] != b"BLF\x00":
            return

        offset = 14
        while offset < len(data) - 4:
            if data[offset:offset + 4] != b"LOBJ":
                offset += 1
                continue

            if offset + 16 > len(data):
                break

            obj_type = struct.unpack_from("<H", data, offset + 6)[0]

            if obj_type == 71:
                _parse_ethernet_frame_object(data, offset, entries, filepath)

            next_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if next_offset == 0 or next_offset <= offset:
                offset += 1
            else:
                offset = next_offset
    except Exception as e:
        logger.warning("BLF二进制解析失败 %s: %s", filepath, e)


def _parse_ethernet_frame_object(
    data: bytes, offset: int, entries: set[SomeIPEntry], filepath: str
):
    import struct

    try:
        if offset + 64 > len(data):
            return

        obj_size = struct.unpack_from("<I", data, offset + 12)[0]
        payload_offset = offset + 64
        payload_len = obj_size - 64
        if payload_len <= 0:
            return

        payload = data[payload_offset:payload_offset + payload_len]

        _try_parse_someip_from_bytes(payload, entries, filepath)
    except Exception:
        pass
