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
    import zlib

    LOG_CONTAINER = 10
    ETHERNET_FRAME = 71

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        if len(data) < 144:
            return

        if data[:4] != b"LOGG":
            return

        offset = 144
        while offset < len(data) - 16:
            if data[offset:offset + 4] != b"LOBJ":
                break

            hs = struct.unpack_from("<H", data, offset + 4)[0]
            hv = struct.unpack_from("<H", data, offset + 6)[0]
            obj_size = struct.unpack_from("<I", data, offset + 8)[0]
            obj_type = struct.unpack_from("<I", data, offset + 12)[0]

            if obj_type == LOG_CONTAINER:
                cont_offset = offset + 16
                if cont_offset + 16 > len(data):
                    break
                compression = struct.unpack_from("<H", data, cont_offset)[0]
                comp_data = data[cont_offset + 16:offset + obj_size]
                if compression == 2:
                    container_data = zlib.decompress(comp_data)
                elif compression == 0:
                    container_data = comp_data
                else:
                    offset += obj_size
                    continue
                _scan_container_for_ethernet(container_data, entries, filepath)

            next_offset = offset + obj_size
            if next_offset <= offset:
                break
            offset = next_offset
    except Exception as e:
        logger.warning("BLF二进制解析失败 %s: %s", filepath, e)


def _scan_container_for_ethernet(
    data: bytes, entries: set[SomeIPEntry], filepath: str
):
    import struct

    ETHERNET_FRAME = 71
    pos = 0

    while pos < len(data) - 16:
        try:
            pos = data.index(b"LOBJ", pos, pos + 8)
        except ValueError:
            break

        hs = struct.unpack_from("<H", data, pos + 4)[0]
        hv = struct.unpack_from("<H", data, pos + 6)[0]
        obj_size = struct.unpack_from("<I", data, pos + 8)[0]
        obj_type = struct.unpack_from("<I", data, pos + 12)[0]

        if obj_type == ETHERNET_FRAME:
            payload = data[pos + 16:pos + obj_size]
            _try_parse_someip_from_bytes(payload, entries, filepath)

        next_pos = pos + obj_size
        if next_pos <= pos:
            break
        pos = next_pos
