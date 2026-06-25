from scapy.all import rdpcap, UDP
from scapy.contrib.automotive.someip import SOMEIP
from scapy.layers.inet import IP

from .models import SomeIPEntry


def parse_pcap(filepath: str) -> set[SomeIPEntry]:
    packets = rdpcap(filepath)
    entries = set()

    for pkt in packets:
        if not pkt.haslayer(UDP):
            continue

        someip_layer = pkt.getlayer(SOMEIP)
        if someip_layer is None:
            continue

        if not pkt.haslayer(IP):
            continue

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

    return entries
