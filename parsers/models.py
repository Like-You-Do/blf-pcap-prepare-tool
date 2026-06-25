from dataclasses import dataclass


@dataclass(frozen=True)
class SomeIPEntry:
    service_id: int
    ip_address: str
    source: str


@dataclass(frozen=True)
class CANEntry:
    can_id: int
    channel_id: int
    source: str
