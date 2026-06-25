from dataclasses import dataclass, field
from parsers.models import SomeIPEntry, CANEntry


@dataclass
class CompareResult:
    common_someip: list[tuple[SomeIPEntry, SomeIPEntry]] = field(default_factory=list)
    only_in_file1: list[SomeIPEntry] = field(default_factory=list)
    only_in_file2: list[SomeIPEntry] = field(default_factory=list)
    common_can: list[tuple[CANEntry, CANEntry]] = field(default_factory=list)
    only_can_in_file1: list[CANEntry] = field(default_factory=list)
    only_can_in_file2: list[CANEntry] = field(default_factory=list)


def compare_someip(
    entries1: set[SomeIPEntry], entries2: set[SomeIPEntry]
) -> tuple[list[tuple[SomeIPEntry, SomeIPEntry]], list[SomeIPEntry], list[SomeIPEntry]]:
    key1 = {(e.service_id, e.ip_address) for e in entries1}
    key2 = {(e.service_id, e.ip_address) for e in entries2}

    common_keys = key1 & key2
    only1_keys = key1 - key2
    only2_keys = key2 - key1

    lookup1 = {(e.service_id, e.ip_address): e for e in entries1}
    lookup2 = {(e.service_id, e.ip_address): e for e in entries2}

    common = [(lookup1[k], lookup2[k]) for k in common_keys]
    only1 = [lookup1[k] for k in only1_keys]
    only2 = [lookup2[k] for k in only2_keys]

    return common, only1, only2


def compare_can(
    entries1: set[CANEntry], entries2: set[CANEntry]
) -> tuple[list[tuple[CANEntry, CANEntry]], list[CANEntry], list[CANEntry]]:
    key1 = {(e.can_id, e.channel_id) for e in entries1}
    key2 = {(e.can_id, e.channel_id) for e in entries2}

    common_keys = key1 & key2
    only1_keys = key1 - key2
    only2_keys = key2 - key1

    lookup1 = {(e.can_id, e.channel_id): e for e in entries1}
    lookup2 = {(e.can_id, e.channel_id): e for e in entries2}

    common = [(lookup1[k], lookup2[k]) for k in common_keys]
    only1 = [lookup1[k] for k in only1_keys]
    only2 = [lookup2[k] for k in only2_keys]

    return common, only1, only2


def compare_files(
    someip1: set[SomeIPEntry],
    someip2: set[SomeIPEntry],
    can1: set[CANEntry],
    can2: set[CANEntry],
) -> CompareResult:
    common_someip, only1_someip, only2_someip = compare_someip(someip1, someip2)
    common_can, only1_can, only2_can = compare_can(can1, can2)

    return CompareResult(
        common_someip=common_someip,
        only_in_file1=only1_someip,
        only_in_file2=only2_someip,
        common_can=common_can,
        only_can_in_file1=only1_can,
        only_can_in_file2=only2_can,
    )
