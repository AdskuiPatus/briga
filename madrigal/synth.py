"""Генератор синтетических записей для тестов и демонстрации.

Строит настоящие Ethernet/IPv4/TCP-кадры и записывает их в PCAP или PCAPNG,
поэтому тесты проверяют тот же код, что и работает на реальных файлах.
"""

from __future__ import annotations

import struct
from pathlib import Path

LINKTYPE_ETHERNET = 1

_FLAG_NIBBLES = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def tcp_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.2",
    sport: int = 51000,
    dport: int = 5000,
    seq: int = 1000,
    ack: int = 0,
    flags: str = "A",
    payload: bytes = b"",
    ttl: int = 64,
    identification: int = 0x1234,
) -> bytes:
    """Собрать один Ethernet/IPv4/TCP-кадр.

    flags — строка-набор букв: S Y N A P F R U (например 'SA', 'PA', 'FA').
    checksum TCP намеренно 0 (парсер его не валидирует; политика checksum —
    отдельная настройка инструмента).
    """
    flag_bits = 0
    for ch in flags.upper():
        flag_bits |= _FLAG_NIBBLES.get(ch, 0)

    tcp_wo = struct.pack(
        "!HHIIHHHH",
        sport, dport, seq, ack,
        (5 << 12) | flag_bits,   # data offset = 5 слов (20 Б)
        65535, 0, 0,
    )
    tcp_seg = tcp_wo + payload

    ip_len = 20 + len(tcp_seg)
    ip_wo = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, identification, 0x4000, ttl, 6, 0,
        _ip_bytes(src_ip), _ip_bytes(dst_ip),
    )
    ip_hdr = ip_wo[:10] + struct.pack("!H", _checksum16(ip_wo)) + ip_wo[12:]

    eth = (
        bytes.fromhex("001122334455")      # dst mac
        + bytes.fromhex("665544332211")    # src mac
        + struct.pack("!H", 0x0800)
    )
    return eth + ip_hdr + tcp_seg


def write_pcap(path: str | Path, packets: list[tuple[float, bytes]],
               linktype: int = LINKTYPE_ETHERNET) -> None:
    """Записать классический PCAP (microsecond, little-endian)."""
    out = bytearray()
    out += struct.pack("<I", 0xA1B2C3D4)
    out += struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype)
    for ts, data in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        out += struct.pack("<IIII", sec, usec, len(data), len(data))
        out += data
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(bytes(out))


def write_pcapng(path: str | Path, packets: list[tuple[float, bytes]],
                 linktype: int = LINKTYPE_ETHERNET) -> None:
    """Записать PCAPNG (little-endian, один интерфейс, EPB, tsresol=1e-6)."""
    def block(btype: int, payload: bytes) -> bytes:
        pad = (-len(payload)) % 4
        payload += b"\x00" * pad
        total = 12 + len(payload)
        return (struct.pack("<II", btype, total) + payload
                + struct.pack("<I", total))

    out = bytearray()
    # SHB
    out += block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    # IDB
    out += block(0x00000001, struct.pack("<HHI", linktype, 0, 0))
    # EPB
    for ts, data in packets:
        ts_raw = int(round(ts * 1_000_000))
        cap = len(data)
        payload = struct.pack(
            "<IIIII", 0, ts_raw >> 32, ts_raw & 0xFFFFFFFF, cap, cap
        ) + data
        out += block(0x00000006, payload)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(bytes(out))
