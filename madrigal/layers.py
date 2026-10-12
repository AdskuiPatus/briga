"""Разбор кадров: Ethernet (с VLAN) → IPv4 → TCP.

Разбор каждого пакета возвращает Parsed с явными warnings/errors:
неподдерживаемые данные диагностируются, а не подменяются.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

ETHERTYPE_IPV4 = 0x0800
_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

TCP_FLAG_NAMES = (
    (FLAG_FIN, "FIN"), (FLAG_SYN, "SYN"), (FLAG_RST, "RST"),
    (FLAG_PSH, "PSH"), (FLAG_ACK, "ACK"), (FLAG_URG, "URG"),
)


def tcp_flags_str(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return ",".join(names) if names else "-"


@dataclass
class Ethernet:
    dst: bytes
    src: bytes
    ethertype: int
    vlan_ids: List[int] = field(default_factory=list)


@dataclass
class IPv4:
    src: str
    dst: str
    protocol: int
    header_len: int
    total_len: int
    identification: int
    frag_offset: int
    more_fragments: bool
    ttl: int


@dataclass
class TCP:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int
    header_len: int

    @property
    def syn(self) -> bool:
        return bool(self.flags & FLAG_SYN)

    @property
    def fin(self) -> bool:
        return bool(self.flags & FLAG_FIN)

    @property
    def rst(self) -> bool:
        return bool(self.flags & FLAG_RST)

    @property
    def ack_flag(self) -> bool:
        return bool(self.flags & FLAG_ACK)

    @property
    def flags_str(self) -> str:
        return tcp_flags_str(self.flags)


@dataclass
class Parsed:
    """Результат разбора одного кадра."""

    index: int = -1
    ethernet: Optional[Ethernet] = None
    ip4: Optional[IPv4] = None
    tcp: Optional[TCP] = None
    payload: bytes = b""
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.tcp is not None


def _parse_ethernet(data: bytes) -> tuple[Optional[Ethernet], Optional[str], int]:
    if len(data) < 14:
        return None, f"кадр короче Ethernet-заголовка ({len(data)} Б)", 0
    dst, src = data[0:6], data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]
    off = 14
    vlans: List[int] = []
    while ethertype in _VLAN_ETHERTYPES:
        if len(data) < off + 4:
            return None, "VLAN-заголовок обрезан", off
        tci, ethertype = struct.unpack("!HH", data[off:off + 4])
        vlans.append(tci & 0x0FFF)
        off += 4
        if len(vlans) > 2:
            break
    return Ethernet(dst=dst, src=src, ethertype=ethertype, vlan_ids=vlans), None, off


def _parse_ipv4(
    data: bytes, off: int
) -> tuple[Optional[IPv4], Optional[str], List[str], int, int]:
    """Возвращает (ip, error, warnings, tcp_off, ip_end).

    ip_end — конец IP-пакета по полю total_len (ограничен размером кадра):
    именно им ограничивается полезная нагрузка TCP, чтобы не захватить
   Ethernet-выравнивание коротких кадров (минимум 60 Б) как «данные».
    """
    warnings: List[str] = []
    if len(data) < off + 20:
        return None, "IPv4-заголовок обрезан", warnings, off, off
    vihl = data[off]
    version, ihl_bits = vihl >> 4, vihl & 0x0F
    if version != 4:
        return None, f"не IPv4 (version={version})", warnings, off, off
    ihl = ihl_bits * 4
    if ihl < 20:
        return None, f"некорректная длина IPv4-заголовка ({ihl})", warnings, off, off
    if len(data) < off + ihl:
        return None, "IPv4-заголовок обрезан", warnings, off, off

    total_len, ident, frag, ttl, proto, _csum = struct.unpack(
        "!HHHBBH", data[off + 2:off + 12]
    )
    frag_offset = frag & 0x1FFF
    more_frags = bool(frag & 0x2000)
    src = ".".join(str(b) for b in data[off + 12:off + 16])
    dst = ".".join(str(b) for b in data[off + 16:off + 20])

    ip = IPv4(
        src=src, dst=dst, protocol=proto, header_len=ihl, total_len=total_len,
        identification=ident, frag_offset=frag_offset, more_fragments=more_frags,
        ttl=ttl,
    )

    if frag_offset or more_frags:
        warnings.append(
            "IP-фрагментация (вне условий кейса): "
            f"offset={frag_offset}, MF={more_frags}"
        )
    end = off + total_len if total_len else len(data)
    if total_len and end > len(data):
        warnings.append(
            f"IP-пакет усечён в записи: заявлено {total_len} Б, доступно {len(data) - off} Б"
        )
        end = len(data)
    if frag_offset:
        # не первый фрагмент — TCP-заголовок недоступен
        return ip, None, warnings, end, end
    return ip, None, warnings, off + ihl, end


def _parse_tcp(
    data: bytes, off: int, end: int
) -> tuple[Optional[TCP], Optional[str], bytes]:
    """Разобрать TCP-заголовок; полезная нагрузка ограничена end (концом IP-пакета).

    Без ограничения end к коротким кадрам (равным 60-байтовому минимуму Ethernet)
    подмешивалось бы выравнивающее заполнение как будто это данные.
    """
    if len(data) < off + 20:
        return None, "TCP-заголовок обрезан", b""
    sport, dport, seq, ack = struct.unpack("!HHII", data[off:off + 12])
    off_flags = struct.unpack("!H", data[off + 12:off + 14])[0]
    doff = (off_flags >> 12) * 4
    flags = off_flags & 0x01FF
    if doff < 20:
        return None, f"некорректная длина TCP-заголовка ({doff})", b""
    if len(data) < off + doff:
        return None, "TCP-заголовок обрезан", b""
    window = struct.unpack("!H", data[off + 14:off + 16])[0]
    tcp = TCP(
        src_port=sport, dst_port=dport, seq=seq, ack=ack,
        flags=flags, window=window, header_len=doff,
    )
    payload_start = off + doff
    payload_end = max(payload_start, min(end, len(data)))
    return tcp, None, data[payload_start:payload_end]


def parse_packet(data: bytes, linktype: int, index: int = -1) -> Parsed:
    """Разобрать один кадр. Ошибки не бросаются — возвращаются в Parsed."""
    if linktype != 1:
        return Parsed(
            index=index,
            error=f"неподдерживаемый linktype {linktype} (ожидается Ethernet=1)",
        )

    eth, err, off = _parse_ethernet(data)
    if err:
        return Parsed(index=index, error=err)

    parsed = Parsed(index=index, ethernet=eth)

    if eth.ethertype != ETHERTYPE_IPV4:
        parsed.error = f"не IPv4 (ethertype 0x{eth.ethertype:04X})"
        return parsed

    ip, err, ip_warnings, tcp_off, ip_end = _parse_ipv4(data, off)
    parsed.warnings.extend(ip_warnings)
    if err:
        parsed.error = err
        return parsed
    parsed.ip4 = ip
    if ip is None:
        return parsed
    if ip.protocol != 6:
        parsed.error = f"не TCP (IPv4 protocol={ip.protocol})"
        return parsed
    if ip.frag_offset:
        parsed.error = "не первый IP-фрагмент — TCP-заголовок недоступен"
        return parsed

    tcp, err, payload = _parse_tcp(data, tcp_off, ip_end)
    if err:
        parsed.error = err
        return parsed
    parsed.tcp = tcp
    parsed.payload = payload
    return parsed


def parse_capture(capture) -> List[Parsed]:
    """Разобрать все пакеты записи (параллельно списку capture.packets)."""
    out: List[Parsed] = []
    for pkt in capture.packets:
        p = parse_packet(pkt.data, pkt.linktype, index=pkt.index)
        if pkt.truncated:
            p.warnings.append(
                f"кадр усечён при захвате: {len(pkt.data)} из {pkt.orig_len} Б"
            )
        out.append(p)
    return out
