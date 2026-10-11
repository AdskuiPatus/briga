"""Чтение записей трафика: PCAP и PCAPNG (только стандартная библиотека).

Поддержаны:
  * классический PCAP (usec/nsec, оба порядка байт);
  * PCAPNG: SHB, IDB (в т.ч. опция tsresol), EPB, SPB; прочие блоки
    пропускаются с сохранением потока чтения.

Ошибки формата диагностируются ясно (CaptureError/UnsupportedCapture),
неподдерживаемые данные не подменяются.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

LINKTYPE_ETHERNET = 1

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1e-6),   # usec, little-endian
    0xA1B23C4D: ("<", 1e-9),   # nsec, little-endian
    0xD4C3B2A1: (">", 1e-6),   # usec, big-endian
    0x4D3CB2A1: (">", 1e-9),   # nsec, big-endian
}

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006

_OPT_TSRESOL = 9


class CaptureError(Exception):
    """Ошибка чтения записи."""


class UnsupportedCapture(CaptureError):
    """Формат или тип канального уровня не поддерживается."""


@dataclass
class Packet:
    """Один пакет (кадр) из записи."""

    index: int
    timestamp: float
    linktype: int
    data: bytes
    orig_len: int
    interface_id: int = 0

    @property
    def truncated(self) -> bool:
        """Кадр усечён относительно оригинальной длины."""
        return self.orig_len > len(self.data)


@dataclass
class Capture:
    """Прочитанная запись трафика."""

    path: str
    fmt: str                      # 'pcap' | 'pcapng'
    packets: List[Packet]
    sha256: str
    notes: List[str] = field(default_factory=list)

    @property
    def linktypes(self) -> List[int]:
        return sorted({p.linktype for p in self.packets})

    @property
    def sha256_short(self) -> str:
        return self.sha256[:16]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def open_capture(path: str | Path) -> Capture:
    """Открыть PCAP/PCAPNG и вернуть объект Capture."""
    p = Path(path)
    if not p.is_file():
        raise CaptureError(f"файл не найден: {p}")

    with open(p, "rb") as f:
        head = f.read(4)
    if len(head) < 4:
        raise CaptureError(f"{p.name}: файл слишком мал для записи трафика")

    if head == b"\x0a\x0d\x0d\x0a":
        fmt = "pcapng"
        packets, notes = _read_pcapng(p)
    else:
        fmt = "pcap"
        packets, notes = _read_pcap(p)

    return Capture(
        path=str(p),
        fmt=fmt,
        packets=packets,
        sha256=_sha256_file(p),
        notes=notes,
    )


# ---------------------------------------------------------------- PCAP ----

def _read_pcap(path: Path) -> tuple[List[Packet], List[str]]:
    packets: List[Packet] = []
    notes: List[str] = []

    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise CaptureError(f"{path.name}: PCAP: глобальный заголовок обрезан")

        magic = struct.unpack("<I", gh[:4])[0]
        info = _PCAP_MAGICS.get(magic)
        if info is None:
            raise UnsupportedCapture(
                f"{path.name}: неизвестный magic PCAP 0x{magic:08X}"
            )
        endian, frac_scale = info

        _vmaj, _vmin, _zone, _sigfigs, _snaplen, linktype = struct.unpack(
            endian + "HHIIII", gh[4:]
        )
        if linktype not in (LINKTYPE_ETHERNET,):
            notes.append(
                f"linktype {linktype} не Ethernet({LINKTYPE_ETHERNET}) — "
                "разбор пакетов будет диагностироваться как неподдерживаемый"
            )

        idx = 0
        while True:
            hdr = f.read(16)
            if not hdr:
                break
            if len(hdr) < 16:
                notes.append(f"пакет #{idx}: заголовок обрезан — чтение остановлено")
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                notes.append(
                    f"пакет #{idx}: данные обрезаны "
                    f"(ожидалось {incl_len}, получено {len(data)})"
                )
                break
            packets.append(
                Packet(
                    index=idx,
                    timestamp=ts_sec + ts_frac * frac_scale,
                    linktype=linktype,
                    data=data,
                    orig_len=orig_len,
                )
            )
            idx += 1

    return packets, notes


# -------------------------------------------------------------- PCAPNG ----

def _iter_pcapng_options(buf: bytes, endian: str):
    """Итератор по опциям блока pcapng: (code, value)."""
    off = 0
    while off + 4 <= len(buf):
        code, length = struct.unpack(endian + "HH", buf[off:off + 4])
        off += 4
        if code == 0:  # opt_endofopt
            break
        if off + length > len(buf):
            break
        yield code, buf[off:off + length]
        off += (length + 3) & ~3  # выравнивание 32 бит


def _read_pcapng(path: Path) -> tuple[List[Packet], List[str]]:
    packets: List[Packet] = []
    notes: List[str] = []
    endian: str | None = None
    ifaces: list[dict] = []
    section_no = 0

    with open(path, "rb") as f:
        while True:
            head = f.read(8)
            if not head:
                break
            if len(head) < 8:
                notes.append("хвостовой заголовок блока обрезан")
                break

            if head[:4] == b"\x0a\x0d\x0d\x0a":
                # --- SHB: порядок байт узнаётся по BOM ---
                bom = f.read(4)
                if len(bom) < 4:
                    raise CaptureError(f"{path.name}: PCAPNG: SHB обрезан")
                if struct.unpack("<I", bom)[0] == 0x1A2B3C4D:
                    endian = "<"
                elif struct.unpack(">I", bom)[0] == 0x1A2B3C4D:
                    endian = ">"
                else:
                    raise UnsupportedCapture(
                        f"{path.name}: PCAPNG: неверный byte order magic"
                    )
                total = struct.unpack(endian + "I", head[4:8])[0]
                if total < 28 or total % 4 != 0:
                    raise CaptureError(
                        f"{path.name}: PCAPNG: подозрительная длина SHB ({total})"
                    )
                rest = f.read(total - 12)  # BOM(4) уже прочитаны
                if len(rest) != total - 12:
                    raise CaptureError(f"{path.name}: PCAPNG: SHB обрезан")
                if section_no > 0:
                    notes.append("начало новой секции PCAPNG — интерфейсы сброшены")
                section_no += 1
                ifaces = []
                continue

            if endian is None:
                raise UnsupportedCapture(
                    f"{path.name}: PCAPNG: первый блок не SHB"
                )

            btype = struct.unpack(endian + "I", head[:4])[0]
            total = struct.unpack(endian + "I", head[4:8])[0]
            if total < 12 or total % 4 != 0:
                raise CaptureError(
                    f"{path.name}: PCAPNG: подозрительная длина блока 0x{btype:08X} "
                    f"({total})"
                )
            body = f.read(total - 8)
            if len(body) != total - 8:
                notes.append(f"блок 0x{btype:08X} обрезан — чтение остановлено")
                break
            payload = body[:-4]  # отсечь повторную длину блока

            if btype == _PCAPNG_IDB:
                if len(payload) < 8:
                    notes.append("IDB обрезан — пропущен")
                    continue
                linktype, _res, snaplen = struct.unpack(endian + "HHI", payload[:8])
                ts_pow2 = False
                ts_exp = 6
                for code, val in _iter_pcapng_options(payload[8:], endian):
                    if code == _OPT_TSRESOL and len(val) == 1:
                        ts_pow2 = bool(val[0] & 0x80)
                        ts_exp = val[0] & 0x7F
                if linktype != LINKTYPE_ETHERNET:
                    notes.append(
                        f"интерфейс #{len(ifaces)}: linktype {linktype} не Ethernet — "
                        "разбор пакетов диагностируется как неподдерживаемый"
                    )
                ifaces.append(
                    {"linktype": linktype, "snaplen": snaplen,
                     "ts_pow2": ts_pow2, "ts_exp": ts_exp}
                )

            elif btype == _PCAPNG_EPB:
                if len(payload) < 20:
                    notes.append("EPB обрезан — пропущен")
                    continue
                iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                    endian + "IIIII", payload[:20]
                )
                data = payload[20:20 + cap_len]
                if len(data) < cap_len:
                    notes.append("EPB: данные пакета обрезаны")
                iface = ifaces[iface_id] if iface_id < len(ifaces) else None
                if iface is None:
                    notes.append(
                        f"EPB ссылается на несуществующий интерфейс #{iface_id}"
                    )
                    linktype, ts_units = LINKTYPE_ETHERNET, 1e-6
                else:
                    linktype = iface["linktype"]
                    if iface["ts_pow2"]:
                        ts_units = 2.0 ** (-iface["ts_exp"])
                    else:
                        ts_units = 10.0 ** (-iface["ts_exp"])
                ts = ((ts_hi << 32) | ts_lo) * ts_units
                packets.append(
                    Packet(
                        index=len(packets),
                        timestamp=ts,
                        linktype=linktype,
                        data=bytes(data),
                        orig_len=orig_len,
                        interface_id=iface_id,
                    )
                )

            elif btype == _PCAPNG_SPB:
                if len(payload) < 4:
                    notes.append("SPB обрезан — пропущен")
                    continue
                (orig_len,) = struct.unpack(endian + "I", payload[:4])
                raw = payload[4:]
                iface = ifaces[0] if ifaces else None
                snaplen = iface["snaplen"] if iface else 0
                cap_len = orig_len if not snaplen else min(orig_len, snaplen)
                cap_len = min(cap_len, len(raw))
                packets.append(
                    Packet(
                        index=len(packets),
                        timestamp=0.0,
                        linktype=iface["linktype"] if iface else LINKTYPE_ETHERNET,
                        data=bytes(raw[:cap_len]),
                        orig_len=orig_len,
                    )
                )

            # прочие блоки (NRB, ISB, пользовательские) — уже прочитаны, пропускаем

    if not packets:
        notes.append("в записи нет пакетов")
    return packets, notes
