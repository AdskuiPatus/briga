"""Восстановление направленного TCP-потока (R1 кейса).

Свойства (проверяются тестами):
  * порядок байтов соответствует TCP sequence numbers независимо от порядка
    пакетов в записи;
  * одинаковые повторные передачи не дублируют байты, исходные пакеты сохраняются;
  * пропуски (gap) остаются неизвестными участками и НЕ подменяются нулями;
  * перекрытие с различающимися байтами фиксируется как неоднозначность
    с привязкой к пакетам, политика обработки — first-seen (воспроизводима);
  * каждый байт хранит происхождение: пакет, доставивший его первым.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from .layers import Parsed
from .sessions import Session

OVERLAP_POLICIES = ("first-seen",)
DEFAULT_OVERLAP_POLICY = "first-seen"


class UnknownDataError(Exception):
    """Попытка получить байты из неизвестного (недостающего) участка потока."""


@dataclass
class DataRun:
    """Непрерывный участок достоверных байтов потока."""

    start: int
    data: bytes
    packet: int  # индекс пакета, первым доставивший эти байты

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class GapRun:
    """Неизвестный участок потока (пропуск/усечение захвата)."""

    start: int
    length: int
    reason: str = "пропуск в захвате"

    @property
    def end(self) -> int:
        return self.start + self.length


Run = object  # DataRun | GapRun


@dataclass
class SliceResult:
    """Результат среза потока: достоверные куски + явно отмеченные пропуски."""

    offset: int
    length: int
    pieces: List[Tuple[int, bytes]] = field(default_factory=list)  # (смещение, байты)
    gaps: List["GapRun"] = field(default_factory=list)

    @property
    def known_bytes(self) -> int:
        return sum(len(b) for _, b in self.pieces)

    @property
    def is_complete(self) -> bool:
        return not self.gaps and self.known_bytes == self.length

    def to_bytes(self, fill: Optional[int] = None) -> bytes:
        """Собрать срез в один байтовый объект.

        Без fill неизвестные байты подменяются исключением; fill задаётся
        только вызывающим кодом осознанно (например, b'?' для отображения).
        """
        if self.gaps and fill is None:
            raise UnknownDataError(
                f"в срезе {len(self.gaps)} неизвестных участков — "
                "подмена невозможна без явного fill"
            )
        out = bytearray()
        pos = self.offset
        end = self.offset + self.length
        pieces = dict(self.pieces)
        while pos < end:
            data = pieces.get(pos)
            if data:
                take = min(len(data), end - pos)
                out += data[:take]
                pos += take
            else:
                if fill is None:
                    raise UnknownDataError("смещение вне известных байтов")
                out.append(fill)
                pos += 1
        return bytes(out)


@dataclass
class Ambiguity:
    """Перекрытие с различающимися байтами (неоднозначность)."""

    start: int
    end: int
    kept_packet: int     # чьи байты оставлены (политика first-seen)
    alt_packet: int      # пакет с альтернативными байтами
    alt_bytes: bytes     # альтернативные байты в диапазоне [start, end)

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class Retransmission:
    """Повторная передача: байты уже есть в потоке (дубликат не добавлен)."""

    packet: int
    start: int
    length: int


@dataclass
class Cell:
    """Одна ячейка потока для отображения (offset, байт, источник, флаг)."""

    offset: int
    value: Optional[int]      # None — неизвестный байт (не подменяется)
    packet: int               # индекс пакета-источника или -1
    amb: bool                 # байт в диапазоне неоднозначности


@dataclass
class Stream:
    """Восстановленный направленный поток одной сессии."""

    session_id: int
    direction: str                     # 'a2b' | 'b2a'
    base_seq: int = 0
    midstream: bool = False            # начало соединения недоступно
    runs: List[object] = field(default_factory=list)   # DataRun | GapRun
    ambiguities: List[Ambiguity] = field(default_factory=list)
    retransmissions: List[Retransmission] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    segment_count: int = 0

    # ------------------------------------------------------------ свойства

    @property
    def length(self) -> int:
        """Полная длина потока, включая неизвестные участки."""
        return self.runs[-1].end if self.runs else 0

    @property
    def data_length(self) -> int:
        return sum(len(r.data) for r in self.runs if isinstance(r, DataRun))

    @property
    def gaps(self) -> List[GapRun]:
        return [r for r in self.runs if isinstance(r, GapRun)]

    @property
    def is_complete(self) -> bool:
        return not self.gaps

    @property
    def is_ambiguous(self) -> bool:
        return bool(self.ambiguities)

    # -------------------------------------------------------------- доступ

    def _starts(self) -> List[int]:
        """Кэшированные начала ранов для бинарного поиска."""
        cache = getattr(self, "_starts_cache", None)
        if cache is None or len(cache) != len(self.runs):
            cache = [r.start for r in self.runs]
            self._starts_cache = cache
        return cache

    def _locate(self, offset: int) -> Tuple[Optional[object], int]:
        if offset < 0 or offset >= self.length or not self.runs:
            return None, -1
        i = bisect.bisect_right(self._starts(), offset) - 1
        if i < 0:
            return None, -1
        r = self.runs[i]
        if offset >= r.end:
            return None, -1
        return r, offset - r.start

    def at(self, offset: int) -> Optional[int]:
        """Байт по смещению; None — неизвестный участок или вне потока."""
        r, rel = self._locate(offset)
        if r is None:
            return None
        if isinstance(r, GapRun):
            return None
        return r.data[rel]

    def slice(self, offset: int, length: int) -> SliceResult:
        """Срез потока: достоверные куски и неизвестные участки отдельно.

        Неизвестные байты НЕ подменяются — они попадают в result.gaps,
        чтобы вызывающий код показал их явно.
        """
        res = SliceResult(offset=offset, length=length)
        if length <= 0 or not self.runs:
            return res
        end = offset + length
        i = max(0, bisect.bisect_right(self._starts(), offset) - 1)
        piece_start: Optional[int] = None
        piece = bytearray()
        while i < len(self.runs) and self.runs[i].start < end:
            r = self.runs[i]
            r0, r1 = max(r.start, offset), min(r.end, end)
            if r1 > r0:
                if isinstance(r, GapRun):
                    if piece:
                        res.pieces.append((piece_start, bytes(piece)))
                        piece.clear()
                        piece_start = None
                    res.gaps.append(GapRun(start=r0, length=r1 - r0, reason=r.reason))
                else:
                    data = r.data[r0 - r.start:r1 - r.start]
                    if piece and piece_start is not None and piece_start + len(piece) == r0:
                        piece += data
                    else:
                        if piece:
                            res.pieces.append((piece_start, bytes(piece)))
                        piece_start = r0
                        piece = bytearray(data)
            i += 1
        if piece:
            res.pieces.append((piece_start, bytes(piece)))
        return res

    def packets_for(self, offset: int, length: int) -> List[int]:
        """Пакеты-источники байтов диапазона (для перехода к источнику)."""
        ids: List[int] = []
        for off in range(offset, offset + length):
            r, _ = self._locate(off)
            if isinstance(r, DataRun) and r.packet not in ids:
                ids.append(r.packet)
        return ids

    # ------------------------------------------------------------ ячейки

    def _amb_index(self) -> Tuple[List[int], List[int]]:
        """Кэшированные границы неоднозначностей для бинарного поиска."""
        cache = getattr(self, "_amb_cache", None)
        if cache is None:
            ordered = sorted(self.ambiguities, key=lambda a: a.start)
            cache = ([a.start for a in ordered], [a.end for a in ordered])
            self._amb_cache = cache
        return cache

    def cells(self, offset: int, length: int) -> List["Cell"]:
        """Побайтовые ячейки диапазона для отображения.

        value=None — неизвестный (не подменяется), packet=-1 — происхождение
        неизвестно, amb=True — байт в диапазоне неоднозначности.
        """
        cells: List["Cell"] = []
        if length <= 0 or not self.runs or self.length == 0:
            return cells
        start = max(0, offset)
        end = min(offset + length, self.length)
        if end <= start:
            return cells
        amb_starts, amb_ends = self._amb_index()

        def in_amb(off: int) -> bool:
            if not amb_starts:
                return False
            k = bisect.bisect_right(amb_starts, off) - 1
            return k >= 0 and off < amb_ends[k]

        i = max(0, bisect.bisect_right(self._starts(), start) - 1)
        while i < len(self.runs) and self.runs[i].start < end:
            r = self.runs[i]
            r0, r1 = max(r.start, start), min(r.end, end)
            if r1 > r0:
                if isinstance(r, GapRun):
                    for off in range(r0, r1):
                        cells.append(Cell(off, None, -1, in_amb(off)))
                else:
                    base = r0 - r.start
                    for k, v in enumerate(r.data[base:base + (r1 - r0)]):
                        off = r0 + k
                        cells.append(Cell(off, int(v), r.packet, in_amb(off)))
            i += 1
        return cells

    def iter_data(self) -> Iterator[Tuple[int, bytes, int]]:
        """(start, bytes, packet) по всем достоверным участкам."""
        for r in self.runs:
            if isinstance(r, DataRun):
                yield r.start, r.data, r.packet

    def to_bytes(self) -> bytes:
        """Все достоверные байты подряд. При наличии пропусков — ошибка:
        неизвестное нельзя подменять."""
        if self.gaps:
            raise UnknownDataError(
                f"в потоке {len(self.gaps)} неизвестных участков — "
                "используйте hexdump() или slice() с явной обработкой"
            )
        return b"".join(r.data for r in self.runs if isinstance(r, DataRun))

    # ------------------------------------------------------------ вывод

    def hexdump(self, offset: int = 0, length: Optional[int] = None, width: int = 16) -> str:
        """Hex-дамп: '??' — неизвестные байты, диапазоны неоднозначности — в конце."""
        if length is None:
            length = max(0, self.length - offset)
        lines: List[str] = []
        pos = offset
        end = offset + length
        while pos < end:
            chunk: List[str] = []
            ascii_col: List[str] = []
            for k in range(width):
                if pos + k >= end:
                    chunk.append("   ")
                    ascii_col.append(" ")
                    continue
                b = self.at(pos + k)
                if b is None:
                    chunk.append("??")
                    ascii_col.append("?")
                else:
                    chunk.append(f"{b:02X}")
                    ascii_col.append(chr(b) if 32 <= b < 127 else ".")
            lines.append(f"{pos:08X}  {' '.join(chunk):<{width * 3}}  |{''.join(ascii_col)}|")
            pos += width

        if self.gaps:
            g = ", ".join(f"[0x{gap.start:X}..0x{gap.end:X})" for gap in self.gaps[:8])
            more = "" if len(self.gaps) <= 8 else f" …ещё {len(self.gaps) - 8}"
            lines.append(f"неизвестные участки: {g}{more}")
        if self.ambiguities:
            a = ", ".join(
                f"[0x{amb.start:X}..0x{amb.end:X}) pkt#{amb.kept_packet}"
                f" vs pkt#{amb.alt_packet}"
                for amb in self.ambiguities[:8]
            )
            more = "" if len(self.ambiguities) <= 8 else f" …ещё {len(self.ambiguities) - 8}"
            lines.append(f"неоднозначности: {a}{more}")
        return "\n".join(lines)

    def stats(self) -> str:
        parts = [
            f"поток {self.direction} сессии #{self.session_id}:",
            f"длина {self.length} Б (достоверно {self.data_length} Б)",
            f"сегментов {self.segment_count}",
            f"неизвестных участков {len(self.gaps)}",
            f"ретрансмиссий {len(self.retransmissions)}",
            f"неоднозначностей {len(self.ambiguities)}",
        ]
        if self.midstream:
            parts.append("начало соединения недоступно (midstream)")
        return ", ".join(parts)


def build_stream(
    timestamps: List[float],
    parsed: List[Parsed],
    session: Session,
    direction: str,
    overlap_policy: str = DEFAULT_OVERLAP_POLICY,
) -> Stream:
    """Собрать направленный поток сессии.

    timestamps — список меток времени пакетов записи (для последовательности),
    parsed — список разобранных пакетов, session — сессия, direction — 'a2b'/'b2a'.
    """
    if overlap_policy not in OVERLAP_POLICIES:
        raise ValueError(
            f"политика перекрытия {overlap_policy!r} не поддерживается; "
            f"доступны: {', '.join(OVERLAP_POLICIES)}"
        )

    stream = Stream(
        session_id=session.id,
        direction=direction,
        midstream=session.midstream,
    )

    # 1. собираем сегменты с полезной нагрузкой
    raw: List[Tuple[int, bytes, int]] = []  # (seq, payload, packet_index)
    for idx, d in session.events:
        if d != direction:
            continue
        p = parsed[idx]
        if p.tcp is None or not p.payload:
            continue
        raw.append((p.tcp.seq, p.payload, idx))
    stream.segment_count = len(raw)

    if not raw:
        stream.diagnostics.append("нет сегментов с полезной нагрузкой")
        return stream

    # 2. относительные смещения (учитываем циклическое переполнение seq)
    ref = raw[0][0]

    def rel(seq: int) -> int:
        r = (seq - ref) & 0xFFFFFFFF
        if r >= 0x80000000:
            r -= 0x100000000
        return r

    min_rel = min(rel(seq) for seq, _, _ in raw)
    base = (ref + min_rel) & 0xFFFFFFFF
    stream.base_seq = base

    segments = [
        (rel(seq) - min_rel, payload, pkt) for seq, payload, pkt in raw
    ]
    # порядок: по смещению, при равенстве — по порядку в записи (first-seen)
    segments.sort(key=lambda s: (s[0], s[2]))

    # 3. вставка с обработкой пропусков и перекрытий
    runs: List[object] = []
    starts: List[int] = []
    covered = 0

    def add_run(r) -> None:
        runs.append(r)
        starts.append(r.start)

    for off, payload, pkt in segments:
        seg_end = off + len(payload)

        if off > covered:
            add_run(GapRun(start=covered, length=off - covered))
            covered = off

        if off < covered and seg_end > off:
            # перекрытие с уже вставленными байтами (см. сортировку — только data)
            i = bisect.bisect_right(starts, off) - 1
            limit = min(seg_end, covered)
            while 0 <= i < len(runs) and runs[i].start < limit:
                r = runs[i]
                if isinstance(r, GapRun):
                    # по построению недостижимо; фиксируем как аномалию
                    stream.diagnostics.append(
                        f"сегмент pkt#{pkt} пересёк неизвестный участок [0x{r.start:X}..0x{r.end:X})"
                    )
                    i += 1
                    continue
                a0, a1 = max(off, r.start), min(seg_end, r.end)
                if a1 > a0:
                    existing = r.data[a0 - r.start:a1 - r.start]
                    incoming = payload[a0 - off:a1 - off]
                    if existing == incoming:
                        stream.retransmissions.append(
                            Retransmission(packet=pkt, start=a0, length=a1 - a0)
                        )
                    else:
                        # узкий диапазон реально отличающихся байтов
                        diffs = [k for k in range(len(existing)) if existing[k] != incoming[k]]
                        d0, d1 = a0 + diffs[0], a0 + diffs[-1] + 1
                        stream.ambiguities.append(
                            Ambiguity(
                                start=d0, end=d1,
                                kept_packet=r.packet, alt_packet=pkt,
                                alt_bytes=payload[d0 - off:d1 - off],
                            )
                        )
                        stream.diagnostics.append(
                            f"неоднозначность [0x{d0:X}..0x{d1:X}): "
                            f"оставлены байты pkt#{r.packet}, альтернатива pkt#{pkt} "
                            f"(политика {overlap_policy})"
                        )
                i += 1

        if seg_end > covered:
            tail = payload[covered - off:]
            add_run(DataRun(start=covered, data=bytes(tail), packet=pkt))
            covered = seg_end

    stream.runs = runs

    # 4. диагностика
    if stream.gaps:
        total_gap = sum(g.length for g in stream.gaps)
        stream.diagnostics.append(
            f"неизвестных участков: {len(stream.gaps)} (всего {total_gap} Б)"
        )
    if stream.midstream:
        stream.diagnostics.append(
            "midstream: начало соединения недоступно, роли сторон не установлены, "
            "байты до первого сегмента неизвестны"
        )
    if stream.retransmissions:
        stream.diagnostics.append(
            f"повторных передач: {len(stream.retransmissions)} (байты не дублированы)"
        )
    return stream
