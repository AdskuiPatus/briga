"""Выделение TCP-сессий (соединений) из последовательности пакетов.

Терминология кейса:
  * сессия — отдельный экземпляр TCP-соединения между двумя адресами и портами;
    повторное использование адресов и портов НЕ объединяет разные соединения;
  * направления называются a2b/b2a (канонические endpoint'ы A и B), роли сторон
    не назначаются — они могут быть неизвестны при недоступном начале записи.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .layers import Parsed

Endpoint = Tuple[str, int]

DIR_A2B = "a2b"
DIR_B2A = "b2a"


@dataclass
class Session:
    """Одно TCP-соединение (экземпляр), собранное из пакетов."""

    id: int
    a: Endpoint                    # канонический endpoint (ip, port)
    b: Endpoint
    events: List[Tuple[int, str]] = field(default_factory=list)  # (packet_index, dir)
    start: float = 0.0
    end: float = 0.0
    saw_syn: bool = False
    fin_count: int = 0
    saw_rst: bool = False
    midstream: bool = False        # запись началась не с рукопожатия
    closed: bool = False
    payload_bytes: int = 0
    parse_errors: int = 0
    warnings: int = 0

    @property
    def a_label(self) -> str:
        return f"{self.a[0]}:{self.a[1]}"

    @property
    def b_label(self) -> str:
        return f"{self.b[0]}:{self.b[1]}"

    @property
    def packet_count(self) -> int:
        return len(self.events)

    @property
    def flags_summary(self) -> str:
        parts = []
        if self.midstream:
            parts.append("midstream")
        if self.closed:
            parts.append("closed")
        if self.saw_rst:
            parts.append("RST")
        if self.saw_syn:
            parts.append("SYN")
        return ",".join(parts) or "-"

    def direction_of(self, ep1: Endpoint) -> str:
        return DIR_A2B if ep1 == self.a else DIR_B2A


def build_sessions(
    timestamps: List[float], parsed: List[Parsed]
) -> List[Session]:
    """Назначить каждый TCP-пакет своей сессии (в порядке записи).

    Правила разбиения:
      * новый пакет с SYN на закрытую/заканчивающуюся сессию с тем же ключом
        создаёт НОВУЮ сессию (повторное использование портов не склеивается);
      * поздние ретрансмиссии после FIN/RST (без SYN) остаются в старой сессии;
      * первый пакет сессии без SYN делает её midstream — начала соединения нет.
    """
    sessions: List[Session] = []
    current: Dict[Endpoint, Session] = {}  # канонический ключ -> сессия
    next_id = 0

    for i, p in enumerate(parsed):
        if p.tcp is None or p.ip4 is None:
            continue

        ep1: Endpoint = (p.ip4.src, p.tcp.src_port)
        ep2: Endpoint = (p.ip4.dst, p.tcp.dst_port)
        key = (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)
        direction = DIR_A2B if ep1 == key[0] else DIR_B2A

        syn = p.tcp.syn
        s = current.get(key)
        if s is None or (syn and (s.closed or s.fin_count > 0)):
            s = Session(
                id=next_id,
                a=key[0],
                b=key[1],
                start=timestamps[i],
                end=timestamps[i],
                midstream=not syn,
            )
            next_id += 1
            sessions.append(s)
            current[key] = s

        s.events.append((i, direction))
        s.end = timestamps[i]
        if syn:
            s.saw_syn = True
        if p.tcp.fin:
            s.fin_count += 1
        if p.tcp.rst:
            s.saw_rst = True
            s.closed = True
        if s.fin_count >= 2:
            s.closed = True
        if p.payload:
            s.payload_bytes += len(p.payload)
        if p.error:
            s.parse_errors += 1
        if p.warnings:
            s.warnings += 1

    # сводные свойства — по фактическим данным, а не по порядку в файле
    for s in sessions:
        if s.events:
            s.start = min(timestamps[i] for i, _ in s.events)
            s.end = max(timestamps[i] for i, _ in s.events)
        # рукопожатие где-либо в сессии означает, что начало соединения доступно
        s.midstream = not s.saw_syn

    # стабильный порядок: по времени начала, затем по id
    sessions.sort(key=lambda x: (x.start, x.id))
    for idx, s in enumerate(sessions):
        s.id = idx
    return sessions


def sessions_summary(sessions: List[Session]) -> str:
    if not sessions:
        return "TCP-сессий не найдено"
    lines = [
        f"{'#':>3}  {'A':<24} {'B':<24} {'пак.':>6} {'байт':>9}  флаги"
    ]
    for s in sessions:
        lines.append(
            f"{s.id:>3}  {s.a_label:<24} {s.b_label:<24} "
            f"{s.packet_count:>6} {s.payload_bytes:>9}  {s.flags_summary}"
        )
    return "\n".join(lines)
