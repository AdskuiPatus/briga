"""Применение схем интерпретации к восстановленным потокам (R3, R4).

Разделение обязанностей (раздел 9 кейса):
  * правила (framing/messages) применяются программно к любому потоку в
    области действия схемы и дают воспроизводимый результат с привязкой
    к смещениям и пакетам;
  * гипотезы (hypotheses) хранятся с основаниями и, если задана проверка,
    прогоняются по парам сообщений с учётом контрпримеров и неполных данных.

Неизвестные и частичные данные не подменяются: сообщение, пересекающее
пропусок, помечается partial, поля из недоступных байтов — known=false.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Union

from .reassembly import Stream
from .schema import (
    FIXED_TYPES,
    INT_TYPES,
    RECORD_TYPE,
    SIGNED_TYPES,
    TYPE_SIZE,
    FieldDef,
    FramingRule,
    MessageDef,
    Schema,
    VAR_TYPES,
)

Value = Union[int, str, bytes, None]

MAX_MESSAGE = 1 << 20   # защитный предел: сообщение больше 1 МиБ не разбирается
MAX_RECORD_ELEMENTS = 65536   # защитный предел для поля-повтора


@dataclass
class FieldResult:
    """Извлечённое поле одного сообщения."""

    name: str
    offset: int              # смещение внутри сообщения
    size: Optional[int]      # None — размер не определён (нужен from_field)
    type: str
    value: Value             # int для скаляров, str для ascii, bytes для bytes
    known: bool
    raw: Optional[bytes] = None   # исходные байты, если все доступны

    @property
    def hex(self) -> Optional[str]:
        if self.raw is not None:
            return self.raw.hex()
        if isinstance(self.value, int) and self.known:
            size = TYPE_SIZE.get(self.type, 1)
            order = "big" if self.type.endswith("be") else "little"
            signed = self.type in SIGNED_TYPES
            return int(self.value).to_bytes(size, order, signed=signed).hex()
        return None

    @property
    def comparable(self) -> Optional[Union[int, str]]:
        """Значение для механического сравнения (гипотезы). None — неизвестно."""
        if not self.known or self.value is None:
            return None
        if isinstance(self.value, int):
            return self.value
        if isinstance(self.value, (bytes, bytearray)):
            return bytes(self.value).hex()
        return str(self.value)


@dataclass
class MsgResult:
    """Одно сообщение, выделенное фреймингом и разобранное правилами."""

    i: int
    direction: str
    start: int
    end: int
    id: Optional[str]                 # None — тип не распознан правилами
    partial: bool                     # есть недоступные байты или обрыв
    gap_ranges: List[Tuple[int, int]]  # абсолютные [смещение, длина) внутри
    fields: Dict[str, FieldResult]
    known_bytes: int
    described_bytes: int              # байты, покрытые описанными полями
    described_known: int              # ...из них доступных
    match_unknown: bool               # условие сопоставления не проверяемо
    note: str = ""

    @property
    def size(self) -> int:
        return self.end - self.start

    def field(self, name: str) -> Optional[FieldResult]:
        return self.fields.get(name)


@dataclass
class DirResult:
    """Результат применения схемы к одному направлению потока."""

    direction: str
    scope_ok: bool = True
    note: str = ""
    messages: List[MsgResult] = field(default_factory=list)
    unframed: List[Tuple[int, int]] = field(default_factory=list)  # (смещение, длина)
    framing_errors: List[dict] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def stats(self) -> dict:
        matched = Counter(m.id for m in self.messages if m.id)
        return {
            "direction": self.direction,
            "scope_ok": self.scope_ok,
            "note": self.note,
            "total_bytes": self.total_bytes,
            "messages": len(self.messages),
            "matched": dict(matched),
            "unmatched": sum(1 for m in self.messages if m.id is None),
            "partial": sum(1 for m in self.messages if m.partial),
            "match_unknown": sum(1 for m in self.messages if m.match_unknown),
            "framing_errors": len(self.framing_errors),
            "unframed_bytes": sum(n for _, n in self.unframed),
            "known_bytes": sum(m.known_bytes for m in self.messages),
            "described_bytes": sum(m.described_bytes for m in self.messages),
        }


@dataclass
class HypCheck:
    """Результат проверки одной гипотезы на данных."""

    id: str
    statement: str
    basis: List[str]
    status_before: str
    status_after: str
    result: str                        # pass|fail|incomplete|not_applicable|not_checked
    note: str = ""
    pairs_total: int = 0
    pairs_ok: int = 0
    pairs_unknown: int = 0             # пара есть, но значения неизвестны
    counterexamples: List[dict] = field(default_factory=list)
    unpaired_a: List[int] = field(default_factory=list)   # номера сообщений
    unpaired_b: List[int] = field(default_factory=list)


# ------------------------------------------------------------- чтение ----

def _cells(stream: Stream, offset: int, size: int) -> List[Optional[int]]:
    """Значения байтов [offset, offset+size); None — недоступно (не подменяется)."""
    if size <= 0:
        return []
    return [c.value for c in stream.cells(offset, size)]


def _decode(values: Sequence[Optional[int]], ftype: str) -> Value:
    if any(v is None for v in values):
        return None
    data = bytes(values)  # type: ignore[arg-type]
    if ftype == "u8":
        return data[0]
    if ftype == "i8":
        return int.from_bytes(data, "little", signed=True)
    if ftype in ("u16le", "i16le", "u32le", "i32le"):
        return int.from_bytes(data, "little", signed=ftype.startswith("i"))
    if ftype in ("u16be", "i16be", "u32be", "i32be"):
        return int.from_bytes(data, "big", signed=ftype.startswith("i"))
    if ftype == "ascii":
        return data.decode("ascii", errors="replace")
    return data  # bytes


def _find_magic(stream: Stream, magic: bytes, start: int) -> Optional[int]:
    """Найти байты маркера, начиная с offset (пропуски не подменяются)."""
    if start >= stream.length or not magic:
        return None
    mlen = len(magic)
    chunk = 65536
    pos = start
    carry: List[Optional[int]] = []
    while pos < stream.length:
        vals = _cells(stream, pos, min(chunk, stream.length - pos))
        if not vals:
            break
        seq = carry + vals
        base = pos - len(carry)
        for i in range(0, len(seq) - mlen + 1):
            if all(seq[i + j] is not None and seq[i + j] == magic[j]
                   for j in range(mlen)):
                return base + i
        carry = seq[-(mlen - 1):] if mlen > 1 else []
        pos += len(vals)
    return None


# --------------------------------------------------- применение к потоку ----

def _build_message(stream: Stream, schema: Schema, direction: str,
                   i: int, start: int, size: int, note: str = "") -> MsgResult:
    end = start + size
    cells = _cells(stream, start, size)
    known_bytes = sum(1 for v in cells if v is not None)

    # диапазоны пропусков внутри сообщения (из известных ячеек)
    gaps: List[Tuple[int, int]] = []
    run_start: Optional[int] = None
    for rel, v in enumerate(cells):
        if v is None and run_start is None:
            run_start = rel
        elif v is not None and run_start is not None:
            gaps.append((start + run_start, rel - run_start))
            run_start = None
    if run_start is not None:
        gaps.append((start + run_start, len(cells) - run_start))

    def mread(rel: int, n: int) -> List[Optional[int]]:
        if rel < 0 or n <= 0:
            return []
        return cells[rel:rel + n] if rel < len(cells) else []

    # --- сопоставление с определениями сообщений (по порядку) ---
    matched: Optional[MessageDef] = None
    match_unknown = False
    for mdef in schema.messages:
        if mdef.direction != "any" and mdef.direction != direction:
            continue
        unknown_cond = False
        ok = True
        for cond in mdef.when:
            n = len(cond.bytes) if cond.bytes is not None else TYPE_SIZE[cond.type or "u8"]
            vals = mread(cond.offset, n)
            if len(vals) < n or any(v is None for v in vals):
                unknown_cond = True
                ok = False
                break
            if cond.bytes is not None:
                if bytes(v for v in vals if v is not None) != cond.bytes:
                    ok = False
                    break
            else:
                decoded = _decode(vals, cond.type or "u8")
                if cond.values is not None:
                    if decoded not in cond.values:
                        ok = False
                        break
                elif decoded != cond.eq:
                    ok = False
                    break
        if unknown_cond:
            match_unknown = True
            continue
        if ok:
            matched = mdef
            break

    # --- извлечение полей ---
    fields: Dict[str, FieldResult] = {}
    desc = bytearray(size)      # байты, попавшие в описанные поля

    def mark(rel_start: int, rel_end: int) -> None:
        for rel in range(max(0, rel_start), min(size, rel_end)):
            desc[rel] = 1

    def extract_scalar(name: str, offset: int, ftype: str,
                       fsize: Optional[int]) -> FieldResult:
        """Разобрать одно поле; fsize None — размер не определён."""
        if fsize is None:
            return FieldResult(name=name, offset=offset, size=None, type=ftype,
                               value=None, known=False)
        vals = mread(offset, fsize)
        truncated = len(vals) < fsize
        known = (not truncated) and all(v is not None for v in vals)
        raw = bytes(v for v in vals if v is not None) if known else None
        if ftype in INT_TYPES:
            value: Value = _decode(vals, ftype) if known else None
        elif ftype == "ascii":
            value = _decode(vals, "ascii") if known else None
        else:
            value = raw
        return FieldResult(name=name, offset=offset,
                           size=fsize if not truncated else len(vals),
                           type=ftype, value=value, known=known, raw=raw)

    if matched is not None:
        scalar_values: Dict[str, Value] = {}
        for f in matched.fields:
            # --- поле-повтор: серия записей фиксированной длины ---
            if f.is_record:
                cnt = scalar_values.get(f.repeat_count) if f.repeat_count else None
                rsize = f.repeat_size or 0
                if not isinstance(cnt, int) or cnt < 0 or rsize <= 0:
                    fields[f.name] = FieldResult(
                        name=f.name, offset=f.offset, size=None, type=f.type,
                        value=None, known=False)
                    continue
                nelem = min(cnt, MAX_RECORD_ELEMENTS)
                for i in range(nelem):
                    base = f.offset + i * rsize
                    if base >= size:
                        break          # записи за концом сообщения не разбираем
                    for sub in f.subfields:
                        ssize: Optional[int] = TYPE_SIZE.get(sub.type)
                        if sub.type in VAR_TYPES:
                            ssize = sub.length if sub.length is not None else max(
                                0, rsize - sub.offset)
                        sname = f"{f.name}[{i}].{sub.name}"
                        fr = extract_scalar(sname, base + sub.offset, sub.type, ssize)
                        fields[sname] = fr
                mark(f.offset, f.offset + nelem * rsize)
                continue

            # --- скалярное / переменное поле ---
            fsize2: Optional[int] = TYPE_SIZE.get(f.type)
            if f.type in VAR_TYPES:
                if f.length is not None:
                    fsize2 = f.length
                elif f.from_field is not None:
                    prev = scalar_values.get(f.from_field)
                    fsize2 = prev if isinstance(prev, int) else None
                else:
                    fsize2 = max(0, size - f.offset)
            fr = extract_scalar(f.name, f.offset, f.type, fsize2)
            fields[f.name] = fr
            if f.type in INT_TYPES:
                scalar_values[f.name] = fr.value
            if fsize2 is not None:
                mark(f.offset, f.offset + fsize2)

    described = sum(desc)
    described_known = sum(1 for rel, flag in enumerate(desc)
                          if flag and cells[rel] is not None)

    return MsgResult(
        i=i, direction=direction, start=start, end=end,
        id=matched.id if matched else None,
        partial=bool(gaps) or bool(note),
        gap_ranges=gaps, fields=fields,
        known_bytes=known_bytes,
        described_bytes=described, described_known=described_known,
        match_unknown=match_unknown, note=note,
    )


def apply_to_stream(stream: Stream, schema: Schema, direction: str) -> DirResult:
    """Применить схему (фрейминг + сопоставление) к одному потоку."""
    res = DirResult(direction=direction, total_bytes=stream.length)

    if schema.scope_directions and direction not in schema.scope_directions:
        res.scope_ok = False
        res.note = ("вне области действия схемы: scope.directions = "
                    + ", ".join(schema.scope_directions))
        return res

    rule: Optional[FramingRule] = schema.framing_for(direction)
    if rule is None:
        res.scope_ok = False
        res.note = f"для направления {direction} нет правила фрейминга"
        return res

    pos = 0
    idx = 0
    while pos < stream.length:
        # 1) при наличии маркера — встать на границу сообщения
        if rule.magic is not None:
            if _cells(stream, pos, len(rule.magic)) != list(rule.magic):
                nxt = _find_magic(stream, rule.magic, pos)
                if nxt is None:
                    res.unframed.append((pos, stream.length - pos))
                    break
                res.unframed.append((pos, nxt - pos))
                pos = nxt

        # 2) заголовок (с учётом поля длины)
        need = rule.header
        if rule.needs_length_field:
            need = max(need, (rule.length_offset or 0) + TYPE_SIZE[rule.length_type or "u8"])
        hdr = _cells(stream, pos, need)
        if len(hdr) < need or any(v is None for v in hdr):
            res.framing_errors.append({
                "start": pos,
                "reason": "заголовок недоступен (пропуск в захвате или конец потока)",
            })
            break

        # 3) длина сообщения
        if rule.fixed is not None:
            total = rule.fixed
        else:
            off = rule.length_offset or 0
            lsize = TYPE_SIZE[rule.length_type or "u8"]
            lv = _decode(hdr[off:off + lsize], rule.length_type or "u8")
            assert isinstance(lv, int)
            total = lv + rule.header if rule.includes == "payload" else lv

        if total < rule.min_len or total > rule.max_len:
            res.framing_errors.append({
                "start": pos,
                "reason": (f"длина {total} Б вне диапазона "
                           f"[{rule.min_len}..{rule.max_len}]"),
            })
            if rule.magic is None:
                break
            nxt = _find_magic(stream, rule.magic, pos + 1)
            if nxt is None:
                res.unframed.append((pos, stream.length - pos))
                break
            res.unframed.append((pos, nxt - pos))
            pos = nxt
            continue

        if total < 1:
            res.framing_errors.append({"start": pos, "reason": "нулевая длина"})
            break

        # 4) конец потока посреди сообщения — явно, с сохранением данных
        if pos + total > stream.length:
            avail = stream.length - pos
            res.framing_errors.append({
                "start": pos,
                "reason": (f"сообщение обрезано концом потока: "
                           f"доступно {avail} из {total} Б"),
            })
            res.messages.append(_build_message(
                stream, schema, direction, idx, pos, avail,
                note="обрезано концом потока"))
            break

        res.messages.append(_build_message(stream, schema, direction, idx, pos, total))
        idx += 1
        pos += total

    return res


# ------------------------------------------------------------- гипотезы ----

def _comparable(msg: Optional[MsgResult], field_name: str) -> Optional[Union[int, str]]:
    if msg is None:
        return None
    fr = msg.field(field_name)
    if fr is None:
        return None
    return fr.comparable


def _value_repr(fr: Optional[FieldResult]) -> Union[int, str, None]:
    if fr is None or not fr.known:
        return None
    if isinstance(fr.value, (bytes, bytearray)):
        return bytes(fr.value).hex()
    if isinstance(fr.value, int):
        return fr.value
    return str(fr.value)


def check_hypotheses(schema: Schema,
                     dir_results: Dict[str, DirResult],
                     streams: Optional[Dict[str, "Stream"]] = None
                     ) -> List[HypCheck]:
    """Проверить гипотезы схемы на результатах применения к направлениям.

    streams (опционально) — для привязки контрпримеров к исходным пакетам
    (provenance: байты → пакеты).
    """
    out: List[HypCheck] = []
    for h in schema.hypotheses:
        chk = HypCheck(
            id=h.id, statement=h.statement, basis=list(h.basis),
            status_before=h.status, status_after=h.status, result="not_checked",
        )
        out.append(chk)

        if h.check is None:
            chk.note = ("нет механической проверки — утверждение остаётся "
                        "предположением исследователя")
            continue

        a_dir, b_dir = h.check.a.direction or "", h.check.b.direction or ""
        ra, rb = dir_results.get(a_dir), dir_results.get(b_dir)
        if ra is None or rb is None or not ra.scope_ok or not rb.scope_ok:
            chk.result = "not_applicable"
            chk.note = ("нет результатов для одного из направлений "
                        f"({a_dir}/{b_dir}) в области действия")
            continue

        a_msgs = [m for m in ra.messages if m.id == h.check.a.message]
        b_msgs = [m for m in rb.messages if m.id == h.check.b.message]
        if not a_msgs or not b_msgs:
            chk.result = "not_applicable"
            chk.note = (f"нет примеров сообщений: {h.check.a.message} "
                        f"({len(a_msgs)}), {h.check.b.message} ({len(b_msgs)})")
            continue

        # сопоставление пар: по порядку или по ключу корреляции (pair_by),
        # устойчивое к пропускам и переупорядочиванию сообщений
        paired: List[Tuple[MsgResult, MsgResult]]
        if h.check.pair_by:
            a_by: Dict[Union[int, str], MsgResult] = {}
            for m in a_msgs:
                k = _comparable(m, h.check.pair_by)
                if k is not None:
                    a_by.setdefault(k, m)
            b_by: Dict[Union[int, str], MsgResult] = {}
            for m in b_msgs:
                k = _comparable(m, h.check.pair_by)
                if k is not None:
                    b_by.setdefault(k, m)

            def _ksort(k: Union[int, str]) -> Tuple[int, int, str]:
                return (0, k, "") if isinstance(k, int) else (1, 0, str(k))

            common = sorted(set(a_by) & set(b_by), key=_ksort)
            paired = [(a_by[k], b_by[k]) for k in common]
            a_paired = {id(x) for x, _ in paired}
            b_paired = {id(y) for _, y in paired}
            chk.unpaired_a = [m.i for m in a_msgs if id(m) not in a_paired]
            chk.unpaired_b = [m.i for m in b_msgs if id(m) not in b_paired]
        else:
            npairs = min(len(a_msgs), len(b_msgs))
            paired = [(a_msgs[k], b_msgs[k]) for k in range(npairs)]
            chk.unpaired_a = [m.i for m in a_msgs[npairs:]]
            chk.unpaired_b = [m.i for m in b_msgs[npairs:]]
        chk.pairs_total = len(paired)

        for ma, mb in paired:
            va = _comparable(ma, h.check.a.field)
            vb = _comparable(mb, h.check.b.field)
            if va is None or vb is None:
                chk.pairs_unknown += 1
                continue
            if va == vb:
                chk.pairs_ok += 1
            else:
                ce = {
                    "a": {"message": h.check.a.message, "index": ma.i,
                          "offset": ma.start, "size": ma.size, "value": va,
                          "direction": ma.direction, "partial": ma.partial},
                    "b": {"message": h.check.b.message, "index": mb.i,
                          "offset": mb.start, "size": mb.size, "value": vb,
                          "direction": mb.direction, "partial": mb.partial},
                }
                # привязка к исходным пакетам (provenance: байты → пакеты)
                if streams is not None:
                    for side, m in (("a", ma), ("b", mb)):
                        st = streams.get(m.direction)
                        if st is not None:
                            ce[side]["packets"] = st.packets_for(
                                m.start, m.size)
                chk.counterexamples.append(ce)

        if chk.counterexamples:
            chk.result = "fail"
            chk.status_after = "refuted"
            chk.note = (f"опровергнуто на данных: контрпримеров "
                        f"{len(chk.counterexamples)} из {chk.pairs_total} пар")
        elif chk.pairs_total == 0:
            chk.result = "not_applicable"
        elif chk.pairs_unknown or chk.unpaired_a or chk.unpaired_b:
            chk.result = "incomplete"
            chk.status_after = h.status
            parts = []
            if chk.pairs_unknown:
                parts.append(f"пар с неизвестными значениями: {chk.pairs_unknown}")
            if chk.unpaired_a or chk.unpaired_b:
                parts.append(f"непарных сообщений: A={len(chk.unpaired_a)}, "
                             f"B={len(chk.unpaired_b)}")
            chk.note = "проверка неполная: " + "; ".join(parts)
        else:
            chk.result = "pass"
            chk.status_after = "checked"
            chk.note = f"подтверждено на {chk.pairs_total} парах"
    return out


def analyze_session(schema: Schema, streams: Dict[str, Stream]
                    ) -> Tuple[Dict[str, DirResult], List[HypCheck]]:
    """Применить схему ко всем доступным направлениям и проверить гипотезы.

    streams: {'a2b': Stream, 'b2a': Stream} — направления, участвующие в анализе.
    """
    directions = schema.scope_directions or sorted(streams)
    results: Dict[str, DirResult] = {}
    for d in directions:
        st = streams.get(d)
        if st is None:
            r = DirResult(direction=d, scope_ok=False,
                          note="поток не запрошен/недоступен")
            results[d] = r
            continue
        results[d] = apply_to_stream(st, schema, d)
    return results, check_hypotheses(schema, results, streams=streams)


# ------------------------------------------------------ сериализация ----

def field_to_dict(f: FieldResult) -> dict:
    out = {
        "name": f.name, "offset": f.offset, "size": f.size,
        "type": f.type, "known": f.known,
    }
    if f.known:
        if isinstance(f.value, (bytes, bytearray)):
            out["value"] = bytes(f.value).hex()
            out["text"] = bytes(f.value).decode("ascii", errors="replace")
        elif isinstance(f.value, int):
            out["value"] = f.value
            out["hex"] = f.hex
        else:
            out["value"] = f.value
            if f.raw is not None:
                out["hex"] = f.raw.hex()
    return out


def message_to_dict(m: MsgResult) -> dict:
    return {
        "index": m.i, "direction": m.direction,
        "start": m.start, "end": m.end, "size": m.size,
        "id": m.id, "partial": m.partial,
        "gaps": [{"start": s, "length": n} for s, n in m.gap_ranges],
        "known_bytes": m.known_bytes,
        "described": {"known": m.described_known, "total": m.described_bytes},
        "match_unknown": m.match_unknown,
        "note": m.note,
        "fields": {name: field_to_dict(f) for name, f in m.fields.items()},
    }


def dir_result_to_dict(r: DirResult, max_messages: int = 1000) -> dict:
    return {
        "stats": r.stats,
        "messages": [message_to_dict(m) for m in r.messages[:max_messages]],
        "messages_total": len(r.messages),
        "messages_truncated": len(r.messages) > max_messages,
        "unframed": [{"start": s, "length": n} for s, n in r.unframed],
        "framing_errors": r.framing_errors,
    }


def hyp_check_to_dict(h: HypCheck) -> dict:
    return {
        "id": h.id, "statement": h.statement, "basis": h.basis,
        "status_before": h.status_before, "status_after": h.status_after,
        "result": h.result, "note": h.note,
        "pairs": {"total": h.pairs_total, "ok": h.pairs_ok,
                  "unknown": h.pairs_unknown},
        "counterexamples": h.counterexamples,
        "unpaired": {"a": h.unpaired_a, "b": h.unpaired_b},
    }
