# -*- coding: utf-8 -*-
"""Журнал действий исследователя ↔ обмен в записи (R2).

Связывает известные действия из журнала (CSV: capture/session/action_id/
start_utc/end_utc/action/parameters/observed_result) с сообщениями,
выделенными интерпретацией:

  * для каждого действия находит запрос и ответ — по сессии (меткам времени
    пакетов) и ожидаемым идентификаторам сообщений;
  * сверяет наблюдаемый результат действия с декодированными полями ответа;
  * даёт переход к исходным байтам (смещения сообщения + пакеты).

Привязки декларативны и живут в секции ``journal`` схемы интерпретации
(каких действий — какие сообщения, как сверять поля), поэтому ядро не знает
ничего о конкретном протоколе.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .interpreter import MsgResult
from .schema import JournalSpec, Schema

# допустимые вердикты корреляции действия с обменом
VERDICTS = ("matched", "mismatch", "uncovered", "incomplete", "missing")


class JournalError(Exception):
    """Журнал действий непригоден: список причин."""

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# ------------------------------------------------------------- чтение ----

@dataclass
class Action:
    """Одно действие исследователя из журнала."""

    capture: str          # относительный путь записи (как в журнале)
    session: str          # s1, s2, …
    action_id: str
    start: float          # эпоха, с
    end: float            # эпоха, с
    action: str           # read-config | set-config | read-values | probe-…
    parameters: Dict[str, Any]
    observed_result: Dict[str, Any]
    row: int              # строка CSV (происхождение записи)

    @property
    def window(self) -> Tuple[float, float]:
        return (self.start, self.end)


def _parse_ts(text: str) -> float:
    """ISO-8601 UTC → эпоха (с)."""
    return datetime.fromisoformat(text.strip().replace("Z", "+00:00")).timestamp()


def _parse_json(text: str, where: str, errors: List[str]) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except ValueError as e:
        errors.append(f"{where}: поле не разбирается как JSON — {e}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{where}: ожидался JSON-объект, получен {type(value).__name__}")
        return {}
    return value


_REQUIRED = ("capture", "session", "action_id", "start_utc", "end_utc",
             "action", "parameters", "observed_result")


def load_journal(path: str | Path) -> Tuple[List[Action], List[str]]:
    """Прочитать журнал действий (CSV). Возвращает (действия, замечания).

    Строчные замечания (плохой JSON/время) не роняют чтение: действие
    помечается, но строка сохраняется, чтобы не потерять происхождение.
    """
    p = Path(path)
    errors: List[str] = []
    actions: List[Action] = []
    try:
        raw = p.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise JournalError([f"не удалось прочитать журнал {p}: {e}"])

    reader = csv.DictReader(raw.splitlines())
    if reader.fieldnames is None:
        raise JournalError([f"журнал {p} пуст или без заголовка"])
    missing = [c for c in _REQUIRED if c not in reader.fieldnames]
    if missing:
        raise JournalError([f"в журнале {p} нет колонок: {', '.join(missing)}"])

    for i, row in enumerate(reader, start=2):   # 1 — заголовок
        aid = (row.get("action_id") or "").strip()
        where = f"строка {i}" + (f" ({aid})" if aid else "")
        try:
            start = _parse_ts(row["start_utc"])
            end = _parse_ts(row["end_utc"])
        except (ValueError, TypeError) as e:
            errors.append(f"{where}: время действия не разбирается — {e}")
            continue
        if end < start:
            errors.append(f"{where}: end раньше start — пропущено")
            continue
        params = _parse_json(row.get("parameters", ""), f"{where}.parameters", errors)
        observed = _parse_json(row.get("observed_result", ""),
                               f"{where}.observed_result", errors)
        actions.append(Action(
            capture=(row.get("capture") or "").strip(),
            session=(row.get("session") or "").strip(),
            action_id=aid,
            start=start, end=end,
            action=(row.get("action") or "").strip(),
            parameters=params, observed_result=observed,
            row=i,
        ))
    if not actions and not errors:
        errors.append(f"в журнале {p} нет ни одного действия")
    return actions, errors


def filter_capture(actions: Iterable[Action], capture_path: str | Path) -> List[Action]:
    """Действия, относящиеся к записи (по имени файла — путь относительный)."""
    name = Path(capture_path).name.lower()
    return [a for a in actions
            if Path(a.capture.replace("\\", "/")).name.lower() == name]


# --------------------------------------------------- сообщения-кандидаты ----

@dataclass
class MsgRef:
    """Сообщение, связанное с пакетами (для корреляции и перехода к байтам)."""

    session: int
    direction: str
    index: int
    id: Optional[str]
    start: int            # смещение в потоке
    end: int
    t0: float             # время первого пакета (эпоха, с)
    t1: float             # время последнего пакета
    msg: MsgResult

    @property
    def packets_time(self) -> Tuple[float, float]:
        return (self.t0, self.t1)

    def overlaps(self, win: Tuple[float, float], tol: float = 0.05) -> bool:
        return self.t0 <= win[1] + tol and self.t1 >= win[0] - tol

    def to_dict(self) -> dict:
        return {
            "session": self.session, "direction": self.direction,
            "index": self.index, "id": self.id,
            "start": self.start, "end": self.end,
            "t0": self.t0, "t1": self.t1,
        }


def collect_messages(session_index: int, streams: Dict[str, Any],
                     results: Dict[str, Any],
                     timestamps: Sequence[float]) -> List[MsgRef]:
    """Собрать все сообщения одной сессии с метками времени пакетов."""
    out: List[MsgRef] = []
    for direction, dr in results.items():
        if not getattr(dr, "scope_ok", False):
            continue
        stream = streams.get(direction)
        if stream is None:
            continue
        for m in dr.messages:
            pk = stream.packets_for(m.start, m.end - m.start)
            if pk:
                t0 = min(timestamps[i] for i in pk)
                t1 = max(timestamps[i] for i in pk)
            else:                      # без пакетов — берём границы сессии
                t0 = t1 = float(m.start)
            out.append(MsgRef(
                session=session_index, direction=direction, index=m.i,
                id=m.id, start=m.start, end=m.end, t0=t0, t1=t1, msg=m,
            ))
    out.sort(key=lambda r: (r.t0, r.t1, r.direction, r.index))
    return out


def session_spans(sessions: Sequence[Any],
                  timestamps: Sequence[float]) -> List[Tuple[int, float, float]]:
    """(индекс, начало, конец) по меткам времени пакетов сессии."""
    spans = []
    for i, s in enumerate(sessions):
        ev = getattr(s, "events", None)
        if ev:
            ts = [timestamps[idx] for idx, _ in ev]
            spans.append((i, min(ts), max(ts)))
        else:
            spans.append((i, getattr(s, "start", 0.0), getattr(s, "end", 0.0)))
    return spans


def match_session(start: float,
                  spans: Sequence[Tuple[int, float, float]]) -> Optional[int]:
    """Сессия, меткам времени которой принадлежит действие."""
    for idx, lo, hi in spans:
        if lo - 0.05 <= start <= hi + 0.05:
            return idx
    # запасной вариант — ближайшая по началу
    if spans:
        return min(spans, key=lambda sp: abs(sp[1] - start))[0]
    return None


# ------------------------------------------------------------- сверка ----

@dataclass
class Check:
    """Одно сверенное поле: наблюдаемый результат ↔ декодированное значение."""

    path: str                       # путь в observed_result (с [i] для серий)
    observed: Any
    decoded: Any
    equal: Optional[bool]           # None — не сверялось (не охвачено схемой)
    note: str = ""

    def to_dict(self) -> dict:
        out = {"path": self.path, "observed": self.observed,
               "decoded": self.decoded, "equal": self.equal}
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class Match:
    """Результат корреляции одного действия с обменом."""

    action: Action
    verdict: str                    # из VERDICTS
    request: Optional[MsgRef] = None
    response: Optional[MsgRef] = None
    checks: List[Check] = field(default_factory=list)
    note: str = ""
    session_index: Optional[int] = None

    @property
    def provenance(self) -> Optional[dict]:
        """Связь к исходным байтам (R2: непосредственная сверка)."""
        ref = self.request or self.response
        if ref is None:
            return None
        return {
            "session": ref.session, "direction": ref.direction,
            "request": self.request.to_dict() if self.request else None,
            "response": self.response.to_dict() if self.response else None,
        }

    def to_dict(self) -> dict:
        return {
            "action_id": self.action.action_id,
            "action": self.action.action,
            "capture": self.action.capture,
            "session": self.action.session,
            "session_index": self.session_index,
            "start": self.action.start,
            "end": self.action.end,
            "parameters": self.action.parameters,
            "observed_result": self.action.observed_result,
            "verdict": self.verdict,
            "note": self.note,
            "row": self.action.row,
            "request": self.request.to_dict() if self.request else None,
            "response": self.response.to_dict() if self.response else None,
            "checks": [c.to_dict() for c in self.checks],
            "provenance": self.provenance,
        }


def _traverse(root: Any, path: str) -> Tuple[Any, bool]:
    """Значение по точечному пути в observed_result; (значение, найдено)."""
    cur = root
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return None, False
    return cur, True


def _decoded_value(ref: Optional[MsgRef], name: str) -> Tuple[Any, bool, bool]:
    """(значение, известно, есть_поле). name — плоское имя поля сообщения."""
    if ref is None or ref.msg is None:
        return None, False, False
    fr = ref.msg.fields.get(name)
    if fr is None:
        return None, False, False
    if not fr.known or fr.value is None:
        return None, False, True
    return fr.value, True, True


def _as_comparable(value: Any, bind: Any, spec: JournalSpec) -> Any:
    """Привести декодированное значение к виду наблюдаемого (transform)."""
    if bind.status:
        if isinstance(value, bool):
            value = int(value)
        return spec.status_map.get(int(value), f"<{value}>") if isinstance(
            value, int) else value
    if bind.boolean:
        if isinstance(value, str):
            return bool(value)
        return bool(value)
    if bind.scale and bind.scale != 1.0 and isinstance(value, (int, float)) \
            and not isinstance(value, bool):
        return value * bind.scale
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(value).hex()
    return value


def _equal(observed: Any, decoded: Any) -> bool:
    if isinstance(observed, (int, float)) and isinstance(decoded, (int, float)) \
            and not isinstance(observed, bool) and not isinstance(decoded, bool):
        return abs(float(observed) - float(decoded)) < 1e-6
    return observed == decoded


def _run_checks(observed: Dict[str, Any], response: Optional[MsgRef],
                spec: Optional[JournalSpec]) -> Tuple[List[Check], int, int]:
    """Сверить observed_result с полями ответа. Возвращает (checks, ok, gaps)."""
    checks: List[Check] = []
    ok = gaps = 0
    if spec is None:
        return checks, ok, gaps
    for bind in spec.binds:
        if "[i]" in bind.observed:
            prefix, rest = bind.observed.split("[i]", 1)
            lst, found = _traverse(observed, prefix)
            if not found or not isinstance(lst, list):
                continue                     # эта ветка наблюдению не встречается
            rest = rest.lstrip(".")
            for i, item in enumerate(lst):
                ov, o_found = _traverse(item, rest) if rest else (item, True)
                if not o_found:
                    continue
                df = bind.decoded.replace("[i]", f"[{i}]")
                dv, known, present = _decoded_value(response, df)
                if not present:
                    checks.append(Check(f"{prefix}[{i}].{rest}", ov, None, None,
                                        "поле не описано схемой"))
                    gaps += 1
                elif not known:
                    checks.append(Check(f"{prefix}[{i}].{rest}", ov, None, None,
                                        "значение байтов недоступно"))
                    gaps += 1
                else:
                    dec = _as_comparable(dv, bind, spec)
                    eq = _equal(ov, dec)
                    checks.append(Check(f"{prefix}[{i}].{rest}", ov, dec, eq))
                    ok += 1 if eq else 0
                    if not eq:
                        pass
        else:
            ov, found = _traverse(observed, bind.observed)
            if not found:
                continue                     # поля нет в этом наблюдении
            dv, known, present = _decoded_value(response, bind.decoded)
            if not present:
                checks.append(Check(bind.observed, ov, None, None,
                                    "поле не описано схемой"))
                gaps += 1
            elif not known:
                checks.append(Check(bind.observed, ov, None, None,
                                    "значение байтов недоступно"))
                gaps += 1
            else:
                dec = _as_comparable(dv, bind, spec)
                eq = _equal(ov, dec)
                checks.append(Check(bind.observed, ov, dec, eq))
                ok += 1 if eq else 0
    return checks, ok, gaps


def _expected(spec: Optional[JournalSpec], action: str) -> Optional[Dict[str, Any]]:
    if spec is None:
        return None
    return spec.actions.get(action)


def _pick(messages: List[MsgRef], expected_id: Optional[str],
          direction: Optional[str], win: Tuple[float, float],
          unknown: bool = False) -> Optional[MsgRef]:
    """Сообщение-кандидат: ожидаемый id (или неопознанный) в окне действия."""
    cands = [m for m in messages if m.overlaps(win)]
    if unknown:
        cands = [m for m in cands if m.id is None
                 and (direction is None or m.direction == direction)]
    elif expected_id is not None:
        cands = [m for m in cands if m.id == expected_id]
    else:
        cands = [m for m in cands
                 if (direction is None or m.direction == direction)]
    if not cands:
        return None
    return cands[0]                       # первое по времени (first-seen)


def correlate_action(action: Action, messages: List[MsgRef],
                     spec: Optional[JournalSpec],
                     session_index: Optional[int]) -> Match:
    """Сопоставить одно действие с запросом/ответом и сверить результат."""
    win = action.window
    exp = _expected(spec, action.action)
    unknown = bool(exp and exp.get("unknown"))

    if unknown:
        req = _pick(messages, None, "a2b", win, unknown=True)
        resp = _pick(messages, None, "b2a", win, unknown=True)
    elif exp is not None:
        req = _pick(messages, exp.get("request"), None, win)
        resp = _pick(messages, exp.get("response"), None, win)
    else:
        # привязки для действия нет — сопоставляем только по времени и направлению
        req = _pick(messages, None, "a2b", win)
        resp = _pick(messages, None, "b2a", win)

    if req is None and resp is None:
        return Match(action, "missing", note="обмен в записи не найден",
                     session_index=session_index)

    # запрос без ответа — ответ не попал в захват или не распознан
    if resp is None:
        if req is not None and req.id is None:
            return Match(action, "incomplete", request=req,
                         note="запрос вне интерпретации, ответ не найден",
                         session_index=session_index)
        return Match(action, "incomplete", request=req,
                     note="ответ на действие в записи не найден",
                     session_index=session_index)
    if req is None:
        return Match(action, "incomplete", response=resp,
                     note="запрос в окне действия не найден",
                     session_index=session_index)

    # обмен найден целиком — но вне интерпретации (например, неизвестная команда)
    if unknown or (resp.id is None and req.id is None):
        return Match(action, "uncovered", request=req, response=resp,
                     note="обмен найден, но тип сообщения не покрыт "
                          "текущей интерпретацией — сверка полей невозможна",
                     session_index=session_index)

    checks, ok, gaps = _run_checks(action.observed_result, resp, spec)
    mismatches = [c for c in checks if c.equal is False]
    if mismatches:
        note = "; ".join(f"{c.path}: журнал={c.observed!r} "
                         f"запись={c.decoded!r}" for c in mismatches[:3])
        if len(mismatches) > 3:
            note += f" … ещё {len(mismatches) - 3}"
        return Match(action, "mismatch", request=req, response=resp,
                     checks=checks, note=note, session_index=session_index)
    if not checks:
        return Match(action, "incomplete", request=req, response=resp,
                     note="привязки полей не заданы — сверка не выполнялась",
                     session_index=session_index)
    if gaps:
        return Match(action, "incomplete", request=req, response=resp,
                     checks=checks,
                     note=f"сверено {ok} полей, {gaps} не охвачено схемой",
                     session_index=session_index)
    return Match(action, "matched", request=req, response=resp, checks=checks,
                 note=f"сверено полей: {ok}", session_index=session_index)


def correlate(actions: Sequence[Action],
              messages_by_session: Dict[int, List[MsgRef]],
              spans: Sequence[Tuple[int, float, float]],
              spec: Optional[JournalSpec]) -> List[Match]:
    """Скоррелировать все действия записи с обменом."""
    matches: List[Match] = []
    for action in actions:
        idx = match_session(action.start, spans)
        msgs = messages_by_session.get(idx, []) if idx is not None else []
        matches.append(correlate_action(action, msgs, spec, idx))
    return matches


def summarize(matches: Sequence[Match]) -> Dict[str, int]:
    """Счётчики по вердиктам."""
    out = {v: 0 for v in VERDICTS}
    for m in matches:
        out[m.verdict] = out.get(m.verdict, 0) + 1
    return out


def render_table(matches: Sequence[Match], width: int = 100) -> str:
    """Читаемая таблица корреляции для консоли."""
    lines: List[str] = []
    hdr = (f"{'действие':<22} {'id':<12} {'сесс':<4} {'вердикт':<11} "
           f"{'req':<16} {'resp':<16} примечание")
    lines.append(hdr)
    lines.append("-" * min(width, len(hdr) + 30))
    for m in matches:
        req = (m.request.id if m.request and m.request.id
               else ("—" if m.request else "-"))
        resp = (m.response.id if m.response and m.response.id
                else ("—" if m.response else "-"))
        note = m.note or ""
        if len(note) > 40:
            note = note[:37] + "…"
        lines.append(f"{m.action.action[:21]:<22} {m.action.action_id[:11]:<12} "
                     f"{(m.action.session or '?'):<4} {m.verdict:<11} "
                     f"{req[:15]:<16} {resp[:15]:<16} {note}")
    return "\n".join(lines)


def render_compare(matches: Sequence[Match], action: str) -> str:
    """Сопоставить примеры одного действия с разными параметрами (R2).

    Показывает параметры каждого вхождения рядом и отмечает, какие поля
    меняются, а какие повторяются (закономерность).
    """
    sel = [m for m in matches if m.action.action == action]
    if not sel:
        return f"действий {action!r} в журнале нет"
    # собрать все ключи параметров
    keys: List[str] = []
    for m in sel:
        for k in m.action.parameters:
            if k not in keys:
                keys.append(k)
    out = [f"действие {action} — вхождений {len(sel)}", ""]
    out.append(f"{'id':<12} " + " ".join(f"{k[:14]:<15}" for k in keys))
    varying = {k: set() for k in keys}
    for m in sel:
        cells = []
        for k in keys:
            v = m.action.parameters.get(k, "—")
            cells.append(f"{str(v)[:14]:<15}")
            varying[k].add(json.dumps(v, ensure_ascii=False, sort_keys=True))
        out.append(f"{m.action.action_id[:11]:<12} " + " ".join(cells))
    out.append("")
    const = [k for k in keys if len(varying[k]) == 1]
    chang = [k for k in keys if len(varying[k]) > 1]
    out.append("повторяющиеся (одинаковые параметры): "
               + (", ".join(const) if const else "—"))
    out.append("различающиеся: "
               + (", ".join(f"{k} ({len(varying[k])} знач.)" for k in chang)
                  if chang else "—"))

    # закономерности на уровне байтов: что повторяется в каждом сообщении
    hdr: Dict[str, set] = {}
    seqs: List[Any] = []
    req_ids: set = set()
    resp_ids: set = set()
    for m in sel:
        if m.request and m.request.msg:
            req_ids.add(m.request.id or "вне интерпретации")
            for fname in ("type", "flags"):
                fr = m.request.msg.fields.get(fname)
                if fr is not None and fr.known:
                    hdr.setdefault(fname, set()).add(fr.value)
            fr = m.request.msg.fields.get("seq")
            if fr is not None and fr.known:
                seqs.append(fr.value)
        if m.response:
            resp_ids.add(m.response.id or "вне интерпретации")
    out.append("")
    out.append("закономерности сообщений (повторяются в каждом примере):")
    if len(req_ids) == 1:
        out.append(f"  запрос  = {next(iter(req_ids))}")
    if len(resp_ids) == 1:
        out.append(f"  ответ   = {next(iter(resp_ids))}")
    for fname, vals in hdr.items():
        if len(vals) == 1:
            out.append(f"  {fname} = {next(iter(vals))} (одинаково)")
        else:
            out.append(f"  {fname}: {sorted(vals)} (меняется)")
    if seqs:
        out.append(f"  seq: {seqs} (сквозная нумерация запросов)")
    return "\n".join(out)
