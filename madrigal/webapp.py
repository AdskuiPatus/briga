"""Локальный веб-интерфейс (стек A): FastAPI + статический фронтенд.

Запуск: python -m madrigal serve [--port 8000] [--open]

Отвечает только на запросы localhost. Исходные записи открываются на сервере
по пути (офлайн-сценарий), неизменность источника обеспечивается тем, что
код инструмента их только читает.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
from .capture import CaptureError, open_capture
from .corpus import CorpusError, verify_corpus
from .interpreter import analyze_session, dir_result_to_dict, hyp_check_to_dict
from .jobs import Job, JobStore
from .layers import parse_capture, tcp_flags_str
from .limits import (
    LimitExceeded,
    check_capture,
    file_size,
    get_profile,
)
from .reassembly import DataRun, Stream, build_stream
from .schema import Schema, SchemaError, load_schema_file, load_schema_text
from .sessions import Session, build_sessions

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_CHUNK = 8192          # максимум байт в одном запросе hex-представления
MAX_SEARCH = 8 * 1024 * 1024   # предел сканирования поиска (защитный)
MAX_SCHEMA = 1024 * 1024       # предел размера текста схемы
SCHEMA_SUFFIXES = {".yaml", ".yml", ".json"}
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap", ".dmp", ".trace"}


# ------------------------------------------------------------ состояние ----

class Loaded:
    """Одна открытая запись со всеми производными данными."""

    def __init__(self, path: str):
        self.capture = open_capture(path)
        self.parsed = parse_capture(self.capture)
        self.timestamps = [p.timestamp for p in self.capture.packets]
        self.sessions = build_sessions(self.timestamps, self.parsed)
        self._streams: Dict[tuple, Stream] = {}
        self._lock = threading.Lock()

    def session(self, sid: int) -> Session:
        if sid < 0 or sid >= len(self.sessions):
            raise HTTPException(404, f"нет сессии #{sid}")
        return self.sessions[sid]

    def stream(self, sid: int, direction: str) -> Stream:
        if direction not in ("a2b", "b2a"):
            raise HTTPException(400, "direction должен быть a2b или b2a")
        s = self.session(sid)
        key = (sid, direction)
        with self._lock:
            st = self._streams.get(key)
            if st is None:
                st = build_stream(self.timestamps, self.parsed, s, direction)
                self._streams[key] = st
            return st


class AppState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.loaded: Optional[Loaded] = None
        # текущая схема интерпретации (текст виден в UI, активна пока валидна)
        self.schema: Optional[Schema] = None
        self.schema_text: str = ""
        self.schema_errors: List[str] = []
        # фоновые задачи: ход и отмена длительных операций (раздел 10)
        self.jobs = JobStore()


state = AppState()
app = FastAPI(title="madrigal-lab", version=__version__)


def _require() -> Loaded:
    if state.loaded is None:
        raise HTTPException(400, "запись не открыта")
    return state.loaded


def _require_schema() -> Schema:
    if state.schema is None:
        raise HTTPException(400, "схема не загружена или не прошла валидацию")
    return state.schema


def _schema_info() -> dict:
    s = state.schema
    return {
        "present": s is not None,
        "text": state.schema_text,
        "errors": list(state.schema_errors),
        "name": s.name if s else None,
        "sha256": s.sha256 if s else None,
        "messages": s.message_ids if s else [],
        "hypotheses": [h.id for h in s.hypotheses] if s else [],
        "scope": s.scope_directions if s else None,
    }


# ------------------------------------------------------------- модели ----

class OpenBody(BaseModel):
    path: str
    limits: str = "control"      # control | none — защитный профиль (раздел 10)


class SearchBody(BaseModel):
    session: int
    direction: str
    pattern: str
    mode: str = "ascii"        # ascii | hex
    limit: int = 200


class CompareSide(BaseModel):
    session: int
    direction: str
    offset: int = 0
    length: int = 256


class CompareBody(BaseModel):
    a: CompareSide
    b: CompareSide


class SchemaBody(BaseModel):
    """Загрузка схемы: текстом или путём к файлу на сервере."""
    text: str = ""
    path: str = ""


class ApplyBody(BaseModel):
    scope: str = "session"        # session | all
    session: int = 0
    max_messages: int = 500       # сколько сообщений на поток отдавать в JSON


class VerifyBody(BaseModel):
    """Проверка корпуса: путь к манифесту; схема — файла или текст
    из редактора (живая перепроверка изменённой интерпретации)."""
    path: str
    schema_text: str = ""
    limits: str = "control"      # control | none — защитный профиль


class JobBody(BaseModel):
    """Фоновая задача: verify — проверка корпуса; apply — применение
    схемы (session | all) к открытой записи."""
    op: str                      # verify | apply
    path: str = ""               # verify: манифест корпуса
    schema_text: str = ""        # verify: текст схемы из редактора
    limits: str = "control"      # verify: защитный профиль
    scope: str = "all"           # apply: session | all
    session: int = 0             # apply: номер сессии при scope=session
    max_messages: int = 500      # apply: сообщений на поток в JSON


# ---------------------------------------------------------- сериализация ----

def _session_info(s: Session) -> dict:
    return {
        "id": s.id,
        "a": {"ip": s.a[0], "port": s.a[1], "label": s.a_label},
        "b": {"ip": s.b[0], "port": s.b[1], "label": s.b_label},
        "packets": s.packet_count,
        "payload_bytes": s.payload_bytes,
        "start": s.start,
        "end": s.end,
        "midstream": s.midstream,
        "closed": s.closed,
        "saw_syn": s.saw_syn,
        "fin_count": s.fin_count,
        "saw_rst": s.saw_rst,
        "parse_errors": s.parse_errors,
        "flags": s.flags_summary,
    }


def _stream_stats(st: Stream) -> dict:
    gap_total = sum(g.length for g in st.gaps)
    return {
        "length": st.length,
        "data_length": st.data_length,
        "segments": st.segment_count,
        "gap_count": len(st.gaps),
        "gap_bytes": gap_total,
        "retransmissions": len(st.retransmissions),
        "ambiguities": len(st.ambiguities),
        "midstream": st.midstream,
        "complete": st.is_complete,
        "diagnostics": st.diagnostics,
        "gaps": [{"start": g.start, "length": g.length, "end": g.end}
                 for g in st.gaps],
        "ambiguity_list": [
            {"start": a.start, "end": a.end, "kept": a.kept_packet,
             "alt": a.alt_packet, "alt_hex": a.alt_bytes.hex()}
            for a in st.ambiguities
        ],
    }


def _loaded_info(loaded: Loaded) -> dict:
    cap = loaded.capture
    errors = sum(1 for p in loaded.parsed if p.error)
    warnings = sum(1 for p in loaded.parsed if p.warnings)
    return {
        "path": cap.path,
        "name": Path(cap.path).name,
        "fmt": cap.fmt,
        "sha256": cap.sha256,
        "packets": len(cap.packets),
        "linktypes": cap.linktypes,
        "sessions": len(loaded.sessions),
        "errors": errors,
        "warnings": warnings,
        "notes": cap.notes,
        "version": __version__,
    }


def _cells_payload(st: Stream, offset: int, length: int) -> dict:
    length = max(0, min(length, MAX_CHUNK))
    cells = st.cells(offset, length)
    return {
        "offset": offset,
        "length": length,
        "total": st.length,
        "cells": [[c.offset, c.value, c.packet, 1 if c.amb else 0]
                  for c in cells],
        "stats": _stream_stats(st),
    }


# ------------------------------------------------------------- маршрут ----

@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "version": __version__}


def _limits_or_400(name: str):
    try:
        return get_profile(name)
    except ValueError as e:
        raise HTTPException(400, str(e))


def _limit_response(limits, violations: List[str]):
    text = ("превышение защитных пределов "
            f"({limits.profile}): " + "; ".join(violations)
            + f". {limits.describe()}. Откройте файл с профилем 'none' "
            f"для исследовательского запуска сверх контрольной нагрузки.")
    return HTTPException(413, text)


@app.post("/api/open")
def api_open(body: OpenBody) -> dict:
    path = body.path.strip().strip('"')
    if not path:
        raise HTTPException(400, "путь пуст")
    limits = _limits_or_400(body.limits)
    # защитная проверка размера — до чтения файла в память
    try:
        violations = check_capture(limits, file_bytes=file_size(path))
    except OSError as e:
        raise HTTPException(400, f"не удалось открыть файл: {e}")
    if violations:
        raise _limit_response(limits, violations)
    try:
        loaded = Loaded(path)
    except CaptureError as e:
        raise HTTPException(400, f"ошибка чтения: {e}")
    except OSError as e:
        raise HTTPException(400, f"не удалось открыть файл: {e}")
    violations = check_capture(limits, packets=len(loaded.capture.packets),
                               sessions=len(loaded.sessions))
    if violations:
        raise _limit_response(limits, violations)
    with state.lock:
        state.loaded = loaded
    info = _loaded_info(loaded)
    info["sessions"] = [_session_info(s) for s in loaded.sessions]
    info["limits"] = limits.profile
    return info


@app.get("/api/state")
def api_state() -> dict:
    with state.lock:
        loaded = state.loaded
    if loaded is None:
        return {"loaded": False}
    info = _loaded_info(loaded)
    info["loaded"] = True
    info["sessions"] = [_session_info(s) for s in loaded.sessions]
    return info


@app.get("/api/session/{sid}")
def api_session(sid: int) -> dict:
    loaded = _require()
    s = loaded.session(sid)
    detail = _session_info(s)
    detail["streams"] = {
        d: _stream_stats(loaded.stream(sid, d)) for d in ("a2b", "b2a")
    }
    return detail


@app.get("/api/stream/{sid}/{direction}")
def api_stream(sid: int, direction: str,
               offset: int = Query(0, ge=0),
               length: int = Query(2048)) -> dict:
    loaded = _require()
    st = loaded.stream(sid, direction)
    return _cells_payload(st, offset, length)


@app.get("/api/stream/{sid}/{direction}/text")
def api_stream_text(sid: int, direction: str,
                    offset: int = Query(0, ge=0),
                    length: int = Query(1024)) -> dict:
    """Срез для панели выделения: hex/ascii + происхождение."""
    loaded = _require()
    st = loaded.stream(sid, direction)
    length = max(0, min(length, MAX_CHUNK))
    res = st.slice(offset, length)
    data = bytearray()
    for _s, chunk in res.pieces:
        data += chunk
    packets: List[int] = []
    for s, chunk in res.pieces:
        for pid in st.packets_for(s, len(chunk)):
            if pid not in packets:
                packets.append(pid)
    return {
        "offset": offset,
        "length": length,
        "known": res.known_bytes,
        "unknown": sum(g.length for g in res.gaps),
        "hex": bytes(data).hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
        "packets": packets,
        "gaps": [{"start": g.start, "length": g.length} for g in res.gaps],
    }


@app.post("/api/search")
def api_search(body: SearchBody) -> dict:
    loaded = _require()
    st = loaded.stream(body.session, body.direction)

    pattern_raw = body.pattern.strip()
    if not pattern_raw:
        raise HTTPException(400, "шаблон пуст")
    if body.mode == "hex":
        compact = "".join(pattern_raw.split()).replace(":", "")
        try:
            pattern = bytes.fromhex(compact)
        except ValueError:
            raise HTTPException(400, "некорректный hex-шаблон (ожидаются пары 0-9A-F)")
    else:
        pattern = pattern_raw.encode("utf-8", errors="replace")
    if not pattern:
        raise HTTPException(400, "шаблон пуст")

    # поиск только по достоверным участкам; границы известных кусков сохраняются
    matches: List[int] = []
    scanned = 0
    truncated = False
    for run in st.runs:
        if not isinstance(run, DataRun):
            continue
        if scanned >= MAX_SEARCH:
            truncated = True
            break
        data = run.data
        idx = data.find(pattern)
        while idx != -1:
            matches.append(run.start + idx)
            if len(matches) >= body.limit:
                return {"matches": matches, "total": len(matches),
                        "limited": True, "truncated": False}
            idx = data.find(pattern, idx + 1)
        scanned += len(data)
    return {"matches": matches, "total": len(matches), "limited": False,
            "truncated": truncated, "scanned": scanned}


@app.post("/api/compare")
def api_compare(body: CompareBody) -> dict:
    loaded = _require()
    sa = loaded.stream(body.a.session, body.a.direction)
    sb = loaded.stream(body.b.session, body.b.direction)

    length = max(8, min(min(body.a.length, body.b.length), MAX_CHUNK))
    ca = sa.cells(body.a.offset, length)
    cb = sb.cells(body.b.offset, length)
    n = min(len(ca), len(cb))

    rows = []
    same = diff = unknown = 0
    per_row = 8
    for base in range(0, n, per_row):
        chunk_a = ca[base:base + per_row]
        chunk_b = cb[base:base + per_row]
        flags = []
        for x, y in zip(chunk_a, chunk_b):
            if x.value is None or y.value is None:
                flags.append(-1)
                unknown += 1
            elif x.value == y.value:
                flags.append(1)
                same += 1
            else:
                flags.append(0)
                diff += 1
        rows.append({
            "off_a": chunk_a[0].offset,
            "off_b": chunk_b[0].offset,
            "a": [[c.offset, c.value, c.packet, 1 if c.amb else 0] for c in chunk_a],
            "b": [[c.offset, c.value, c.packet, 1 if c.amb else 0] for c in chunk_b],
            "same": flags,
        })
    return {
        "rows": rows,
        "summary": {"same": same, "diff": diff, "unknown": unknown,
                    "compared": same + diff + unknown},
        "total_a": sa.length,
        "total_b": sb.length,
        "truncated": n < min(body.a.length, body.b.length) or n < length,
    }


def _read_schema_file(raw: str) -> str:
    p = Path(raw.strip().strip('"')).expanduser()
    if p.suffix.lower() not in SCHEMA_SUFFIXES:
        raise HTTPException(
            400, "файл схемы должен быть "
                 + ", ".join(sorted(SCHEMA_SUFFIXES)))
    if not p.is_file():
        raise HTTPException(404, f"файл не найден: {p}")
    try:
        if p.stat().st_size > MAX_SCHEMA:
            raise HTTPException(413, "файл схемы больше 1 МиБ")
        return p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, f"файл не в UTF-8: {p}")
    except OSError as e:
        raise HTTPException(400, f"не удалось прочитать {p}: {e}")


@app.get("/api/schema")
def api_schema_get() -> dict:
    """Текущая схема: текст (для редактора), ошибки, сводка."""
    with state.lock:
        return _schema_info()


@app.post("/api/schema")
def api_schema_post(body: SchemaBody) -> dict:
    """Загрузить и провалидировать схему (текстом или файлом).

    При ошибках активная схема снимается — применять нельзя, пока не валидна.
    """
    text = body.text
    source_path = body.path.strip().strip('"')
    if source_path and not text:
        text = _read_schema_file(source_path)
    if not text.strip():
        raise HTTPException(400, "текст схемы пуст")
    if len(text) > MAX_SCHEMA:
        raise HTTPException(413, "схема больше 1 МиБ")

    with state.lock:
        state.schema_text = text
        try:
            schema = load_schema_text(text, source_path=source_path)
        except SchemaError as e:
            state.schema = None
            state.schema_errors = e.errors
            return _schema_info()
        state.schema = schema
        state.schema_errors = []
        return _schema_info()


@app.post("/api/schema/apply")
def api_schema_apply(body: ApplyBody) -> dict:
    """Применить активную схему к записи и проверить гипотезы (R3→R4)."""
    loaded = _require()
    schema = _require_schema()
    if body.scope not in ("session", "all"):
        raise HTTPException(400, "scope должен быть session или all")
    if body.scope == "session":
        indices = [body.session]
        loaded.session(body.session)          # валидация номера → 404
    else:
        indices = list(range(len(loaded.sessions)))
    max_messages = max(1, min(body.max_messages, 5000))
    directions = schema.scope_directions or ["a2b", "b2a"]

    sessions_out = []
    for idx in indices:
        s = loaded.sessions[idx]
        # потоки кэшируются в Loaded — последующие прыжки в hex дешёвые
        streams = {d: loaded.stream(idx, d) for d in directions}
        results, hyps = analyze_session(schema, streams)
        sessions_out.append({
            "index": idx,
            "endpoints": {"a": s.a_label, "b": s.b_label},
            "midstream": s.midstream,
            "directions": {
                d: dir_result_to_dict(results[d], max_messages)
                for d in directions
            },
            "hypotheses": [hyp_check_to_dict(h) for h in hyps],
        })
    return {
        "schema": {"name": schema.name, "sha256": schema.sha256},
        "file": {"path": loaded.capture.path,
                 "sha256": loaded.capture.sha256},
        "scope": body.scope,
        "sessions": sessions_out,
    }


@app.post("/api/verify")
def api_verify(body: VerifyBody) -> dict:
    """Проверить корпус записей с ожиданиями (R4).

    Отчёт содержит сводку пяти групп находок и штампы входов; независит
    от открытой записи — корпус читается со диска по путям манифеста.
    """
    path = body.path.strip().strip('"')
    if not path:
        raise HTTPException(400, "путь к манифесту корпуса пуст")
    if len(body.schema_text) > MAX_SCHEMA:
        raise HTTPException(413, "схема больше 1 МиБ")
    limits = _limits_or_400(body.limits)
    try:
        return verify_corpus(path, schema_text=body.schema_text or None,
                             limits=limits)
    except CorpusError as e:
        raise HTTPException(400, "корпус не прошёл проверку: "
                                 + "; ".join(e.errors))
    except LimitExceeded as e:
        raise _limit_response(e.limits, e.violations)


# --------------------------------------------------- фоновые задачи ----

def _job_verify_fn(path: str, schema_text: str, limits):
    def run(progress) -> dict:
        try:
            return verify_corpus(path, schema_text=schema_text or None,
                                 limits=limits, progress=progress)
        except CorpusError as e:
            # ошибка корпуса — не сбой задачи, а результат проверки
            return {"corpus_error": "; ".join(e.errors)}
    return run


def _job_apply_fn(loaded: Loaded, schema: Schema, scope: str,
                  session: int, max_messages: int):
    if scope == "session":
        indices = [session]
    else:
        indices = list(range(len(loaded.sessions)))
    directions = schema.scope_directions or ["a2b", "b2a"]

    def run(progress) -> dict:
        progress.start_stage(f"сессий {len(indices)}", len(indices))
        sessions_out = []
        for idx in indices:
            progress.check_cancel()
            s = loaded.sessions[idx]
            streams = {d: loaded.stream(idx, d) for d in directions}
            results, hyps = analyze_session(schema, streams)
            sessions_out.append({
                "index": idx,
                "endpoints": {"a": s.a_label, "b": s.b_label},
                "midstream": s.midstream,
                "directions": {
                    d: dir_result_to_dict(results[d], max_messages)
                    for d in directions
                },
                "hypotheses": [hyp_check_to_dict(h) for h in hyps],
            })
            progress.advance(note=f"сессия {idx}")
        return {
            "schema": {"name": schema.name, "sha256": schema.sha256},
            "file": {"path": loaded.capture.path,
                     "sha256": loaded.capture.sha256},
            "scope": scope,
            "sessions": sessions_out,
        }
    return run


@app.post("/api/jobs")
def api_job_start(body: JobBody) -> dict:
    """Запустить длительную операцию в фоне: клиент поллит /api/jobs/{id},
    видит ход и может отменить. Результат задачи тот же, что у
    синхронного /api/verify и /api/schema/apply."""
    if body.op == "verify":
        path = body.path.strip().strip('"')
        if not path:
            raise HTTPException(400, "путь к манифесту корпуса пуст")
        if len(body.schema_text) > MAX_SCHEMA:
            raise HTTPException(413, "схема больше 1 МиБ")
        limits = _limits_or_400(body.limits)
        job = state.jobs.submit(
            "verify", f"проверка корпуса {Path(path).name}",
            _job_verify_fn(path, body.schema_text, limits))
    elif body.op == "apply":
        loaded = _require()
        schema = _require_schema()
        if body.scope not in ("session", "all"):
            raise HTTPException(400, "scope должен быть session или all")
        if body.scope == "session":
            loaded.session(body.session)          # валидация → 404
        max_messages = max(1, min(body.max_messages, 5000))
        job = state.jobs.submit(
            "apply",
            f"применение схемы {schema.name} "
            f"({'все сессии' if body.scope == 'all' else f'сессия {body.session}'})",
            _job_apply_fn(loaded, schema, body.scope, body.session,
                          max_messages))
    else:
        raise HTTPException(400, "op должен быть verify или apply")
    return job.snapshot(include_result=False)


@app.get("/api/jobs")
def api_job_list() -> dict:
    return {"jobs": [j.snapshot(include_result=False)
                     for j in state.jobs.list()]}


@app.get("/api/jobs/{job_id}")
def api_job_get(job_id: str) -> dict:
    job = state.jobs.get(job_id)
    if job is None:
        raise HTTPException(404, f"нет задачи {job_id}")
    return job.snapshot()


@app.post("/api/jobs/{job_id}/cancel")
def api_job_cancel(job_id: str) -> dict:
    """Отменить задачу: флаг ставится немедленно, останов — на ближайшей
    проверке между единицами работы; статус становится cancelled."""
    job = state.jobs.get(job_id)
    if job is None:
        raise HTTPException(404, f"нет задачи {job_id}")
    job.cancel()
    return job.snapshot(include_result=False)


@app.get("/api/packet/{index}")
def api_packet(index: int) -> dict:
    loaded = _require()
    packets = loaded.capture.packets
    if index < 0 or index >= len(packets):
        raise HTTPException(404, f"нет пакета #{index}")
    pkt = packets[index]
    p = loaded.parsed[index]

    payload_off = -1
    if p.tcp is not None:
        payload_off = len(pkt.data) - len(p.payload)

    hex_limit = 2048
    cells = [[i, int(b), 1 if (payload_off >= 0 and i >= payload_off) else 0, 0]
             for i, b in enumerate(pkt.data[:hex_limit])]

    return {
        "index": pkt.index,
        "timestamp": pkt.timestamp,
        "linktype": pkt.linktype,
        "size": len(pkt.data),
        "orig_len": pkt.orig_len,
        "truncated": pkt.truncated,
        "error": p.error,
        "warnings": p.warnings,
        "ethernet": None if not p.ethernet else {
            "src": p.ethernet.src.hex(":"),
            "dst": p.ethernet.dst.hex(":"),
            "ethertype": f"0x{p.ethernet.ethertype:04X}",
            "vlan": p.ethernet.vlan_ids,
        },
        "ip": None if not p.ip4 else {
            "src": p.ip4.src, "dst": p.ip4.dst, "ttl": p.ip4.ttl,
            "protocol": p.ip4.protocol, "id": p.ip4.identification,
            "frag_offset": p.ip4.frag_offset, "more_fragments": p.ip4.more_fragments,
            "total_len": p.ip4.total_len,
        },
        "tcp": None if not p.tcp else {
            "src_port": p.tcp.src_port, "dst_port": p.tcp.dst_port,
            "seq": p.tcp.seq, "ack": p.tcp.ack, "flags": tcp_flags_str(p.tcp.flags),
            "window": p.tcp.window, "header_len": p.tcp.header_len,
        },
        "payload_len": len(p.payload),
        "payload_offset": payload_off,
        "hex_limit": hex_limit,
        "hex": cells,
    }


@app.get("/api/browse")
def apibrowse(path: str = Query("")) -> dict:
    """Локальный обзор файлов для выбора записи (только localhost)."""
    raw = path.strip().strip('"')
    base = Path(raw).expanduser() if raw else Path.cwd()
    try:
        base = base.resolve()
    except OSError:
        raise HTTPException(400, f"некорректный путь: {raw}")
    if not base.exists():
        raise HTTPException(400, f"путь не существует: {base}")
    if base.is_file():
        return {"type": "file", "path": str(base)}

    dirs: List[str] = []
    files: List[str] = []
    try:
        for entry in sorted(base.iterdir(), key=lambda e: e.name.lower()):
            if entry.is_dir():
                dirs.append(entry.name)
            elif entry.suffix.lower() in PCAP_SUFFIXES:
                files.append(entry.name)
    except PermissionError:
        raise HTTPException(403, f"нет доступа к каталогу: {base}")

    parent = str(base.parent) if base.parent != base else ""
    return {"type": "dir", "path": str(base), "parent": parent,
            "dirs": dirs, "files": files}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
