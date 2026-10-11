"""Замеры времени и памяти основных операций (раздел 10 кейса).

Измеряются Wallace-время и память по стадиям конвейера исследования
на контрольной нагрузке:

    open      чтение файла, sha256, заголовки PCAP/PCAPNG
    parse     разбор Ethernet/IPv4/TCP каждого пакета
    sessions  группировка в TCP-соединения
    reassembly восстановление потоков (обе стороны каждой сессии)
    apply     применение схемы интерпретации (если задана схема)
    verify    проверка корпуса с ожиданиями (если задан корпус)

Память: текущий и пиковый RSS процесса (Linux — /proc, Windows —
GetProcessMemoryInfo); пиковый RSS монотонен, поэтому для стадий
сообщается прирост текущего RSS, а пик — общий по процессу.

Результат — таблица для человека и JSON для отчёта. Замер воспроизводим
по входам (одна и та же запись/схема/корпус), но само время зависит от
машины; детерминизм результата анализа обеспечивают golden-примеры.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from . import __version__
from .capture import open_capture
from .corpus import verify_corpus
from .interpreter import analyze_session
from .layers import parse_capture
from .reassembly import build_stream
from .schema import load_schema_file
from .sessions import build_sessions


# ------------------------------------------------------------- память ----

def _rss_windows() -> tuple[Optional[int], Optional[int]]:
    import ctypes
    from ctypes import wintypes

    class PMC(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.GetCurrentProcess()
    counters = PMC()
    counters.cb = ctypes.sizeof(PMC)
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                      counters.cb):
        return None, None
    return counters.WorkingSetSize, counters.PeakWorkingSetSize


def _rss_linux() -> tuple[Optional[int], Optional[int]]:
    current = peak = None
    try:
        with open("/proc/self/status", "r", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    current = int(line.split()[1]) * 1024
                elif line.startswith("VmHWM:"):
                    peak = int(line.split()[1]) * 1024
    except OSError:
        return None, None
    return current, peak


def memory_snapshot() -> tuple[Optional[int], Optional[int]]:
    """(текущий RSS, пиковый RSS) в байтах; None — недоступно."""
    if sys.platform == "win32":
        return _rss_windows()
    return _rss_linux()


def _mb(n: Optional[int]) -> Optional[float]:
    return None if n is None else round(n / (1 << 20), 1)


# ------------------------------------------------------------ замер ----

class _Stage:
    def __init__(self, name: str, title: str):
        self.name = name
        self.title = title
        self.seconds = 0.0
        self.items = 0
        self.rss_before: Optional[int] = None
        self.rss_after: Optional[int] = None
        self.peak_rss: Optional[int] = None

    def as_dict(self) -> dict:
        per_sec = (self.items / self.seconds) if self.seconds > 0 else None
        return {
            "name": self.name,
            "title": self.title,
            "seconds": round(self.seconds, 3),
            "items": self.items,
            "items_per_sec": (int(per_sec) if per_sec else None),
            "rss_before_mb": _mb(self.rss_before),
            "rss_after_mb": _mb(self.rss_after),
            "rss_delta_mb": (None if self.rss_before is None
                             or self.rss_after is None
                             else round((self.rss_after - self.rss_before)
                                        / (1 << 20), 1)),
            "peak_rss_mb": _mb(self.peak_rss),
        }


def _run_stage(stage: _Stage, fn: Callable[[], int]) -> None:
    stage.rss_before, _ = memory_snapshot()
    t0 = time.perf_counter()
    stage.items = fn()
    stage.seconds = time.perf_counter() - t0
    stage.rss_after, stage.peak_rss = memory_snapshot()


def bench_file(path: str | Path,
               schema_path: Optional[str | Path] = None,
               corpus_path: Optional[str | Path] = None,
               progress=None) -> dict:
    """Замерить конвейер исследования на записи.

    schema_path — применение интерпретации ко всей записи; corpus_path —
    проверка корпуса (последняя стадия, если задана).
    """
    stages: List[_Stage] = []
    path = str(path)

    cap_holder: dict = {}

    def do_open() -> int:
        cap = open_capture(path)
        cap_holder["cap"] = cap
        return len(cap.packets)

    st = _Stage("open", "чтение записи, sha256, заголовки")
    _run_stage(st, do_open)
    stages.append(st)
    if progress:
        progress("open", st.seconds, st.items)
    cap = cap_holder["cap"]

    parsed_holder: dict = {}

    def do_parse() -> int:
        parsed = parse_capture(cap)
        parsed_holder["parsed"] = parsed
        return len(parsed)

    st = _Stage("parse", "разбор Ethernet/IPv4/TCP")
    _run_stage(st, do_parse)
    stages.append(st)
    if progress:
        progress("parse", st.seconds, st.items)
    parsed = parsed_holder["parsed"]
    timestamps = [p.timestamp for p in cap.packets]

    sess_holder: dict = {}

    def do_sessions() -> int:
        sessions = build_sessions(timestamps, parsed)
        sess_holder["sessions"] = sessions
        return len(sessions)

    st = _Stage("sessions", "группировка в TCP-соединения")
    _run_stage(st, do_sessions)
    stages.append(st)
    if progress:
        progress("sessions", st.seconds, st.items)
    sessions = sess_holder["sessions"]

    def do_reassembly() -> int:
        n = 0
        for s in sessions:
            for d in ("a2b", "b2a"):
                build_stream(timestamps, parsed, s, d)
                n += 1
        return n

    st = _Stage("reassembly", "восстановление потоков (обе стороны)")
    _run_stage(st, do_reassembly)
    stages.append(st)
    if progress:
        progress("reassembly", st.seconds, st.items)

    schema = None
    if schema_path:
        schema = load_schema_file(schema_path)
        directions = schema.scope_directions or ["a2b", "b2a"]

        def do_apply() -> int:
            n = 0
            for s in sessions:
                streams = {d: build_stream(timestamps, parsed, s, d)
                           for d in directions}
                analyze_session(schema, streams)
                n += 1
            return n

        st = _Stage("apply", f"применение схемы {schema.name}")
        _run_stage(st, do_apply)
        stages.append(st)
        if progress:
            progress("apply", st.seconds, st.items)

    if corpus_path:
        def do_verify() -> int:
            report = verify_corpus(corpus_path)
            return report["totals"]["files"]

        st = _Stage("verify", "проверка корпуса с ожиданиями")
        _run_stage(st, do_verify)
        stages.append(st)
        if progress:
            progress("verify", st.seconds, st.items)

    _, peak = memory_snapshot()
    try:
        file_bytes = Path(path).stat().st_size
    except OSError:
        file_bytes = None
    return {
        "tool": {"name": "madrigal-lab", "version": __version__},
        "generated_at": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds"),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "file": {"path": path, "sha256": cap.sha256,
                 "bytes": file_bytes,
                 "packets": len(cap.packets),
                 "sessions": len(sessions)},
        "schema": ({"path": str(schema_path), "sha256": schema.sha256}
                   if schema else None),
        "corpus": str(corpus_path) if corpus_path else None,
        "stages": [s.as_dict() for s in stages],
        "total_seconds": round(sum(s.seconds for s in stages), 3),
        "peak_rss_mb": _mb(peak),
    }


def render_bench(report: dict) -> str:
    """Человекочитаемая таблица замера."""
    f = report["file"]
    lines = [
        f"замер: {Path(f['path']).name} — пакетов {f['packets']}, "
        f"сессий {f['sessions']}",
        f"платформа: {report['platform']}, python {report['python']}",
        "",
        f"{'стадия':<14}{'время, с':>10}{'элементов':>12}"
        f"{'элем/с':>12}{'RSS-прирост, МиБ':>18}",
        "-" * 66,
    ]
    for s in report["stages"]:
        per = (f"{s['items_per_sec']:,}".replace(",", " ")
               if s["items_per_sec"] else "—")
        delta = ("—" if s["rss_delta_mb"] is None
                 else f"{s['rss_delta_mb']:+.1f}")
        items = f"{s['items']:,}".replace(",", " ")
        lines.append(f"{s['name']:<14}{s['seconds']:>10.3f}"
                     f"{items:>12}{per:>12}{delta:>18}")
    lines.append("-" * 66)
    peak = report["peak_rss_mb"]
    lines.append(f"итого {report['total_seconds']:.3f} с; "
                 f"пиковый RSS процесса: "
                 f"{peak if peak is not None else 'н/д'} МиБ")
    if report.get("schema"):
        lines.append(f"схема: {Path(report['schema']['path']).name} "
                     f"(sha256 {report['schema']['sha256'][:12]}…)")
    if report.get("corpus"):
        lines.append(f"корпус: {report['corpus']}")
    return "\n".join(lines)
