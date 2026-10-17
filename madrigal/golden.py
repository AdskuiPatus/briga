"""Golden-примеры: воспроизводимые входы и ожидаемые результаты (R6).

Комплект документирует повторное применение интерпретации: фиксированные
входные данные (запись + схема или корпус) и машиночитаемые ожидаемые
результаты. `python -m madrigal golden` прогоняет каждый случай и сверяет
факт с ожиданием: расхождения перечисляются по путям, код выхода 4 —
результаты не согласованы с принятыми ожиданиями.

Манифест (examples/golden.yaml, пути — относительно манифеста):

    version: 1
    name: demo-golden
    cases:
      - name: apply-demo
        kind: apply               # apply | verify | journal
        file: demo.pcapng         # для apply
        schema: demo-protocol.yaml
        # session: 0              # опционально — одна сессия
        expect: {…}               # нормализованный ожидаемый результат
      - name: verify-demo-corpus
        kind: verify
        corpus: demo-corpus.yaml
        expect: {…}
      - name: journal-thermostand
        kind: journal             # корреляция журнала действий с обменом (R2)
        file: ../case/recordings/research/01_configuration.pcap
        schema: ../schemas/thermostand-protocol.yaml
        journal: ../case/action_journal.csv
        expect: {…}

Нормализация сознательно отбрасывает нестабильные детали (время, версию
инструмента) и хранит проверяемые факты: счётчики сообщений по
направлениям, список сообщений (id/смещение/размер), результаты
механической проверки гипотез, sha256 входов. Для journal — итоговые
вердикты корреляции и исход сверки каждого поля. `--update` переписывает
ожидания текущими фактами (после уточнения интерпретации — явное
документирование изменения).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Union

import yaml

from .capture import open_capture
from .interpreter import analyze_session
from .journal import (JournalError, collect_messages, correlate,
                      filter_capture, load_journal, session_spans, summarize)
from .layers import parse_capture
from .reassembly import build_stream
from .schema import SchemaError, load_schema_file
from .sessions import build_sessions
from .corpus import verify_corpus, CorpusError

GOLDEN_VERSION = 1


class GoldenError(Exception):
    """Манифест golden-примеров непригоден."""

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class GoldenCase:
    name: str
    kind: str                       # apply | verify | journal
    file: str = ""                  # apply/journal: запись
    schema: str = ""                # apply/journal: схема
    session: Optional[int] = None   # apply: одна сессия
    corpus: str = ""                # verify: манифест корпуса
    journal: str = ""               # journal: CSV журнала действий
    expect: dict = field(default_factory=dict)


@dataclass
class GoldenSet:
    name: str
    path: Path
    cases: List[GoldenCase]


def _relpath(value: object, path: str, errors: List[str]) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}: ожидается относительный путь")
        return None
    p = value.replace("\\", "/")
    pp = PurePosixPath(p)
    if pp.is_absolute() or (len(p) > 1 and p[1] == ":") or p.startswith("~"):
        errors.append(f"{path}: путь обязан быть относительным: {value!r}")
        return None
    return "/".join(pp.parts)


def load_golden(path: Union[str, Path]) -> GoldenSet:
    p = Path(path)
    if not p.is_file():
        raise GoldenError([f"манифест golden-примеров не найден: {p}"])
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise GoldenError([f"{p}: манифест не в UTF-8"])
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise GoldenError([f"{p}: ошибка YAML: {e}"])
    if not isinstance(data, dict):
        raise GoldenError([f"{p}: ожидался словарь с ключами version/name/cases"])

    errors: List[str] = []
    version = data.get("version", 1)
    if version != GOLDEN_VERSION:
        errors.append(f"version: поддерживается только "
                      f"{GOLDEN_VERSION} (получено {version!r})")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("name: непустая строка обязательна")
        name = ""
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        errors.append("cases: нужен непустой список")
        raw_cases = []

    base = p.resolve().parent
    cases: List[GoldenCase] = []
    seen: set = set()
    for i, raw in enumerate(raw_cases):
        where = f"cases[{i}]"
        if not isinstance(raw, dict):
            errors.append(f"{where}: ожидается словарь")
            continue
        cname = raw.get("name")
        if not isinstance(cname, str) or not cname.strip():
            errors.append(f"{where}.name: непустая строка обязательна")
            continue
        if cname in seen:
            errors.append(f"{where}.name: имя {cname!r} повторяется")
            continue
        seen.add(cname)
        kind = raw.get("kind")
        if kind not in ("apply", "verify", "journal"):
            errors.append(f"{where}.kind: ожидается apply, verify или journal")
            continue
        case = GoldenCase(name=cname, kind=kind)
        if kind == "apply":
            case.file = _relpath(raw.get("file"), f"{where}.file", errors) or ""
            case.schema = _relpath(raw.get("schema"), f"{where}.schema",
                                   errors) or ""
            sess = raw.get("session")
            if sess is not None and (isinstance(sess, bool)
                                     or not isinstance(sess, int) or sess < 0):
                errors.append(f"{where}.session: ожидается целое >= 0")
            else:
                case.session = sess
            for label, rel in (("file", case.file), ("schema", case.schema)):
                if rel and not (base / rel).is_file():
                    errors.append(f"{where}.{label}: файл не найден: {rel}")
        elif kind == "journal":
            case.file = _relpath(raw.get("file"), f"{where}.file", errors) or ""
            case.schema = _relpath(raw.get("schema"), f"{where}.schema",
                                   errors) or ""
            case.journal = _relpath(raw.get("journal"), f"{where}.journal",
                                    errors) or ""
            for label, rel in (("file", case.file), ("schema", case.schema),
                               ("journal", case.journal)):
                if rel and not (base / rel).is_file():
                    errors.append(f"{where}.{label}: файл не найден: {rel}")
        else:
            case.corpus = _relpath(raw.get("corpus"), f"{where}.corpus",
                                   errors) or ""
            if case.corpus and not (base / case.corpus).is_file():
                errors.append(f"{where}.corpus: файл не найден: {case.corpus}")
        expect = raw.get("expect", {})
        if not isinstance(expect, dict):
            errors.append(f"{where}.expect: ожидается словарь "
                          f"(или отсутствует — тогда заполнится --update)")
            expect = {}
        case.expect = expect
        cases.append(case)

    if errors:
        raise GoldenError(errors)
    return GoldenSet(name=name, path=p, cases=cases)


# ------------------------------------------------------------- прогон -----

def _session_result(schema, ts, parsed, s, index: int) -> dict:
    directions = schema.scope_directions or ["a2b", "b2a"]
    streams = {d: build_stream(ts, parsed, s, d) for d in directions}
    results, hyps = analyze_session(schema, streams)
    dirs: Dict[str, dict] = {}
    for d in directions:
        st = results[d].stats
        dirs[d] = {
            "messages": st["messages"],
            "matched": st["matched"],
            "unmatched": st["unmatched"],
            "partial": st["partial"],
            "framing_errors": st["framing_errors"],
            "unframed_bytes": st["unframed_bytes"],
            "total_bytes": st["total_bytes"],
            "message_list": [
                {"id": m.id, "direction": m.direction,
                 "start": m.start, "size": m.size}
                for m in results[d].messages],
        }
    return {
        "index": index,
        "directions": dirs,
        "hypotheses": {h.id: h.result for h in hyps},
    }


def run_apply(base: Path, case: GoldenCase) -> dict:
    try:
        schema = load_schema_file(base / case.schema)
    except SchemaError as e:
        raise GoldenError([f"{case.name}: схема {case.schema}: "
                           + "; ".join(e.errors)])
    cap = open_capture(str(base / case.file))
    parsed = parse_capture(cap)
    ts = [p.timestamp for p in cap.packets]
    sessions = build_sessions(ts, parsed)
    indices = [case.session] if case.session is not None \
        else list(range(len(sessions)))
    for i in indices:
        if not 0 <= i < len(sessions):
            raise GoldenError([f"{case.name}: нет сессии #{i} "
                               f"(всего {len(sessions)})"])
    return {
        "kind": "apply",
        "file_sha256": cap.sha256,
        "schema_sha256": schema.sha256,
        "sessions": [_session_result(schema, ts, parsed, sessions[i], i)
                     for i in indices],
    }


def run_verify(base: Path, case: GoldenCase) -> dict:
    try:
        report = verify_corpus(base / case.corpus)
    except CorpusError as e:
        raise GoldenError([f"{case.name}: корпус {case.corpus}: "
                           + "; ".join(e.errors)])
    return {
        "kind": "verify",
        "corpus_sha256": report["corpus"]["sha256"],
        "schema_sha256": report["schema"]["sha256"],
        "totals": report["totals"],
        "summary_counts": report["summary_counts"],
        "files": [{"path": f["path"], "ok": f["ok"],
                   "sessions": f["sessions"],
                   "hypotheses": {h["id"]: h["result"]
                                  for h in f["hypotheses"]}}
                  for f in report["files"]],
    }


def run_journal(base: Path, case: GoldenCase) -> dict:
    try:
        schema = load_schema_file(base / case.schema)
    except SchemaError as e:
        raise GoldenError([f"{case.name}: схема {case.schema}: "
                           + "; ".join(e.errors)])
    if schema.journal is None:
        raise GoldenError([f"{case.name}: в схеме {case.schema} нет секции "
                           f"journal — корреляция действий невозможна"])
    try:
        actions, _warn = load_journal(base / case.journal)
    except JournalError as e:
        raise GoldenError([f"{case.name}: журнал {case.journal}: "
                           + "; ".join(e.errors)])
    cap = open_capture(str(base / case.file))
    parsed = parse_capture(cap)
    ts = [p.timestamp for p in cap.packets]
    sessions = build_sessions(ts, parsed)
    acts = filter_capture(actions, Path(cap.path).name)
    if not acts:
        raise GoldenError([f"{case.name}: в журнале нет действий для записи "
                           f"{Path(cap.path).name}"])
    directions = schema.scope_directions or ["a2b", "b2a"]
    msgs_by_session: Dict[int, list] = {}
    for si, s in enumerate(sessions):
        streams = {d: build_stream(ts, parsed, s, d) for d in directions}
        results, _hyps = analyze_session(schema, streams)
        msgs_by_session[si] = collect_messages(si, streams, results, ts)
    spans = session_spans(sessions, ts)
    matches = correlate(acts, msgs_by_session, spans, schema.journal)
    totals = summarize(matches)
    journal_sha = hashlib.sha256(
        (base / case.journal).read_bytes()).hexdigest()
    return {
        "kind": "journal",
        "file_sha256": cap.sha256,
        "schema_sha256": schema.sha256,
        "journal_sha256": journal_sha,
        "actions_count": len(acts),
        "totals": totals,
        # по действию: вердикт корреляции и исход сверки каждого поля
        "actions": [{"action_id": m.action.action_id, "verdict": m.verdict,
                     "checks": {c.path: c.equal for c in m.checks}}
                    for m in matches],
    }


def run_case(golden: GoldenSet, case: GoldenCase) -> dict:
    base = golden.path.resolve().parent
    if case.kind == "apply":
        return run_apply(base, case)
    if case.kind == "journal":
        return run_journal(base, case)
    return run_verify(base, case)


# ---------------------------------------------------------- сравнение -----

def _diff(expected, actual, path: str, out: List[str], limit: int = 30) -> None:
    if len(out) >= limit:
        return
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            sub = f"{path}.{key}" if path else str(key)
            if key not in actual:
                out.append(f"{sub}: в ожиданиях есть, в факте отсутствует")
            elif key not in expected:
                out.append(f"{sub}: фактическое значение отсутствует "
                           f"в ожиданиях")
            else:
                _diff(expected[key], actual[key], sub, out, limit)
        return
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            out.append(f"{path}: ожидалось элементов {len(expected)}, "
                       f"получено {len(actual)}")
        for i, (e, a) in enumerate(zip(expected, actual)):
            _diff(e, a, f"{path}[{i}]", out, limit)
        return
    if expected != actual:
        out.append(f"{path}: ожидалось {expected!r}, получено {actual!r}")


def check_golden(path: Union[str, Path]) -> dict:
    """Прогнать все golden-случаи и сверить с ожидаемыми результатами."""
    golden = load_golden(path)
    results: List[dict] = []
    ok_all = True
    for case in golden.cases:
        entry: Dict[str, object] = {"name": case.name, "kind": case.kind}
        try:
            actual = run_case(golden, case)
        except GoldenError as e:
            entry["error"] = "; ".join(e.errors)
            entry["ok"] = False
            results.append(entry)
            ok_all = False
            continue
        diffs: List[str] = []
        if not case.expect:
            diffs.append("expect не задан — заполните --update")
        else:
            _diff(case.expect, actual, "", diffs)
        entry["ok"] = not diffs
        entry["diffs"] = diffs
        entry["actual"] = actual
        results.append(entry)
        if diffs:
            ok_all = False
    return {"name": golden.name, "path": str(golden.path),
            "cases": results, "ok": ok_all}


def update_golden(path: Union[str, Path]) -> dict:
    """Переписать манифест с текущими фактами как ожидаемыми результатами."""
    golden = load_golden(path)
    text = golden.path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    for case_entry in data.get("cases") or []:
        case = next(c for c in golden.cases
                    if c.name == case_entry.get("name"))
        case_entry["expect"] = run_case(golden, case)
    golden.path.write_text(
        "# Golden-примеры (R6): фиксированные входы + ожидаемые результаты.\n"
        "# Проверка: python -m madrigal golden\n"
        "# Обновление после уточнения интерпретации: "
        "python -m madrigal golden --update\n"
        + yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    return {"path": str(golden.path), "cases": len(golden.cases)}


def golden_to_json(path: Union[str, Path]) -> dict:
    """Полный фактический результат (для --json/отладки)."""
    golden = load_golden(path)
    return {"name": golden.name,
            "cases": [{"name": c.name, "actual": run_case(golden, c)}
                      for c in golden.cases]}
