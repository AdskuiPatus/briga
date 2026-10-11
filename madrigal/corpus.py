"""Корпус записей с ожиданиями и механическая проверка интерпретаций (R4).

Манифест корпуса — декларативный YAML/JSON рядом с записями:

    version: 1
    name: demo-corpus
    schema: demo-protocol.yaml      # путь относительно манифеста
    files:
      - path: demo.pcapng           # путь относительно манифеста
        note: эталонное соединение
        expect:
          sessions: 1
          directions:
            b2a:
              matched: {set_value: 2}  # сверяются только перечисленные типы
              unmatched: 0             # числа сверяются строго
              partial: 0
          hypotheses:
            h-echo: pass

Проверка сопоставляет ожидания с результатом применения схемы и собирает
отчёт с пятью группами находок (R4):

  нарушения        — ожидания не выполнились или гипотеза опровергнута
                     данными (контрпримеры прикрепляются к пакетам);
  неохват          — данные, которые схема не описала: неопознанные
                     сообщения, байты вне сообщений, ошибки фрейминга;
  неоднозначности  — конфликтующие перекрытия восстановления (оставлен
                     первый увиденный вариант);
  неприменимые     — проверки, не запускавшиеся по построению (вне
                     области действия, нет примеров сообщений);
  неизвестные      — недостающие данные: пропуски, частичные сообщения,
                     неполные пары, соединения без рукопожатия.

Каждый отчёт штампуется: версия инструмента, время, sha256 манифеста,
схемы и каждой записи. `python -m madrigal stale ОТЧЁТ` пересчитывает
контрольные суммы и перечисляет причины устаревания — устаревший
результат отличим от актуального механически.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

import yaml

from . import __version__
from .capture import CaptureError, open_capture
from .interpreter import HypCheck, analyze_session, hyp_check_to_dict
from .layers import parse_capture
from .limits import LimitExceeded, Limits, check_capture, file_size
from .progress import Progress
from .reassembly import build_stream
from .schema import SchemaError, load_schema_file, load_schema_text
from .sessions import build_sessions

DIRECTIONS = ("a2b", "b2a")
HYP_RANK = {"not_applicable": 1, "not_checked": 1, "pass": 2,
            "incomplete": 3, "fail": 4}
HYP_RESULTS = set(HYP_RANK)
# строго сверяемые числовые поля ожиданий по направлениям
DIR_INT_KEYS = ("messages", "unmatched", "partial", "match_unknown",
                "framing_errors", "unframed_bytes")
GROUPS = ("violations", "coverage", "ambiguities", "not_applicable", "unknown")
CE_LIMIT = 20              # сколько контрпримеров включать в отчёт на гипотезу


class CorpusError(Exception):
    """Манифест, схема или запись корпуса непригодны для проверки."""

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# ------------------------------------------------------------ манифест ----

@dataclass
class CorpusFile:
    path: str                       # относительно каталога манифеста
    note: str = ""
    expect: dict = field(default_factory=dict)


@dataclass
class Corpus:
    name: str
    schema_ref: str                 # путь к схеме относительно манифеста
    manifest_path: str              # как передан в команде
    base_dir: Path                  # каталог манифеста (абсолютный)
    manifest_sha256: str            # sha256 байтов манифеста
    files: List[CorpusFile]


def _check_keys(d: dict, allowed: set, path: str, errors: List[str]) -> None:
    for k in d:
        if k not in allowed:
            hint = ""
            if any(k.startswith(a[:4]) for a in allowed):
                hint = " (возможно, опечатка)"
            errors.append(f"{path}: неизвестный ключ {k!r}{hint}")


def _nonneg_int(v: Union[int, float], path: str, errors: List[str]) -> int:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or int(v) != v \
            or v < 0:
        errors.append(f"{path}: ожидалось целое >= 0, получено {v!r}")
        return 0
    return int(v)


def _load_yaml(path: Path) -> tuple[Optional[dict], List[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None, [f"{path.name}: файл не в UTF-8"]
    except OSError as e:
        return None, [f"не удалось прочитать {path}: {e}"]
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, [f"{path.name}: ошибка YAML: {e}"]
    if not isinstance(data, dict):
        return None, [f"{path.name}: ожидался словарь с ключами "
                      f"version/name/schema/files"]
    return data, []


def load_corpus(path: Union[str, Path]) -> Corpus:
    """Загрузить и провалидировать манифест корпуса."""
    p = Path(path)
    if not p.is_file():
        raise CorpusError([f"манифест не найден: {p}"])
    data, errors = _load_yaml(p)
    if data is None:
        raise CorpusError(errors)

    errors = []
    _check_keys(data, {"version", "name", "schema", "files"}, "корпус", errors)

    version = data.get("version", 1)
    if version != 1:
        errors.append(f"version: поддерживается только 1 (получено {version!r})")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("name: имя корпуса (непустая строка) обязательно")
        name = ""
    schema_ref = data.get("schema")
    if not isinstance(schema_ref, str) or not schema_ref.strip():
        errors.append("schema: путь к файлу схемы обязателен")
        schema_ref = ""
    raw_files = data.get("files")
    files: List[CorpusFile] = []
    if not isinstance(raw_files, list) or not raw_files:
        errors.append("files: нужен непустой список записей корпуса")
        raw_files = []
    for i, entry in enumerate(raw_files):
        where = f"files[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: ожидался словарь с ключом path")
            continue
        _check_keys(entry, {"path", "note", "expect"}, where, errors)
        fpath = entry.get("path")
        if not isinstance(fpath, str) or not fpath.strip():
            errors.append(f"{where}.path: путь к записи обязателен")
            continue
        note = entry.get("note", "")
        if not isinstance(note, str):
            errors.append(f"{where}.note: ожидалась строка")
            note = ""
        expect = entry.get("expect", {})
        if not isinstance(expect, dict):
            errors.append(f"{where}.expect: ожидался словарь ожиданий")
            expect = {}
        else:
            _check_keys(expect, {"sessions", "directions", "hypotheses"},
                        f"{where}.expect", errors)
            if "sessions" in expect:
                expect["sessions"] = _nonneg_int(
                    expect["sessions"], f"{where}.expect.sessions", errors)
            dirs = expect.get("directions")
            if dirs is not None:
                if not isinstance(dirs, dict):
                    errors.append(f"{where}.expect.directions: ожидался словарь")
                    expect["directions"] = {}
                else:
                    _check_keys(dirs, set(DIRECTIONS),
                                f"{where}.expect.directions", errors)
                    for dname, dexp in dirs.items():
                        w = f"{where}.expect.directions.{dname}"
                        if dname not in DIRECTIONS:
                            continue            # уже указано в _check_keys
                        if not isinstance(dexp, dict):
                            errors.append(f"{w}: ожидался словарь")
                            dirs[dname] = {}
                            continue
                        _check_keys(dexp, set(DIR_INT_KEYS) | {"matched"},
                                    w, errors)
                        for k in list(dexp):
                            if k in DIR_INT_KEYS:
                                dexp[k] = _nonneg_int(dexp[k], f"{w}.{k}",
                                                      errors)
                        matched = dexp.get("matched")
                        if matched is not None:
                            if not isinstance(matched, dict):
                                errors.append(f"{w}.matched: ожидался словарь "
                                              f"тип -> количество")
                                dexp["matched"] = {}
                            else:
                                for mid, n in list(matched.items()):
                                    matched[mid] = _nonneg_int(
                                        n, f"{w}.matched.{mid}", errors)
            hyps = expect.get("hypotheses")
            if hyps is not None:
                if not isinstance(hyps, dict):
                    errors.append(f"{where}.expect.hypotheses: ожидался словарь")
                    expect["hypotheses"] = {}
                else:
                    for hid, res in list(hyps.items()):
                        if res not in HYP_RESULTS:
                            errors.append(
                                f"{where}.expect.hypotheses.{hid}: результат "
                                f"{res!r} должен быть одним из "
                                f"{sorted(HYP_RESULTS)}")
        files.append(CorpusFile(path=fpath, note=note, expect=expect))

    base = p.resolve().parent
    if schema_ref:
        if not (base / schema_ref).is_file():
            errors.append(f"schema: файл схемы не найден: {base / schema_ref}")
    for f in files:
        if not (base / f.path).is_file():
            errors.append(f"запись не найдена: {base / f.path}")

    if errors:
        raise CorpusError(errors)
    return Corpus(name=name, schema_ref=schema_ref, manifest_path=str(p),
                  base_dir=base,
                  manifest_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                  files=files)


# -------------------------------------------------------------- прогон ----

def _merge_hyp(into: Dict[str, HypCheck], h: HypCheck, session: int) -> None:
    """Свести результаты гипотезы по сессиям: худший результат побеждает."""
    ce = [dict(x, session=session) for x in h.counterexamples]
    cur = into.get(h.id)
    if cur is None:
        into[h.id] = replace(h, basis=list(h.basis), counterexamples=ce,
                             unpaired_a=list(h.unpaired_a),
                             unpaired_b=list(h.unpaired_b))
        return
    cur.pairs_total += h.pairs_total
    cur.pairs_ok += h.pairs_ok
    cur.pairs_unknown += h.pairs_unknown
    cur.unpaired_a.extend(h.unpaired_a)
    cur.unpaired_b.extend(h.unpaired_b)
    cur.counterexamples.extend(ce)
    if HYP_RANK[h.result] > HYP_RANK[cur.result]:
        cur.result = h.result
        cur.note = h.note
        cur.status_after = h.status_after


def _empty_dir_agg() -> dict:
    return {"scope_ok": True, "notes": [], "messages": 0, "matched": {},
            "unmatched": 0, "partial": 0, "match_unknown": 0,
            "framing_errors": 0, "unframed_bytes": 0, "known_bytes": 0,
            "described_bytes": 0, "total_bytes": 0}


def run_capture(path: Path, schema: Schema) -> dict:
    """Применить схему ко всем сессиям записи, свести в файловый отчёт."""
    cap = open_capture(str(path))
    parsed = parse_capture(cap)
    ts = [p.timestamp for p in cap.packets]
    sessions = build_sessions(ts, parsed)

    dirs: Dict[str, dict] = {d: _empty_dir_agg() for d in DIRECTIONS}
    # все сводимые счётчики Direction-отчёта (ожидания сверяют только DIR_INT_KEYS)
    sum_keys = DIR_INT_KEYS + ("total_bytes", "known_bytes", "described_bytes")
    stream_facts: Dict[str, dict] = {d: {"gaps": 0, "gap_bytes": 0,
                                         "ambiguities": 0,
                                         "retransmissions": 0}
                                     for d in DIRECTIONS}
    hyps: Dict[str, HypCheck] = {}
    midstream_sessions = 0

    # направления вне области действия схемы не подменяются нулями
    for d in DIRECTIONS:
        if schema.scope_directions and d not in schema.scope_directions:
            dirs[d]["scope_ok"] = False
            dirs[d]["notes"].append("вне области действия схемы "
                                    "(scope.directions)")

    for i, s in enumerate(sessions):
        streams = {d: build_stream(ts, parsed, s, d) for d in DIRECTIONS}
        for d in DIRECTIONS:
            st = streams[d]
            facts = stream_facts[d]
            facts["gaps"] += len(st.gaps)
            facts["gap_bytes"] += sum(g.length for g in st.gaps)
            facts["ambiguities"] += len(st.ambiguities)
            facts["retransmissions"] += len(st.retransmissions)
        if s.midstream:
            midstream_sessions += 1

        results, hyp_list = analyze_session(schema, streams)
        for h in hyp_list:
            _merge_hyp(hyps, h, i)
        for d, r in results.items():
            agg = dirs.get(d)
            if agg is None:                     # неожиданное направление
                continue
            st = r.stats
            if not r.scope_ok:
                agg["scope_ok"] = False
                if r.note and r.note not in agg["notes"]:
                    agg["notes"].append(r.note)
                continue
            for key in sum_keys:
                agg[key] += st[key]
            for mid, n in st["matched"].items():
                agg["matched"][mid] = agg["matched"].get(mid, 0) + n

    return {
        "sha256": cap.sha256,
        "packets_count": len(cap.packets),
        "sessions_count": len(sessions),
        "midstream_sessions": midstream_sessions,
        "directions": dirs,
        "stream": stream_facts,
        "hypotheses": hyps,
    }


# ------------------------------------------------------ оценка и отчёт ----

def _hyp_entry(h: HypCheck) -> dict:
    d = hyp_check_to_dict(h)
    total = len(h.counterexamples)
    d["counterexamples"] = h.counterexamples[:CE_LIMIT]
    d["counterexamples_total"] = total
    return d


def _evaluate(run: dict, expect: dict) -> dict:
    """Свести прогон и ожидания: mismatches, violations, findings."""
    mismatches: List[str] = []
    dirs = run["directions"]

    if "sessions" in expect and expect["sessions"] != run["sessions_count"]:
        mismatches.append(f"сессий: ожидалось {expect['sessions']}, "
                          f"получено {run['sessions_count']}")

    for d, dexp in expect.get("directions", {}).items():
        agg = dirs.get(d)
        if agg is None or not agg["scope_ok"]:
            note = "; ".join(agg["notes"]) if agg and agg["notes"] else \
                "нет результата"
            mismatches.append(f"{d}: направление не обработано схемой — {note}")
            continue
        for mid, n in (dexp.get("matched") or {}).items():
            act = agg["matched"].get(mid, 0)
            if act != n:
                mismatches.append(f"{d}.{mid}: ожидалось {n}, получено {act}")
        for key in DIR_INT_KEYS:
            if key in dexp and dexp[key] != agg[key]:
                mismatches.append(f"{d}.{key}: ожидалось {dexp[key]}, "
                                  f"получено {agg[key]}")

    hyps: Dict[str, HypCheck] = run["hypotheses"]
    for hid, want in expect.get("hypotheses", {}).items():
        actual = hyps.get(hid)
        if actual is None:
            mismatches.append(f"гипотеза {hid}: в схеме такой нет")
        elif actual.result != want:
            mismatches.append(f"гипотеза {hid}: ожидался результат {want}, "
                              f"получен {actual.result}")

    violations = list(mismatches)
    for h in hyps.values():
        if h.result != "fail":
            continue
        line = (f"гипотеза {h.id} опровергнута данными: контрпримеров "
                f"{len(h.counterexamples)} из {h.pairs_total} пар")
        if h.counterexamples:
            ce = h.counterexamples[0]
            line += (f"; первый: {ce['a']['message']}#{ce['a']['index']}="
                     f"{ce['a']['value']} против {ce['b']['message']}"
                     f"#{ce['b']['index']}={ce['b']['value']}")
        violations.append(line)

    coverage: List[str] = []
    ambiguities: List[str] = []
    not_applicable: List[str] = []
    unknown: List[str] = []

    for d in DIRECTIONS:
        agg = dirs[d]
        facts = run["stream"][d]
        if not agg["scope_ok"]:
            not_applicable.append(f"{d}: не применялось — "
                                  + ("; ".join(agg["notes"]) or "без правила"))
            continue
        if agg["unmatched"]:
            coverage.append(f"{d}: неопознанных сообщений {agg['unmatched']} — "
                            f"правилами схемы не описаны")
        if agg["unframed_bytes"]:
            coverage.append(f"{d}: {agg['unframed_bytes']} Б данных вне сообщений")
        if agg["framing_errors"]:
            coverage.append(f"{d}: ошибок фрейминга {agg['framing_errors']} — "
                            f"поток не размечен полностью")
        if facts["ambiguities"]:
            ambiguities.append(f"{d}: конфликтующих перекрытий "
                               f"{facts['ambiguities']} (оставлен первый "
                               f"увиденный вариант)")
        if facts["gaps"]:
            unknown.append(f"{d}: неизвестных байтов {facts['gap_bytes']} "
                           f"в {facts['gaps']} пропусках")
        if agg["partial"]:
            unknown.append(f"{d}: частичных сообщений {agg['partial']} — "
                           f"байты не подменяются")
        if agg["match_unknown"]:
            unknown.append(f"{d}: сообщений с невыполнимым условием "
                           f"сопоставления {agg['match_unknown']}")

    for h in hyps.values():
        if h.result in ("not_applicable", "not_checked"):
            not_applicable.append(f"{h.id}: {h.result} — {h.note}")
        elif h.result == "incomplete":
            unknown.append(f"{h.id}: проверка неполная — {h.note}")
    if run["midstream_sessions"]:
        unknown.append(f"сессий без рукопожатия: {run['midstream_sessions']} — "
                       f"начало соединения не захвачено, роли не объявляются")

    return {
        "mismatches": mismatches,
        "violations": violations,
        "findings": {"coverage": coverage, "ambiguities": ambiguities,
                     "not_applicable": not_applicable, "unknown": unknown},
    }


def verify_corpus(path: Union[str, Path],
                  schema_override: Optional[Union[str, Path]] = None,
                  schema_text: Optional[str] = None,
                  limits: Optional["Limits"] = None,
                  progress: Optional["Progress"] = None) -> dict:
    """Проверить корпус: применить схему к каждой записи и сверить ожидания.

    schema_override — «живое» переопределение интерпретации (сценарий
    защиты): путь к другой схеме вместо указанной в манифесте.
    schema_text — текст схемы из запроса (UI прогоняет корпус по активной
    схеме редактора, чтобы правка интерпретации сразу перепроверялась).
    limits — защитные пределы профиля (раздел 10 кейса): превышение на
    любой записи корпуса — явный отказ, без тихого обрезания данных.
    progress — ход и кооперативная отмена: этап — один файл корпуса.
    """
    corpus = load_corpus(path)

    if schema_text:
        try:
            schema = load_schema_text(schema_text, source_path="")
        except SchemaError as e:
            raise CorpusError([f"схема из запроса: {err}" for err in e.errors])
        schema_path: Union[Path, str] = "<schema_text>"
        schema_source = "text"
    elif schema_override is not None:
        schema_path = Path(schema_override)
        schema_source = "file"
        if not schema_path.is_file():
            raise CorpusError([f"файл схемы не найден: {schema_path}"])
        try:
            schema = load_schema_file(schema_path)
        except SchemaError as e:
            raise CorpusError([f"схема {schema_path.name}: {err}"
                               for err in e.errors])
        except OSError as e:
            raise CorpusError([f"не удалось прочитать схему {schema_path}: {e}"])
    else:
        schema_path = corpus.base_dir / corpus.schema_ref
        schema_source = "file"
        if not schema_path.is_file():
            raise CorpusError([f"файл схемы не найден: {schema_path}"])
        try:
            schema = load_schema_file(schema_path)
        except SchemaError as e:
            raise CorpusError([f"схема {schema_path.name}: {err}"
                               for err in e.errors])
        except OSError as e:
            raise CorpusError([f"не удалось прочитать схему {schema_path}: {e}"])
    overridden = schema_source == "text" or schema_override is not None

    files_out: List[dict] = []
    summary: Dict[str, List[str]] = {g: [] for g in GROUPS}
    mismatched = 0

    for f in corpus.files:
        abs_path = corpus.base_dir / f.path
        if progress is not None:
            progress.start_stage(
                f"файл {len(files_out) + 1}/{len(corpus.files)}: {f.path}")
        if limits is not None and limits.file_bytes is not None:
            violations = check_capture(limits,
                                       file_bytes=file_size(str(abs_path)))
            if violations:
                raise LimitExceeded(limits, [f"{f.path}: {v}"
                                             for v in violations])
        try:
            run = run_capture(abs_path, schema)
        except (CaptureError, OSError) as e:
            raise CorpusError([f"{f.path}: не удалось прочитать: {e}"])
        if limits is not None:
            violations = check_capture(limits, packets=run["packets_count"],
                                       sessions=run["sessions_count"])
            if violations:
                raise LimitExceeded(limits, [f"{f.path}: {v}"
                                             for v in violations])
        ev = _evaluate(run, f.expect)
        ok = not ev["mismatches"]
        if not ok:
            mismatched += 1

        entry = {
            "path": f.path,
            "note": f.note,
            "sha256": run["sha256"],
            "sessions": run["sessions_count"],
            "ok": ok,
            "mismatches": ev["mismatches"],
            "violations": ev["violations"],
            "findings": ev["findings"],
            "directions": {d: {k: v for k, v in agg.items() if k != "notes"}
                           for d, agg in run["directions"].items()},
            "stream": run["stream"],
            "midstream_sessions": run["midstream_sessions"],
            "hypotheses": [_hyp_entry(h) for h in run["hypotheses"].values()],
        }
        files_out.append(entry)

        for g in GROUPS:
            items = entry["violations"] if g == "violations" \
                else entry["findings"][g]
            for line in items:
                summary[g].append(f"{f.path}: {line}")

    return {
        "tool": {"name": "madrigal-lab", "version": __version__},
        "generated_at": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds"),
        "corpus": {"name": corpus.name, "path": corpus.manifest_path,
                   "base": str(corpus.base_dir),
                   "sha256": corpus.manifest_sha256},
        "schema": {"name": schema.name, "path": str(schema_path),
                   "source": schema_source, "overridden": overridden,
                   "sha256": schema.sha256,
                   "messages": schema.message_ids,
                   "hypotheses": [h.id for h in schema.hypotheses]},
        "files": files_out,
        "totals": {"files": len(files_out),
                   "ok": len(files_out) - mismatched,
                   "mismatched": mismatched},
        "summary": summary,
        "summary_counts": {g: len(summary[g]) for g in GROUPS},
    }


# --------------------------------------------------------- устаревание ----

def check_report_stale(report: dict, report_path: Union[str, Path],
                       extra_search_dirs: Optional[List[Path]] = None
                       ) -> List[str]:
    """Причины, по которым отчёт больше не соответствует входным данным.

    extra_search_dirs — дополнительные каталоги поиска (перенесённый проект
    ищет манифест относительно себя, а не по прежним абсолютным путям).
    """
    rpath = Path(report_path)
    reasons: List[str] = []

    cinfo = report.get("corpus") or {}
    sinfo = report.get("schema") or {}
    base = Path(cinfo.get("base") or ".")
    mname = Path(cinfo.get("path") or "corpus.yaml").name

    # манифест ищем: в сохранённом каталоге, рядом с отчётом, в дополнительных
    # каталогах (проект), в текущем каталоге
    candidates = [base / mname, rpath.parent / mname]
    candidates += [Path(d) / mname for d in (extra_search_dirs or [])]
    candidates.append(Path.cwd() / mname)
    manifest = next((c for c in candidates if c.is_file()), None)
    if manifest is None:
        return [f"манифест корпуса не найден: {mname} (ищется в {base}, "
                f"{rpath.parent}, {Path.cwd()})"]
    new_base = manifest.resolve().parent

    if hashlib.sha256(manifest.read_bytes()).hexdigest() != \
            cinfo.get("sha256"):
        reasons.append(f"манифест корпуса изменён: {manifest}")

    # схема: для переопределённой — путь как записан, иначе относительно
    # манифеста; сверка через load_schema_file даёт тот же sha256, что и
    # при генерации. Схема, заданная текстом, файлово не сверяется —
    # её sha256 сам по себе заштампован в отчёте.
    if sinfo.get("source") == "text":
        spath_raw = None
    else:
        spath_raw = Path(sinfo.get("path") or "")
    if spath_raw is not None:
        scands = ([spath_raw, new_base / spath_raw.name]
                  if sinfo.get("overridden") else [new_base / spath_raw])
        scands += [rpath.parent / spath_raw, Path.cwd() / spath_raw]
        scands += [Path(d) / spath_raw for d in (extra_search_dirs or [])]
        scands += [Path(d) / spath_raw.name for d in (extra_search_dirs or [])]
        sfile = next((c for c in scands if c.is_file()), None)
        if sfile is None:
            reasons.append(f"файл схемы не найден: {sinfo.get('path')}")
        else:
            try:
                cur = load_schema_file(sfile)
            except (SchemaError, OSError) as e:
                reasons.append(f"схема {sfile.name} непригодна: {e}")
            else:
                if cur.sha256 != sinfo.get("sha256"):
                    reasons.append(
                        f"схема изменена: {sfile} "
                        f"(sha256 {sinfo.get('sha256', '')[:12]}… -> "
                        f"{cur.sha256[:12]}…)")

    for f in report.get("files") or []:
        rel = f.get("path", "")
        fcands = [new_base / rel]
        fcands += [Path(d) / rel for d in (extra_search_dirs or [])]
        fp = next((c for c in fcands if c.is_file()), None)
        if fp is None:
            reasons.append(f"запись не найдена: {rel}")
            continue
        try:
            cap = open_capture(str(fp))
        except (CaptureError, OSError) as e:
            reasons.append(f"не удалось прочитать {f.get('path')}: {e}")
            continue
        if cap.sha256 != f.get("sha256"):
            reasons.append(f"запись изменена: {f.get('path')} "
                           f"(sha256 {str(f.get('sha256'))[:12]}… -> "
                           f"{cap.sha256[:12]}…)")
    return reasons


def check_report(report_path: Union[str, Path],
                 extra_search_dirs: Optional[List[Path]] = None
                 ) -> List[str]:
    """Прочитать отчёт с диска и оценить его актуальность."""
    p = Path(report_path)
    if not p.is_file():
        raise CorpusError([f"отчёт не найден: {p}"])
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise CorpusError([f"{p}: не похоже на JSON-отчёт: {e}"])
    if not isinstance(data, dict) or "corpus" not in data:
        raise CorpusError([f"{p}: в отчёте нет блока corpus "
                           f"— не тот файл"])
    return check_report_stale(data, p, extra_search_dirs=extra_search_dirs)
