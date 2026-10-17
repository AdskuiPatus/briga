"""Консольный интерфейс ядра (полезен и для тестов, и для исследователя).

Команды:
  python -m madrigal info FILE
      формат, пакеты, диагностика, таблица TCP-сессий
  python -m madrigal stream FILE SESSION DIR [--offset N] [--length N] [--dump]
      восстановленный поток сессии; DIR = a2b | b2a
  python -m madrigal packet FILE INDEX
      разбор одного пакета (сырые байты, заголовки, предупреждения)
  python -m madrigal apply FILE --schema SCHEMA [--session N] [--out OUT.json]
      применить схему интерпретации: фрейминг, сопоставление, проверка
      гипотез; код выхода 3 — найдены контрпримеры (гипотеза опровергнута)
  python -m madrigal journal FILE --journal CSV --schema SCHEMA
                                 [--action ID] [--compare ACTION] [--out OUT.json]
      найти обмен, связанный с известным действием исследователя, и сверить
      наблюдаемый результат с декодированными полями (R2): поиск по сессии и
      окну времени, сопоставление примеров с разными параметрами, переход к
      исходным байтам; код выхода 4 — журнал противоречит записи (mismatch)
  python -m madrigal verify CORPUS [--schema SCHEMA] [--out REPORT.json]
      проверить интерпретацию по корпусу записей с ожиданиями (R4):
      сводка нарушений/неохвата/неоднозначностей/неприменимых/неизвестных;
      код выхода 4 — ожидания корпуса не выполнились
  python -m madrigal stale REPORT.json
      пересчитать контрольные суммы отчёта корпуса и перечислить причины
      устаревания; код выхода 5 — отчёт устарел
  python -m madrigal project init DIR | check DIR | add DIR KIND FILE |
                                       observe DIR TEXT
      переносимый исследовательский проект (R5): манифест с относительными
      путями, контрольными суммами, наблюдениями и результатами проверок;
      check отличает актуальные результаты от устаревших (код 5)
  python -m madrigal report [DIR] [--md OUT.md] [--json OUT.json]
      читаемый отчёт об исследовании и его машиночитаемая форма (R6)
  python -m madrigal golden [MANIFEST] [--update] [--json OUT.json]
      прогнать golden-примеры: входы + ожидаемые результаты повторного
      применения (R6); код выхода 4 — расхождение с ожиданиями
  python -m madrigal loadgen --out FILE [--sessions N] [--messages N]
                             [--seed N] [--max-bytes N]
      сгенерировать детерминированную нагрузочную запись контрольного
      профиля (раздел 10): до 1000 соединений, 100 000 сообщений,
      ответы до 64 КиБ; предел max_bytes останавливает явно
  python -m madrigal bench FILE [--schema S] [--corpus C] [--out B.json]
      замер времени и памяти основных операций на контрольной нагрузке;
      выход 0 всегда (сам замер — не проверка)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .bench import bench_file, render_bench
from .capture import CaptureError, open_capture
from .corpus import CorpusError, check_report, verify_corpus
from .interpreter import analyze_session, dir_result_to_dict, hyp_check_to_dict
from .layers import parse_capture, parse_packet, tcp_flags_str
from .limits import (
    LimitExceeded,
    Limits,
    MIB,
    check_capture,
    check_messages,
    file_size,
    get_profile,
)
from .loadgen import generate_load
from .project import ProjectError
from .progress import CancelledError, StderrProgress
from .reassembly import build_stream
from .schema import SchemaError, load_schema_file
from .sessions import build_sessions, sessions_summary


def _load(path: str, limits: Optional[Limits] = None):
    # защитная проверка размера — до чтения файла в память
    if limits is not None and limits.file_bytes is not None:
        violations = check_capture(limits, file_bytes=file_size(path))
        if violations:
            raise LimitExceeded(limits, violations)
    cap = open_capture(path)
    parsed = parse_capture(cap)
    timestamps = [p.timestamp for p in cap.packets]
    sessions = build_sessions(timestamps, parsed)
    if limits is not None:
        violations = check_capture(limits, packets=len(cap.packets),
                                   sessions=len(sessions))
        if violations:
            raise LimitExceeded(limits, violations)
    return cap, parsed, timestamps, sessions


def cmd_info(args: argparse.Namespace) -> int:
    cap, parsed, _ts, sessions = _load(args.file, get_profile(args.limits))

    errors = sum(1 for p in parsed if p.error)
    warns = sum(1 for p in parsed if p.warnings)
    non_tcp = sum(1 for p in parsed if p.tcp is None)

    print(f"файл:        {Path(cap.path).name}")
    print(f"формат:      {cap.fmt}")
    print(f"sha256:      {cap.sha256}")
    print(f"пакетов:     {len(cap.packets)}")
    print(f"linktype:    {cap.linktypes}")
    print(f"TCP:         {len(parsed) - non_tcp} (не TCP/не разобрано: {non_tcp})")
    print(f"ошибок:      {errors}, пакетов с предупреждениями: {warns}")
    if cap.notes:
        print("замечания к файлу:")
        for n in cap.notes:
            print(f"  - {n}")
    print()
    print(sessions_summary(sessions))

    bad = [p for p in parsed if p.error]
    if bad and args.show_errors:
        print("\nошибки разбора (первые 20):")
        for p in bad[:20]:
            print(f"  пакет #{p.index}: {p.error}")

    return 0


def cmd_stream(args: argparse.Namespace) -> int:
    cap, parsed, ts, sessions = _load(args.file, get_profile(args.limits))
    if args.session < 0 or args.session >= len(sessions):
        print(f"нет сессии #{args.session} (всего {len(sessions)})", file=sys.stderr)
        return 2
    s = sessions[args.session]
    if args.dir not in ("a2b", "b2a"):
        print("DIR должен быть a2b или b2a", file=sys.stderr)
        return 2

    stream = build_stream(ts, parsed, s, args.dir)
    print(f"A: {s.a_label}  B: {s.b_label}")
    print(stream.stats())
    for d in stream.diagnostics:
        print(f"  ! {d}")

    length = args.length
    if length is None:
        length = max(0, stream.length - args.offset)
    print()
    print(stream.hexdump(args.offset, length))
    return 0


def cmd_packet(args: argparse.Namespace) -> int:
    limits = get_profile(args.limits)
    if limits.file_bytes is not None:
        violations = check_capture(limits, file_bytes=file_size(args.file))
        if violations:
            raise LimitExceeded(limits, violations)
    cap = open_capture(args.file)
    if args.index < 0 or args.index >= len(cap.packets):
        print(f"нет пакета #{args.index} (всего {len(cap.packets)})", file=sys.stderr)
        return 2
    pkt = cap.packets[args.index]
    p = parse_packet(pkt.data, pkt.linktype, index=pkt.index)

    print(f"пакет #{pkt.index}: время={pkt.timestamp:.6f}, {len(pkt.data)} Б"
          + (f" (усечён, orig={pkt.orig_len})" if pkt.truncated else ""))
    if p.error:
        print(f"ошибка: {p.error}")
    if p.ethernet:
        print(f"Ethernet: {p.ethernet.src.hex(':')} -> {p.ethernet.dst.hex(':')} "
              f"ethertype=0x{p.ethernet.ethertype:04X} vlan={p.ethernet.vlan_ids}")
    if p.ip4:
        print(f"IPv4: {p.ip4.src} -> {p.ip4.dst} proto={p.ip4.protocol} "
              f"id={p.ip4.identification} ttl={p.ip4.ttl} "
              f"frag={p.ip4.frag_offset} MF={p.ip4.more_fragments}")
    if p.tcp:
        print(f"TCP: {p.tcp.src_port} -> {p.tcp.dst_port} seq={p.tcp.seq} "
              f"ack={p.tcp.ack} flags={tcp_flags_str(p.tcp.flags)} win={p.tcp.window}")
        print(f"payload: {len(p.payload)} Б")
    for w in p.warnings:
        print(f"предупреждение: {w}")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    """Применить схему интерпретации к записи (R3) и проверить гипотезы."""
    try:
        schema = load_schema_file(args.schema)
    except SchemaError as e:
        print("схема не прошла валидацию:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    cap, parsed, ts, sessions = _load(args.file, get_profile(args.limits))
    if args.session is not None:
        if not 0 <= args.session < len(sessions):
            print(f"нет сессии #{args.session} (всего {len(sessions)})",
                  file=sys.stderr)
            return 2
        indices = [args.session]
    else:
        indices = list(range(len(sessions)))

    directions = schema.scope_directions or ["a2b", "b2a"]
    limits = get_profile(args.limits)
    print(f"схема: {schema.name} (sha256 {schema.sha256[:12]}…, "
          f"правил: {len(schema.messages)}, гипотез: {len(schema.hypotheses)})")
    print(f"файл:  {Path(cap.path).name} — сессий {len(sessions)}, "
          f"выбрано {len(indices)}")

    out_payload = {
        "tool": {"name": "madrigal-lab", "version": __version__},
        "generated_at": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds"),
        "schema": {"name": schema.name, "sha256": schema.sha256,
                   "path": schema.source_path,
                   "messages": schema.message_ids,
                   "hypotheses": [h.id for h in schema.hypotheses]},
        "file": {"path": str(cap.path), "sha256": cap.sha256},
        "sessions": [],
    }
    hyp_totals: Counter = Counter()
    any_refuted = False
    messages_total = 0
    progress = StderrProgress(quiet=args.quiet)
    progress.start_stage(f"сессий {len(indices)}", len(indices))

    for idx in indices:
        progress.check_cancel()
        s = sessions[idx]
        streams = {}
        for d in directions:
            # направление, которого нет в потоке, analyze_session отметит сам
            streams[d] = build_stream(ts, parsed, s, d)
        results, hyps = analyze_session(schema, streams)
        messages_total += sum(
            st.stats["messages"] for st in results.values() if st.scope_ok)

        print(f"\nсессия {idx}: A {s.a_label} / B {s.b_label}")
        for d in directions:
            st = results[d]
            if not st.scope_ok:
                print(f"  {d}: не применялось — {st.note}")
                continue
            matched = ", ".join(f"{k}:{v}" for k, v in
                                sorted(st.stats["matched"].items())) or "—"
            print(f"  {d}: сообщений {st.stats['messages']}, "
                  f"распознано [{matched}], "
                  f"неопознано {st.stats['unmatched']}, "
                  f"частичных {st.stats['partial']}, "
                  f"ошибок фрейминга {st.stats['framing_errors']}, "
                  f"вне рамок {st.stats['unframed_bytes']} Б")
            for fe in st.framing_errors[:5]:
                print(f"      ! смещение {fe['start']}: {fe['reason']}")
            if st.stats["framing_errors"] > 5:
                print(f"      ! … ещё {st.stats['framing_errors'] - 5}")

        if hyps:
            print("  гипотезы:")
        for h in hyps:
            hyp_totals[h.result] += 1
            if h.result == "fail":
                any_refuted = True
            arrow = (f"{h.status_before} -> {h.status_after}"
                     if h.status_before != h.status_after
                     else h.status_before)
            print(f"    {h.id}: {h.result} ({arrow}) — {h.note}")
            for ce in h.counterexamples[:3]:
                print(f"      контрпример: {ce['a']['message']}"
                      f"#{ce['a']['index']}={ce['a']['value']} vs "
                      f"{ce['b']['message']}#{ce['b']['index']}={ce['b']['value']}")

        out_payload["sessions"].append({
            "index": idx,
            "endpoints": {"a": s.a_label, "b": s.b_label},
            "directions": {d: dir_result_to_dict(results[d],
                                                  max_messages=args.max_messages)
                           for d in directions},
            "hypotheses": [hyp_check_to_dict(h) for h in hyps],
        })
        progress.advance(note=f"сессия {idx}")

    if hyp_totals:
        parts = [f"{k}={v}" for k, v in sorted(hyp_totals.items())]
        print(f"\nитог по гипотезам: {', '.join(parts)}")

    # защитный предел по числу сообщений: отказ явный, без тихого усечения
    violations = check_messages(limits, messages_total)
    if violations:
        raise LimitExceeded(limits, violations)

    if args.out:
        Path(args.out).write_text(
            json.dumps(out_payload, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"машиночитаемый результат: {args.out}")

    return 3 if any_refuted else 0


def cmd_journal(args: argparse.Namespace) -> int:
    """Найти обмен, связанный с известным действием журнала, и сверить (R2)."""
    import hashlib

    from . import journal as jn

    try:
        schema = load_schema_file(args.schema)
    except SchemaError as e:
        print("схема не прошла валидацию:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    if schema.journal is None:
        print("в схеме нет секции journal — сопоставление действий с "
              "сообщениями и сверка полей невозможны", file=sys.stderr)
        print("добавьте раздел journal (см. schemas/thermostand-protocol.yaml)",
              file=sys.stderr)
        return 1

    try:
        actions, jwarn = jn.load_journal(args.journal)
    except jn.JournalError as e:
        print("журнал действий непригоден:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    cap, parsed, ts, sessions = _load(args.file, get_profile(args.limits))
    acts = jn.filter_capture(actions, Path(cap.path).name)
    if not acts:
        print(f"в журнале нет действий для записи {Path(cap.path).name}",
              file=sys.stderr)
        return 2

    directions = schema.scope_directions or ["a2b", "b2a"]
    limits = get_profile(args.limits)
    progress = StderrProgress(quiet=args.quiet)
    progress.start_stage(f"сессий {len(sessions)}", len(sessions))

    msgs_by_session = {}
    messages_total = 0
    for si, s in enumerate(sessions):
        progress.check_cancel()
        streams = {d: build_stream(ts, parsed, s, d) for d in directions}
        results, _hyps = analyze_session(schema, streams)
        refs = jn.collect_messages(si, streams, results, ts)
        msgs_by_session[si] = refs
        messages_total += sum(len(r.msg.fields) for r in refs)
        progress.advance(note=f"сессия {si}")

    spans = jn.session_spans(sessions, ts)
    matches = jn.correlate(acts, msgs_by_session, spans, schema.journal)
    totals = jn.summarize(matches)

    violations = check_messages(limits, messages_total)
    if violations:
        raise LimitExceeded(limits, violations)

    print(f"схема:   {schema.name} (sha256 {schema.sha256[:12]}…)")
    print(f"файл:    {Path(cap.path).name} — сессий {len(sessions)}")
    print(f"журнал:  {Path(args.journal).name} — действий {len(acts)} "
          f"для этой записи (всего {len(actions)})")
    for w in jwarn:
        print(f"  ! журнал: {w}")

    if args.compare:
        print()
        print(jn.render_compare(matches, args.compare))
    else:
        sel = matches
        if args.action:
            sel = [m for m in matches if m.action.action_id == args.action]
            if not sel:
                print(f"действия {args.action} в этой записи нет", file=sys.stderr)
                return 2
        print()
        print(jn.render_table(sel))
        if args.action:
            m = sel[0]
            print(f"\nдействие {m.action.action_id} ({m.action.action}) — "
                  f"вердикт: {m.verdict}")
            if m.note:
                print(f"  {m.note}")
            print(f"  параметры:  {json.dumps(m.action.parameters, ensure_ascii=False)}")
            print(f"  наблюдено:  {json.dumps(m.action.observed_result, ensure_ascii=False)}")
            for role, ref in (("запрос", m.request), ("ответ", m.response)):
                if ref is None:
                    print(f"  {role}: не найден")
                    continue
                print(f"  {role}: {ref.id or 'вне интерпретации'} "
                      f"[{ref.direction} #{ref.index}] "
                      f"байты {ref.start}…{ref.end}, время "
                      f"{datetime.fromtimestamp(ref.t0, timezone.utc).isoformat(timespec='milliseconds')}")
            checked = [c for c in m.checks if c.equal is not None]
            if checked:
                print("  сверка полей:")
                for c in m.checks:
                    mark = ("OK  " if c.equal else "FAIL") if c.equal is not None else "--"
                    print(f"    [{mark}] {c.path}: журнал={c.observed!r} "
                          f"запись={c.decoded!r}"
                          + (f" ({c.note})" if c.note else ""))

    print("\nитог: " + ", ".join(f"{k} {v}" for k, v in totals.items()
                                if v))
    print("поиск: действие -> сессия + окно времени + тип сообщения; "
          "сверка полей -- по bindings секции journal")

    if args.out:
        journal_sha = hashlib.sha256(Path(args.journal).read_bytes()).hexdigest()
        payload = {
            "tool": {"name": "madrigal-lab", "version": __version__},
            "generated_at": datetime.now(timezone.utc)
                            .isoformat(timespec="seconds"),
            "schema": {"name": schema.name, "sha256": schema.sha256,
                       "path": schema.source_path},
            "file": {"path": str(cap.path), "sha256": cap.sha256},
            "journal": {"path": str(args.journal), "sha256": journal_sha,
                        "actions": len(acts), "warnings": jwarn},
            "matches": [m.to_dict() for m in matches],
            "totals": totals,
        }
        Path(args.out).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"машиночитаемый результат: {args.out}")

    return 4 if totals.get("mismatch") else 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Проверить интерпретацию по корпусу записей (R4)."""
    progress = StderrProgress(quiet=args.quiet)
    try:
        report = verify_corpus(args.corpus, schema_override=args.schema,
                               limits=get_profile(args.limits),
                               progress=progress)
    except CorpusError as e:
        print("корпус не прошёл проверку:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    c, s = report["corpus"], report["schema"]
    print(f"корпус:   {c['name']} — файлов {len(report['files'])}")
    print(f"манифест: {c['path']} (sha256 {c['sha256'][:12]}…)")
    ov = " [переопределена]" if s["overridden"] else ""
    print(f"схема:    {s['name']}{ov} sha256 {s['sha256'][:12]}…, "
          f"правил {len(s['messages'])}, гипотез {len(s['hypotheses'])}")

    for f in report["files"]:
        mark = "OK  " if f["ok"] else "FAIL"
        print(f"\n[{mark}] {f['path']} — сессий {f['sessions']}")
        if f["note"]:
            print(f"       {f['note']}")
        for d in ("b2a", "a2b"):
            agg = f["directions"].get(d)
            if agg is None:
                continue
            if not agg["scope_ok"]:
                print(f"  {d}: не применялось схемой")
                continue
            matched = ", ".join(f"{k}:{v}" for k, v in
                                sorted(agg["matched"].items())) or "—"
            print(f"  {d}: сообщений {agg['messages']}, распознано [{matched}], "
                  f"неопознано {agg['unmatched']}, частичных {agg['partial']}, "
                  f"вне сообщений {agg['unframed_bytes']} Б")
        if f["hypotheses"]:
            print("  гипотезы: " + ", ".join(f"{h['id']} {h['result']}"
                                             for h in f["hypotheses"]))
        for line in f["violations"]:
            print(f"  ! {line}")
        counts = {("неохват", "coverage"), ("неоднозначности", "ambiguities"),
                  ("неприменимые", "not_applicable"),
                  ("неизвестные", "unknown")}
        found = [f"{label} {len(f['findings'][key])}"
                 for label, key in counts if f["findings"][key]]
        if found:
            print(f"  находки: {', '.join(found)} "
                  f"(полностью — в отчёте JSON)")

    t, sc = report["totals"], report["summary_counts"]
    print(f"\nитог: файлов {t['files']}, ожидания выполнены {t['ok']}, "
          f"с расхождениями {t['mismatched']}")
    print("сводка: нарушения "
          f"{sc['violations']}, неохват {sc['coverage']}, "
          f"неоднозначности {sc['ambiguities']}, "
          f"неприменимые {sc['not_applicable']}, "
          f"неизвестные {sc['unknown']}")
    if report["summary"]["violations"]:
        print("нарушения:")
        for line in report["summary"]["violations"]:
            print(f"  ! {line}")
    if args.out:
        Path(args.out).write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"отчёт: {args.out}")

    return 4 if t["mismatched"] else 0


def cmd_stale(args: argparse.Namespace) -> int:
    """Проверить актуальность отчёта корпуса по контрольным суммам."""
    try:
        reasons = check_report(args.report)
    except CorpusError as e:
        for err in e.errors:
            print(f"- {err}", file=sys.stderr)
        return 1
    p = Path(args.report)
    if reasons:
        print(f"отчёт УСТАРЕЛ: {p} — причин {len(reasons)}")
        for r in reasons:
            print(f"  ! {r}")
        return 5
    print(f"отчёт актуален: {p} — записи, схема и манифест совпадают "
          f"с заштампованными контрольными суммами")
    return 0


def cmd_loadgen(args: argparse.Namespace) -> int:
    """Сгенерировать нагрузочную запись (контрольный профиль раздела 10)."""
    progress = StderrProgress(quiet=args.quiet)

    def on_progress(packets: int, written: int) -> None:
        progress.note(f"пакетов {packets}, {written >> 20} МиБ")

    progress.start_stage("генерация записи")
    summary = generate_load(args.out, sessions=args.sessions,
                            messages=args.messages,
                            answer_max=args.answer_max, seed=args.seed,
                            max_bytes=args.max_bytes,
                            progress=on_progress)
    print(f"запись:   {summary['path']}")
    print(f"размер:   {summary['bytes']:,} Б "
          f"({summary['bytes'] / MIB:.1f} МиБ)".replace(",", " "))
    print(f"пакетов:  {summary['packets']:,}".replace(",", " "))
    print(f"сессий:   {summary['sessions']:,}".replace(",", " "))
    print(f"сообщений:{summary['messages']:,}".replace(",", " "))
    print(f"seed:     {summary['seed']}")
    print(f"остановлено: {summary['stopped_because']}")
    if args.out_json:
        Path(args.out_json).write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"сводка: {args.out_json}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """Замерить время и память основных операций на контрольной нагрузке."""
    progress = StderrProgress(quiet=args.quiet)

    def on_stage(name: str, seconds: float, items: int) -> None:
        progress.note(f"{name}: {seconds:.3f} с, элементов {items}")

    report = bench_file(args.file, schema_path=args.schema,
                        corpus_path=args.corpus, progress=on_stage)
    print(render_bench(report))
    if args.out:
        Path(args.out).write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"машиночитаемый замер: {args.out}")
    return 0


def cmd_project(args: argparse.Namespace) -> int:
    """Переносимый исследовательский проект (R5)."""
    from . import project as proj

    try:
        if args.action == "init":
            manifest = proj.init_project(args.dir, name=args.name,
                                         description=args.description)
            print(f"создан манифест проекта: {manifest}")
            print("зарегистрируйте материалы: "
                  "python -m madrigal project add DIR recording FILE")
            return 0

        if args.action == "add":
            adders = {"recording": proj.add_recording,
                      "schema": proj.add_schema,
                      "corpus": proj.add_corpus}
            if args.kind in adders:
                art = adders[args.kind](args.dir, args.file, note=args.note)
                sha = f", sha256 {art.sha256[:12]}…" if art.sha256 else ""
                print(f"{args.kind} добавлен: {art.path}{sha}")
            else:
                art = proj.add_result(args.dir, args.file, kind=args.result_kind,
                                      note=args.note)
                print(f"результат ({args.result_kind}) добавлен: {art.path}")
            return 0

        if args.action == "observe":
            source = {}
            if args.file:
                source["file"] = args.file
            if args.session is not None:
                source["session"] = args.session
            if args.direction:
                source["direction"] = args.direction
            if args.offset is not None:
                source["offset"] = args.offset
            if args.packets:
                source["packets"] = [int(x) for x in
                                     args.packets.replace(" ", "").split(",")
                                     if x]
            obs = proj.add_observation(args.dir, args.text, source=source)
            print(f"наблюдение записано: {obs.text[:60]}"
                  + ("…" if len(obs.text) > 60 else ""))
            return 0

        # check
        result = proj.check_project(args.dir)
        p = result["project"]
        print(f"проект:  {p['name']} (манифест {p['path']}, "
              f"sha256 {p['sha256'][:12]}…)")
        req = p.get("requires") or {}
        if req:
            bits = []
            if "python" in req:
                bits.append(f"python {req['python']}")
            if "packages" in req:
                bits.append("пакеты: " + ", ".join(req["packages"]))
            print("нужно:   " + "; ".join(bits))
        for e in result["entries"]:
            if e["section"] == "results":
                mark = "OK  " if e["ok"] else "STALE"
                cur = ("" if e["current"] is None
                       else " — актуален" if e["current"] else " — УСТАРЕЛ")
                print(f"[{mark}] результат {e['path']} ({e['kind']}){cur}")
                for r in e.get("reasons") or []:
                    print(f"       ! {r}")
            else:
                mark = "OK  " if e["ok"] else "STALE"
                print(f"[{mark}] {e['section']}: {e['path']}")
                if not e["ok"]:
                    note = e.get("note") or "контрольная сумма не совпала"
                    print(f"       ! {note}")
        print(f"наблюдений: {result['observations']}")
        for line in result["stale"]:
            print(f"  ! {line}")
        for line in result["errors"]:
            print(f"  !! {line}")
        if result["ok"]:
            print("проект целостен: после переноса всё открывается без "
                  "прежних абсолютных путей, результаты актуальны")
            return 0
        if result["errors"]:
            return 1
        print("проект открыт, но есть устаревшие результаты/изменённые файлы "
              "(устаревшие отличимы от актуальных)")
        return 5
    except proj.ProjectError as e:
        print("проект непригоден:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1


def cmd_report(args: argparse.Namespace) -> int:
    """Читаемый отчёт об исследовании (R6)."""
    from . import report as rep

    try:
        data = rep.build_report(args.dir)
    except ProjectError as e:
        print("не удалось собрать отчёт:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    if args.json:
        Path(args.json).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"машиночитаемый отчёт: {args.json}")
    if args.md:
        Path(args.md).write_text(rep.render_markdown(data),
                                 encoding="utf-8")
        print(f"читаемый отчёт: {args.md}")
    if not args.md and not args.json:
        print(rep.render_markdown(data))
    else:
        qs = len(data["open_questions"])
        ce = sum(len(c.get("violations") or []) for c in data["checks"])
        print(f"отчёт собран: записей {len(data['recordings'])}, схем "
              f"{len(data['schemas'])}, проверок {len(data['checks'])}, "
              f"контрпримеров {ce}, открытых вопросов {qs}")
    return 0


def cmd_golden(args: argparse.Namespace) -> int:
    """Golden-примеры: согласованность повторного применения (R6)."""
    from . import golden as gld

    manifest = args.manifest or "examples/golden.yaml"
    try:
        if args.update:
            info = gld.update_golden(manifest)
            print(f"ожидаемые результаты переписаны: {info['path']} "
                  f"(случаев {info['cases']})")
            return 0
        result = gld.check_golden(manifest)
    except gld.GoldenError as e:
        print("golden-примеры непригодны:", file=sys.stderr)
        for err in e.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"результат: {args.json}")
    failed = 0
    for c in result["cases"]:
        mark = "OK  " if c["ok"] else "FAIL"
        print(f"[{mark}] {c['name']} ({c['kind']})")
        if c.get("error"):
            print(f"       ! {c['error']}")
        failed += 0 if c["ok"] else 1
        for d in c.get("diffs") or []:
            print(f"       ! {d}")
    total = len(result["cases"])
    print(f"итог: {total - failed}/{total} случаев совпали с ожидаемыми "
          f"результатами")
    return 4 if failed else 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Запуск локального веб-интерфейса (стек A)."""
    import webbrowser

    import uvicorn

    from .webapp import app

    url = f"http://{args.host}:{args.port}/"
    print(f"madrigal-lab: {url}")
    print("нажмите Ctrl+C для остановки")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


LIMITS_HELP = ("защитный профиль пределов: control (по умолчанию, раздел 10 "
              "кейса) | none (снять пределы); превышение — код выхода 6")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="madrigal", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="информация о записи и сессиях")
    p.add_argument("file")
    p.add_argument("--show-errors", action="store_true")
    p.add_argument("--limits", default="control",
                   choices=("control", "none"), help=LIMITS_HELP)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("stream", help="восстановленный поток сессии")
    p.add_argument("file")
    p.add_argument("session", type=int)
    p.add_argument("dir", choices=("a2b", "b2a"))
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--length", type=int, default=None)
    p.add_argument("--limits", default="control",
                   choices=("control", "none"), help=LIMITS_HELP)
    p.set_defaults(func=cmd_stream)

    p = sub.add_parser("packet", help="разбор одного пакета")
    p.add_argument("file")
    p.add_argument("index", type=int)
    p.add_argument("--limits", default="control",
                   choices=("control", "none"), help=LIMITS_HELP)
    p.set_defaults(func=cmd_packet)

    p = sub.add_parser(
        "apply", help="применить схему интерпретации и проверить гипотезы")
    p.add_argument("file")
    p.add_argument("--schema", required=True,
                   help="файл схемы (.yaml/.yml/.json)")
    p.add_argument("--session", type=int, default=None,
                   help="только одна сессия (по умолчанию все)")
    p.add_argument("--out", default=None,
                   help="куда записать машиночитаемый результат JSON")
    p.add_argument("--max-messages", type=int, default=1000,
                   help="сколько сообщений на поток включать в JSON")
    p.add_argument("--limits", default="control",
                   choices=("control", "none"), help=LIMITS_HELP)
    p.add_argument("--quiet", action="store_true",
                   help="не печатать ход в stderr (отмена Ctrl+C работает)")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser(
        "journal",
        help="найти обмен, связанный с действием журнала, и сверить (R2)")
    p.add_argument("file", help="запись (.pcap/.pcapng)")
    p.add_argument("--journal", required=True,
                   help="журнал действий CSV (capture/session/action_id/"
                        "start_utc/end_utc/action/parameters/observed_result)")
    p.add_argument("--schema", required=True,
                   help="схема интерпретации с секцией journal")
    p.add_argument("--action", default=None,
                   help="показать детали одного действия (action_id)")
    p.add_argument("--compare", default=None, metavar="ACTION",
                   help="сопоставить примеры одного действия с разными "
                        "параметрами (read-config|set-config|read-values|…)")
    p.add_argument("--out", default=None,
                   help="куда записать машиночитаемый результат JSON")
    p.add_argument("--limits", default="control",
                   choices=("control", "none"), help=LIMITS_HELP)
    p.add_argument("--quiet", action="store_true",
                   help="не печатать ход в stderr (отмена Ctrl+C работает)")
    p.set_defaults(func=cmd_journal)

    p = sub.add_parser(
        "verify", help="проверить интерпретацию по корпусу записей (R4)")
    p.add_argument("corpus", help="манифест корпуса (.yaml/.json)")
    p.add_argument("--schema", default=None,
                   help="переопределить схему манифеста (для живой проверки "
                        "новой интерпретации)")
    p.add_argument("--out", default=None,
                   help="куда записать машиночитаемый отчёт JSON")
    p.add_argument("--limits", default="control",
                   choices=("control", "none"), help=LIMITS_HELP)
    p.add_argument("--quiet", action="store_true",
                   help="не печатать ход в stderr (отмена Ctrl+C работает)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser(
        "stale", help="проверить актуальность отчёта корпуса по sha256")
    p.add_argument("report", help="отчёт JSON, созданный командой verify")
    p.set_defaults(func=cmd_stale)

    p = sub.add_parser(
        "loadgen", help="сгенерировать нагрузочную запись (раздел 10)")
    p.add_argument("--out", required=True, help="куда записать PCAPNG")
    p.add_argument("--sessions", type=int, default=1000)
    p.add_argument("--messages", type=int, default=100_000,
                   help="всего прикладных сообщений")
    p.add_argument("--answer-max", type=int, default=64 * 1024,
                   help="максимум байт в ответе (профиль: 64 КиБ)")
    p.add_argument("--seed", type=int, default=1,
                   help="детерминизм: одинаковый seed → одинаковые байты")
    p.add_argument("--max-bytes", type=int, default=100 * MIB,
                   help="защитный предел размера записи; остановка явная")
    p.add_argument("--out-json", default=None,
                   help="куда записать сводку генерации в JSON")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_loadgen)

    p = sub.add_parser(
        "bench", help="замер времени и памяти основных операций (раздел 10)")
    p.add_argument("file", help="запись для замера (обычная или нагрузочная)")
    p.add_argument("--schema", default=None,
                   help="добавить стадию применения схемы")
    p.add_argument("--corpus", default=None,
                   help="добавить стадию проверки корпуса")
    p.add_argument("--out", default=None,
                   help="куда записать машиночитаемый замер JSON")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser(
        "project", help="переносимый исследовательский проект (R5)")
    psub = p.add_subparsers(dest="action", required=True)

    q = psub.add_parser("init", help="создать манифест проекта")
    q.add_argument("dir")
    q.add_argument("--name", default="madrigal-lab")
    q.add_argument("--description", default="")
    q.set_defaults(func=cmd_project)

    q = psub.add_parser(
        "check", help="проверить целостность перенесённого проекта")
    q.add_argument("dir")
    q.set_defaults(func=cmd_project)

    q = psub.add_parser("add", help="добавить материал в манифест")
    q.add_argument("dir")
    q.add_argument("kind", choices=("recording", "schema", "corpus",
                                    "result"))
    q.add_argument("file")
    q.add_argument("--note", default="")
    q.add_argument("--result-kind", default="corpus-verify",
                   dest="result_kind",
                   help="вид результата: corpus-verify | apply")
    q.set_defaults(func=cmd_project)

    q = psub.add_parser(
        "observe", help="записать наблюдение со связью к источнику")
    q.add_argument("dir")
    q.add_argument("text")
    q.add_argument("--file", default=None,
                   help="запись-источник (относительный путь проекта)")
    q.add_argument("--session", type=int, default=None)
    q.add_argument("--direction", choices=("a2b", "b2a"), default=None)
    q.add_argument("--offset", type=int, default=None)
    q.add_argument("--packets", default=None,
                   help="номера пакетов через запятую")
    q.set_defaults(func=cmd_project)

    p = sub.add_parser(
        "report", help="отчёт об исследовании: читаемый и машиночитаемый (R6)")
    p.add_argument("dir", nargs="?", default=".",
                   help="каталог проекта (по умолчанию текущий)")
    p.add_argument("--md", default=None,
                   help="куда записать читаемый Markdown-отчёт")
    p.add_argument("--json", default=None,
                   help="куда записать машиночитаемый отчёт JSON")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser(
        "golden", help="golden-примеры: входы + ожидаемые результаты (R6)")
    p.add_argument("manifest", nargs="?", default=None,
                   help="манифест golden-примеров (по умолчанию "
                        "examples/golden.yaml)")
    p.add_argument("--update", action="store_true",
                   help="переписать ожидания текущими фактами "
                        "(после уточнения интерпретации)")
    p.add_argument("--json", default=None,
                   help="куда записать полный результат JSON")
    p.set_defaults(func=cmd_golden)

    p = sub.add_parser("serve", help="запуск локального веб-интерфейса")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--open", action="store_true",
                   help="открыть браузер автоматически")
    p.set_defaults(func=cmd_serve)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (CancelledError, KeyboardInterrupt):
        # отмена явная: частичные результаты не выдаются за полные
        print("\nоперация отменена — неполный результат не записан",
              file=sys.stderr)
        return 130
    except LimitExceeded as e:
        print(f"превышение защитных пределов ({e.limits.profile}):",
              file=sys.stderr)
        for v in e.violations:
            print(f"  ! {v}", file=sys.stderr)
        print(f"профиль: {e.limits.describe()}", file=sys.stderr)
        print("снять пределы: --limits none (исследовательский запуск)",
              file=sys.stderr)
        return 6
    except CaptureError as e:
        print(f"ошибка чтения: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
