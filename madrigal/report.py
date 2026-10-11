"""Читаемый отчёт об исследовании и его машиночитаемая форма (R6).

Отчёт собирается из переносимого проекта (R5):

  * описание исследованных записей и интерпретаций (с контрольными суммами);
  * основания выводов: гипотезы со statement/basis/status и результатом
    механической проверки на данных;
  * проверенные примеры: корпуса, ожидания и итоги прогонов;
  * контрпримеры: опровергнутые гипотезы с привязкой к пакетам;
  * область применимости и политика обработки дефектов;
  * открытые вопросы: непроверяемые механически предположения и находки
    групп «неохват/неизвестные/неоднозначности»;
  * документированные команды повторного применения интерпретации к новым
    данным (CLI + golden-примеры).

`build_report()` возвращает машиночитаемое представление (dict/JSON),
`render_markdown()` — читаемый Markdown на его основе.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Union

from . import __version__
from .corpus import GROUPS, check_report
from .project import Project, load_project
from .schema import SchemaError, load_schema_file

GROUP_TITLES = {
    "violations": "нарушения",
    "coverage": "неохват",
    "ambiguities": "неоднозначности",
    "not_applicable": "неприменимые",
    "unknown": "неизвестные",
}

REAPPLY_STEPS = [
    ("Применить сохранённую интерпретацию к новой записи:",
     "python -m madrigal apply НОВАЯ_ЗАПИСЬ.pcapng "
     "--schema СОХРАНЁННАЯ_СХЕМА.yaml --out result.json"),
    ("Проверить интерпретацию по новому корпусу записей с ожиданиями:",
     "python -m madrigal verify НОВЫЙ_КОРПУС.yaml "
     "--schema СОХРАНЁННАЯ_СХЕМА.yaml --out report.json"),
    ("Проверить актуальность ранее сохранённого отчёта:",
     "python -m madrigal stale report.json"),
    ("Убедиться, что инструмент и схема ведут себя как при сдаче "
     "(golden-примеры: входы + ожидаемые результаты):",
     "python -m madrigal golden"),
    ("Воспроизвести отчёт по проекту (какие записи, какие проверки):",
     "python -m madrigal report ."),
]


def _load_verify_report(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"unreadable": True}
    if not isinstance(data, dict) or "corpus" not in data:
        return {"unreadable": True}
    return data


def build_report(project_dir: Union[str, Path]) -> dict:
    """Собрать машиночитаемый отчёт об исследовании по проекту."""
    project: Project = load_project(project_dir)

    recordings = [{
        "path": a.path,
        "sha256": a.sha256,
        "note": a.note,
        "exists": project.resolve(a.path).is_file(),
    } for a in project.recordings]

    schemas: List[dict] = []
    open_questions: List[str] = []
    for a in project.schemas:
        entry: Dict[str, object] = {"path": a.path, "sha256": a.sha256,
                                    "note": a.note}
        try:
            schema = load_schema_file(project.resolve(a.path))
        except (SchemaError, OSError) as e:
            entry["error"] = str(e)
            schemas.append(entry)
            open_questions.append(f"схема {a.path}: не удалось прочитать — {e}")
            continue
        entry["name"] = schema.name
        entry["scope"] = schema.scope_directions
        entry["messages"] = [
            {"id": m.id, "direction": m.direction,
             "fields": [f.name for f in m.fields]}
            for m in schema.messages]
        entry["hypotheses"] = []
        for h in schema.hypotheses:
            hyp = {"id": h.id, "statement": h.statement,
                   "basis": list(h.basis), "status": h.status,
                   "mechanically_checked": h.check is not None}
            entry["hypotheses"].append(hyp)
            if h.check is None:
                open_questions.append(
                    f"гипотеза {h.id} (статус {h.status}): {h.statement} — "
                    f"механическая проверка не присвоена, предположение "
                    f"остаётся неподтверждённым")
        schemas.append(entry)

    checks: List[dict] = []
    for a in project.results:
        rp = project.resolve(a.path)
        entry = {"path": a.path, "kind": a.kind, "note": a.note,
                 "exists": rp.is_file()}
        if not rp.is_file():
            open_questions.append(f"результат {a.path}: файл отсутствует")
            checks.append(entry)
            continue
        if a.kind == "corpus-verify":
            report = _load_verify_report(rp)
            if report.get("unreadable"):
                entry["error"] = "файл нечитаем или не является отчётом корпуса"
                open_questions.append(f"результат {a.path}: {entry['error']}")
                checks.append(entry)
                continue
            entry["corpus"] = report["corpus"]["name"]
            entry["schema"] = report["schema"]["name"]
            entry["generated_at"] = report.get("generated_at")
            entry["totals"] = report["totals"]
            entry["summary_counts"] = report["summary_counts"]
            entry["summary"] = report["summary"]
            entry["violations"] = []
            for f in report["files"]:
                for h in f["hypotheses"]:
                    if h["result"] == "fail":
                        ces = [{
                            "file": f["path"], "session": ce.get("session"),
                            "a": ce["a"], "b": ce["b"],
                        } for ce in h["counterexamples"][:3]]
                        entry["violations"].append({
                            "hypothesis": h["id"],
                            "statement": h["statement"],
                            "counterexamples_total":
                                h.get("counterexamples_total",
                                      len(h["counterexamples"])),
                            "counterexamples": ces,
                        })
            # актуальность результата — устаревший отличим от актуального
            try:
                reasons = check_report(rp, extra_search_dirs=[project.root])
            except Exception as e:                      # noqa: BLE001
                reasons = [str(e)]
            entry["current"] = not reasons
            entry["stale_reasons"] = reasons
            for g in GROUPS:
                for line in report["summary"].get(g, []):
                    if g in ("coverage", "unknown", "ambiguities"):
                        open_questions.append(f"[{GROUP_TITLES[g]}] {line}")
            if not entry["current"]:
                open_questions.append(
                    f"отчёт {a.path} устарел: входные данные изменились — "
                    f"перезапустите verify перед ссылкой на результат")
        checks.append(entry)

    limitations = [
        "интерпретация частичная: описаны изученные записи корпуса; "
        "неизвестные участки (неопознанные сообщения, пропуски, частичные "
        "сообщения) видимы явно и не подменяются",
        "совпадения на примерах корпуса не доказывают назначение поля и "
        "универсальность модели (раздел 7.1 кейса)",
        "перекрытия с различающимися байтами: применяется политика "
        "first-seen, альтернатива сохраняется в ambiguities с пакетами",
        "midstream-соединения: роли (клиент/устройство) не назначаются, "
        "направления заданы относительно канонических endpoint'ов",
        "поддерживаются PCAP/PCAPNG с Ethernet(+VLAN), IPv4, TCP; "
        "другие уровни явно диагностируются как неподдерживаемые",
    ]

    report = {
        "tool": {"name": "madrigal-lab", "version": __version__},
        "generated_at": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds"),
        "project": {
            "name": project.name,
            "description": project.description,
            "manifest_sha256": project.manifest_sha256,
            "requires": project.requires,
            "settings": project.settings,
        },
        "recordings": recordings,
        "schemas": schemas,
        "checks": checks,
        "observations": [{"text": o.text, "source": dict(o.source)}
                         for o in project.observations],
        "limitations": limitations,
        "open_questions": open_questions,
        "reapply": [{"goal": goal, "command": cmd}
                    for goal, cmd in REAPPLY_STEPS],
    }
    return report


# ------------------------------------------------------------ Markdown ----

def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    """Читаемый отчёт об исследовании на основе машиночитаемого."""
    p = report["project"]
    out: List[str] = []
    add = out.append

    add(f"# Отчёт об исследовании: {p['name']}")
    add("")
    if p.get("description"):
        add(p["description"])
        add("")
    add(f"Инструмент: {report['tool']['name']} "
        f"v{report['tool']['version']}; отчёт сформирован "
        f"{report['generated_at']}. Манифест проекта sha256 "
        f"`{p['manifest_sha256'][:16]}…`.")
    req = p.get("requires") or {}
    if req:
        parts = []
        if "python" in req:
            parts.append(f"Python {req['python']}")
        if "packages" in req:
            parts.append("пакеты: " + ", ".join(req["packages"]))
        add("Условия воспроизведения: " + "; ".join(parts) + ".")
    settings = p.get("settings") or {}
    if settings:
        add("Настройки: " + ", ".join(f"{k}={v}" for k, v in
                                      settings.items()) + ".")
    add("")

    add("## Исследованные записи")
    add("")
    for r in report["recordings"]:
        mark = "" if r["exists"] else " (файл отсутствует!)"
        note = f" — {_md_escape(r['note'])}" if r["note"] else ""
        add(f"* `{r['path']}`{mark} sha256 `{r['sha256'][:16]}…`{note}")
    add("")

    add("## Интерпретации и основания выводов")
    add("")
    for s in report["schemas"]:
        if "error" in s:
            add(f"### `{s['path']}` — не прочитана: {s['error']}")
            add("")
            continue
        scope = ", ".join(s["scope"]) if s.get("scope") else "любое направление"
        add(f"### {s['name']} (`{s['path']}`, sha256 "
            f"`{str(s.get('sha256', ''))[:16]}…`)")
        add("")
        add(f"Область применимости: направления {scope}. "
            f"Распознаваемые сообщения: "
            + ", ".join(f"{m['id']} ({m['direction']})"
                        for m in s["messages"]) + ".")
        add("")
        if s["hypotheses"]:
            add("| Гипотеза | Утверждение | Основания | Статус | Проверка |")
            add("|---|---|---|---|---|")
            for h in s["hypotheses"]:
                basis = "; ".join(_md_escape(b) for b in h["basis"]) or "—"
                check = ("механическая (pairs/expect)"
                         if h["mechanically_checked"] else "не присвоена")
                add(f"| {h['id']} | {_md_escape(h['statement'])} | {basis} "
                    f"| {h['status']} | {check} |")
        else:
            add("Гипотезы не описаны.")
        add("")

    add("## Проверенные примеры")
    add("")
    if not report["checks"]:
        add("Проверки не регистрировались в проекте "
            "(добавьте отчёт `verify` командой "
            "`python -m madrigal project add . результат ОТЧЁТ --kind corpus-verify`).")
        add("")
    for c in report["checks"]:
        if not c.get("exists"):
            add(f"### `{c['path']}` — файл отсутствует")
            add("")
            continue
        if c["kind"] == "corpus-verify" and "totals" in c:
            status = ("актуален" if c.get("current")
                      else "УСТАРЕЛ (входные данные изменились)")
            add(f"### Корпус «{c['corpus']}» (схема «{c['schema']}», "
                f"`{c['path']}`)")
            add("")
            add(f"Отчёт {c.get('generated_at', '?')}, статус: {status}. "
                f"Файлов {c['totals']['files']}: ожидания выполнены "
                f"{c['totals']['ok']}, с расхождениями "
                f"{c['totals']['mismatched']}.")
            add("")
            sc = c["summary_counts"]
            add("| Сводка | " + " | ".join(GROUP_TITLES[g] for g in GROUPS)
                + " |")
            add("|---|" + "---|" * len(GROUPS))
            add("| Значение | "
                + " | ".join(str(sc[g]) for g in GROUPS) + " |")
            add("")
            for g in GROUPS:
                for line in c["summary"].get(g, []):
                    add(f"* {GROUP_TITLES[g]}: {_md_escape(line)}")
            add("")
        else:
            add(f"### `{c['path']}` ({c['kind']})")
            add("")
            if c.get("error"):
                add(f"Ошибка: {c['error']}.")
            else:
                add("Машиночитаемый результат; для проверки актуальности: "
                    f"`python -m madrigal stale {c['path']}`.")
            add("")

    add("## Контрпримеры (опровергнутые данными гипотезы)")
    add("")
    any_ce = False
    for c in report["checks"]:
        for v in c.get("violations") or []:
            any_ce = True
            add(f"* Гипотеза **{v['hypothesis']}** "
                f"(«{_md_escape(v['statement'])}») опровергнута: "
                f"контрпримеров {v['counterexamples_total']}.")
            for ce in v["counterexamples"]:
                a, b = ce["a"], ce["b"]
                pa = ", ".join(str(x) for x in a.get("packets") or []) or "?"
                pb = ", ".join(str(x) for x in b.get("packets") or []) or "?"
                add(f"  * `{ce['file']}` сессия {ce['session']}: "
                    f"{a['message']}#{a['index']}={a['value']} "
                    f"(пакеты {pa}) против "
                    f"{b['message']}#{b['index']}={b['value']} "
                    f"(пакеты {pb})")
    if not any_ce:
        add("Контрпримеры в зарегистрированных результатах не найдены.")
    add("")

    add("## Наблюдения исследователя")
    add("")
    if report["observations"]:
        for o in report["observations"]:
            src = o.get("source") or {}
            if src:
                bits = [f"файл `{src['file']}`"] if "file" in src else []
                if "session" in src:
                    bits.append(f"сессия {src['session']}")
                if "direction" in src:
                    bits.append(f"направление {src['direction']}")
                if "offset" in src:
                    bits.append(f"смещение {src['offset']}")
                if "packets" in src:
                    bits.append("пакеты "
                                + ", ".join(str(x) for x in src["packets"]))
                suffix = " (" + ", ".join(bits) + ")" if bits else ""
            else:
                suffix = ""
            add(f"* {_md_escape(o['text'])}{suffix}")
    else:
        add("Наблюдения не записаны.")
    add("")

    add("## Ограничения области применимости")
    add("")
    for line in report["limitations"]:
        add(f"* {line}")
    add("")

    add("## Открытые вопросы")
    add("")
    if report["open_questions"]:
        for q in report["open_questions"]:
            add(f"* {_md_escape(q)}")
    else:
        add("Открытых вопросов по зарегистрированным материалам нет.")
    add("")

    add("## Повторное применение интерпретации")
    add("")
    add("Сохранённая схема (машиночитаемое представление YAML/JSON) "
        "применяется к новым записям без повторения ручной работы:")
    add("")
    for step in report["reapply"]:
        add(f"* {step['goal']}")
        add(f"  ```bash")
        add(f"  {step['command']}")
        add(f"  ```")
    add("")
    add("Комплект golden-примеров (`examples/golden/`) содержит примеры "
        "входных данных и ожидаемых результатов: `python -m madrigal golden` "
        "воспроизводит их и сообщает расхождения — согласованность "
        "повторного применения проверяется механически.")
    add("")
    return "\n".join(out)


def write_report(project_dir: Union[str, Path],
                 markdown_path: Union[str, Path, None] = None,
                 json_path: Union[str, Path, None] = None) -> dict:
    """Собрать отчёт и записать выбранные представления."""
    report = build_report(project_dir)
    if json_path is not None:
        Path(json_path).write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8")
    if markdown_path is not None:
        Path(markdown_path).write_text(render_markdown(report),
                                       encoding="utf-8")
    return report
