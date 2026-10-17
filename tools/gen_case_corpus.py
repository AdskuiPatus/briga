"""Сгенерировать case/corpus.yaml из фактического применения схемы.

Прогоняет run_capture по каждой записи case/recordings/**, сводит счётчики
и гипотезы и печатает YAML-манифест корпуса (R4) с ожиданиями, которые
механически подтверждаются. Ожидания здесь — документирование того, что
правильная интерпретация даёт на этих записях; verify сверяет строго.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from madrigal.corpus import run_capture           # noqa: E402
from madrigal.schema import load_schema_file       # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CASE = ROOT / "case"
REC = CASE / "recordings"
SCHEMA = ROOT / "schemas" / "thermostand-protocol.yaml"

# порядок групп: research (норма) -> additional -> diagnostics (дефекты)
GROUPS = [
    ("research", "исследование протокола (норма обмена)"),
    ("additional", "дополнительные наблюдения"),
    ("diagnostics", "диагностика дефектов захвата"),
]

NOTES = {
    "research/01_configuration.pcap":
        "базовый обмен конфигурацией: всё распознаётся, статусы ok",
    "research/02_variations.pcapng":
        "вариации параметров: есть неопознанный служебный probe (0x7E) — честный неохват",
    "research/03_combined_messages.pcap":
        "несколько сообщений в одном TCP-сегменте (combined), счётчики точны",
    "additional/04_new_observations.pcapng":
        "дополнительные сессии чтения значений и установки порога",
    "diagnostics/01_retransmission.pcap":
        "ретрансмиссия: дедуп по seq, число сообщений не завышается",
    "diagnostics/02_reordered.pcapng":
        "переупорядочение сегментов: порядок по seq, не по приходу",
    "diagnostics/03_missing_segment.pcap":
        "пропуск сегмента: не подменяется, partial/unknown фиксируются",
    "diagnostics/04_snaplen_truncated.pcapng":
        "усечённый захват (snaplen): частичные сообщения отмечены",
    "diagnostics/05_conflicting_overlap.pcap":
        "конфликтующее перекрытие: оставлен первый увиденный вариант",
    "diagnostics/06_missing_beginning.pcapng":
        "сессия без начала (midstream): не объявляется полноценной",
    "diagnostics/07_checksum_offload.pcap":
        "контрольные суммы offload: не влияет на разбор полезной нагрузки",
    "diagnostics/08_bad_checksum.pcap":
        "некорректная контрольная сумма: пакет сохраняется для анализа",
}


def q(s: str) -> str:
    """YAML-кавычки для строк со спецсимволами."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    schema = load_schema_file(str(SCHEMA))
    lines: list[str] = []
    lines.append("# Корпус проверки интерпретации (R4) для стенда «Термостенд».")
    lines.append("#")
    lines.append("# Пути записей и схемы — относительно этого манифеста (переносимость, R5).")
    lines.append("# Ожидания сгенерированы механически (tools/gen_case_corpus.py) и")
    lines.append("# документируют, что правильная интерпретация даёт на этих записях.")
    lines.append("# Прогон: python -m madrigal verify case/corpus.yaml --out report.json")
    lines.append("version: 1")
    lines.append("name: thermostand-case")
    lines.append("schema: ../schemas/thermostand-protocol.yaml")
    lines.append("")
    lines.append("files:")

    for gdir, gtitle in GROUPS:
        lines.append(f"# --- {gtitle} ---")
        recs = sorted((REC / gdir).glob("*"))
        recs = [r for r in recs if r.suffix.lower() in (".pcap", ".pcapng")]
        for rec in recs:
            rel = f"recordings/{gdir}/{rec.name}"
            run = run_capture(rec, schema)
            note = NOTES.get(f"{gdir}/{rec.name}", "")

            lines.append("  - path: " + q(rel))
            if note:
                lines.append("    note: >-")
                lines.append(f"      {note}")

            # expect
            lines.append("    expect:")
            lines.append(f"      sessions: {run['sessions_count']}")

            dirs = run["directions"]
            any_dir = False
            for d in ("a2b", "b2a"):
                agg = dirs[d]
                if not agg.get("scope_ok", True):
                    continue
                if not any_dir:
                    lines.append("      directions:")
                    any_dir = True
                lines.append(f"        {d}:")
                if agg["messages"]:
                    lines.append(f"          messages: {agg['messages']}")
                matched = agg.get("matched", {})
                if matched:
                    pairs = ", ".join(
                        f"{k}: {v}" for k, v in sorted(matched.items()))
                    lines.append(f"          matched: {{{pairs}}}")
                if agg["unmatched"]:
                    lines.append(f"          unmatched: {agg['unmatched']}")
                if agg["partial"]:
                    lines.append(f"          partial: {agg['partial']}")
                if agg["match_unknown"]:
                    lines.append(f"          match_unknown: {agg['match_unknown']}")
                if agg["framing_errors"]:
                    lines.append(f"          framing_errors: {agg['framing_errors']}")
                if agg["unframed_bytes"]:
                    lines.append(f"          unframed_bytes: {agg['unframed_bytes']}")

            hyps = run["hypotheses"]
            if hyps:
                lines.append("      hypotheses:")
                for hid in sorted(hyps):
                    lines.append(f"        {hid}: {hyps[hid].result}")

            lines.append("")
            print(f"[ok] {rel}: сессий {run['sessions_count']}, "
                  f"a2b={dirs['a2b']['messages']} b2a={dirs['b2a']['messages']}, "
                  f"гипотез {len(hyps)}", file=sys.stderr)

    text = "\n".join(lines).rstrip() + "\n"
    out = CASE / "corpus.yaml"
    out.write_text(text, encoding="utf-8")
    print(f"\nзаписано: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
