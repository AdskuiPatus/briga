"""Расширить project.yaml материалами стенда «Термостенд» (R5).

Читает существующий project.yaml, добавляет записи стенда (case/recordings),
схему, корпус, отчёт и наблюдения, пересчитывая sha256 программно.
Демо-материалы (examples/) сохраняются.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "project.yaml"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    data["name"] = "madrigal-lab"
    data["description"] = (
        "Лаборатория протоколов МАДРИГАЛ: локальный инструмент исследования "
        "недокументированного TCP-протокола по PCAP/PCAPNG — декларативные "
        "интерпретации, корпус проверки, корреляция с журналом действий, "
        "отчёты и замеры. Демо-стенд (examples/) и реальный стенд "
        "«Термостенд» (case/)."
    )

    def art(rel: str, note: str) -> dict:
        return {"path": rel, "sha256": sha(ROOT / rel), "note": note}

    # --- записи стенда «Термостенд» --------------------------------------
    case_notes = {
        "case/recordings/research/01_configuration.pcap":
            "исследование: базовый обмен конфигурацией (2 сессии)",
        "case/recordings/research/02_variations.pcapng":
            "исследование: вариации параметров, есть служебный probe 0x7E",
        "case/recordings/research/03_combined_messages.pcap":
            "исследование: несколько сообщений в одном TCP-сегменте",
        "case/recordings/additional/04_new_observations.pcapng":
            "дополнительные наблюдения чтения значений и установки порога",
        "case/recordings/diagnostics/01_retransmission.pcap":
            "диагностика: ретрансмиссия, дедуп по seq",
        "case/recordings/diagnostics/02_reordered.pcapng":
            "диагностика: переупорядочение сегментов, порядок по seq",
        "case/recordings/diagnostics/03_missing_segment.pcap":
            "диагностика: пропуск сегмента, partial/unknown фиксируются",
        "case/recordings/diagnostics/04_snaplen_truncated.pcapng":
            "диагностика: усечённый захват (snaplen)",
        "case/recordings/diagnostics/05_conflicting_overlap.pcap":
            "диагностика: конфликтующее перекрытие, оставлен первый увиденный",
        "case/recordings/diagnostics/06_missing_beginning.pcapng":
            "диагностика: сессия без начала (midstream)",
        "case/recordings/diagnostics/07_checksum_offload.pcap":
            "диагностика: контрольные суммы offload",
        "case/recordings/diagnostics/08_bad_checksum.pcapng":
            "диагностика: некорректная контрольная сумма",
    }
    for rel, note in case_notes.items():
        data["recordings"].append(art(rel, note))

    # --- схема интерпретации стенда --------------------------------------
    data["schemas"].append(art(
        "schemas/thermostand-protocol.yaml",
        "декларативная интерпретация протокола стенда «Термостенд» "
        "(кадр A6 5C, типы 10/20/30, статусы, знаковые поля, повторы, "
        "журнал действий)"))

    # --- корпус проверки ---------------------------------------------------
    data["corpora"].append(art(
        "case/corpus.yaml",
        "корпус проверки стенда: 12 записей (норма + дефекты захвата) "
        "с ожиданиями по счётчикам и гипотезам"))

    # --- результаты --------------------------------------------------------
    data["results"].append({
        "path": "reports/thermostand-corpus-verify.json",
        "kind": "corpus-verify",
        "note": "прогон корпуса стенда по схеме: 12/12 ожиданий выполнены, "
                "дефекты захвата честно отражены (fail/not_applicable)",
    })

    # --- наблюдения --------------------------------------------------------
    data["observations"].extend([
        {
            "text": "журнал действий ↔ обмен: 6 типов действий "
                    "(чтение/запись конфигурации, чтение значений) "
                    "сверены с записями research/01–03 и additional/04 — "
                    "0 противоречий (mismatch); статусы и эхо подтверждаются "
                    "исходными байтами",
            "source": {"file": "case/recordings/research/01_configuration.pcap",
                       "session": 0},
        },
        {
            "text": "неопознанный служебный probe (тип 0x7E) в research/02 — "
                    "оставлен как честный неохват, не подменён известным типом",
            "source": {"file": "case/recordings/research/02_variations.pcapng",
                       "session": 0},
        },
        {
            "text": "пропуск сегмента (diagnostics/03): гипотезы "
                    "h_seq_read_config и h_read_values_count опровергнуты "
                    "данными, контрпримеры привязаны к пакетам; число "
                    "сообщений не завышается",
            "source": {"file": "case/recordings/diagnostics/03_missing_segment.pcap",
                       "session": 0, "direction": "b2a"},
        },
        {
            "text": "midstream (diagnostics/06): сессия без начала не "
                    "объявлена полноценной, 3 байта вне рамок зафиксированы",
            "source": {"file": "case/recordings/diagnostics/06_missing_beginning.pcapng",
                       "session": 0, "direction": "a2b"},
        },
    ])

    MANIFEST.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    print(f"записано: {MANIFEST}", file=sys.stderr)
    print(f"записей: {len(data['recordings'])}, схем: {len(data['schemas'])}, "
          f"корпусов: {len(data['corpora'])}, результатов: {len(data['results'])}, "
          f"наблюдений: {len(data['observations'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
