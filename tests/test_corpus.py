"""Корпус записей: манифест, проверка ожиданий, контрпримеры, R4-сводка."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from madrigal.__main__ import main
from madrigal.capture import open_capture
from madrigal.corpus import (
    CorpusError,
    check_report,
    check_report_stale,
    load_corpus,
    verify_corpus,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
CORPUS = EXAMPLES / "demo-corpus.yaml"
DEMO_FILES = ("demo.pcapng", "demo_defect.pcapng", "demo_counterexample.pcapng")

BAD_COUNT = """
version: 1
name: bad-count
schema: demo-protocol.yaml
files:
  - path: demo.pcapng
    expect:
      directions:
        b2a: {matched: {set_value: 5}}
"""

BAD_HYP = """
version: 1
name: bad-hyp
schema: demo-protocol.yaml
files:
  - path: demo.pcapng
    expect:
      hypotheses: {h-echo: confirmed}
"""

BAD_KEY = """
version: 1
name: bad-key
schema: demo-protocol.yaml
files:
  - path: demo.pcapng
    expects: {}
"""


def _copy_corpus(tmp_path: Path, manifest_text: str | None = None) -> Path:
    """Скопировать записи и схему в tmp, вернуть путь к манифесту."""
    for name in DEMO_FILES + ("demo-protocol.yaml",):
        shutil.copy(EXAMPLES / name, tmp_path / name)
    m = tmp_path / "corpus.yaml"
    m.write_text(manifest_text or CORPUS.read_text(encoding="utf-8"),
                 encoding="utf-8")
    return m


# ------------------------------------------------------------- манифест ----

def test_load_corpus_ok():
    c = load_corpus(CORPUS)
    assert c.name == "demo-corpus"
    assert c.schema_ref == "demo-protocol.yaml"
    assert [f.path for f in c.files] == list(DEMO_FILES)
    assert len(c.manifest_sha256) == 64


def test_load_corpus_missing_manifest(tmp_path):
    with pytest.raises(CorpusError) as e:
        load_corpus(tmp_path / "нет.yaml")
    assert "манифест не найден" in e.value.errors[0]


def test_load_corpus_unknown_key_rejected(tmp_path):
    with pytest.raises(CorpusError) as e:
        load_corpus(_copy_corpus(tmp_path, BAD_KEY))
    assert any("неизвестный ключ 'expects'" in x and "опечатка" in x
               for x in e.value.errors)


def test_load_corpus_bad_hyp_result(tmp_path):
    with pytest.raises(CorpusError) as e:
        load_corpus(_copy_corpus(tmp_path, BAD_HYP))
    assert any("h-echo" in x and "confirmed" in x for x in e.value.errors)


def test_load_corpus_missing_capture(tmp_path):
    m = _copy_corpus(tmp_path, """
version: 1
name: ghost
schema: demo-protocol.yaml
files:
  - path: нет.pcapng
""")
    with pytest.raises(CorpusError) as e:
        load_corpus(m)
    assert any("запись не найдена" in x for x in e.value.errors)


def test_load_corpus_negative_count(tmp_path):
    m = _copy_corpus(tmp_path, """
version: 1
name: neg
schema: demo-protocol.yaml
files:
  - path: demo.pcapng
    expect:
      directions:
        b2a: {unmatched: -3}
""")
    with pytest.raises(CorpusError) as e:
        load_corpus(m)
    assert any("unmatched" in x and ">= 0" in x for x in e.value.errors)


def test_load_corpus_bad_direction(tmp_path):
    m = _copy_corpus(tmp_path, """
version: 1
name: baddir
schema: demo-protocol.yaml
files:
  - path: demo.pcapng
    expect:
      directions:
        aa: {unmatched: 0}
""")
    with pytest.raises(CorpusError) as e:
        load_corpus(m)
    assert any("expect.directions" in x and "'aa'" in x
               for x in e.value.errors)


# -------------------------------------------------------------- прогон ----

def test_verify_demo_corpus_all_ok():
    r = verify_corpus(CORPUS)
    assert r["totals"] == {"files": 3, "ok": 3, "mismatched": 0}
    assert r["summary_counts"] == {
        "violations": 1,       # контрпример: h-echo опровергнута данными
        "coverage": 1,         # defect: неопознанные сообщения
        "ambiguities": 1,      # defect: конфликтующее перекрытие
        "not_applicable": 4,   # h-status-zero ×3 + h-echo в defect
        "unknown": 3,          # пропуск, частичное, midstream
    }
    assert set(r["summary"]) == {
        "violations", "coverage", "ambiguities", "not_applicable", "unknown"}


def test_verify_counterexample_detected():
    r = verify_corpus(CORPUS)
    f = next(x for x in r["files"] if "counterexample" in x["path"])
    assert f["ok"] is True                     # ожидание «fail» выполнено
    assert any("опровергнута данными" in v and "21" in v and "99" in v
               for v in f["violations"])
    h = next(x for x in f["hypotheses"] if x["id"] == "h-echo")
    assert h["result"] == "fail"
    assert h["counterexamples_total"] == 1
    ce = h["counterexamples"][0]
    assert ce["a"]["value"] == 21 and ce["b"]["value"] == 99


def test_verify_defect_findings():
    r = verify_corpus(CORPUS)
    f = next(x for x in r["files"] if "defect" in x["path"])
    assert any("неопознанных сообщений 2" in x for x in f["findings"]["coverage"])
    assert any("перекрытий 1" in x for x in f["findings"]["ambiguities"])
    assert any("40" in x for x in f["findings"]["unknown"])           # пропуск
    assert any("частичных сообщений 1" in x for x in f["findings"]["unknown"])
    assert any("рукопожатия" in x for x in f["findings"]["unknown"])  # midstream
    assert any("h-echo: not_applicable" in x
               for x in f["findings"]["not_applicable"])
    assert f["midstream_sessions"] == 1


def test_expectation_mismatch_marks_violation(tmp_path):
    r = verify_corpus(_copy_corpus(tmp_path, BAD_COUNT))
    assert r["totals"]["mismatched"] == 1
    f = r["files"][0]
    assert f["ok"] is False
    assert f["mismatches"] == ["b2a.set_value: ожидалось 5, получено 2"]
    assert any("b2a.set_value" in v for v in r["summary"]["violations"])


def test_wrong_hypothesis_expectation_marks_violation(tmp_path):
    manifest = BAD_HYP.replace("{h-echo: confirmed}", "{h-echo: fail}")
    r = verify_corpus(_copy_corpus(tmp_path, manifest))
    assert r["totals"]["mismatched"] == 1
    assert any("h-echo: ожидался результат fail, получен pass" in m
               for m in r["files"][0]["mismatches"])


def test_schema_override_reflects_live_change(tmp_path):
    """Сценарий защиты: изменили интерпретацию — перепроверка нашла расхождения."""
    m = _copy_corpus(tmp_path)
    override = tmp_path / "narrow.yaml"      # убрали правило set_value
    override.write_text(NARROW_SCHEMA, encoding="utf-8")
    r = verify_corpus(m, schema_override=override)
    assert r["schema"]["overridden"] is True
    assert r["schema"]["name"] == "narrow"
    f = next(x for x in r["files"] if x["path"] == "demo.pcapng")
    assert f["ok"] is False
    assert any("b2a.set_value" in x for x in f["mismatches"])


NARROW_SCHEMA = """
version: 1
name: narrow
scope: {directions: [b2a]}
framing:
  magic: "AA 55"
  header: 5
  length: {offset: 3, type: u16le, includes: payload}
messages:
  - id: read_params
    direction: b2a
    when: [{offset: 2, type: u8, eq: 1}]
    fields: [{name: cmd, offset: 2, type: u8}]
"""


def test_schema_text_override_stamps_and_stale(tmp_path):
    """Текст из редактора: переопределение заштамповано, файловой сверки нет."""
    m = _copy_corpus(tmp_path)
    text = (EXAMPLES / "demo-protocol.yaml").read_text(encoding="utf-8")
    r = verify_corpus(m, schema_text=text + "\n# правка исследователя\n")
    assert r["schema"]["overridden"] is True
    assert r["schema"]["source"] == "text"
    assert r["schema"]["path"] == "<schema_text>"
    assert check_report_stale(r, m / "report.json") == []


def test_schema_text_override_changes_outcome(tmp_path):
    """Правка интерпретации текстом сразу видна в результатах корпуса."""
    m = _copy_corpus(tmp_path)
    r = verify_corpus(m, schema_text=NARROW_SCHEMA)
    f = next(x for x in r["files"] if x["path"] == "demo.pcapng")
    assert f["ok"] is False
    assert any("b2a.set_value" in x for x in f["mismatches"])


def test_report_stamps_inputs():
    r = verify_corpus(CORPUS)
    assert r["tool"]["version"] and r["generated_at"]
    assert len(r["corpus"]["sha256"]) == 64
    assert len(r["schema"]["sha256"]) == 64
    for f, name in zip(r["files"], DEMO_FILES):
        assert f["sha256"] == open_capture(str(EXAMPLES / name)).sha256


def test_verify_missing_capture_raises(tmp_path):
    m = _copy_corpus(tmp_path)
    (tmp_path / "demo.pcapng").write_bytes(b"this is not a capture")
    with pytest.raises(CorpusError) as e:
        verify_corpus(m)
    assert any("не удалось прочитать" in x for x in e.value.errors)


# --------------------------------------------------------- устаревание ----

def test_report_fresh_after_generation(tmp_path):
    m = _copy_corpus(tmp_path)
    assert check_report_stale(verify_corpus(m), m / "report.json") == []


def test_stale_detects_capture_change(tmp_path):
    m = _copy_corpus(tmp_path)
    report = verify_corpus(m)
    shutil.copy(EXAMPLES / "demo_defect.pcapng", tmp_path / "demo.pcapng")
    reasons = check_report_stale(report, m)
    assert any("запись изменена: demo.pcapng" in x for x in reasons)


def test_stale_detects_schema_change(tmp_path):
    m = _copy_corpus(tmp_path)
    report = verify_corpus(m)
    p = tmp_path / "demo-protocol.yaml"
    p.write_text(p.read_text(encoding="utf-8") + "\n# поправка\n",
                 encoding="utf-8")
    reasons = check_report_stale(report, m)
    assert any("схема изменена" in x for x in reasons)


def test_stale_detects_manifest_change(tmp_path):
    m = _copy_corpus(tmp_path)
    report = verify_corpus(m)
    m.write_text(m.read_text(encoding="utf-8") + "\n# правка\n",
                 encoding="utf-8")
    reasons = check_report_stale(report, m)
    assert any("манифест корпуса изменён" in x for x in reasons)


def test_stale_detects_missing_capture(tmp_path):
    m = _copy_corpus(tmp_path)
    report = verify_corpus(m)
    (tmp_path / "demo.pcapng").unlink()
    reasons = check_report_stale(report, m)
    assert any("запись не найдена: demo.pcapng" in x for x in reasons)


def test_check_report_rejects_foreign_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}', encoding="utf-8")
    with pytest.raises(CorpusError):
        check_report(p)


# ---------------------------------------------------------------- CLI ----

def test_cli_verify_ok(tmp_path, capsys):
    out = tmp_path / "report.json"
    code = main(["verify", str(CORPUS), "--out", str(out)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["totals"]["mismatched"] == 0
    text = capsys.readouterr().out
    assert "итог" in text and "сводка" in text


def test_cli_verify_mismatch_exit_4(tmp_path):
    code = main(["verify", str(_copy_corpus(tmp_path, BAD_COUNT))])
    assert code == 4


def test_cli_verify_bad_manifest_exit_1(tmp_path):
    assert main(["verify", str(tmp_path / "нет.yaml")]) == 1


def test_cli_stale_roundtrip(tmp_path, capsys):
    m = _copy_corpus(tmp_path)
    out = tmp_path / "report.json"
    assert main(["verify", str(m), "--out", str(out)]) == 0
    assert main(["stale", str(out)]) == 0
    shutil.copy(EXAMPLES / "demo_counterexample.pcapng",
                tmp_path / "demo.pcapng")
    assert main(["stale", str(out)]) == 5
    text = capsys.readouterr().out
    assert "УСТАРЕЛ" in text and "изменена" in text


def test_cli_apply_output_is_stamped(tmp_path):
    out = tmp_path / "apply.json"
    code = main(["apply", str(EXAMPLES / "demo.pcapng"),
                 "--schema", str(EXAMPLES / "demo-protocol.yaml"),
                 "--out", str(out)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"]["version"] and data["generated_at"]
    assert data["schema"]["sha256"] and data["file"]["sha256"]
