"""Тесты отчёта исследователя (R6) и golden-примеров (R6)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from madrigal.__main__ import main
from madrigal.golden import (
    GoldenError,
    check_golden,
    load_golden,
    update_golden,
)
from madrigal.project import (
    add_corpus,
    add_observation,
    add_recording,
    add_result,
    add_schema,
    init_project,
)
from madrigal.report import build_report, render_markdown, write_report

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
GOLDEN = EXAMPLES / "golden.yaml"
DEMO_FILES = ("demo.pcapng", "demo_defect.pcapng",
              "demo_counterexample.pcapng")


def _copy_golden(tmp_path: Path) -> Path:
    """Копия golden-комплекта (манифест + записи) для правок в тестах."""
    for name in DEMO_FILES + ("demo-protocol.yaml", "demo-corpus.yaml"):
        shutil.copy(EXAMPLES / name, tmp_path / name)
    golden_file = tmp_path / "golden.yaml"
    shutil.copy(GOLDEN, golden_file)
    return golden_file


def _make_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    ex = proj / "examples"
    ex.mkdir()
    for name in DEMO_FILES + ("demo-protocol.yaml", "demo-corpus.yaml"):
        shutil.copy(EXAMPLES / name, ex / name)
    (proj / "project.yaml").write_text("version: 1\nname: t\n",
                                       encoding="utf-8")
    for name in DEMO_FILES:
        add_recording(proj, ex / name)
    add_schema(proj, ex / "demo-protocol.yaml")
    add_corpus(proj, ex / "demo-corpus.yaml")
    return proj


# ------------------------------------------------------------- отчёт -----

def test_report_contains_required_sections(tmp_path, capsys):
    proj = _make_project(tmp_path)
    rep = proj / "reports" / "v.json"
    rep.parent.mkdir()
    assert main(["verify", str(proj / "examples" / "demo-corpus.yaml"),
                 "--out", str(rep)]) == 0
    add_result(proj, rep, kind="corpus-verify")
    add_observation(proj, "ответ подтверждает значение",
                    source={"file": "examples/demo.pcapng", "session": 0,
                            "direction": "a2b", "offset": 9})

    data = build_report(proj)
    text = render_markdown(data)

    # основания выводов (R6): гипотезы с утверждением и основаниями
    assert "h-echo" in text and "основания" in text.lower()
    hyp = data["schemas"][0]["hypotheses"][0]
    assert hyp["statement"] and hyp["basis"]
    assert hyp["mechanically_checked"] is True
    # проверенные примеры
    assert "Проверенные примеры" in text
    assert data["checks"][0]["totals"]["files"] == 3
    # контрпримеры с привязкой к пакетам
    v = data["checks"][0]["violations"][0]
    assert v["hypothesis"] == "h-echo"
    ce = v["counterexamples"][0]
    assert ce["a"]["packets"] and ce["b"]["packets"]
    assert "Контрпримеры" in text
    # область применимости
    assert "Область применимости" in text
    # открытые вопросы: h-status-zero без механической проверки
    assert any("h-status-zero" in q for q in data["open_questions"])
    # наблюдения со связями к источникам
    assert "Наблюдения исследователя" in text
    assert "examples/demo.pcapng" in text
    # документированные команды повторного применения
    assert "apply" in text and "verify" in text and "golden" in text


def test_report_notes_stale_result(tmp_path):
    proj = _make_project(tmp_path)
    rep = proj / "reports" / "v.json"
    rep.parent.mkdir()
    assert main(["verify", str(proj / "examples" / "demo-corpus.yaml"),
                 "--out", str(rep)]) == 0
    add_result(proj, rep, kind="corpus-verify")
    # правим запись — отчёт корпуса устаревает
    with open(proj / "examples" / "demo_defect.pcapng", "ab") as f:
        f.write(b"\x00")
    data = build_report(proj)
    check = data["checks"][0]
    assert check["current"] is False
    assert any("устарел" in q for q in data["open_questions"])


def test_report_without_results_is_honest(tmp_path):
    proj = _make_project(tmp_path)
    data = build_report(proj)
    assert data["checks"] == []
    text = render_markdown(data)
    assert "Проверки не регистрировались" in text


def test_report_json_and_md_written(tmp_path):
    proj = _make_project(tmp_path)
    md = tmp_path / "r.md"
    js = tmp_path / "r.json"
    write_report(proj, markdown_path=md, json_path=js)
    assert "Отчёт об исследовании" in md.read_text(encoding="utf-8")
    loaded = json.loads(js.read_text(encoding="utf-8"))
    assert loaded["project"]["name"] == "t"


def test_cli_report(tmp_path, capsys):
    proj = _make_project(tmp_path)
    md = tmp_path / "r.md"
    assert main(["report", str(proj), "--md", str(md)]) == 0
    assert md.is_file()
    assert main(["report", str(tmp_path / "нет")]) == 1


# ------------------------------------------------------------ golden -----

def test_golden_manifest_valid():
    golden = load_golden(GOLDEN)
    assert golden.name == "demo-golden"
    kinds = {c.kind for c in golden.cases}
    assert kinds == {"apply", "verify"}


def test_golden_all_pass_on_current_tool():
    """Повторное применение даёт согласованные результаты (R6)."""
    result = check_golden(GOLDEN)
    assert result["ok"], [c.get("diffs") for c in result["cases"]]
    assert len(result["cases"]) == 5


def test_golden_detects_changed_expectation(tmp_path):
    golden_file = _copy_golden(tmp_path)
    text = golden_file.read_text(encoding="utf-8")
    # портим ожидаемый счётчик
    golden_file.write_text(
        text.replace("messages: 5", "messages: 6", 1), encoding="utf-8")
    result = check_golden(golden_file)
    assert not result["ok"]
    failed = next(c for c in result["cases"] if not c["ok"])
    assert any("messages" in d for d in failed["diffs"])


def test_golden_update_restores(tmp_path):
    golden_file = _copy_golden(tmp_path)
    golden_file.write_text(
        golden_file.read_text(encoding="utf-8")
        .replace("messages: 5", "messages: 6", 1), encoding="utf-8")
    assert not check_golden(golden_file)["ok"]
    update_golden(golden_file)
    assert check_golden(golden_file)["ok"]


def test_golden_empty_expect_fails_with_hint(tmp_path):
    import yaml

    golden_file = _copy_golden(tmp_path)
    data = yaml.safe_load(golden_file.read_text(encoding="utf-8"))
    data["cases"][0]["expect"] = {}
    golden_file.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    result = check_golden(golden_file)
    assert not result["ok"]
    assert any("--update" in d for c in result["cases"]
               for d in c.get("diffs") or [])


def test_golden_bad_manifest(tmp_path):
    p = tmp_path / "golden.yaml"
    p.write_text("version: 1\nname: x\ncases:\n  - name: y\n    kind: что\n",
                 encoding="utf-8")
    with pytest.raises(GoldenError):
        load_golden(p)


def test_golden_absolute_path_rejected(tmp_path):
    p = tmp_path / "golden.yaml"
    p.write_text(
        f"version: 1\nname: x\ncases:\n  - name: y\n    kind: apply\n"
        f"    file: {DEMO_FILES[0]}\n    schema: {EXAMPLES.as_posix()}/"
        f"demo-protocol.yaml\n", encoding="utf-8")
    with pytest.raises(GoldenError) as e:
        load_golden(p)
    assert any("относительным" in err for err in e.value.errors)


def test_cli_golden_ok(capsys):
    assert main(["golden", str(GOLDEN)]) == 0
    out = capsys.readouterr().out
    assert "расхожд" not in out or "0 случаев" not in out


def test_cli_golden_mismatch_exit_4(tmp_path, capsys):
    golden_file = _copy_golden(tmp_path)
    golden_file.write_text(
        golden_file.read_text(encoding="utf-8")
        .replace("unmatched: 0", "unmatched: 1", 1), encoding="utf-8")
    assert main(["golden", str(golden_file)]) == 4
    assert main(["golden", str(tmp_path / "нет.yaml")]) == 1


def test_cli_golden_update(tmp_path, capsys):
    golden_file = _copy_golden(tmp_path)
    assert main(["golden", str(golden_file), "--update"]) == 0
    assert main(["golden", str(golden_file)]) == 0
