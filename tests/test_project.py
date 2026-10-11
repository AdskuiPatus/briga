"""Тесты переносимого проекта: манифест, целостность, перенос, R5."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from madrigal.__main__ import main
from madrigal.project import (
    ProjectError,
    add_corpus,
    add_observation,
    add_recording,
    add_result,
    add_schema,
    check_project,
    init_project,
    load_project,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
DEMO = EXAMPLES / "demo.pcapng"
SCHEMA = EXAMPLES / "demo-protocol.yaml"
CORPUS = EXAMPLES / "demo-corpus.yaml"

MINIMAL = """version: 1
name: t
"""


def _make_project(tmp_path: Path) -> Path:
    """Проект с демонстрационными материалами (копии в tmp)."""
    proj = tmp_path / "proj"
    proj.mkdir(parents=True)
    ex = proj / "examples"
    ex.mkdir()
    for f in (DEMO, EXAMPLES / "demo_defect.pcapng",
              EXAMPLES / "demo_counterexample.pcapng", SCHEMA, CORPUS):
        shutil.copy(f, ex / f.name)
    (proj / "project.yaml").write_text(MINIMAL, encoding="utf-8")
    add_recording(proj, ex / "demo.pcapng", note="эталон")
    add_recording(proj, ex / "demo_defect.pcapng")
    add_recording(proj, ex / "demo_counterexample.pcapng")
    add_schema(proj, ex / "demo-protocol.yaml")
    add_corpus(proj, ex / "demo-corpus.yaml")
    return proj


# ------------------------------------------------------------ манифест ----

def test_init_creates_manifest(tmp_path):
    manifest = init_project(tmp_path / "p", name="x", description="d")
    assert manifest.is_file()
    project = load_project(tmp_path / "p")
    assert project.name == "x"
    assert project.description == "d"
    assert project.recordings == [] and project.results == []


def test_init_refuses_overwrite(tmp_path):
    init_project(tmp_path)
    with pytest.raises(ProjectError):
        init_project(tmp_path)


def test_add_computes_sha_and_rejects_duplicates(tmp_path):
    proj = _make_project(tmp_path)
    # запись уже зарегистрирована _make_project — повтор добавить нельзя
    with pytest.raises(ProjectError):
        add_recording(proj, proj / "examples" / "demo.pcapng")
    project = load_project(proj)
    art = project.recordings[0]
    assert len(art.sha256) == 64 and art.path == "examples/demo.pcapng"


def test_add_rejects_file_outside_project(tmp_path):
    proj = _make_project(tmp_path)
    outside = tmp_path / "outside.pcapng"
    shutil.copy(DEMO, outside)
    with pytest.raises(ProjectError) as e:
        add_recording(proj, outside)
    assert "вне каталога проекта" in str(e.value)


def test_absolute_path_rejected(tmp_path):
    p = tmp_path / "project.yaml"
    p.write_text(MINIMAL + f"recordings:\n  - path: {DEMO.as_posix()}\n"
                           f"    sha256: {'0' * 64}\n", encoding="utf-8")
    with pytest.raises(ProjectError) as e:
        load_project(tmp_path)
    assert any("относительным" in err for err in e.value.errors)


def test_parent_escape_rejected(tmp_path):
    proj = _make_project(tmp_path)
    (proj / "project.yaml").write_text(
        MINIMAL + "recordings:\n  - path: ../чужой.pcapng\n"
                  f"    sha256: {'0' * 64}\n", encoding="utf-8")
    with pytest.raises(ProjectError) as e:
        load_project(proj)
    assert any("выход за пределы" in err for err in e.value.errors)


def test_missing_sha_rejected(tmp_path):
    proj = _make_project(tmp_path)
    (proj / "project.yaml").write_text(
        MINIMAL + "schemas:\n  - path: examples/demo-protocol.yaml\n",
        encoding="utf-8")
    with pytest.raises(ProjectError) as e:
        load_project(proj)
    assert any("sha256" in err for err in e.value.errors)


def test_unknown_key_rejected(tmp_path):
    proj = _make_project(tmp_path)
    (proj / "project.yaml").write_text(
        MINIMAL + "records: []\n", encoding="utf-8")
    with pytest.raises(ProjectError) as e:
        load_project(proj)
    assert any("неизвестный ключ" in err for err in e.value.errors)


def test_missing_recording_rejected(tmp_path):
    proj = _make_project(tmp_path)
    (proj / "examples" / "demo.pcapng").unlink()
    with pytest.raises(ProjectError) as e:
        load_project(proj)
    assert any("не найден" in err for err in e.value.errors)


# ---------------------------------------------------------- наблюдения ----

def test_observation_roundtrip(tmp_path):
    proj = _make_project(tmp_path)
    obs = add_observation(proj, "ответ подтверждает значение",
                          source={"file": "examples/demo.pcapng",
                                  "session": 0, "direction": "a2b",
                                  "offset": 9, "packets": [8, 9]})
    assert obs.source["packets"] == [8, 9]
    loaded = load_project(proj)
    assert len(loaded.observations) == 1
    assert loaded.observations[0].source["direction"] == "a2b"


def test_observation_bad_direction_rejected(tmp_path):
    proj = _make_project(tmp_path)
    with pytest.raises(ProjectError):
        add_observation(proj, "x", source={"direction": "нет"})


def test_observation_unknown_file_rejected(tmp_path):
    proj = _make_project(tmp_path)
    with pytest.raises(ProjectError):
        add_observation(proj, "x", source={"file": "examples/нет.pcapng"})


# ------------------------------------------------------------ проверка ----

def test_check_clean_after_add(tmp_path):
    proj = _make_project(tmp_path)
    result = check_project(proj)
    assert result["ok"]
    assert not result["stale"] and not result["errors"]


def test_check_detects_changed_recording(tmp_path):
    proj = _make_project(tmp_path)
    with open(proj / "examples" / "demo.pcapng", "ab") as f:
        f.write(b"\x00")
    result = check_project(proj)
    assert not result["ok"]
    assert any("изменён" in line for line in result["stale"])


def test_check_project_survives_transfer(tmp_path):
    """Ключевое свойство R5: после копирования проекта в другой каталог
    проверка проходит без прежних абсолютных путей."""
    proj = _make_project(tmp_path / "src")
    # отчёт корпуса регистрируем и переносим вместе с проектом
    rep = proj / "reports" / "verify.json"
    rep.parent.mkdir()
    assert main(["verify", str(proj / "examples" / "demo-corpus.yaml"),
                 "--out", str(rep)]) == 0
    add_result(proj, rep, kind="corpus-verify", note="прогон")
    before = check_project(proj)
    assert before["ok"], before["stale"]

    moved = tmp_path / "moved-elsewhere"
    shutil.copytree(proj, moved)
    after = check_project(moved)
    assert after["ok"], after["stale"] or after["errors"]
    # результат corpus-verify помечен как актуальный
    verify_entry = next(e for e in after["entries"]
                        if e["section"] == "results")
    assert verify_entry["current"] is True


def test_check_marks_stale_result(tmp_path):
    proj = _make_project(tmp_path)
    rep = proj / "reports" / "verify.json"
    rep.parent.mkdir()
    assert main(["verify", str(proj / "examples" / "demo-corpus.yaml"),
                 "--out", str(rep)]) == 0
    add_result(proj, rep, kind="corpus-verify")
    # правим схему после прогона — отчёт должен стать устаревшим
    schema_file = proj / "examples" / "demo-protocol.yaml"
    schema_file.write_text(
        schema_file.read_text(encoding="utf-8") + "\n# правка\n",
        encoding="utf-8")
    # сама запись схемы тоже изменилась — фиксируем новый sha, чтобы
    # устарел именно результат
    data = (proj / "project.yaml").read_text(encoding="utf-8")
    import hashlib
    new_sha = hashlib.sha256(schema_file.read_bytes()).hexdigest()
    old_sha = next(a.sha256 for a in load_project(proj).schemas)
    (proj / "project.yaml").write_text(
        data.replace(old_sha, new_sha), encoding="utf-8")

    result = check_project(proj)
    assert not result["ok"]
    verify_entry = next(e for e in result["entries"]
                        if e["section"] == "results")
    assert verify_entry["current"] is False
    assert any("устарел" in line for line in result["stale"])


# ---------------------------------------------------------------- CLI ----

def test_cli_init_add_check(tmp_path, capsys):
    proj = tmp_path / "p"
    assert main(["project", "init", str(proj), "--name", "t"]) == 0
    ex = proj / "examples"
    ex.mkdir()
    shutil.copy(DEMO, ex / "demo.pcapng")
    shutil.copy(SCHEMA, ex / "demo-protocol.yaml")
    assert main(["project", "add", str(proj), "recording",
                 str(ex / "demo.pcapng")]) == 0
    assert main(["project", "add", str(proj), "schema",
                 str(ex / "demo-protocol.yaml")]) == 0
    assert main(["project", "observe", str(proj), "наблюдение",
                 "--file", "examples/demo.pcapng"]) == 0
    assert main(["project", "check", str(proj)]) == 0
    out = capsys.readouterr().out
    assert "проект целостен" in out


def test_cli_check_exit_5_on_stale(tmp_path, capsys):
    proj = _make_project(tmp_path)
    rep = proj / "reports" / "verify.json"
    rep.parent.mkdir()
    assert main(["verify", str(proj / "examples" / "demo-corpus.yaml"),
                 "--out", str(rep)]) == 0
    assert main(["project", "add", str(proj), "result", str(rep)]) == 0
    assert main(["project", "check", str(proj)]) == 0
    # ломаем запись
    with open(proj / "examples" / "demo_defect.pcapng", "ab") as f:
        f.write(b"\x00")
    assert main(["project", "check", str(proj)]) == 5
    out = capsys.readouterr().out
    assert "STALE" in out


def test_cli_add_outside_project_fails(tmp_path, capsys):
    proj = _make_project(tmp_path)
    outside = tmp_path / "чужой.pcapng"
    shutil.copy(DEMO, outside)
    code = main(["project", "add", str(proj), "recording", str(outside)])
    assert code == 1
    err = capsys.readouterr().err
    assert "вне каталога проекта" in err


def test_cli_bad_manifest_exit_1(tmp_path, capsys):
    assert main(["project", "check", str(tmp_path / "нет")]) == 1
