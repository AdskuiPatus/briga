"""API проверки корпуса (R4) и штампов для распознавания устаревания."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from madrigal.capture import open_capture
from madrigal.webapp import app, state

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
CORPUS = EXAMPLES / "demo-corpus.yaml"
DEMO = EXAMPLES / "demo.pcapng"
SCHEMA = EXAMPLES / "demo-protocol.yaml"


def _client():
    state.loaded = None
    state.schema = None
    state.schema_text = ""
    state.schema_errors = []
    return TestClient(app)


def test_api_verify_ok():
    with _client() as c:
        r = c.post("/api/verify", json={"path": str(CORPUS)})
    assert r.status_code == 200
    d = r.json()
    assert d["totals"] == {"files": 3, "ok": 3, "mismatched": 0}
    assert d["summary_counts"]["violations"] == 1
    assert d["corpus"]["name"] == "demo-corpus"
    assert len(d["schema"]["sha256"]) == 64
    assert all(len(f["sha256"]) == 64 for f in d["files"])


def test_api_verify_whitespace_path():
    with _client() as c:
        r = c.post("/api/verify", json={"path": "   "})
    assert r.status_code == 400


def test_api_verify_missing_manifest():
    with _client() as c:
        r = c.post("/api/verify", json={"path": "нет/нет.yaml"})
    assert r.status_code == 400
    assert "корпус не прошёл проверку" in r.json()["detail"]


def test_api_verify_bad_manifest_lists_errors(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("version: 1\nname: x\nschema: s.yaml\nfiles: []\n",
                 encoding="utf-8")
    with _client() as c:
        r = c.post("/api/verify", json={"path": str(p)})
    assert r.status_code == 400
    assert "files" in r.json()["detail"]


def test_api_apply_response_carries_stamps():
    with _client() as c:
        assert c.post("/api/open", json={"path": str(DEMO)}).status_code == 200
        assert c.post("/api/schema",
                      json={"path": str(SCHEMA)}).json()["present"] is True
        r = c.post("/api/schema/apply", json={"scope": "session", "session": 0})
    assert r.status_code == 200
    d = r.json()
    assert len(d["schema"]["sha256"]) == 64
    assert d["file"]["sha256"] == open_capture(str(DEMO)).sha256


def test_api_verify_schema_text_override():
    """UI гоняет корпус по активной схеме редактора (живая перепроверка)."""
    with _client() as c:
        s1 = c.post("/api/schema", json={"path": str(SCHEMA)}).json()
        modified = s1["text"] + "\n# правка исследователя\n"
        r = c.post("/api/verify",
                   json={"path": str(CORPUS), "schema_text": modified})
    assert r.status_code == 200
    d = r.json()
    assert d["schema"]["overridden"] is True
    assert d["schema"]["source"] == "text"
    assert d["schema"]["sha256"] != s1["sha256"]
    assert d["totals"]["mismatched"] == 0     # правка комментария ничего не ломает


def test_api_verify_bad_schema_text():
    with _client() as c:
        r = c.post("/api/verify",
                   json={"path": str(CORPUS), "schema_text": "version: 2\n"})
    assert r.status_code == 400
    assert "корпус не прошёл проверку" in r.json()["detail"]


def test_api_schema_sha_changes_after_edit():
    """Основа UI-индикатора устаревания: правка схемы меняет её sha256."""
    with _client() as c:
        assert c.post("/api/open", json={"path": str(DEMO)}).status_code == 200
        s1 = c.post("/api/schema", json={"path": str(SCHEMA)}).json()
        applied = c.post("/api/schema/apply",
                         json={"scope": "session", "session": 0}).json()
        assert applied["schema"]["sha256"] == s1["sha256"]
        s2 = c.post("/api/schema", json={"text": s1["text"] + "\n# правка\n"}).json()
    assert s2["present"] is True
    assert s2["sha256"] != applied["schema"]["sha256"]
