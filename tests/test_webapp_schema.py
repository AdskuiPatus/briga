"""API схем интерпретации: загрузка, валидация, применение (R3)."""

from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient

from madrigal.synth import tcp_packet, write_pcapng
from madrigal.webapp import app, state

C_IP, C_PORT = "192.168.1.10", 40000
S_IP, S_PORT = "10.0.0.2", 5000

SCHEMA_YAML = """
version: 1
name: api-test
framing:
  magic: "AA 55"
  header: 5
  length: {offset: 3, type: u16le, includes: payload}
messages:
  - id: set_value
    direction: b2a
    when: [{offset: 2, type: u8, eq: 2}]
    fields: [{name: value, offset: 5, type: u16le}]
  - id: set_ack
    direction: a2b
    when: [{offset: 3, type: u16le, eq: 2}]
    fields: [{name: value, offset: 5, type: u16le}]
hypotheses:
  - id: h-echo
    statement: "ответ подтверждает значение"
    basis: ["наблюдение"]
    check:
      pairs:
        a: {message: set_value, field: value}
        b: {message: set_ack, field: value}
      expect: equal
"""


def _frames():
    def c(seq, flags="A", payload=b"", ack=1001):
        return tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=C_PORT, dport=S_PORT,
                          seq=seq, flags=flags, payload=payload, ack=ack)

    def s(seq, flags="A", payload=b"", ack=1001):
        return tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT, dport=C_PORT,
                          seq=seq, flags=flags, payload=payload, ack=ack)

    req = b"\xAA\x55\x02\x02\x00" + struct.pack("<H", 21)
    ack = b"\xAA\x55\x00\x02\x00" + struct.pack("<H", 21)
    return [
        (0.0, c(1000, flags="S")),
        (0.1, s(5000, flags="SA", ack=1001)),
        (0.2, c(1001)),
        (0.3, c(1001, payload=req)),
        (0.4, s(5001, payload=ack)),
        (0.5, c(1001 + len(req), flags="FA")),
        (0.6, s(5001 + len(ack), flags="FA")),
    ]


@pytest.fixture()
def client(tmp_path):
    path = tmp_path / "schema_api.pcapng"
    write_pcapng(path, _frames())
    state.loaded = None
    state.schema = None
    state.schema_text = ""
    state.schema_errors = []
    with TestClient(app) as c:
        assert c.post("/api/open", json={"path": str(path)}).status_code == 200
        yield c
    state.loaded = None
    state.schema = None
    state.schema_text = ""
    state.schema_errors = []


def test_schema_initially_absent(client):
    d = client.get("/api/schema").json()
    assert d["present"] is False and d["errors"] == [] and d["messages"] == []


def test_schema_valid_text_accepted(client):
    r = client.post("/api/schema", json={"text": SCHEMA_YAML})
    d = r.json()
    assert d["present"] is True and d["errors"] == []
    assert d["name"] == "api-test" and len(d["sha256"]) == 64
    assert d["messages"] == ["set_value", "set_ack"]
    assert d["hypotheses"] == ["h-echo"]
    # текст сохранён для редактора
    assert client.get("/api/schema").json()["text"] == SCHEMA_YAML


def test_schema_invalid_text_reported_and_deactivated(client):
    assert client.post("/api/schema", json={"text": SCHEMA_YAML}).json()["present"]
    bad = SCHEMA_YAML.replace("u16le", "u16")    # неизвестный тип поля
    d = client.post("/api/schema", json={"text": bad}).json()
    assert d["present"] is False
    assert d["errors"], "ожидались ошибки валидации"
    # непрогремевшая схема не остаётся «тихо активной»
    assert client.post("/api/schema/apply", json={}).status_code == 400


def test_schema_empty_text_rejected(client):
    assert client.post("/api/schema", json={"text": "   "}).status_code == 400


def test_schema_from_file(client, tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(SCHEMA_YAML, encoding="utf-8")
    d = client.post("/api/schema", json={"path": str(p)}).json()
    assert d["present"] is True and d["name"] == "api-test"


def test_schema_file_wrong_suffix(client, tmp_path):
    p = tmp_path / "s.txt"
    p.write_text(SCHEMA_YAML, encoding="utf-8")
    assert client.post("/api/schema", json={"path": str(p)}).status_code == 400


def test_schema_file_missing(client, tmp_path):
    r = client.post("/api/schema", json={"path": str(tmp_path / "no.yaml")})
    assert r.status_code == 404


def test_schema_apply_requires_schema(client):
    r = client.post("/api/schema/apply", json={"scope": "session", "session": 0})
    assert r.status_code == 400


def test_schema_apply_bad_scope(client):
    client.post("/api/schema", json={"text": SCHEMA_YAML})
    r = client.post("/api/schema/apply", json={"scope": "galaxy"})
    assert r.status_code == 400


def test_schema_apply_unknown_session(client):
    client.post("/api/schema", json={"text": SCHEMA_YAML})
    r = client.post("/api/schema/apply", json={"scope": "session", "session": 7})
    assert r.status_code == 404


def test_schema_apply_session(client):
    client.post("/api/schema", json={"text": SCHEMA_YAML})
    d = client.post("/api/schema/apply",
                    json={"scope": "session", "session": 0}).json()
    assert d["schema"]["name"] == "api-test"
    assert d["scope"] == "session" and len(d["sessions"]) == 1

    sess = d["sessions"][0]
    assert sess["midstream"] is False
    rb = sess["directions"]["b2a"]["stats"]
    assert rb["matched"] == {"set_value": 1} and rb["messages"] == 1
    ra = sess["directions"]["a2b"]["stats"]
    assert ra["matched"] == {"set_ack": 1} and ra["messages"] == 1

    msg = sess["directions"]["b2a"]["messages"][0]
    assert msg["fields"]["value"]["value"] == 21
    assert msg["fields"]["value"]["known"] is True

    h = sess["hypotheses"][0]
    assert h["result"] == "pass" and h["status_after"] == "checked"
    assert h["pairs"] == {"total": 1, "ok": 1, "unknown": 0}


def test_schema_apply_all(client):
    client.post("/api/schema", json={"text": SCHEMA_YAML})
    d = client.post("/api/schema/apply", json={"scope": "all"}).json()
    assert len(d["sessions"]) == 1


def test_schema_apply_message_cap(client):
    client.post("/api/schema", json={"text": SCHEMA_YAML})
    d = client.post("/api/schema/apply",
                    json={"scope": "session", "session": 0,
                          "max_messages": 1}).json()
    rd = d["sessions"][0]["directions"]["b2a"]
    # в потоке одно сообщение — кап не сработал, но поле присутствует
    assert rd["messages_total"] == 1 and rd["messages_truncated"] is False
