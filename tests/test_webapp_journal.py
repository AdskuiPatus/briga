# -*- coding: utf-8 -*-
"""API корреляции журнала действий с обменом (R2)."""

from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient

from madrigal.synth import tcp_packet, write_pcapng
from madrigal.webapp import app, state

# стороны: A/B назначаются по лексикографическому порядку (ip, порт), поэтому
# IP клиента (отправитель запроса) меньше IP сервера -> клиент = A = a2b
C_IP, C_PORT = "10.0.0.2", 40000
S_IP, S_PORT = "10.0.0.3", 5000

# мини-протокол: запрос (a2b) = type 1 + value(u16be); ответ (b2a) = type 2 +
# status(u8) + value(u16be). Секция journal связывает действие set-value с
# этими сообщениями и задаёт сверку полей (value в сотых).
SCHEMA_YAML = """
version: 1
name: japi
framing:
  magic: "AA 55"
  header: 5
  length: {offset: 3, type: u16le, includes: payload}
messages:
  - id: req_set
    direction: a2b
    when: [{offset: 2, type: u8, eq: 1}]
    fields: [{name: value, offset: 5, type: u16be}]
  - id: resp_set
    direction: b2a
    when: [{offset: 2, type: u8, eq: 2}]
    fields: [{name: status, offset: 5, type: u8}, {name: value, offset: 6, type: u16be}]
journal:
  actions:
    set-value: {request: req_set, response: resp_set}
  status_map: {0: ok}
  bindings:
    - {observed: status, decoded: status, status: true}
    - {observed: value, decoded: value, scale: 0.01}
"""

SCHEMA_NO_JOURNAL = SCHEMA_YAML.split("journal:")[0]

CSV = (
    "capture,session,action_id,start_utc,end_utc,action,parameters,observed_result\n"
    "journal_api.pcapng,s1,J1,1970-01-01T00:00:00.300000Z,"
    '1970-01-01T00:00:00.400000Z,set-value,"{""value"": 2100}",'
    '"{""status"": ""ok"", ""value"": 21.0}"\n'
)


def _frames():
    def c(seq, flags="A", payload=b"", ack=1001):
        return tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=C_PORT, dport=S_PORT,
                          seq=seq, flags=flags, payload=payload, ack=ack)

    def s(seq, flags="A", payload=b"", ack=1001):
        return tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT, dport=C_PORT,
                          seq=seq, flags=flags, payload=payload, ack=ack)

    # value 2100 = 21.00 (сотые); заголовок 5 байт: magic|type|len(u16le)
    req = b"\xAA\x55\x01\x02\x00" + struct.pack(">H", 2100)
    resp = b"\xAA\x55\x02\x03\x00" + b"\x00" + struct.pack(">H", 2100)
    return [
        (0.0, c(1000, flags="S")),
        (0.1, s(5000, flags="SA", ack=1001)),
        (0.2, c(1001)),
        (0.3, c(1001, payload=req)),
        (0.4, s(5001, payload=resp)),
        (0.5, c(1001 + len(req), flags="FA")),
        (0.6, s(5001 + len(resp), flags="FA")),
    ]


def _csv(tmp_path) -> str:
    p = tmp_path / "journal.csv"
    p.write_text(CSV, encoding="utf-8")
    return str(p)


@pytest.fixture()
def client(tmp_path):
    path = tmp_path / "journal_api.pcapng"
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


def _load_schema(client, text=SCHEMA_YAML):
    d = client.post("/api/schema", json={"text": text}).json()
    assert d["present"] is True, d.get("errors")


def test_journal_requires_schema_section(client, tmp_path):
    _load_schema(client, SCHEMA_NO_JOURNAL)
    r = client.post("/api/journal", json={"path": _csv(tmp_path)})
    assert r.status_code == 400 and "journal" in r.json()["detail"]


def test_journal_correlates_and_verifies(client, tmp_path):
    _load_schema(client)
    d = client.post("/api/journal", json={"path": _csv(tmp_path)}).json()
    assert d["totals"] == {"matched": 1, "mismatch": 0, "uncovered": 0,
                           "incomplete": 0, "missing": 0}
    m = d["matches"][0]
    assert m["action_id"] == "J1" and m["verdict"] == "matched"
    assert m["request"]["id"] == "req_set" and m["request"]["direction"] == "a2b"
    assert m["response"]["id"] == "resp_set" and m["response"]["direction"] == "b2a"
    # оба поля сошлись: status 0 -> "ok", value 2100*0.01 -> 21.0
    assert [(c["path"], c["equal"]) for c in m["checks"]] == [
        ("status", True), ("value", True)]
    # provenance: переход к исходным байтам
    assert m["provenance"]["request"]["start"] == m["request"]["start"]
    assert d["action_types"] == ["set-value"]
    assert "set-value" in d["compare"]


def test_journal_mismatch_detected(client, tmp_path):
    _load_schema(client)
    # журнал утверждает value=99.0, а запись даёт 21.00 -> расхождение
    bad = CSV.replace('"value"": 21.0', '"value"": 99.0')
    p = tmp_path / "bad.csv"
    p.write_text(bad, encoding="utf-8")
    d = client.post("/api/journal", json={"path": str(p)}).json()
    assert d["totals"]["mismatch"] == 1 and d["totals"]["matched"] == 0
    assert "value" in d["matches"][0]["note"]


def test_journal_no_actions_for_capture(client, tmp_path):
    _load_schema(client)
    p = tmp_path / "other.csv"
    p.write_text(CSV.replace("journal_api.pcapng", "unrelated.pcapng"),
                 encoding="utf-8")
    assert client.post("/api/journal", json={"path": str(p)}).status_code == 404


def test_journal_empty_path_rejected(client):
    _load_schema(client)
    assert client.post("/api/journal", json={"path": "   "}).status_code == 400
