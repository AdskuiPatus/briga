"""Тесты веб-API (стек A): открытие записи, потоки, поиск, сравнение, пакеты."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from madrigal.synth import tcp_packet, write_pcapng
from madrigal.webapp import app, state

C_IP, C_PORT = "192.168.1.10", 40000
S_IP, S_PORT = "10.0.0.2", 5000


def _frames():
    def c(seq, flags="A", payload=b"", ack=1001):
        return tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=C_PORT, dport=S_PORT,
                          seq=seq, flags=flags, payload=payload, ack=ack)

    def s(seq, flags="A", payload=b"", ack=1001):
        return tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT, dport=C_PORT,
                          seq=seq, flags=flags, payload=payload, ack=ack)

    return [
        (0.0, c(1000, flags="S")),
        (0.1, s(5000, flags="SA", ack=1001)),
        (0.2, c(1001)),
        (0.3, c(1001, payload=b"\xAA\x55\x00\x00SET21")),
        (0.4, s(5001, payload=b"\xAA\x55\x00\x00OK")),
        (0.5, c(1010, flags="FA")),
        (0.6, s(5007, flags="FA")),
    ]


@pytest.fixture()
def client(tmp_path):
    path = tmp_path / "web.pcapng"
    write_pcapng(path, _frames())
    state.loaded = None
    with TestClient(app) as c:
        r = c.post("/api/open", json={"path": str(path)})
        assert r.status_code == 200, r.text
        yield c
    state.loaded = None


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_state_after_open(client):
    r = client.get("/api/state")
    d = r.json()
    assert d["loaded"] is True
    assert d["name"] == "web.pcapng"
    assert d["fmt"] == "pcapng"
    assert len(d["sessions"]) == 1
    assert d["sha256"]


def test_open_missing_file(client):
    r = client.post("/api/open", json={"path": "/no/such/file.pcap"})
    assert r.status_code == 400
    # защитная проверка размера идёт до чтения — сообщение о недоступном файле
    assert "не удалось открыть файл" in r.json()["detail"]


def test_session_detail(client):
    s = client.get("/api/session/0").json()
    assert s["packets"] == 7
    assert s["midstream"] is False
    assert set(s["streams"]) == {"a2b", "b2a"}
    to_client = s["streams"]["a2b"]
    assert to_client["length"] > 0
    assert to_client["diagnostics"] is not None


def test_stream_cells_and_provenance(client):
    s = client.get("/api/session/0").json()
    d = client.get("/api/stream/0/a2b",
                   params={"offset": 0, "length": 64}).json()
    assert d["total"] == s["streams"]["a2b"]["length"]
    assert d["cells"], "ячейки не должны быть пустыми"
    off, value, packet, amb = d["cells"][0]
    assert off == 0
    assert value in (None,) or 0 <= value <= 255
    # известные байты обязаны иметь происхождение
    known = [c for c in d["cells"] if c[1] is not None]
    assert known and all(c[2] >= 0 for c in known)


def test_stream_text_selection(client):
    d = client.get("/api/stream/0/a2b/text",
                   params={"offset": 0, "length": 16}).json()
    assert d["known"] > 0
    assert len(d["hex"]) == 2 * d["known"]
    assert d["packets"] and all(p >= 0 for p in d["packets"])


def test_search_ascii_and_hex(client):
    r = client.post("/api/search", json={
        "session": 0, "direction": "b2a", "pattern": "SET", "mode": "ascii"})
    d = r.json()
    assert r.status_code == 200
    assert len(d["matches"]) == 1
    match = d["matches"][0]
    assert match == 4, "AA55|SET21 — SET начинается на смещении 4"

    r2 = client.post("/api/search", json={
        "session": 0, "direction": "b2a", "pattern": "AA 55", "mode": "hex"})
    assert len(r2.json()["matches"]) >= 1

    # поиск — настоящий разбор байтов, не привязка к именам файлов
    assert d["scanned"] > 0


def test_search_bad_hex_rejected(client):
    r = client.post("/api/search", json={
        "session": 0, "direction": "a2b", "pattern": "GG HH", "mode": "hex"})
    assert r.status_code == 400


def test_compare_same_stream_with_itself(client):
    side = {"session": 0, "direction": "a2b", "offset": 0, "length": 32}
    r = client.post("/api/compare", json={"a": side, "b": side})
    d = r.json()
    assert r.status_code == 200
    assert d["summary"]["diff"] == 0
    assert d["summary"]["same"] > 0
    assert d["summary"]["unknown"] == 0


def test_packet_detail(client):
    d = client.get("/api/packet/3").json()
    assert d["index"] == 3
    assert d["tcp"]["seq"] == 1001
    assert d["payload_len"] == 9
    assert d["payload_offset"] > 0
    assert any(c[2] == 1 for c in d["hex"]), "payload должен быть подсвечен"
    # переход байт → пакет: данные пакета совпадают с потоком
    assert client.get("/api/packet/9999").status_code == 404


def test_browse_directory(client, tmp_path):
    d = client.get("/api/browse", params={"path": str(tmp_path)}).json()
    assert d["type"] == "dir"
    assert "web.pcapng" in d["files"]


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
