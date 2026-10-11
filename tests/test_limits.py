"""Тесты защитных пределов контрольной нагрузки (раздел 10 кейса).

Профиль по умолчанию `control` (100 МиБ / 250 000 пакетов / 1000 сессий /
100 000 сообщений): превышение обрабатывается явно — CLI с кодом 6,
API с 413; данные не обрезаются и не подменяются. Профиль `none` снимает
пределы для исследовательских запусков. Для быстрых тестов профиль
подменяется на крошечный тем же способом, которым он читается из PROFILES.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from madrigal.__main__ import main
from madrigal.limits import (
    CONTROL,
    KIB,
    MIB,
    UNLIMITED,
    LimitExceeded,
    Limits,
    PROFILES,
    check_capture,
    check_messages,
    get_profile,
)
from madrigal.synth import tcp_packet, write_pcapng
from madrigal.webapp import app, state

C_IP, C_PORT = "192.168.1.10", 40000
S_IP, S_PORT = "10.0.0.2", 5000
DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo.pcapng"


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


# --- профили и проверки ---------------------------------------------------

def test_control_profile_matches_case():
    assert CONTROL.file_bytes == 100 * MIB
    assert CONTROL.packets == 250_000
    assert CONTROL.sessions == 1_000
    assert CONTROL.messages == 100_000
    assert CONTROL.answer_bytes == 64 * KIB


def test_get_profile_unknown():
    with pytest.raises(ValueError, match="неизвестный профиль"):
        get_profile("huge")


def test_none_profile_has_no_limits():
    assert check_capture(UNLIMITED, file_bytes=10 ** 12, packets=10 ** 9,
                         sessions=10 ** 6) == []
    assert check_messages(UNLIMITED, 10 ** 9) == []


def test_check_capture_reports_each_violation():
    lim = Limits(profile="t", file_bytes=100, packets=10, sessions=2)
    out = check_capture(lim, file_bytes=200, packets=20, sessions=3)
    assert len(out) == 3
    assert "размер файла" in out[0] and "превышает предел 100 Б" in out[0]
    assert "пакетов 20" in out[1]
    assert "соединений 3" in out[2]


def test_check_capture_omits_unset_facts():
    lim = Limits(profile="t", file_bytes=100)
    assert check_capture(lim) == []          # факты неизвестны — нет вывода
    assert check_capture(lim, file_bytes=50) == []


def test_check_messages():
    lim = Limits(profile="t", messages=5)
    assert check_messages(lim, 5) == []
    out = check_messages(lim, 6)
    assert len(out) == 1 and "сообщений 6" in out[0]


def test_violation_carries_profile_and_list():
    lim = Limits(profile="t", packets=1)
    e = LimitExceeded(lim, ["a", "b"])
    assert e.limits is lim
    assert e.violations == ["a", "b"]
    assert "a" in str(e) and "b" in str(e)


def test_describe_mentions_profile():
    assert "control" in CONTROL.describe()
    assert "сняты" in UNLIMITED.describe()


# --- CLI ------------------------------------------------------------------

def test_cli_control_load_fits_small_file():
    # демо-файл далеко от всех пределей — обычный профиль работает
    assert main(["info", str(DEMO), "--limits", "control"]) == 0


def test_cli_none_profile(tmp_path, monkeypatch):
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", file_bytes=10))
    # файл больше 10 Б — но профиль none снят, команда проходит
    assert main(["info", str(DEMO), "--limits", "none"]) == 0


def test_cli_info_refused_when_too_big(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", file_bytes=10))
    code = main(["info", str(DEMO), "--limits", "control"])
    assert code == 6
    err = capsys.readouterr().err
    assert "превышение защитных пределов" in err
    assert "превышает предел" in err
    assert "--limits none" in err          # подсказка исследователю


def test_cli_stream_refused_when_too_many_sessions(tmp_path, monkeypatch):
    path = tmp_path / "two.pcapng"
    write_pcapng(path, _frames())
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", sessions=0))
    assert main(["stream", str(path), "0", "a2b", "--limits", "control"]) == 6


def test_cli_apply_refused_when_messages_exceed(tmp_path, monkeypatch, capsys):
    path = tmp_path / "msgs.pcapng"
    write_pcapng(path, _frames())
    schema = Path(__file__).resolve().parents[1] / "examples" / \
        "demo-protocol.yaml"
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", messages=0))
    code = main(["apply", str(path), "--schema", str(schema),
                 "--out", str(tmp_path / "r.json"), "--limits", "control"])
    assert code == 6
    assert "прикладных сообщений" in capsys.readouterr().err
    # отказ явный: файла результата нет, данные не подменены
    assert not (tmp_path / "r.json").exists()


def test_cli_apply_refused_after_compute_has_no_partial_output(
        tmp_path, monkeypatch):
    """Даже посчитанный результат не пишется молча: предел срабатывает
    до выгрузки, JSON не появляется (без скрытого обрезания)."""
    path = tmp_path / "msgs2.pcapng"
    write_pcapng(path, _frames())
    schema = Path(__file__).resolve().parents[1] / "examples" / \
        "demo-protocol.yaml"
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", messages=1))
    code = main(["apply", str(path), "--schema", str(schema),
                 "--out", str(tmp_path / "out.json"), "--limits", "control"])
    assert code == 6
    assert not (tmp_path / "out.json").exists()


def test_cli_verify_refused_when_file_too_big(tmp_path, monkeypatch):
    examples = Path(__file__).resolve().parents[1] / "examples"
    import shutil
    shutil.copy(examples / "demo-protocol.yaml", tmp_path / "schema.yaml")
    shutil.copy(examples / "demo.pcapng", tmp_path / "d.pcapng")
    corpus = tmp_path / "c.yaml"
    corpus.write_text(
        "version: 1\nname: t\nschema: schema.yaml\n"
        "files:\n  - path: d.pcapng\n    expect:\n"
        "      sessions: 1\n",
        encoding="utf-8")
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", file_bytes=10))
    code = main(["verify", str(corpus), "--limits", "control"])
    assert code == 6


# --- API ------------------------------------------------------------------

@pytest.fixture()
def fresh_client(tmp_path):
    path = tmp_path / "api.pcapng"
    write_pcapng(path, _frames())
    state.loaded = None
    with TestClient(app) as c:
        c.post("/api/open", json={"path": str(path)})
        yield c, path
    state.loaded = None


def test_api_open_default_profile_fits(fresh_client):
    c, path = fresh_client
    r = c.post("/api/open", json={"path": str(path)})
    assert r.status_code == 200
    assert r.json()["limits"] == "control"


def test_api_open_none_profile(fresh_client):
    c, path = fresh_client
    r = c.post("/api/open", json={"path": str(path), "limits": "none"})
    assert r.status_code == 200
    assert r.json()["limits"] == "none"


def test_api_open_unknown_profile_is_400(fresh_client):
    c, path = fresh_client
    r = c.post("/api/open", json={"path": str(path), "limits": "huge"})
    assert r.status_code == 400
    assert "профиль" in r.json()["detail"]


def test_api_open_413_lists_violations(fresh_client, monkeypatch):
    c, path = fresh_client
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", packets=1))
    r = c.post("/api/open", json={"path": str(path)})
    assert r.status_code == 413
    detail = r.json()["detail"]
    assert "превышение защитных пределов" in detail
    assert "пакетов" in detail and "превышает предел 1" in detail
    assert "none" in detail               # как снять предел исследователю
    # отказ не затирает уже открытую запись: доступные данные остаются
    assert c.get("/api/state").json()["loaded"] is True


def test_api_verify_413(fresh_client, tmp_path, monkeypatch):
    c, _ = fresh_client
    corpus = tmp_path / "api-corpus.yaml"
    corpus.write_text(
        "version: 1\nname: t\nschema: schema.yaml\nfiles:\n"
        "  - path: demo.pcapng\n    expect:\n      sessions: 1\n",
        encoding="utf-8")
    (tmp_path / "schema.yaml").write_text(
        (Path(__file__).resolve().parents[1] / "examples" /
         "demo-protocol.yaml").read_text(encoding="utf-8"),
        encoding="utf-8")
    write_pcapng(tmp_path / "demo.pcapng", _frames())
    monkeypatch.setitem(PROFILES, "control",
                        Limits(profile="control", sessions=0))
    r = c.post("/api/verify", json={"path": str(corpus)})
    assert r.status_code == 413
    assert "соединений" in r.json()["detail"]


def test_api_verify_default_fits(fresh_client):
    c, _ = fresh_client
    examples = Path(__file__).resolve().parents[1] / "examples"
    r = c.post("/api/verify", json={
        "path": str(examples / "demo-corpus.yaml")})
    assert r.status_code == 200, r.text
    assert r.json()["schema"]["name"]
