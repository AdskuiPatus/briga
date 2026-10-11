"""Тесты прогресса и отмены длительных операций (раздел 10 кейса).

Длительные операции показывают ход и допускают отмену; уже доступные
данные остаются доступны (открытая запись не затирается), неполный
результат не выдаётся за полный. Проверяется ядро (Progress), задачи
API (jobs) и код выхода CLI 130 при отмене.
"""

from __future__ import annotations

import io
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from madrigal.__main__ import main
from madrigal.corpus import verify_corpus
from madrigal.jobs import JobStore
from madrigal.progress import CancelledError, Progress, StderrProgress
from madrigal.synth import tcp_packet, write_pcapng
from madrigal.webapp import app, state

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
C_IP, C_PORT = "192.168.1.10", 40000
S_IP, S_PORT = "10.0.0.2", 5000


# ------------------------------------------------------------- ядро ----

def test_progress_stage_and_advance():
    p = Progress()
    p.start_stage("файлов", 3)
    p.advance()
    p.advance(note="файл 3")
    snap = p.snapshot()
    assert snap["current"] == 2
    assert snap["total"] == 3
    assert snap["label"] == "файл 3"
    assert snap["cancelled"] is False


def test_progress_cancel_raises_on_check():
    p = Progress()
    p.start_stage("x", 1)
    p.cancel()
    assert p.cancelled is True
    with pytest.raises(CancelledError):
        p.check_cancel()
    with pytest.raises(CancelledError):
        p.advance()          # отмена ловится и на следующей единице


def test_progress_update_callback_fires():
    seen = []
    p = Progress(update_callback=lambda: seen.append(1))
    p.start_stage("x", 2)
    p.advance()
    assert len(seen) >= 2


def test_progress_note_keeps_counters():
    p = Progress()
    p.start_stage("сессий", 5)
    p.advance(note="сессия 2")
    snap = p.snapshot()
    assert snap["current"] == 1 and snap["total"] == 5
    assert snap["label"] == "сессия 2"


def test_progress_cancel_from_other_thread():
    """Отмена ставится из другого потока (HTTP-запрос) и видна сразу."""
    p = Progress()
    p.start_stage("x", 10)
    t = threading.Thread(target=p.cancel)
    t.start()
    t.join()
    with pytest.raises(CancelledError):
        p.check_cancel()


def test_stderr_progress_writes_to_stream():
    buf = io.StringIO()
    p = StderrProgress(stream=buf)
    p.start_stage("файлов", 2)
    p.advance(note="файл 1")
    p.advance(note="файл 2")
    out = buf.getvalue()
    assert "файлов: 0/2" in out
    assert "файл 1: 1/2" in out
    assert "файл 2: 2/2" in out


def test_stderr_progress_quiet_is_silent():
    buf = io.StringIO()
    p = StderrProgress(stream=buf, quiet=True)
    p.start_stage("x", 1)
    p.advance()
    assert buf.getvalue() == ""


def test_stderr_progress_throttles_large_stages():
    buf = io.StringIO()
    p = StderrProgress(stream=buf)
    p.start_stage("сессий", 100000)
    for _ in range(100000):
        p.advance()
    # на большом этапе печатается не каждая единица
    assert buf.getvalue().count("\n") < 60


# --------------------------------------------------- verify_corpus ----

def test_verify_corpus_reports_progress(tmp_path):
    examples = EXAMPLES
    import shutil
    for name in ("demo.pcapng", "demo_defect.pcapng", "demo-protocol.yaml"):
        shutil.copy(examples / name, tmp_path / name)
    (tmp_path / "c.yaml").write_text(
        "version: 1\nname: t\nschema: demo-protocol.yaml\nfiles:\n"
        "  - path: demo.pcapng\n    expect: {sessions: 1}\n"
        "  - path: demo_defect.pcapng\n    expect: {sessions: 1}\n",
        encoding="utf-8")
    seen = []
    p = Progress(update_callback=lambda: seen.append(p.snapshot()))
    report = verify_corpus(tmp_path / "c.yaml", progress=p)
    assert report["totals"]["files"] == 2
    labels = [s["label"] for s in seen]
    assert any("файл 1/2" in lb for lb in labels)
    assert any("файл 2/2" in lb for lb in labels)


def test_verify_corpus_cancel_between_files(tmp_path):
    """Отмена между файлами: CancelledError, отчёт не построен."""
    import shutil
    for name in ("demo.pcapng", "demo_defect.pcapng", "demo-protocol.yaml"):
        shutil.copy(EXAMPLES / name, tmp_path / name)
    (tmp_path / "c.yaml").write_text(
        "version: 1\nname: t\nschema: demo-protocol.yaml\nfiles:\n"
        "  - path: demo.pcapng\n    expect: {sessions: 1}\n"
        "  - path: demo_defect.pcapng\n    expect: {sessions: 1}\n",
        encoding="utf-8")
    p = Progress()

    # отменяем во время первого файла: ловится на старте второго
    first = {"done": False}

    def on_update():
        if not first["done"] and "1/2" in p.snapshot()["label"]:
            first["done"] = True
            p.cancel()

    p._update = on_update
    with pytest.raises(CancelledError):
        verify_corpus(tmp_path / "c.yaml", progress=p)


# ------------------------------------------------------------- jobs ----

def test_jobstore_runs_to_done():
    store = JobStore()
    job = store.submit("t", "тест", lambda prog: {"x": 1})
    deadline = time.time() + 5
    while job.status not in ("done",) and time.time() < deadline:
        time.sleep(0.01)
    assert job.status == "done"
    assert job.result == {"x": 1}
    snap = job.snapshot()
    assert snap["finished_at"] is not None
    assert snap["progress"]["cancelled"] is False


def test_jobstore_cancel_mid_run():
    store = JobStore()

    def slow(prog):
        prog.start_stage("итераций", 1000)
        out = []
        for i in range(1000):
            prog.check_cancel()
            prog.advance()
            time.sleep(0.005)
            out.append(i)
        return {"count": len(out)}

    job = store.submit("t", "долгая", slow)
    time.sleep(0.05)
    job.cancel()
    deadline = time.time() + 5
    while job.status != "cancelled" and time.time() < deadline:
        time.sleep(0.01)
    assert job.status == "cancelled"
    # неполный результат не выдаётся за полный
    assert job.result is None
    # но ход до отмены доступен
    assert job.snapshot()["progress"]["cancelled"] is True


def test_jobstore_failed_carries_error():
    store = JobStore()

    def boom(prog):
        raise ValueError("намеренный сбой")

    job = store.submit("t", "сбойная", boom)
    deadline = time.time() + 5
    while job.status != "failed" and time.time() < deadline:
        time.sleep(0.01)
    assert job.status == "failed"
    assert "намеренный сбой" in job.error


def test_jobstore_list_sorted():
    store = JobStore()
    store.submit("t", "a", lambda p: {})
    jobs = store.list()
    assert len(jobs) == 1
    assert store.get(jobs[0].id) is jobs[0]


# ------------------------------------------------------------- API ----

@pytest.fixture()
def client(tmp_path):
    path = tmp_path / "jobs.pcapng"
    write_pcapng(path, _frames())
    state.loaded = None
    with TestClient(app) as c:
        r = c.post("/api/open", json={"path": str(path)})
        assert r.status_code == 200, r.text
        yield c, path
    state.loaded = None


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


def _poll(c, job_id, want=("done", "failed", "cancelled"), timeout=10.0):
    deadline = time.time() + timeout
    d = None
    while time.time() < deadline:
        d = c.get(f"/api/jobs/{job_id}").json()
        if d["status"] in want:
            return d
        time.sleep(0.02)
    raise AssertionError(f"задача не завершилась: {d}")


def test_api_job_verify_completes(client):
    c, _ = client
    examples = EXAMPLES
    r = c.post("/api/jobs", json={
        "op": "verify", "path": str(examples / "demo-corpus.yaml")})
    assert r.status_code == 200, r.text
    job = r.json()
    assert job["status"] in ("queued", "running")
    assert "result" not in job            # результат только по завершении
    d = _poll(c, job["id"])
    assert d["status"] == "done"
    assert d["result"]["totals"]["files"] == 3
    assert d["finished_at"] is not None


def test_api_job_apply_all_completes(client):
    c, _ = client
    schema = (EXAMPLES / "demo-protocol.yaml").read_text(encoding="utf-8")
    r = c.post("/api/schema", json={"text": schema})
    assert r.json()["present"] is True
    r = c.post("/api/jobs", json={"op": "apply", "scope": "all"})
    assert r.status_code == 200, r.text
    d = _poll(c, r.json()["id"])
    assert d["status"] == "done"
    assert d["result"]["scope"] == "all"
    assert len(d["result"]["sessions"]) == 1


def test_api_job_cancel_verify(client):
    """Отмена проверки корпуса: статус cancelled, отчёт не выдан."""
    c, _ = client
    r = c.post("/api/jobs", json={
        "op": "verify", "path": str(EXAMPLES / "demo-corpus.yaml")})
    job_id = r.json()["id"]
    c.post(f"/api/jobs/{job_id}/cancel")
    d = _poll(c, job_id, want=("done", "failed", "cancelled"))
    # быстрый корпус мог успеть завершиться до отмены — это допустимо;
    # главное: cancelled не выдаёт частичный отчёт
    if d["status"] == "cancelled":
        assert d["result"] is None


def test_api_job_unknown_op(client):
    c, _ = client
    r = c.post("/api/jobs", json={"op": "bogus"})
    assert r.status_code == 400
    assert "verify или apply" in r.json()["detail"]


def test_api_job_missing_404(client):
    c, _ = client
    assert c.get("/api/jobs/nonexistent").status_code == 404
    assert c.post("/api/jobs/nonexistent/cancel").status_code == 404


def test_api_job_verify_missing_corpus(client):
    """Ошибка корпуса — результат задачи, не сбой сервера."""
    c, _ = client
    r = c.post("/api/jobs", json={"op": "verify", "path": "/nope/x.yaml"})
    d = _poll(c, r.json()["id"], want=("done", "failed"))
    assert d["status"] == "done"
    assert "корпус_error" in d["result"] or "corpus_error" in d["result"]


def test_api_jobs_list(client):
    c, _ = client
    c.post("/api/jobs", json={"op": "verify",
                              "path": str(EXAMPLES / "demo-corpus.yaml")})
    r = c.get("/api/jobs")
    assert r.status_code == 200
    assert len(r.json()["jobs"]) >= 1


def test_api_job_limits_400(client):
    c, _ = client
    r = c.post("/api/jobs", json={
        "op": "verify", "path": str(EXAMPLES / "demo-corpus.yaml"),
        "limits": "bogus"})
    assert r.status_code == 400


# ------------------------------------------------------------- CLI ----

def test_cli_verify_prints_progress_to_stderr(tmp_path, capsys):
    code = main(["verify", str(EXAMPLES / "demo-corpus.yaml")])
    assert code in (0, 4)
    err = capsys.readouterr().err
    assert "файл 1/3" in err or "файл" in err


def test_cli_verify_quiet_no_progress(tmp_path, capsys):
    code = main(["verify", str(EXAMPLES / "demo-corpus.yaml"), "--quiet"])
    assert code in (0, 4)
    err = capsys.readouterr().err
    assert "файл 1/3" not in err


def test_cli_apply_progress_stderr(capsys):
    code = main(["apply", str(EXAMPLES / "demo.pcapng"),
                 "--schema", str(EXAMPLES / "demo-protocol.yaml")])
    assert code in (0, 3)
    err = capsys.readouterr().err
    assert "сессий 1" in err


def test_cli_cancel_returns_130(monkeypatch, capsys):
    """Отмена (CancelledError из прогресса) — код 130 и явное сообщение."""
    from madrigal import __main__ as m

    original = m.verify_corpus

    def cancelling_verify(path, **kw):
        kw["progress"].cancel()          # отмена до первой единицы работы
        return original(path, **kw)

    monkeypatch.setattr(m, "verify_corpus", cancelling_verify)
    code = main(["verify", str(EXAMPLES / "demo-corpus.yaml"), "--quiet"])
    assert code == 130
    assert "отменена" in capsys.readouterr().err
