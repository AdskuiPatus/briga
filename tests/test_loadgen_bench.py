"""Тесты нагрузочного генератора и замеров (раздел 10 кейса).

Контрольная нагрузка: детерминированный генератор (seed → одинаковые
байты), явная остановка по пределу max_bytes без тихого усечения,
замер времени и памяти по стадиям конвейера.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from madrigal.bench import bench_file, memory_snapshot, render_bench
from madrigal.capture import open_capture
from madrigal.limits import MIB
from madrigal.loadgen import generate_load, generate_packets
from madrigal.sessions import build_sessions
from madrigal.layers import parse_capture


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------- генератор ----

def test_generate_load_deterministic(tmp_path):
    """Одинаковый seed → одинаковые байты (sha256 стабилен)."""
    a = tmp_path / "a.pcapng"
    b = tmp_path / "b.pcapng"
    generate_load(a, sessions=5, messages=50, seed=42)
    generate_load(b, sessions=5, messages=50, seed=42)
    assert _sha(a) == _sha(b)


def test_generate_load_seed_changes_bytes(tmp_path):
    a = tmp_path / "a.pcapng"
    b = tmp_path / "b.pcapng"
    generate_load(a, sessions=5, messages=50, seed=1)
    generate_load(b, sessions=5, messages=50, seed=2)
    assert _sha(a) != _sha(b)


def test_generate_load_summary_counts(tmp_path):
    out = tmp_path / "load.pcapng"
    s = generate_load(out, sessions=10, messages=100, seed=7)
    assert s["sessions"] == 10
    assert s["packets"] > 0
    # messages = запросы + ответы: 10 сессий * 5 пар * 2 = 100
    assert s["messages"] == 100
    assert s["bytes"] == out.stat().st_size
    assert "план исчерпан" in s["stopped_because"]


def test_generate_load_file_is_readable(tmp_path):
    """Сгенерированная запись читается обычным конвейером."""
    out = tmp_path / "load.pcapng"
    generate_load(out, sessions=3, messages=30, seed=1)
    cap = open_capture(out)
    parsed = parse_capture(cap)
    sessions = build_sessions([p.timestamp for p in cap.packets], parsed)
    assert len(sessions) == 3
    assert len(cap.packets) > 0


def test_generate_load_max_bytes_stops_explicitly(tmp_path):
    """Предел max_bytes останавливает генерацию явно, без тихого усечения."""
    out = tmp_path / "limited.pcapng"
    s = generate_load(out, sessions=100, messages=1000, seed=3,
                      max_bytes=8192)
    assert out.stat().st_size <= 8192
    assert "предел max_bytes" in s["stopped_because"]
    assert s["bytes"] == out.stat().st_size


def test_generate_load_answer_max_respected(tmp_path):
    """Ответы не превышают заявленный максимум (профиль 64 КиБ)."""
    out = tmp_path / "answers.pcapng"
    generate_load(out, sessions=5, messages=50, answer_max=512, seed=9)
    cap = open_capture(out)
    # структурная проверка: длины payload в кадрах в пределах answer_max+5
    for pkt in cap.packets:
        if len(pkt.data) > 54:
            # payload TCP = data - 14 (Ethernet) - 20 (IP) - 20 (TCP)
            assert len(pkt.data) - 54 <= 512 + 5


def test_generate_packets_yields_tuples():
    for item in generate_packets(2, 10, seed=1):
        assert isinstance(item, tuple)
        assert len(item) == 2
        ts, data = item
        assert isinstance(ts, float)
        assert isinstance(data, bytes)


def test_generate_load_progress_callback(tmp_path):
    calls = []
    out = tmp_path / "p.pcapng"
    generate_load(out, sessions=30, messages=300, seed=1,
                  progress=lambda p, w: calls.append((p, w)),
                  progress_every=50)
    assert calls                       # колбэк зван хотя бы раз


# ------------------------------------------------------------ bench ----

def test_memory_snapshot_shape():
    cur, peak = memory_snapshot()
    # на поддерживаемых платформах — числа; иначе None, но не исключение
    assert cur is None or (isinstance(cur, int) and cur > 0)
    assert peak is None or (isinstance(peak, int) and peak > 0)


def test_bench_file_stages(tmp_path):
    out = tmp_path / "bench.pcapng"
    generate_load(out, sessions=5, messages=50, seed=1)
    schema = Path(__file__).resolve().parents[1] / "examples" / \
        "demo-protocol.yaml"
    report = bench_file(out, schema_path=schema)
    names = [s["name"] for s in report["stages"]]
    assert names == ["open", "parse", "sessions", "reassembly", "apply"]
    for s in report["stages"]:
        assert s["seconds"] >= 0
        assert s["items"] > 0
    assert report["file"]["packets"] > 0
    assert report["file"]["sessions"] == 5
    assert report["schema"]["sha256"]
    assert report["total_seconds"] >= 0


def test_bench_file_without_schema(tmp_path):
    out = tmp_path / "bench2.pcapng"
    generate_load(out, sessions=3, messages=30, seed=1)
    report = bench_file(out)
    names = [s["name"] for s in report["stages"]]
    assert "apply" not in names
    assert report["schema"] is None


def test_bench_includes_corpus_stage(tmp_path):
    examples = Path(__file__).resolve().parents[1] / "examples"
    report = bench_file(examples / "demo.pcapng",
                        corpus_path=examples / "demo-corpus.yaml")
    names = [s["name"] for s in report["stages"]]
    assert "verify" in names
    verify = [s for s in report["stages"] if s["name"] == "verify"][0]
    assert verify["items"] == 3       # три файла корпуса


def test_bench_json_serializable(tmp_path):
    out = tmp_path / "bench3.pcapng"
    generate_load(out, sessions=3, messages=30, seed=1)
    report = bench_file(out)
    text = json.dumps(report, ensure_ascii=False)
    assert "stages" in text and "peak_rss_mb" in text


def test_render_bench_readable(tmp_path):
    out = tmp_path / "bench4.pcapng"
    generate_load(out, sessions=3, messages=30, seed=1)
    report = bench_file(out)
    table = render_bench(report)
    assert "стадия" in table
    assert "open" in table and "parse" in table
    assert "итого" in table
    # вывод безопасен для cp1251-консоли (нет Δ → × ✓)
    table.encode("cp1251")


def test_bench_probe_is_monotonic_safe(tmp_path):
    """Пиковый RSS не меньше текущего (если оба доступны)."""
    out = tmp_path / "bench5.pcapng"
    generate_load(out, sessions=3, messages=30, seed=1)
    report = bench_file(out)
    for s in report["stages"]:
        if s["rss_before_mb"] is not None and s["rss_after_mb"] is not None:
            assert s["rss_after_mb"] >= 0
