"""Применение схем к потокам: фрейминг, сопоставление, гипотезы (R3, R4)."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest

from madrigal.capture import open_capture
from madrigal.interpreter import (
    analyze_session,
    apply_to_stream,
    check_hypotheses,
    dir_result_to_dict,
    hyp_check_to_dict,
    message_to_dict,
)
from madrigal.layers import parse_capture
from madrigal.reassembly import DataRun, GapRun, Stream, build_stream
from madrigal.schema import load_schema_file, load_schema_text
from madrigal.sessions import build_sessions
from madrigal.synth import tcp_packet, write_pcapng

ROOT = Path(__file__).resolve().parents[1]
DEMO_SCHEMA = ROOT / "examples" / "demo-protocol.yaml"

C_IP, C_PORT = "192.168.1.10", 40000
S_IP, S_PORT = "10.0.0.2", 5000

# минимальная схема для юнит-тестов (запрос/ответ с подтверждением)
UNIT_SCHEMA = """
version: 1
name: unit
framing:
  magic: "AA 55"
  header: 5
  length: {offset: 3, type: u16le, includes: payload}
  min: 5
  max: 65536
messages:
  - id: set_value
    direction: b2a
    when: [{offset: 2, type: u8, eq: 2}]
    fields:
      - {name: value, offset: 5, type: u16le}
  - id: set_ack
    direction: a2b
    when: [{offset: 3, type: u16le, eq: 2}]
    fields:
      - {name: value, offset: 5, type: u16le}
hypotheses:
  - id: h-echo
    statement: "ответ подтверждает установленное значение"
    basis: ["наблюдение в записи"]
    status: proposed
    check:
      pairs:
        a: {message: set_value, field: value}
        b: {message: set_ack, field: value}
      expect: equal
"""


# ------------------------------------------------------------ построение ----

def req(cmd: int, payload: bytes = b"") -> bytes:
    return b"\xAA\x55" + bytes([cmd]) + struct.pack("<H", len(payload)) + payload


def resp(payload: bytes, status: int = 0) -> bytes:
    return b"\xAA\x55" + bytes([status]) + struct.pack("<H", len(payload)) + payload


def mk_stream(spec, direction: str) -> Stream:
    """Поток из кусков: bytes — данные, ('gap', длина) — пропуск."""
    runs = []
    pos = 0
    for item in spec:
        if isinstance(item, tuple):
            runs.append(GapRun(start=pos, length=item[1]))
            pos += item[1]
        else:
            runs.append(DataRun(start=pos, data=bytes(item), packet=0))
            pos += len(item)
    return Stream(session_id=0, direction=direction, runs=runs)


def demo_frames(kind: str):
    path = ROOT / "examples" / "make_demo.py"
    spec = importlib.util.spec_from_file_location("make_demo_ut", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_demo() if kind == "demo" else mod.build_defects()


def _load(tmp_path, frames):
    path = tmp_path / "t.pcapng"
    write_pcapng(path, frames)
    cap = open_capture(path)
    parsed = parse_capture(cap)
    ts = [p.timestamp for p in cap.packets]
    sessions = build_sessions(ts, parsed)
    return ts, parsed, sessions


def _stream(ts, parsed, session, endpoint_ip, endpoint_port):
    direction = session.direction_of((endpoint_ip, endpoint_port))
    return build_stream(ts, parsed, session, direction)


# ------------------------------------------------- сквозной тест (демо) ----

@pytest.fixture(scope="module")
def demo_data(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("demo")
    ts, parsed, sessions = _load(tmp, demo_frames("demo"))
    assert len(sessions) == 1
    sess = sessions[0]
    return {
        "a2b": _stream(ts, parsed, sess, S_IP, S_PORT),   # устройство → клиент
        "b2a": _stream(ts, parsed, sess, C_IP, C_PORT),   # клиент → устройство
    }


def test_demo_stream_lengths_sanity(demo_data):
    assert demo_data["b2a"].length == 31      # 5+7+7+6+6, ретрансмиссия снята
    assert demo_data["a2b"].length == 4097


def test_demo_all_messages_recognized(demo_data):
    schema = load_schema_file(DEMO_SCHEMA)
    results, hyps = analyze_session(schema, demo_data)

    rb = results["b2a"]
    assert rb.framing_errors == [] and rb.unframed == []
    assert [m.id for m in rb.messages] == [
        "read_params", "set_value", "set_value",
        "get_measurement", "get_measurement"]
    set_values = [m for m in rb.messages if m.id == "set_value"]
    assert [m.field("value").value for m in set_values] == [21, 37]
    assert all(m.known_bytes == m.size for m in rb.messages)

    ra = results["a2b"]
    assert ra.framing_errors == [] and ra.unframed == []
    assert [m.id for m in ra.messages] == [
        "params_response", "set_ack", "set_ack",
        "measurement_response", "measurement_response"]
    assert ra.messages[0].field("params").value == bytes.fromhex("10203040")
    acks = [m for m in ra.messages if m.id == "set_ack"]
    assert [m.field("value").value for m in acks] == [21, 37]
    meas = [m for m in ra.messages if m.id == "measurement_response"]
    assert [len(m.field("payload").value) for m in meas] == [64, 4000]
    assert all(m.field("status").value == 0 for m in ra.messages)


def test_demo_message_coverage_partial_ruled_out(demo_data):
    schema = load_schema_file(DEMO_SCHEMA)
    results, _ = analyze_session(schema, demo_data)
    for r in results.values():
        for m in r.messages:
            # изученные байты отделены от неописанных, но покрытие ненулевое
            assert 0 < m.described_bytes <= m.size
            assert m.described_known == m.described_bytes
            assert not m.partial and m.gap_ranges == []


def test_demo_hypotheses_checked_and_not_checked(demo_data):
    schema = load_schema_file(DEMO_SCHEMA)
    _, hyps = analyze_session(schema, demo_data)
    by_id = {h.id: h for h in hyps}

    echo = by_id["h-echo"]
    assert echo.result == "pass" and echo.status_after == "checked"
    assert echo.pairs_total == 2 and echo.pairs_ok == 2
    assert echo.counterexamples == [] and echo.unpaired_a == []

    status = by_id["h-status-zero"]
    assert status.result == "not_checked"      # нет механической проверки
    assert status.status_after == "proposed"
    assert "предположением" in status.note


# --------------------------------------------- дефектная запись (честность) ----

@pytest.fixture(scope="module")
def defect_data(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("defect")
    ts, parsed, sessions = _load(tmp, demo_frames("defect"))
    sess = sessions[0]
    return {
        "a2b": _stream(ts, parsed, sess, S_IP, S_PORT),
        "b2a": _stream(ts, parsed, sess, C_IP, C_PORT),
    }


def test_defect_unrecognized_messages_stay_unknown(defect_data):
    schema = load_schema_file(DEMO_SCHEMA)
    results, _ = analyze_session(schema, defect_data)
    ra = results["a2b"]
    # ответы 32 и 100 Б не подошли ни под одно правило — id=None, а не догадка
    assert [m.id for m in ra.messages] == [None, None]
    assert ra.stats["unmatched"] == 2


def test_defect_gap_makes_message_partial(defect_data):
    schema = load_schema_file(DEMO_SCHEMA)
    results, hyps = analyze_session(schema, defect_data)
    ra = results["a2b"]
    m = ra.messages[1]
    assert m.partial and (77, 40) in m.gap_ranges
    assert m.known_bytes == 65 and m.size == 105
    assert ra.framing_errors == []            # обрыва нет: конец потока совпал

    rb = results["b2a"]
    assert defect_data["b2a"].midstream        # начало без рукопожатия видно
    assert [m.id for m in rb.messages] == ["set_value"]
    assert rb.messages[0].field("value").value == 55


def test_defect_overlap_policy_keeps_first_seen(defect_data):
    # артефакт: сегмент с тем же seq, но байтами FF — политика first-seen
    assert defect_data["a2b"].ambiguities
    schema = load_schema_file(DEMO_SCHEMA)
    results, hyps = analyze_session(schema, defect_data)
    by_id = {h.id: h for h in hyps}
    # проверка h-echo не применима (нет set_ack), а НЕ «подтверждено»
    assert by_id["h-echo"].result == "not_applicable"
    assert by_id["h-echo"].status_after == "proposed"


# --------------------------------------------------------- юнит-тесты ----

@pytest.fixture(scope="module")
def unit_schema():
    return load_schema_text(UNIT_SCHEMA)


def test_resync_after_garbage(unit_schema):
    stream = mk_stream([b"XYZ", req(2, struct.pack("<H", 1)), b"AB",
                        req(2, struct.pack("<H", 2))], "b2a")
    r = apply_to_stream(stream, unit_schema, "b2a")
    assert [m.id for m in r.messages] == ["set_value", "set_value"]
    assert [m.field("value").value for m in r.messages] == [1, 2]
    assert r.unframed == [(0, 3), (10, 2)]
    assert r.framing_errors == []


def test_length_out_of_range_recorded_and_resynced(unit_schema):
    bad = b"\xAA\x55\x01\xFF\xFF\x00\x00"   # длина 65535 → 65540 > max
    stream = mk_stream([bad, req(2, struct.pack("<H", 3))], "b2a")
    r = apply_to_stream(stream, unit_schema, "b2a")
    assert len(r.framing_errors) == 1
    assert "вне диапазона" in r.framing_errors[0]["reason"]
    assert [m.field("value").value for m in r.messages] == [3]
    assert r.unframed == [(0, 7)]


def test_truncated_tail_is_explicit(unit_schema):
    stream = mk_stream([req(2, struct.pack("<H", 9))[:6]], "b2a")
    r = apply_to_stream(stream, unit_schema, "b2a")
    assert len(r.messages) == 1
    m = r.messages[0]
    assert m.partial and m.note == "обрезано концом потока"
    assert m.size == 6 and m.known_bytes == 6
    # поле value не влезло целиком — оно известным не объявляется
    assert not m.field("value").known and m.field("value").value is None
    assert "обрезано" in r.framing_errors[0]["reason"]


def test_gap_in_header_stops_framing(unit_schema):
    stream = mk_stream([b"\xAA\x55\x02", ("gap", 4), b"\x00\x02\x00\x09\x00"],
                       "b2a")
    r = apply_to_stream(stream, unit_schema, "b2a")
    assert r.messages == []
    assert "заголовок недоступен" in r.framing_errors[0]["reason"]


def test_gap_after_header_partial_message(unit_schema):
    stream = mk_stream([b"\xAA\x55\x02\x02\x00\x09", ("gap", 1), b"\x00"],
                       "b2a")
    r = apply_to_stream(stream, unit_schema, "b2a")
    m = r.messages[0]
    assert m.partial and m.gap_ranges == [(6, 1)]
    assert not m.field("value").known       # байт значения частично потерян
    # хвост после сообщения не подменяется, а помечается
    assert r.unframed == [(7, 1)]


def test_unknown_condition_flags_match_unknown():
    schema = load_schema_text("""
version: 1
name: t
framing: {magic: "AA 55", header: 5,
          length: {offset: 3, type: u16le, includes: payload}}
messages:
  - id: x
    direction: b2a
    when: [{offset: 6, type: u8, eq: 1}]
    fields: [{name: n, offset: 7, type: u8}]
""")
    stream = mk_stream([b"\xAA\x55\x02\x04\x00\x07", ("gap", 1),
                        b"\x07\x08\x09"], "b2a")
    r = apply_to_stream(stream, schema, "b2a")
    m = r.messages[0]
    assert m.id is None and m.match_unknown   # условие не проверяемо из-за пропуска
    assert r.stats["match_unknown"] == 1


def test_length_from_unknown_field_yields_unknown_field():
    schema = load_schema_text("""
version: 1
name: t
framing: {magic: "AA 55", header: 5,
          length: {offset: 3, type: u16le, includes: payload}}
messages:
  - id: g
    direction: b2a
    when: [{offset: 2, type: u8, eq: 1}]
    fields:
      - {name: x, offset: 5, type: u16le}
      - {name: payload, offset: 7, type: bytes, length: {from_field: x}}
""")
    stream = mk_stream([b"\xAA\x55\x01\x10\x00\x01", ("gap", 2),
                        bytes(13)], "b2a")
    r = apply_to_stream(stream, schema, "b2a")
    f = r.messages[0].fields
    assert not f["x"].known and f["x"].value is None
    assert not f["payload"].known and f["payload"].size is None


def test_fixed_length_framing_without_magic():
    schema = load_schema_text("""
version: 1
name: t
framing: {header: 0, length: {fixed: 4}}
messages:
  - id: quad
    direction: any
    when: [{offset: 0, bytes: "AA BB"}]
    fields:
      - {name: tag, offset: 0, type: bytes, length: 2}
      - {name: n, offset: 2, type: u8}
""")
    stream = mk_stream([b"\xAA\xBB\x01\x02\xAA\xBB\x03\x04"], "b2a")
    r = apply_to_stream(stream, schema, "b2a")
    assert [m.id for m in r.messages] == ["quad", "quad"]
    assert [m.field("n").value for m in r.messages] == [1, 3]
    assert r.messages[0].field("tag").value == b"\xAA\xBB"
    # направление 'any' работает и на другом направлении
    r2 = apply_to_stream(stream, schema, "a2b")
    assert [m.id for m in r2.messages] == ["quad", "quad"]


def test_scope_outside_directions_refused(unit_schema):
    scoped = load_schema_text("""
version: 1
name: t
scope: {directions: [b2a]}
framing: {magic: "AA 55", header: 5,
          length: {offset: 3, type: u16le, includes: payload}}
messages:
  - id: any_msg
    direction: b2a
    fields: [{name: cmd, offset: 2, type: u8}]
""")
    stream = mk_stream([req(2, b"\x01\x00")], "a2b")
    r = apply_to_stream(stream, scoped, "a2b")
    assert not r.scope_ok and "вне области" in r.note
    assert r.messages == []


def test_empty_stream(unit_schema):
    r = apply_to_stream(mk_stream([], "b2a"), unit_schema, "b2a")
    assert r.messages == [] and r.stats["messages"] == 0


# --------------------------------------------------------- гипотезы ----

def _pair_streams(value_a, value_b, ack_payload=None):
    b2a = mk_stream([req(2, struct.pack("<H", value_a))], "b2a")
    payload = (struct.pack("<H", value_b) if ack_payload is None else ack_payload)
    a2b = mk_stream([resp(payload)], "a2b")
    return {"b2a": b2a, "a2b": a2b}


def test_hypothesis_pass(unit_schema):
    streams = {"b2a": mk_stream([req(2, struct.pack("<H", 21)),
                                 req(2, struct.pack("<H", 37))], "b2a"),
               "a2b": mk_stream([resp(struct.pack("<H", 21)),
                                 resp(struct.pack("<H", 37))], "a2b")}
    _, hyps = analyze_session(unit_schema, streams)
    h = hyps[0]
    assert h.result == "pass" and h.status_after == "checked"
    assert (h.pairs_total, h.pairs_ok) == (2, 2)
    assert "2 парах" in h.note


def test_hypothesis_refuted_with_counterexample(unit_schema):
    _, hyps = analyze_session(unit_schema, _pair_streams(21, 99))
    h = hyps[0]
    assert h.result == "fail" and h.status_after == "refuted"
    assert len(h.counterexamples) == 1
    ce = h.counterexamples[0]
    assert ce["a"]["value"] == 21 and ce["b"]["value"] == 99
    assert ce["a"]["offset"] == 0 and ce["b"]["offset"] == 0


def test_hypothesis_incomplete_on_unpaired(unit_schema):
    streams = {"b2a": mk_stream([req(2, struct.pack("<H", 21)),
                                 req(2, struct.pack("<H", 37))], "b2a"),
               "a2b": mk_stream([resp(struct.pack("<H", 21))], "a2b")}
    _, hyps = analyze_session(unit_schema, streams)
    h = hyps[0]
    # одна пара совпала, но вторая без ответа — успехом это не считается
    assert h.result == "incomplete" and h.status_after == "proposed"
    assert h.unpaired_a == [1] and h.pairs_ok == 1
    assert "непарных" in h.note


def test_hypothesis_incomplete_on_unknown_values(unit_schema):
    streams = {"b2a": mk_stream([req(2, struct.pack("<H", 21))], "b2a"),
               "a2b": mk_stream([b"\xAA\x55\x00\x02\x00", ("gap", 2)], "a2b")}
    _, hyps = analyze_session(unit_schema, streams)
    h = hyps[0]
    # значение ответа в пропуске: не равны и не не равны — неизвестно
    assert h.result == "incomplete" and h.pairs_unknown == 1
    assert h.pairs_ok == 0 and h.counterexamples == []


def test_hypothesis_not_applicable_without_examples(unit_schema):
    streams = {"b2a": mk_stream([req(1, b"")], "b2a"),
               "a2b": mk_stream([resp(b"\x01")], "a2b")}
    _, hyps = analyze_session(unit_schema, streams)
    assert hyps[0].result == "not_applicable"


def test_hypothesis_without_direction_results(unit_schema):
    # при scope/skip направления a2b гипотеза не выдумывает результат
    only_b = apply_to_stream(mk_stream([req(2, struct.pack("<H", 1))], "b2a"),
                             unit_schema, "b2a")
    hyps = check_hypotheses(unit_schema, {"b2a": only_b})
    assert hyps[0].result == "not_applicable"


# ------------------------------------------------------- сериализация ----

def test_dir_result_to_dict_limits_messages(unit_schema):
    stream = mk_stream([req(2, struct.pack("<H", i)) for i in range(5)], "b2a")
    r = apply_to_stream(stream, unit_schema, "b2a")
    d = dir_result_to_dict(r, max_messages=2)
    assert d["messages_total"] == 5 and d["messages_truncated"] is True
    assert len(d["messages"]) == 2
    m = d["messages"][0]
    assert m["id"] == "set_value" and m["size"] == 7
    assert m["fields"]["value"] == {"name": "value", "offset": 5, "size": 2,
                                    "type": "u16le", "known": True,
                                    "value": 0, "hex": "0000"}
    assert d["stats"]["matched"] == {"set_value": 5}


def test_message_to_dict_marks_unknown_fields():
    stream = mk_stream([req(2, struct.pack("<H", 9))[:6]], "b2a")
    r = apply_to_stream(stream, load_schema_text(UNIT_SCHEMA), "b2a")
    d = message_to_dict(r.messages[0])
    assert d["partial"] is True
    assert d["fields"]["value"]["known"] is False
    assert "value" not in d["fields"]["value"]


def test_hyp_check_to_dict_shapes(unit_schema):
    _, hyps = analyze_session(unit_schema, _pair_streams(5, 5))
    d = hyp_check_to_dict(hyps[0])
    assert d["result"] == "pass" and d["status_after"] == "checked"
    assert d["pairs"] == {"total": 1, "ok": 1, "unknown": 0}
    assert d["basis"] == ["наблюдение в записи"]
