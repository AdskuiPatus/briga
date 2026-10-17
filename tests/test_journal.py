# -*- coding: utf-8 -*-
"""Журнал действий <-> обмен в записи: корреляция и сверка (R2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from madrigal.interpreter import FieldResult, MsgResult
from madrigal.journal import (
    Action,
    JournalError,
    MsgRef,
    correlate,
    correlate_action,
    filter_capture,
    load_journal,
    match_session,
    session_spans,
    summarize,
    render_compare,
    render_table,
)
from madrigal.schema import SchemaError, load_schema_text

# --- минимальная схема с секцией journal (два действия + неизвестное) ---

SCHEMA = """
version: 1
name: jtest
framing:
  magic: "AA 55"
  header: 5
  length: {offset: 3, type: u16le, includes: payload}
  min: 5
  max: 65536
messages:
  - id: req_set
    direction: a2b
    when: [{offset: 2, type: u8, eq: 1}]
    fields: [{name: seq, offset: 5, type: u8}, {name: value, offset: 6, type: u16be}]
  - id: resp_set
    direction: b2a
    when: [{offset: 2, type: u8, eq: 2}]
    fields: [{name: seq, offset: 5, type: u8}, {name: status, offset: 6, type: u8},
             {name: value, offset: 7, type: u16be}]
  - id: req_get
    direction: a2b
    when: [{offset: 2, type: u8, eq: 3}]
    fields: [{name: seq, offset: 5, type: u8}]
  - id: resp_get
    direction: b2a
    when: [{offset: 2, type: u8, eq: 4}]
    fields: [{name: seq, offset: 5, type: u8}, {name: status, offset: 6, type: u8}]
journal:
  actions:
    set-value: {request: req_set, response: resp_set}
    get-value: {request: req_get, response: resp_get}
    probe-bad: {unknown: true}
  status_map: {0: ok, 3: out_of_range}
  bindings:
    - {observed: status, decoded: status, status: true}
    - {observed: value, decoded: value, scale: 0.01}
"""


def spec():
    return load_schema_text(SCHEMA).journal


# ------------------------------------------------------------ построение ----

def F(name, value, ftype="u8"):
    return FieldResult(name=name, offset=0, size=2, type=ftype,
                       value=value, known=True)


def ref(session, direction, index, mid, start, t0, t1, fields):
    fmap = {f.name: f for f in fields}
    m = MsgResult(i=index, direction=direction, start=start, end=start + 16,
                  id=mid, partial=False, gap_ranges=[], fields=fmap,
                  known_bytes=16, described_bytes=16, described_known=16,
                  match_unknown=False)
    return MsgRef(session=session, direction=direction, index=index, id=mid,
                  start=start, end=start + 16, t0=t0, t1=t1, msg=m)


def act(aid, action, start, end, observed=None, session="s1", capture="rec.pcap"):
    return Action(capture=capture, session=session, action_id=aid,
                  start=start, end=end, action=action,
                  parameters={}, observed_result=observed or {}, row=2)


# ------------------------------------------------------------- чтение ----

def test_load_journal_parses_rows(tmp_path):
    p = tmp_path / "j.csv"
    p.write_text(
        "capture,session,action_id,start_utc,end_utc,action,parameters,observed_result\n"
        "rec.pcap,s1,A1,2026-01-01T00:00:00.000000Z,"
        "2026-01-01T00:00:00.100000Z,set-value,"
        '"{""value"": 1000}","{""status"": ""ok"", ""value"": 21.0}"\n',
        encoding="utf-8")
    actions, errors = load_journal(p)
    assert errors == []
    assert len(actions) == 1
    a = actions[0]
    assert a.action_id == "A1" and a.action == "set-value" and a.session == "s1"
    assert a.parameters == {"value": 1000}
    assert a.observed_result == {"status": "ok", "value": 21.0}
    assert a.end > a.start


def test_load_journal_bad_time_skips_row(tmp_path):
    p = tmp_path / "j.csv"
    p.write_text(
        "capture,session,action_id,start_utc,end_utc,action,parameters,observed_result\n"
        "rec.pcap,s1,BAD,not-a-time,2026-01-01T00:00:00Z,set-value,{},{}\n"
        "rec.pcap,s1,OK,2026-01-01T00:00:00Z,2026-01-01T00:00:01Z,set-value,{},{}\n",
        encoding="utf-8")
    actions, errors = load_journal(p)
    assert [a.action_id for a in actions] == ["OK"]
    assert errors and "время" in errors[0]


def test_load_journal_bad_json_keeps_row(tmp_path):
    p = tmp_path / "j.csv"
    p.write_text(
        "capture,session,action_id,start_utc,end_utc,action,parameters,observed_result\n"
        "rec.pcap,s1,C1,2026-01-01T00:00:00Z,2026-01-01T00:00:01Z,"
        "set-value,{bad,{}\n",
        encoding="utf-8")
    actions, errors = load_journal(p)
    assert len(actions) == 1 and actions[0].parameters == {}
    assert errors and "JSON" in errors[0]


def test_load_journal_missing_columns(tmp_path):
    p = tmp_path / "j.csv"
    p.write_text("capture,session\nrec.pcap,s1\n", encoding="utf-8")
    with pytest.raises(JournalError) as e:
        load_journal(p)
    assert any("колонок" in x for x in e.value.errors)


def test_load_journal_missing_file(tmp_path):
    with pytest.raises(JournalError):
        load_journal(tmp_path / "nope.csv")


def test_filter_capture_matches_basename():
    a = act("A", "set-value", 0, 1, capture="research/01.pcap")
    assert filter_capture([a], "C:/elsewhere/01.pcap") == [a]
    assert filter_capture([a], "C:/elsewhere/02.pcap") == []


# ------------------------------------------- схема: секция journal ----

def test_schema_journal_parsed():
    s = load_schema_text(SCHEMA)
    j = s.journal
    assert j is not None
    assert set(j.actions) == {"set-value", "get-value", "probe-bad"}
    assert j.actions["set-value"] == {"request": "req_set", "response": "resp_set",
                                      "unknown": False}
    assert j.actions["probe-bad"]["unknown"] is True
    assert j.status_map == {0: "ok", 3: "out_of_range"}
    assert len(j.binds) == 2
    assert j.binds[1].scale == 0.01


def test_schema_journal_unknown_message_id_rejected():
    bad = SCHEMA.replace("set-value: {request: req_set,",
                         "set-value: {request: ghost,")
    with pytest.raises(SchemaError) as e:
        load_schema_text(bad)
    assert any("ghost" in x for x in e.value.errors)


def test_schema_journal_index_mismatch_rejected():
    bad = SCHEMA.replace(
        "- {observed: status, decoded: status, status: true}",
        '- {observed: "m[i].x", decoded: status}')
    with pytest.raises(SchemaError) as e:
        load_schema_text(bad)
    assert any("[i]" in x for x in e.value.errors)


# -------------------------------------------------- корреляция/вердикты ----

def test_matched_field_checks():
    msgs = [
        ref(0, "a2b", 0, "req_set", 100, 100.0, 100.1, [F("value", 2100, "u16be")]),
        ref(0, "b2a", 0, "resp_set", 140, 100.2, 100.3,
            [F("status", 0), F("value", 2100, "u16be")]),
    ]
    a = act("A1", "set-value", 100.0, 100.3,
            observed={"status": "ok", "value": 21.0})
    m = correlate_action(a, msgs, spec(), 0)
    assert m.verdict == "matched"
    assert len(m.checks) == 2 and all(c.equal for c in m.checks)
    # provenance: переход к байтам
    assert m.provenance["request"]["start"] == 100


def test_mismatch_detected():
    msgs = [
        ref(0, "a2b", 0, "req_set", 100, 100.0, 100.1, []),
        ref(0, "b2a", 0, "resp_set", 140, 100.2, 100.3,
            [F("status", 0), F("value", 2100, "u16be")]),
    ]
    a = act("A1", "set-value", 100.0, 100.3,
            observed={"status": "ok", "value": 99.0})
    m = correlate_action(a, msgs, spec(), 0)
    assert m.verdict == "mismatch"
    assert "value" in m.note


def test_status_transform_maps_code_to_name():
    msgs = [
        ref(0, "a2b", 0, "req_set", 100, 100.0, 100.1, []),
        ref(0, "b2a", 0, "resp_set", 140, 100.2, 100.3,
            [F("status", 3), F("value", 0, "u16be")]),
    ]
    a = act("A1", "set-value", 100.0, 100.3,
            observed={"status": "out_of_range", "value": 0.0})
    m = correlate_action(a, msgs, spec(), 0)
    assert m.verdict == "matched"


def test_uncovered_unknown_exchange():
    msgs = [
        ref(0, "a2b", 0, None, 100, 100.0, 100.1, []),
        ref(0, "b2a", 0, None, 140, 100.2, 100.3, []),
    ]
    a = act("A1", "probe-bad", 100.0, 100.3, observed={"status": "???"})
    m = correlate_action(a, msgs, spec(), 0)
    assert m.verdict == "uncovered"
    assert m.request is not None and m.response is not None


def test_incomplete_when_response_absent():
    msgs = [ref(0, "a2b", 0, "req_set", 100, 100.0, 100.1, [])]
    a = act("A1", "set-value", 100.0, 100.3, observed={"status": "ok"})
    m = correlate_action(a, msgs, spec(), 0)
    assert m.verdict == "incomplete"
    assert m.request is not None and m.response is None


def test_missing_when_no_exchange():
    a = act("A1", "set-value", 100.0, 100.3, observed={})
    m = correlate_action(a, [], spec(), 0)
    assert m.verdict == "missing"


def test_disambiguates_by_id_within_same_window():
    # два действия с одинаковым окном времени, разными типами сообщений
    msgs = [
        ref(0, "a2b", 0, "req_set", 100, 100.0, 100.05, []),
        ref(0, "a2b", 1, "req_get", 100, 100.0, 100.05, []),
        ref(0, "b2a", 0, "resp_set", 140, 100.1, 100.15, [F("status", 0)]),
        ref(0, "b2a", 1, "resp_get", 160, 100.1, 100.15, [F("status", 0)]),
    ]
    a_set = act("S", "set-value", 100.0, 100.15, observed={"status": "ok"})
    a_get = act("G", "get-value", 100.0, 100.15, observed={"status": "ok"})
    m_set = correlate_action(a_set, msgs, spec(), 0)
    m_get = correlate_action(a_get, msgs, spec(), 0)
    assert m_set.request.id == "req_set" and m_set.response.id == "resp_set"
    assert m_get.request.id == "req_get" and m_get.response.id == "resp_get"
    assert m_set.verdict == "matched" and m_get.verdict == "matched"


def test_session_mapping_by_time_and_correlate():
    spans = [(0, 100.0, 200.0), (1, 300.0, 400.0)]
    assert match_session(150.0, spans) == 0
    assert match_session(350.0, spans) == 1
    # сессии: действия и сообщения распределены по индексам
    msgs_by_session = {
        0: [ref(0, "a2b", 0, "req_set", 100, 150.0, 150.1, []),
            ref(0, "b2a", 0, "resp_set", 140, 150.2, 150.3,
                [F("status", 0), F("value", 1000, "u16be")])],
        1: [ref(1, "a2b", 0, "req_set", 100, 350.0, 350.1, []),
            ref(1, "b2a", 0, "resp_set", 140, 350.2, 350.3,
                [F("status", 0), F("value", 500, "u16be")])],
    }
    actions = [
        act("A", "set-value", 150.0, 150.3, observed={"status": "ok", "value": 10.0}),
        act("B", "set-value", 350.0, 350.3, observed={"status": "ok", "value": 5.0},
            session="s2"),
    ]
    ms = correlate(actions, msgs_by_session, spans, spec())
    assert [m.session_index for m in ms] == [0, 1]
    assert all(m.verdict == "matched" for m in ms)


def test_session_spans_and_summarize():
    class S:
        def __init__(self, ev, a, b):
            self.events = [(i, None) for i in ev]
            self.start, self.end = a, b

    ts = [10, 11, 12, 13, 14, 15, 30, 31, 32, 33, 34, 35]
    spans = session_spans([S([0, 5], 10.0, 20.0), S([6, 11], 30.0, 40.0)], ts)
    assert spans == [(0, 10, 15), (1, 30, 35)]
    ms = [act("A", "set-value", 0, 1)]
    # summarize ожидает Match — соберём через correlate на пустом наборе
    assert summarize(correlate(ms, {}, spans, spec())) == {
        "matched": 0, "mismatch": 0, "uncovered": 0, "incomplete": 0, "missing": 1}


# ------------------------------------------------------------- рендер ----

def test_render_table_and_compare_smoke():
    msgs = [
        ref(0, "a2b", 0, "req_set", 100, 100.0, 100.1, [F("value", 2100, "u16be")]),
        ref(0, "b2a", 0, "resp_set", 140, 100.2, 100.3,
            [F("status", 0), F("value", 2100, "u16be")]),
    ]
    a = act("A1", "set-value", 100.0, 100.3,
            observed={"status": "ok", "value": 21.0})
    a.parameters = {"value": 21.0}
    m = correlate_action(a, msgs, spec(), 0)
    assert "matched" in render_table([m])
    out = render_compare([m], "set-value")
    assert "set-value" in out and "закономерности" in out
