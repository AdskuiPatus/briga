"""Валидация и загрузка схем интерпретации (R3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from madrigal.schema import (
    SchemaError,
    dump_schema,
    load_schema_file,
    load_schema_text,
    parse_schema,
)

ROOT = Path(__file__).resolve().parents[1]
DEMO_SCHEMA = ROOT / "examples" / "demo-protocol.yaml"

BASE = {
    "version": 1,
    "name": "t",
    "framing": {"magic": "AA 55", "header": 5,
                "length": {"offset": 3, "type": "u16le", "includes": "payload"}},
    "messages": [
        {"id": "req", "direction": "b2a",
         "when": [{"offset": 2, "type": "u8", "eq": 2}],
         "fields": [{"name": "value", "offset": 5, "type": "u16le"}]},
    ],
}


def _clone() -> dict:
    return json.loads(json.dumps(BASE))


# ------------------------------------------------- демо-схема из проекта ----

def test_demo_schema_loads():
    s = load_schema_file(DEMO_SCHEMA)
    assert s.name == "demo-protocol"
    assert s.scope_directions == ["a2b", "b2a"]
    assert len(s.messages) == 6
    assert s.message_ids == [
        "read_params", "set_value", "get_measurement",
        "params_response", "set_ack", "measurement_response"]
    assert len(s.hypotheses) == 2
    assert s.hypotheses[0].check is not None
    assert s.hypotheses[1].check is None        # без механической проверки
    rule = s.framing_for("b2a")
    assert rule is not None and rule.magic == b"\xAA\x55"
    assert rule.length_offset == 3 and rule.includes == "payload"


def test_demo_schema_roundtrip_canonical():
    s1 = load_schema_file(DEMO_SCHEMA)
    text = dump_schema(s1, "yaml")
    s2 = load_schema_text(text)
    assert s1.to_dict() == s2.to_dict()
    # и JSON-вывод тоже машиночитаем и обратно совместим
    s3 = load_schema_text(dump_schema(s1, "json"))
    assert s1.to_dict() == s3.to_dict()


def test_json_schema_accepted():
    s = load_schema_text(json.dumps(BASE))
    assert s.message_ids == ["req"]


def test_schema_sha256_is_stable():
    s1 = load_schema_file(DEMO_SCHEMA)
    s2 = load_schema_file(DEMO_SCHEMA)
    assert s1.sha256 == s2.sha256 and len(s1.sha256) == 64


# ------------------------------------------------------------ ошибки ----

def test_unknown_key_rejected():
    d = _clone()
    d["messages"][0]["directoin"] = "b2a"      # опечатка
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "directoin" in str(e.value)


def test_duplicate_message_id():
    d = _clone()
    d["messages"].append({"id": "req", "direction": "b2a"})
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "повторяется" in str(e.value)


def test_unknown_field_type():
    d = _clone()
    d["messages"][0]["fields"][0]["type"] = "u16"   # нет указания порядка
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "u16" in str(e.value) and "type" in str(e.value)


def test_eq_and_in_mutually_exclusive():
    d = _clone()
    d["messages"][0]["when"] = [{"offset": 2, "type": "u8", "eq": 1, "in": [1]}]
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "eq" in str(e.value)


def test_in_must_be_nonempty_int_list():
    d = _clone()
    d["messages"][0]["when"] = [{"offset": 2, "type": "u8", "in": []}]
    with pytest.raises(SchemaError):
        parse_schema(d)


def test_from_field_must_be_declared_earlier():
    d = _clone()
    d["messages"][0]["fields"] = [
        {"name": "payload", "offset": 5, "type": "bytes",
         "length": {"from_field": "plen"}},
        {"name": "plen", "offset": 3, "type": "u16le"},
    ]
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "plen" in str(e.value)


def test_from_field_self_reference_rejected():
    d = _clone()
    d["messages"][0]["fields"] = [
        {"name": "payload", "offset": 5, "type": "bytes",
         "length": {"from_field": "payload"}},
    ]
    with pytest.raises(SchemaError):
        parse_schema(d)


def test_length_field_beyond_header():
    d = _clone()
    d["framing"]["header"] = 3     # поле длины на offset 3 больше не влезает
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "заголовка" in str(e.value)


def test_missing_framing():
    d = _clone()
    del d["framing"]
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "framing" in str(e.value)


def test_bad_magic_hex():
    d = _clone()
    d["framing"]["magic"] = "GG 55"
    with pytest.raises(SchemaError):
        parse_schema(d)


def test_scope_bad_direction():
    d = _clone()
    d["scope"] = {"directions": ["left"]}
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "scope" in str(e.value)


def test_hypothesis_unknown_message_and_field():
    d = _clone()
    d["hypotheses"] = [{
        "id": "h", "statement": "s",
        "check": {"pairs": {
            "a": {"message": "req", "field": "value"},
            "b": {"message": "nope", "field": "value"}}}}]
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "nope" in str(e.value)


def test_hypothesis_any_direction_requires_explicit():
    d = _clone()
    d["messages"].append({"id": "resp", "direction": "any",
                          "fields": [{"name": "value", "offset": 5,
                                      "type": "u16le"}]})
    d["hypotheses"] = [{
        "id": "h", "statement": "s",
        "check": {"pairs": {
            "a": {"message": "req", "field": "value"},
            "b": {"message": "resp", "field": "value"}}}}]
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert "direction" in str(e.value)


def test_multiple_errors_reported_together():
    d = _clone()
    d["messages"][0]["direction"] = "sideways"
    d["messages"][0]["fields"][0]["type"] = "nope"
    with pytest.raises(SchemaError) as e:
        parse_schema(d)
    assert len(e.value.errors) >= 2


def test_hypothesis_without_check_is_valid():
    d = _clone()
    d["hypotheses"] = [{"id": "h", "statement": "просто утверждение",
                        "basis": ["наблюдение 1"], "status": "proposed"}]
    s = parse_schema(d)
    assert s.hypotheses[0].check is None


def test_condition_in_survives_roundtrip():
    d = _clone()
    d["messages"][0]["when"] = [{"offset": 2, "type": "u8", "in": [1, 3]}]
    s = parse_schema(d)
    out = s.to_dict()
    assert out["messages"][0]["when"][0]["in"] == [1, 3]
    s2 = parse_schema(out)
    assert s2.to_dict() == out
