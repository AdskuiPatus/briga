"""Схема интерпретации (R3): загрузка, валидация, каноническая форма.

Схема отделяет два вида утверждений (раздел 9 кейса):
  * messages/framing — правила: применяются программно и проверяются на данных;
  * hypotheses — предположения о назначении данных: имеют основания (basis),
    статус и, опционально, механическую проверку (check) с контрпримерами.

Формат (YAML или JSON):

    version: 1
    name: demo-protocol
    scope: {directions: [a2b, b2a]}        # область действия (необязательно)
    framing:
      magic: "AA 55"                       # маркер начала сообщения
      header: 5                            # размер заголовка
      length: {offset: 3, type: u16le, includes: payload}  # | {fixed: N}
      min: 5
      max: 65536
    messages:
      - id: set_value
        direction: b2a                     # a2b | b2a | any
        when: [{offset: 2, type: u8, eq: 2}]
        fields:
          - {name: cmd, offset: 2, type: u8}
          - {name: value, offset: 5, type: u16le}
          - {name: payload, offset: 5, type: bytes, length: {from_field: plen}}
    hypotheses:
      - id: h1
        statement: "ответ подтверждает установленное значение"
        basis: ["действие «задать 21» → в ответе 21"]
        status: proposed                   # proposed | checked | refuted | refined
        check:
          pairs:
            a: {message: set_value, field: value}
            b: {message: set_ack, field: value}
          expect: equal
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

DIRECTIONS = ("a2b", "b2a")
MATCH_DIRECTIONS = DIRECTIONS + ("any",)
HYPOTHESIS_STATUSES = ("proposed", "checked", "refuted", "refined")

# типы полей: имя -> (фиксированный размер | None = переменный), функция декодирования
FIXED_TYPES = ("u8", "u16le", "u16be", "u32le", "u32be")
VAR_TYPES = ("bytes", "ascii")
ALL_TYPES = FIXED_TYPES + VAR_TYPES
TYPE_SIZE = {"u8": 1, "u16le": 2, "u16be": 2, "u32le": 4, "u32be": 4}


class SchemaError(Exception):
    """Ошибки валидации схемы (список с путями к полям)."""

    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass
class Condition:
    offset: int
    type: Optional[str] = None       # для eq/in-условий
    eq: Optional[int] = None
    values: Optional[List[int]] = None   # in: [..] — значение из набора
    bytes: Optional[bytes] = None    # для bytes-условий


@dataclass
class FieldDef:
    name: str
    offset: int
    type: str
    length: Optional[int] = None           # фиксированная длина для bytes/ascii
    from_field: Optional[str] = None       # длина из значения другого поля


@dataclass
class MessageDef:
    id: str
    direction: str = "any"
    when: List[Condition] = field(default_factory=list)
    fields: List[FieldDef] = field(default_factory=list)


@dataclass
class FramingRule:
    direction: Optional[str] = None        # None — для любого направления
    magic: Optional[bytes] = None
    header: int = 0
    length_offset: Optional[int] = None
    length_type: Optional[str] = None
    includes: str = "payload"              # payload | total
    fixed: Optional[int] = None
    min_len: int = 1
    max_len: int = 1 << 20

    @property
    def needs_length_field(self) -> bool:
        return self.fixed is None


@dataclass
class PairEndpoint:
    message: str
    field: str
    direction: Optional[str] = None        # уточнение; иначе из определения сообщения


@dataclass
class PairCheck:
    a: PairEndpoint
    b: PairEndpoint
    expect: str = "equal"


@dataclass
class Hypothesis:
    id: str
    statement: str
    basis: List[str] = field(default_factory=list)
    status: str = "proposed"
    check: Optional[PairCheck] = None


@dataclass
class Schema:
    version: int
    name: str
    scope_directions: Optional[List[str]]
    framing: List[FramingRule]
    messages: List[MessageDef]
    hypotheses: List[Hypothesis]
    source_text: str = ""
    source_path: str = ""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.source_text.encode("utf-8")).hexdigest()

    @property
    def message_ids(self) -> List[str]:
        return [m.id for m in self.messages]

    def message(self, mid: str) -> Optional[MessageDef]:
        for m in self.messages:
            if m.id == mid:
                return m
        return None

    def framing_for(self, direction: str) -> Optional[FramingRule]:
        best: Optional[FramingRule] = None
        for r in self.framing:
            if r.direction is None:
                best = best or r
            elif r.direction == direction:
                return r
        return best

    def to_dict(self) -> dict:
        """Каноническое машиночитаемое представление схемы."""
        out: Dict[str, Any] = {"version": self.version, "name": self.name}
        if self.scope_directions:
            out["scope"] = {"directions": list(self.scope_directions)}

        def framing_dict(r: FramingRule) -> dict:
            d: Dict[str, Any] = {}
            if r.direction:
                d["direction"] = r.direction
            if r.magic is not None:
                d["magic"] = r.magic.hex(" ").upper()
            d["header"] = r.header
            if r.fixed is not None:
                d["length"] = {"fixed": r.fixed}
            else:
                d["length"] = {
                    "offset": r.length_offset,
                    "type": r.length_type,
                    "includes": r.includes,
                }
            d["min"] = r.min_len
            d["max"] = r.max_len
            return d

        if len(self.framing) == 1 and self.framing[0].direction is None:
            out["framing"] = framing_dict(self.framing[0])
        else:
            out["framing"] = [framing_dict(r) for r in self.framing]

        msgs = []
        for m in self.messages:
            md: Dict[str, Any] = {"id": m.id, "direction": m.direction}
            if m.when:
                md["when"] = [
                    ({"offset": c.offset, "bytes": c.bytes.hex(" ").upper()}
                     if c.bytes is not None
                     else ({"offset": c.offset, "type": c.type, "in": c.values}
                           if c.values is not None
                           else {"offset": c.offset, "type": c.type, "eq": c.eq}))
                    for c in m.when
                ]
            md["fields"] = []
            for f in m.fields:
                fd: Dict[str, Any] = {"name": f.name, "offset": f.offset, "type": f.type}
                if f.length is not None:
                    fd["length"] = f.length
                if f.from_field is not None:
                    fd["length"] = {"from_field": f.from_field}
                md["fields"].append(fd)
            msgs.append(md)
        out["messages"] = msgs

        hyps = []
        for h in self.hypotheses:
            hd: Dict[str, Any] = {
                "id": h.id, "statement": h.statement,
                "basis": list(h.basis), "status": h.status,
            }
            if h.check:
                hd["check"] = {
                    "pairs": {
                        "a": {"message": h.check.a.message, "field": h.check.a.field,
                              **({"direction": h.check.a.direction}
                                 if h.check.a.direction else {})},
                        "b": {"message": h.check.b.message, "field": h.check.b.field,
                              **({"direction": h.check.b.direction}
                                 if h.check.b.direction else {})},
                    },
                    "expect": h.check.expect,
                }
            hyps.append(hd)
        if hyps:
            out["hypotheses"] = hyps
        return out


# ------------------------------------------------------------ валидация ----

def parse_hex(text: str, path: str, errors: List[str]) -> Optional[bytes]:
    if not isinstance(text, str):
        errors.append(f"{path}: ожидается строка в hex (например \"AA 55\")")
        return None
    compact = text.replace("0x", "").replace("0X", "")
    compact = "".join(compact.split()).replace(":", "")
    if not compact or len(compact) % 2:
        errors.append(f"{path}: некорректная hex-строка {text!r}")
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        errors.append(f"{path}: в hex-строке есть не hex-символы: {text!r}")
        return None


def _expect_dict(value: Any, path: str, errors: List[str]) -> Optional[dict]:
    if not isinstance(value, dict):
        errors.append(f"{path}: ожидается объект/словарь")
        return None
    return value


def _expect_list(value: Any, path: str, errors: List[str]) -> Optional[list]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{path}: ожидается список")
        return None
    return value


def _check_keys(d: dict, allowed: set, path: str, errors: List[str]) -> None:
    """Неизвестные ключи — почти всегда опечатка; игнорировать нельзя."""
    for key in d:
        if key not in allowed:
            errors.append(
                f"{path}.{key}: неизвестный ключ (допустимы: "
                + ", ".join(sorted(allowed)) + ")")


def _parse_condition(raw: Any, path: str, errors: List[str]) -> Optional[Condition]:
    d = _expect_dict(raw, path, errors)
    if d is None:
        return None
    _check_keys(d, {"offset", "type", "eq", "in", "bytes"}, path, errors)
    if "offset" not in d or not isinstance(d["offset"], int) or d["offset"] < 0:
        errors.append(f"{path}.offset: ожидается целое ≥ 0")
        return None
    if "bytes" in d:
        b = parse_hex(d["bytes"], f"{path}.bytes", errors)
        return Condition(offset=d["offset"], bytes=b) if b is not None else None
    if "type" not in d or d["type"] not in FIXED_TYPES:
        errors.append(f"{path}.type: ожидается одно из {', '.join(FIXED_TYPES)}")
        return None
    has_eq, has_in = "eq" in d, "in" in d
    if has_eq == has_in:  # ни того, ни другого — или оба сразу
        errors.append(f"{path}: нужен ровно один из ключей eq или in")
        return None
    if has_in:
        values = d["in"]
        if (not isinstance(values, list) or not values
                or not all(isinstance(v, int) for v in values)):
            errors.append(f"{path}.in: ожидается непустой список целых")
            return None
        return Condition(offset=d["offset"], type=d["type"], values=list(values))
    if not isinstance(d["eq"], int):
        errors.append(f"{path}.eq: ожидается целое значение")
        return None
    return Condition(offset=d["offset"], type=d["type"], eq=d["eq"])


def _parse_field(raw: Any, path: str, seen_names: set, errors: List[str]) -> Optional[FieldDef]:
    d = _expect_dict(raw, path, errors)
    if d is None:
        return None
    _check_keys(d, {"name", "offset", "type", "length"}, path, errors)
    ok = True
    name = d.get("name")
    if not isinstance(name, str) or not name:
        errors.append(f"{path}.name: ожидается непустая строка")
        ok = False
    elif name in seen_names:
        errors.append(f"{path}.name: поле {name!r} уже описано в этом сообщении")
        ok = False
    if not isinstance(d.get("offset"), int) or d.get("offset", -1) < 0:
        errors.append(f"{path}.offset: ожидается целое ≥ 0")
        ok = False
    ftype = d.get("type")
    if ftype not in ALL_TYPES:
        errors.append(f"{path}.type: ожидается одно из {', '.join(ALL_TYPES)}")
        ok = False

    length = None
    from_field = None
    if ftype in VAR_TYPES:
        if "length" in d:
            ln = d["length"]
            if isinstance(ln, int) and ln >= 0:
                length = ln
            elif isinstance(ln, dict) and isinstance(ln.get("from_field"), str):
                from_field = ln["from_field"]
            else:
                errors.append(
                    f"{path}.length: ожидается целое ≥ 0 или {{from_field: имя}}")
                ok = False
    elif "length" in d:
        errors.append(f"{path}.length: длина задаётся только для bytes/ascii")
        ok = False

    if from_field is not None and from_field not in seen_names:
        errors.append(
            f"{path}.length.from_field: поле {from_field!r} не описано ранее "
            "в этом сообщении")
        ok = False

    if not ok:
        return None
    return FieldDef(name=name, offset=d["offset"], type=ftype,
                    length=length, from_field=from_field)


def _parse_message(raw: Any, path: str, errors: List[str]) -> Optional[MessageDef]:
    d = _expect_dict(raw, path, errors)
    if d is None:
        return None
    _check_keys(d, {"id", "direction", "when", "fields"}, path, errors)
    ok = True
    mid = d.get("id")
    if not isinstance(mid, str) or not mid:
        errors.append(f"{path}.id: ожидается непустая строка")
        ok = False
    direction = d.get("direction", "any")
    if direction not in MATCH_DIRECTIONS:
        errors.append(f"{path}.direction: ожидается одно из {', '.join(MATCH_DIRECTIONS)}")
        ok = False

    conditions: List[Condition] = []
    for i, raw_c in enumerate(_expect_list(d.get("when"), f"{path}.when", errors) or []):
        c = _parse_condition(raw_c, f"{path}.when[{i}]", errors)
        if c is None:
            ok = False
        else:
            conditions.append(c)

    fields: List[FieldDef] = []
    names: set = set()
    for i, raw_f in enumerate(_expect_list(d.get("fields"), f"{path}.fields", errors) or []):
        f = _parse_field(raw_f, f"{path}.fields[{i}]", names, errors)
        if f is None:
            ok = False
        else:
            names.add(f.name)
            fields.append(f)

    if not ok:
        return None
    return MessageDef(id=mid, direction=direction, when=conditions, fields=fields)


def _parse_framing(raw: Any, path: str, errors: List[str]) -> List[FramingRule]:
    items = raw if isinstance(raw, list) else [raw]
    rules: List[FramingRule] = []
    for i, item in enumerate(items):
        p = f"{path}[{i}]" if isinstance(raw, list) else path
        d = _expect_dict(item, p, errors)
        if d is None:
            continue
        _check_keys(d, {"direction", "magic", "header", "length", "min", "max"},
                    p, errors)
        rule = FramingRule()

        direction = d.get("direction")
        if direction is not None:
            if direction not in DIRECTIONS:
                errors.append(f"{p}.direction: ожидается одно из {', '.join(DIRECTIONS)}")
                continue
            rule.direction = direction

        if "magic" in d:
            m = parse_hex(d["magic"], f"{p}.magic", errors)
            if m is None:
                continue
            rule.magic = m

        header = d.get("header", 0)
        if not isinstance(header, int) or header < 0:
            errors.append(f"{p}.header: ожидается целое ≥ 0")
            continue
        rule.header = header

        length = d.get("length")
        if length is None:
            errors.append(f"{p}.length: обязательно ({{offset, type, includes}} или {{fixed}})")
            continue
        ld = _expect_dict(length, f"{p}.length", errors)
        if ld is None:
            continue
        _check_keys(ld, {"fixed", "offset", "type", "includes"}, f"{p}.length",
                    errors)
        if "fixed" in ld:
            if not isinstance(ld["fixed"], int) or ld["fixed"] <= 0:
                errors.append(f"{p}.length.fixed: ожидается целое > 0")
                continue
            rule.fixed = ld["fixed"]
        else:
            if not isinstance(ld.get("offset"), int) or ld.get("offset", -1) < 0:
                errors.append(f"{p}.length.offset: ожидается целое ≥ 0")
                continue
            ltype = ld.get("type")
            if ltype not in FIXED_TYPES:
                errors.append(f"{p}.length.type: ожидается одно из {', '.join(FIXED_TYPES)}")
                continue
            includes = ld.get("includes", "payload")
            if includes not in ("payload", "total"):
                errors.append(f"{p}.length.includes: ожидается 'payload' или 'total'")
                continue
            rule.length_offset = ld["offset"]
            rule.length_type = ltype
            rule.includes = includes
            if rule.length_offset + TYPE_SIZE[ltype] > header:
                errors.append(
                    f"{p}: поле длины (смещение {rule.length_offset}) выходит за границы "
                    f"заголовка ({header} Б)")
                continue

        mn = d.get("min", 1)
        mx = d.get("max", 1 << 20)
        if not isinstance(mn, int) or not isinstance(mx, int) or mn < 1 or mx < mn:
            errors.append(f"{p}.min/max: ожидается 1 ≤ min ≤ max")
            continue
        rule.min_len, rule.max_len = mn, mx
        rules.append(rule)

    if not rules:
        errors.append(f"{path}: нет ни одного рабочего правила фрейминга")
    return rules


def _parse_hypothesis(raw: Any, path: str, msg_index: Dict[str, MessageDef],
                      errors: List[str]) -> Optional[Hypothesis]:
    d = _expect_dict(raw, path, errors)
    if d is None:
        return None
    _check_keys(d, {"id", "statement", "basis", "status", "check"}, path, errors)
    ok = True
    hid = d.get("id")
    if not isinstance(hid, str) or not hid:
        errors.append(f"{path}.id: ожидается непустая строка")
        ok = False
    statement = d.get("statement")
    if not isinstance(statement, str) or not statement:
        errors.append(f"{path}.statement: утверждение обязательно")
        ok = False
    basis = d.get("basis", [])
    if not isinstance(basis, list) or not all(isinstance(x, str) for x in basis):
        errors.append(f"{path}.basis: ожидается список строк (основания)")
        ok = False
    status = d.get("status", "proposed")
    if status not in HYPOTHESIS_STATUSES:
        errors.append(f"{path}.status: ожидается одно из {', '.join(HYPOTHESIS_STATUSES)}")
        ok = False

    check = None
    if "check" in d:
        cd = _expect_dict(d.get("check"), f"{path}.check", errors)
        if cd is None:
            ok = False
        else:
            _check_keys(cd, {"pairs", "expect"}, f"{path}.check", errors)
            pairs = _expect_dict(cd.get("pairs"), f"{path}.check.pairs", errors)
            if pairs is None:
                ok = False
            else:
                _check_keys(pairs, {"a", "b"}, f"{path}.check.pairs", errors)
                endpoints: Dict[str, PairEndpoint] = {}
                for side in ("a", "b"):
                    sd = _expect_dict(pairs.get(side), f"{path}.check.pairs.{side}", errors)
                    if sd is None:
                        ok = False
                        continue
                    _check_keys(sd, {"message", "field", "direction"},
                                f"{path}.check.pairs.{side}", errors)
                    mid, fid = sd.get("message"), sd.get("field")
                    if mid not in msg_index:
                        errors.append(
                            f"{path}.check.pairs.{side}.message: нет сообщения {mid!r}")
                        ok = False
                        continue
                    mdef = msg_index[mid]
                    if fid not in {f.name for f in mdef.fields}:
                        errors.append(
                            f"{path}.check.pairs.{side}.field: у сообщения {mid!r} "
                            f"нет поля {fid!r}")
                        ok = False
                        continue
                    direction = sd.get("direction")
                    if direction is None and mdef.direction == "any":
                        errors.append(
                            f"{path}.check.pairs.{side}: сообщение {mid!r} — направление "
                            "'any', укажите direction явно")
                        ok = False
                        continue
                    if direction is not None and direction not in DIRECTIONS:
                        errors.append(f"{path}.check.pairs.{side}.direction: ожидается "
                                      f"одно из {', '.join(DIRECTIONS)}")
                        ok = False
                        continue
                    endpoints[side] = PairEndpoint(
                        message=mid, field=fid,
                        direction=direction or mdef.direction)
                expect = cd.get("expect", "equal")
                if expect != "equal":
                    errors.append(f"{path}.check.expect: поддерживается 'equal'")
                    ok = False
                if set(endpoints) == {"a", "b"}:
                    check = PairCheck(a=endpoints["a"], b=endpoints["b"], expect=expect)

    if not ok:
        return None
    return Hypothesis(id=hid, statement=statement, basis=list(basis),
                      status=status, check=check)


def parse_schema(data: Any, source_text: str = "", source_path: str = "") -> Schema:
    """Разобрать и провалидировать схему. При ошибках — SchemaError со списком."""
    errors: List[str] = []
    root = _expect_dict(data, "корень", errors)
    if root is None:
        raise SchemaError(errors)
    _check_keys(root, {"version", "name", "scope", "framing", "messages",
                       "hypotheses"}, "корень", errors)

    version = root.get("version", 1)
    if version != 1:
        errors.append(f"version: поддерживается только версия 1 (получено {version!r})")
    name = root.get("name")
    if not isinstance(name, str) or not name:
        errors.append("name: ожидается непустая строка")
        name = "без имени"

    scope_dirs: Optional[List[str]] = None
    if "scope" in root:
        sd = _expect_dict(root.get("scope"), "scope", errors)
        if sd is not None:
            _check_keys(sd, {"directions"}, "scope", errors)
            dirs = sd.get("directions")
            if dirs is not None:
                if (not isinstance(dirs, list) or not dirs
                        or any(d not in DIRECTIONS for d in dirs)):
                    errors.append(
                        f"scope.directions: ожидается непустой список из {', '.join(DIRECTIONS)}")
                else:
                    scope_dirs = list(dirs)

    if "framing" not in root:
        errors.append("framing: раздел обязателен")
        framing: List[FramingRule] = []
    else:
        framing = _parse_framing(root.get("framing"), "framing", errors)

    messages: List[MessageDef] = []
    msg_index: Dict[str, MessageDef] = {}
    for i, raw_m in enumerate(_expect_list(root.get("messages"), "messages", errors) or []):
        m = _parse_message(raw_m, f"messages[{i}]", errors)
        if m is None:
            continue
        if m.id in msg_index:
            errors.append(f"messages[{i}].id: id {m.id!r} повторяется")
            continue
        msg_index[m.id] = m
        messages.append(m)

    hypotheses: List[Hypothesis] = []
    hyp_ids: set = set()
    for i, raw_h in enumerate(_expect_list(root.get("hypotheses"), "hypotheses", errors) or []):
        h = _parse_hypothesis(raw_h, f"hypotheses[{i}]", msg_index, errors)
        if h is None:
            continue
        if h.id in hyp_ids:
            errors.append(f"hypotheses[{i}].id: id {h.id!r} повторяется")
            continue
        hyp_ids.add(h.id)
        hypotheses.append(h)

    if errors:
        raise SchemaError(errors)
    return Schema(
        version=version, name=name, scope_directions=scope_dirs,
        framing=framing, messages=messages, hypotheses=hypotheses,
        source_text=source_text, source_path=source_path,
    )


def load_schema_text(text: str, source_path: str = "") -> Schema:
    """Разобрать схему из YAML/JSON-текста."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SchemaError([f"YAML/JSON: {e}"])
    if data is None:
        raise SchemaError(["схема пуста"])
    return parse_schema(data, source_text=text, source_path=source_path)


def load_schema_file(path: str | Path) -> Schema:
    p = Path(path)
    if not p.is_file():
        raise SchemaError([f"файл схемы не найден: {p}"])
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise SchemaError([f"{p}: файл не в UTF-8"])
    return load_schema_text(text, source_path=str(p))


def dump_schema(schema: Schema, fmt: str = "yaml") -> str:
    """Канонический вывод схемы (машиночитаемое представление, R6)."""
    data = schema.to_dict()
    if fmt == "json":
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
