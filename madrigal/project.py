"""Переносимый исследовательский проект (R5).

Проект — каталог с манифестом `project.yaml`, который связывает воедино
исходные записи, интерпретации, корпуса, результаты проверок, наблюдения
и условия воспроизведения. Все пути в манифесте — относительные
(POSIX-разделители `/`); после копирования каталога в другой каталог или
на другую машину `python -m madrigal project check` подтверждает
целостность без обращения к прежним абсолютным путям.

    version: 1
    name: madrigal-demo
    description: исследование протокола демо-стенда
    requires:
      python: ">=3.12"
      packages: [pyyaml>=6.0, fastapi, uvicorn]
    settings:                          # условия воспроизведения
      overlap_policy: first-seen
      directions: [a2b, b2a]
    recordings:
      - {path: examples/demo.pcapng, sha256: <hex>, note: эталон}
    schemas:
      - {path: examples/demo-protocol.yaml, sha256: <hex>}
    corpora:
      - {path: examples/demo-corpus.yaml, sha256: <hex>}
    results:
      - {path: reports/demo-corpus-verify.json, kind: corpus-verify}
    observations:                      # наблюдания со связями к источникам
      - text: "ответ set_ack подтверждает значение"
        source: {file: examples/demo.pcapng, session: 0,
                 direction: a2b, offset: 17, packets: [12]}

Проверка (`project check`) отличает актуальные результаты от устаревших:
контрольные суммы записей/схем/корпусов сверяются с заштампованными,
отчёты корпусов дополнительно проверяются механикой `stale`
(пересчёт sha256 входов отчёта).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Union

import yaml

from .corpus import CorpusError, check_report

MANIFEST_NAME = "project.yaml"
PROJECT_VERSION = 1
RESULT_KINDS = ("corpus-verify", "apply")
SOURCE_DIRECTIONS = ("a2b", "b2a")


class ProjectError(Exception):
    """Манифест проекта непригоден (список причин)."""

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# ------------------------------------------------------------ манифест ----

@dataclass
class Artifact:
    path: str                       # относительно каталога манифеста, через "/"
    sha256: str = ""                # контрольная сумма байтов файла
    note: str = ""
    kind: str = ""                  # только для results (corpus-verify|apply)


@dataclass
class Observation:
    text: str
    source: Dict[str, Union[str, int, List[int]]] = field(default_factory=dict)


@dataclass
class Project:
    name: str
    description: str
    manifest_path: Path             # путь к project.yaml на диске
    manifest_sha256: str
    requires: Dict[str, Union[str, List[str]]]
    settings: dict
    recordings: List[Artifact]
    schemas: List[Artifact]
    corpora: List[Artifact]
    results: List[Artifact]
    observations: List[Observation]

    @property
    def root(self) -> Path:
        return self.manifest_path.parent

    def resolve(self, rel: str) -> Path:
        return self.root.joinpath(*PurePosixPath(rel).parts)


def _check_keys(d: dict, allowed: set, path: str, errors: List[str]) -> None:
    for k in d:
        if k not in allowed:
            hint = " (возможно, опечатка)" \
                if any(k.startswith(a[:4]) for a in allowed) else ""
            errors.append(f"{path}: неизвестный ключ {k!r}{hint}")


def _check_relpath(value: object, path: str, errors: List[str]) -> Optional[str]:
    """Путь обязан быть относительным и переносимым (R5)."""
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}: ожидается непустая строка — относительный путь")
        return None
    p = value.replace("\\", "/")
    pp = PurePosixPath(p)
    if pp.is_absolute() or (len(p) > 1 and p[1] == ":"):
        errors.append(f"{path}: путь обязан быть относительным (переносимость "
                      f"проекта): {value!r}")
        return None
    if p.startswith("~"):
        errors.append(f"{path}: путь не должен начинаться с ~: {value!r}")
        return None
    if ".." in pp.parts:
        errors.append(f"{path}: выход за пределы каталога проекта запрещён: "
                      f"{value!r}")
        return None
    return "/".join(pp.parts)


def _parse_artifact(raw: object, path: str, need_sha: bool, errors: List[str],
                    kind: str = "") -> Optional[Artifact]:
    d = raw if isinstance(raw, dict) else None
    if d is None:
        errors.append(f"{path}: ожидается словарь {{path, sha256, note}}")
        return None
    _check_keys(d, {"path", "sha256", "note", "kind"}, path, errors)
    rel = _check_relpath(d.get("path"), f"{path}.path", errors)
    sha = d.get("sha256", "")
    if sha and (not isinstance(sha, str) or len(sha) != 64
                or any(c not in "0123456789abcdef" for c in sha.lower())):
        errors.append(f"{path}.sha256: ожидается 64 hex-символа")
        sha = ""
    if need_sha and not sha:
        errors.append(f"{path}.sha256: контрольная сумма обязательна "
                      f"(целостность при переносе)")
    note = d.get("note", "")
    if not isinstance(note, str):
        errors.append(f"{path}.note: ожидается строка")
        note = ""
    akind = d.get("kind", kind)
    if kind and akind != kind:
        errors.append(f"{path}.kind: ожидается {kind!r} (получено {akind!r})")
        akind = kind
    if rel is None:
        return None
    return Artifact(path=rel, sha256=(sha or "").lower(), note=note, kind=akind)


def _parse_source(raw: object, path: str, errors: List[str]) -> dict:
    d = raw if isinstance(raw, dict) else None
    if d is None:
        errors.append(f"{path}: ожидается словарь {{file, session, direction, "
                      f"offset, packets}}")
        return {}
    _check_keys(d, {"file", "session", "direction", "offset", "packets"},
                path, errors)
    out: Dict[str, Union[str, int, List[int]]] = {}
    if "file" in d:
        rel = _check_relpath(d["file"], f"{path}.file", errors)
        if rel is not None:
            out["file"] = rel
    for key in ("session", "offset"):
        if key in d:
            v = d[key]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                errors.append(f"{path}.{key}: ожидается целое >= 0")
            else:
                out[key] = v
    if "direction" in d:
        if d["direction"] not in SOURCE_DIRECTIONS:
            errors.append(f"{path}.direction: ожидается одно из "
                          f"{', '.join(SOURCE_DIRECTIONS)}")
        else:
            out["direction"] = d["direction"]
    if "packets" in d:
        pk = d["packets"]
        if not isinstance(pk, list) or any(
                isinstance(p, bool) or not isinstance(p, int) or p < 0
                for p in pk):
            errors.append(f"{path}.packets: ожидается список номеров пакетов")
        else:
            out["packets"] = list(pk)
    return out


def load_project(path: Union[str, Path]) -> Project:
    """Загрузить и провалидировать манифест проекта."""
    p = Path(path)
    if p.is_dir():
        p = p / MANIFEST_NAME
    if not p.is_file():
        raise ProjectError([f"манифест проекта не найден: {p}"])
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ProjectError([f"{p}: манифест не в UTF-8"])
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ProjectError([f"{p}: ошибка YAML: {e}"])
    if not isinstance(data, dict):
        raise ProjectError([f"{p}: ожидался словарь с ключами "
                            f"version/name/recordings/..."])

    errors: List[str] = []
    _check_keys(data, {"version", "name", "description", "requires",
                       "settings", "recordings", "schemas", "corpora",
                       "results", "observations"}, "корень", errors)

    version = data.get("version", 1)
    if version != PROJECT_VERSION:
        errors.append(f"version: поддерживается только "
                      f"{PROJECT_VERSION} (получено {version!r})")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("name: непустая строка обязательна")
        name = ""
    description = data.get("description", "")
    if not isinstance(description, str):
        errors.append("description: ожидается строка")
        description = ""

    requires: Dict[str, Union[str, List[str]]] = {}
    if "requires" in data:
        rd = data["requires"]
        if not isinstance(rd, dict):
            errors.append("requires: ожидается словарь (python, packages)")
        else:
            _check_keys(rd, {"python", "packages"}, "requires", errors)
            for key in ("python", "packages"):
                if key in rd:
                    v = rd[key]
                    ok = isinstance(v, str) and v.strip() if key == "python" \
                        else isinstance(v, list) and all(
                            isinstance(x, str) for x in v)
                    if not ok:
                        errors.append(f"requires.{key}: ожидается "
                                      f"{'строка' if key == 'python' else 'список строк'}")
                    else:
                        requires[key] = v

    settings: dict = {}
    if "settings" in data:
        sd = data["settings"]
        if not isinstance(sd, dict):
            errors.append("settings: ожидается словарь условий воспроизведения")
        else:
            settings = dict(sd)

    def section(key: str, need_sha: bool, kind: str = "") -> List[Artifact]:
        raw = data.get(key)
        if raw is None:
            return []
        if not isinstance(raw, list):
            errors.append(f"{key}: ожидается список")
            return []
        out: List[Artifact] = []
        for i, item in enumerate(raw):
            a = _parse_artifact(item, f"{key}[{i}]", need_sha, errors, kind)
            if a is not None:
                out.append(a)
        return out

    recordings = section("recordings", need_sha=True)
    schemas = section("schemas", need_sha=True)
    corpora = section("corpora", need_sha=True)
    results = section("results", need_sha=False)
    for i, r in enumerate(results):
        if r.kind not in RESULT_KINDS:
            errors.append(f"results[{i}].kind: ожидается одно из "
                          f"{', '.join(RESULT_KINDS)} (получено {r.kind!r})")

    observations: List[Observation] = []
    raw_obs = data.get("observations")
    if raw_obs is not None:
        if not isinstance(raw_obs, list):
            errors.append("observations: ожидается список")
        else:
            for i, item in enumerate(raw_obs):
                where = f"observations[{i}]"
                od = item if isinstance(item, dict) else None
                if od is None:
                    errors.append(f"{where}: ожидается словарь {{text, source}}")
                    continue
                _check_keys(od, {"text", "source"}, where, errors)
                text_v = od.get("text")
                if not isinstance(text_v, str) or not text_v.strip():
                    errors.append(f"{where}.text: непустая строка обязательна")
                    continue
                source = {}
                if "source" in od:
                    source = _parse_source(od["source"], f"{where}.source",
                                           errors)
                observations.append(Observation(text=text_v, source=source))

    # целостность состава: файлы обязаны существовать внутри проекта
    for section_name, items in (("recordings", recordings),
                                ("schemas", schemas),
                                ("corpora", corpora)):
        for a in items:
            if not p.parent.joinpath(*PurePosixPath(a.path).parts).is_file():
                errors.append(f"{section_name}: файл не найден в проекте: "
                              f"{a.path}")
    for i, o in enumerate(observations):
        f = o.source.get("file")
        if f is not None and not \
                p.parent.joinpath(*PurePosixPath(str(f)).parts).is_file():
            errors.append(f"observations[{i}].source.file: файл не найден "
                          f"в проекте: {f}")

    if errors:
        raise ProjectError(errors)
    return Project(
        name=name, description=description.strip(), manifest_path=p,
        manifest_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        requires=requires, settings=settings, recordings=recordings,
        schemas=schemas, corpora=corpora, results=results,
        observations=observations)


# ------------------------------------------------------ создание и правка --

def _dump(data: dict) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)


def init_project(dir_path: Union[str, Path], name: str = "madrigal-lab",
                 description: str = "") -> Path:
    """Создать каркас проекта (манифест) в каталоге."""
    d = Path(dir_path)
    d.mkdir(parents=True, exist_ok=True)
    manifest = d / MANIFEST_NAME
    if manifest.exists():
        raise ProjectError([f"манифест уже существует: {manifest}"])
    manifest.write_text(_dump({
        "version": PROJECT_VERSION,
        "name": name,
        "description": description,
        "requires": {"python": ">=3.12", "packages": ["pyyaml>=6.0"]},
        "settings": {"overlap_policy": "first-seen",
                     "directions": ["a2b", "b2a"]},
        "recordings": [],
        "schemas": [],
        "corpora": [],
        "results": [],
        "observations": [],
    }), encoding="utf-8")
    return manifest


def _rel_to(root: Path, file_path: Path) -> str:
    """Относительный POSIX-путь файла внутри проекта (или ошибка)."""
    rel = file_path.resolve().relative_to(root.resolve())
    return "/".join(rel.parts)


def add_recording(project_dir: Union[str, Path], file_path: Union[str, Path],
                  note: str = "") -> Artifact:
    """Зарегистрировать запись в манифесте (вычисляет sha256)."""
    return _add(project_dir, "recordings", file_path, note, with_sha=True)


def add_schema(project_dir: Union[str, Path], file_path: Union[str, Path],
               note: str = "") -> Artifact:
    return _add(project_dir, "schemas", file_path, note, with_sha=True)


def add_corpus(project_dir: Union[str, Path], file_path: Union[str, Path],
               note: str = "") -> Artifact:
    return _add(project_dir, "corpora", file_path, note, with_sha=True)


def add_result(project_dir: Union[str, Path], file_path: Union[str, Path],
               kind: str, note: str = "") -> Artifact:
    if kind not in RESULT_KINDS:
        raise ProjectError([f"kind: ожидается одно из "
                            f"{', '.join(RESULT_KINDS)}"])
    return _add(project_dir, "results", file_path, note, with_sha=False,
                kind=kind)


def _add(project_dir: Union[str, Path], section_name: str,
         file_path: Union[str, Path], note: str, with_sha: bool,
         kind: str = "") -> Artifact:
    project = load_project(project_dir)
    f = Path(file_path)
    if not f.is_file():
        raise ProjectError([f"файл не найден: {f}"])
    try:
        rel = _rel_to(project.root, f)
    except ValueError:
        raise ProjectError([
            f"файл лежит вне каталога проекта ({project.root}): {f} — "
            f"для переносимости всё исследование размещается внутри проекта"])
    sha = hashlib.sha256(f.read_bytes()).hexdigest() if with_sha else ""
    art = Artifact(path=rel, sha256=sha, note=note, kind=kind)

    data = yaml.safe_load(project.manifest_path.read_text(encoding="utf-8"))
    for existing in data.get(section_name) or []:
        if isinstance(existing, dict) and existing.get("path") == rel:
            raise ProjectError([f"{section_name}: {rel} уже зарегистрирован"])
    data.setdefault(section_name, []).append(
        {k: v for k, v in (("path", rel), ("sha256", sha), ("kind", kind),
                           ("note", note)) if v})
    project.manifest_path.write_text(_dump(data), encoding="utf-8")
    return art


def add_observation(project_dir: Union[str, Path], text: str,
                    source: Optional[dict] = None) -> Observation:
    """Дописать наблюдение со связью к источнику (файл/сессия/смещение)."""
    project = load_project(project_dir)
    obs = Observation(text=text, source=dict(source or {}))
    errors: List[str] = []
    parsed = _parse_source(obs.source, "source", errors)
    if errors:
        raise ProjectError(errors)
    obs.source = parsed
    f = parsed.get("file")
    if f is not None and not project.resolve(str(f)).is_file():
        raise ProjectError([f"source.file: файл не найден в проекте: {f}"])

    data = yaml.safe_load(project.manifest_path.read_text(encoding="utf-8"))
    entry: Dict[str, object] = {"text": text}
    if parsed:
        entry["source"] = parsed
    data.setdefault("observations", []).append(entry)
    project.manifest_path.write_text(_dump(data), encoding="utf-8")
    return obs


# ------------------------------------------------------------ проверка ----

def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_project(dir_path: Union[str, Path]) -> dict:
    """Проверить переносимый проект после открытия (R5).

    Возвращает словарь: ошибки формата, целостность файлов (sha256),
    актуальность результатов проверок (устаревшие отличимы от актуальных).
    """
    project = load_project(dir_path)

    errors: List[str] = []
    stale: List[str] = []
    entries: List[dict] = []

    for section_name, items in (("recordings", project.recordings),
                                ("schemas", project.schemas),
                                ("corpora", project.corpora)):
        for a in items:
            fp = project.resolve(a.path)
            actual = _sha(fp)
            ok = actual == a.sha256
            if not ok:
                stale.append(
                    f"{section_name}: {a.path} изменён "
                    f"(заштамповано {a.sha256[:12]}…, сейчас {actual[:12]}…)")
            entries.append({"section": section_name, "path": a.path,
                            "note": a.note, "sha256": actual, "expected":
                                a.sha256, "ok": ok})

    for r in project.results:
        rp = project.resolve(r.path)
        entry = {"section": "results", "path": r.path, "note": r.note,
                 "kind": r.kind, "ok": False, "current": None,
                 "reasons": []}
        if not rp.is_file():
            errors.append(f"results: файл не найден: {r.path}")
            entry["reasons"] = ["файл не найден"]
            entries.append(entry)
            continue
        entry["sha256"] = _sha(rp)
        if r.kind == "corpus-verify":
            # отчёт проверяется механикой stale: поиск манифеста/схемы/записей
            # ищем и в каталогах корпусов проекта — после переноса прежние
            # абсолютные пути не используются
            search_dirs = [project.root]
            for c in project.corpora:
                search_dirs.append(project.resolve(c.path).parent)
            try:
                reasons = check_report(rp, extra_search_dirs=search_dirs)
            except CorpusError as e:
                reasons = list(e.errors)
            entry["reasons"] = reasons
            entry["current"] = not reasons
            entry["ok"] = not reasons
            if reasons:
                stale.append(f"results: {r.path} устарел — "
                             + "; ".join(reasons))
        else:
            entry["current"] = None         # apply-результат не сверяется
            entry["ok"] = True
        entries.append(entry)

    return {
        "project": {"name": project.name,
                    "path": "/".join(project.manifest_path.parts[-2:]),
                    "sha256": project.manifest_sha256,
                    "description": project.description,
                    "requires": project.requires,
                    "settings": project.settings},
        "entries": entries,
        "observations": len(project.observations),
        "errors": errors,
        "stale": stale,
        "ok": not errors and not stale,
    }


def to_json(project: Project) -> dict:
    """Машиночитаемое представление манифеста проекта."""

    def artifact(a: Artifact) -> dict:
        d: Dict[str, object] = {"path": a.path}
        if a.sha256:
            d["sha256"] = a.sha256
        if a.kind:
            d["kind"] = a.kind
        if a.note:
            d["note"] = a.note
        return d

    return {
        "version": PROJECT_VERSION,
        "name": project.name,
        "description": project.description,
        "requires": project.requires,
        "settings": project.settings,
        "recordings": [artifact(a) for a in project.recordings],
        "schemas": [artifact(a) for a in project.schemas],
        "corpora": [artifact(a) for a in project.corpora],
        "results": [artifact(a) for a in project.results],
        "observations": [
            {"text": o.text, **({"source": dict(o.source)} if o.source else {})}
            for o in project.observations],
    }
