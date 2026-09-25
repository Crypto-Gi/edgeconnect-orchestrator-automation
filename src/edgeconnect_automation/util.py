import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping


_SECRET_KEYS = re.compile(r"(?:api[-_]?key|authorization|cookie|csrf|password|secret|token)", re.I)
_SECRET_TEXT = re.compile(r"(?i)(authorization|x-auth-token|api[-_]?key|password|secret|cookie)\s*[:=]\s*([^\s,;]+)")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): "<REDACTED>" if _SECRET_KEYS.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        return _SECRET_TEXT.sub(lambda match: match.group(1) + "=<REDACTED>", value)
    return value


def safe_report(path: str, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(redact(value), indent=2, ensure_ascii=False) + "\n"
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(str(target), 0o600)


def split_values(value: str) -> Iterable[str]:
    return (part.strip() for part in value.split("|") if part.strip())


def detect_cycle(graph: Mapping[str, Iterable[str]]) -> bool:
    active = set()
    visited = set()

    def visit(node: str) -> bool:
        if node in active:
            return True
        if node in visited:
            return False
        active.add(node)
        for child in graph.get(node, ()):
            if child in graph and visit(child):
                return True
        active.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def semantic_equal(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def normalize_acl_entries(entries: Mapping[str, Any]) -> Dict[str, Any]:
    result = {}
    for priority, value in entries.items():
        if not isinstance(value, Mapping):
            result[str(priority)] = value
            continue
        result[str(priority)] = {str(key): item for key, item in value.items() if key not in {"self", "gms_marked"}}
    return result


def indexed_by_name(items: Iterable[Mapping[str, Any]], key: str = "name") -> Dict[str, Mapping[str, Any]]:
    return {str(item[key]): item for item in items if key in item}
