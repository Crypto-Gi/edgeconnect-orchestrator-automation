"""The GUI's tables: the run log, each run's per-row outcomes, and the discovered inventory.

Python searches, filters, sorts and pages every table, so the browser only ever holds one page (the run log can have
tens of thousands of runs). Run summaries come from reporting's own reader, so each table shows what
`report summarize` prints for the same file, and the row CSV is the one `report summarize --rows-csv` writes.
"""
import json
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .reporting import _PROBLEMS, ROW_FIELDS, _summary_of, csv_text

PAGE_SIZES = (25, 50, 100, 200)
OK_STATUSES = {"SUCCESS", "NO_OP", "DRY_RUN", "VALID", "PLANNED"}
RUN_FIELDS = ("timestamp", "orchestrator", "workflow", "status", "changes_written", "row_outcomes", "duration_seconds", "source", "run_id")
RUN_FILTERS = ("orchestrator", "workflow", "status", "source")


def select(rows: Sequence[Dict[str, Any]], params: Mapping[str, str], filters: Sequence[str] = (), default_sort: str = "", descending: bool = False) -> Tuple[List[Dict[str, Any]], str, str]:
    """Search (rows' "_text"), filter (exact match on each named field, plus "problems") and sort; returns (rows, sort, order)."""
    query = params.get("q", "").strip().lower()
    chosen = [row for row in rows if (not query or query in row["_text"]) and (params.get("problems") != "1" or row["_problem"])]
    for name in filters:
        if params.get(name):
            chosen = [row for row in chosen if str(row.get(name, "")) == params[name]]
    columns = {key for row in rows[:1] for key in row if not key.startswith("_")}
    sort = params.get("sort") if params.get("sort") in columns else default_sort
    order = params.get("order") if params.get("order") in ("asc", "desc") else ("desc" if descending else "asc")
    if sort:
        key = "_sort_" + sort if rows and "_sort_" + sort in rows[0] else sort
        filled = [row for row in chosen if row.get(key) not in (None, "")]
        empty = [row for row in chosen if row.get(key) in (None, "")]
        chosen = sorted(filled, key=lambda row: _sort_key(row[key]), reverse=order == "desc") + empty  # blanks last either way
    return chosen, sort, order


def page(rows: Sequence[Dict[str, Any]], params: Mapping[str, str], filters: Sequence[str] = (), default_sort: str = "", descending: bool = False) -> Dict[str, Any]:
    """One page of select(). Facets list each filter's values across all rows, so a filter never hides its own choices."""
    chosen, sort, order = select(rows, params, filters, default_sort, descending)
    size = _integer(params.get("size"), 50)
    size = size if size in PAGE_SIZES else 50
    pages = max((len(chosen) + size - 1) // size, 1)
    number = min(max(_integer(params.get("page"), 1), 1), pages)
    return {
        "total": len(rows),
        "matching": len(chosen),
        "page": number,
        "pages": pages,
        "size": size,
        "sort": sort,
        "order": order,
        "facets": {name: sorted({str(row.get(name, "")) for row in rows}) for name in filters},
        "rows": public(chosen[(number - 1) * size:number * size]),
    }


def public(rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [{key: value for key, value in row.items() if not key.startswith("_")} for row in rows]


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sort_key(value: Any) -> Tuple[int, Any]:
    """Numbers (and numeric text such as zone IDs) in number order, before text in case-insensitive order."""
    if isinstance(value, str) and value.isdigit():
        return (0, int(value))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return (1, str(value).lower())
    return (0, value)


def _text(values: Iterable[Any]) -> str:
    return " ".join(str(value) for value in values if value not in (None, "")).lower()


def outcome_text(totals: Mapping[str, int]) -> str:
    """Row outcome counts as `report summarize` prints them."""
    return ", ".join("{} {}".format(count, outcome) for outcome, count in sorted(totals.items()))


def run_row(summary: Mapping[str, Any]) -> Dict[str, Any]:
    totals = summary.get("row_outcomes") or {}
    problem = summary.get("status") not in OK_STATUSES or any(outcome in _PROBLEMS for outcome in totals)
    row = {key: summary.get(key, "not recorded") for key in RUN_FIELDS}
    row.update(row_outcomes=outcome_text(totals), rows=len(summary.get("rows") or []), exit_code=summary.get("exit_code"), tone="bad" if problem else "ok")
    row.update(
        _problem=problem,
        _sort_row_outcomes=row["rows"],
        _text=_text([row[key] for key in RUN_FIELDS] + [summary.get("command"), summary.get("orchestrator_url"), (summary.get("csv") or {}).get("path")] + list(summary.get("blocking_issues") or [])),
    )
    return row


def outcome_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    problem = row.get("outcome") in _PROBLEMS
    return dict({key: row.get(key, "") for key in ROW_FIELDS}, tone="bad" if problem else "ok", _problem=problem, _text=_text(row.get(key) for key in ROW_FIELDS))


ISSUE_FIELDS = ("row", "column", "rule", "value", "message", "fix", "blocks")
_ACTION_ORDER = {"delete": 0, "modify": 1, "create": 2}


def issue_row(issue: Mapping[str, Any]) -> Dict[str, Any]:
    row = {key: issue.get(key) if issue.get(key) is not None else "" for key in ISSUE_FIELDS}
    return dict(row, _problem=True, _text=_text(row.values()))


def change_row(change: Mapping[str, Any]) -> Dict[str, Any]:
    """One object a write creates, modifies or deletes, with its field-level diff; deletes sort first."""
    fields = list(change.get("fields") or [])
    row = {"action": change.get("action", ""), "type": change.get("type", ""), "scope": change.get("scope", ""), "object": change.get("object", ""), "fields": fields}
    return dict(
        row,
        _problem=row["action"] == "delete",
        _sort_action="{}|{}|{}|{}".format(_ACTION_ORDER.get(row["action"], 3), row["type"], row["scope"], row["object"]),
        _text=_text([row["action"], row["type"], row["scope"], row["object"]] + [part for item in fields for part in (item.get("field"), item.get("before"), item.get("after"))]),
    )


def to_csv(rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> bytes:
    """The same CSV that reporting.write_rows_csv writes, as bytes for a download."""
    return csv_text(rows, fields).encode("utf-8")


class RunLog:
    """Every run in the report folder's *.jsonl logs. A log file is read again only when its size or time changes."""

    def __init__(self, directory: Optional[Path]) -> None:
        self.directory = directory
        self._files: Dict[Path, Tuple[Tuple[int, int], List[Dict[str, Any]], int]] = {}
        self._lock = threading.Lock()

    def load(self) -> Tuple[List[Dict[str, Any]], int]:
        """(run summaries newest first, number of log lines that could not be read)."""
        if self.directory is None or not self.directory.is_dir():
            return [], 0
        summaries: List[Dict[str, Any]] = []
        unreadable = 0
        with self._lock:
            paths = sorted(self.directory.glob("*.jsonl"))
            self._files = {path: entry for path, entry in self._files.items() if path in paths}
            for path in paths:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                stamp = (stat.st_mtime_ns, stat.st_size)
                if path not in self._files or self._files[path][0] != stamp:
                    self._files[path] = (stamp,) + _read(path)
                summaries += self._files[path][1]
                unreadable += self._files[path][2]
        summaries.sort(key=lambda summary: str(summary.get("timestamp", "")), reverse=True)
        return summaries, unreadable

    def runs(self) -> Tuple[List[Dict[str, Any]], int]:
        summaries, unreadable = self.load()
        return [summary["_row"] for summary in summaries], unreadable

    def find(self, run_id: str) -> Optional[Dict[str, Any]]:
        return next((summary for summary in self.load()[0] if summary.get("run_id") == run_id), None)


def _read(path: Path) -> Tuple[List[Dict[str, Any]], int]:
    """Each log line as its run summary, with its table rows built once; a half-written or damaged line is counted, not fatal."""
    summaries, unreadable = [], 0
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        return [], 1
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            summary = _summary_of(json.loads(line), str(path))
        except (ValueError, TypeError, KeyError, AttributeError):
            unreadable += 1
            continue
        if not str(summary.get("run_id", "")).startswith("run-"):
            # Records from versions without a run ID all read as "file <name>"; give each one an ID a link can name.
            summary["run_id"] = "{}-line-{}".format(path.stem, number)
        summary.setdefault("source", "not recorded")
        summary["_row"] = run_row(summary)
        summary["_outcomes"] = [outcome_row(row) for row in summary.get("rows") or []]
        summaries.append(summary)
    return summaries, unreadable


def run_detail(summary: Mapping[str, Any], params: Mapping[str, str]) -> Dict[str, Any]:
    """One run's summary (as `report summarize` shows it) and one page of its per-row table."""
    headline = {key: value for key, value in summary.items() if key not in ("rows",) and not key.startswith("_")}
    headline["row_outcomes_text"] = outcome_text(summary.get("row_outcomes") or {})
    headline["tone"] = summary["_row"]["tone"]
    return {"run": headline, "rows": page(summary["_outcomes"], params, ("outcome",))}


# Inventory: the tables a discovery run returns, one tab each.
INVENTORY_TABS = (("segments", "Segments"), ("zones", "Zones"), ("segment_zones", "Zones per segment"), ("address_groups", "Address groups"), ("service_groups", "Service groups"))


def _named_map(value: Any) -> List[Dict[str, Any]]:
    """{id: {"name": ...}} as rows of id and name."""
    if not isinstance(value, Mapping):
        return []
    return [{"id": key, "name": item.get("name", "") if isinstance(item, Mapping) else str(item)} for key, item in value.items()]


def _join(values: Any) -> str:
    return ", ".join(str(value) for value in values) if isinstance(values, list) else "" if values is None else str(values)


def _groups(value: Any, fields: Sequence[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """One row per group, each field joining that field across the group's rules."""
    rows = []
    for group in value if isinstance(value, list) else []:
        if not isinstance(group, Mapping):
            continue
        rules = [rule for rule in group.get("rules") or [] if isinstance(rule, Mapping)]
        row: Dict[str, Any] = {"name": group.get("name", ""), "rules": len(rules)}
        for column, key in fields:
            row[column] = "; ".join(text for text in (_join(rule.get(key)) for rule in rules) if text)
        rows.append(row)
    return rows


def inventory_tables(discovery: Mapping[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    segment_zones = discovery.get("segment_zones")
    tables = {
        "segments": _named_map(discovery.get("segments")),
        "zones": _named_map(discovery.get("zones")),
        "segment_zones": [{"segment": item.get("vrfName", ""), "zone": item.get("zoneName", ""), "zone_id": item.get("zoneId", "")} for item in segment_zones if isinstance(item, Mapping)] if isinstance(segment_zones, list) else [],
        "address_groups": _groups(discovery.get("address_groups"), (("included_ips", "includedIPs"), ("excluded_ips", "excludedIPs"), ("included_groups", "includedGroups"), ("comment", "comment"))),
        "service_groups": _groups(discovery.get("service_groups"), (("protocol", "protocol"), ("included_ports", "includedPorts"), ("excluded_ports", "excludedPorts"), ("included_groups", "includedGroups"), ("comment", "comment"))),
    }
    for rows in tables.values():
        for row in rows:
            row.update(_problem=False, _text=_text(row.values()))
    return tables


def inventory_page(discovery: Mapping[str, Any], params: Mapping[str, str]) -> Dict[str, Any]:
    tables = inventory_tables(discovery)
    tab = params.get("tab") if params.get("tab") in tables else INVENTORY_TABS[0][0]
    return {
        "tabs": [{"id": key, "label": label, "count": len(tables[key])} for key, label in INVENTORY_TABS],
        "tab": tab,
        "release": str((discovery.get("version") or {}).get("release", "")) if isinstance(discovery.get("version"), Mapping) else "",
        "table": page(tables[tab], params, default_sort="name" if tab != "segment_zones" else "segment"),
    }
