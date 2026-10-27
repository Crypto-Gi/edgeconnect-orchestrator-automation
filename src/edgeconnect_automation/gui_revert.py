"""Undo an upload made in the GUI: a delete CSV of exactly what that upload created, kept with its run.

The revert itself is an ordinary delete task, so it goes through the same preview, tick box and typed gates as Remove
by CSV, and the delete commands still refuse anything that no longer matches the CSV exactly.
"""
import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Set, Tuple

CREATED = {"CREATED", "CREATED, UNVERIFIED", "ADDED", "ADDED, UNVERIFIED"}
# Outcomes that changed something that existed before: deleting what the upload added would not bring that back.
REPLACED = {"OVERWRITTEN", "OVERWRITTEN, UNVERIFIED", "DELETED", "DELETED, UNVERIFIED"}
_NAME_COLUMNS = ("rule_key", "Name", "ACLName")
_GROUPS = {"address-groups", "service-groups"}
# The run summary reads these results as empty, so what they created comes from the plan.
_FROM_PLAN = {"app-definitions", "app-groups"}
_PRIORITY = re.compile(r"\(priority (\d+)\)$")


def build(kind: str, orchestrator: str, csv_text: str, rows: Iterable[Mapping[str, Any]], plan: Optional[Mapping[str, Any]] = None, status: str = "") -> Dict[str, Any]:
    """What Revert needs for one upload: the delete CSV of the rows it created, or why it cannot be reverted here.

    rows are the run summary's row outcomes, plan the approved plan and status the run's result (SUCCESS, PARTIAL...).
    """
    value: Dict[str, Any] = {"kind": kind, "orchestrator": orchestrator, "csv_text": "", "count": 0, "reason": ""}
    rows = list(rows)
    plan = plan or {}
    plan = plan["plan"] if isinstance(plan.get("plan"), Mapping) else plan
    created = [row for row in rows if str(row.get("outcome")) in CREATED]
    if kind == "zones":
        value["reason"] = "Zones cannot be deleted by this tool, so this upload cannot be undone here."
    elif any(str(row.get("outcome")) in REPLACED for row in rows):
        value["reason"] = "This upload replaced or removed entries that already existed. Deleting what it added would not bring those back, so it cannot be undone here."
    elif _changed_settings(kind, plan):
        value["reason"] = _changed_settings(kind, plan)
    elif kind in _FROM_PLAN and not created and status.upper() != "SUCCESS":
        # The run summary cannot say which of these were written, so only a complete upload is undone from its plan.
        value["reason"] = "This upload did not complete, so what it created is not known exactly. Use Remove by CSV with the rows you want deleted."
    else:
        numbers: Dict[Any, Any] = {row["row"]: _PRIORITY.search(str(row.get("item"))) for row in created if isinstance(row.get("row"), int)}
        names = {str(row.get("item")) for row in created if not isinstance(row.get("row"), int)}
        if kind in _GROUPS:
            # A group's later rows have no outcome of their own: keep every row with a created group's name.
            numbers, names = {}, {str(row.get("item")) for row in created}
        elif kind == "app-definitions":
            numbers, names = {entry.get("row"): None for entry in plan.get("new", []) if isinstance(entry, Mapping) and isinstance(entry.get("row"), int)}, set()
        elif kind == "app-groups":
            numbers, names = {}, names | (set(plan.get("candidate") or {}) - set(plan.get("baseline") or {}))
        priorities = {number: int(found.group(1)) for number, found in numbers.items() if found}
        value["csv_text"], value["count"] = _keep(csv_text, set(numbers), names, priorities, kind == "firewall")
        if not value["count"]:
            value["reason"] = "This upload created nothing, so there is nothing to undo."
    return value


def _changed_settings(kind: str, plan: Mapping[str, Any]) -> str:
    """Why this upload cannot be undone because it also changed settings that a delete does not restore, or ""."""
    if kind == "template-acls":
        for group in plan.get("groups", []) or []:
            if isinstance(group, Mapping) and any(group.get(key) for key in ("create", "selection_change", "template_mode_change")):
                return ("This upload also created template group {} or turned on its Access Lists template or merge mode. Deleting the entries would not undo that, "
                        "so it cannot be undone here.").format(group.get("template_group", ""))
    express = plan.get("appexpress") if kind == "app-definitions" else None
    if isinstance(express, Mapping):
        before = {str(entry.get("name", key)).lower() for key, entry in (express.get("baseline") or {}).items() if isinstance(entry, Mapping)}
        if express.get("off") or any(str(name).lower() in before for name in express.get("monitor") or []):
            return "This upload also changed AppExpress entries that already existed. Deleting what it created would not bring those back, so it cannot be undone here."
    return ""


def _keep(text: str, numbers: Set[int], names: Set[str], priorities: Mapping[int, int], count_blank: bool) -> Tuple[str, int]:
    """The CSV with only the data rows whose number or name is listed.

    Rows are numbered from 2 as the parsers number them: the firewall parser counts empty lines, the others skip them.

    A firewall row left to automatic priority gets the priority it was created at, since a delete needs it.
    """
    records = [record for record in csv.reader(io.StringIO(text.lstrip("\ufeff"), newline="")) if record or count_blank]
    if not records:
        return "", 0
    header, kept = records[0], []
    names_in = [name.strip() for name in header]
    columns = [names_in.index(name) for name in _NAME_COLUMNS if name in names_in]
    priority = names_in.index("priority") if "priority" in names_in else None
    for number, record in enumerate(records[1:], 2):
        if not record:
            continue
        if number in numbers or any(index < len(record) and record[index].strip() in names for index in columns):
            if priority is not None and number in priorities and priority < len(record) and not record[priority].strip():
                record[priority] = str(priorities[number])
            kept.append(record)
    if not kept:
        return "", 0
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows([header] + kept)
    return out.getvalue(), len(kept)


def path(folder: Path, run_id: str) -> Path:
    return folder / "revert" / "{}.json".format(run_id)


def save(folder: Path, run_id: str, value: Mapping[str, Any]) -> None:
    target = path(folder, run_id)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle)


def load(folder: Optional[Path], run_id: str) -> Optional[Dict[str, Any]]:
    if folder is None or not run_id.replace("-", "").isalnum():
        return None
    try:
        value = json.loads(path(folder, run_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None
