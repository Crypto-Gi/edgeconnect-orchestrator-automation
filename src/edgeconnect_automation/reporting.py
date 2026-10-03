"""End-of-run summaries and the automatic, append-only report log for every command."""
import datetime
import hashlib
import json
import csv
import os
import re
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from . import __version__
from .util import fingerprint, redact, safe_report

DEFAULT_REPORT_DIR = "reports"
REPORT_DIR_ENV = "EDGECONNECT_REPORT_DIR"

EXIT_MEANING = {
    0: "completed (success, verified no-op, or dry run)",
    1: "unexpected runtime or API error",
    2: "blocked by validation or planning; nothing was written",
    3: "approval refused; nothing was written",
    4: "drift: Orchestrator changed after planning; nothing was written",
    5: "partial: some items were skipped, unverified, or failed",
    130: "interrupted by the operator",
}

NEXT_STEP = {
    "SUCCESS": "Nothing to do.",
    "NO_OP": "Nothing to do; Orchestrator already matches the CSV.",
    "VALID": "Run the same workflow with deploy --dry-run to check it against Orchestrator.",
    "DRY_RUN": "Review the planned changes, then run the same command without --dry-run to apply.",
    "PLANNED": "Review the plan file, then apply it or run deploy.",
    "BLOCKED": "Fix every blocking issue listed above, then rerun the same command with --dry-run.",
    "INVALID": "Fix every issue listed above, then rerun the same command.",
    "REFUSED": "Nothing was written. Rerun and type the exact confirmation text when prompted.",
    "DRIFT": "Orchestrator changed after planning. Rerun the same command to build a fresh plan.",
    "PARTIAL": "Review the unverified or failed items above. Unreachable appliances receive the change when they reconnect; rerun the same command with --dry-run later to confirm.",
    "ZONES_CREATED_RERUN": "Zones were created; firewall rules were not attempted yet. Run the same firewall command again.",
    "INTERRUPTED": "The run was interrupted. If that happened after APPLY, check Orchestrator, then rerun the same command with --dry-run to see the current state.",
    "ERROR": "Read the error above. Rerun with -vv for API details and a traceback.",
}

_ISSUE_KEYS = ("errors", "error", "conflicts", "skipped_conflicts", "missing", "existing_base_zones_missing_segment_mapping")
_WARNING_KEYS = ("warnings",)
_MAX_LINES = 25


class RunRecorder:
    """Collects everything one command prints or writes, so the ending can always be reported."""

    def __init__(self, argv: Sequence[str]) -> None:
        self.run_id = "run-" + uuid.uuid4().hex[:12]
        self.started = datetime.datetime.now().astimezone()
        self.argv = list(argv)
        self.payloads: List[Any] = []
        self.written_paths: List[str] = []
        self.saved: Dict[str, Any] = {}
        self.verbose = 0
        self.orchestrator_release = ""
        self.orchestrator_target = ""
        self.orchestrator_name = ""
        self.orchestrator_url = ""
        self.appliances: Dict[str, str] = {}
        self.error: Optional[BaseException] = None
        self.tool_version = __version__

    def capture(self, value: Any) -> None:
        self.payloads.append(value)

    def saved_report(self, path: str, value: Any) -> None:
        self.capture(value)
        self.written_paths.append(str(path))
        self.saved[str(path)] = value

    def note_appliances(self, items: Any) -> None:
        for item in items if isinstance(items, list) else []:
            if isinstance(item, Mapping):
                key = str(item.get("nePk") or item.get("id") or "")
                name = str(item.get("hostName") or item.get("hostname") or item.get("name") or "")
                if key and name:
                    self.appliances[key] = name


def workflow_name(args: Any) -> str:
    return str(getattr(args, "command", "") or "edgeconnect-auto")


def action_name(args: Any) -> str:
    for key, value in vars(args).items():
        if key.endswith("_command") and value:
            return str(value)
    return ""


def report_dir(args: Any) -> Optional[Path]:
    value = getattr(args, "report_dir", None)
    if value is None:
        value = os.environ.get(REPORT_DIR_ENV, DEFAULT_REPORT_DIR)
    return Path(value) if str(value).strip() else None


def _walk(value: Any, keys: Sequence[str], found: List[str], depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in keys:
                found.extend(_describe(item))
            elif key not in {"baseline", "candidate", "baseline_acl_value", "candidate_acl_value", "payload", "rules", "content", "new_rows", "new", "resolved_rows"}:
                _walk(item, keys, found, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _walk(item, keys, found, depth + 1)


def _describe(item: Any) -> List[str]:
    if item in (None, "", [], {}):
        return []
    if isinstance(item, str):
        return [item]
    if isinstance(item, list):
        return [line for entry in item for line in _describe(entry)]
    if isinstance(item, Mapping):
        if "reason" in item or "message" in item:
            prefix = " ".join(str(part) for part in ("row {}".format(item["row"]) if item.get("row") not in (None, "") else "", item.get("name", "")) if part)
            text = str(item.get("reason") or item.get("message"))
            return ["{}: {}".format(prefix, text) if prefix else text]
        if "segment" in item and "zone" in item:
            return ["zone {} in segment {}".format(item["zone"], item["segment"])]
        return [json.dumps(item, sort_keys=True, default=str)]
    return [str(item)]


def _unique(values: Iterable[str]) -> List[str]:
    seen, result = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _status(recorder: RunRecorder, args: Any, exit_code: int) -> str:
    error = recorder.error
    if error is not None:
        name = type(error).__name__
        if isinstance(error, KeyboardInterrupt):
            return "INTERRUPTED"
        if name == "ApprovalError" or isinstance(error, EOFError):
            return "REFUSED"
        if name == "DriftError":
            return "DRIFT"
        if name in {"ValidationError", "ConfigurationError"}:
            return "INVALID"
        return "ERROR"
    for value in reversed(recorder.payloads):
        if not isinstance(value, Mapping):
            continue
        if value.get("firewall_status") == "NOT_ATTEMPTED_RERUN_REQUIRED" and exit_code == 2:
            return "ZONES_CREATED_RERUN"
        result = value.get("result") if isinstance(value.get("result"), Mapping) else value
        raw = str(result.get("status") or value.get("status") or "").upper()
        if raw in {"BLOCKED", "BLOCKED_SEGMENT_MAPPING"}:
            return "BLOCKED"
        if raw.startswith("DRY_RUN"):
            return "DRY_RUN"
        if raw == "SUCCESS" and _all_no_op(result):
            return "NO_OP"
        if raw in {"SUCCESS", "NO_OP", "PARTIAL", "DRIFT"}:
            return raw
        if raw in {"CRITICAL", "FAILED"}:
            return "PARTIAL"
        if raw == "VALIDATION":
            return "BLOCKED"
        if raw == "VALID":
            return "VALID"
        if raw == "INVALID":
            return "INVALID"
    if exit_code == 2:
        return "BLOCKED"
    if exit_code == 5:
        return "PARTIAL"
    if getattr(args, "dry_run", False):
        return "DRY_RUN"
    if action_name(args) == "plan" or (getattr(args, "output", None) and workflow_name(args) != "discovery"):
        return "PLANNED"
    return "SUCCESS" if exit_code == 0 else "ERROR"


def _all_no_op(result: Mapping[str, Any]) -> bool:
    items = result.get("pairs") if isinstance(result.get("pairs"), list) else result.get("groups") if isinstance(result.get("groups"), list) else []
    return bool(items) and all(str(item.get("status", "")).lower() == "no_op" for item in items if isinstance(item, Mapping))


def _written(status: str, recorder: RunRecorder) -> str:
    if status in {"BLOCKED", "INVALID", "REFUSED", "DRY_RUN", "VALID", "PLANNED", "NO_OP", "DRIFT"}:
        return "no"
    if status in {"SUCCESS", "ZONES_CREATED_RERUN"}:
        return "yes"
    if status == "INTERRUPTED":
        return "unknown; check Orchestrator"
    return "possibly; see the result details" if status == "PARTIAL" else "unknown; check Orchestrator"


def _plan_of(recorder: RunRecorder) -> Mapping[str, Any]:
    for value in reversed(recorder.payloads):
        if isinstance(value, Mapping) and ("preview" in value or "kind" in value):
            preview = value.get("preview", value)
            if isinstance(preview, Mapping):
                plan = preview.get("plan", preview)
                if isinstance(plan, Mapping):
                    return plan
    return {}


def _result_of(recorder: RunRecorder) -> Mapping[str, Any]:
    for value in reversed(recorder.payloads):
        if isinstance(value, Mapping) and isinstance(value.get("result"), Mapping):
            return value["result"]
        if isinstance(value, Mapping) and "status" in value and ("pairs" in value or "groups" in value or "created" in value or "deleted" in value):
            return value
    return {}


def _counts(plan: Mapping[str, Any], result: Mapping[str, Any]) -> List[str]:
    lines = []
    for pair in plan.get("pairs", []) if isinstance(plan.get("pairs"), list) else []:
        rows = len(pair.get("rules", []))
        label = "{} -> {}".format(*pair.get("pair", ["?", "?"]))
        if pair.get("eligible"):
            lines.append("segment pair {}: {} rows, {} to create, {} already present".format(label, rows, len(pair.get("created_priorities", [])), len(pair.get("no_op_rows", []))))
        else:
            lines.append("segment pair {}: BLOCKED by {} issue(s); none of its {} rows will be written".format(label, len(pair.get("errors", [])), rows))
    for group in plan.get("groups", []) if isinstance(plan.get("groups"), list) else []:
        state = "eligible" if group.get("eligible") else "BLOCKED"
        appliance_only = {item.get("acl") for item in group.get("appliance_only_deletions", [])}
        delete_count = len(group.get("deletions", [])) + sum(item.get("acl") in appliance_only for item in group.get("absent", []))
        lines.append("template group {} ({}{}): {} to add, {} to overwrite, {} to delete, {} already present, associated with {}".format(
            group.get("template_group"), state, ", new" if group.get("create") else "", len(group.get("additions", [])), len(group.get("overwrites", [])), delete_count, len(group.get("no_ops", [])), ", ".join(group.get("associations", [])) or "no appliances"))
    if plan.get("kind") == "app-groups" and isinstance(plan.get("candidate"), Mapping) and isinstance(plan.get("baseline"), Mapping):
        lines.append("to create: {}".format(len(set(plan["candidate"]) - set(plan["baseline"]))))
    for key, label in (("new_rows", "to create"), ("new", "to create"), ("delete", "to delete"), ("no_ops", "already present"), ("absent", "already absent"), ("conflicts", "conflicts"), ("skipped_conflicts", "skipped")):
        value = plan.get(key)
        if isinstance(value, list) and (value or key in {"new_rows", "new", "delete"}):
            lines.append("{}: {}".format(label, len(value)))
    if isinstance(plan.get("created"), Mapping) and plan.get("kind") in {"zones", "missing-firewall-zones"}:
        lines.append("zones to create: {}".format(", ".join(sorted(plan["created"])) or "none"))
    for key, label in (("created", "created"), ("deleted", "deleted"), ("unverified", "unverified")):
        value = result.get(key)
        if isinstance(value, list):
            lines.append("{}: {}".format(label, len(value)))
    for pair in result.get("pairs", []) if isinstance(result.get("pairs"), list) else []:
        if isinstance(pair, Mapping):
            pair_status = pair.get("status")
            if pair_status is None and "deleted" in pair:
                pair_status = "success" if pair.get("readback_verified") and pair.get("audit_verified") else "partial"
            text = "result {} -> {}: {}".format(*(list(pair.get("pair", ["?", "?"])) + [pair_status]))
            if pair.get("rollback_status") not in (None, "not_needed"):
                text += " (rollback {})".format(pair["rollback_status"])
            if pair.get("message"):
                text += " - {}".format(pair["message"])
            lines.append(text)
    for group in result.get("groups", []) if isinstance(result.get("groups"), list) else []:
        if isinstance(group, Mapping):
            lines.append("result template group {}: {}{}".format(group.get("template_group"), group.get("status"), " - {}".format(group["error"]) if group.get("error") else ""))
    return lines


def _targets(recorder: RunRecorder, plan: Mapping[str, Any], result: Mapping[str, Any]) -> List[str]:
    states: Dict[str, str] = {}
    for pair in plan.get("pairs", []) if isinstance(plan.get("pairs"), list) else []:
        for target, state in (pair.get("target_states") or {}).items():
            states[target] = state
    for item in list(result.get("pairs", []) or []) + list(result.get("groups", []) or []):
        if isinstance(item, Mapping):
            for target, state in (item.get("targets") or {}).items():
                states[target] = state
    lines = []
    for target, state in sorted(states.items()):
        name = recorder.appliances.get(target)
        lines.append("{}{}: {}".format(target, " ({})".format(name) if name else "", state))
    return lines


def preview_text(value: Any) -> str:
    """Short change table shown before an approval prompt instead of the full JSON preview."""
    preview = value.get("preview", value) if isinstance(value, Mapping) else {}
    plan = preview.get("plan", preview) if isinstance(preview, Mapping) else {}
    issues: List[str] = []
    warnings: List[str] = []
    _walk(value, _ISSUE_KEYS, issues)
    _walk(value, _WARNING_KEYS, warnings)
    bar = "-" * 78
    lines = ["", bar, "PLANNED CHANGES (full preview: add -v, or see the report log after this run)", bar]
    lines += _section("Changes", _counts(plan if isinstance(plan, Mapping) else {}, {}) or ["see full preview"])
    lines += _section("Skipped or blocked items", _unique(issues))
    lines += _section("Warnings (do not block)", _unique(warnings))
    if isinstance(value, Mapping) and value.get("impact"):
        lines += ["", "Impact       : {}".format(value["impact"]), "Recovery     : {}".format(value.get("recovery", ""))]
    lines.append(bar)
    return "\n".join(lines)


_ROW_PREFIX = re.compile(r"^row (\d+) ")
_ROWS_PREFIX = re.compile(r"\bin rows ([\d, ]+)")
_PROBLEMS = ("BLOCKED", "FAILED", "SKIPPED", "NOT WRITTEN", "INVALID", "UNVERIFIED")
ROW_FIELDS = ("row", "item", "scope", "outcome", "reason")


def _errors_by_row(errors: Iterable[Any]) -> Dict[int, List[str]]:
    found: Dict[int, List[str]] = {}
    for error in errors:
        text = str(error)
        match = _ROW_PREFIX.match(text)
        rows = [int(match.group(1))] if match else [int(part) for part in _ROWS_PREFIX.search(text).group(1).replace(" ", "").split(",") if part] if _ROWS_PREFIX.search(text) else []
        for row in rows:
            found.setdefault(row, []).append(_ROW_PREFIX.sub("", text))
    return found


def _row(row: Any, item: Any, scope: str, outcome: str, reason: str = "") -> Dict[str, Any]:
    number = int(row) if str(row).isdigit() else row if row not in (None, "") else ""
    return {"row": number, "item": str(item), "scope": scope, "outcome": outcome, "reason": reason}


def _rejected(item: Mapping[str, Any]) -> Dict[str, List[str]]:
    """{priority: [targets]} for targets whose policy engine refused rules (state 'rejected:<p>,<p>')."""
    found: Dict[str, List[str]] = {}
    for target, state in (item.get("targets") or {}).items():
        if str(state).startswith("rejected:"):
            for priority in str(state)[len("rejected:"):].split(","):
                found.setdefault(priority, []).append(str(target))
    return found


def _rejected_reason(targets: Sequence[str]) -> str:
    return "appliance {} rejected this rule with 'ACL rule has invalid syntax'; it is stored but not enforced".format(", ".join(sorted(targets)))


def _pair_rows(pair: Mapping[str, Any], outcome_after: Mapping[str, Any]) -> List[Dict[str, Any]]:
    label = "{} -> {}".format(*pair.get("pair", ["?", "?"]))
    errors = list(pair.get("errors", []))
    by_row = _errors_by_row(errors)
    pair_level = [error for error in errors if not _ROW_PREFIX.match(str(error)) and not _ROWS_PREFIX.search(str(error))]
    blockers = sorted(by_row)
    no_ops = set(pair.get("no_op_rows", []))
    result = outcome_after.get(label)
    rows, seen = [], set()
    for rule in pair.get("rules", []):
        number = rule.get("row")
        seen.add(number)
        item = "{} (priority {})".format(rule.get("rule_key", ""), rule.get("priority") if rule.get("priority") is not None else "auto")
        scope = "{} | {} -> {}".format(label, rule.get("source_zone", ""), rule.get("destination_zone", ""))
        if number in by_row:
            rows.append(_row(number, item, scope, "BLOCKED", "; ".join(by_row[number])))
        elif errors:
            reason = "segment pair blocked by row {}".format(", ".join(str(row) for row in blockers)) if blockers else "segment pair blocked: {}".format(pair_level[0] if pair_level else "see issues")
            rows.append(_row(number, item, scope, "NOT ATTEMPTED", reason))
        elif number in no_ops:
            rows.append(_row(number, item, scope, "ALREADY PRESENT"))
        elif result is None:
            rows.append(_row(number, item, scope, "WOULD CREATE"))
        else:
            status, message, rejected = result
            if str(rule.get("priority")) in rejected:
                rows.append(_row(number, item, scope, "FAILED", _rejected_reason(rejected[str(rule.get("priority"))])))
                continue
            outcome = {"success": "CREATED", "partial": "CREATED, UNVERIFIED", "failed": "FAILED", "critical": "FAILED", "drift": "NOT WRITTEN", "no_op": "ALREADY PRESENT", "ineligible": "NOT ATTEMPTED"}.get(status, status.upper())
            rows.append(_row(number, item, scope, outcome, message))
    for number in sorted(set(by_row) - seen):
        rows.append(_row(number, "", label, "INVALID", "; ".join(by_row[number])))
    return rows


def _group_rows(group: Mapping[str, Any], outcome_after: Mapping[str, Any]) -> List[Dict[str, Any]]:
    name = str(group.get("template_group", ""))
    errors = list(group.get("errors", []))
    by_row = _errors_by_row(errors)
    result = outcome_after.get(name)
    blockers = ", ".join(str(row) for row in sorted(by_row))
    rows = []
    for key, planned, done in (("additions", "WOULD ADD", "ADDED"), ("overwrites", "WOULD OVERWRITE", "OVERWRITTEN"), ("deletions", "WOULD DELETE", "DELETED"), ("no_ops", "ALREADY PRESENT", "ALREADY PRESENT"), ("absent", "ALREADY ABSENT", "ALREADY ABSENT")):
        for entry in group.get(key, []):
            number = entry.get("row", "")
            item = "{} priority {}".format(entry.get("acl", ""), entry.get("priority", ""))
            appliance_only = {candidate.get("acl") for candidate in group.get("appliance_only_deletions", [])}
            entry_planned, entry_done = ("WOULD DELETE", "DELETED") if key == "absent" and entry.get("acl") in appliance_only else (planned, done)
            if number in by_row:
                rows.append(_row(number, item, name, "BLOCKED", "; ".join(by_row.pop(number))))
            elif errors:
                rows.append(_row(number, item, name, "NOT ATTEMPTED", "template group blocked by {}".format("row " + blockers if blockers else "an issue listed above")))
            elif result is None or key == "no_ops" or key == "absent" and entry_planned == "ALREADY ABSENT":
                rows.append(_row(number, item, name, entry_planned))
            else:
                status, message, rejected = result
                if str(entry.get("priority")) in rejected:
                    rows.append(_row(number, item, name, "FAILED", _rejected_reason(rejected[str(entry.get("priority"))])))
                    continue
                rows.append(_row(number, item, name, {"success": entry_done, "partial": entry_done + ", UNVERIFIED", "drift": "NOT WRITTEN", "no_op": "ALREADY PRESENT"}.get(status, status.upper()), message))
    for number, messages in sorted(by_row.items()):
        rows.append(_row(number, "", name, "BLOCKED", "; ".join(messages)))
    return rows


def row_outcomes(plan: Mapping[str, Any], result: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """One line per CSV row (or object), from the saved plan and result; works on old reports too."""
    rows: List[Dict[str, Any]] = []
    kind = str(plan.get("kind", ""))
    pairs = plan.get("pairs") if isinstance(plan.get("pairs"), list) else []
    delete_plans = plan.get("plans") if isinstance(plan.get("plans"), list) else []
    groups = plan.get("groups") if isinstance(plan.get("groups"), list) else []
    if delete_plans:
        deleted = {str(entry.get("rule_key")) for pair in result.get("pairs", []) or [] if isinstance(pair, Mapping) for entry in pair.get("deleted", []) if isinstance(entry, Mapping)}
        lingering: Dict[str, List[str]] = {}
        for pair in result.get("pairs", []) or []:
            for target, state in ((pair.get("targets") or {}).items() if isinstance(pair, Mapping) else []):
                if str(state).startswith("still_present:"):
                    for priority in str(state).split(":", 1)[1].split(","):
                        lingering.setdefault(priority, []).append(str(target))
        for delete_plan in delete_plans:
            scope = "{} -> {}".format(*delete_plan.get("pair", ["?", "?"]))
            for entry in delete_plan.get("removed", []):
                name = str(entry.get("rule_key", ""))
                left = lingering.get(str(entry.get("priority")), [])
                outcome = "WOULD DELETE" if not result else "DELETE UNVERIFIED" if left or name not in deleted else "DELETED"
                rows.append(_row("", name, "{} | zones {} | priority {}".format(scope, entry.get("zone_key", ""), entry.get("priority", "")), outcome, "still present on appliance {}".format(", ".join(sorted(left))) if left else ""))
        for name in _names(plan.get("absent")):
            rows.append(_row("", name, scope if delete_plans else kind, "ALREADY ABSENT"))
        return rows
    if pairs:
        after = {"{} -> {}".format(*item.get("pair", ["?", "?"])): (str(item.get("status", "")), str(item.get("message") or ""), _rejected(item)) for item in result.get("pairs", []) or [] if isinstance(item, Mapping)}
        for number, messages in sorted(_errors_by_row(plan.get("errors", [])).items()):
            rows.append(_row(number, "", "all segment pairs", "INVALID", "; ".join(messages)))
        for pair in pairs:
            rows.extend(_pair_rows(pair, after))
        return rows
    if groups:
        after = {str(item.get("template_group")): (str(item.get("status", "")), str(item.get("error") or ""), _rejected(item)) for item in result.get("groups", []) or [] if isinstance(item, Mapping)}
        for group in groups:
            rows.extend(_group_rows(group, after))
        return rows
    status = str(result.get("status", "")).lower()
    created = {str(name) for name in _names(result.get("created")) + _names((result.get("application_definitions") or {}).get("created") if isinstance(result.get("application_definitions"), Mapping) else [])}
    unverified = {str(name) for name in _names(result.get("unverified"))}
    deleted = {str(name) for name in _names(result.get("deleted"))}
    seen = set()
    for entry in list(plan.get("new_rows", []) or []) + list(plan.get("new", []) or []):
        if not isinstance(entry, Mapping):
            continue
        name = str(entry.get("Name") or entry.get("name") or "")
        if name in seen:
            continue
        seen.add(name)
        outcome = "WOULD CREATE" if not result else "CREATED, UNVERIFIED" if name in unverified else "CREATED" if name in created or status == "success" else "NOT CREATED"
        rows.append(_row(entry.get("_row") or entry.get("row"), name, kind, outcome, str(result.get("error") or "") if outcome == "NOT CREATED" else ""))
    for name in _names(plan.get("delete")):
        outcome = "WOULD DELETE" if not result else "DELETED" if name in deleted and name not in unverified else "DELETE UNVERIFIED"
        rows.append(_row("", name, kind, outcome))
    for key, outcome in (("no_ops", "ALREADY PRESENT"), ("absent", "ALREADY ABSENT"), ("conflicts", "BLOCKED")):
        for name in _names(plan.get(key)):
            rows.append(_row("", name, kind, outcome, "an existing object with this name differs from the CSV" if key == "conflicts" else ""))
    if kind == "app-groups" and isinstance(plan.get("candidate"), Mapping) and isinstance(plan.get("baseline"), Mapping):
        for name in sorted(set(plan["candidate"]) - set(plan["baseline"])):
            rows.append(_row("", name, kind, "WOULD CREATE" if not result else "CREATED" if status in {"success", "partial"} else status.upper()))
    for entry in plan.get("skipped_conflicts", []) or []:
        if isinstance(entry, Mapping):
            rows.append(_row(entry.get("row"), entry.get("name", ""), kind, "SKIPPED", str(entry.get("reason", ""))))
    return rows


def _rejected_csv_rows(text: str, errors: Mapping[int, Sequence[str]]) -> List[Dict[str, Any]]:
    rows = []
    try:
        records = list(csv.DictReader(text.splitlines()))
    except csv.Error:
        records = []
    blockers = ", ".join(str(number) for number in sorted(errors))
    for number, record in enumerate(records, 2):
        item = str(record.get("rule_key") or record.get("Name") or record.get("ACLName") or "")
        if number in errors:
            rows.append(_row(number, item, "CSV", "INVALID", "; ".join(errors[number])))
        else:
            rows.append(_row(number, item, "CSV", "NOT ATTEMPTED", "CSV blocked by invalid row{} {}".format("s" if len(errors) != 1 else "", blockers)))
    if not records:
        rows.extend(_row(number, "", "CSV", "INVALID", "; ".join(messages)) for number, messages in sorted(errors.items()))
    return rows


def _unattempted_csv_rows(text: str, reason: str) -> List[Dict[str, Any]]:
    try:
        records = list(csv.DictReader(text.splitlines()))
    except csv.Error:
        records = []
    return [_row(number, str(record.get("rule_key") or record.get("Name") or record.get("ACLName") or ""), "CSV", "NOT ATTEMPTED", "command stopped before row processing: " + reason) for number, record in enumerate(records, 2)]


def _fill_row_numbers(rows: List[Dict[str, Any]], text: str) -> None:
    """Some plans only record object names; look their CSV row numbers up by Name."""
    if not any(row["row"] == "" for row in rows):
        return
    try:
        reader = csv.DictReader(text.splitlines())
        numbers: Dict[str, int] = {}
        for index, record in enumerate(reader, 2):
            for key in ("Name", "rule_key"):
                if str(record.get(key) or "").strip():
                    numbers.setdefault(str(record[key]).strip(), index)
    except csv.Error:
        return
    for row in rows:
        if row["row"] == "" and row["item"] in numbers:
            row["row"] = numbers[row["item"]]


def _complete_csv_rows(rows: List[Dict[str, Any]], text: str) -> List[Dict[str, Any]]:
    """Repeat an object outcome for every CSV row that contributes to that object."""
    if not rows:
        return rows
    try:
        records = list(csv.DictReader(text.splitlines()))
    except csv.Error:
        return rows
    by_number = {row["row"] for row in rows if isinstance(row["row"], int)}
    by_item: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        by_item.setdefault(str(row["item"]), row)
    for number, record in enumerate(records, 2):
        if number in by_number:
            continue
        item = str(record.get("rule_key") or record.get("Name") or record.get("ACLName") or "")
        if item in by_item:
            rows.append(dict(by_item[item], row=number))
    return rows


def _names(value: Any) -> List[str]:
    return [str(item.get("name") if isinstance(item, Mapping) else item) for item in value] if isinstance(value, list) else []


def _outcome_totals(rows: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    totals: Dict[str, int] = {}
    for row in rows:
        totals[row["outcome"]] = totals.get(row["outcome"], 0) + 1
    return totals


def rows_table(rows: Sequence[Mapping[str, Any]], limit: Optional[int] = None) -> List[str]:
    ordered = sorted(rows, key=lambda row: (not str(row["outcome"]).startswith(_PROBLEMS), row["row"] if isinstance(row["row"], int) else 10 ** 9))
    shown = list(ordered if limit is None else ordered[:limit])
    widths = [max([len(field)] + [len(str(row[field])) for row in shown]) for field in ("row", "outcome", "item")]
    lines = ["{:<{}}  {:<{}}  {:<{}}  {}".format("ROW", widths[0], "OUTCOME", widths[1], "ITEM", widths[2], "SCOPE / REASON")]
    for row in shown:
        detail = row["scope"] + (" | " + row["reason"] if row["reason"] else "")
        lines.append("{:<{}}  {:<{}}  {:<{}}  {}".format(str(row["row"]), widths[0], row["outcome"], widths[1], row["item"], widths[2], detail))
    if limit is not None and len(ordered) > limit:
        lines.append("... {} more rows in the report log (or: edgeconnect-auto report summarize <file> --rows-csv rows.csv)".format(len(ordered) - limit))
    return lines


def write_rows_csv(path: str, rows: Sequence[Mapping[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, ROW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def build_summary(recorder: RunRecorder, args: Any, exit_code: int) -> Dict[str, Any]:
    status = _status(recorder, args, exit_code)
    plan, result = _plan_of(recorder), _result_of(recorder)
    rows = row_outcomes(plan, result)
    issues: List[str] = []
    warnings: List[str] = []
    for value in recorder.payloads:
        _walk(value, _ISSUE_KEYS, issues)
        _walk(value, _WARNING_KEYS, warnings)
    counts = _counts(plan, result)
    csv_path = getattr(args, "csv", None)
    csv_info: Dict[str, Any] = {}
    if csv_path and Path(csv_path).is_file():
        data = Path(csv_path).read_bytes()
        csv_info = {"path": str(csv_path), "sha256": hashlib.sha256(data).hexdigest(), "data_rows": max(len(data.decode("utf-8-sig", "replace").splitlines()) - 1, 0)}
        csv_text = data.decode("utf-8-sig", "replace")
        _fill_row_numbers(rows, csv_text)
        rows = _complete_csv_rows(rows, csv_text)
    if recorder.error is not None:
        error = recorder.error
        lines = [line for line in (str(redact(str(error))) or type(error).__name__).splitlines() if line.strip()]
        issues[:0] = ["{}: {}".format(type(error).__name__, lines[0])] + lines[1:]
        by_row = _errors_by_row(lines)
        csv_text = data.decode("utf-8-sig", "replace") if csv_path and Path(csv_path).is_file() else ""
        if by_row and not rows:
            rows = _rejected_csv_rows(csv_text, by_row)
            counts.append("CSV rejected: {} invalid row(s), {} valid row(s) not attempted; nothing was written".format(len(by_row), len(rows) - len(by_row)))
        elif not rows and csv_text:
            rows = _unattempted_csv_rows(csv_text, lines[0])
            counts.append("command stopped before processing any row; {} row(s) not attempted".format(len(rows)))
    return {
        "run_id": recorder.run_id,
        "timestamp": recorder.started.isoformat(timespec="seconds"),
        "duration_seconds": round((datetime.datetime.now().astimezone() - recorder.started).total_seconds(), 1),
        "tool_version": recorder.tool_version,
        "orchestrator_release": recorder.orchestrator_release or "not contacted",
        "orchestrator_target": recorder.orchestrator_target,
        "orchestrator": recorder.orchestrator_name or ("unnamed" if recorder.orchestrator_url else "not contacted"),
        "orchestrator_url": recorder.orchestrator_url or "not contacted",
        "workflow": " ".join(part for part in (workflow_name(args), action_name(args)) if part),
        "command": "edgeconnect-auto " + " ".join(recorder.argv),
        "dry_run": bool(getattr(args, "dry_run", False)),
        "csv": csv_info,
        "status": status,
        "changes_written": "no" if workflow_name(args) in {"discovery", "report"} else _written(status, recorder),
        "exit_code": exit_code,
        "exit_meaning": EXIT_MEANING.get(exit_code, "unknown"),
        "counts": counts,
        "row_outcomes": _outcome_totals(rows),
        "rows": rows,
        "blocking_issues": _named(recorder, _unique(issues)),
        "warnings": _named(recorder, _unique(warnings)),
        "targets": _targets(recorder, plan, result),
        "run_reference": result.get("run_reference", ""),
        "next_step": _next_step(status, result),
    }


def _named(recorder: RunRecorder, lines: Sequence[str]) -> List[str]:
    result = []
    for line in lines:
        for target, name in recorder.appliances.items():
            line = line.replace("target {} ".format(target), "target {} ({}) ".format(target, name))
        result.append(line)
    return result


def _next_step(status: str, result: Mapping[str, Any]) -> str:
    rollbacks = [pair.get("rollback_status") for pair in result.get("pairs", []) or [] if isinstance(pair, Mapping)]
    if any(state in {"unresolved", "unverified"} for state in rollbacks):
        return "URGENT: automatic rollback did not verify. Compare the segment pair with the baseline in the report log and restore it manually before any other change."
    if any(_rejected(item) for key in ("pairs", "groups") for item in result.get(key, []) or [] if isinstance(item, Mapping)):
        return "Rows marked FAILED were rejected by the appliance and are not enforced. Correct them (see each reason), remove them with the matching delete command, then deploy the corrected CSV."
    return NEXT_STEP.get(status, NEXT_STEP["ERROR"])


def _section(title: str, lines: Sequence[str]) -> List[str]:
    if not lines:
        return []
    shown = list(lines[:_MAX_LINES])
    if len(lines) > _MAX_LINES:
        shown.append("... {} more in the report log".format(len(lines) - _MAX_LINES))
    return ["", title] + ["  - " + line for line in shown]


def render(summary: Mapping[str, Any], title: str = "RUN SUMMARY", row_limit: Optional[int] = _MAX_LINES) -> str:
    bar = "=" * 78
    csv_info = summary.get("csv") or {}
    lines = [
        "", bar, title, bar,
        "Workflow     : {}".format(summary["workflow"]),
        "Run          : {}  at {}{}".format(summary["run_id"], summary["timestamp"], "" if summary.get("duration_seconds") is None else "  ({}s)".format(summary["duration_seconds"])),
        "Versions     : tool {}, Orchestrator {}".format(summary["tool_version"], summary["orchestrator_release"]),
    ]
    if summary.get("orchestrator_target"):
        lines.append("Orchestrator : {}".format(summary["orchestrator_target"]))
    if csv_info:
        lines.append("CSV          : {} ({} data rows, sha256 {}...)".format(csv_info["path"], csv_info["data_rows"], csv_info["sha256"][:12]))
    lines += [
        "RESULT       : {}".format(summary["status"]),
        "Changes made : {}".format(summary["changes_written"]),
        "Exit code    : {} = {}".format(summary["exit_code"], summary["exit_meaning"]),
    ]
    if summary.get("run_reference"):
        lines.append("Run ref      : {} (matches Orchestrator audit log comments)".format(summary["run_reference"]))
    lines += _section("What was planned or done", summary.get("counts", []))
    if summary.get("rows"):
        totals = ", ".join("{} {}".format(count, outcome) for outcome, count in sorted(summary.get("row_outcomes", {}).items()))
        lines += ["", "Rows ({}): {}".format(len(summary["rows"]), totals)] + ["  " + line for line in rows_table(summary["rows"], row_limit)]
    lines += _section("Why it stopped or what failed" if summary["status"] not in {"SUCCESS", "NO_OP", "DRY_RUN", "VALID", "PLANNED"} else "Issues", summary.get("blocking_issues", []))
    lines += _section("Warnings (do not block)", summary.get("warnings", []))
    lines += _section("Appliances", summary.get("targets", []))
    for path in summary.get("reports", []):
        lines.append("Report       : {}".format(path))
    lines += ["", "Next step    : {}".format(summary["next_step"]), bar]
    return "\n".join(lines)


_LEGACY_EXIT = {"SUCCESS": 0, "NO_OP": 0, "DRY_RUN": 0, "VALID": 0, "DRY_RUN_MISSING_ZONES": 2, "BLOCKED": 2, "BLOCKED_SEGMENT_MAPPING": 2, "VALIDATION": 2, "INVALID": 2, "DRIFT": 4, "PARTIAL": 5, "CRITICAL": 5, "FAILED": 5}


def summaries_from_file(path: str, last: int = 1) -> List[Dict[str, Any]]:
    """Summaries for a saved --report file, a plan file, or the last runs of a .jsonl report log."""
    text = Path(path).read_text(encoding="utf-8-sig")
    try:
        values = [json.loads(text)]
    except json.JSONDecodeError:
        values = [json.loads(line) for line in text.splitlines() if line.strip()]
    values = values[-last:] if last > 0 else values
    return [_summary_of(value, path) for value in values]


def _summary_of(value: Any, path: str) -> Dict[str, Any]:
    if isinstance(value, Mapping) and isinstance(value.get("summary"), Mapping):
        summary = dict(value["summary"])
        if "rows" not in summary:
            recorder = RunRecorder([])
            recorder.payloads = list(value.get("outputs", [])) or [value]
            summary["rows"] = row_outcomes(_plan_of(recorder), _result_of(recorder))
            summary["row_outcomes"] = _outcome_totals(summary["rows"])
        return summary
    recorder = RunRecorder([])
    recorder.payloads = [value]
    recorder.run_id = "file " + Path(path).name
    recorder.started = datetime.datetime.fromtimestamp(Path(path).stat().st_mtime).astimezone()
    recorder.tool_version = "unknown (report written by an older version)"
    preview = value.get("preview", value) if isinstance(value, Mapping) else {}
    kind = str(preview.get("kind", "") if isinstance(preview, Mapping) else "")
    result = value.get("result") if isinstance(value, Mapping) and isinstance(value.get("result"), Mapping) else {}
    raw = str(result.get("status") or (value.get("status") if isinstance(value, Mapping) else "") or "").upper()
    args = SimpleNamespace(command=re.sub(r"-delete$", "", kind) or "report", dry_run=raw.startswith("DRY_RUN"), report=None, csv=None, output=None, report_dir="")
    summary = build_summary(recorder, args, _LEGACY_EXIT.get(raw, 0 if raw else 1))
    summary.update(command="not recorded in this report", duration_seconds=None, orchestrator_release=summary["orchestrator_release"].replace("not contacted", "not recorded"), orchestrator=summary["orchestrator"].replace("not contacted", "not recorded"), orchestrator_url=summary["orchestrator_url"].replace("not contacted", "not recorded"), exit_meaning=summary["exit_meaning"] + " (derived from the report status)")
    return summary


def _headline(summary: Mapping[str, Any]) -> Dict[str, Any]:
    """The same top-level fields, with the same status words, in every report file and log record."""
    return {key: summary.get(key, "not recorded") for key in ("status", "exit_code", "changes_written", "timestamp", "run_id", "workflow", "orchestrator", "orchestrator_url")}


def _append(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(text)


def finish(recorder: RunRecorder, args: Any, exit_code: int) -> Dict[str, Any]:
    """Write the log entry and any missing --report file, then print the summary to stderr."""
    summary = build_summary(recorder, args, exit_code)
    directory = report_dir(args)
    name = workflow_name(args)
    explicit = getattr(args, "report", None)
    reports = ([str(explicit)] if explicit else []) + ([str(directory / "{}.jsonl".format(name)), str(directory / "{}.log".format(name))] if directory is not None else [])
    summary["reports"] = reports
    try:
        if directory is not None:
            record = redact(dict(_headline(summary), summary=summary, outputs=recorder.payloads, files_written=recorder.written_paths))
            record["report_fingerprint"] = fingerprint(record)
            _append(directory / "{}.jsonl".format(name), json.dumps(record, ensure_ascii=False, default=str) + "\n")
        if explicit:
            saved = recorder.saved.get(str(explicit))
            value = dict(saved) if isinstance(saved, Mapping) else {"outputs": recorder.payloads}
            if "status" in value and value["status"] != summary["status"]:
                value["detail_status"] = value["status"]
            value.update(_headline(summary), summary=summary)
            value = redact(value)
            value["report_fingerprint"] = fingerprint({key: item for key, item in value.items() if key != "report_fingerprint"})
            safe_report(explicit, value)
        text = render(summary)
        if directory is not None:
            _append(directory / "{}.log".format(name), render(summary, row_limit=None) + "\n")
    except OSError as error:
        summary["reports"] = reports
        text = render(summary) + "\nWARNING: could not write the report log: {}".format(error)
    print(text, file=sys.stderr)
    return summary
