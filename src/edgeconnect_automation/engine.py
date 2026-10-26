"""Python API over the CLI commands, for the GUI.

Each call runs the same command code the CLI runs, in this process with its own RunContext, and returns a Result with
structured issues, counts, per-object changes with field-level diffs, per-row outcomes, and what approving the write
takes. Writes need a GUI approval token; without one a write is refused like a CLI run with no terminal.
"""
import datetime
import getpass
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from .approval import Gate, GuiApprovals
from .cli import RunContext, _context, execute
from .errors import ApprovalError
from .util import fingerprint

KINDS = ("firewall", "template-acls", "zones", "address-groups", "service-groups", "app-groups", "app-definitions")
_PLAN_VERB = {"zones": "plan-missing"}


@dataclass
class Result:
    exit_code: int
    status: str
    changes_written: str
    issues: List[Dict[str, Any]]
    counts: List[str]
    changes: List[Dict[str, Any]]
    rows: List[Dict[str, Any]]
    warnings: List[str]
    approval: Optional[Dict[str, Any]]
    outputs: List[Any] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Approval:
    """A GUI approval token, redeemed against the exact preview the run is about to write and the run's Orchestrator.

    Redeeming it records who approved what in the run's log: the OS user, the time, the fingerprint of the exact preview,
    the Orchestrator, and every confirmation as typed.
    """

    approvals: GuiApprovals
    token: str
    answers: Tuple[str, ...] = ()
    typed_orchestrator: str = ""

    def __call__(self, gates: Sequence[Gate], subject: Any, no_terminal: str) -> None:
        context = _context()
        plan = fingerprint(subject)
        self.approvals.redeem(self.token, plan, context.target_url)
        if context.recorder is not None:
            context.recorder.approval = {
                "by": _os_user(),
                "time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "plan_fingerprint": plan,
                "orchestrator": context.target,
                "orchestrator_id": context.target_id,
                "typed_orchestrator": self.typed_orchestrator,
                "typed": list(self.answers),
            }


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no user name in the environment or the password database; the approval still stands
        return "unknown"


def approve(approvals: GuiApprovals, request: Mapping[str, Any], answers: Sequence[str], typed_orchestrator: str = "") -> Approval:
    """Check the typed answers against a Result.approval request and return the single-use approval for that exact write."""
    gates = [Gate(**gate) for gate in request["gates"]]
    return Approval(approvals, approvals.issue(gates, answers, request["fingerprint"], request["orchestrator"]), tuple(answers), typed_orchestrator)


def _refuse(gates: Sequence[Gate], subject: Any, no_terminal: str) -> None:
    raise ApprovalError("no approval was given for this write")


def run(argv: Sequence[str], approval: Optional[Approval] = None, context: Optional[RunContext] = None) -> Result:
    """Run one CLI command line in-process and return its structured result."""
    context = context or RunContext(source="gui")
    context.approver = approval or _refuse
    # shortcut: the command still prints its usual text to this process's stdout and stderr; capture it per run if the GUI needs it.
    code, summary, context = execute(list(argv), context)
    recorder = context.recorder
    outputs = list(recorder.payloads) if recorder else []
    summary = summary or {}
    request = context.approval_request
    return Result(
        exit_code=code,
        status=str(summary.get("status", "")),
        changes_written=str(summary.get("changes_written", "")),
        issues=_issues(recorder.error if recorder else None, outputs, summary),
        counts=list(summary.get("counts", [])),
        changes=_changes(outputs, request),
        rows=list(summary.get("rows", [])),
        warnings=list(summary.get("warnings", [])),
        approval=None if request is None else {"fingerprint": request["fingerprint"], "orchestrator": context.target_url, "gates": [asdict(gate) for gate in request["gates"]]},
        outputs=outputs,
        summary=summary,
    )


def _globals(orchestrator: Optional[str], report_dir: Optional[str]) -> List[str]:
    return (["--orchestrator", orchestrator] if orchestrator else []) + (["--report-dir", report_dir] if report_dir is not None else [])


def _flags(**flags: Any) -> List[str]:
    argv: List[str] = []
    for name, value in flags.items():
        option = "--" + name.replace("_", "-")
        if value is True:
            argv.append(option)
        elif isinstance(value, (list, tuple)):
            for item in value:
                argv += [option, str(item)]
        elif value not in (None, False):
            argv += [option, str(value)]
    return argv


def discover(output: Optional[str] = None, orchestrator: Optional[str] = None, report_dir: Optional[str] = None, context: Optional[RunContext] = None) -> Result:
    return run(_globals(orchestrator, report_dir) + ["discovery"] + _flags(output=output), context=context)


def validate(csv: str, report_dir: Optional[str] = None, context: Optional[RunContext] = None) -> Result:
    """Check a firewall CSV offline; the other object types are validated by plan."""
    return run(_globals(None, report_dir) + ["firewall", "validate"] + _flags(csv=csv), context=context)


def plan(kind: str, output: str, orchestrator: Optional[str] = None, report_dir: Optional[str] = None, context: Optional[RunContext] = None, **flags: Any) -> Result:
    """Read-only plan saved to output; flags are the command's own options (csv=..., name=[...] for zones, inventory=..., applications=...)."""
    return run(_globals(orchestrator, report_dir) + [kind, _PLAN_VERB.get(kind, "plan")] + _flags(output=output, **flags), context=context)


def apply(kind: str, approved_plan: str, approval: Optional[Approval] = None, dry_run: bool = False, orchestrator: Optional[str] = None, report_dir: Optional[str] = None, context: Optional[RunContext] = None, **flags: Any) -> Result:
    """Apply a saved plan. A dry run returns what approving it takes; a real run needs the approval issued for that plan."""
    return run(_globals(orchestrator, report_dir) + [kind, "apply"] + _flags(approved_plan=approved_plan, dry_run=dry_run, **flags), approval, context)


def delete(kind: str, csv: str, approval: Optional[Approval] = None, dry_run: bool = False, orchestrator: Optional[str] = None, report_dir: Optional[str] = None, context: Optional[RunContext] = None, **flags: Any) -> Result:
    """Delete exactly the CSV-matched objects. A dry run returns the deletion table's approval; a real run needs it."""
    return run(_globals(orchestrator, report_dir) + [kind, "delete"] + _flags(csv=csv, dry_run=dry_run, **flags), approval, context)


def verify(run_id: str, output: Optional[str] = None, orchestrator: Optional[str] = None, report_dir: Optional[str] = None, context: Optional[RunContext] = None) -> Result:
    return run(_globals(orchestrator, report_dir) + ["firewall", "verify"] + _flags(run_id=run_id, output=output), context=context)


def summarize(path: str, last: int = 1) -> List[Dict[str, Any]]:
    """Run summaries (with their per-row tables) read from a saved report, plan, or reports/<workflow>.jsonl log."""
    from .reporting import summaries_from_file

    return summaries_from_file(path, last)


_ISSUE = re.compile(r"^row (?P<row>\d+) \[(?P<rule>[A-Z]+-\d+)\] (?:(?P<column>[\w ]+?)(?:=(?P<value>'.*?'|\".*?\"))?: )?(?P<message>.*?)(?:; fix: (?P<fix>.*?))?(?: \(blocks (?P<blocks>.*)\))?$")


def _issues(error: Any, outputs: Sequence[Any], summary: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Every problem as {row, column, rule, value, message, fix, blocks}; row and rule are None for a problem not tied to a CSV row."""
    found: Dict[str, Dict[str, Any]] = {}

    def add(item: Mapping[str, Any]) -> None:
        issue = {"row": item.get("row"), "column": item.get("field") or item.get("column") or "", "rule": item.get("rule"), "value": item.get("value", ""), "message": item.get("message", ""), "fix": item.get("fix", ""), "blocks": item.get("blocks", "")}
        found.setdefault(fingerprint(issue), issue)

    for item in getattr(error, "issues", None) or []:
        add(item)
    for value in outputs:
        for item in _walk(value):
            for entry in item.get("issues", []) if isinstance(item.get("issues"), list) else []:
                if isinstance(entry, Mapping):
                    add(entry)
    structured = {(issue["row"], issue["rule"]) for issue in found.values()}
    for text in summary.get("blocking_issues", []):
        for line in str(text).splitlines():
            match = _ISSUE.match(line.strip())
            if match:
                parsed = match.groupdict()
                if (int(parsed["row"]), parsed["rule"]) in structured:
                    continue
                add({"row": int(parsed["row"]), "rule": parsed["rule"], "field": parsed["column"] or "", "value": (parsed["value"] or "")[1:-1], "message": parsed["message"], "fix": parsed["fix"] or "", "blocks": parsed["blocks"] or ""})
            elif line.strip():
                add({"message": line.strip()})
    return list(found.values())


def _walk(value: Any, depth: int = 0) -> Iterator[Mapping[str, Any]]:
    if depth > 12:
        return
    if isinstance(value, Mapping):
        yield value
        for item in value.values():
            yield from _walk(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item, depth + 1)


def _flatten(value: Any, prefix: Tuple[str, ...] = ()) -> Dict[Tuple[str, ...], Any]:
    if not prefix and (value is None or value == {}):
        return {}
    if isinstance(value, Mapping) and value:
        flat: Dict[Tuple[str, ...], Any] = {}
        for key, item in value.items():
            flat.update(_flatten(item, prefix + (str(key),)))
        return flat
    return {prefix: value}


def _diff(before: Any, after: Any) -> List[Dict[str, Any]]:
    old, new = _flatten(before), _flatten(after)
    return [{"field": ".".join(path), "before": old.get(path), "after": new.get(path)} for path in sorted(set(old) | set(new)) if old.get(path) != new.get(path)]


def _objects(scope: str, kind: str, before: Any, after: Any, depth: int) -> List[Dict[str, Any]]:
    """Compare two mappings whose keys `depth` levels down are objects; return each created, modified or deleted object."""
    old = {path: value for path, value in _levels(before, depth)}
    new = {path: value for path, value in _levels(after, depth)}
    changes = []
    for path in sorted(set(old) | set(new)):
        if old.get(path) == new.get(path):
            continue
        action = "create" if path not in old else "delete" if path not in new else "modify"
        changes.append({"scope": scope, "type": kind, "object": "/".join(path), "action": action, "fields": _diff(old.get(path), new.get(path))})
    return changes


def _levels(value: Any, depth: int, prefix: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], Any]]:
    if depth == 0:
        yield prefix, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _levels(item, depth - 1, prefix + (str(key),))


def _changes(outputs: Sequence[Any], request: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Per-object create/modify/delete with field-level diffs, from whatever plan or preview the run produced."""
    changes: Dict[str, Dict[str, Any]] = {}

    def add(items: Sequence[Dict[str, Any]]) -> None:
        for item in items:
            changes.setdefault(fingerprint([item["scope"], item["object"], item["action"]]), item)

    for item in (entry for value in outputs for entry in _walk(value)):
        if "pair" in item and isinstance(item.get("baseline"), Mapping) and isinstance(item.get("candidate"), Mapping):
            scope = "{} -> {}".format(*item["pair"])
            add(_objects(scope, "firewall rule", item["baseline"].get("data", {}).get("map1", {}), item["candidate"].get("data", {}).get("map1", {}), 3))
        elif "candidate_acl_value" in item and item.get("eligible", True):
            add(_objects("template group " + str(item.get("template_group")), "access list entry", (item.get("baseline_acl_value") or {}).get("data", {}), (item.get("candidate_acl_value") or {}).get("data", {}), 3))
        elif item.get("kind") in {"zones", "app-groups"} and isinstance(item.get("candidate"), Mapping):
            add(_objects(item["kind"], "zone" if item["kind"] == "zones" else "application group", item.get("baseline") or {}, item["candidate"], 1))
        elif item.get("kind") in {"address-groups", "service-groups"} and isinstance(item.get("new_rows"), list):
            # One CSV row is one rule; rows sharing a Name are the rules of one group.
            groups: Dict[str, Dict[str, Any]] = {}
            for row in item["new_rows"]:
                rules = groups.setdefault(str(row.get("Name", "")), {})
                rules[str(len(rules) + 1)] = {key: value for key, value in row.items() if key != "Name" and not key.startswith("_")}
            kind = item["kind"][:-1].replace("-", " ")
            add([{"scope": item["kind"], "type": kind, "object": name, "action": "create", "fields": _diff({}, {"rule": rules})} for name, rules in groups.items()])
        elif item.get("kind") == "app-definitions" and isinstance(item.get("new"), list):
            add([{"scope": "app-definitions", "type": "application definition", "object": entry.get("name", ""), "action": "create", "fields": _diff({}, entry.get("payload", {}))} for entry in item["new"]])
            appexpress = item.get("appexpress") or {}
            add(_objects("AppExpress", "AppExpress entry", appexpress.get("baseline") or {}, appexpress.get("candidate") or {}, 1))
    subject = (request or {}).get("subject")
    deletes_shown = any(item["action"] == "delete" for item in changes.values())
    if not deletes_shown and isinstance(subject, list) and subject and all(isinstance(row, list) and len(row) == 3 for row in subject):
        add([{"scope": str(identity), "type": str(kind), "object": str(name), "action": "delete", "fields": []} for kind, name, identity in subject])
    return list(changes.values())
