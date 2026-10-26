"""GUI tasks: each engine call runs as a task with a state the browser follows.

Reads (discover, validate, plan) run in parallel. A change (apply, delete) holds its Orchestrator's change lock from
start to finish, so a second change on that Orchestrator waits as queued:

  queued -> running (preview) -> awaiting_approval -> applying -> done | failed
                    \\-> failed      \\-> rejected (wrong answer) | expired (no answer in time) | cancelled

A plan ends planned (or failed); discover and validate end done (or failed). Only tasks not yet applying can be cancelled.
"""
import dataclasses
import itertools
import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from . import engine, gui_tables
from .approval import APPROVAL_SECONDS, GuiApprovals
from .config import orchestrator_profiles
from .errors import ApprovalError, ConfigurationError
from .fleet import _gui_settings

READS = {"discover", "validate", "plan"}
CHANGES = {"apply", "delete"}
FINAL = {"planned", "done", "failed", "rejected", "expired", "cancelled"}
_OPEN = {"queued", "running", "awaiting_approval"}


class TaskError(Exception):
    """A task request the GUI refuses; the message is shown as is."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class Task:
    def __init__(self, task_id: str, action: str, orchestrator: str, kind: str, folder: Path) -> None:
        self.id, self.action, self.orchestrator, self.kind, self.folder = task_id, action, orchestrator, kind, folder
        self.state = "queued"
        self.created = time.time()
        self.message = ""
        self.result: Optional[engine.Result] = None
        self.events: List[Dict[str, Any]] = []
        self.answers: Optional[List[str]] = None
        self.typed_orchestrator = ""
        self.understood = False
        self.deadline: Optional[float] = None
        self.cancelled = False
        self._tables: Dict[str, List[Dict[str, Any]]] = {}
        self.changed = threading.Condition()

    def set(self, state: str, message: str = "", result: Optional[engine.Result] = None) -> None:
        with self.changed:
            self.state, self.message = state, message
            if result is not None:
                self.result = result
                self._tables = {}
            self.events.append({"state": state, "message": message, "time": time.time()})
            self.changed.notify_all()

    def view(self) -> Dict[str, Any]:
        """The task as the browser sees it. Issues, changes and rows can run to thousands, so they come a page at a time from table()."""
        result = None
        if self.result is not None:
            found = self.result
            summary = found.summary or {}
            result = {
                "exit_code": found.exit_code,
                "status": found.status,
                "changes_written": found.changes_written,
                "counts": found.counts,
                "warnings": found.warnings,
                "approval": found.approval,
                "run_id": summary.get("run_id", ""),
                "row_outcomes": summary.get("row_outcomes", {}),
                "issues": len(found.issues),
                "changes": len(found.changes),
                "deletes": sum(1 for change in found.changes if change.get("action") == "delete"),
                "rows": len(found.rows),
            }
        return {"id": self.id, "action": self.action, "orchestrator": self.orchestrator, "kind": self.kind, "state": self.state, "message": self.message, "created": self.created, "deadline": self.deadline, "result": result}

    def table(self, name: str) -> List[Dict[str, Any]]:
        """The rows of one of the result's tables (issues, changes, rows), built once per result."""
        if self.result is None:
            return []
        if name not in self._tables:
            build = {"issues": gui_tables.issue_row, "changes": gui_tables.change_row, "rows": gui_tables.outcome_row}[name]
            self._tables[name] = [build(item) for item in getattr(self.result, name)]
        return self._tables[name]


class TaskManager:
    def __init__(self, folder: Optional[str] = None, report_dir: Optional[str] = None, environ: Optional[Mapping[str, str]] = None, approval_seconds: float = APPROVAL_SECONDS) -> None:
        self.folder = Path(folder or tempfile.mkdtemp(prefix="edgeconnect-gui-"))
        self.report_dir = report_dir
        self.environ = environ
        self.approval_seconds = approval_seconds
        self.approvals = GuiApprovals(seconds=approval_seconds)
        self.tasks: Dict[str, Task] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._change_locks: Dict[str, threading.Lock] = {}

    def create(self, request: Mapping[str, Any]) -> Task:
        action = request.get("action")
        if action not in READS | CHANGES:
            raise TaskError("unknown action {!r}; use one of {}".format(action, ", ".join(sorted(READS | CHANGES))))
        orchestrator = self.known_orchestrator(request.get("orchestrator"), writes=action in CHANGES)
        kind = request.get("kind") or ""
        if action in {"plan", "apply", "delete"} and kind not in engine.KINDS:
            raise TaskError("unknown kind {!r}; use one of {}".format(kind, ", ".join(engine.KINDS)))
        with self._lock:
            task_id = "task-{}".format(next(self._ids))
        folder = self.folder / task_id
        folder.mkdir(mode=0o700, parents=True)
        task = Task(task_id, action, orchestrator, kind, folder)
        work = self._prepare(task, request)
        with self._lock:
            self.tasks[task_id] = task
        task.set("queued")
        threading.Thread(target=work, name=task_id, daemon=True).start()
        return task

    def get(self, task_id: str) -> Task:
        task = self.tasks.get(task_id)
        if task is None:
            raise TaskError("no task {}".format(task_id), 404)
        return task

    def list(self) -> List[Task]:
        return sorted(self.tasks.values(), key=lambda task: task.created)

    def discovery(self, task_id: str) -> Mapping[str, Any]:
        """The inventory a finished discover task read."""
        task = self.get(task_id)
        if (task.action, task.state) != ("discover", "done"):
            raise TaskError("task {} is a {} that is {}, not a finished discover".format(task_id, task.action, task.state), 409)
        try:
            return json.loads((task.folder / "discovery.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise TaskError("could not read the inventory of task {}: {}".format(task_id, error), 500) from None

    def table(self, task_id: str, name: str, params: Mapping[str, str]) -> Dict[str, Any]:
        """One page of a task's issues, changes (deletes first) or per-row outcomes."""
        task = self.get(task_id)
        if name == "issues":
            return gui_tables.page(task.table(name), params, ("rule", "column"))
        if name == "changes":
            return gui_tables.page(task.table(name), params, ("action", "type"), default_sort="action")
        return gui_tables.page(task.table(name), params, ("outcome",))

    def approve(self, task_id: str, answers: Any, orchestrator: Any = "", understood: Any = False) -> Task:
        """Hand the typed confirmations, the Orchestrator nickname as typed and, for a delete, the "I understand" tick to a task awaiting approval."""
        task = self.get(task_id)
        if not isinstance(answers, list) or not all(isinstance(answer, str) for answer in answers):
            raise TaskError("answers must be a list of the typed confirmations")
        if not isinstance(orchestrator, str):
            raise TaskError("orchestrator must be the nickname as typed")
        with task.changed:
            if task.state != "awaiting_approval" or task.answers is not None:
                raise TaskError("task {} is {}, not awaiting approval".format(task_id, task.state), 409)
            task.answers, task.typed_orchestrator, task.understood = answers, orchestrator, understood is True
            task.changed.notify_all()
        return task

    def cancel(self, task_id: str) -> Task:
        task = self.get(task_id)
        with task.changed:
            if task.state not in _OPEN or task.answers is not None:
                raise TaskError("task {} is {} and can no longer be cancelled".format(task_id, task.state), 409)
            task.cancelled = True
            task.changed.notify_all()
        return task

    def known_orchestrator(self, name: Any, writes: bool) -> str:
        try:
            profiles = orchestrator_profiles(None, self.environ)
        except ConfigurationError as error:
            raise TaskError(str(error)) from None
        name = name.strip().lower() if isinstance(name, str) else "" if name is None else repr(name)
        if (profiles and name not in profiles) or (not profiles and name):
            raise TaskError("unknown Orchestrator {!r}; configured: {}".format(name, ", ".join(profiles) or "one, unnamed"))
        if writes:
            try:
                allowed = _gui_settings(name, profiles.get(name, {}))["writes"]
            except ConfigurationError as error:
                raise TaskError(str(error)) from None
            if not allowed:
                raise TaskError("GUI writes are off for {0}; set {0}_gui_writes=on in .env to allow them".format(name or "this Orchestrator"), 403)
        return name

    def _csv(self, task: Task, request: Mapping[str, Any]) -> str:
        text = request.get("csv_text")
        if not isinstance(text, str) or not text.strip():
            raise TaskError("csv_text is required")
        path = task.folder / "input.csv"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def _prepare(self, task: Task, request: Mapping[str, Any]) -> Callable[[], None]:
        """Check the request now (so the browser hears about bad input at once) and return the work to run in the task's thread."""
        common = {"orchestrator": task.orchestrator or None, "report_dir": self.report_dir}
        if task.action == "discover":
            return self._read(task, lambda: engine.discover(str(task.folder / "discovery.json"), **common), "done")
        if task.action == "validate":
            csv = self._csv(task, request)
            return self._read(task, lambda: engine.validate(csv, report_dir=self.report_dir), "done")
        if task.action == "plan":
            names = request.get("names") or []
            if task.kind == "zones":
                if not isinstance(names, list) or not names or not all(isinstance(name, str) and name for name in names):
                    raise TaskError("names must list the zones to plan")
                flags: Dict[str, Any] = {"name": names}
            else:
                flags = {"csv": self._csv(task, request)}
            return self._read(task, lambda: engine.plan(task.kind, str(task.folder / "plan.json"), **common, **flags), "planned")
        if task.action == "apply":
            source = self.get(str(request.get("plan_task") or ""))
            if (source.action, source.state, source.kind, source.orchestrator) != ("plan", "planned", task.kind, task.orchestrator):
                raise TaskError("plan_task must be a finished {} plan on the same Orchestrator".format(task.kind))
            plan = str(source.folder / "plan.json")
            return self._change(task, lambda approval, dry_run: engine.apply(task.kind, plan, approval, dry_run, **common))
        csv = self._csv(task, request)
        return self._change(task, lambda approval, dry_run: engine.delete(task.kind, csv, approval, dry_run, **common))

    def _read(self, task: Task, call: Callable[[], engine.Result], success: str) -> Callable[[], None]:
        def work() -> None:
            if task.cancelled:
                return task.set("cancelled")
            task.set("running")
            self._finish(task, call, success)

        return work

    def _change(self, task: Task, call: Callable[[Optional[engine.Approval], bool], engine.Result]) -> Callable[[], None]:
        def work() -> None:
            with self._lock:
                lock = self._change_locks.setdefault(task.orchestrator, threading.Lock())
            while not lock.acquire(timeout=0.2):
                if task.cancelled:
                    return task.set("cancelled", "cancelled while waiting for another change on this Orchestrator")
            try:
                self._run_change(task, call)
            finally:
                lock.release()

        return work

    def _run_change(self, task: Task, call: Callable[[Optional[engine.Approval], bool], engine.Result]) -> None:
        if task.cancelled:
            return task.set("cancelled")
        task.set("running", "building the preview")
        preview = self._call(task, lambda: call(None, True))
        if preview is None:
            return
        if preview.exit_code != 0 or preview.approval is None:
            # Blocked, or nothing to write: the preview is the outcome.
            return task.set("failed" if preview.exit_code else "done", _first_issue(preview) or preview.status, preview)
        task.deadline = time.time() + self.approval_seconds  # for the browser's countdown; the wait below uses the monotonic clock
        task.set("awaiting_approval", "type the confirmations to approve this exact preview", preview)
        deadline = time.monotonic() + self.approval_seconds
        with task.changed:
            while task.answers is None and not task.cancelled and time.monotonic() < deadline:
                task.changed.wait(min(1.0, max(deadline - time.monotonic(), 0.0)))
            answers, cancelled = task.answers, task.cancelled
        if cancelled:
            return task.set("cancelled")
        if answers is None:
            return task.set("expired", "no approval within {:g} minutes; nothing was written".format(self.approval_seconds / 60))
        if task.typed_orchestrator != task.orchestrator:
            # The GUI's own gate: the nickname proves the person looked at which Orchestrator this write goes to.
            return task.set("rejected", "Orchestrator nickname refused (typed {!r}, this write goes to {!r}); nothing was written".format(task.typed_orchestrator, task.orchestrator))
        if task.action == "delete" and not task.understood:
            return task.set("rejected", "you did not confirm you understand what this deletes; nothing was deleted")
        try:
            approval = engine.approve(self.approvals, preview.approval, answers, task.typed_orchestrator)
        except ApprovalError as error:
            return task.set("rejected", "{}; nothing was written".format(error))
        task.deadline = None
        task.set("applying")
        self._finish(task, lambda: call(approval, False), "done")

    def _finish(self, task: Task, call: Callable[[], engine.Result], success: str) -> None:
        result = self._call(task, call)
        if result is not None:
            task.set(success if result.exit_code == 0 else "failed", _first_issue(result) or result.status, result)

    @staticmethod
    def _call(task: Task, call: Callable[[], engine.Result]) -> Optional[engine.Result]:
        try:
            return call()
        except Exception as error:  # the browser must hear about every failure; the run log holds the detail
            task.set("failed", "{}: {}".format(type(error).__name__, error))
            return None


def _first_issue(result: engine.Result) -> str:
    return str(result.issues[0].get("message", "")) if result.issues else ""


def dumps(value: Any) -> bytes:
    return json.dumps(value, default=str, sort_keys=True).encode("utf-8")
