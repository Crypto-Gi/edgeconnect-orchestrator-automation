"""Approval gates shared by the terminal and the GUI.

A gate is one exact phrase a person must type before a write. The terminal asks for each gate in turn; the GUI collects
the same answers and exchanges them for a single-use approval bound to one plan and one Orchestrator.
"""
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .errors import ApprovalError

DELETE_ACKNOWLEDGMENT = "I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION"
APPROVAL_SECONDS = 600
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


@dataclass(frozen=True)
class Gate:
    prompt: str
    expected: str
    refusal: str
    notice: str = ""


def write_gates(zone_names: Sequence[str] = (), target: str = "") -> List[Gate]:
    gates = [Gate("Type {} to confirm this zone: ".format("CREATE " + name), "CREATE " + name, "zone confirmation refused") for name in zone_names]
    return gates + [_apply_gate(target)]


def template_acl_gates(preview: Mapping[str, Any], target: str = "") -> List[Gate]:
    gates: List[Gate] = []
    for group in preview["plan"]["groups"]:
        if not group["eligible"]:
            continue
        name = group["template_group"]
        if group["create"]:
            gates.append(Gate("Type the exact template group name {} to authorize creation: ".format(name), name, "template group creation confirmation refused"))
        if not group["create"] and group["selection_change"]:
            gates.append(Gate("Type SELECT ACLS {} to select Access Lists: ".format(name), "SELECT ACLS " + name, "Access Lists selection confirmation refused"))
        if group["template_mode_change"]:
            gates.append(Gate("Type MERGE ACLS {} to change appliance template mode: ".format(name), "MERGE ACLS " + name, "template merge-mode confirmation refused"))
    return gates + [_apply_gate(target)]


def delete_gates(code: Optional[str] = None) -> List[Gate]:
    """The deletion code (new and random unless given) and the acknowledgement sentence."""
    code = code or "DELETE-{}".format("".join(secrets.choice(_CODE_ALPHABET) for _ in range(8)))
    return [
        Gate("Deletion code: ", code, "deletion confirmation code refused", "\nWARNING 2 OF 3 — Type this system-generated code exactly:\n\n{}\n".format(code)),
        Gate("Final acknowledgment: ", DELETE_ACKNOWLEDGMENT, "final deletion acknowledgment refused", "\nWARNING 3 OF 3 — FINAL DESTRUCTIVE ACTION WARNING\nThe complete table above will be deleted. Dependencies may stop working, rollback is not automatic, and you are responsible for this abyss action.\n\nTo answer 'Are you absolutely sure?' type exactly:\n\n{}\n".format(DELETE_ACKNOWLEDGMENT)),
    ]


def _apply_gate(target: str) -> Gate:
    return Gate("Type APPLY to execute the exact preview: ", "APPLY", "write approval refused", "Target Orchestrator: {}".format(target) if target else "")


def ask_in_terminal(gates: Sequence[Gate], no_terminal: str = "non-interactive writes are refused") -> None:
    """Ask for every gate in order; raise ApprovalError at the first wrong answer, or at once without a terminal."""
    if not sys.stdin.isatty():
        raise ApprovalError(no_terminal)
    for gate in gates:
        if gate.notice:
            print(gate.notice)
        if input(gate.prompt) != gate.expected:
            raise ApprovalError(gate.refusal)


@dataclass(frozen=True)
class _Grant:
    plan_fingerprint: str
    orchestrator: str
    expires: float


class GuiApprovals:
    """Single-use approvals for the GUI: each is bound to one plan fingerprint and one Orchestrator, and expires."""

    def __init__(self, seconds: float = APPROVAL_SECONDS, clock: Callable[[], float] = time.monotonic) -> None:
        self._seconds = seconds
        self._clock = clock
        self._grants: Dict[str, _Grant] = {}
        self._lock = threading.Lock()

    def issue(self, gates: Sequence[Gate], answers: Sequence[str], plan_fingerprint: str, orchestrator: str) -> str:
        """Check the typed answers against every gate and return an approval token for exactly this plan and Orchestrator."""
        if len(answers) != len(gates):
            raise ApprovalError("every confirmation must be answered")
        for gate, answer in zip(gates, answers):
            if answer != gate.expected:
                raise ApprovalError(gate.refusal)
        token = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._grants = {key: grant for key, grant in self._grants.items() if grant.expires > now}
            self._grants[token] = _Grant(plan_fingerprint, orchestrator, now + self._seconds)
        return token

    def redeem(self, token: str, plan_fingerprint: str, orchestrator: str) -> None:
        """Use an approval once; raise ApprovalError if it is unknown, already used, expired, or for another plan or Orchestrator."""
        with self._lock:
            grant = self._grants.pop(token, None)
        if grant is None:
            raise ApprovalError("approval is unknown or was already used")
        if self._clock() >= grant.expires:
            raise ApprovalError("approval expired; review the plan and approve again")
        if grant.plan_fingerprint != plan_fingerprint:
            raise ApprovalError("approval is for a different plan")
        if grant.orchestrator != orchestrator:
            raise ApprovalError("approval is for a different Orchestrator")
