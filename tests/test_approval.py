import contextlib
import contextvars
import io
import unittest
from unittest.mock import patch

from edgeconnect_automation import cli
from edgeconnect_automation.approval import GuiApprovals, delete_gates, write_gates
from edgeconnect_automation.errors import ApprovalError
from tests.test_golden import GOLDEN, UPDATE

TEMPLATE_PREVIEW = {"plan": {"groups": [
    {"template_group": "new-group", "eligible": True, "create": True, "selection_change": True, "template_mode_change": False},
    {"template_group": "existing-group", "eligible": True, "create": False, "selection_change": True, "template_mode_change": True},
    {"template_group": "blocked-group", "eligible": False, "create": True, "selection_change": True, "template_mode_change": True},
]}}
DELETE_ROWS = [("address-group", "web", "address-groups"), ("service-group", "https", "service-groups")]


def transcript(call, answers, tty=True):
    """Run one approval gate with typed answers; return everything the terminal shows, prompts included, and how it ended."""
    out = io.StringIO()
    typed = iter(answers)

    def type_answer(prompt):
        answer = next(typed)
        out.write("{}{}\n".format(prompt, answer))
        return answer

    def run():
        context = cli._context()
        context.target, context.target_name, context.target_url = "lab (https://orchestrator.invalid)", "lab", "https://orchestrator.invalid"
        try:
            return "returned {}".format(call())
        except ApprovalError as error:
            return "ApprovalError: {}".format(error)

    with patch("edgeconnect_automation.cli._show_preview"), patch("sys.stdin.isatty", return_value=tty), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=type_answer), contextlib.redirect_stdout(out):
        # A fresh context, so this run's target never leaks into other tests.
        ending = contextvars.Context().run(run)
    return out.getvalue() + "=> " + ending + "\n"


SCENARIOS = [
    ("write, approved, with zones", lambda: cli._approve({}, False, ["Z1", "Z2"]), ["CREATE Z1", "CREATE Z2", "APPLY"]),
    ("write, wrong zone", lambda: cli._approve({}, False, ["Z1"]), ["CREATE Z2"]),
    ("write, APPLY refused", lambda: cli._approve({}, False), ["apply"]),
    ("write, dry run", lambda: cli._approve({}, True), []),
    ("write, no terminal", lambda: cli._approve({}, False), [], False),
    ("template ACLs, approved", lambda: cli._approve_template_acls(TEMPLATE_PREVIEW, False), ["new-group", "SELECT ACLS existing-group", "MERGE ACLS existing-group", "APPLY"]),
    ("template ACLs, wrong group name", lambda: cli._approve_template_acls(TEMPLATE_PREVIEW, False), ["New-Group"]),
    ("template ACLs, selection refused", lambda: cli._approve_template_acls(TEMPLATE_PREVIEW, False), ["new-group", "SELECT ACLS new-group"]),
    ("template ACLs, merge mode refused", lambda: cli._approve_template_acls(TEMPLATE_PREVIEW, False), ["new-group", "SELECT ACLS existing-group", "MERGE"]),
    ("template ACLs, no terminal", lambda: cli._approve_template_acls(TEMPLATE_PREVIEW, False), [], False),
    ("delete, approved", lambda: cli._approve_delete(DELETE_ROWS, False), ["DELETE-AAAAAAAA", cli.DELETE_ACKNOWLEDGMENT]),
    ("delete, wrong code", lambda: cli._approve_delete(DELETE_ROWS, False), ["DELETE-AAAAAAAB"]),
    ("delete, acknowledgement refused", lambda: cli._approve_delete(DELETE_ROWS, False), ["DELETE-AAAAAAAA", "yes"]),
    ("delete, dry run", lambda: cli._approve_delete(DELETE_ROWS, True), []),
    ("delete, nothing to delete", lambda: cli._approve_delete([], False), []),
    ("delete, no terminal", lambda: cli._approve_delete(DELETE_ROWS, False), [], False),
]


class TerminalApprovalTests(unittest.TestCase):
    def test_every_terminal_prompt_matches_golden_transcript(self):
        text = "".join("### {}\n{}\n".format(name, transcript(call, answers, *rest)) for name, call, answers, *rest in SCENARIOS)
        expected = GOLDEN / "approval-terminal.txt"
        if UPDATE:
            expected.write_text(text, encoding="utf-8")
        self.assertEqual(text, expected.read_text(encoding="utf-8"))



class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class GuiApprovalTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.approvals = GuiApprovals(clock=self.clock)
        self.gates = write_gates(["Z1"])

    def issue(self, plan="sha256:plan", orchestrator="lab"):
        return self.approvals.issue(self.gates, ["CREATE Z1", "APPLY"], plan, orchestrator)

    def test_approval_is_used_once(self):
        token = self.issue()
        self.approvals.redeem(token, "sha256:plan", "lab")
        with self.assertRaisesRegex(ApprovalError, "already used"):
            self.approvals.redeem(token, "sha256:plan", "lab")

    def test_approval_expires_after_ten_minutes(self):
        token = self.issue()
        self.clock.now += 599
        self.approvals.redeem(token, "sha256:plan", "lab")
        token = self.issue()
        self.clock.now += 600
        with self.assertRaisesRegex(ApprovalError, "expired"):
            self.approvals.redeem(token, "sha256:plan", "lab")

    def test_approval_is_refused_for_another_plan_or_orchestrator_and_is_then_spent(self):
        token = self.issue()
        with self.assertRaisesRegex(ApprovalError, "different plan"):
            self.approvals.redeem(token, "sha256:other-plan", "lab")
        with self.assertRaisesRegex(ApprovalError, "already used"):
            self.approvals.redeem(token, "sha256:plan", "lab")
        token = self.issue()
        with self.assertRaisesRegex(ApprovalError, "different Orchestrator"):
            self.approvals.redeem(token, "sha256:plan", "other-lab")

    def test_unknown_token_is_refused(self):
        with self.assertRaisesRegex(ApprovalError, "unknown"):
            self.approvals.redeem("made-up", "sha256:plan", "lab")

    def test_wrong_or_missing_answer_issues_nothing_and_names_the_gate(self):
        with self.assertRaisesRegex(ApprovalError, "zone confirmation refused"):
            self.approvals.issue(self.gates, ["CREATE Z2", "APPLY"], "sha256:plan", "lab")
        with self.assertRaisesRegex(ApprovalError, "write approval refused"):
            self.approvals.issue(self.gates, ["CREATE Z1", "apply"], "sha256:plan", "lab")
        with self.assertRaisesRegex(ApprovalError, "every confirmation"):
            self.approvals.issue(self.gates, ["CREATE Z1"], "sha256:plan", "lab")

    def test_delete_needs_its_code_and_the_acknowledgement(self):
        gates = delete_gates("DELETE-ABCDEFGH")
        with self.assertRaisesRegex(ApprovalError, "deletion confirmation code refused"):
            self.approvals.issue(gates, ["DELETE-ABCDEFGX", cli.DELETE_ACKNOWLEDGMENT], "sha256:plan", "lab")
        token = self.approvals.issue(gates, ["DELETE-ABCDEFGH", cli.DELETE_ACKNOWLEDGMENT], "sha256:plan", "lab")
        self.approvals.redeem(token, "sha256:plan", "lab")


if __name__ == "__main__":
    unittest.main()
