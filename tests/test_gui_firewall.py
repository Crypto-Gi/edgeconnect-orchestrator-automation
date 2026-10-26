import copy
import getpass
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation import gui_tables
from edgeconnect_automation.cli import main
from tests.test_engine import NEW_GROUP, WritableGateway
from tests.test_gui import GROUP_CSV, Offline


class FirewallGateway(WritableGateway):
    """The golden Orchestrator with a firewall policy that can be written, and appliances that always confirm it."""

    policies = {}

    def get_policy(self, segment_map):
        return copy.deepcopy(type(self).policies.get(segment_map) or super().get_policy(segment_map))

    def post_policy(self, segment_map, candidate, comment):
        type(self).policies[segment_map] = copy.deepcopy(candidate)

    def verify_targets(self, segment_map, candidate, run_reference, acl_dependencies=None):
        return {"0.NE": "verified"}

    def correlate_audit(self, segment_map, run_reference):
        return True


class FirewallCase(Offline):
    """The task manager on an Orchestrator whose firewall policy and address groups can be written."""

    def setUp(self):
        super().setUp()
        FirewallGateway.policies, FirewallGateway.groups = {}, []
        patcher = patch("edgeconnect_automation.cli.OrchestratorGateway", FirewallGateway)
        patcher.start()
        self.addCleanup(patcher.stop)

    def plan_and_wait_for_approval(self, tasks, kind="address-groups", csv_text=GROUP_CSV):
        plan = self.wait(tasks.create({"action": "plan", "orchestrator": "lab", "kind": kind, "csv_text": csv_text}), "planned", "failed")
        self.assertEqual(plan.state, "planned", plan.message)
        return self.wait(tasks.create({"action": "apply", "orchestrator": "lab", "kind": kind, "plan_task": plan.id}), "awaiting_approval", "failed", "done")


class GuidedWriteTests(FirewallCase):
    def test_the_orchestrator_nickname_must_be_typed_exactly(self):
        for typed in ("Lab", "", "lab "):
            tasks = self.manager()
            task = self.plan_and_wait_for_approval(tasks)
            tasks.approve(task.id, ["APPLY"], typed)
            self.wait(task, "rejected")
            self.assertEqual((task.message, FirewallGateway.groups), ("Orchestrator nickname refused (typed {!r}, this write goes to 'lab'); nothing was written".format(typed), []))

    def test_who_approved_what_is_in_the_run_log(self):
        reports = self.root / "reports"
        tasks = self.manager(report_dir=str(reports))
        task = self.plan_and_wait_for_approval(tasks)
        fingerprint = task.result.approval["fingerprint"]
        tasks.approve(task.id, ["APPLY"], "lab")
        self.wait(task, "done")
        self.assertEqual(FirewallGateway.groups, [NEW_GROUP])
        records = [json.loads(line) for line in (reports / "address-groups.jsonl").read_text().splitlines()]
        self.assertEqual([("approval" in record["summary"], record["source"]) for record in records], [(False, "gui"), (False, "gui"), (True, "gui")])
        approval = records[-1]["summary"]["approval"]
        self.assertEqual({key: approval[key] for key in ("by", "plan_fingerprint", "orchestrator", "orchestrator_id", "typed_orchestrator", "typed")}, {
            "by": getpass.getuser(), "plan_fingerprint": fingerprint, "orchestrator": "lab (https://orchestrator.invalid)", "orchestrator_id": "ORCH-SERIAL-1", "typed_orchestrator": "lab", "typed": ["APPLY"]})
        self.assertRegex(approval["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d$")
        self.assertIn("Approved by  : {} at {} in the GUI, typing 'lab', 'APPLY'".format(getpass.getuser(), approval["time"]), (reports / "address-groups.log").read_text())

    def test_the_browser_gets_counts_and_pages_never_the_whole_plan(self):
        tasks = self.manager()
        rows = "".join("g{0},10.{1}.{2}.0/24,,,\n".format(number, number // 250, number % 250) for number in range(600))
        plan = self.wait(tasks.create({"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": "Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\n" + rows}), "planned", "failed")
        view = plan.view()
        self.assertEqual((view["result"]["changes"], view["result"]["rows"], view["result"]["deletes"]), (600, 600, 0))
        self.assertLess(len(json.dumps(view)), 4000)
        page = tasks.table(plan.id, "changes", {"q": "10.2.", "size": "25"})
        self.assertEqual((page["matching"], len(page["rows"])), (100, 25))
        self.assertIn({"field": "rule.1.IncludedIPs", "before": None, "after": "10.2.0.0/24"}, page["rows"][0]["fields"])

    def test_deletes_are_listed_before_modifications_and_creates(self):
        changes = [gui_tables.change_row({"action": action, "type": kind, "scope": "s", "object": name, "fields": []}) for action, kind, name in (("create", "zone", "b"), ("modify", "firewall rule", "a"), ("delete", "zone", "c"), ("create", "firewall rule", "a"))]
        order = [(row["action"], row["type"]) for row in gui_tables.page(changes, {}, ("action", "type"), default_sort="action")["rows"]]
        self.assertEqual(order, [("delete", "zone"), ("modify", "firewall rule"), ("create", "firewall rule"), ("create", "zone")])

    def test_the_same_firewall_csv_through_the_cli_and_the_gui_writes_the_same_policy(self):
        text = Path("firewall_rules_small.csv").read_text(encoding="utf-8")
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            self.assertEqual(main(["--report-dir", "cli-reports", "firewall", "plan", "--csv", "firewall_rules_small.csv", "--output", "cli-plan.json"]), 0)
            self.assertEqual(main(["--report-dir", "cli-reports", "firewall", "apply", "--approved-plan", "cli-plan.json"]), 0)
        cli_policies, FirewallGateway.policies = FirewallGateway.policies, {}
        cli_rows = [json.loads(line)["summary"]["rows"] for line in Path("cli-reports/firewall.jsonl").read_text().splitlines()]

        tasks = self.manager(report_dir="gui-reports")
        task = self.plan_and_wait_for_approval(tasks, "firewall", text)
        self.assertEqual([gate["expected"] for gate in task.result.approval["gates"]], ["APPLY"])
        tasks.approve(task.id, ["APPLY"], "lab")
        self.wait(task, "done", "failed")
        self.assertEqual(task.state, "done", task.message)
        gui_rows = [json.loads(line)["summary"]["rows"] for line in Path("gui-reports/firewall.jsonl").read_text().splitlines()]

        self.assertTrue(cli_policies)
        self.assertEqual(FirewallGateway.policies, cli_policies)
        self.assertEqual([row["outcome"] for row in gui_rows[-1]], ["CREATED", "CREATED"])
        # plan, then apply: the GUI also logs the preview it showed for approval, between the two
        self.assertEqual((gui_rows[0], gui_rows[-1]), (cli_rows[0], cli_rows[-1]))


if __name__ == "__main__":
    unittest.main()
