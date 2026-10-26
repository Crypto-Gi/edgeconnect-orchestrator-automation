import json
import unittest
from pathlib import Path

from edgeconnect_automation import gui_revert
from edgeconnect_automation.gui_tasks import TaskError
from tests.test_engine import NEW_GROUP
from tests.test_gui import GROUP_CSV, ServerCase
from tests.test_gui_firewall import FirewallCase, FirewallGateway

FIREWALL = "rule_key,priority,action\nkept,20010,allow\nthere-before,20020,allow\n\nauto,,allow\nfailed,20040,allow\n"


def row(number, item, outcome):
    return {"row": number, "item": item, "scope": "", "outcome": outcome, "reason": ""}


class BuildTests(unittest.TestCase):
    def test_only_the_rows_the_upload_created_are_kept(self):
        # the firewall parser counts the empty line, so "auto" is row 5; it was given priority 20030
        value = gui_revert.build("firewall", "lab", FIREWALL, [
            row(2, "kept (priority 20010)", "CREATED"), row(3, "there-before (priority 20020)", "ALREADY PRESENT"),
            row(5, "auto (priority 20030)", "CREATED, UNVERIFIED"), row(6, "failed (priority 20040)", "FAILED")])
        self.assertEqual((value["csv_text"], value["count"], value["reason"]), ("rule_key,priority,action\nkept,20010,allow\nauto,20030,allow\n", 2, ""))

    def test_rows_without_a_number_are_matched_by_name_with_every_row_of_that_name(self):
        text = "Name,Protocol,IncludedPorts\nweb,TCP,80\n\nold,TCP,22\nweb,TCP,443\n"
        value = gui_revert.build("service-groups", "lab", text, [row("", "web", "CREATED"), row("", "old", "ALREADY PRESENT")])
        self.assertEqual((value["csv_text"], value["count"]), ("Name,Protocol,IncludedPorts\nweb,TCP,80\nweb,TCP,443\n", 2))
        groups = "Name,Applications,ParentGroups\nfresh,zoom,\n"
        self.assertEqual(gui_revert.build("app-groups", "lab", groups, [row("", "fresh", "CREATED")])["count"], 1)

    def test_uploads_that_cannot_be_undone_say_why(self):
        for kind, rows, reason in [
            ("zones", [row("", "NEW_ZONE", "CREATED")], "Zones cannot be deleted"),
            ("template-acls", [row(2, "acl priority 10", "ADDED"), row(3, "acl priority 20", "OVERWRITTEN")], "replaced or removed entries that already existed"),
            ("firewall", [row(3, "there-before (priority 20020)", "ALREADY PRESENT")], "created nothing"),
        ]:
            with self.subTest(kind):
                value = gui_revert.build(kind, "lab", FIREWALL, rows)
                self.assertEqual((value["csv_text"], value["count"]), ("", 0))
                self.assertIn(reason, value["reason"])


class UndoTests(FirewallCase):
    def upload(self, tasks, kind, text):
        task = self.plan_and_wait_for_approval(tasks, kind, text)
        tasks.approve(task.id, ["APPLY"], "lab")
        self.assertEqual(self.wait(task, "done", "failed").state, "done", task.message)
        return task.result.summary["run_id"]

    def undo(self, tasks, kind, run_id):
        task = self.wait(tasks.create({"action": "delete", "orchestrator": "lab", "kind": kind, "revert": run_id}), "awaiting_approval", "failed", "done")
        self.assertEqual(task.state, "awaiting_approval", task.message)
        deleting = [change["object"] for change in tasks.table(task.id, "changes", {})["rows"] if change["action"] == "delete"]
        tasks.approve(task.id, [gate["expected"] for gate in task.result.approval["gates"]], "lab", True)
        self.assertEqual(self.wait(task, "done", "failed").state, "done", task.message)
        return deleting

    def test_undoing_a_firewall_upload_puts_the_policy_back_as_it_was(self):
        before = FirewallGateway(None).get_policy("0_0")
        tasks = self.manager(report_dir=str(self.root / "reports"))
        run_id = self.upload(tasks, "firewall", Path("firewall_rules_small.csv").read_text(encoding="utf-8"))
        self.assertNotEqual(FirewallGateway.policies["0_0"]["data"], before["data"])
        kept = tasks.revert(run_id)
        self.assertEqual((kept["kind"], kept["orchestrator"], kept["count"]), ("firewall", "lab", 2))
        self.assertEqual(len(self.undo(tasks, "firewall", run_id)), 2)
        self.assertEqual(FirewallGateway.policies["0_0"], before)

    def test_undo_deletes_only_what_the_upload_created(self):
        FirewallGateway.groups = [{"name": "existing-ag", "type": None, "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
        tasks = self.manager(report_dir=str(self.root / "reports"))
        run_id = self.upload(tasks, "address-groups", GROUP_CSV + "existing-ag,10.0.0.0/24,,,\n")
        self.assertEqual(tasks.revert(run_id)["csv_text"], GROUP_CSV)
        self.assertEqual(self.undo(tasks, "address-groups", run_id), ["new"])
        self.assertEqual([group["name"] for group in FirewallGateway.groups], ["existing-ag"])

    def test_undo_is_refused_for_another_orchestrator_or_type_and_for_unknown_runs(self):
        tasks = self.manager(report_dir=str(self.root / "reports"))
        run_id = self.upload(tasks, "address-groups", GROUP_CSV)
        self.assertEqual(FirewallGateway.groups, [NEW_GROUP])
        with self.assertRaisesRegex(TaskError, "was an upload of address-groups to 'lab'"):
            tasks.create({"action": "delete", "orchestrator": "lab", "kind": "service-groups", "revert": run_id})
        for bad in ("run-000000000000", "../reports", 7):
            with self.assertRaises(TaskError):
                tasks.create({"action": "delete", "orchestrator": "lab", "kind": "address-groups", "revert": bad})
        gui_revert.save(tasks.run_folder, "run-zones", gui_revert.build("zones", "lab", "", []))
        with self.assertRaisesRegex(TaskError, "Zones cannot be deleted"):
            tasks.create({"action": "delete", "orchestrator": "lab", "kind": "zones", "revert": "run-zones"})
        self.assertEqual(FirewallGateway.groups, [NEW_GROUP])

    def test_nothing_is_kept_without_a_run_log(self):
        tasks = self.manager(report_dir="")
        run_id = self.upload(tasks, "address-groups", GROUP_CSV)
        self.assertIsNone(tasks.revert(run_id))


class UndoServerTests(ServerCase):
    def test_the_run_page_says_whether_and_how_an_upload_can_be_undone(self):
        tasks = self.server.tasks
        plan = self.wait(tasks.create({"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": GROUP_CSV}), "planned")
        task = self.wait(tasks.create({"action": "apply", "orchestrator": "lab", "kind": "address-groups", "plan_task": plan.id}), "awaiting_approval")
        tasks.approve(task.id, ["APPLY"], "lab")
        run_id = self.wait(task, "done", "failed").result.summary["run_id"]
        view = json.loads(self.request("GET", "/api/runs/{}/revert".format(run_id))[1])
        self.assertEqual({key: view[key] for key in ("available", "kind", "orchestrator", "count", "csv_text")}, {"available": True, "kind": "address-groups", "orchestrator": "lab", "count": 1, "csv_text": GROUP_CSV})
        plan_run = [run["run_id"] for run in json.loads(self.request("GET", "/api/runs")[1])["rows"] if run["workflow"] == "address-groups plan"][0]
        self.assertEqual(json.loads(self.request("GET", "/api/runs/{}/revert".format(plan_run))[1]), {"available": False, "reason": ""})
        self.assertEqual(self.request("GET", "/api/runs/run-nope/revert")[0].status, 404)
        self.assertFalse([body for body in self.bodies if "SECRET-KEY" in body])


if __name__ == "__main__":
    unittest.main()
