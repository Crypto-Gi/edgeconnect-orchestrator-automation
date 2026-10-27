import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from edgeconnect_automation import engine, gui_revert, reporting
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


class BuildFromRealOutcomesTests(unittest.TestCase):
    """Rows as reporting.row_outcomes really writes them after an apply, not hand-made ones.

    The run summary reads an applications or application-groups apply's result as empty (its result has no created
    list), so those rows say WOULD CREATE even after a real write; the tests pass {} for them, as the summary does.
    """

    def build(self, kind, text, plan, result, status="SUCCESS"):
        return gui_revert.build(kind, "lab", text, reporting.row_outcomes(plan, result), plan, status)

    def test_a_group_with_several_rules_keeps_every_row_of_that_group(self):
        text = "Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nmulti,10.0.0.0/24,,,first\nold,10.9.0.0/24,,,\nmulti,10.0.1.0/24,,,second\n"
        plan = {"kind": "address-groups", "new_rows": [{"Name": "multi", "_row": 2}, {"Name": "multi", "_row": 4}], "no_ops": ["old"]}
        value = self.build("address-groups", text, plan, {"status": "success", "created": ["multi"]})
        self.assertEqual((value["csv_text"], value["count"]), ("Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nmulti,10.0.0.0/24,,,first\nmulti,10.0.1.0/24,,,second\n", 2))

    def test_applications_are_undone_by_the_rows_the_plan_created_even_when_two_share_a_name(self):
        text = "DefinitionType,Name,Port,AppExpressMode\nTCP_PORT,app,8443,OFF\nDNS,app,,OFF\nTCP_PORT,there,22,OFF\n"
        plan = {"kind": "app-definitions", "new": [{"row": 2, "name": "app"}, {"row": 3, "name": "app"}], "no_ops": ["there"],
                "appexpress": {"baseline": {}, "candidate": {}, "monitor": [], "off": [], "no_ops": [], "changed": False}}
        value = self.build("app-definitions", text, plan, {})
        self.assertEqual((value["csv_text"], value["count"], value["reason"]), ("DefinitionType,Name,Port,AppExpressMode\nTCP_PORT,app,8443,OFF\nDNS,app,,OFF\n", 2, ""))

    def test_application_groups_are_undone_by_the_groups_the_plan_added(self):
        text = "Name,Applications,ParentGroups\nfresh,zoom,\nexisting,teams,\n"
        plan = {"kind": "app-groups", "baseline": {"existing": {"apps": ["teams"]}}, "candidate": {"existing": {"apps": ["teams"]}, "fresh": {"apps": ["zoom"]}}}
        value = self.build("app-groups", text, plan, {})
        self.assertEqual((value["csv_text"], value["count"]), ("Name,Applications,ParentGroups\nfresh,zoom,\n", 1))

    def test_an_upload_that_did_not_fully_succeed_is_not_undone_from_the_plan(self):
        plan = {"kind": "app-groups", "baseline": {}, "candidate": {"fresh": {"apps": ["zoom"]}}}
        value = self.build("app-groups", "Name,Applications,ParentGroups\nfresh,zoom,\n", plan, {}, "PARTIAL")
        self.assertEqual(value["count"], 0)
        self.assertIn("Remove by CSV", value["reason"])

    def test_uploads_that_changed_more_than_they_created_cannot_be_undone(self):
        acl = {"template_group": "g", "create": False, "selection_change": False, "template_mode_change": False, "additions": [], "overwrites": [], "no_ops": []}
        for change in ("create", "selection_change", "template_mode_change"):
            with self.subTest(change):
                value = self.build("template-acls", "TemplateGroup,ACLName,Priority\ng,a,10\n", {"kind": "template-acls", "groups": [dict(acl, **{change: True})]}, {})
                self.assertEqual(value["count"], 0)
                self.assertIn("cannot be undone", value["reason"])
        express = {"baseline": {"old": {"name": "Old"}}, "candidate": {}, "monitor": [], "off": [], "no_ops": [], "changed": True}
        # An entry already on monitor is a no-op for the upload, but the Undo delete would still remove it.
        for change in ({"off": ["Old"]}, {"monitor": ["Old"]}, {"no_ops": ["Old"]}):
            with self.subTest(change):
                plan = {"kind": "app-definitions", "new": [{"row": 2, "name": "app"}], "appexpress": dict(express, **change)}
                value = self.build("app-definitions", "DefinitionType,Name,Port,AppExpressMode\nTCP_PORT,app,8443,OFF\n", plan, {})
                self.assertEqual(value["count"], 0)
                self.assertIn("AppExpress", value["reason"])


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

    def test_an_application_group_upload_is_kept_from_its_plan_even_though_its_rows_say_would_create(self):
        tasks = self.manager(report_dir=str(self.root / "reports"))
        text = Path("application_groups_valid.csv").read_text(encoding="utf-8")
        plan = self.wait(tasks.create({"action": "plan", "orchestrator": "lab", "kind": "app-groups", "csv_text": text}), "planned", "failed")
        self.assertEqual(plan.state, "planned", plan.message)
        upload = SimpleNamespace(kind="app-groups", orchestrator="lab", source_csv=plan.folder / "input.csv", source_plan=plan.folder / "plan.json")
        rows = [row(None, name, "WOULD CREATE") for name in ("fresh-one", "fresh-two")]  # what the run summary says after a real write
        result = engine.Result(0, "SUCCESS", "yes", [], [], [], rows, [], None, summary={"run_id": "run-appgroups"})
        self.assertEqual(tasks._keep_revert(upload, result), "")
        kept = tasks.revert("run-appgroups")
        added = set(json.loads((plan.folder / "plan.json").read_text())["candidate"]) - set(json.loads((plan.folder / "plan.json").read_text())["baseline"])
        self.assertEqual((kept["count"], kept["reason"]), (len(added), ""))
        self.assertTrue(added)

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
