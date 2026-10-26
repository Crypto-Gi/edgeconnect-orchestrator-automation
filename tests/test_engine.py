import contextlib
import copy
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation import engine
from edgeconnect_automation.approval import DELETE_ACKNOWLEDGMENT, GuiApprovals
from tests.test_golden import GOLDEN, GoldenGateway

NEW_GROUP = {"name": "new", "type": None, "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}


class WritableGateway(GoldenGateway):
    """GoldenGateway whose address groups can be uploaded and deleted, for the approval round trips."""

    groups = []

    def get_address_groups(self):
        return copy.deepcopy(type(self).groups)

    def upload_address_groups(self, content):
        type(self).groups = type(self).groups + [copy.deepcopy(NEW_GROUP)]
        return {"success": True}

    def delete_address_group(self, name):
        type(self).groups = [group for group in type(self).groups if group["name"] != name]


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        for path in (GOLDEN / "inputs").iterdir():
            shutil.copy(path, root / path.name)
        (root / "new_group.csv").write_text("Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nnew,10.0.0.0/24,,,\n", encoding="utf-8")
        self.cwd = os.getcwd()
        os.chdir(root)
        WritableGateway.groups = []
        self.client = SimpleNamespace(write_requests=0)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("edgeconnect_automation.cli.load_config", return_value=SimpleNamespace(name="lab", base_url="https://orchestrator.invalid/gms/rest")))
        stack.enter_context(patch("edgeconnect_automation.cli.ApiClient", return_value=self.client))
        stack.enter_context(patch("edgeconnect_automation.cli.OrchestratorGateway", WritableGateway))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def tearDown(self):
        os.chdir(self.cwd)
        self.directory.cleanup()

    def test_validate_returns_issues_with_row_column_and_rule(self):
        result = engine.validate("firewall_rules_mixed.csv", report_dir="")
        self.assertEqual((result.exit_code, result.status), (2, "INVALID"))
        self.assertIn({"row": 4, "column": "action", "rule": "FW-03", "value": "drop", "message": "action must be allow, deny, or inspect", "fix": "use allow, deny, or inspect", "blocks": "segment pair Default -> Default"}, result.issues)
        self.assertEqual(len({(issue["row"], issue["rule"]) for issue in result.issues}), 11)

    def test_blocking_issues_from_other_workflows_are_parsed_into_fields(self):
        result = engine.plan("app-definitions", "plan.json", report_dir="", csv="application_definitions_valid.csv")
        self.assertEqual(result.exit_code, 0)
        with patch.object(WritableGateway, "get_interface_labels", return_value={}):
            result = engine.plan("app-definitions", "plan.json", report_dir="", csv="application_definitions_valid.csv")
        self.assertEqual(result.exit_code, 2)
        issue = next(issue for issue in result.issues if issue["row"] == 46)
        self.assertEqual((issue["rule"], issue["column"], issue["value"]), ("CMP-09", "vlan", "Data"))
        self.assertIn("interface label Data is unknown", issue["message"])

    def test_firewall_plan_lists_each_rule_with_field_level_diffs(self):
        result = engine.plan("firewall", "plan.json", report_dir="", csv="firewall_rules_small.csv", inventory="firewall_inventory.json")
        self.assertEqual((result.exit_code, result.status), (0, "PLANNED"))
        self.assertEqual(result.counts, ["segment pair Default -> Default: 2 rows, 2 to create, 0 already present"])
        self.assertEqual(sorted((change["object"], change["action"]) for change in result.changes), [("3_4/prio/20010", "create"), ("3_4/prio/20020", "create")])
        fields = {item["field"]: item["after"] for item in result.changes[0]["fields"]}
        self.assertEqual((fields["match.src_ip"], fields["set.action"]), ("10.0.0.0/24", "allow"))
        self.assertEqual([(row["item"], row["outcome"]) for row in result.rows], [("new-rule (priority 20010)", "WOULD CREATE"), ("second-rule (priority 20020)", "WOULD CREATE")])

    def test_zone_and_group_plans_list_creates_and_template_acls_list_entries(self):
        zones = engine.plan("zones", "zones.json", report_dir="", name=["NEW_ZONE", "INSIDE"])
        self.assertEqual(zones.changes, [{"scope": "zones", "type": "zone", "object": "5", "action": "create", "fields": [{"field": "name", "before": None, "after": "NEW_ZONE"}]}])
        groups = engine.plan("address-groups", "groups.json", report_dir="", csv="address_groups_valid.csv")
        multi = next(change for change in groups.changes if change["object"] == "test-51-ag-MultiRule")
        self.assertEqual({item["field"].split(".")[1] for item in multi["fields"]}, {"1", "2"})
        acls = engine.plan("template-acls", "acls.json", report_dir="", csv="template_acls_small.csv")
        self.assertEqual([(change["scope"], change["object"], change["action"]) for change in acls.changes], [("template group new-group", "new-acl/entry/1000", "create")])

    def test_write_needs_a_gui_approval_for_that_exact_plan_and_it_works_once(self):
        planned = engine.plan("address-groups", "plan.json", report_dir="", csv="new_group.csv")
        self.assertEqual(planned.exit_code, 0)
        refused = engine.apply("address-groups", "plan.json", report_dir="")
        self.assertEqual((refused.exit_code, refused.status, refused.changes_written), (3, "REFUSED", "no"))
        self.assertIn("no approval was given for this write", [issue["message"].split(": ", 1)[1] for issue in refused.issues])
        preview = engine.apply("address-groups", "plan.json", dry_run=True, report_dir="")
        self.assertEqual((preview.status, [gate["expected"] for gate in preview.approval["gates"]]), ("DRY_RUN", ["APPLY"]))
        self.assertEqual(preview.approval["orchestrator"], "https://orchestrator.invalid")
        approvals = GuiApprovals()
        approval = engine.approve(approvals, preview.approval, ["APPLY"])
        applied = engine.apply("address-groups", "plan.json", approval, report_dir="")
        self.assertEqual((applied.exit_code, [group["name"] for group in WritableGateway.groups]), (0, ["new"]))
        again = engine.apply("address-groups", "plan.json", approval, report_dir="")
        self.assertEqual(again.exit_code, 3)
        self.assertIn("approval is unknown or was already used", " ".join(issue["message"] for issue in again.issues))

    def test_approval_for_one_plan_is_refused_for_another(self):
        engine.plan("address-groups", "one.json", report_dir="", csv="new_group.csv")
        engine.plan("address-groups", "two.json", report_dir="", csv="address_groups_delete.csv")
        approval = engine.approve(GuiApprovals(), engine.apply("address-groups", "one.json", dry_run=True, report_dir="").approval, ["APPLY"])
        result = engine.apply("address-groups", "two.json", approval, report_dir="")
        self.assertEqual((result.exit_code, WritableGateway.groups), (3, []))
        self.assertIn("approval is for a different plan", " ".join(issue["message"] for issue in result.issues))

    def test_delete_preview_returns_the_table_and_its_code_then_deletes_with_the_approval(self):
        WritableGateway.groups = [{"name": "existing-ag", "type": None, "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
        preview = engine.delete("address-groups", "address_groups_delete.csv", dry_run=True, report_dir="")
        self.assertEqual([(change["type"], change["object"], change["action"]) for change in preview.changes], [("Address group", "existing-ag", "delete")])
        code, acknowledgement = [gate["expected"] for gate in preview.approval["gates"]]
        self.assertRegex(code, r"^DELETE-[A-Z2-9]{8}$")
        self.assertEqual(acknowledgement, DELETE_ACKNOWLEDGMENT)
        approval = engine.approve(GuiApprovals(), preview.approval, [code, acknowledgement])
        deleted = engine.delete("address-groups", "address_groups_delete.csv", approval, report_dir="")
        self.assertEqual((deleted.exit_code, WritableGateway.groups), (0, []))

    def test_each_call_gets_its_own_context(self):
        context = engine.RunContext()
        result = engine.plan("zones", "zones.json", report_dir="", context=context, name=["NEW_ZONE"])
        self.assertEqual((result.exit_code, context.target_url), (0, "https://orchestrator.invalid"))
        self.assertIsNone(engine.RunContext().gateway)


if __name__ == "__main__":
    unittest.main()
