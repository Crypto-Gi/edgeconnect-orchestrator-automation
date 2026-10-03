import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation.cli import main
from edgeconnect_automation.errors import DriftError, ValidationError
from edgeconnect_automation.firewall import parse_firewall_text, rule_payload
from edgeconnect_automation.reporting import RunRecorder, build_summary, render
from edgeconnect_automation.util import fingerprint
from tests.test_hardening import firewall_text
from tests.test_inventory_cli import DeployGateway, baseline

EXISTING = {"match": {"acl": "EXAMPLE-ACL"}, "set": {"action": "allow"}, "comment": "", "gms_marked": True, "misc": {"rule": "disable", "logging_priority": 0, "logging": "disable"}}


def _recorder(preview):
    recorder = RunRecorder([])
    recorder.capture({"preview": preview, "status": "DRY_RUN"})
    return recorder


def inventory(policy):
    return {"segments": {"Default": 0}, "zones": {"Default|INSIDE": 1, "Default|OUTSIDE": 2}, "policies": {"Default|Default": policy}, "statuses": {"all": "complete"}, "segmentation_enabled": True, "target_states": {"0.NE": "reachable", "3.NE": "unreachable"}}


class RunReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.logs = self.root / "logs"
        self.csv = self.root / "rules.csv"
        self.csv.write_text(firewall_text({"priority": "20000", "destination_address": "10.9.9.0/24", "protocol": "tcp", "destination_port": "443"}), encoding="utf-8")
        conflicted = baseline()
        conflicted["data"]["map1"]["1_2"] = {"prio": {"20000": EXISTING}}
        self.conflict_inventory = self.root / "conflict.json"
        self.conflict_inventory.write_text(json.dumps(inventory(conflicted)), encoding="utf-8")
        self.clean_inventory = self.root / "clean.json"
        self.clean_inventory.write_text(json.dumps(inventory(baseline())), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def run_cli(self, *argv, gateway=None, tty=False, answer="APPLY"):
        stderr = io.StringIO()
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=tty), patch("builtins.input", return_value=answer), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", stderr):
            code = main(["--report-dir", str(self.logs)] + list(argv))
        return code, stderr.getvalue()

    def records(self, workflow="firewall"):
        return [json.loads(line) for line in (self.logs / "{}.jsonl".format(workflow)).read_text(encoding="utf-8").splitlines()]

    def test_blocked_run_explains_the_exact_conflict_and_logs_it(self):
        report = self.root / "blocked.json"
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.conflict_inventory), "--report", str(report))
        self.assertEqual(code, 2)
        for expected in ("RESULT       : BLOCKED", "Changes made : no", "[FW-24]", "INSIDE -> OUTSIDE", "existing: allow disabled, match acl=EXAMPLE-ACL", "free priority such as 20001", "BLOCKED by 1 issue(s); none of its 1 rows", "3.NE: unreachable", "Next step    : Fix every blocking issue"):
            self.assertIn(expected, text)
        summary = json.loads(report.read_text(encoding="utf-8"))["summary"]
        self.assertEqual((summary["status"], summary["exit_code"], summary["changes_written"]), ("BLOCKED", 2, "no"))
        self.assertEqual(self.records()[0]["summary"]["status"], "BLOCKED")
        self.assertIn("RESULT       : BLOCKED", (self.logs / "firewall.log").read_text(encoding="utf-8"))

    def test_log_appends_one_timestamped_record_per_run_per_workflow(self):
        self.run_cli("firewall", "validate", "--csv", str(self.csv))
        self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), "--dry-run")
        records = self.records()
        self.assertEqual([record["summary"]["status"] for record in records], ["VALID", "DRY_RUN"])
        self.assertNotEqual(records[0]["summary"]["run_id"], records[1]["summary"]["run_id"])
        self.assertTrue(all(record["summary"]["timestamp"] for record in records))
        self.assertEqual(records[1]["summary"]["changes_written"], "no")
        self.assertEqual(records[1]["summary"]["csv"]["data_rows"], 1)
        self.assertFalse((self.logs / "template-acls.jsonl").exists())

    def test_refused_approval_replaces_a_stale_report(self):
        report = self.root / "report.json"
        report.write_text('{"status": "SUCCESS", "old": true}', encoding="utf-8")
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), "--report", str(report), gateway=DeployGateway(baseline()), tty=True, answer="no")
        self.assertEqual(code, 3)
        value = json.loads(report.read_text(encoding="utf-8"))
        self.assertNotIn("old", value)
        self.assertEqual((value["summary"]["status"], value["summary"]["changes_written"]), ("REFUSED", "no"))
        self.assertIn("write approval refused", text)

    def test_unexpected_error_is_still_summarized_and_logged(self):
        code, text = self.run_cli("firewall", "validate", "--csv", str(self.root / "missing.csv"))
        self.assertEqual(code, 1)
        self.assertIn("RESULT       : ERROR", text)
        self.assertIn("FileNotFoundError", self.records()[0]["summary"]["blocking_issues"][0])

    def test_success_lists_counts_targets_and_run_reference(self):
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), gateway=DeployGateway(baseline()), tty=True)
        self.assertEqual(code, 0)
        for expected in ("RESULT       : SUCCESS", "Changes made : yes", "1 to create", "result Default -> Default: success", "0.NE: verified", "Run ref      : edgeconnect-auto-"):
            self.assertIn(expected, text)

    def test_read_only_discovery_never_reports_changes(self):
        recorder = RunRecorder([])
        recorder.capture({"appliances": []})
        for output in (None, "inventory.json"):
            summary = build_summary(recorder, SimpleNamespace(command="discovery", dry_run=False, output=output), 0)
            self.assertEqual((summary["status"], summary["changes_written"]), ("SUCCESS", "no"))

    def test_summary_and_headline_name_the_orchestrator(self):
        from edgeconnect_automation.reporting import _headline
        recorder = RunRecorder([])
        recorder.orchestrator_target, recorder.orchestrator_name, recorder.orchestrator_url = "ge (https://ge.invalid)", "ge", "https://ge.invalid"
        summary = build_summary(recorder, SimpleNamespace(command="discovery", dry_run=False), 0)
        self.assertEqual({key: _headline(summary)[key] for key in ("orchestrator", "orchestrator_url")}, {"orchestrator": "ge", "orchestrator_url": "https://ge.invalid"})
        self.assertIn("Orchestrator : ge (https://ge.invalid)", render(summary))
        offline = build_summary(RunRecorder([]), SimpleNamespace(command="firewall", firewall_command="validate", dry_run=False), 0)
        self.assertEqual((offline["orchestrator"], offline["orchestrator_url"]), ("not contacted", "not contacted"))

    def target(self, url, name=""):
        import edgeconnect_automation.cli as cli

        def connect(args):
            cli._TARGET_NAME, cli._TARGET_URL = name, url
            return DeployGateway(baseline())
        return connect

    def test_plan_is_refused_on_another_orchestrator_and_names_only_its_own(self):
        plan = {"kind": "address-groups", "new_rows": [], "no_ops": 0, "conflicts": [], "content": "", "baseline_fingerprint": "x", "warnings": [], "orchestrator": {"name": "ge", "url": "https://ge.invalid"}}
        plan["report_fingerprint"] = fingerprint(plan)
        path = self.root / "plan.json"
        path.write_text(json.dumps(plan), encoding="utf-8")
        with patch("edgeconnect_automation.cli._gateway", side_effect=self.target("https://other.invalid", "semir")), patch("builtins.input", side_effect=AssertionError("must not ask for approval")), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO) as err:
            code = main(["--report-dir", "", "address-groups", "apply", "--approved-plan", str(path)])
        self.assertNotEqual(code, 0)
        self.assertIn("this plan is for Orchestrator ge (https://ge.invalid); rerun with --orchestrator ge to use it", err.getvalue())
        refusals = [line for line in err.getvalue().splitlines() if "this plan is for" in line]
        self.assertTrue(refusals)
        self.assertFalse(any("other.invalid" in line or "semir" in line for line in refusals))
        with patch("edgeconnect_automation.cli._gateway", side_effect=self.target("https://ge.invalid", "ge")), patch("sys.stdin.isatty", return_value=False), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO) as err:
            main(["--report-dir", "", "address-groups", "apply", "--approved-plan", str(path)])
        self.assertNotIn("this plan is for Orchestrator", err.getvalue())
        self.assertIn("non-interactive writes are refused", err.getvalue())

    def test_offline_firewall_plan_inherits_the_inventory_orchestrator(self):
        stamped = json.loads(self.clean_inventory.read_text(encoding="utf-8"))
        stamped["orchestrator"] = {"name": "ge", "url": "https://ge.invalid"}
        self.clean_inventory.write_text(json.dumps(stamped), encoding="utf-8")
        output = self.root / "fw-plan.json"
        self.run_cli("firewall", "plan", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), "--output", str(output))
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["orchestrator"], {"name": "ge", "url": "https://ge.invalid"})

    def test_firewall_rule_rejected_by_appliance_is_failed_not_success(self):
        gateway = DeployGateway(baseline())
        gateway.policy_compile_alarms = lambda targets, since_ms, priorities: {"0.NE": [20000]}
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), gateway=gateway, tty=True)
        self.assertEqual(code, 5)
        for expected in ("RESULT       : PARTIAL", "FAILED", "appliance 0.NE rejected this rule with 'ACL rule has invalid syntax'", "0.NE: rejected:20000", "Rows marked FAILED were rejected by the appliance"):
            self.assertIn(expected, text)

    def test_empty_report_dir_disables_the_log(self):
        with patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
            main(["--report-dir", "", "firewall", "validate", "--csv", str(self.csv)])
        self.assertFalse(self.logs.exists())


    def two_row_csv(self):
        self.csv.write_text(firewall_text({"rule_key": "conflict", "priority": "20000", "destination_address": "10.9.9.0/24"}, {"rule_key": "fine", "priority": "20010", "destination_address": "10.9.8.0/24"}), encoding="utf-8")

    def test_row_table_shows_blocked_row_and_rows_it_holds_back(self):
        self.two_row_csv()
        report = self.root / "blocked.json"
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.conflict_inventory), "--report", str(report))
        self.assertEqual(code, 2)
        self.assertIn("Rows (2): 1 BLOCKED, 1 NOT ATTEMPTED", text)
        rows = {row["item"]: row for row in json.loads(report.read_text(encoding="utf-8"))["summary"]["rows"]}
        self.assertEqual((rows["conflict (priority 20000)"]["row"], rows["conflict (priority 20000)"]["outcome"]), (2, "BLOCKED"))
        self.assertEqual(rows["fine (priority 20010)"]["reason"], "segment pair blocked by row 2")

    def test_every_report_and_log_record_has_the_same_top_level_status_fields(self):
        report = self.root / "dry.json"
        self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), "--dry-run", "--report", str(report))
        for value in (json.loads(report.read_text(encoding="utf-8")), self.records()[0]):
            self.assertEqual((value["status"], value["exit_code"], value["changes_written"]), ("DRY_RUN", 0, "no"))
            self.assertTrue(value["run_id"].startswith("run-"))
            self.assertEqual(value["report_fingerprint"], fingerprint({key: item for key, item in value.items() if key != "report_fingerprint"}))

    def test_success_rows_are_created(self):
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), gateway=DeployGateway(baseline()), tty=True)
        self.assertEqual(code, 0)
        self.assertEqual(self.records()[0]["summary"]["row_outcomes"], {"CREATED": 1})

    def test_all_no_op_firewall_run_reports_no_op_and_no_write(self):
        rule = parse_firewall_text(self.csv.read_text(encoding="utf-8"))[0]
        policy = baseline()
        policy["data"]["map1"] = {"1_2": {"prio": {"20000": rule_payload(rule)}}}
        existing_inventory = self.root / "existing.json"
        existing_inventory.write_text(json.dumps(inventory(policy)), encoding="utf-8")
        gateway = DeployGateway(policy)
        code, text = self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(existing_inventory), gateway=gateway, tty=True)
        self.assertEqual(code, 0)
        self.assertEqual(gateway.posts, 0)
        self.assertIn("RESULT       : NO_OP", text)
        self.assertIn("Changes made : no", text)
        self.assertEqual(self.records()[0]["summary"]["row_outcomes"], {"ALREADY PRESENT": 1})

    def test_summarize_old_report_without_summary_and_export_rows(self):
        self.two_row_csv()
        self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.conflict_inventory), "--report", str(self.root / "new.json"))
        legacy = json.loads((self.root / "new.json").read_text(encoding="utf-8"))
        old = self.root / "old.json"
        old.write_text(json.dumps({"preview": legacy["preview"], "status": "BLOCKED", "report_fingerprint": "x"}), encoding="utf-8")
        rows_csv = self.root / "rows.csv"
        stdout = io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main(["--report-dir", str(self.root / "no-log"), "report", "summarize", str(old), "--rows-csv", str(rows_csv)]), 0)
        text = stdout.getvalue()
        for expected in ("RESULT       : BLOCKED", "report written by an older version", "Rows (2): 1 BLOCKED, 1 NOT ATTEMPTED", "[FW-24]"):
            self.assertIn(expected, text)
        self.assertEqual(rows_csv.read_text(encoding="utf-8").splitlines()[0], "row,item,scope,outcome,reason")
        self.assertFalse((self.root / "no-log").exists())

    def test_summarize_last_runs_of_a_report_log(self):
        self.run_cli("firewall", "validate", "--csv", str(self.csv))
        self.run_cli("firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.clean_inventory), "--dry-run")
        stdout = io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", new_callable=io.StringIO):
            main(["report", "summarize", str(self.logs / "firewall.jsonl"), "--last", "2"])
        text = stdout.getvalue()
        self.assertEqual(text.count("RUN SUMMARY (from"), 2)
        self.assertLess(text.index("RESULT       : VALID"), text.index("RESULT       : DRY_RUN"))


class SummaryTests(unittest.TestCase):
    def test_rejected_csv_lists_valid_rows_as_not_attempted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "groups.csv"
            path.write_text("Name,Applications,ParentGroups\nbad,missing,\ngood,present,\n", encoding="utf-8")
            recorder = RunRecorder(["app-groups", "deploy"])
            recorder.error = ValidationError("row 2 [DEP-04] missing application missing")
            summary = build_summary(recorder, SimpleNamespace(command="app-groups", app_group_command="deploy", dry_run=False, csv=str(path)), 2)
        self.assertEqual([(row["row"], row["outcome"]) for row in summary["rows"]], [(2, "INVALID"), (3, "NOT ATTEMPTED")])
        self.assertEqual(summary["row_outcomes"], {"INVALID": 1, "NOT ATTEMPTED": 1})

    def test_multi_rule_native_group_has_an_outcome_for_every_csv_row(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "address.csv"
            path.write_text("Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nshared,10.0.0.0/24,,,\nshared,10.1.0.0/24,,,\n", encoding="utf-8")
            recorder = RunRecorder(["address-groups", "deploy"])
            recorder.capture({"preview": {"kind": "address-groups", "new_rows": [], "no_ops": ["shared"], "conflicts": []}, "status": "DRY_RUN"})
            summary = build_summary(recorder, SimpleNamespace(command="address-groups", address_groups_command="deploy", dry_run=True, csv=str(path)), 0)
        self.assertEqual([(row["row"], row["outcome"]) for row in summary["rows"]], [(2, "ALREADY PRESENT"), (3, "ALREADY PRESENT")])

    def test_string_planner_row_numbers_do_not_duplicate_csv_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "address.csv"
            path.write_text("Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\na,10.0.0.0/24,,,\n", encoding="utf-8")
            recorder = RunRecorder(["address-groups", "deploy"])
            recorder.capture({"preview": {"kind": "address-groups", "new_rows": [{"Name": "a", "_row": "2"}], "no_ops": [], "conflicts": []}, "status": "DRY_RUN"})
            summary = build_summary(recorder, SimpleNamespace(command="address-groups", address_groups_command="deploy", dry_run=True, csv=str(path)), 0)
        self.assertEqual(summary["rows"], [{"row": 2, "item": "a", "scope": "address-groups", "outcome": "WOULD CREATE", "reason": ""}])

    def test_operation_level_error_lists_every_csv_row_as_not_attempted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "groups.csv"
            path.write_text("Name,Applications,ParentGroups\none,a,\ntwo,b,\n", encoding="utf-8")
            recorder = RunRecorder(["app-groups", "delete"])
            recorder.error = ValidationError("deletion blocked because objects are referenced")
            summary = build_summary(recorder, SimpleNamespace(command="app-groups", app_group_command="delete", dry_run=True, csv=str(path)), 2)
        self.assertEqual(summary["row_outcomes"], {"NOT ATTEMPTED": 2})
        self.assertTrue(all("deletion blocked" in row["reason"] for row in summary["rows"]))

    def test_firewall_delete_has_one_outcome_per_removed_rule(self):
        recorder = RunRecorder(["firewall", "delete"])
        recorder.capture({"preview": {"kind": "firewall-delete", "plans": [{"pair": ["Default", "Default"], "removed": [{"rule_key": "r1", "zone_key": "1_2", "priority": 20000}]}], "absent": []}, "status": "DRY_RUN"})
        summary = build_summary(recorder, SimpleNamespace(command="firewall", firewall_command="delete", dry_run=True, csv=None), 0)
        self.assertEqual(summary["row_outcomes"], {"WOULD DELETE": 1})
        self.assertEqual(summary["rows"][0], {"row": "", "item": "r1", "scope": "Default -> Default | zones 1_2 | priority 20000", "outcome": "WOULD DELETE", "reason": ""})

    def test_live_cycle_summary_counts_for_delete_app_groups_and_appliance_cleanup(self):
        recorder = RunRecorder([])
        recorder.capture({"preview": {"kind": "firewall-delete", "plans": []}, "result": {"status": "success", "pairs": [{"pair": ["Default", "Default"], "deleted": [{"rule_key": "r"}], "readback_verified": True, "audit_verified": True}]}})
        summary = build_summary(recorder, SimpleNamespace(command="firewall", firewall_command="delete", dry_run=False, csv=None), 0)
        self.assertIn("result Default -> Default: success", summary["counts"])
        app = {"kind": "app-groups", "baseline": {"keep": {}}, "candidate": {"keep": {}, "new": {}}, "no_ops": [], "skipped_conflicts": []}
        self.assertIn("to create: 1", build_summary(_recorder(app), SimpleNamespace(command="app-groups", app_group_command="deploy", dry_run=True, csv=None), 0)["counts"])
        group = {"template_group": "g", "eligible": True, "associations": ["0.NE"], "deletions": [], "absent": [{"acl": "a"}], "appliance_only_deletions": [{"target": "0.NE", "acl": "a"}], "additions": [], "overwrites": [], "no_ops": []}
        self.assertTrue(any("1 to delete" in line for line in build_summary(_recorder({"kind": "template-acls-delete", "groups": [group]}), SimpleNamespace(command="template-acls", template_acl_command="delete", dry_run=True, csv=None), 0)["counts"]))

    def test_template_acl_rows_follow_group_state(self):
        recorder = RunRecorder(["template-acls", "deploy"])
        recorder.capture({"preview": {"kind": "template-acls", "plan": {"groups": [{"template_group": "g1", "eligible": False, "errors": ["row 3 [DEP-03] missing application x"], "additions": [{"row": 2, "acl": "a", "priority": "1000"}, {"row": 3, "acl": "a", "priority": "1010"}], "overwrites": [], "no_ops": []}]}}, "status": "BLOCKED"})
        rows = build_summary(recorder, SimpleNamespace(command="template-acls", template_acl_command="deploy", dry_run=False), 2)["rows"]
        self.assertEqual([(row["row"], row["outcome"]) for row in rows], [(2, "NOT ATTEMPTED"), (3, "BLOCKED")])
        self.assertEqual(rows[0]["reason"], "template group blocked by row 3")

    def test_drift_interruption_and_zone_rerun_have_distinct_statuses(self):
        args = SimpleNamespace(command="firewall", firewall_command="deploy", dry_run=False, csv=None)
        drift = RunRecorder([])
        drift.error = DriftError("baseline changed")
        self.assertEqual((build_summary(drift, args, 4)["status"], build_summary(drift, args, 4)["changes_written"]), ("DRIFT", "no"))
        interrupted = RunRecorder([])
        interrupted.error = KeyboardInterrupt()
        self.assertEqual((build_summary(interrupted, args, 130)["status"], build_summary(interrupted, args, 130)["changes_written"]), ("INTERRUPTED", "unknown; check Orchestrator"))
        zones = RunRecorder([])
        zones.capture({"firewall_status": "NOT_ATTEMPTED_RERUN_REQUIRED", "result": {"status": "success"}})
        self.assertEqual((build_summary(zones, args, 2)["status"], build_summary(zones, args, 2)["changes_written"]), ("ZONES_CREATED_RERUN", "yes"))

    def test_partial_shows_hostnames_and_rollback(self):
        recorder = RunRecorder(["firewall", "deploy"])
        recorder.appliances = {"3.NE": "branch-03"}
        recorder.capture({"result": {"status": "PARTIAL", "run_reference": "r1", "pairs": [{"pair": ["Default", "Default"], "status": "critical", "message": "readback differs", "rollback_status": "unresolved", "targets": {"3.NE": "unreachable"}}]}})
        summary = build_summary(recorder, SimpleNamespace(command="firewall", firewall_command="deploy", dry_run=False), 5)
        text = render(summary)
        self.assertEqual(summary["status"], "PARTIAL")
        for expected in ("3.NE (branch-03): unreachable", "rollback unresolved", "readback differs", "5 = partial"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
