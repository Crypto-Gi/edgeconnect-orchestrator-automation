import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation.errors import ApprovalError, DriftError, ValidationError
from edgeconnect_automation.util import fingerprint
from edgeconnect_automation.workflows import native_group_semantic_equal
from scripts.cleanup_comprehensive_lab import FINAL_ACKNOWLEDGMENT, PREFIX, apply_plan, confirm, deletion_order, deletion_rows, expected_groups, format_deletion_table, generate_confirmation_code, load_suite, parse_args, require_prefix, verify_absent


class EmptyGateway:
    def get_policy(self, segment_map):
        return {"data": {"map1": {}}}

    def get_application_groups(self):
        return {}

    def get_appexpress(self):
        return {}

    def get_application_definitions(self, base):
        return [] if base == "dnsClassification" else {}

    def get_service_groups(self):
        return []

    def get_address_groups(self):
        return []


class ComprehensiveLabTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[1] / "examples" / "comprehensive_lab"

    def cleanup_plan(self):
        return {
            "firewall": [{"pair": ("Default", "Default"), "segment_map": "0_0", "removed": [{"zone_pair": "1_2", "priority": 30000, "rule_key": "lab25-fw-001"}]}],
            "application_groups": {"remove": ["lab25-apps-all"]},
            "appexpress": {"remove": ["lab25-domain-01"]},
            "application_definitions": [
                {"type": "DOMAIN", "name": "lab25-domain-01", "domain": "alpha.example.com"},
                {"type": "COMPOUND", "name": "lab25-cmp-08"},
            ],
            "service_groups": {"remove": ["lab25-sg-tcp-web"]},
            "address_groups": {"remove": ["lab25-ag-base-v4"]},
        }

    def test_generated_suite_counts_and_valid_files(self):
        suite = load_suite(self.directory)
        self.assertEqual(len({row["Name"] for row in suite["address_rows"]}), 20)
        self.assertEqual(len({row["Name"] for row in suite["service_rows"]}), 20)
        self.assertEqual(len(suite["definitions"]), 40)
        self.assertEqual(suite["definitions"][0].name, "lab25-ip-01")
        self.assertEqual(suite["definitions"][0].identity, ("0", 2))
        self.assertEqual(len(suite["firewall_rules"]), 45)
        self.assertEqual(set(suite["app_express"]), {definition.name for definition in suite["definitions"] if definition.app_express == "MONITOR"})
        self.assertFalse((self.directory / "appexpress_monitor_valid.csv").exists())

    def test_invalid_files_are_at_least_twenty_percent(self):
        import csv
        with (self.directory / "expected_failures.csv").open() as handle:
            expectations = list(csv.DictReader(handle))
        self.assertEqual(len([row for row in expectations if row["Category"] == "address_group"]), 5)
        self.assertEqual(len([row for row in expectations if row["Category"] == "service_group"]), 5)
        self.assertEqual(len([row for row in expectations if row["Category"] == "application_definition"]), 10)
        self.assertEqual(len([row for row in expectations if row["Category"] == "firewall_rule"]), 12)

    def test_cleanup_accepts_server_managed_null_group_type(self):
        row = {"Name": "lab25-sg-web", "Protocol": "TCP", "IncludedPorts": "443", "ExcludedPorts": "", "IncludedGroups": "", "ExcludedGroups": "", "IcmpTypes": "", "IcmpCodes": "", "Comment": ""}
        expected = expected_groups([row], "service")["lab25-sg-web"]
        actual = dict(expected, type=None)
        self.assertTrue(native_group_semantic_equal(actual, expected))

    def test_prefix_guard_and_dependency_delete_order(self):
        with self.assertRaises(ValidationError):
            require_prefix({"production-object"}, "objects")
        groups = {
            PREFIX + "parent": {"rules": [{"includedGroups": [PREFIX + "child"]}]},
            PREFIX + "child": {"rules": [{"includedGroups": []}]},
        }
        self.assertEqual(deletion_order(set(groups), groups), [PREFIX + "parent", PREFIX + "child"])

    def test_cleanup_defaults_to_dry_run_and_empty_verification(self):
        args = parse_args([])
        self.assertFalse(args.apply)
        self.assertIsNone(args.dotenv)
        plan = {"firewall": []}
        self.assertTrue(verify_absent(EmptyGateway(), plan)["verified_absent"])

    def test_deletion_table_lists_every_resource_without_truncation(self):
        rows = deletion_rows(self.cleanup_plan())
        self.assertEqual(len(rows), 7)
        table = format_deletion_table(rows)
        for value in ("lab25-fw-001", "lab25-apps-all", "lab25-domain-01", "lab25-cmp-08", "lab25-sg-tcp-web", "lab25-ag-base-v4"):
            self.assertIn(value, table)
        self.assertIn("Default -> Default; segment 0_0; zones 1_2; priority 30000", table)
        self.assertIn("compound name identity; current ID resolved at deletion", table)

    def test_confirmation_code_is_generated_in_unambiguous_format(self):
        self.assertRegex(generate_confirmation_code(), r"^DELETE-LAB25-[A-HJ-NP-Z2-9]{8}$")

    def test_cleanup_confirmation_requires_interactive_terminal(self):
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaisesRegex(ApprovalError, "non-interactive"):
                confirm(self.cleanup_plan())

    def test_cleanup_confirmation_rejects_wrong_generated_code(self):
        with patch("sys.stdin.isatty", return_value=True), patch("scripts.cleanup_comprehensive_lab.generate_confirmation_code", return_value="DELETE-LAB25-ABCDEFGH"), patch("builtins.input", return_value="wrong") as prompt, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ApprovalError, "confirmation code"):
                confirm(self.cleanup_plan())
        self.assertEqual(prompt.call_count, 1)

    def test_cleanup_confirmation_rejects_wrong_final_acknowledgment(self):
        responses = ["DELETE-LAB25-ABCDEFGH", "not sure"]
        with patch("sys.stdin.isatty", return_value=True), patch("scripts.cleanup_comprehensive_lab.generate_confirmation_code", return_value="DELETE-LAB25-ABCDEFGH"), patch("builtins.input", side_effect=responses) as prompt, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ApprovalError, "final cleanup acknowledgment"):
                confirm(self.cleanup_plan())
        self.assertEqual(prompt.call_count, 2)

    def test_cleanup_confirmation_requires_both_exact_phrases(self):
        output = io.StringIO()
        responses = ["DELETE-LAB25-ABCDEFGH", FINAL_ACKNOWLEDGMENT]
        with patch("sys.stdin.isatty", return_value=True), patch("scripts.cleanup_comprehensive_lab.generate_confirmation_code", return_value="DELETE-LAB25-ABCDEFGH"), patch("builtins.input", side_effect=responses), redirect_stdout(output):
            confirm(self.cleanup_plan())
        rendered = output.getvalue()
        self.assertIn("COMPLETE DELETION TABLE", rendered)
        self.assertIn("DELETE-LAB25-ABCDEFGH", rendered)
        self.assertIn("FINAL WARNING", rendered)
        self.assertIn(FINAL_ACKNOWLEDGMENT, rendered)

    def test_application_definition_drift_aborts_before_deletion(self):
        plan = {
            "firewall": [],
            "application_groups": {"remove": []},
            "appexpress": {"remove": []},
            "application_definitions": [{"type": "DOMAIN", "name": "lab25-domain-01", "domain": "alpha.example.com"}],
            "application_definition_fingerprints": {"dnsClassification": fingerprint([])},
            "service_groups": {"remove": []},
            "address_groups": {"remove": []},
        }

        class Gateway:
            def get_application_definitions(self, base):
                return [{"name": "changed"}]

        with self.assertRaisesRegex(DriftError, "application definitions changed"):
            apply_plan(Gateway(), plan)

    def test_group_collection_drift_aborts_before_deletion(self):
        plan = {
            "firewall": [],
            "application_groups": {"remove": []},
            "appexpress": {"remove": []},
            "application_definitions": [],
            "service_groups": {"fingerprint": fingerprint([]), "remove": ["lab25-sg-tcp-web"]},
            "address_groups": {"remove": []},
        }

        class Gateway:
            def get_service_groups(self):
                return [{"name": "changed"}]

        with self.assertRaisesRegex(DriftError, "service group collection changed"):
            apply_plan(Gateway(), plan)


if __name__ == "__main__":
    unittest.main()
