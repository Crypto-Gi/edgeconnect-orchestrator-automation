import unittest
from pathlib import Path

from edgeconnect_automation.errors import ValidationError
from scripts.cleanup_comprehensive_lab import PREFIX, deletion_order, load_suite, parse_args, require_prefix, verify_absent


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

    def test_generated_suite_counts_and_valid_files(self):
        suite = load_suite(self.directory)
        self.assertEqual(len({row["Name"] for row in suite["address_rows"]}), 20)
        self.assertEqual(len({row["Name"] for row in suite["service_rows"]}), 20)
        self.assertEqual(len(suite["definitions"]), 40)
        self.assertEqual(len(suite["firewall_rules"]), 45)

    def test_invalid_files_are_at_least_twenty_percent(self):
        import csv
        expectations = list(csv.DictReader((self.directory / "expected_failures.csv").open()))
        self.assertEqual(len([row for row in expectations if row["Category"] == "address_group"]), 5)
        self.assertEqual(len([row for row in expectations if row["Category"] == "service_group"]), 5)
        self.assertEqual(len([row for row in expectations if row["Category"] == "application_definition"]), 10)
        self.assertEqual(len([row for row in expectations if row["Category"] == "firewall_rule"]), 12)

    def test_prefix_guard_and_dependency_delete_order(self):
        with self.assertRaises(ValidationError):
            require_prefix({"production-object"}, "objects")
        groups = {
            PREFIX + "parent": {"rules": [{"includedGroups": [PREFIX + "child"]}]},
            PREFIX + "child": {"rules": [{"includedGroups": []}]},
        }
        self.assertEqual(deletion_order(set(groups), groups), [PREFIX + "parent", PREFIX + "child"])

    def test_cleanup_defaults_to_dry_run_and_empty_verification(self):
        self.assertFalse(parse_args(["--dotenv", ".env"]).apply)
        plan = {"firewall": []}
        self.assertTrue(verify_absent(EmptyGateway(), plan)["verified_absent"])


if __name__ == "__main__":
    unittest.main()
