"""Regression tests for the v1.2.0 hardening items (fuzz findings H1-H3, M1-M7, R1-R2, L1-L5)."""
import copy
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation.cli import _discover_inventory, main
from edgeconnect_automation.errors import ResponseFormatError, ValidationError
from edgeconnect_automation.firewall import FIREWALL_HEADERS, _policy_rules, build_firewall_plan, parse_firewall_document, rule_payload
from edgeconnect_automation.models import Inventory
from edgeconnect_automation.validation import Issues, members, policy_ip, valid_domain, valid_protocol
from edgeconnect_automation.workflows import _native_group_warnings, parse_application_groups, parse_template_acls, plan_application_groups
from tests.test_inventory_cli import InventoryGateway
from tests import test_workflows
from tests.test_workflows import TempCsv

HEADERS = sorted(FIREWALL_HEADERS)


def firewall_text(*rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, HEADERS)
    writer.writeheader()
    for row in rows:
        writer.writerow({**{"rule_key": "k", "source_segment": "Default", "destination_segment": "Default", "source_zone": "INSIDE", "destination_zone": "OUTSIDE", "action": "allow", "enabled": "FALSE"}, **row})
    return buffer.getvalue()


def payload(**row):
    document = parse_firewall_document(firewall_text(row))
    return document.errors, [rule_payload(rule)["match"] for rule in document.rules]


class ValueGrammarTests(unittest.TestCase):
    def test_non_ascii_digits_and_leading_zeros_are_rejected(self):
        for value in ("１７", "٦", "006"):
            self.assertFalse(valid_protocol(value), value)
        self.assertTrue(valid_protocol("17"))
        for field, value in (("destination_port", "0443"), ("destination_port", "４４３"), ("source_address", "10.0.0.010")):
            errors, _ = payload(protocol="tcp", **{field: value})
            self.assertTrue(errors, value)
        self.assertFalse(payload(protocol="tcp", destination_port="0|443")[0])

    def test_domain_ipv6_zone_and_invisible_characters(self):
        for value in ("-bad.com", "bad-.com", "any", "256.1.1.1", "10.0.0.1"):
            self.assertFalse(valid_domain(value), value)
        for value in ("example.com", "*.example.com", "*example.com", "a_b.example.com"):
            self.assertTrue(valid_domain(value), value)
        with self.assertRaisesRegex(ValueError, "zone"):
            policy_ip("fe80::1%eth0")
        self.assertIn("CSV-10", " ".join(payload(source_address_group="a\u200bb")[0]))
        self.assertFalse(payload(source_address="10.0.0.1", description="non\u00a0breaking")[0])

    def test_case_only_and_semantic_duplicates(self):
        issues = Issues()
        members("A|a", issues, 2, "f")
        self.assertEqual(issues.items[0]["rule"], "VAL-03")
        self.assertIn("same network", " ".join(payload(source_address="10.0.0.1|10.0.0.1/32")[0]))
        self.assertFalse(payload(source_address="10.0.0.1|10.0.0.2")[0])


class FirewallHardeningTests(unittest.TestCase):
    def inventory(self, existing=None, local=None):
        policy = {"data": {"map1": {"1_2": {"prio": existing or {}}}}, "options": {"merge": False, "templateApply": False}, "settings": {}}
        return Inventory(segments={"Default": 0}, zones={("Default", "INSIDE"): 1, ("Default", "OUTSIDE"): 2}, policies={("Default", "Default"): policy}, statuses={"x": "complete"}, local_priorities=local or {})

    def test_list_members_are_normalized_in_payload(self):
        self.assertEqual(payload(source_address=" 10.0.0.1 | 10.0.0.2 ", protocol="tcp", destination_port="80 | 443")[1], [{"src_ip": "10.0.0.1|10.0.0.2", "protocol": "tcp", "dst_port": "80|443"}])

    def test_reordered_lists_are_a_no_op_not_a_conflict(self):
        document = parse_firewall_document(firewall_text({"priority": "41000", "source_address": "10.0.0.2|10.0.0.1"}))
        existing = dict(rule_payload(document.rules[0]), match={"src_ip": "10.0.0.1|10.0.0.2"})
        plan = build_firewall_plan(document.rules, self.inventory({"41000": existing}))
        self.assertEqual((plan.pairs[0].errors, plan.pairs[0].no_op_rows), ([], [2]))

    def test_duplicate_rule_key_is_caught_by_validate(self):
        document = parse_firewall_document(firewall_text({"priority": "1", "source_address": "10.0.0.1"}, {"priority": "2", "source_address": "10.0.0.2"}))
        self.assertIn("FW-21", " ".join(document.errors))
        self.assertEqual(document.issues[-1]["rule"], "FW-21")

    def test_auto_priority_skips_appliance_local_priorities(self):
        document = parse_firewall_document(firewall_text({"source_address": "10.0.0.1"}))
        plan = build_firewall_plan(document.rules, self.inventory(local={("Default", "Default", "INSIDE", "OUTSIDE"): {20000}}))
        self.assertEqual(plan.pairs[0].created_priorities, [("1_2", 20010)])
        occupied = build_firewall_plan(document.rules, self.inventory({"30000": {"match": {}, "set": {"action": "deny"}}}))
        self.assertIn("set an explicit priority", " ".join(occupied.pairs[0].errors))

    def test_malformed_csv_and_policy_shapes_raise_clear_errors(self):
        for text in ('rule_key,action\n"k1,allow\n', "rule_key\x00,action\n"):
            with self.assertRaisesRegex(ValidationError, "CSV-11"):
                parse_firewall_document(text)
        for policy in ({"data": {"map1": {"1_2": "x"}}}, {"data": {"map1": {"1_2": {"prio": {"1": "x"}}}}}, {"data": {"map1": {"1_2": {"prio": []}}}}):
            with self.assertRaises(ResponseFormatError):
                _policy_rules(policy, "1_2")


class DiscoveryHardeningTests(unittest.TestCase):
    ROW = {"rule_key": "k", "priority": "20000", "source_address": "10.0.0.1"}

    def discover(self, gateway):
        rules = parse_firewall_document(firewall_text(self.ROW)).rules
        return _discover_inventory(gateway, rules, {rules[0].pair}), rules

    def test_local_priorities_fail_closed_for_odd_gms_marked_and_versions(self):
        for marker in ({}, {"gms_marked": None}, {"gms_marked": "false"}, {"gms_marked": 0}):
            gateway = InventoryGateway()
            gateway.get_security_map = lambda nepk, marker=marker: {"map1": {"1_2": {"prio": {"20000": dict(marker)}}}}
            inventory, rules = self.discover(gateway)
            self.assertEqual(inventory.local_priorities[rules[0].scope], {20000}, marker)
        for version in ("", "ECOS 9.6.4.0", "unknown"):
            gateway = InventoryGateway()
            gateway.get_appliances = lambda version=version: [{"nePk": "0.NE", "state": 1, "softwareVersion": version}]
            self.assertEqual(self.discover(gateway)[0].target_states["0.NE"], "reachable", version)
        gateway = InventoryGateway()
        gateway.get_appliances = lambda: [{"nePk": "0.NE", "state": 1, "softwareVersion": "9.4.1.0_1"}]
        self.assertEqual(self.discover(gateway)[0].target_states["0.NE"], "unsupported")

    def test_unexpected_nested_response_shapes_become_response_format_errors(self):
        breakers = {
            "get_segment_zones": lambda: [{"vrfName": "Default"}],
            "get_segments": lambda: {"0": "Default"},
            "get_appliances": lambda: [True],
            "get_reachability": lambda nepk: {"state": "x"},
            "get_address_groups": lambda: ["name"],
        }
        for name, broken in breakers.items():
            gateway = InventoryGateway()
            setattr(gateway, name, broken)
            with self.assertRaises(ResponseFormatError, msg=name):
                self.discover(gateway)


class WorkflowHardeningTests(unittest.TestCase):
    def test_application_group_cycle_through_existing_group_is_skipped(self):
        rows = [{"Name": "G", "Applications": "web", "ParentGroups": "X", "_row": "2"}]
        for existing in ({"X": {"apps": ["web"], "parentGroup": "G"}}, {"X": {"apps": ["web"], "parentGroup": ["Y"]}, "Y": {"apps": ["web"], "parentGroup": "G"}}):
            plan = plan_application_groups(rows, existing, {"web"})
            self.assertNotIn("G", plan["candidate"])
            self.assertEqual(plan["skipped_conflicts"][0]["reason"], "application group parent cycle")
        self.assertIn("G", plan_application_groups(rows, {"X": {"apps": ["web"], "parentGroup": None}}, {"web"})["candidate"])

    def test_strict_application_group_parser_matches_deploy_validation(self):
        for row in ({"Name": "", "Applications": "web", "ParentGroups": ""}, {"Name": "G", "Applications": "web|dns", "ParentGroups": ""}, {"Name": "a,b", "Applications": "web", "ParentGroups": ""}):
            fixture = TempCsv(["Name", "Applications", "ParentGroups"], [row])
            try:
                with self.assertRaises(ValidationError):
                    parse_application_groups(str(fixture.path))
            finally:
                fixture.close()

    def test_template_acl_application_any_bad_name_and_malformed_csv(self):
        case = test_workflows.TemplateAclTests()
        for values, code in ((dict(Application="any"), "ACL-28"), (dict(ACLName="a|b", Application="App"), "ACL-20")):
            with self.assertRaisesRegex(ValidationError, code):
                case.parse([case.row(**values)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "acl.csv"
            path.write_text('"TemplateGroup","ACLName\n', encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "CSV-11"):
                parse_template_acls(str(path))

    def test_address_group_exclusion_outside_inclusion_warns(self):
        rows = [{"_row": "2", "IncludedIPs": "10.0.0.0/24", "ExcludedIPs": "192.168.1.1,10.0.0.5", "IncludedGroups": ""}]
        self.assertEqual(len(_native_group_warnings("address", rows, [], b"")), 1)


class AclTargetVerificationTests(unittest.TestCase):
    PLAN = {"associations": ["0.NE"], "touched_acls": ["a"], "candidate_acl_value": {"data": {"a": {"entry": {"1": {"permit": True}}}}}}

    class Gateway:
        client = type("Client", (), {"config": type("Config", (), {"verification_timeout": 5.0, "poll_interval": 0.0})()})()

        def __init__(self, states):
            self.states = list(states)

        def get_appliances(self):
            return [{"nePk": "0.NE"}]

        def get_reachability(self, target):
            return {"state": self.states.pop(0) if len(self.states) > 1 else self.states[0]}

        def get_appliance_acls(self, target):
            return {"a": {"1": {"permit": True, "self": 1}}}

    def test_transient_unreachable_reading_is_retried_until_verified(self):
        from edgeconnect_automation.workflows import _verify_template_acl_targets
        self.assertEqual(_verify_template_acl_targets(self.Gateway([2, 2, 1]), self.PLAN), {"0.NE": "verified"})

    def test_persistently_unreachable_target_is_reported_unreachable(self):
        from edgeconnect_automation.workflows import _verify_template_acl_targets
        gateway = self.Gateway([2])
        gateway.client.config.verification_timeout = 0.05
        self.assertEqual(_verify_template_acl_targets(gateway, self.PLAN), {"0.NE": "unreachable"})


class PolicyShapeTests(unittest.TestCase):
    def test_empty_segment_pair_policy_with_null_data_is_accepted(self):
        from edgeconnect_automation.gateway import OrchestratorGateway

        class Client:
            def __init__(self, value):
                self.value = value

            def get(self, path, query=None):
                return copy.deepcopy(self.value)

        empty = {"data": None, "settings": {"map1": {"logging": {"imp_fw_drop": "2"}}}, "options": {"merge": False, "templateApply": False}}
        self.assertEqual(OrchestratorGateway(Client(empty)).get_policy("0_1")["data"], {"map1": {}})
        for broken in ({"data": []}, {"data": {"map1": []}}, {"data": {}, "options": []}, []):
            with self.assertRaises(ResponseFormatError):
                OrchestratorGateway(Client(broken)).get_policy("0_1")


class BlockedPlanReportTests(unittest.TestCase):
    def test_blocked_firewall_deploy_still_writes_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules.csv").write_text(firewall_text({"priority": "1", "source_address": "10.0.0.1", "source_zone": "MISSING"}), encoding="utf-8")
            inventory = {"segments": {"Default": 0}, "zones": {"Default|INSIDE": 1, "Default|OUTSIDE": 2}, "policies": {}, "statuses": {"x": "complete"}, "segmentation_enabled": True}
            (root / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
            with patch("edgeconnect_automation.cli._gateway", return_value=None), patch("sys.stdout", new_callable=io.StringIO):
                code = main(["firewall", "deploy", "--csv", str(root / "rules.csv"), "--inventory", str(root / "inventory.json"), "--report", str(root / "report.json")])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads((root / "report.json").read_text())["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
