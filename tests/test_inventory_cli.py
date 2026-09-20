import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation.cli import DELETE_ACKNOWLEDGMENT, _approve_delete, _discover_inventory, main
from edgeconnect_automation.errors import ApprovalError
from edgeconnect_automation.firewall import parse_firewall_text, rule_payload
from edgeconnect_automation.workflows import APP_DEF_HEADERS


HEADERS = "rule_key,rule_name,description,enabled,priority,source_segment,destination_segment,source_zone,destination_zone,source_address,source_address_group,destination_address,destination_address_group,either_address,either_address_group,application,application_group,protocol,source_port,destination_port,either_port,source_service_group,destination_service_group,either_service_group,action,logging,logging_level,broad_match_ack"
ROW = "rule,name,description,true,20000,Default,Default,INSIDE,OUTSIDE,10.0.0.0/24,,,,,,BuiltinApp,BuiltinGroup,tcp,,443,,,,,allow,true,2,false"


def baseline():
    return {"data": {"map1": {}}, "options": {"merge": False, "templateApply": False}, "settings": {}}


class InventoryGateway:
    def __init__(self):
        self.security_reads = []
        self.wildcards = []

    def get_segmentation(self):
        return {"enable": True}

    def get_segments(self):
        return {"0": {"id": 0, "name": "Default"}, "1": {"id": 1, "name": "Other"}}

    def get_segment_zones(self):
        return [
            {"vrfName": "Default", "zoneName": "INSIDE", "zoneId": 1},
            {"vrfName": "Default", "zoneName": "OUTSIDE", "zoneId": 2},
            {"vrfName": "Other", "zoneName": "OZONE", "zoneId": 3},
        ]

    def get_policy(self, segment_map):
        return baseline()

    def get_address_groups(self):
        return []

    def get_service_groups(self):
        return []

    def get_application_definitions(self, base):
        return [] if base == "dnsClassification" else {}

    def get_application_groups(self):
        return {}

    def search_application(self, name):
        self.wildcards.append(("app", name))
        return [{"name": name}]

    def search_application_group(self, name):
        self.wildcards.append(("group", name))
        return [{"group": name}]

    def get_appliances(self):
        return [{"nePk": "0.NE", "state": 1, "softwareVersion": "9.5.4.1_1"}, {"nePk": "1.NE", "state": 2, "softwareVersion": "9.5.4.1_1"}, {"nePk": "2.NE", "state": 1, "softwareVersion": "9.5.4.1_1"}]

    def get_paused_orchestration(self):
        return [{"nePk": "2.NE"}]

    def get_reachability(self, nepk):
        return {"id": nepk, "state": 1 if nepk != "1.NE" else 2}

    def get_security_map(self, nepk):
        self.security_reads.append(nepk)
        return {"map1": {"1_2": {"prio": {"20000": {"gms_marked": False}}}}}


class LiveInventoryTests(unittest.TestCase):
    def test_all_appliances_states_wildcards_and_local_priorities(self):
        rule = parse_firewall_text(HEADERS + "\n" + ROW)[0]
        gateway = InventoryGateway()
        inventory = _discover_inventory(gateway, [rule], {rule.pair})
        self.assertEqual(inventory.target_states, {"0.NE": "reachable", "1.NE": "unreachable", "2.NE": "paused"})
        self.assertEqual(gateway.security_reads, ["0.NE"])
        self.assertEqual(inventory.local_priorities[rule.scope], {20000})
        self.assertIn("BuiltinApp", inventory.applications)
        self.assertIn("BuiltinGroup", inventory.application_groups)
        self.assertTrue(all(status == "complete" for status in inventory.statuses.values()))

    def test_nondefault_segment_uses_unique_segment_zone_ids(self):
        row = ROW.replace("Default,Default,INSIDE,OUTSIDE", "Other,Other,OZONE,OZONE")
        rule = parse_firewall_text(HEADERS + "\n" + row)[0]
        inventory = _discover_inventory(InventoryGateway(), [rule], {rule.pair})
        self.assertNotIn(rule.pair, inventory.pair_errors)
        self.assertEqual(inventory.zones[("Other", "OZONE")], 3)
        self.assertEqual(inventory.local_priorities[rule.scope], set())


class DeployGateway:
    def __init__(self, policy):
        self.policy = copy.deepcopy(policy)
        self.posts = 0

    def get_policy(self, segment_map):
        return copy.deepcopy(self.policy)

    def post_policy(self, segment_map, candidate, reference):
        self.posts += 1
        self.policy = copy.deepcopy(candidate)

    def verify_targets(self, segment_map, candidate, reference):
        return {"0.NE": "verified"}

    def correlate_audit(self, segment_map, reference):
        return True

    def get_segments(self):
        return {"0": {"id": 0, "name": "Default"}}

    def get_segment_zones(self):
        return [{"vrfName": "Default", "zoneName": "INSIDE", "zoneId": 1}, {"vrfName": "Default", "zoneName": "OUTSIDE", "zoneId": 2}]


class BulkDeployGateway:
    def __init__(self):
        self.values = []
        self.uploads = 0

    def get_address_groups(self):
        return copy.deepcopy(self.values)

    def upload_address_groups(self, content):
        self.uploads += 1
        self.values = [{"name": "new", "type": "AG", "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
        return {"success": True}

    def delete_address_group(self, name):
        self.values = [value for value in self.values if value["name"] != name]


class AppDefinitionDeployGateway:
    def __init__(self):
        self.inventories = {"portProtocolClassification": {}, "dnsClassification": [], "compoundClassification": {}}
        self.appexpress = {}
        self.definition_posts = 0
        self.appexpress_posts = 0

    def get_application_definitions(self, base):
        return copy.deepcopy(self.inventories[base])

    def post_application_definition(self, base, value, identity):
        self.definition_posts += 1
        self.inventories[base].append(copy.deepcopy(value))

    def get_appexpress(self):
        return copy.deepcopy(self.appexpress)

    def post_appexpress(self, value):
        self.appexpress_posts += 1
        self.appexpress = copy.deepcopy(value)

    def get_application_groups(self):
        return {}

    def delete_application_definition(self, base, identity):
        if base == "dnsClassification":
            self.inventories[base] = [value for value in self.inventories[base] if value.get("domain") != identity]


class DeployCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.csv = root / "rules.csv"
        self.csv.write_text(HEADERS + "\n" + ROW + "\n", encoding="utf-8")
        self.address_csv = root / "address.csv"
        self.address_csv.write_text("Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nnew,10.0.0.0/24,,,\n", encoding="utf-8")
        self.application_csv = root / "applications.csv"
        application = {header: "" for header in APP_DEF_HEADERS}
        application.update({"DefinitionType": "DOMAIN", "Name": "monitor-app", "Notes": "monitor test", "Enabled": "TRUE", "Confidence": "100", "Domain": "monitor.example.com", "AppExpressMode": "MONITOR"})
        with self.application_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, APP_DEF_HEADERS)
            writer.writeheader()
            writer.writerow(application)
        self.app_group_csv = root / "application_groups.csv"
        self.app_group_csv.write_text("Name,Applications,ParentGroups\ntest-group,monitor-app,\n", encoding="utf-8")
        self.appexpress_csv = root / "appexpress.csv"
        self.appexpress_csv.write_text("Application,Mode\nmonitor-app,MONITOR\n", encoding="utf-8")
        self.inventory = root / "inventory.json"
        self.inventory.write_text(json.dumps({
            "segments": {"Default": 0},
            "zones": {"Default|INSIDE": 1, "Default|OUTSIDE": 2},
            "policies": {"Default|Default": baseline()},
            "applications": ["BuiltinApp"],
            "application_groups": ["BuiltinGroup"],
            "statuses": {"all": "complete"},
            "segmentation_enabled": True,
            "target_states": {"0.NE": "reachable"},
        }), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_firewall_deploy_dry_run_returns_success_without_write(self):
        gateway = DeployGateway(baseline())
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=False):
            code = main(["firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.inventory), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(gateway.posts, 0)

    def test_auto_priority_requires_resolved_csv(self):
        auto_csv = Path(self.directory.name) / "auto.csv"
        auto_csv.write_text(HEADERS + "\n" + ROW.replace("true,20000,Default", "true,,Default") + "\n", encoding="utf-8")
        resolved = Path(self.directory.name) / "resolved.csv"
        gateway = DeployGateway(baseline())
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway):
            self.assertEqual(main(["firewall", "deploy", "--csv", str(auto_csv), "--inventory", str(self.inventory), "--dry-run"]), 2)
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway):
            self.assertEqual(main(["firewall", "deploy", "--csv", str(auto_csv), "--inventory", str(self.inventory), "--resolved-csv", str(resolved), "--dry-run"]), 0)
        self.assertTrue(resolved.exists())

    def test_address_group_deploy_dry_run_and_tty(self):
        dry_gateway = BulkDeployGateway()
        with patch("edgeconnect_automation.cli._gateway", return_value=dry_gateway), patch("sys.stdin.isatty", return_value=False):
            code = main(["address-groups", "deploy", "--csv", str(self.address_csv), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(dry_gateway.uploads, 0)
        apply_gateway = BulkDeployGateway()
        with patch("edgeconnect_automation.cli._gateway", return_value=apply_gateway), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            code = main(["address-groups", "deploy", "--csv", str(self.address_csv)])
        self.assertEqual(code, 0)
        self.assertEqual(apply_gateway.uploads, 1)

    def test_application_definition_deploy_dry_run_and_apply_include_appexpress(self):
        dry_gateway = AppDefinitionDeployGateway()
        with patch("edgeconnect_automation.cli._gateway", return_value=dry_gateway), patch("sys.stdin.isatty", return_value=False):
            code = main(["app-definitions", "deploy", "--csv", str(self.application_csv), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(dry_gateway.definition_posts, 0)
        self.assertEqual(dry_gateway.appexpress_posts, 0)

        apply_gateway = AppDefinitionDeployGateway()
        with patch("edgeconnect_automation.cli._gateway", return_value=apply_gateway), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            code = main(["app-definitions", "deploy", "--csv", str(self.application_csv)])
        self.assertEqual(code, 0)
        self.assertEqual(apply_gateway.definition_posts, 1)
        self.assertEqual(apply_gateway.appexpress_posts, 1)
        self.assertTrue(apply_gateway.appexpress["monitor-app"]["monitor"])
        self.assertFalse(apply_gateway.appexpress["monitor-app"]["appExpressEnabled"])

    def test_application_group_missing_dependency_skips_group_and_dependents(self):
        groups_csv = Path(self.directory.name) / "application-groups-partial.csv"
        groups_csv.write_text("Name,Applications,ParentGroups\nbad-group,missing-app,\ndependent-group,present-app,bad-group\ngood-group,present-app,\n", encoding="utf-8")
        applications = Path(self.directory.name) / "available-applications.json"
        applications.write_text(json.dumps(["present-app"]), encoding="utf-8")

        class Gateway:
            def __init__(self):
                self.value = {}
                self.posts = 0

            def get_application_groups(self):
                return copy.deepcopy(self.value)

            def post_application_groups(self, value):
                self.posts += 1
                self.value = copy.deepcopy(value)

        dry_gateway = Gateway()
        with patch("edgeconnect_automation.cli._gateway", return_value=dry_gateway), patch("sys.stdin.isatty", return_value=False):
            self.assertEqual(main(["app-groups", "deploy", "--csv", str(groups_csv), "--applications", str(applications), "--dry-run"]), 5)
        self.assertEqual(dry_gateway.posts, 0)

        apply_gateway = Gateway()
        report = Path(self.directory.name) / "application-groups-partial-report.json"
        with patch("edgeconnect_automation.cli._gateway", return_value=apply_gateway), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            self.assertEqual(main(["app-groups", "deploy", "--csv", str(groups_csv), "--applications", str(applications), "--report", str(report)]), 5)
        self.assertEqual(apply_gateway.posts, 1)
        self.assertEqual(set(apply_gateway.value), {"good-group"})
        result = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(result["result"]["status"], "partial")
        self.assertEqual([item["name"] for item in result["result"]["skipped_conflicts"]], ["bad-group", "dependent-group"])

    def test_application_definition_conflict_skips_row_and_deploys_remaining(self):
        conflict_csv = Path(self.directory.name) / "applications-conflict.csv"
        rows = []
        for name, domain in (("conflict-app", "collision.example.com"), ("valid-app", "valid.example.com")):
            row = {header: "" for header in APP_DEF_HEADERS}
            row.update({"DefinitionType": "DOMAIN", "Name": name, "Enabled": "TRUE", "Confidence": "100", "Domain": domain, "AppExpressMode": "MONITOR"})
            rows.append(row)
        with conflict_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, APP_DEF_HEADERS)
            writer.writeheader()
            writer.writerows(rows)

        dry_gateway = AppDefinitionDeployGateway()
        dry_gateway.inventories["dnsClassification"] = [{"domain": "collision.example.com", "name": "existing-app", "description": "", "priority": 100, "disabled": False}]
        with patch("edgeconnect_automation.cli._gateway", return_value=dry_gateway), patch("sys.stdin.isatty", return_value=False):
            self.assertEqual(main(["app-definitions", "deploy", "--csv", str(conflict_csv), "--dry-run"]), 5)
        self.assertEqual(dry_gateway.definition_posts, 0)
        self.assertEqual(dry_gateway.appexpress_posts, 0)

        apply_gateway = AppDefinitionDeployGateway()
        apply_gateway.inventories["dnsClassification"] = copy.deepcopy(dry_gateway.inventories["dnsClassification"])
        report = Path(self.directory.name) / "applications-conflict-report.json"
        with patch("edgeconnect_automation.cli._gateway", return_value=apply_gateway), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            self.assertEqual(main(["app-definitions", "deploy", "--csv", str(conflict_csv), "--report", str(report)]), 5)
        self.assertEqual(apply_gateway.definition_posts, 1)
        self.assertEqual(apply_gateway.appexpress_posts, 1)
        self.assertIn("valid-app", apply_gateway.appexpress)
        self.assertNotIn("conflict-app", apply_gateway.appexpress)
        result = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(result["result"]["status"], "partial")
        self.assertEqual(result["result"]["skipped_conflicts"][0]["name"], "conflict-app")
        self.assertEqual(result["result"]["skipped_conflicts"][0]["reason"], "existing domain identity has different semantics")

    def test_delete_confirmation_requires_all_three_stages(self):
        rows = [("Service group", "test", "exact CSV semantic match")]
        with patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
            self.assertTrue(_approve_delete(rows, False))
        with patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", return_value="wrong"):
            with self.assertRaises(ApprovalError):
                _approve_delete(rows, False)

    def test_address_group_delete_dry_run_and_confirmed_apply(self):
        expected = {"name": "new", "type": None, "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}
        dry_gateway = BulkDeployGateway()
        dry_gateway.values = [copy.deepcopy(expected)]
        with patch("edgeconnect_automation.cli._gateway", return_value=dry_gateway):
            self.assertEqual(main(["address-groups", "delete", "--csv", str(self.address_csv), "--dry-run"]), 0)
        self.assertEqual(len(dry_gateway.values), 1)
        apply_gateway = BulkDeployGateway()
        apply_gateway.values = [copy.deepcopy(expected)]
        with patch("edgeconnect_automation.cli._gateway", return_value=apply_gateway), patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
            self.assertEqual(main(["address-groups", "delete", "--csv", str(self.address_csv)]), 0)
        self.assertFalse(apply_gateway.values)

    def test_delete_blocks_semantically_different_group(self):
        gateway = BulkDeployGateway()
        gateway.values = [{"name": "new", "type": "AG", "rules": [{"includedIPs": ["10.99.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway):
            self.assertEqual(main(["address-groups", "delete", "--csv", str(self.address_csv), "--dry-run"]), 2)
        self.assertEqual(len(gateway.values), 1)

    def test_firewall_delete_exact_rule(self):
        rule = parse_firewall_text(HEADERS + "\n" + ROW)[0]
        policy = baseline()
        policy["data"]["map1"] = {"1_2": {"prio": {"20000": rule_payload(rule)}}}
        gateway = DeployGateway(policy)
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
            self.assertEqual(main(["firewall", "delete", "--csv", str(self.csv)]), 0)
        self.assertNotIn("20000", gateway.policy["data"]["map1"]["1_2"]["prio"])

    def test_application_group_delete_exact_collection_entry(self):
        class Gateway:
            def __init__(self):
                self.value = {"test-group": {"apps": ["monitor-app"], "parentGroup": None}, "keep": {"apps": [], "parentGroup": None}}

            def get_application_groups(self):
                return copy.deepcopy(self.value)

            def post_application_groups(self, value):
                self.value = copy.deepcopy(value)

        gateway = Gateway()
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
            self.assertEqual(main(["app-groups", "delete", "--csv", str(self.app_group_csv)]), 0)
        self.assertNotIn("test-group", gateway.value)
        self.assertIn("keep", gateway.value)

    def test_application_definition_delete_removes_integrated_appexpress(self):
        gateway = AppDefinitionDeployGateway()
        gateway.inventories["dnsClassification"] = [{"domain": "monitor.example.com", "name": "monitor-app", "description": "monitor test", "priority": 100, "disabled": False}]
        gateway.appexpress = {"monitor-app": {"id": 1, "name": "monitor-app", "monitor": True, "appExpressEnabled": False}}
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
            self.assertEqual(main(["app-definitions", "delete", "--csv", str(self.application_csv)]), 0)
        self.assertFalse(gateway.inventories["dnsClassification"])
        self.assertFalse(gateway.appexpress)

    def test_appexpress_delete_exact_monitor_entry(self):
        gateway = AppDefinitionDeployGateway()
        gateway.appexpress = {"monitor-app": {"id": 1, "name": "monitor-app", "monitor": True, "appExpressEnabled": False}, "keep": {"id": 2, "name": "Keep", "monitor": True, "appExpressEnabled": False}}
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
            self.assertEqual(main(["appexpress", "delete", "--csv", str(self.appexpress_csv)]), 0)
        self.assertNotIn("monitor-app", gateway.appexpress)
        self.assertIn("keep", gateway.appexpress)

    def test_firewall_deploy_tty_apply_writes(self):
        gateway = DeployGateway(baseline())
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            code = main(["firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.inventory)])
        self.assertEqual(code, 0)
        self.assertEqual(gateway.posts, 1)


if __name__ == "__main__":
    unittest.main()
