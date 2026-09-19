import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation.cli import _discover_inventory, main
from edgeconnect_automation.firewall import parse_firewall_text


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


class DeployCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.csv = root / "rules.csv"
        self.csv.write_text(HEADERS + "\n" + ROW + "\n", encoding="utf-8")
        self.address_csv = root / "address.csv"
        self.address_csv.write_text("Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nnew,10.0.0.0/24,,,\n", encoding="utf-8")
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

    def test_firewall_deploy_tty_apply_writes(self):
        gateway = DeployGateway(baseline())
        with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            code = main(["firewall", "deploy", "--csv", str(self.csv), "--inventory", str(self.inventory)])
        self.assertEqual(code, 0)
        self.assertEqual(gateway.posts, 1)


if __name__ == "__main__":
    unittest.main()
