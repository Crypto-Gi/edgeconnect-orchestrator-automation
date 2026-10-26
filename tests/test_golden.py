"""Golden CLI outputs: exact text each representative read-only command prints and writes.

These pin CLI behaviour while the GUI refactor moves code around (docs/gui/BUILD_PLAN.md, steps 1 to 4).
Regenerate after an intended output change with: EDGECONNECT_UPDATE_GOLDEN=1 PYTHONPATH=src python3 -m unittest tests.test_golden
"""
import contextlib
import copy
import io
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation.cli import main
from edgeconnect_automation.firewall import parse_firewall_text, rule_payload
from tests.test_inventory_cli import HEADERS, ROW, baseline

GOLDEN = Path(__file__).parent / "golden"
UPDATE = os.environ.get("EDGECONNECT_UPDATE_GOLDEN") == "1"


class GoldenGateway:
    """A small fixed Orchestrator: one segment, two zones, one firewall rule, and one object of each kind. It refuses every write."""

    def __init__(self, client):
        self.client = client
        policy = baseline()
        policy["data"]["map1"] = {"1_2": {"prio": {"20000": rule_payload(parse_firewall_text(HEADERS + "\n" + ROW)[0])}}}
        self.policy = policy

    def __getattr__(self, name):
        if name.split("_")[0] in {"post", "upload", "delete", "create", "select"}:
            raise AssertionError("golden runs never write; {} was called".format(name))
        raise AttributeError(name)

    def get_version(self):
        return {"release": "9.7.1"}

    def get_server_id(self):
        return "ORCH-SERIAL-1"

    def get_segmentation(self):
        return {"enable": True}

    def get_segments(self):
        return {"0": {"id": 0, "name": "Default"}}

    def get_segment_zones(self):
        return [{"vrfName": "Default", "zoneName": name, "zoneId": number} for number, name in enumerate(("INSIDE", "OUTSIDE", "SOURCE_ZONE", "DESTINATION_ZONE"), 1)]

    def get_policy(self, segment_map):
        return copy.deepcopy(self.policy)

    def get_central_acls(self, names=None):
        return {}

    def get_zones(self):
        return {str(number): {"name": name} for number, name in enumerate(("INSIDE", "OUTSIDE", "SOURCE_ZONE", "DESTINATION_ZONE"), 1)}

    def get_all_vrf_zones(self):
        return {}

    def get_zone_mappings(self):
        return {}

    def get_next_zone_id(self):
        return 5

    def get_address_groups(self):
        return [{"name": "existing-ag", "type": None, "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]

    def get_service_groups(self):
        return [{"name": "existing-sg", "type": None, "rules": [{"protocol": "TCP", "includedPorts": ["443"], "excludedPorts": [], "includedGroups": [], "excludedGroups": [], "icmpTypes": [], "icmpCodes": [], "comment": None}]}]

    def get_application_groups(self):
        return {"existing-group": {"apps": ["existing-app"], "parentGroup": None}}

    def get_application_definitions(self, base):
        return [{"domain": "existing.example.com", "name": "existing-app", "description": "", "priority": 100, "disabled": False}] if base == "dnsClassification" else {}

    def get_appexpress(self):
        return {}

    def get_countries(self):
        return {"United States of America": ["1", "0", "United States of America", "US"], "Canada": ["2", "0", "Canada", "CA"]}

    def get_interface_labels(self):
        return {"lan": {"5": {"name": "EXISTING_INTERFACE_LABEL", "active": True}, "6": {"name": "Voice", "active": True}, "7": {"name": "Data", "active": True}}, "wan": {"1": {"name": "MPLS1", "active": True}}}

    def search_address_map(self, name):
        return [{"name": name}]

    def search_application(self, name):
        return [{"name": name}]

    def search_application_group(self, name):
        return [{"group": name}]

    def get_template_groups(self):
        return [self.get_template_group("Default Template Group")]

    def get_template_group(self, name):
        acls = {"name": "acls", "value": {"data": {"EXISTING-ACL": {"entry": {}}}, "options": {"merge": True, "delDependent": True}}}
        return {"name": name, "selectedTemplateNames": ["acls"], "templates": [acls]} if name == "Default Template Group" else None

    def get_template_selection(self, name):
        return []

    def get_template_associations(self):
        return {"0.NE": ["Default Template Group"]}

    def get_appliances(self):
        return [{"nePk": "0.NE", "hostName": "edge-a", "state": 1, "softwareVersion": "9.5.4.1_1"}]

    def get_paused_orchestration(self):
        return []

    def get_reachability(self, nepk):
        return {"id": nepk, "state": 1}

    def get_security_map(self, nepk):
        return {"map1": {}}

    def get_appliance_acls(self, nepk):
        return {}

    def get_appliance_acl_details(self, nepk):
        return {}

    def get_actions(self, start, end):
        return []


SCENARIOS = {
    "firewall-validate-valid": ["firewall", "validate", "--csv", "firewall_rules_valid.csv"],
    "firewall-validate-mixed": ["firewall", "validate", "--csv", "firewall_rules_mixed.csv"],
    "firewall-plan-offline": ["firewall", "plan", "--csv", "firewall_rules_valid.csv", "--inventory", "firewall_inventory.json", "--output", "firewall-plan.json"],
    "firewall-plan-offline-small": ["firewall", "plan", "--csv", "firewall_rules_small.csv", "--inventory", "firewall_inventory.json", "--output", "firewall-small-plan.json"],
    "firewall-deploy-dry-run-small": ["firewall", "deploy", "--csv", "firewall_rules_small.csv", "--dry-run", "--report", "firewall-small-report.json"],
    "firewall-deploy-dry-run": ["firewall", "deploy", "--csv", "firewall_rules_valid.csv", "--dry-run", "--report", "firewall-report.json"],
    "firewall-delete-dry-run": ["firewall", "delete", "--csv", "firewall_delete.csv", "--dry-run", "--report", "firewall-delete-report.json"],
    "template-acls-plan-small": ["template-acls", "plan", "--csv", "template_acls_small.csv", "--output", "template-acls-small-plan.json"],
    "template-acls-deploy-dry-run-small": ["template-acls", "deploy", "--csv", "template_acls_small.csv", "--dry-run"],
    "template-acls-plan": ["template-acls", "plan", "--csv", "template_acls_valid.csv", "--output", "template-acls-plan.json"],
    "template-acls-deploy-dry-run": ["template-acls", "deploy", "--csv", "template_acls_valid.csv", "--dry-run"],
    "template-acls-delete-dry-run": ["template-acls", "delete", "--csv", "template_acls_valid.csv", "--dry-run"],
    "zones-plan-missing": ["zones", "plan-missing", "--name", "NEW_ZONE", "--name", "INSIDE", "--output", "zones-plan.json"],
    "zones-create-dry-run": ["zones", "create", "--name", "NEW_ZONE", "--dry-run"],
    "address-groups-plan": ["address-groups", "plan", "--csv", "address_groups_valid.csv", "--output", "address-plan.json"],
    "address-groups-deploy-dry-run": ["address-groups", "deploy", "--csv", "address_groups_valid.csv", "--dry-run"],
    "address-groups-delete-dry-run": ["address-groups", "delete", "--csv", "address_groups_delete.csv", "--dry-run"],
    "service-groups-plan": ["service-groups", "plan", "--csv", "service_groups_valid.csv", "--output", "service-plan.json"],
    "service-groups-deploy-dry-run": ["service-groups", "deploy", "--csv", "service_groups_valid.csv", "--dry-run"],
    "service-groups-delete-dry-run": ["service-groups", "delete", "--csv", "service_groups_delete.csv", "--dry-run"],
    "app-groups-plan": ["app-groups", "plan", "--csv", "application_groups_valid.csv", "--output", "app-groups-plan.json"],
    "app-groups-deploy-dry-run": ["app-groups", "deploy", "--csv", "application_groups_valid.csv", "--dry-run"],
    "app-groups-delete-dry-run": ["app-groups", "delete", "--csv", "application_groups_delete.csv", "--dry-run"],
    "app-definitions-plan": ["app-definitions", "plan", "--csv", "application_definitions_valid.csv", "--output", "app-definitions-plan.json"],
    "app-definitions-deploy-dry-run": ["app-definitions", "deploy", "--csv", "application_definitions_valid.csv", "--dry-run"],
}
# Each plan is then applied with --dry-run, which reads the saved plan back.
APPLY_DRY_RUN = {
    "address-groups-apply-dry-run": ("address-groups-plan", ["address-groups", "apply", "--approved-plan", "address-plan.json", "--dry-run"]),
    "service-groups-apply-dry-run": ("service-groups-plan", ["service-groups", "apply", "--approved-plan", "service-plan.json", "--dry-run"]),
    "app-groups-apply-dry-run": ("app-groups-plan", ["app-groups", "apply", "--approved-plan", "app-groups-plan.json", "--dry-run"]),
    "app-definitions-apply-dry-run": ("app-definitions-plan", ["app-definitions", "apply", "--approved-plan", "app-definitions-plan.json", "--dry-run"]),
    "zones-apply-dry-run": ("zones-plan-missing", ["zones", "apply", "--approved-plan", "zones-plan.json", "--dry-run"]),
    "template-acls-apply-dry-run": ("template-acls-plan-small", ["template-acls", "apply", "--approved-plan", "template-acls-small-plan.json", "--dry-run"]),
    "firewall-apply-dry-run": ("firewall-plan-offline-small", ["firewall", "apply", "--approved-plan", "firewall-small-plan.json", "--dry-run"]),
}

_VOLATILE = [
    (re.compile(r"run-[0-9a-f]{12}"), "run-<ID>"),
    (re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?([+-]\d\d:\d\d|Z)?"), "<TIME>"),
    (re.compile(r"\(\d+\.\d+s\)"), "(<SECONDS>)"),
    (re.compile(r'"duration_seconds": [0-9.]+'), '"duration_seconds": "<SECONDS>"'),
    (re.compile(r"tool \d+\.\d+\.\d+[0-9a-z.]*"), "tool <VERSION>"),
    (re.compile(r'"tool_version": "[^"]*"'), '"tool_version": "<VERSION>"'),
    # Report fingerprints cover the run's own time and ID; the content they cover is compared directly.
    (re.compile(r'"report_fingerprint": "sha256:[0-9a-f]{64}"'), '"report_fingerprint": "<FINGERPRINT>"'),
]


def _normalize(text, root):
    text = text.replace(str(root) + os.sep, "").replace(str(root), ".")
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def run(argv, root):
    """Run one CLI command in root against GoldenGateway; return its normalized output and every file it wrote."""
    config = SimpleNamespace(name="lab", base_url="https://orchestrator.invalid/gms/rest")
    client = SimpleNamespace(write_requests=0)
    before = {path for path in root.rglob("*") if path.is_file()}
    out, err = io.StringIO(), io.StringIO()
    with patch("edgeconnect_automation.cli.load_config", return_value=config), patch("edgeconnect_automation.cli.ApiClient", return_value=client), patch("edgeconnect_automation.cli.OrchestratorGateway", GoldenGateway), patch("sys.stdin.isatty", return_value=False), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(["--report-dir", "reports"] + argv)
    parts = ["$ edgeconnect-auto {}".format(" ".join(argv)), "exit code: {}".format(code), "--- stdout", out.getvalue(), "--- stderr", err.getvalue()]
    for path in sorted(path for path in root.rglob("*") if path.is_file() and (path not in before or path.suffix in {".jsonl", ".log"})):
        parts += ["--- file {}".format(path.relative_to(root).as_posix()), path.read_text(encoding="utf-8")]
    return _normalize("\n".join(parts), root)


class GoldenOutputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        for path in (GOLDEN / "inputs").iterdir():
            shutil.copy(path, self.root / path.name)
        self.cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self.cwd)
        self.directory.cleanup()

    def check(self, name, text):
        expected = GOLDEN / "{}.txt".format(name)
        if UPDATE:
            expected.write_text(text, encoding="utf-8")
        self.assertEqual(text, expected.read_text(encoding="utf-8"), "golden output changed for {}".format(name))
        self.assertNotIn("Traceback", text)
        self.assertNotIn("AttributeError", text)

    def test_commands_match_golden_outputs(self):
        for name, argv in SCENARIOS.items():
            with self.subTest(name):
                shutil.rmtree(self.root / "reports", ignore_errors=True)
                self.check(name, run(argv, self.root))

    def test_apply_dry_run_of_saved_plans_matches_golden_outputs(self):
        for name, (plan, argv) in APPLY_DRY_RUN.items():
            with self.subTest(name):
                shutil.rmtree(self.root / "reports", ignore_errors=True)
                run(SCENARIOS[plan], self.root)
                shutil.rmtree(self.root / "reports", ignore_errors=True)
                self.check(name, run(argv, self.root))

    def test_report_summarize_matches_golden_output(self):
        run(SCENARIOS["address-groups-deploy-dry-run"], self.root)
        run(SCENARIOS["firewall-validate-mixed"], self.root)
        for log in ("address-groups", "firewall"):
            with self.subTest(log):
                self.check("report-summarize-" + log, run(["report", "summarize", "reports/{}.jsonl".format(log), "--last", "0"], self.root))


if __name__ == "__main__":
    unittest.main()
