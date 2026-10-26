import csv
import io
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation import engine, gui_editor
from edgeconnect_automation.firewall import FIREWALL_HEADERS
from tests.test_engine import WritableGateway
from tests.test_gui import Offline, ServerCase
from tests.test_gui_tables import InventoryTests


class SearchGateway:
    def __init__(self, found):
        self.found = found
        self.patterns = []

    def get_application_definitions(self, base):
        return {"portProtocolClassification": {"6": [{"name": "Corp-Web"}]}, "dnsClassification": [{"name": "corp-dns"}], "compoundClassification": {"x": {"name": "Payroll"}}}[base]

    def get_application_groups(self):
        return {"Corp-Apps": {}, "Finance": {}}

    def search_application(self, pattern):
        self.patterns.append(pattern)
        return self.found

    def search_application_group(self, pattern):
        self.patterns.append(pattern)
        return self.found


class EditorTests(unittest.TestCase):
    def test_every_firewall_column_in_the_templates_order(self):
        header = next(csv.reader((gui_editor.TEMPLATES / "firewall_rules.csv").open(encoding="utf-8")))
        self.assertEqual(gui_editor.FIELD_NAMES, header)
        self.assertEqual(set(gui_editor.FIELD_NAMES), FIREWALL_HEADERS)
        self.assertEqual({field["name"] for field in gui_editor.FIREWALL_FIELDS if field["kind"] in ("name", "names", "search")}, {
            "source_segment", "destination_segment", "source_zone", "destination_zone", "source_address_group", "destination_address_group", "either_address_group",
            "application", "application_group", "source_service_group", "destination_service_group", "either_service_group"})

    def test_starting_points_are_the_template_and_examples_and_nothing_else(self):
        ids = [item["id"] for item in gui_editor.sources()]
        self.assertEqual(ids[0], "template")
        self.assertIn("example:firewall_rules_valid.csv", ids)
        for bad in ("example:../../setup.py", "example:address_groups_valid.csv", "../templates/edgeconnect/firewall_rules.csv", ""):
            with self.assertRaises(ValueError):
                gui_editor.source(bad)

    def test_parse_and_write_keep_every_value_and_extra_column(self):
        for item in gui_editor.sources():
            parsed = gui_editor.parse(gui_editor.source(item["id"]))
            self.assertTrue(parsed["rows"])
            self.assertEqual(gui_editor.parse(gui_editor.write(parsed["rows"], parsed["extra"])), parsed, item["id"])
        legacy = gui_editor.parse('﻿rule_key,action,note\nr1,"allow","a, ""quoted"" note"\n')
        self.assertEqual((legacy["extra"], legacy["rows"][0]["note"], legacy["rows"][0]["source_zone"]), (["note"], 'a, "quoted" note', ""))
        self.assertEqual(gui_editor.write(legacy["rows"], legacy["extra"]).splitlines()[0].split(",")[-2:], ["broad_match_ack", "note"])

    def test_choices_come_from_the_inventory(self):
        discovery = dict(InventoryTests.DISCOVERY, segment_zones=[{"vrfName": "Default", "zoneName": "INSIDE", "zoneId": 2}, {"vrfName": "Default", "zoneName": "OUTSIDE", "zoneId": 10}, {"vrfName": "Guest", "zoneName": "INSIDE", "zoneId": 2}])
        self.assertEqual(gui_editor.options(discovery), {
            "segments": ["Default", "Guest"], "zones": {"Default": ["INSIDE", "OUTSIDE"], "Guest": ["INSIDE"]}, "all_zones": ["INSIDE", "OUTSIDE"],
            "address_groups": ["web"], "service_groups": ["https"]})
        self.assertEqual(gui_editor.options({}), {"segments": [], "zones": {}, "all_zones": [], "address_groups": [], "service_groups": []})

    def test_search_finds_user_defined_and_built_in_names(self):
        gateway = SearchGateway({"apps": [{"name": "Corporate-VPN"}, {"name": "office365"}], "more": ["corp-mail"]})
        self.assertEqual(gui_editor.search("applications", " corp ", gateway=gateway), ["corp-dns", "corp-mail", "Corp-Web", "Corporate-VPN"])
        self.assertEqual(gateway.patterns, ["*corp*"])
        self.assertEqual(gui_editor.search("application_groups", "an", gateway=SearchGateway([{"group": "Banking"}])), ["any", "Banking", "Finance"])
        self.assertEqual(gui_editor.search("applications", "  ", gateway=gateway), [])
        with self.assertRaises(ValueError):
            gui_editor.search("zones", "x", gateway=gateway)

    def test_5000_rows_parse_and_write_quickly(self):
        row = gui_editor.parse(gui_editor.source("template"))["rows"][0]
        rows = [dict(row, rule_key="rule-{}".format(number), priority=str(20000 + number)) for number in range(5000)]
        started = time.monotonic()
        text = gui_editor.write(rows)
        parsed = gui_editor.parse(text)
        self.assertEqual(len(parsed["rows"]), 5000)
        self.assertLess(time.monotonic() - started, 2)
        self.assertLess(len(json.dumps(parsed)), 5 * 1024 * 1024, "fits in one request to the GUI server")


class SavedCsvChecksTheSame(Offline):
    def test_a_saved_csv_validates_exactly_like_the_one_it_came_from(self):
        for name in ("firewall_rules_valid.csv", "firewall_rules_mixed.csv"):
            parsed = gui_editor.parse(Path(name).read_text(encoding="utf-8"))
            Path("saved.csv").write_text(gui_editor.write(parsed["rows"], parsed["extra"]), encoding="utf-8")
            original, saved = engine.validate(name, report_dir=""), engine.validate("saved.csv", report_dir="")
            self.assertEqual((saved.status, saved.issues, saved.warnings), (original.status, original.issues, original.warnings), name)


class EditorServerTests(ServerCase):
    def test_editor_endpoints(self):
        spec = json.loads(self.request("GET", "/api/editor/firewall")[1])
        self.assertEqual(([field["name"] for field in spec["fields"]], spec["blank"]["action"]), (gui_editor.FIELD_NAMES, "allow"))
        template = json.loads(self.request("GET", "/api/editor/firewall/source?id=template")[1])
        self.assertTrue(template["rows"])
        self.assertEqual(self.request("GET", "/api/editor/firewall/source?id=example:../../setup.py")[0].status, 404)
        written = json.loads(self.request("POST", "/api/editor/firewall/csv", {"rows": template["rows"], "extra": []})[1])["csv_text"]
        self.assertEqual(json.loads(self.request("POST", "/api/editor/firewall/parse", {"csv_text": written})[1]), template)
        self.assertEqual(self.request("POST", "/api/editor/firewall/csv", {"rows": "x"})[0].status, 400)
        self.assertEqual(self.request("POST", "/api/editor/firewall/csv", {"rows": []}, cookie=False)[0].status, 401)
        self.assertEqual(self.request("GET", "/api/editor/search?orchestrator=lab&kind=zones&q=x")[0].status, 400)
        self.assertEqual(self.request("GET", "/api/editor/search?orchestrator=nope&kind=applications&q=x")[0].status, 400)
        with patch("edgeconnect_automation.gui_editor.OrchestratorGateway", lambda client: SearchGateway([{"name": "corp-mail"}])), patch("edgeconnect_automation.gui_editor.ApiClient"):
            response, text = self.request("GET", "/api/editor/search?orchestrator=lab&kind=applications&q=corp")
        self.assertEqual((response.status, json.loads(text)), (200, {"names": ["corp-dns", "corp-mail", "Corp-Web"]}))
        with patch.object(WritableGateway, "discover", return_value=InventoryTests.DISCOVERY, create=True):
            task = self.wait(self.server.tasks.create({"action": "discover", "orchestrator": "lab"}), "done", "failed")
        self.assertEqual(json.loads(self.request("GET", "/api/editor/options?task=" + task.id)[1])["segments"], ["Default", "Guest"])
        self.assertFalse([body for body in self.bodies if "SECRET-KEY" in body])


if __name__ == "__main__":
    unittest.main()
