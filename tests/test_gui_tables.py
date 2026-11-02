import json
import time
import unittest
from pathlib import Path

from edgeconnect_automation import engine, gui_tables
from edgeconnect_automation.cli import main
from edgeconnect_automation.reporting import summaries_from_file, write_rows_csv
from tests.test_gui import Offline

ALL = {"size": "200"}


class RunLogTests(Offline):
    def log_runs(self):
        reports = self.root / "reports"
        for argv in (
            ["address-groups", "plan", "--csv", "address_groups_valid.csv", "--output", "groups.json"],
            ["firewall", "validate", "--csv", "firewall_rules_mixed.csv"],
            ["address-groups", "delete", "--csv", "address_groups_delete.csv", "--dry-run"],
        ):
            main(["--report-dir", str(reports)] + argv)
        engine.plan("zones", "zones.json", report_dir=str(reports), name=["NEW_ZONE"])
        return reports

    def test_each_run_records_whether_the_cli_or_the_gui_ran_it(self):
        reports = self.log_runs()
        records = [json.loads(line) for path in sorted(reports.glob("*.jsonl")) for line in path.read_text().splitlines()]
        self.assertEqual(sorted((record["workflow"], record["source"], record["summary"]["source"]) for record in records), [
            ("address-groups delete", "cli", "cli"), ("address-groups plan", "cli", "cli"), ("firewall validate", "cli", "cli"), ("zones plan-missing", "gui", "gui")])

    def test_tables_show_what_report_summarize_shows_for_the_same_files(self):
        reports = self.log_runs()
        log = gui_tables.RunLog(reports)
        runs = log.runs()[0]
        expected = [summary for path in sorted(reports.glob("*.jsonl")) for summary in summaries_from_file(str(path), 0)]
        self.assertEqual(len(runs), len(expected))
        for summary in expected:
            run = next(run for run in runs if run["run_id"] == summary["run_id"])
            for key in ("timestamp", "orchestrator", "workflow", "status", "changes_written", "duration_seconds", "source", "exit_code"):
                self.assertEqual(run[key], summary[key], key)
            self.assertEqual(run["row_outcomes"], ", ".join("{} {}".format(count, outcome) for outcome, count in sorted(summary["row_outcomes"].items())))
            detail = gui_tables.run_detail(log.find(summary["run_id"]), ALL)
            self.assertEqual([{key: row[key] for key in ("row", "item", "scope", "outcome", "reason")} for row in detail["rows"]["rows"]], summary["rows"])
            self.assertEqual((detail["run"]["counts"], detail["run"]["blocking_issues"], detail["run"]["next_step"]), (summary["counts"], summary["blocking_issues"], summary["next_step"]))
            write_rows_csv("expected.csv", summary["rows"])
            self.assertEqual(gui_tables.to_csv(gui_tables.select(log.find(summary["run_id"])["_outcomes"], {}, ("outcome",))[0], gui_tables.ROW_FIELDS), Path("expected.csv").read_bytes())
        validate = next(run for run in runs if run["workflow"] == "firewall validate")
        self.assertEqual((validate["status"], validate["tone"]), ("INVALID", "bad"))

    def test_a_damaged_line_is_counted_and_the_rest_still_shown(self):
        reports = self.log_runs()
        with (reports / "firewall.jsonl").open("a") as handle:
            handle.write('{"half a record\n')
        runs, unreadable = gui_tables.RunLog(reports).runs()
        self.assertEqual((len(runs), unreadable), (4, 1))
        self.assertEqual(gui_tables.RunLog(self.root / "missing").runs(), ([], 0))

    def test_records_from_before_run_ids_each_get_their_own_id(self):
        reports = self.root / "reports"
        reports.mkdir()
        record = json.dumps({"preview": {"kind": "address-groups", "new": []}, "result": {"status": "SUCCESS"}})
        (reports / "address-groups.jsonl").write_text(record + "\n" + record + "\n")
        log = gui_tables.RunLog(reports)
        runs = log.runs()[0]
        self.assertEqual(sorted(run["run_id"] for run in runs), ["address-groups-line-1", "address-groups-line-2"])
        self.assertEqual((runs[0]["source"], log.find("address-groups-line-2")["status"]), ("not recorded", "SUCCESS"))


def rows(count):
    return [dict(name="row-{:05d}".format(number), size=number % 7, kind=("a", "b", "c")[number % 3], _problem=number % 10 == 0, _text="row-{:05d} kind-{}".format(number, ("a", "b", "c")[number % 3])) for number in range(count)]


class TableTests(unittest.TestCase):
    def test_search_filter_problems_sort_and_page(self):
        data = rows(1000)
        result = gui_tables.page(data, {"q": "KIND-B", "kind": "b", "problems": "1", "sort": "size", "order": "desc", "size": "25", "page": "2"}, ("kind",))
        self.assertEqual((result["total"], result["matching"], result["pages"], result["page"], len(result["rows"])), (1000, 33, 2, 2, 8))
        self.assertEqual(result["facets"], {"kind": ["a", "b", "c"]})
        self.assertNotIn("_text", result["rows"][0])
        sizes = [row["size"] for row in gui_tables.select(data, {"q": "kind-b", "problems": "1", "sort": "size", "order": "desc"}, ("kind",))[0]]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_bad_paging_values_fall_back_and_unknown_sort_columns_are_ignored(self):
        result = gui_tables.page(rows(120), {"size": "7", "page": "99", "sort": "__class__"}, default_sort="name")
        self.assertEqual((result["size"], result["page"], result["sort"], result["rows"][0]["name"]), (50, 3, "name", "row-00100"))
        self.assertEqual(gui_tables.page(rows(3), {"page": "x"})["page"], 1)

    def test_numbers_and_numeric_text_sort_as_numbers_and_blanks_go_last(self):
        data = [dict(id=value, _problem=False, _text="") for value in ("10", "9", "", "100", None)]
        self.assertEqual([row["id"] for row in gui_tables.select(data, {"sort": "id"})[0]], ["9", "10", "100", "", None])
        self.assertEqual([row["id"] for row in gui_tables.select(data, {"sort": "id", "order": "desc"})[0]], ["100", "10", "9", "", None])

    def test_10000_runs_stay_responsive(self):
        """The browser only receives one page; loading, searching and sorting 10,000 logged runs stays fast on the server."""
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.jsonl"
            run_rows = [{"row": number, "item": "rule-{}".format(number), "scope": "Default -> Default", "outcome": "CREATED", "reason": ""} for number in range(2, 12)]
            with path.open("w") as handle:
                for number in range(10000):
                    summary = {"run_id": "run-{:012d}".format(number), "timestamp": "2026-10-26T{:02d}:{:02d}:{:02d}+00:00".format(number // 3600 % 24, number // 60 % 60, number % 60), "workflow": "firewall deploy", "status": "SUCCESS" if number % 50 else "FAILED", "orchestrator": ("lab", "lab2")[number % 2], "changes_written": "yes", "exit_code": 0, "duration_seconds": 1.5, "source": "cli", "row_outcomes": {"CREATED": 10}, "rows": run_rows, "counts": [], "blocking_issues": []}
                    handle.write(json.dumps({"summary": summary, "outputs": [{"preview": {"rules": run_rows}}]}) + "\n")
            log = gui_tables.RunLog(Path(directory))
            started = time.monotonic()
            runs = log.runs()[0]
            loaded = time.monotonic() - started
            started = time.monotonic()
            result = gui_tables.page(runs, {"q": "run-0000000012", "orchestrator": "lab", "sort": "status", "size": "50"}, gui_tables.RUN_FILTERS, "timestamp", True)
            problems = gui_tables.page(runs, {"problems": "1"}, gui_tables.RUN_FILTERS, "timestamp", True)
            queried = time.monotonic() - started
            started = time.monotonic()
            log.runs()
            cached = time.monotonic() - started
        self.assertEqual((len(runs), result["matching"], len(result["rows"]), problems["matching"]), (10000, 50, 50, 200))
        self.assertLess(loaded, 15, "first load of 10,000 runs")
        self.assertLess(queried, 1, "two queries over 10,000 runs")
        self.assertLess(cached, 1, "an unchanged log is not read again")


class InventoryTests(unittest.TestCase):
    DISCOVERY = {
        "version": {"release": "9.7.1"},
        "segments": {"0": {"id": 0, "name": "Default"}, "1": {"id": 1, "name": "Guest"}},
        "zones": {"10": {"name": "OUTSIDE"}, "2": {"name": "INSIDE"}},
        "segment_zones": [{"vrfName": "Default", "zoneName": "INSIDE", "zoneId": 2}],
        "address_groups": [{"name": "web", "rules": [{"includedIPs": ["10.0.0.0/24", "10.0.1.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}, {"includedIPs": ["10.9.0.0/16"], "comment": "dc"}]}],
        "service_groups": [{"name": "https", "rules": [{"protocol": "TCP", "includedPorts": ["443"]}]}],
    }

    def test_each_tab_is_a_searchable_paged_table(self):
        result = gui_tables.inventory_page(self.DISCOVERY, {"tab": "zones"})
        self.assertEqual(result["tabs"], [{"id": "segments", "label": "Segments", "count": 2}, {"id": "zones", "label": "Zones", "count": 2}, {"id": "segment_zones", "label": "Zones per segment", "count": 1}, {"id": "address_groups", "label": "Address groups", "count": 1}, {"id": "service_groups", "label": "Service groups", "count": 1}])
        self.assertEqual(result["table"]["rows"], [{"id": "2", "name": "INSIDE"}, {"id": "10", "name": "OUTSIDE"}])
        groups = gui_tables.inventory_page(self.DISCOVERY, {"tab": "address_groups", "q": "10.9."})["table"]["rows"]
        self.assertEqual(groups, [{"name": "web", "rules": 2, "included_ips": "10.0.0.0/24, 10.0.1.0/24; 10.9.0.0/16", "excluded_ips": "", "included_groups": "", "comment": "dc"}])
        self.assertEqual(gui_tables.inventory_page(self.DISCOVERY, {"tab": "nope"})["tab"], "segments")

    def test_unexpected_shapes_give_empty_tables_not_errors(self):
        result = gui_tables.inventory_page({"zones": [1, 2], "address_groups": {"a": 1}, "version": "9"}, {"tab": "zones"})
        self.assertEqual(([tab["count"] for tab in result["tabs"]], result["release"]), ([0, 0, 0, 0, 0], ""))


if __name__ == "__main__":
    unittest.main()
