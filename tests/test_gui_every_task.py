import json
from pathlib import Path

from edgeconnect_automation.approval import DELETE_ACKNOWLEDGMENT
from edgeconnect_automation.cli import main
from tests.test_engine import WritableGateway
from tests.test_gui import Offline

EXISTING = {"name": "existing-ag", "type": None, "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}
CSV_KINDS = {
    "firewall": "firewall_rules_small.csv",
    "template-acls": "template_acls_small.csv",
    "address-groups": "address_groups_valid.csv",
    "service-groups": "service_groups_valid.csv",
    "app-groups": "application_groups_valid.csv",
    "app-definitions": "application_definitions_valid.csv",
}


class EveryTaskTests(Offline):
    def test_each_task_plans_the_same_through_the_cli_and_the_gui(self):
        tasks = self.manager()
        requests = dict({kind: ({"csv_text": Path(csv).read_text(encoding="utf-8")}, ["--csv", csv]) for kind, csv in CSV_KINDS.items()},
                        zones=({"names": ["NEW_ZONE", "INSIDE"]}, ["--name", "NEW_ZONE", "--name", "INSIDE"]))
        for kind, (body, flags) in requests.items():
            with self.subTest(kind):
                verb = "plan-missing" if kind == "zones" else "plan"
                main(["--report-dir", "", kind, verb, "--output", "cli.json"] + flags)
                task = self.wait(tasks.create(dict(body, action="plan", orchestrator="lab", kind=kind)), "planned", "failed")
                self.assertEqual(task.state, "planned", task.message)
                self.assertEqual(json.loads((task.folder / "plan.json").read_text()), json.loads(Path("cli.json").read_text()))
                self.assertTrue(task.result.changes)

    def delete_awaiting_approval(self, tasks):
        WritableGateway.groups = [dict(EXISTING)]
        task = self.wait(tasks.create({"action": "delete", "orchestrator": "lab", "kind": "address-groups", "csv_text": Path("address_groups_delete.csv").read_text()}), "awaiting_approval", "failed", "done")
        self.assertEqual(task.state, "awaiting_approval", task.message)
        self.assertEqual([(row["action"], row["object"]) for row in tasks.table(task.id, "changes", {})["rows"]], [("delete", "existing-ag")])
        return task

    def test_delete_needs_the_tick_box_the_code_the_sentence_and_the_nickname(self):
        for understood, code_ok, sentence, nickname, message in [
            (False, True, DELETE_ACKNOWLEDGMENT, "lab", "you did not confirm you understand what this deletes; nothing was deleted"),
            ("yes", True, DELETE_ACKNOWLEDGMENT, "lab", "you did not confirm you understand what this deletes; nothing was deleted"),
            (True, False, DELETE_ACKNOWLEDGMENT, "lab", "deletion confirmation code refused; nothing was written"),
            (True, True, DELETE_ACKNOWLEDGMENT.lower(), "lab", "final deletion acknowledgment refused; nothing was written"),
            (True, True, DELETE_ACKNOWLEDGMENT, "LAB", "Orchestrator nickname refused (typed 'LAB', this write goes to 'lab'); nothing was written"),
        ]:
            with self.subTest(message):
                tasks = self.manager()
                task = self.delete_awaiting_approval(tasks)
                code = task.result.approval["gates"][0]["expected"]
                tasks.approve(task.id, [code if code_ok else "DELETE-AAAAAAAA", sentence], nickname, understood)
                self.assertEqual((self.wait(task, "rejected").message, WritableGateway.groups), (message, [EXISTING]))

    def test_delete_with_every_gate_answered_deletes_exactly_the_table(self):
        tasks = self.manager()
        task = self.delete_awaiting_approval(tasks)
        code, sentence = [gate["expected"] for gate in task.result.approval["gates"]]
        self.assertEqual(sentence, DELETE_ACKNOWLEDGMENT)
        tasks.approve(task.id, [code, sentence], "lab", True)
        self.wait(task, "done", "failed")
        self.assertEqual((task.state, WritableGateway.groups), ("done", []))

    def test_the_tick_box_is_only_for_deletes(self):
        tasks = self.manager()
        plan = self.wait(tasks.create({"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": "Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nnew,10.0.0.0/24,,,\n"}), "planned")
        task = self.wait(tasks.create({"action": "apply", "orchestrator": "lab", "kind": "address-groups", "plan_task": plan.id}), "awaiting_approval")
        tasks.approve(task.id, ["APPLY"], "lab")
        self.assertEqual(self.wait(task, "done", "failed").state, "done")


if __name__ == "__main__":
    import unittest

    unittest.main()
