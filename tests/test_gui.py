import contextlib
import functools
import http.client
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation import fleet, gui_server
from edgeconnect_automation.gui_tasks import TaskError, TaskManager
from tests.test_engine import NEW_GROUP, WritableGateway
from tests.test_fleet import Client as FleetClient
from tests.test_golden import GOLDEN

KEY = "SECRET-KEY-must-never-leave-the-server-7f3a"
GROUP_CSV = "Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment\nnew,10.0.0.0/24,,,\n"


def environment(**extra):
    return dict({"orch_1": "lab", "lab_base_url": "https://orchestrator.invalid", "lab_api_key": KEY, "lab_gui_writes": "on"}, **extra)


class Offline(unittest.TestCase):
    """Engine runs against the fake Orchestrator from the golden tests, in a scratch folder."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for path in (GOLDEN / "inputs").iterdir():
            shutil.copy(path, self.root / path.name)
        cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, cwd)
        WritableGateway.groups = []
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("edgeconnect_automation.cli.load_config", return_value=SimpleNamespace(name="lab", base_url="https://orchestrator.invalid/gms/rest")))
        stack.enter_context(patch("edgeconnect_automation.cli.ApiClient", return_value=SimpleNamespace(write_requests=0)))
        stack.enter_context(patch("edgeconnect_automation.cli.OrchestratorGateway", WritableGateway))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def manager(self, environ=None, report_dir="", **options):
        return TaskManager(folder=tempfile.mkdtemp(dir=str(self.root)), report_dir=report_dir, environ=environ or environment(), **options)

    def wait(self, task, *states):
        deadline = time.monotonic() + 10
        while task.state not in states:
            self.assertLess(time.monotonic(), deadline, "task stayed {} ({})".format(task.state, task.message))
            time.sleep(0.01)
        return task


class TaskTests(Offline):
    def planned(self, tasks):
        return self.wait(tasks.create({"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": GROUP_CSV}), "planned", "failed")

    def apply(self, tasks, plan):
        return tasks.create({"action": "apply", "orchestrator": "lab", "kind": "address-groups", "plan_task": plan.id})

    def test_plan_then_apply_waits_for_the_typed_approval_then_writes(self):
        tasks = self.manager()
        plan = self.planned(tasks)
        self.assertEqual((plan.state, tasks.table(plan.id, "changes", {})["rows"][0]["object"]), ("planned", "new"))
        task = self.wait(self.apply(tasks, plan), "awaiting_approval")
        self.assertEqual([gate["expected"] for gate in task.view()["result"]["approval"]["gates"]], ["APPLY"])
        self.assertEqual(WritableGateway.groups, [])
        self.assertIsNotNone(task.view()["deadline"])
        tasks.approve(task.id, ["APPLY"], "lab")
        self.wait(task, "done")
        self.assertIsNone(task.view()["deadline"])
        self.assertEqual(WritableGateway.groups, [NEW_GROUP])
        self.assertEqual([event["state"] for event in task.events], ["queued", "running", "awaiting_approval", "applying", "done"])

    def test_wrong_answer_is_rejected_and_writes_nothing(self):
        tasks = self.manager()
        task = self.wait(self.apply(tasks, self.planned(tasks)), "awaiting_approval")
        tasks.approve(task.id, ["apply"], "lab")
        self.assertEqual((self.wait(task, "rejected").message, WritableGateway.groups), ("write approval refused; nothing was written", []))
        with self.assertRaisesRegex(TaskError, "not awaiting approval"):
            tasks.approve(task.id, ["APPLY"], "lab")

    def test_unanswered_approval_expires(self):
        tasks = self.manager(approval_seconds=0.2)
        task = self.wait(self.apply(tasks, self.planned(tasks)), "awaiting_approval")
        self.assertEqual((self.wait(task, "expired").state, WritableGateway.groups), ("expired", []))

    def test_one_change_per_orchestrator_and_cancel_before_apply(self):
        tasks = self.manager()
        plan = self.planned(tasks)
        first = self.wait(self.apply(tasks, plan), "awaiting_approval")
        second = self.apply(tasks, plan)
        time.sleep(0.5)
        self.assertEqual(second.state, "queued")
        tasks.cancel(first.id)
        self.wait(first, "cancelled")
        self.wait(second, "awaiting_approval")
        tasks.cancel(second.id)
        self.assertEqual((self.wait(second, "cancelled").state, WritableGateway.groups), ("cancelled", []))

    def test_reads_run_while_a_change_waits(self):
        tasks = self.manager()
        self.wait(self.apply(tasks, self.planned(tasks)), "awaiting_approval")
        self.assertEqual(self.planned(tasks).state, "planned")

    def test_writes_need_the_orchestrator_switch_and_requests_are_checked(self):
        tasks = self.manager(environment(lab_gui_writes="off"))
        plan = self.planned(tasks)
        with self.assertRaisesRegex(TaskError, "GUI writes are off for lab; set lab_gui_writes=on"):
            self.apply(tasks, plan)
        for request, message in [
            ({"action": "rm"}, "unknown action"),
            ({"action": "plan", "orchestrator": "other", "kind": "zones"}, "unknown Orchestrator 'other'"),
            ({"action": "plan", "orchestrator": "lab", "kind": "../x"}, "unknown kind"),
            ({"action": "plan", "orchestrator": "lab", "kind": "zones", "names": "Z"}, "names must list"),
            ({"action": "plan", "orchestrator": "lab", "kind": "address-groups"}, "csv_text is required"),
            ({"action": "apply", "orchestrator": "lab", "kind": "zones", "plan_task": plan.id}, "GUI writes are off"),
        ]:
            with self.assertRaisesRegex(TaskError, message):
                tasks.create(request)
        tasks = self.manager()
        with self.assertRaisesRegex(TaskError, "finished zones plan on the same Orchestrator"):
            tasks.create({"action": "apply", "orchestrator": "lab", "kind": "zones", "plan_task": self.planned(tasks).id})


class ServerCase(Offline):
    """A GUI server on the fake Orchestrator, and a request helper that records every response body."""

    def setUp(self):
        super().setUp()
        check = functools.partial(fleet.check_all, client_factory=FleetClient)
        FleetClient.answers = {"lab": {}}
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("edgeconnect_automation.gui_server.check_all", check))
        self.server = gui_server.GuiServer(0, self.manager(report_dir=str(self.root / "reports")), environ=environment())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.host = "127.0.0.1:{}".format(self.port)
        self.cookie = "edgeconnect_gui_{}={}".format(self.port, self.server.session)
        self.bodies = []

    def request(self, method, path, body=None, host=None, cookie=True, origin=True, content_type="application/json"):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or self.host}
        if cookie:
            headers["Cookie"] = self.cookie if cookie is True else cookie
        if origin and method == "POST":
            headers["Origin"] = origin if isinstance(origin, str) else "http://" + (host or self.host)
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = content_type
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        text = response.read().decode()
        connection.close()
        self.bodies.append(text)
        self.assertFalse([name for name in response.headers if name.lower().startswith("access-control-")], "no CORS headers, ever")
        return response, text


class ServerTests(ServerCase):
    def test_launch_link_works_once_and_sets_a_strict_http_only_cookie_that_is_not_the_token(self):
        self.assertEqual(self.request("GET", "/?token=wrong", cookie=False)[0].status, 401)
        response, _ = self.request("GET", "/?token=" + self.server.token, cookie=False)
        self.assertEqual((response.status, response.headers["Location"]), (303, "/"))
        name, _, rest = response.headers["Set-Cookie"].partition("=")
        session, _, flags = rest.partition(";")
        self.assertEqual((name, flags.strip()), ("edgeconnect_gui_{}".format(self.port), "HttpOnly; SameSite=Strict; Path=/"))
        self.assertNotEqual(session, self.server.token)
        response, text = self.request("GET", "/", cookie="{}={}".format(name, session))
        self.assertEqual((response.status, response.headers["Content-Security-Policy"].split(";")[0]), (200, "default-src 'self'"))
        self.assertIn("<title>EdgeConnect Automation</title>", text)
        # Another account may have read the link from the browser's command line: it must not get in after the person did.
        response, text = self.request("GET", "/?token=" + self.server.token, cookie=False)
        self.assertEqual(response.status, 401)
        self.assertIn("already used", text)
        self.assertEqual(self.request("GET", "/api/tasks", cookie="{}={}".format(name, self.server.token))[0].status, 401)

    def test_missing_or_wrong_cookie_is_refused_everywhere(self):
        for path in ("/", "/app.js", "/api/tasks", "/api/orchestrators", "/api/tasks/task-1/events", "/api/tasks/task-1/inventory", "/api/runs", "/api/runs.csv", "/api/runs/run-1", "/api/runs/run-1/rows.csv", "/api/runs/run-1/revert"):
            for cookie in (False, "edgeconnect_gui_{}=guess".format(self.port), "edgeconnect_gui_1=" + self.server.session):
                self.assertEqual(self.request("GET", path, cookie=cookie)[0].status, 401, path)
        self.assertEqual(self.request("POST", "/api/tasks", {"action": "discover"}, cookie=False)[0].status, 401)

    def test_dns_rebinding_host_is_refused_even_with_the_cookie(self):
        for host in ("evil.example:{}".format(self.port), "127.0.0.1", "localhost:1", "127.0.0.1.evil.example:{}".format(self.port)):
            self.assertEqual(self.request("GET", "/api/tasks", host=host)[0].status, 421, host)
        for host in ("localhost:{}".format(self.port), "[::1]:{}".format(self.port)):
            self.assertEqual(self.request("GET", "/api/tasks", host=host)[0].status, 200, host)

    def test_cross_origin_or_non_json_posts_are_refused(self):
        body = {"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": GROUP_CSV}
        self.assertEqual(self.request("POST", "/api/tasks", body, origin="http://evil.example")[0].status, 403)
        self.assertEqual(self.request("POST", "/api/tasks", body, origin=False)[0].status, 403)
        self.assertEqual(self.request("POST", "/api/tasks", body, content_type="text/plain")[0].status, 415)
        self.assertEqual(self.server.tasks.list(), [])
        self.assertEqual(self.request("POST", "/api/tasks", body)[0].status, 201)

    def test_full_change_over_http_with_progress_stream_and_no_key_in_any_response(self):
        response, text = self.request("GET", "/api/orchestrators")
        self.assertEqual([(item["name"], item["status"], item["writes"]) for item in json.loads(text)["orchestrators"]], [("lab", "green", True)])
        _, text = self.request("POST", "/api/tasks", {"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": GROUP_CSV})
        plan = self.wait(self.server.tasks.get(json.loads(text)["id"]), "planned")
        _, text = self.request("POST", "/api/tasks", {"action": "apply", "orchestrator": "lab", "kind": "address-groups", "plan_task": plan.id})
        task_id = json.loads(text)["id"]
        self.wait(self.server.tasks.get(task_id), "awaiting_approval")
        self.assertEqual(self.request("POST", "/api/tasks/{}/approve".format(task_id), {"answers": ["APPLY"], "orchestrator": "lab"})[0].status, 202)
        response, stream = self.request("GET", "/api/tasks/{}/events".format(task_id))
        self.assertEqual(response.headers["Content-Type"], "text/event-stream")
        states = [json.loads(line[6:])["state"] for line in stream.splitlines() if line.startswith("data: ")]
        self.assertEqual(states, ["queued", "running", "awaiting_approval", "applying", "done"])
        self.assertEqual(WritableGateway.groups, [NEW_GROUP])
        self.request("GET", "/api/tasks")
        self.request("GET", "/api/tasks/" + task_id)
        self.assertEqual(self.request("POST", "/api/tasks/{}/cancel".format(task_id), {})[0].status, 409)
        runs = json.loads(self.request("GET", "/api/runs")[1])["rows"]
        for run in runs:
            self.request("GET", "/api/runs/" + run["run_id"])
            self.request("GET", "/api/runs/{}/rows.csv".format(run["run_id"]))
        self.request("GET", "/api/runs.csv")
        self.assertEqual([body for body in self.bodies if KEY in body], [])

    def test_run_log_and_inventory_tables(self):
        discovery = {"version": {"release": "9.7.1"}, "segments": {"0": {"name": "Default"}}, "zones": {"10": {"name": "OUTSIDE"}, "2": {"name": "INSIDE"}}, "segment_zones": [], "address_groups": [], "service_groups": []}
        with patch.object(WritableGateway, "discover", return_value=discovery, create=True):
            _, text = self.request("POST", "/api/tasks", {"action": "discover", "orchestrator": "lab"})
            task = self.wait(self.server.tasks.get(json.loads(text)["id"]), "done", "failed")
        response, text = self.request("GET", "/api/tasks/{}/inventory?tab=zones&sort=id&order=desc".format(task.id))
        self.assertEqual((response.status, json.loads(text)["table"]["rows"]), (200, [{"id": "10", "name": "OUTSIDE"}, {"id": "2", "name": "INSIDE"}]))
        _, text = self.request("POST", "/api/tasks", {"action": "plan", "orchestrator": "lab", "kind": "address-groups", "csv_text": "Name\n"})
        plan = self.wait(self.server.tasks.get(json.loads(text)["id"]), "planned", "failed")
        self.assertEqual(self.request("GET", "/api/tasks/{}/inventory".format(plan.id))[0].status, 409)

        runs = json.loads(self.request("GET", "/api/runs")[1])
        self.assertEqual((runs["folder"], runs["unreadable"], [(run["workflow"], run["source"], run["tone"]) for run in runs["rows"]]), (str(self.root / "reports"), 0, [("address-groups plan", "gui", "bad"), ("discovery", "gui", "ok")]))
        problems = json.loads(self.request("GET", "/api/runs?problems=1&workflow=discovery")[1])
        self.assertEqual((problems["matching"], problems["facets"]["workflow"]), (0, ["address-groups plan", "discovery"]))
        run_id = runs["rows"][0]["run_id"]
        detail = json.loads(self.request("GET", "/api/runs/" + run_id)[1])
        self.assertEqual((detail["run"]["run_id"], detail["run"]["status"]), (run_id, runs["rows"][0]["status"]))
        response, text = self.request("GET", "/api/runs/{}/rows.csv".format(run_id))
        self.assertEqual((response.headers["Content-Disposition"], text.splitlines()[0]), ('attachment; filename="{}-rows.csv"'.format(run_id), "row,item,scope,outcome,reason"))
        response, text = self.request("GET", "/api/runs.csv?source=gui")
        self.assertEqual((response.headers["Content-Type"], len(text.splitlines())), ("text/csv; charset=utf-8", 3))
        for path in ("/api/runs/run-nope", "/api/runs/{}/other".format(run_id), "/api/runsx/{}".format(run_id), "/api/runs/"):
            self.assertEqual(self.request("GET", path)[0].status, 404, path)


class IconTests(ServerCase):
    def test_the_page_names_an_icon_the_server_has_so_browsers_do_not_ask_for_a_missing_favicon(self):
        page = self.request("GET", "/")[1]
        self.assertIn('<link rel="icon" href="favicon.svg"', page)
        response, body = self.request("GET", "/favicon.svg")
        self.assertEqual((response.status, response.headers["Content-Type"]), (200, "image/svg+xml"))
        self.assertTrue(body.startswith("<svg"))


if __name__ == "__main__":
    unittest.main()
