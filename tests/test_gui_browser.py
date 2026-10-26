"""Browser smoke test: the GUI in Chromium against the fake Orchestrator, from a CSV with problems to an undone upload.

Needs Playwright for Python and its Chromium (`pip install playwright` then `python -m playwright install chromium`), so it
is skipped without them. CI sets EDGECONNECT_BROWSER_TESTS=1, which turns a missing Playwright into a failure.
"""
import importlib.util
import os
import unittest

from tests.test_gui import ServerCase
from tests.test_gui_firewall import FirewallCase, FirewallGateway

REQUIRED = os.environ.get("EDGECONNECT_BROWSER_TESTS") == "1"

# Every visible control must have a name a screen reader can say.
UNNAMED = """() => [...document.querySelectorAll("button, input, select, textarea, a[href]")]
  .filter((node) => node.offsetParent !== null && node.type !== "file")
  .filter((node) => !(node.labels && node.labels.length) && !node.getAttribute("aria-label") && !node.getAttribute("aria-labelledby") && !(/^(BUTTON|A)$/.test(node.tagName) && node.textContent.trim()))
  .map((node) => node.outerHTML.slice(0, 80))"""


@unittest.skipUnless(REQUIRED or importlib.util.find_spec("playwright"), "Playwright for Python is not installed") # guard-ok: Playwright is not a dependency; the browser CI job sets EDGECONNECT_BROWSER_TESTS=1 so it never skips there
class BrowserSmokeTests(ServerCase, FirewallCase):
    def setUp(self):
        super().setUp()
        from playwright.sync_api import sync_playwright

        playwright = sync_playwright().start()
        self.addCleanup(playwright.stop)
        browser = playwright.chromium.launch()
        self.addCleanup(browser.close)
        self.page = browser.new_page(viewport={"width": 1280, "height": 900})
        self.errors = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.on("console", lambda message: message.type == "error" and self.errors.append(message.text))
        self.page.set_default_timeout(15000)

    def assert_page_is_sound(self):
        self.assertEqual(self.page.evaluate(UNNAMED), [])
        self.assertEqual(self.errors, [])

    def open_firewall_with(self, name):
        self.page.click('a.intent[href="#/do/firewall"]')
        self.page.set_input_files("#flow-file", str(self.root / name))

    def test_a_csv_upload_from_problems_to_undo(self):
        page = self.page
        before = FirewallGateway(None).get_policy("0_0")
        page.goto(self.server.url)
        page.wait_for_selector("#fleet .orch")
        self.assertIn("lab", page.text_content("#orch-status") + page.text_content("#fleet"))
        self.assert_page_is_sound()

        self.open_firewall_with("firewall_rules_mixed.csv")
        page.wait_for_selector("#flow-issues tbody tr")
        self.assertIn("to fix in the CSV", page.text_content("#flow-fix-text"))
        self.assert_page_is_sound()

        page.click("#flow-reload")
        page.set_input_files("#flow-file", str(self.root / "firewall_rules_small.csv"))
        page.click("#flow-plan:visible")
        page.click("#flow-approve:visible")
        page.fill("#gate-0", "APPLY")
        page.fill("#approve-orch", "lab")
        self.assert_page_is_sound()
        page.click("#approve-submit")
        page.wait_for_selector("#flow-done:not([hidden])")
        self.assertNotEqual(FirewallGateway.policies["0_0"], before)

        page.click("#flow-run-link")
        page.wait_for_selector("#run-revert-start:visible")
        self.assert_page_is_sound()
        page.click("#run-revert-start")
        page.wait_for_selector("#flow-understood:visible")
        page.check("#flow-understood")
        page.click("#flow-delete")
        page.wait_for_selector("#approve-orch:visible")
        waiting = [task for task in self.server.tasks.list() if task.state == "awaiting_approval"]
        for index, gate in enumerate(waiting[0].result.approval["gates"]):
            page.fill("#gate-{}".format(index), gate["expected"])
        page.fill("#approve-orch", "lab")
        page.click("#approve-submit")
        page.wait_for_selector("#flow-done:not([hidden])")
        self.assertEqual(FirewallGateway.policies["0_0"], before)

        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(self.server.url.split("?")[0] + "#/runs")
        page.wait_for_selector("#runs-table tbody tr")
        self.assertFalse(page.evaluate("document.documentElement.scrollWidth > window.innerWidth"))
        self.assert_page_is_sound()


if __name__ == "__main__":
    unittest.main()
