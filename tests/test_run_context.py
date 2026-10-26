import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation.cli import main
from tests.test_golden import GOLDEN, GoldenGateway


class RunContextTests(unittest.TestCase):
    def test_two_runs_in_one_process_keep_their_own_orchestrator(self):
        """Both runs are connected before either stamps its plan, so shared state would stamp one plan with the other's Orchestrator."""
        both_connected = threading.Barrier(2, timeout=10)

        class Gateway(GoldenGateway):
            def get_address_groups(self):
                both_connected.wait()
                return super().get_address_groups()

        def config(dotenv, allow_http=False, orchestrator=None):
            return SimpleNamespace(name=orchestrator, base_url="https://{}.invalid/gms/rest".format(orchestrator))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy(GOLDEN / "inputs" / "address_groups_valid.csv", root / "groups.csv")
            codes = {}

            def run(name):
                codes[name] = main(["--report-dir", "", "--orchestrator", name, "address-groups", "plan", "--csv", str(root / "groups.csv"), "--output", str(root / (name + ".json"))])

            with open(os.devnull, "w") as sink, patch("edgeconnect_automation.cli.load_config", side_effect=config), patch("edgeconnect_automation.cli.ApiClient", return_value=SimpleNamespace(write_requests=0)), patch("edgeconnect_automation.cli.OrchestratorGateway", Gateway), patch("sys.stdout", sink), patch("sys.stderr", sink):
                threads = [threading.Thread(target=run, args=(name,)) for name in ("orch-a", "orch-b")]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            self.assertEqual(codes, {"orch-a": 0, "orch-b": 0})
            for name in ("orch-a", "orch-b"):
                plan = json.loads((root / (name + ".json")).read_text(encoding="utf-8"))
                self.assertEqual(plan["orchestrator"], {"name": name, "url": "https://{}.invalid".format(name)})


if __name__ == "__main__":
    unittest.main()
