import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation.cli import main


class GuiCommandTests(unittest.TestCase):
    """setup.sh's edgeconnect-auto launcher always passes --dotenv <install folder>/.env."""

    def run_gui(self, *argv):
        stderr = io.StringIO()
        with patch("edgeconnect_automation.gui_server.serve", return_value=0) as serve, contextlib.redirect_stderr(stderr):
            code = main(list(argv) + ["gui", "--no-browser"])
        return code, serve.called, stderr.getvalue()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        (self.root / "install").mkdir()
        (self.root / "install" / ".env").write_text("orch_1=lab\n")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)

    def test_the_launcher_dotenv_is_accepted_from_its_own_folder(self):
        os.chdir(str(self.root / "install"))
        self.assertEqual(self.run_gui("--dotenv", str(self.root / "install" / ".env"))[:2], (0, True))

    def test_another_folder_is_told_where_to_start(self):
        os.chdir(str(self.root))
        code, started, stderr = self.run_gui("--dotenv", str(self.root / "install" / ".env"))
        self.assertEqual((code, started), (2, False))
        self.assertIn("start it from {}".format(self.root / "install"), stderr)

    def test_orchestrator_is_still_refused(self):
        os.chdir(str(self.root / "install"))
        code, started, stderr = self.run_gui("--orchestrator", "lab")
        self.assertEqual((code, started), (2, False))
        self.assertIn("lets you choose the Orchestrator", stderr)


if __name__ == "__main__":
    unittest.main()
