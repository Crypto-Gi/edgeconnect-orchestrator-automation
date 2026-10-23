"""Every .env / environment key the code reads must be documented in .env.example."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "edgeconnect_automation"


def keys_read_by_code():
    config = (SRC / "config.py").read_text(encoding="utf-8")
    keys = set(re.findall(r'"((?:orchestrator|ORCHESTRATOR|EDGECONNECT|EC|REQUESTS|SSL|orch)_\w+)"', config))
    fields = re.search(r"for field in \(([^)]*)\)", config).group(1)
    keys.update("<nickname>_" + field for field in re.findall(r'"(\w+)"', fields))
    if "_SLOT = re.compile" in config:
        keys.add("orch_<N>")
    for path in SRC.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        keys.update(re.findall(r'(?:getenv|environ\.get)\(\s*["\'](\w+)', source))
        keys.update(re.findall(r'^\w+_ENV = "(\w+)"', source, re.MULTILINE))
    return keys


class EnvExampleTest(unittest.TestCase):
    def test_every_key_read_by_code_is_in_env_example(self):
        keys = keys_read_by_code()
        self.assertGreater(len(keys), 20)  # the scan itself still finds the loader's keys
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        missing = sorted(key for key in keys if not re.search(r"(?<!\w)" + re.escape(key) + r"(?!\w)", text))
        self.assertEqual(missing, [], "keys read by the code but not documented in .env.example")


if __name__ == "__main__":
    unittest.main()
