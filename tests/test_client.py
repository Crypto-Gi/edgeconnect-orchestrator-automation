import io
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from edgeconnect_automation.cli import _approve, build_parser
from edgeconnect_automation.client import ApiClient
from edgeconnect_automation.config import Config, load_config, parse_dotenv
from edgeconnect_automation.errors import ApprovalError, ConfigurationError, ResponseFormatError, ServerError
from edgeconnect_automation.util import redact


class Response:
    def __init__(self, body=b"{}", status=200, content_type="application/json"):
        self.body = body
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self.body


class Opener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def http_error(status, body=b""):
    headers = Message()
    headers["Content-Type"] = "application/json"
    return HTTPError("https://unit.invalid/x", status, "error", headers, io.BytesIO(body))


class ClientTests(unittest.TestCase):
    def config(self):
        return Config("https://unit.invalid", "super-secret", max_read_attempts=3)

    def test_get_retries_429_and_5xx(self):
        opener = Opener([http_error(429), http_error(503), Response(b'{"ok":true}')])
        delays = []
        result = ApiClient(self.config(), opener=opener, sleep=delays.append, jitter=lambda: 0).get("/x")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(len(opener.calls), 3)
        self.assertEqual(len(delays), 2)

    def test_write_is_never_retried(self):
        opener = Opener([http_error(503), Response(status=204, body=b"")])
        with self.assertRaises(ServerError):
            ApiClient(self.config(), opener=opener, sleep=lambda _: None).post_json("/x", {"a": 1}, expected_status=(204,))
        self.assertEqual(len(opener.calls), 1)

    def test_post_can_request_text_response_contract(self):
        opener = Opener([Response(status=204, body=b"", content_type="text/plain")])
        ApiClient(self.config(), opener=opener).post_json("/template", {"name": "group"}, expected_status=(204,), accept="text/plain")
        self.assertEqual(opener.calls[0].get_header("Accept"), "text/plain")

    def test_binary_upload_and_api_key_header(self):
        opener = Opener([Response(status=204, body=b"", content_type="application/octet-stream")])
        ApiClient(self.config(), opener=opener).post_binary("/upload", b"abc", expected_status=(204,))
        request = opener.calls[0]
        self.assertEqual(request.data, b"abc")
        self.assertEqual(request.get_header("Content-type"), "application/octet-stream")
        self.assertEqual(request.get_header("X-auth-token"), "super-secret")

    def test_multipart_csv_file_encoding_and_json_response(self):
        opener = Opener([Response(b'{"success":true}')])
        result = ApiClient(self.config(), opener=opener).post_multipart_file("/upload", "csvFile", "groups.csv", b'Name,Value\nexample,"a,b"\n')
        request = opener.calls[0]
        content_type = request.get_header("Content-type")
        self.assertTrue(content_type.startswith("multipart/form-data; boundary="))
        boundary = content_type.split("boundary=", 1)[1]
        self.assertIn(b'name="csvFile"; filename="groups.csv"', request.data)
        self.assertIn(b'example,"a,b"', request.data)
        self.assertTrue(request.data.endswith(("--" + boundary + "--\r\n").encode("ascii")))
        self.assertEqual(result, {"success": True})

    def test_strict_media_type_and_empty_json(self):
        with self.assertRaises(ResponseFormatError):
            ApiClient(self.config(), opener=Opener([Response(b"<html>", content_type="text/html")])).get("/x")
        with self.assertRaises(ResponseFormatError):
            ApiClient(self.config(), opener=Opener([Response(b"")])).get("/x")

    def test_redaction_recursive_and_text(self):
        value = redact({"api_key": "secret", "nested": {"Authorization": "bearer secret"}, "message": "password=hunter2"})
        self.assertEqual(value["api_key"], "<REDACTED>")
        self.assertEqual(value["nested"]["Authorization"], "<REDACTED>")
        self.assertNotIn("hunter2", value["message"])


class ConfigAndCliTests(unittest.TestCase):
    def test_config_aliases_and_https(self):
        config = load_config(environ={"EC_BASE_URL": "https://unit.invalid", "EC_API_KEY": "secret"})
        self.assertEqual(config.base_url, "https://unit.invalid/gms/rest")
        explicit = load_config(environ={"EC_BASE_URL": "https://unit.invalid/gms/rest", "EC_API_KEY": "secret"})
        self.assertEqual(explicit.base_url, "https://unit.invalid/gms/rest")
        with self.assertRaises(ConfigurationError):
            load_config(environ={"EC_BASE_URL": "https://unit.invalid/unexpected", "EC_API_KEY": "secret"})
        with self.assertRaises(ConfigurationError):
            load_config(environ={"EC_BASE_URL": "http://unit.invalid", "EC_API_KEY": "secret"})

    def test_current_directory_dotenv_default_override_and_environment_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("orchestrator_base_url=https://default.invalid\norchestrator_api_key=default-key\n", encoding="utf-8")
            override = root / "override.env"
            override.write_text("orchestrator_base_url=https://override.invalid\norchestrator_api_key=override-key\n", encoding="utf-8")
            previous = os.getcwd()
            try:
                os.chdir(root)
                default = load_config(environ={})
                self.assertEqual(default.base_url, "https://default.invalid/gms/rest")
                self.assertEqual(default.api_key, "default-key")
                explicit = load_config(str(override), environ={})
                self.assertEqual(explicit.base_url, "https://override.invalid/gms/rest")
                environment = load_config(environ={"EC_BASE_URL": "https://environment.invalid", "EC_API_KEY": "environment-key"})
                self.assertEqual(environment.base_url, "https://environment.invalid/gms/rest")
                self.assertEqual(environment.api_key, "environment-key")
            finally:
                os.chdir(previous)

    def test_default_dotenv_does_not_search_parent_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("orchestrator_base_url=https://parent.invalid\norchestrator_api_key=parent-key\n", encoding="utf-8")
            child = root / "child"
            child.mkdir()
            previous = os.getcwd()
            try:
                os.chdir(child)
                with self.assertRaisesRegex(ConfigurationError, "./.env"):
                    load_config(environ={})
            finally:
                os.chdir(previous)

    def test_help_does_not_load_config_or_network(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as result:
            parser.parse_args(["--help"])
        self.assertEqual(result.exception.code, 0)

    def test_standalone_appexpress_command_is_removed(self):
        commands = next(action.choices for action in build_parser()._actions if action.dest == "command")
        self.assertNotIn("appexpress", commands)
        self.assertIn("app-definitions", commands)

    def test_exact_apply_is_required(self):
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="apply"):
            with self.assertRaisesRegex(ApprovalError, "refused"):
                _approve({"candidate": {}}, False)
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="APPLY"):
            _approve({"candidate": {}}, False)

    def test_dry_run_and_non_tty_refuse_writes(self):
        self.assertFalse(_approve({"candidate": {}}, True))
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaisesRegex(ApprovalError, "non-interactive"):
                _approve({"candidate": {}}, False)


if __name__ == "__main__":
    unittest.main()
