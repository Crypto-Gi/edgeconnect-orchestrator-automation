import io
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import BaseHandler
from urllib.response import addinfourl

from edgeconnect_automation.cli import _approve, build_parser
from edgeconnect_automation.client import ApiClient
from edgeconnect_automation.config import Config, load_config, parse_dotenv
from edgeconnect_automation.errors import ApprovalError, ConfigurationError, ResponseFormatError, ServerError, TransportError
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


class IsolatedCwdTestCase(unittest.TestCase):
    """Run each test in an empty directory so load_config never picks up a real ./.env."""

    def setUp(self):
        workdir = tempfile.TemporaryDirectory()
        previous = os.getcwd()
        os.chdir(workdir.name)
        self.addCleanup(workdir.cleanup)
        self.addCleanup(os.chdir, previous)


class ClientTests(IsolatedCwdTestCase):
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

    def test_redirect_is_refused_and_api_key_never_follows_it(self):
        seen = []

        class Transport(BaseHandler):
            handler_order = 100

            def https_open(self, request):
                seen.append((request.full_url, request.get_header("X-auth-token")))
                headers = Message()
                headers["Location"] = "http://elsewhere.invalid/gms/rest/x"
                response = addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
                response.msg = "Found"
                return response

            def http_open(self, request):
                seen.append((request.full_url, request.get_header("X-auth-token")))
                response = addinfourl(io.BytesIO(b"{}"), Message(), request.full_url, 200)
                response.msg = "OK"
                return response

        for method in ("GET", "POST"):
            seen.clear()
            client = ApiClient(self.config(), sleep=lambda _: None)
            client._opener.add_handler(Transport())
            with self.assertRaisesRegex(TransportError, "redirect refused"):
                client.request(method, "/x", json_body={} if method == "POST" else None, expect_json=method == "GET")
            self.assertEqual(seen, [("https://unit.invalid/x", "super-secret")])

    def test_write_requests_are_counted_reads_are_not(self):
        opener = Opener([Response(), Response(b"", 204), Response(b"[]"), Response(b"", 204)])
        client = ApiClient(self.config(), opener=opener)
        client.get("/zones")
        client.post_json("/zones", {})
        client.request("POST", "/applicationDefinition/applications/wildcard", json_body={}, read_only=True)
        client.request("DELETE", "/ipObjects/addressGroup", query={"name": "x"}, expected_status=(204,), expect_json=False)
        self.assertEqual(client.write_requests, 2)

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
        value = redact({"presharedkey": "abc12", "authKey": "k", "passwordMinLen": 8, "csrfProtection": True, "md5Password": ""})
        self.assertEqual(value, {"presharedkey": "<REDACTED>", "authKey": "<REDACTED>", "passwordMinLen": 8, "csrfProtection": True, "md5Password": ""})

    def test_redirects_are_refused_not_followed(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from threading import Thread
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("X-Auth-Token")))
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()

            def log_message(self, *args):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            config = load_config(environ={"orchestrator_base_url": "http://127.0.0.1:{}".format(httpd.server_port), "orchestrator_api_key": "K"}, allow_http=True)
            with self.assertRaisesRegex(TransportError, "redirect refused"):
                ApiClient(config).get("/x")
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(seen, [("/gms/rest/x", "K")])  # the redirect target never got the key

    def test_http_is_only_allowed_for_loopback(self):
        for url in ("http://127.0.0.1:8080", "http://localhost", "http://[::1]"):
            load_config(environ={"orchestrator_base_url": url, "orchestrator_api_key": "K"}, allow_http=True)
        for url in ("http://192.0.2.1", "http://127.evil.example"):
            with self.assertRaises(ConfigurationError):
                load_config(environ={"orchestrator_base_url": url, "orchestrator_api_key": "K"}, allow_http=True)

    def test_tls_pin_is_normalized_and_validated(self):
        env = {"orch_1": "lab", "lab_base_url": "https://192.0.2.1", "lab_api_key": "K", "lab_tls_sha256": "AB:" * 31 + "AB"}
        self.assertEqual(load_config(environ=env, orchestrator="lab").tls_sha256, "ab" * 32)
        with self.assertRaises(ConfigurationError):
            load_config(environ=dict(env, lab_tls_sha256="abc"), orchestrator="lab")


class ConfigAndCliTests(IsolatedCwdTestCase):
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

    def test_named_orchestrator_profiles_selection_order(self):
        with tempfile.TemporaryDirectory() as directory:
            dotenv = Path(directory) / "multi.env"
            base = (
                "orch_1=prod\norch_2=Test\nORCH_3=half\n"
                "prod_base_url=https://prod.invalid\nprod_api_key=prod-key\n"
                "TEST_BASE_URL=https://test.invalid\ntest_api_key=test-key\n"
                "half_base_url=https://half.invalid\n"
            )
            dotenv.write_text(base, encoding="utf-8")
            path = str(dotenv)
            refuse = lambda _: self.fail("must not prompt")
            self.assertEqual(load_config(path, environ={}, orchestrator="TEST", prompt=refuse).api_key, "test-key")
            self.assertEqual(load_config(path, environ={}, orchestrator="orch_1", prompt=refuse).name, "prod")
            with self.assertRaisesRegex(ConfigurationError, "prod, test, half"):
                load_config(path, environ={}, interactive=False)
            chosen = load_config(path, environ={}, interactive=True, prompt=lambda _: "2")
            self.assertEqual((chosen.name, chosen.base_url), ("test", "https://test.invalid/gms/rest"))
            self.assertEqual(load_config(path, environ={}, interactive=True, prompt=lambda _: "prod").name, "prod")
            with self.assertRaisesRegex(ConfigurationError, "unknown Orchestrator choice"):
                load_config(path, environ={}, interactive=True, prompt=lambda _: "9")
            with self.assertRaisesRegex(ConfigurationError, "half_api_key"):
                load_config(path, environ={}, orchestrator="half")
            with self.assertRaisesRegex(ConfigurationError, "unknown Orchestrator 'nope'"):
                load_config(path, environ={}, orchestrator="nope")
            for default in ("prod", "orch_1"):
                dotenv.write_text(base + "orch_default={}\n".format(default), encoding="utf-8")
                self.assertEqual(load_config(path, environ={}, prompt=refuse).name, "prod")
                self.assertEqual(load_config(path, environ={}, orchestrator="test", prompt=refuse).name, "test")
            self.assertEqual(load_config(path, environ={"ORCH_DEFAULT": "test", "TEST_API_KEY": "env-key"}, prompt=refuse).api_key, "env-key")
            for bad in ("orch_4=prod\n", "orch_4=default\n", "orch_4=bad-name\n"):
                dotenv.write_text(base + bad, encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_config(path, environ={}, orchestrator="prod")
        self.assertEqual(load_config(environ={"orch_1": "only", "only_base_url": "https://only.invalid", "only_api_key": "k"}, prompt=refuse).name, "only")
        legacy_and_named = {"orchestrator_base_url": "https://old.invalid", "orchestrator_api_key": "old", "orch_1": "prod", "prod_base_url": "https://prod.invalid", "prod_api_key": "g"}
        with self.assertRaisesRegex(ConfigurationError, "prod, orchestrator"):
            load_config(environ=legacy_and_named, interactive=False)
        self.assertEqual(load_config(environ=legacy_and_named, orchestrator="orchestrator").api_key, "old")
        self.assertEqual(load_config(environ=legacy_and_named, interactive=True, prompt=lambda _: "1").name, "prod")
        with self.assertRaisesRegex(ConfigurationError, "orch_x=testlab: Orchestrator slots must be numbered, for example orch_2=testlab with testlab_base_url"):
            load_config(environ=dict(legacy_and_named, orch_x="testlab"))
        with self.assertRaisesRegex(ConfigurationError, "no named Orchestrators"):
            load_config(environ={"EC_BASE_URL": "https://unit.invalid", "EC_API_KEY": "secret"}, orchestrator="lab")

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
