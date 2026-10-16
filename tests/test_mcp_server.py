import io
import json
import tempfile
import unittest
from pathlib import Path

from edgeconnect_automation.config import Config, load_config
from edgeconnect_automation.errors import ConfigurationError
from edgeconnect_automation.mcp_server import Orchestrator, Server, ToolError

SPEC = {
    "swagger": "2.0",
    "basePath": "/gms/rest",
    "paths": {
        "/appliance": {"get": {"summary": "List all appliances", "tags": ["appliance"]}},
        "/appliance/{nePk}": {
            "get": {"summary": "Get one appliance", "parameters": [{"name": "nePk", "in": "path"}]},
            "delete": {"summary": "Delete appliance"},
        },
        "/appliance/rest/{nePk}": {"post": {"summary": "Appliance REST passthrough"}},
        "/thirdPartyServices/zscaler/countries": {"post": {"summary": "Set countries", "requestBody": {"content": {"text/plain": {"schema": {"type": "string"}}}}}},
        "/thirdPartyServices/zscaler/legacy": {"post": {"summary": "Set legacy text", "consumes": ["text/plain"]}},
        "/ipObjects/addressGroup": {"post": {"summary": "Create address group", "parameters": [{"in": "body", "name": "body", "schema": {"$ref": "#/definitions/Group"}}]}},
    },
    "definitions": {
        "Group": {"type": "object", "properties": {"name": {"type": "string"}, "rules": {"type": "array", "items": {"$ref": "#/definitions/Rule"}}}},
        "Rule": {"type": "object", "properties": {"includedIPs": {"type": "array"}, "parent": {"$ref": "#/definitions/Rule"}}},
    },
}


class FakeClient:
    def __init__(self, body=b'{"ok": true, "apiKey": "s3cret"}'):
        self.body = body
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs.get("query"), kwargs.get("json_body")))
        return self.body

    def _url(self, path, query):
        return "https://orch.example/gms/rest" + path


class McpServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        spec = Path(self.tmp.name) / "spec.json"
        spec.write_text(json.dumps(SPEC))
        config = Config(base_url="https://orch.example/gms/rest", api_key="KEY")
        self.lab_client, self.prod_client = FakeClient(), FakeClient()
        self.server = Server({
            "lab": Orchestrator("lab", config, True, str(spec), self.lab_client),
            "prod": Orchestrator("prod", config, False, str(spec), self.prod_client),
        }, default="prod", log=lambda line: None)

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, name, **arguments):
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        result = response["result"]
        return result["isError"], result["content"][0]["text"]

    def test_initialize_and_list_tools(self):
        init = self.server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        names = [tool["name"] for tool in self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]]
        self.assertEqual(names, ["list_orchestrators", "find_operations", "describe_operation", "api_get", "api_write"])

    def test_redaction_hides_psks_but_keeps_flags_and_numbers(self):
        self.prod_client.body = json.dumps({"presharedkey": "abc12", "authKey": "k", "passwordMinLen": 8, "csrfProtection": True, "md5Password": ""}).encode()
        _, text = self.call("api_get", path="/appliance")
        value = json.loads(text)["result"]
        self.assertEqual(value, {"presharedkey": "<REDACTED>", "authKey": "<REDACTED>", "passwordMinLen": 8, "csrfProtection": True, "md5Password": ""})

    def test_list_orchestrators_never_shows_keys(self):
        error, text = self.call("list_orchestrators")
        self.assertFalse(error)
        self.assertNotIn("KEY", text)
        self.assertEqual({o["name"]: o["writes_enabled"] for o in json.loads(text)}, {"lab": True, "prod": False})

    def test_find_and_describe(self):
        _, text = self.call("find_operations", query="appliance")
        self.assertEqual(json.loads(text)["total_matches"], 4)
        _, text = self.call("describe_operation", method="POST", path="/ipObjects/addressGroup")
        self.assertIn('"name"', text)  # $ref resolved
        self.assertIn('"includedIPs"', text)  # nested $ref resolved
        self.assertIn('"#/definitions/Rule"', text)  # recursion stops at the cycle

    def test_get_is_redacted_and_matched_against_spec(self):
        error, text = self.call("api_get", path="/appliance/2.NE", query={"x": 1})
        self.assertFalse(error)
        self.assertNotIn("s3cret", text)
        self.assertEqual(self.prod_client.calls, [("GET", "/appliance/2.NE", {"x": 1}, None)])
        for bad in ("/appliance/../users", "/nope", "//evil.example/x", "/appliance/%2e%2e", "http://evil"):
            error, _ = self.call("api_get", path=bad)
            self.assertTrue(error, bad)

    def test_writes_are_gated_per_orchestrator(self):
        error, text = self.call("api_write", method="DELETE", path="/appliance/2.NE")
        self.assertTrue(error)
        self.assertIn("prod_mcp_writes", text)
        self.assertEqual(self.prod_client.calls, [])
        error, _ = self.call("api_write", orchestrator="lab", method="POST", path="/ipObjects/addressGroup", body={"name": "g"})
        self.assertFalse(error)
        self.assertEqual(self.lab_client.calls, [("POST", "/ipObjects/addressGroup", None, {"name": "g"})])
        error, text = self.call("api_write", orchestrator="lab", method="POST", path="/ipObjects/addressGroup", body={"name": "g", "password": "<REDACTED>"})
        self.assertTrue(error)
        self.assertIn("placeholders", text)
        error, text = self.call("api_write", orchestrator="lab", method="POST", path="/appliance/rest/2.NE", query={"url": "reboot"})
        self.assertTrue(error)
        self.assertIn("lab_mcp_passthrough", text)
        self.assertEqual(len(self.lab_client.calls), 1)
        self.server.orchestrators["lab"].passthrough = True
        error, _ = self.call("api_write", orchestrator="lab", method="POST", path="/appliance/rest/2.NE", query={"url": "x"})
        self.assertFalse(error)
        error, _ = self.call("api_write", orchestrator="lab", method="PUT", path="/appliance/2.NE")
        self.assertTrue(error)  # undocumented method
        error, _ = self.call("api_write", orchestrator="lab", method="GET", path="/appliance")
        self.assertTrue(error)

    def test_text_plain_bodies_are_sent_raw(self):
        class Raw(FakeClient):
            def request(self, method, path, **kwargs):
                self.calls.append((method, path, kwargs.get("binary_body"), kwargs.get("content_type"), kwargs.get("json_body")))
                return b""

        raw = Raw()
        self.server.orchestrators["lab"].client = raw
        text = "line1\nline2"
        for path in ("/thirdPartyServices/zscaler/countries", "/thirdPartyServices/zscaler/legacy"):
            error, _ = self.call("api_write", orchestrator="lab", method="POST", path=path, body=text)
            self.assertFalse(error)
        self.assertEqual(raw.calls, [("POST", p, b"line1\nline2", "text/plain", None) for p in ("/thirdPartyServices/zscaler/countries", "/thirdPartyServices/zscaler/legacy")])
        # JSON operations still get a JSON-encoded string
        raw.calls.clear()
        self.call("api_write", orchestrator="lab", method="POST", path="/ipObjects/addressGroup", body="x")
        self.assertEqual(raw.calls, [("POST", "/ipObjects/addressGroup", None, None, "x")])

    def test_truncation_and_stdio(self):
        self.prod_client.body = json.dumps(["x" * 100] * 100).encode()
        _, text = self.call("api_get", path="/appliance", max_chars=1000)
        self.assertIn("truncated", text)
        out = io.StringIO()
        self.server.serve(io.StringIO('{"jsonrpc":"2.0","id":7,"method":"ping"}\nnot json\n'), out)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(lines[0], {"jsonrpc": "2.0", "id": 7, "result": {}})
        self.assertEqual(lines[1]["error"]["code"], -32700)

    def test_openapi3_spec_is_downloaded_from_the_orchestrator(self):
        spec = {"openapi": "3.0.0", "servers": [{"url": "https://orch.example:/gms/rest"}], "paths": {"/gmsserver/info": {"get": {"summary": "Info"}}}}
        client = FakeClient(json.dumps(spec).encode())
        orchestrator = Orchestrator("o", Config(base_url="https://orch.example/gms/rest", api_key="K"), False, None, client)
        self.assertEqual(orchestrator.match("GET", "/gmsserver/info")["summary"], "Info")
        self.assertEqual(client.calls[0][:2], ("GET", "/apiDocs"))

    def test_tls_pin_is_normalized_and_validated(self):
        env = {"orch_1": "lab", "lab_base_url": "https://192.0.2.1", "lab_api_key": "K", "lab_tls_sha256": "AB:" * 31 + "AB"}
        self.assertEqual(load_config(environ=env, orchestrator="lab").tls_sha256, "ab" * 32)
        with self.assertRaises(ConfigurationError):
            load_config(environ=dict(env, lab_tls_sha256="abc"), orchestrator="lab")

    def test_errors_are_short_and_explain_tls_failures(self):
        from urllib.error import URLError
        from edgeconnect_automation.errors import ResourceNotFoundError, TransportError

        def html_404(*args, **kwargs):
            raise ResourceNotFoundError("HTTP 404: <html><body>" + "<p>Not found</p>" * 300 + "</body></html>", 404, "GET", "/appliance")

        self.prod_client.request = html_404
        _, text = self.call("api_get", path="/appliance")
        self.assertNotIn("<", text)
        self.prod_client.request = lambda *a, **k: (_ for _ in ()).throw(ResourceNotFoundError('HTTP 404: <html><script>"use strict"; const protocol = "https://";', 404, "GET", "/x"))
        _, text = self.call("api_get", path="/appliance")
        self.assertNotIn("use strict", text)
        self.assertLess(len(text), 520)

        def bad_cert(*args, **kwargs):
            raise TransportError("transport failure: URLError") from URLError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")

        self.lab_client.request = bad_cert
        _, text = self.call("api_get", orchestrator="lab", path="/appliance")
        self.assertIn("CERTIFICATE_VERIFY_FAILED", text)
        self.assertIn("lab_tls_sha256", text)


if __name__ == "__main__":
    unittest.main()
