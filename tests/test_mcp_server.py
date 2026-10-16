import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from edgeconnect_automation.config import Config, load_config
from edgeconnect_automation.errors import ConfigurationError
from edgeconnect_automation.mcp_server import Orchestrator, RateLimiter, Server, ToolError, high_risk_category

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
        self.assertRegex(value.pop("presharedkey"), r"^<REDACTED:[0-9a-f]{16}>$")
        self.assertRegex(value.pop("authKey"), r"^<REDACTED:[0-9a-f]{16}>$")
        self.assertEqual(value, {"passwordMinLen": 8, "csrfProtection": True, "md5Password": ""})
        self.prod_client.body = json.dumps({"cert": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"}).encode()
        _, text = self.call("api_get", path="/appliance")
        self.assertNotIn("MIIE", text)

    def test_secret_tokens_round_trip_on_write_back(self):
        self.lab_client.body = json.dumps({"name": "g", "presharedKey": "hunter2", "nested": [{"password": "p@ss"}]}).encode()
        _, text = self.call("api_get", orchestrator="lab", path="/appliance")
        self.assertNotIn("hunter2", text)
        self.assertNotIn("p@ss", text)
        read = json.loads(text)["result"]
        error, _ = self.call("api_write", orchestrator="lab", method="POST", path="/ipObjects/addressGroup", body=read)
        self.assertFalse(error)
        self.assertEqual(self.lab_client.calls[-1][3], {"name": "g", "presharedKey": "hunter2", "nested": [{"password": "p@ss"}]})
        sent = len(self.lab_client.calls)
        # A token moved into a readable field, or used on another Orchestrator, is refused rather than revealed.
        error, text = self.call("api_write", orchestrator="lab", method="POST", path="/ipObjects/addressGroup", body={"name": read["presharedKey"]})
        self.assertTrue(error)
        self.assertIn("placeholders", text)
        self.server.orchestrators["prod"].writes = True
        error, _ = self.call("api_write", orchestrator="prod", method="POST", path="/ipObjects/addressGroup", body=read)
        self.assertTrue(error)
        self.assertEqual(len(self.lab_client.calls), sent)
        self.assertEqual(self.prod_client.calls, [])

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

    def test_high_risk_writes_need_their_own_opt_in(self):
        lab = self.server.orchestrators["lab"]
        lab.passthrough = True
        error, text = self.call("api_write", orchestrator="lab", method="DELETE", path="/appliance/2.NE")
        self.assertTrue(error)
        self.assertIn("appliance_lifecycle", text)
        self.assertIn("lab_mcp_allow_high_risk", text)
        error, text = self.call("api_write", orchestrator="lab", method="POST", path="/appliance/rest/2.NE", query={"url": "system/reboot"})
        self.assertTrue(error)
        self.assertIn("(reboot)", text)
        self.assertEqual(self.lab_client.calls, [])
        lab.allow_high_risk = ("appliance_lifecycle",)
        error, _ = self.call("api_write", orchestrator="lab", method="DELETE", path="/appliance/2.NE")
        self.assertFalse(error)
        self.assertEqual(high_risk_category("POST", "/ipObjects/addressGroup"), None)
        for template in ("/certificates/parse", "/license/validate", "/cipher/checkCompatibility", "/sslCertificate/verify", "/users/lookup", "/brandImage/upload", "/appliance/rest/{nePk}/x/validate"):
            self.assertEqual(high_risk_category("POST", template), None, template)
        self.assertEqual(high_risk_category("POST", "/appliance/rest/{nePk}", "ntp/validate"), None)
        self.assertEqual(high_risk_category("POST", "/gmsConfig/portalCheck", None, "Test connectivity to the portal"), None)
        self.assertEqual(high_risk_category("POST", "/ssl/x", None, "Validate a certificate chain"), None)
        self.assertEqual(high_risk_category("POST", "/appliance/denied/delete"), "appliance_lifecycle")
        self.assertEqual(high_risk_category("PUT", "/gmsSMTP/config"), "orchestrator_admin")
        self.assertEqual(high_risk_category("POST", "/sse/connector"), "appliance_lifecycle")
        self.assertEqual(high_risk_category("POST", "/brandCustomization/image"), None)
        self.assertEqual(high_risk_category("POST", "/appliance/rest/{nePk}", "deployment"), None)
        for method, template, category in (("DELETE", "/appliance", "appliance_lifecycle"), ("POST", "/appliance", "appliance_lifecycle"),
                                           ("POST", "/appliance/deleteForDiscovery", "appliance_lifecycle"), ("POST", "/appliance/changePassword", "appliance_lifecycle"),
                                           ("POST", "/cloudDeployment/aws/instances", "cloud_deployment"), ("POST", "/edge-ha/groups", "appliance_lifecycle"),
                                           ("POST", "/orch-ha/failover", "orchestrator_ha"), ("POST", "/gmsRemoteAuth/TACACS+", "auth"), ("PUT", "/gmsRemoteAuth/JWT", "auth"),
                                           ("DELETE", "/vxoaImages/{id}", "upgrade"), ("POST", "/preconfiguration/{id}/apply", "provisioning"),
                                           ("POST", "/wizard/appliance/apply", "provisioning"), ("POST", "/rma/wizard", "provisioning"), ("POST", "/portal/registration", "provisioning"),
                                           ("POST", "/ztp/settings", "provisioning"), ("POST", "/accountKey/generate", "provisioning"),
                                           ("PUT", "/gmsConfig/sessionTimeout", "orchestrator_admin"), ("PUT", "/restApiConfig", "orchestrator_admin"),
                                           ("POST", "/advancedProperties", "orchestrator_admin"), ("PUT", "/security/advancedSettings", "orchestrator_admin"),
                                           ("POST", "/smtp", "orchestrator_admin"), ("DELETE", "/debugFiles/{name}", "orchestrator_admin"),
                                           ("DELETE", "/dbPartition/{id}", "orchestrator_admin"), ("POST", "/est/profile", "certificates"), ("POST", "/endEntityProfile", "certificates"),
                                           ("POST", "/users/{username}", "auth"), ("PUT", "/gms/backup/config", "backup_restore"),
                                           ("POST", "/broadcastCli", "cli"), ("POST", "/license/portal", "licensing"), ("POST", "/networkMemory", "traffic_disruptive")):
            self.assertEqual(high_risk_category(method, template), category, template)

    def test_flag_settings_named_like_secrets_stay_readable(self):
        self.lab_client.body = json.dumps({"applyPassword": "true", "enablePassword": "false", "password": "true", "authKey": "yes"}).encode()
        _, text = self.call("api_get", orchestrator="lab", path="/appliance")
        value = json.loads(text)["result"]
        self.assertEqual((value["applyPassword"], value["enablePassword"]), ("true", "false"))
        self.assertTrue(value["password"].startswith("<REDACTED:"))  # not flag-named, so still a secret
        self.assertTrue(value["authKey"].startswith("<REDACTED:"))

    def test_rate_limiter_waits_instead_of_failing(self):
        now, slept = [0.0], []
        limiter = RateLimiter(2, clock=lambda: now[0], sleep=lambda seconds: (slept.append(seconds), now.__setitem__(0, now[0] + seconds)))
        for _ in range(4):
            limiter.take()  # burst of twice the rate
        self.assertEqual(slept, [])
        limiter.take()
        self.assertAlmostEqual(slept[0], 0.5)
        RateLimiter(0, sleep=lambda seconds: self.fail("0 means no limit")).take()

    def test_audit_log_records_calls_without_secrets(self):
        path = os.path.join(self.tmp.name, "audit", "audit.jsonl")
        server = Server(self.server.orchestrators, default="prod", log=lambda line: None, audit_log=path)
        self.lab_client.body = json.dumps({"presharedKey": "hunter2"}).encode()
        for name, arguments in (("api_get", {"orchestrator": "lab", "path": "/appliance", "query": {"password": "q-secret"}}),
                                ("api_write", {"orchestrator": "lab", "method": "POST", "path": "/ipObjects/addressGroup", "body": {"name": "g"}}),
                                ("api_write", {"method": "DELETE", "path": "/appliance/2.NE"})):
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        server.audit.close()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        content = Path(path).read_text()
        self.assertNotIn("hunter2", content)
        self.assertNotIn("q-secret", content)
        records = [json.loads(line) for line in content.splitlines()]
        self.assertEqual([(r["tool"], r["orchestrator"], r["method"], r["outcome"]) for r in records],
                         [("api_get", "lab", "GET", "ok"), ("api_write", "lab", "POST", "ok"), ("api_write", "prod", "DELETE", "error")])
        self.assertTrue(records[1]["body_sha256"].startswith("sha256:"))
        self.assertIn("prod_mcp_writes", records[2]["error"])

    def test_results_are_marked_untrusted_and_hidden_characters_escaped(self):
        self.prod_client.body = json.dumps({"comment": "ok\u202egnp.exe\U000e0041"}).encode()
        _, text = self.call("api_get", path="/appliance")
        self.assertNotIn("\u202e", text)
        self.assertNotIn("\U000e0041", text)
        decoded = json.loads(text)
        self.assertEqual(decoded["result"]["comment"], "ok\u202egnp.exe\U000e0041")  # lossless
        self.assertIn("untrusted", decoded["note"])

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
