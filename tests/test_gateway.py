import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation.errors import ValidationError
from edgeconnect_automation.gateway import OrchestratorGateway


class FakeClient:
    def __init__(self):
        self.calls = []
        self.response = {"success": True, "error": None}
        self.config = SimpleNamespace(verification_timeout=0.1, poll_interval=0)

    def get(self, path, query=None, expected_status=(200,)):
        self.calls.append(("GET", path, query))
        if path == "/applicationDefinition":
            return [] if query["base"] == "dnsClassification" else {}
        if path == "/action":
            return [{"name": "Segment Security Policy Changed", "result": "run 0_0", "taskStatus": "COMPLETED", "completionStatus": True}]
        return {}

    def post_json(self, path, value, query=None, expected_status=(200, 204)):
        self.calls.append(("POST", path, query, value))

    def post_multipart_file(self, path, field, filename, value, query=None, expected_status=(200,)):
        self.calls.append(("MULTIPART", path, field, filename, value))
        return self.response

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return []


class GatewayContractTests(unittest.TestCase):
    def test_native_bulk_uses_csvfile_multipart_and_parses_failure(self):
        client = FakeClient()
        gateway = OrchestratorGateway(client)
        result = gateway.upload_address_groups(b"csv")
        self.assertTrue(result["success"])
        self.assertEqual(client.calls[0][0:4], ("MULTIPART", "/ipObjects/addressGroup/bulkUpload", "csvFile", "address_groups.csv"))
        client.response = {"success": False, "error": "bad CSV"}
        with self.assertRaisesRegex(ValidationError, "bad CSV"):
            gateway.upload_service_groups(b"csv")

    def test_application_definition_paths_and_queries(self):
        client = FakeClient()
        gateway = OrchestratorGateway(client)
        gateway.get_application_definitions("compoundClassification")
        self.assertEqual(client.calls[-1], ("GET", "/applicationDefinition", {"base": "compoundClassification", "resourceKey": "userDefined"}))
        gateway.post_application_definition("portProtocolClassification", {"name": "web"}, ("443", 6))
        self.assertEqual(client.calls[-1][1:3], ("/applicationDefinition/portProtocolClassification", {"port": "443", "protocol": 6}))
        gateway.post_application_definition("dnsClassification", {"name": "dns"}, "*.example.com")
        self.assertEqual(client.calls[-1][1:3], ("/applicationDefinition/dnsClassification", {"domain": "*.example.com"}))
        gateway.post_application_definition("compoundClassification", {"name": "compound", "id": 11}, 11)
        self.assertEqual(client.calls[-1][1:3], ("/applicationDefinition/compoundClassification", {"id": 11}))

    def test_appexpress_and_application_group_write_paths(self):
        client = FakeClient()
        gateway = OrchestratorGateway(client)
        gateway.get_appexpress()
        self.assertEqual(client.calls[-1][1], "/applicationDefinition/appExpressAppConfig")
        gateway.post_appexpress({})
        self.assertEqual(client.calls[-1][1], "/applicationDefinition/appExpressAppConfig")
        gateway.post_application_groups({})
        self.assertEqual(client.calls[-1][1:3], ("/applicationDefinition/applicationTags", None))

    def test_audit_query_requires_time_window(self):
        client = FakeClient()
        gateway = OrchestratorGateway(client)
        with patch("time.time", return_value=1000):
            gateway.correlate_audit("0_0", "run")
        self.assertEqual(client.calls[-1], ("GET", "/action", {"startTime": 700000, "endTime": 1000000}))


if __name__ == "__main__":
    unittest.main()
