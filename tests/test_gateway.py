import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edgeconnect_automation.errors import ValidationError
from edgeconnect_automation.gateway import OrchestratorGateway


class FakeClient:
    def __init__(self):
        self.calls = []
        self.response = {"success": True, "error": None}
        self.template_groups = []
        self.template_selections = {}
        self.associations = {}
        self.appliance_acls = {}
        self.security_map = {}
        self.config = SimpleNamespace(verification_timeout=0.1, poll_interval=0)

    def get(self, path, query=None, expected_status=(200,)):
        self.calls.append(("GET", path, query))
        if path == "/applicationDefinition":
            return [] if query["base"] == "dnsClassification" else {}
        if path == "/action":
            return [{"name": "Segment Security Policy Changed", "result": "run 0_0", "taskStatus": "COMPLETED", "completionStatus": True}]
        if path == "/template/templateGroups":
            return [group for group in self.template_groups if not query or group["name"] == query.get("templateGroup")]
        if path == "/template/templateSelection":
            return self.template_selections.get(query["templateGroup"], [])
        if path == "/template/applianceAssociation":
            return self.associations
        if path == "/acls":
            return self.appliance_acls
        if path == "/securityMaps":
            return self.security_map
        return {}

    def post_json(self, path, value, query=None, expected_status=(200, 204), accept="application/json"):
        self.calls.append(("POST", path, query, value, accept))

    def post_multipart_file(self, path, field, filename, value, query=None, expected_status=(200,)):
        self.calls.append(("MULTIPART", path, field, filename, value))
        return self.response

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return []


class GatewayContractTests(unittest.TestCase):
    def test_policy_compile_alarms_filter_by_source_priority_and_target(self):
        client = FakeClient()
        client.config.alarm_wait = 0
        alarms = [
            {"applianceId": "0.NE", "source": "/policyEngine/acl/46000", "description": "ACL rule has invalid syntax"},
            {"applianceId": "0.NE", "source": "/policyEngine/acl/99999"},
            {"applianceId": "9.NE", "source": "/policyEngine/acl/46020"},
            {"applianceId": "0.NE", "source": "/license/ec"},
        ]
        client.request = lambda method, path, **kwargs: client.calls.append((method, path, kwargs)) or alarms
        found = OrchestratorGateway(client).policy_compile_alarms(["0.NE"], 1000000, [46000, "46020"])
        self.assertEqual(found, {"0.NE": [46000]})
        method, path, kwargs = client.calls[-1]
        self.assertEqual((method, path, kwargs["json_body"], kwargs["query"]["view"]), ("POST", "/alarm/appliance", {"nePks": ["0.NE"]}, "active"))

    def test_deleted_rules_must_disappear_from_reachable_appliances(self):
        client = FakeClient()
        client.security_map = {"map1": {"1_2": {"prio": {"100": {}, "200": {}}}}}
        gateway = OrchestratorGateway(client, {"0.NE": "reachable", "4.NE": "unreachable"})
        removed = [{"zone_key": "1_2", "priority": 100}, {"zone_key": "1_2", "priority": 300}]
        self.assertEqual(gateway.verify_rules_absent(removed), {"0.NE": "still_present:100", "4.NE": "unreachable"})
        client.security_map = {"map1": {"1_2": {"prio": {"200": {}}}}}
        self.assertEqual(gateway.verify_rules_absent(removed), {"0.NE": "verified", "4.NE": "unreachable"})

    def test_alarm_check_failure_is_explicit_and_unverified(self):
        from edgeconnect_automation.gateway import appliance_rejections

        class Broken:
            def policy_compile_alarms(self, *args):
                raise RuntimeError("timeout")

        targets = {"0.NE": "verified", "4.NE": "unreachable"}
        message = appliance_rejections(Broken(), targets, 0, [1])
        self.assertEqual(targets, {"0.NE": "alarm_check_failed", "4.NE": "unreachable"})
        self.assertIn("appliance alarm check failed", message)
        self.assertEqual(appliance_rejections(Broken(), {"0.NE": "unreachable"}, 0, [1]), "")

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

    def test_delete_paths_and_queries(self):
        client = FakeClient()
        gateway = OrchestratorGateway(client)
        gateway.delete_address_group("address")
        self.assertEqual(client.calls[-1][0:2], ("DELETE", "/ipObjects/addressGroup"))
        self.assertEqual(client.calls[-1][2]["query"], {"name": "address"})
        gateway.delete_service_group("service")
        self.assertEqual(client.calls[-1][0:2], ("DELETE", "/ipObjects/serviceGroup"))
        gateway.delete_application_definition("portProtocolClassification", ("443", 6))
        self.assertEqual(client.calls[-1][2]["query"], {"port": "443", "protocol": 6})
        gateway.delete_application_definition("dnsClassification", "example.com")
        self.assertEqual(client.calls[-1][2]["query"], {"domain": "example.com"})
        gateway.delete_application_definition("compoundClassification", 7)
        self.assertEqual(client.calls[-1][2]["query"], {"id": 7})

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

    def test_template_group_write_contracts(self):
        client = FakeClient()
        client.template_groups = [{"name": "test2", "templates": []}]
        client.template_selections = {"test2": ["acls"]}
        gateway = OrchestratorGateway(client)
        self.assertEqual(gateway.get_template_group("test2")["name"], "test2")
        self.assertEqual(gateway.get_template_selection("test2"), ["acls"])
        body = {"name": "test2", "templates": [{"name": "acls", "valObject": {"data": {}, "options": {"merge": True}}}]}
        gateway.post_template_group("test2", body)
        self.assertEqual(client.calls[-1][1:3], ("/template/templateGroups", {"templateGroup": "test2"}))
        gateway.create_template_group(body)
        self.assertEqual(client.calls[-1][1:3], ("/template/templateCreate", None))
        gateway.select_template_group("test2", ["acls"])
        self.assertEqual(client.calls[-1][1:3], ("/template/templateSelection", {"templateGroup": "test2"}))
        self.assertEqual([call[4] for call in client.calls if call[0] == "POST"], ["text/plain"] * 3)

    def test_central_acl_inventory_preserves_group_provenance_and_associations(self):
        client = FakeClient()
        client.template_groups = [{
            "name": "test2",
            "selectedTemplateNames": ["acls"],
            "templates": [{"name": "acls", "value": {"data": {
                "NewACL": {"entry": {}},
                "lab25-test1": {"entry": {"1000": {"permit": True, "app_group": "Accounting"}}},
            }, "options": {"merge": True}}}],
        }]
        client.associations = {"0.NE": ["test2"]}
        inventory = OrchestratorGateway(client).get_central_acls({"lab25-test1"})
        self.assertEqual(inventory["lab25-test1"][0]["template_group"], "test2")
        self.assertEqual(inventory["lab25-test1"][0]["associated_targets"], ["0.NE"])
        self.assertTrue(inventory["lab25-test1"][0]["selected"])
        self.assertNotIn("NewACL", inventory)

    def test_effective_acl_comparison_preserves_nonempty_acl_and_tolerates_empty_for_ordinary_rule(self):
        ordinary = {"data": {"map1": {"1_2": {"prio": {"100": {"match": {"protocol": "tcp"}, "set": {"action": "allow"}, "misc": {"logging_priority": 2}}}}}}}
        appliance_ordinary = {"map1": {"1_2": {"prio": {"100": {"match": {"protocol": "tcp", "acl": ""}, "set": {"action": "allow"}, "misc": {"logging_priority": "2"}}}}}}
        self.assertTrue(OrchestratorGateway._effective_contains(appliance_ordinary, ordinary))
        acl = {"data": {"map1": {"1_2": {"prio": {"100": {"match": {"acl": "lab25-test1"}, "set": {"action": "allow"}, "misc": {}}}}}}}
        appliance_acl = {"map1": {"1_2": {"prio": {"100": {"match": {"acl": "lab25-test1"}, "set": {"action": "allow"}, "misc": {}}}}}}
        self.assertTrue(OrchestratorGateway._effective_contains(appliance_acl, acl))
        appliance_acl["map1"]["1_2"]["prio"]["100"]["match"]["acl"] = "other"
        self.assertFalse(OrchestratorGateway._effective_contains(appliance_acl, acl))

    def test_appliance_acl_normalization_ignores_generated_metadata(self):
        client = FakeClient()
        client.appliance_acls = {"lab25-test1": {"entry": {"1000": {"self": 1000, "gms_marked": False, "permit": True}}, "secmap": {}}}
        entries = OrchestratorGateway(client).get_appliance_acls("0.NE")
        self.assertEqual(entries, {"lab25-test1": {"1000": {"permit": True}}})
        self.assertEqual(client.calls[-1], ("GET", "/acls", {"nePk": "0.NE", "cached": "false"}))

    def test_target_verification_reports_acl_mismatch_after_policy_converges(self):
        client = FakeClient()
        client.security_map = {"map1": {"1_2": {"prio": {"100": {"match": {"acl": "lab25-test1"}, "set": {"action": "allow"}, "misc": {}}}}}}
        client.appliance_acls = {"lab25-test1": {"entry": {"1000": {"permit": False}}}}
        gateway = OrchestratorGateway(client, {"0.NE": "reachable"})
        candidate = {"data": {"map1": {"1_2": {"prio": {"100": {"match": {"acl": "lab25-test1"}, "set": {"action": "allow"}, "misc": {}}}}}}}
        with patch("time.monotonic", side_effect=[0, 0, 1]):
            result = gateway.verify_targets("0_0", candidate, "run", {"lab25-test1": {"1000": {"permit": True}}})
        self.assertEqual(result, {"0.NE": "acl_mismatch:lab25-test1"})


if __name__ == "__main__":
    unittest.main()
