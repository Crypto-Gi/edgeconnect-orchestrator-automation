import copy
import csv
import tempfile
import unittest
from pathlib import Path

from edgeconnect_automation.errors import DriftError, ValidationError
from edgeconnect_automation.workflows import ADDRESS_HEADERS, APP_DEF_HEADERS, SERVICE_HEADERS, ApplicationDefinition, apply_appexpress, apply_native_groups, apply_zones, execute_application_definitions, execute_application_definitions_with_appexpress, native_csv_bytes, native_group_semantic_equal, parse_address_groups, parse_application_definitions, parse_application_groups, parse_service_groups, plan_appexpress, plan_appexpress_modes, plan_application_definitions, plan_application_groups, plan_native_groups, plan_zones


class TempCsv:
    def __init__(self, headers, rows):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "input.csv"
        with self.path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, headers)
            writer.writeheader()
            writer.writerows(rows)

    def close(self):
        self.directory.cleanup()


class RepositoryTemplateTests(unittest.TestCase):
    def test_current_templates_validate(self):
        root = Path(__file__).resolve().parents[1] / "templates" / "edgeconnect"
        self.assertEqual(len(parse_address_groups(str(root / "address_groups.csv"))), 2)
        self.assertEqual(len(parse_service_groups(str(root / "service_groups.csv"))), 2)
        self.assertTrue(any(item.definition_type == "COMPOUND" for item in parse_application_definitions(str(root / "application_definitions.csv"))))
        self.assertEqual(len(parse_application_groups(str(root / "application_groups.csv"))), 2)


class NativeGroupTests(unittest.TestCase):
    def test_address_groups_validate_references_and_create_only(self):
        fixture = TempCsv(ADDRESS_HEADERS, [
            {"Name": "base", "IncludedIPs": "10.0.0.0/24", "ExcludedIPs": "", "IncludedGroups": "", "Comment": ""},
            {"Name": "child", "IncludedIPs": "192.0.2.1/32", "ExcludedIPs": "", "IncludedGroups": "base", "Comment": "test"},
        ])
        try:
            rows = parse_address_groups(str(fixture.path))
            existing = [{"name": "base", "type": "AG", "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
            plan = plan_native_groups("address", rows, existing)
            self.assertEqual(plan.no_ops, ["base"])
            self.assertEqual([row["Name"] for row in plan.new_rows], ["child"])
            self.assertIn(b"child", plan.content)
            self.assertNotIn(b"base,10.0.0.0/24", plan.content)
        finally:
            fixture.close()

    def test_address_groups_accept_documented_ipv4_formats(self):
        values = [
            "10.10.10.1",
            "10.10.0.0/16",
            "10.10.0.0/255.255.0.0",
            "10.10.10.10-20",
            "10.10-20.0.0/16",
            "10.10-20.0.0/255.255.0.0",
            "10.10.10.*",
            "10.*.0.0/16",
            "10.*.0.0/255.255.0.0",
        ]
        fixture = TempCsv(ADDRESS_HEADERS, [
            {"Name": "documented", "IncludedIPs": ",".join(values), "ExcludedIPs": "10.20.30.10-20", "IncludedGroups": "", "Comment": ""},
        ])
        try:
            self.assertEqual(parse_address_groups(str(fixture.path))[0]["IncludedIPs"], ",".join(values))
        finally:
            fixture.close()

    def test_address_groups_reject_ipv6_and_invalid_ipv4_formats(self):
        invalid = [
            ("2001:db8::/64", "IPv6 is not supported"),
            ("999.1.1.1", "out of range"),
            ("10.0.0.20-10", "out of range"),
            ("10.0.0.0/33", "prefix length"),
            ("10.0.0.0/255.0.255.0", "not contiguous"),
            ("10.0.*", "four octets"),
        ]
        for value, message in invalid:
            with self.subTest(value=value):
                fixture = TempCsv(ADDRESS_HEADERS, [
                    {"Name": "invalid", "IncludedIPs": value, "ExcludedIPs": "", "IncludedGroups": "", "Comment": ""},
                ])
                try:
                    with self.assertRaisesRegex(ValidationError, message):
                        parse_address_groups(str(fixture.path))
                finally:
                    fixture.close()

    def test_repeated_group_rows_merge_rules_in_order(self):
        fixture = TempCsv(ADDRESS_HEADERS, [
            {"Name": "multi", "IncludedIPs": "10.0.0.0/24,10.1.0.0/24", "ExcludedIPs": "", "IncludedGroups": "", "Comment": "first"},
            {"Name": "multi", "IncludedIPs": "192.0.2.1/32", "ExcludedIPs": "", "IncludedGroups": "", "Comment": "second"},
        ])
        try:
            rows = parse_address_groups(str(fixture.path))
            plan = plan_native_groups("address", rows, [])
            self.assertEqual(len(plan.new_rows), 2)
            existing = [{"name": "multi", "type": "AG", "rules": [
                {"includedIPs": ["10.0.0.0/24", "10.1.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": "first"},
                {"includedIPs": ["192.0.2.1/32"], "excludedIPs": [], "includedGroups": [], "comment": "second"},
            ]}]
            self.assertEqual(plan_native_groups("address", rows, existing).no_ops, ["multi"])
        finally:
            fixture.close()

    def test_icmpv6_and_tcp_port_zero_are_locally_accepted(self):
        fixture = TempCsv(SERVICE_HEADERS, [
            {"Name": "icmp6", "Protocol": "ICMPV6", "IncludedPorts": "", "ExcludedPorts": "", "IncludedGroups": "", "ExcludedGroups": "", "IcmpTypes": "128", "IcmpCodes": "0", "Comment": ""},
            {"Name": "tcp0", "Protocol": "TCP", "IncludedPorts": "0", "ExcludedPorts": "", "IncludedGroups": "", "ExcludedGroups": "", "IcmpTypes": "", "IcmpCodes": "", "Comment": ""},
        ])
        try:
            rows = parse_service_groups(str(fixture.path))
            self.assertEqual(rows[0]["Protocol"], "ICMPV6")
            self.assertEqual(rows[1]["IncludedPorts"], "0")
        finally:
            fixture.close()

    def test_nesting_depth_over_two_rejected(self):
        fixture = TempCsv(ADDRESS_HEADERS, [
            {"Name": "one", "IncludedIPs": "", "ExcludedIPs": "", "IncludedGroups": "two", "Comment": ""},
            {"Name": "two", "IncludedIPs": "", "ExcludedIPs": "", "IncludedGroups": "three", "Comment": ""},
            {"Name": "three", "IncludedIPs": "", "ExcludedIPs": "", "IncludedGroups": "four", "Comment": ""},
            {"Name": "four", "IncludedIPs": "10.0.0.0/24", "ExcludedIPs": "", "IncludedGroups": "", "Comment": ""},
        ])
        try:
            with self.assertRaisesRegex(ValidationError, "depth 2"):
                parse_address_groups(str(fixture.path))
        finally:
            fixture.close()

    def test_native_binary_upload_is_verified(self):
        rows = [{"Name": "new", "IncludedIPs": "10.0.0.0/24", "ExcludedIPs": "", "IncludedGroups": "", "Comment": "", "_row": "2"}]
        plan = plan_native_groups("address", rows, [])
        gateway = FakeBulkGateway()
        result = apply_native_groups(gateway, plan)
        self.assertEqual(result["status"], "success")
        self.assertEqual(gateway.uploaded, plan.content)

    def test_native_group_server_managed_null_type_is_semantically_equal(self):
        expected = {"name": "web", "type": "SG", "rules": [{"protocol": "TCP", "includedPorts": ["443"], "excludedPorts": [], "includedGroups": [], "excludedGroups": [], "icmpTypes": [], "icmpCodes": [], "comment": None}]}
        actual = dict(expected, type=None)
        self.assertTrue(native_group_semantic_equal(actual, expected))
        self.assertFalse(native_group_semantic_equal(dict(expected, type="AG"), expected))

        rows = [{"Name": "web", "Protocol": "TCP", "IncludedPorts": "443", "ExcludedPorts": "", "IncludedGroups": "", "ExcludedGroups": "", "IcmpTypes": "", "IcmpCodes": "", "Comment": "", "_row": "2"}]
        plan = plan_native_groups("service", rows, [actual])
        self.assertEqual(plan.no_ops, ["web"])
        self.assertFalse(plan.new_rows)
        self.assertFalse(plan.conflicts)

    def test_service_group_null_type_readback_is_verified(self):
        rows = [{"Name": "web", "Protocol": "TCP", "IncludedPorts": "443", "ExcludedPorts": "", "IncludedGroups": "", "ExcludedGroups": "", "IcmpTypes": "", "IcmpCodes": "", "Comment": "", "_row": "2"}]
        plan = plan_native_groups("service", rows, [])

        class Gateway:
            def __init__(self):
                self.values = []

            def get_service_groups(self):
                return copy.deepcopy(self.values)

            def upload_service_groups(self, content):
                self.values = [{"name": "web", "type": None, "rules": [{"protocol": "TCP", "includedPorts": ["443"], "excludedPorts": [], "includedGroups": [], "excludedGroups": [], "icmpTypes": [], "icmpCodes": [], "comment": None}]}]
                return {"success": True}

        result = apply_native_groups(Gateway(), plan)
        self.assertEqual(result["status"], "success")
        self.assertFalse(result["unverified"])

    def test_native_runtime_failure_is_all_or_nothing_partial(self):
        rows = [{"Name": "new", "IncludedIPs": "10.0.0.0/24", "ExcludedIPs": "", "IncludedGroups": "", "Comment": "", "_row": "2"}]
        plan = plan_native_groups("address", rows, [])

        class Gateway:
            def get_address_groups(self):
                return []

            def upload_address_groups(self, content):
                raise ValidationError("An ICMP rule should specify at least one type")

        result = apply_native_groups(Gateway(), plan)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["created"], [])
        self.assertTrue(result["all_or_nothing"])

    def test_group_cycle_rejected(self):
        fixture = TempCsv(ADDRESS_HEADERS, [
            {"Name": "one", "IncludedIPs": "", "ExcludedIPs": "", "IncludedGroups": "two", "Comment": ""},
            {"Name": "two", "IncludedIPs": "", "ExcludedIPs": "", "IncludedGroups": "one", "Comment": ""},
        ])
        try:
            with self.assertRaisesRegex(ValidationError, "cycle"):
                parse_address_groups(str(fixture.path))
        finally:
            fixture.close()

    def test_service_validation_and_excluded_cycle(self):
        fixture = TempCsv(SERVICE_HEADERS, [
            {"Name": "one", "Protocol": "TCP", "IncludedPorts": "80,443", "ExcludedPorts": "", "IncludedGroups": "", "ExcludedGroups": "two", "IcmpTypes": "", "IcmpCodes": "", "Comment": ""},
            {"Name": "two", "Protocol": "UDP", "IncludedPorts": "53", "ExcludedPorts": "", "IncludedGroups": "one", "ExcludedGroups": "", "IcmpTypes": "", "IcmpCodes": "", "Comment": ""},
        ])
        try:
            with self.assertRaisesRegex(ValidationError, "cycle"):
                parse_service_groups(str(fixture.path))
        finally:
            fixture.close()


class FakeBulkGateway:
    def __init__(self):
        self.address = []
        self.uploaded = None

    def upload_address_groups(self, content):
        self.uploaded = content
        self.address = [{"name": "new", "type": "AG", "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
        return {"success": True}

    def get_address_groups(self):
        return self.address


class ZoneTests(unittest.TestCase):
    def test_zone_plan_preserves_collection_and_verifies_mapping(self):
        baseline = {"1": {"name": "EXISTING"}}
        plan = plan_zones(baseline, 2, ["NEW_ZONE"])
        self.assertEqual(plan.candidate["1"], baseline["1"])
        self.assertEqual(plan.created, {"NEW_ZONE": 2})

        class Gateway:
            def __init__(self):
                self.value = copy.deepcopy(baseline)

            def get_zones(self):
                return copy.deepcopy(self.value)

            def post_zones(self, value):
                self.value = copy.deepcopy(value)

            def get_zone_mappings(self):
                return [{"zoneName": "NEW_ZONE", "zoneId": 2}]

        result = apply_zones(Gateway(), plan)
        self.assertEqual(result["status"], "success")

    def test_zone_drift_aborts(self):
        plan = plan_zones({}, 1, ["NEW"])

        class Gateway:
            def get_zones(self):
                return {"9": {"name": "DRIFT"}}

        with self.assertRaises(DriftError):
            apply_zones(Gateway(), plan)

    def test_reserved_zone_rejected(self):
        with self.assertRaises(ValidationError):
            plan_zones({}, 1, ["Default"])


class ApplicationDefinitionTests(unittest.TestCase):
    def _row(self, definition_type="COMPOUND", name="compound"):
        row = {header: "" for header in APP_DEF_HEADERS}
        row.update({"DefinitionType": definition_type, "Name": name, "Enabled": "TRUE", "Confidence": "100", "AppExpressMode": "OFF"})
        return row

    def test_compound_validation_direct_dns_and_id_allocation(self):
        compound = self._row()
        compound.update({"Protocol": "ip", "SourcePort": "80", "EitherDomain": "*.example.com"})
        fixture = TempCsv(APP_DEF_HEADERS, [compound])
        try:
            definitions = parse_application_definitions(str(fixture.path))
            inventories = {"portProtocolClassification": {}, "dnsClassification": [], "compoundClassification": {"9": {"id": 9, "name": "old"}, "10": {"id": 10, "name": "old2"}}}
            plan = plan_application_definitions(definitions, inventories)
            self.assertEqual(plan.new[0].identity, "compound")
            self.assertEqual(plan.new[0].payload["either_dns"], "*.example.com")
            self.assertNotIn("id", plan.new[0].payload)
        finally:
            fixture.close()

    def test_compound_requires_two_attributes_and_direction_exclusivity(self):
        one = self._row(name="one")
        one["Protocol"] = "tcp"
        fixture = TempCsv(APP_DEF_HEADERS, [one])
        try:
            with self.assertRaisesRegex(ValidationError, "at least two"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()
        conflict = self._row(name="conflict")
        conflict.update({"SourcePort": "80", "EitherPort": "443"})
        fixture = TempCsv(APP_DEF_HEADERS, [conflict])
        try:
            with self.assertRaisesRegex(ValidationError, "mutually exclusive"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()

    def test_compound_name_identity_ignores_renumbered_id(self):
        compound = self._row()
        compound.update({"Protocol": "ip", "SourcePort": "80"})
        fixture = TempCsv(APP_DEF_HEADERS, [compound])
        try:
            definition = parse_application_definitions(str(fixture.path))[0]
            existing_body = dict(definition.payload, id=42)
            plan = plan_application_definitions([definition], {"portProtocolClassification": {}, "dnsClassification": [], "compoundClassification": {"1": existing_body}})
            self.assertEqual(plan.no_ops, ["compound"])
        finally:
            fixture.close()

    def test_compound_id_allocated_only_immediately_and_readback_allows_reindex(self):
        definition = ApplicationDefinition(2, "COMPOUND", "new", {"name": "new", "description": "", "disabled": False, "confidence": 100, "protocol": "ip", "src_port": "80"}, "new", "OFF")

        class Gateway:
            def __init__(self):
                self.values = {"9": {"id": 9, "name": "old"}, "10": {"id": 10, "name": "old2"}}
                self.posted = None

            def get_application_definitions(self, base):
                return copy.deepcopy(self.values)

            def post_application_definition(self, base, value, identity):
                self.posted = (base, copy.deepcopy(value), identity)
                new_value = copy.deepcopy(value)
                new_value["id"] = 3
                self.values = {"1": {"id": 1, "name": "old"}, "2": {"id": 2, "name": "old2"}, "3": new_value}

        gateway = Gateway()
        inventories = {"compoundClassification": copy.deepcopy(gateway.values)}
        result = execute_application_definitions(gateway, [definition], inventories)
        self.assertEqual(result["status"], "success")
        self.assertEqual(gateway.posted[0], "compoundClassification")
        self.assertEqual(gateway.posted[2], 11)
        self.assertEqual(gateway.posted[1]["id"], 11)

    def test_confidence_zero_and_compound_over_512_characters_rejected(self):
        invalid = self._row("DOMAIN", "bad")
        invalid.update({"Domain": "example.com", "Confidence": "0"})
        fixture = TempCsv(APP_DEF_HEADERS, [invalid])
        try:
            with self.assertRaisesRegex(ValidationError, "1..100"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()
        oversized = self._row()
        oversized.update({"Protocol": "ip", "EitherDomain": "|".join("domain{}.example.com".format(index) for index in range(40))})
        fixture = TempCsv(APP_DEF_HEADERS, [oversized])
        try:
            with self.assertRaisesRegex(ValidationError, "512 characters"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()

    def test_definition_type_rejects_irrelevant_fields_and_bad_names(self):
        tcp = self._row("TCP_PORT", "valid-name")
        tcp.update({"Port": "443", "Domain": "unexpected.example.com"})
        fixture = TempCsv(APP_DEF_HEADERS, [tcp])
        try:
            with self.assertRaisesRegex(ValidationError, "not valid for TCP_PORT"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()
        bad_name = self._row("DOMAIN", "bad.name")
        bad_name["Domain"] = "example.com"
        fixture = TempCsv(APP_DEF_HEADERS, [bad_name])
        try:
            with self.assertRaisesRegex(ValidationError, "Name must"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()

    def test_dedicated_port_and_domain_validation(self):
        ranged = self._row("TCP_PORT", "tcp-range")
        ranged["Port"] = "80-90"
        fixture = TempCsv(APP_DEF_HEADERS, [ranged])
        try:
            with self.assertRaisesRegex(ValidationError, "one numeric Port"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()
        domain = self._row("DOMAIN", "domain-test")
        domain["Domain"] = "https://example.com/path"
        fixture = TempCsv(APP_DEF_HEADERS, [domain])
        try:
            with self.assertRaisesRegex(ValidationError, "invalid Domain"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()

    def test_simple_compound_tcp_port_is_rejected(self):
        row = self._row("COMPOUND", "compound-test")
        row.update({"Protocol": "tcp", "DestinationPort": "443"})
        fixture = TempCsv(APP_DEF_HEADERS, [row])
        try:
            with self.assertRaisesRegex(ValidationError, "dedicated definition type"):
                parse_application_definitions(str(fixture.path))
        finally:
            fixture.close()

    def test_sequential_creation_stops_on_partial_failure(self):
        definitions = [
            ApplicationDefinition(2, "DOMAIN", "one", {"domain": "one.example", "name": "one", "description": "", "priority": 100, "disabled": False}, "one.example", "OFF"),
            ApplicationDefinition(3, "DOMAIN", "two", {"domain": "two.example", "name": "two", "description": "", "priority": 100, "disabled": False}, "two.example", "OFF"),
        ]

        class Gateway:
            def __init__(self):
                self.values = []
                self.posts = 0

            def get_application_definitions(self, base):
                return copy.deepcopy(self.values)

            def post_application_definition(self, base, value, identity=None):
                self.posts += 1
                if self.posts == 2:
                    raise RuntimeError("failure")
                self.values.append(copy.deepcopy(value))

        gateway = Gateway()
        result = execute_application_definitions(gateway, definitions, {"dnsClassification": []})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["created"], ["one"])
        self.assertEqual(gateway.posts, 2)

    def test_simple_identical_noop_and_conflict(self):
        row = self._row("TCP_PORT", "web")
        row["Port"] = "443"
        fixture = TempCsv(APP_DEF_HEADERS, [row])
        try:
            definitions = parse_application_definitions(str(fixture.path))
            identical = {"portProtocolClassification": {"443": [{"port": "443", "protocol": 6, "name": "web", "description": "", "priority": 100, "disabled": False}]}, "dnsClassification": [], "compound": {}}
            self.assertEqual(plan_application_definitions(definitions, identical).no_ops, ["web"])
            different = copy.deepcopy(identical)
            different["portProtocolClassification"]["443"][0]["name"] = "other"
            conflicts = plan_application_definitions(definitions, different).conflicts
            self.assertEqual(conflicts, [{"row": 2, "name": "web", "definition_type": "TCP_PORT", "identity": ("443", 6), "reason": "existing port/protocol identity has different semantics"}])
        finally:
            fixture.close()


class ApplicationGroupAndExpressTests(unittest.TestCase):
    def test_application_group_parent_cycle(self):
        fixture = TempCsv(["Name", "Applications", "ParentGroups"], [
            {"Name": "one", "Applications": "app", "ParentGroups": "two"},
            {"Name": "two", "Applications": "app", "ParentGroups": "one"},
        ])
        try:
            with self.assertRaisesRegex(ValidationError, "cycle"):
                parse_application_groups(str(fixture.path))
        finally:
            fixture.close()

    def test_application_group_plural_parents_and_comma_members(self):
        rows = [{"Name": "child", "Applications": "app1,app2", "ParentGroups": "parent1,parent2", "_row": "2"}]
        existing = {"parent1": {"apps": [], "parentGroup": None}, "parent2": {"apps": [], "parentGroup": None}}
        plan = plan_application_groups(rows, existing, {"app1", "app2"})
        self.assertEqual(plan["candidate"]["child"]["apps"], ["app1", "app2"])
        self.assertEqual(plan["candidate"]["child"]["parentGroup"], ["parent1", "parent2"])

    def test_appexpress_monitor_preserves_collection_and_ids(self):
        current = {"old": {"id": 4, "name": "Old", "monitor": True, "appExpressEnabled": False}}
        plan = plan_appexpress(["NewApp"], {"NewApp"}, current)
        self.assertEqual(plan["candidate"]["newapp"]["id"], 5)
        self.assertEqual(plan["candidate"]["old"], current["old"])

        class Gateway:
            def __init__(self):
                self.value = copy.deepcopy(current)

            def get_appexpress(self):
                return copy.deepcopy(self.value)

            def post_appexpress(self, value):
                self.value = copy.deepcopy(value)

        self.assertEqual(apply_appexpress(Gateway(), plan)["status"], "success")

    def test_appexpress_readback_ignores_server_reindexed_ids(self):
        current = {"first": {"id": 7, "name": "First", "monitor": True, "appExpressEnabled": False}}
        plan = plan_appexpress(["Second"], {"Second"}, current)

        class Gateway:
            def __init__(self):
                self.value = copy.deepcopy(current)

            def get_appexpress(self):
                return copy.deepcopy(self.value)

            def post_appexpress(self, value):
                self.value = copy.deepcopy(value)
                self.value["first"]["id"] = 0
                self.value["second"]["id"] = 1

        self.assertEqual(list(plan["candidate"]), ["first", "second"])
        self.assertEqual(apply_appexpress(Gateway(), plan)["status"], "success")

    def test_appexpress_missing_application_rejected(self):
        with self.assertRaisesRegex(ValidationError, "do not exist"):
            plan_appexpress(["missing"], set(), {})

    def test_appexpress_modes_apply_monitor_and_off_as_desired_state(self):
        current = {
            "remove": {"id": 1, "name": "Remove", "monitor": True, "appExpressEnabled": False},
            "update": {"id": 2, "name": "Update", "monitor": False, "appExpressEnabled": True, "probes": ["preserve"]},
            "unrelated": {"id": 3, "name": "Unrelated", "monitor": True, "appExpressEnabled": False},
        }
        plan = plan_appexpress_modes({"Remove": "OFF", "Update": "MONITOR", "New": "MONITOR", "Absent": "OFF"}, current)
        self.assertNotIn("remove", plan["candidate"])
        self.assertTrue(plan["candidate"]["update"]["monitor"])
        self.assertFalse(plan["candidate"]["update"]["appExpressEnabled"])
        self.assertEqual(plan["candidate"]["update"]["probes"], ["preserve"])
        self.assertEqual(plan["candidate"]["unrelated"], current["unrelated"])
        self.assertIn("new", plan["candidate"])
        self.assertEqual(plan["monitor"], ["Update", "New"])
        self.assertEqual(plan["off"], ["Remove"])
        self.assertIn("Absent", plan["no_ops"])

        class Gateway:
            def __init__(self):
                self.value = copy.deepcopy(current)

            def get_appexpress(self):
                return copy.deepcopy(self.value)

            def post_appexpress(self, value):
                self.value = copy.deepcopy(value)

        gateway = Gateway()
        self.assertEqual(apply_appexpress(gateway, plan)["status"], "success")
        self.assertFalse(any(value.get("name") == "Remove" for value in gateway.value.values()))
        self.assertEqual(gateway.value["unrelated"], current["unrelated"])

    def test_combined_definition_workflow_reports_appexpress_drift_as_partial(self):
        plan = plan_appexpress_modes({"App": "MONITOR"}, {})

        class Gateway:
            def get_appexpress(self):
                return {"other": {"name": "Other", "monitor": True, "appExpressEnabled": False}}

        result = execute_application_definitions_with_appexpress(Gateway(), [], {}, plan)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["application_definitions"]["status"], "success")
        self.assertEqual(result["appexpress"]["status"], "failed")
        self.assertIn("changed before write", result["appexpress"]["error"])

    def test_combined_definition_failure_does_not_write_appexpress(self):
        definition = ApplicationDefinition(2, "DOMAIN", "broken", {"domain": "broken.example", "name": "broken", "description": "", "priority": 100, "disabled": False}, "broken.example", "MONITOR")

        class Gateway:
            def __init__(self):
                self.appexpress_posts = 0

            def get_application_definitions(self, base):
                return []

            def post_application_definition(self, base, value, identity=None):
                raise RuntimeError("definition failure")

            def get_appexpress(self):
                return {}

            def post_appexpress(self, value):
                self.appexpress_posts += 1

        gateway = Gateway()
        result = execute_application_definitions_with_appexpress(gateway, [definition], {"dnsClassification": []}, plan_appexpress_modes({"broken": "MONITOR"}, {}))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["appexpress"]["status"], "not_attempted")
        self.assertEqual(gateway.appexpress_posts, 0)


if __name__ == "__main__":
    unittest.main()
