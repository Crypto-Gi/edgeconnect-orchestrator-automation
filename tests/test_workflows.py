import copy
import csv
import tempfile
import unittest
from pathlib import Path

from edgeconnect_automation.errors import DriftError, ValidationError
from edgeconnect_automation.firewall import parse_firewall_csv
from edgeconnect_automation.workflows import ACL_HEADERS, ACL_HEADERS_LEGACY, ADDRESS_HEADERS, APP_DEF_HEADERS, SERVICE_HEADERS, ApplicationDefinition, apply_appexpress, apply_native_groups, apply_template_acls, apply_zones, execute_application_definitions, execute_application_definitions_with_appexpress, native_csv_bytes, native_group_semantic_equal, parse_address_groups, parse_application_definitions, parse_application_groups, parse_service_groups, parse_template_acls, plan_appexpress_modes, plan_application_definitions, plan_application_groups, plan_native_groups, plan_template_acl_deletions, plan_template_acls, plan_zones


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


def acl_group(name, acls=None, merge=True, selected=True):
    return {
        "name": name,
        "selectedTemplateNames": ["acls"] if selected else [],
        "templates": [
            {"name": "acls", "value": {"data": copy.deepcopy(acls or {"NewACL": {"entry": {}}}), "options": {"merge": merge, "delDependent": True}}},
            {"name": "hostname", "value": {"hostname": name}},
        ],
    }


class TemplateAclTests(unittest.TestCase):
    def row(self, **values):
        row = {header: "" for header in ACL_HEADERS}
        row.update({"TemplateGroup": "test2", "ACLName": "web-acl", "ACLUpdateMode": "MERGE", "TemplateApplyMode": "MERGE", "Priority": "1000", "Permit": "TRUE", "BroadMatchAck": "FALSE"}, **values)
        return row

    def test_strict_delete_removes_only_an_exact_complete_acl(self):
        fixture = TempCsv(ACL_HEADERS, [self.row(Protocol="tcp")])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        existing = acl_group("test2", {"web-acl": {"entry": {"1000": rules[0].entry}}, "keep": {"entry": {"9000": {"permit": False}}}})
        plan = plan_template_acl_deletions(rules, [existing], {"test2": ["acls", "hostname"]}, {"0.NE": ["test2"]})
        group = plan["groups"][0]
        self.assertTrue(group["eligible"], group["errors"])
        self.assertEqual(group["deleted_acls"], ["web-acl"])
        self.assertNotIn("web-acl", group["candidate_acl_value"]["data"])
        self.assertIn("keep", group["candidate_acl_value"]["data"])
        self.assertEqual(group["candidate_selection"], ["acls", "hostname"])
        self.assertEqual(group["associations"], ["0.NE"])
        self.assertEqual(group["unrelated_templates"], [existing["templates"][1]])

    def test_addresses_are_written_with_prefix_and_old_bare_acl_still_deletes_exactly(self):
        fixture = TempCsv(ACL_HEADERS, [self.row(SourceIP="198.18.80.193", DestinationIP="198.18.4.0/255.255.254.0", Protocol="tcp")])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        self.assertEqual((rules[0].entry["src_ip"], rules[0].entry["dst_ip"]), ("198.18.80.193/32", "198.18.4.0/23"))
        self.assertEqual(sum("[ACL-29]" in warning for warning in rules[0].warnings), 2)
        legacy = dict(rules[0].entry, src_ip="198.18.80.193", dst_ip="198.18.4.0/255.255.254.0")
        group = plan_template_acl_deletions(rules, [acl_group("test2", {"web-acl": {"entry": {"1000": legacy}}})], {"test2": ["acls"]}, {})["groups"][0]
        self.assertTrue(group["eligible"], group["errors"])
        self.assertEqual(group["deleted_acls"], ["web-acl"])

    def test_strict_delete_blocks_partial_or_semantically_different_acl(self):
        fixture = TempCsv(ACL_HEADERS, [self.row(Protocol="tcp")])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        extra = copy.deepcopy(rules[0].entry)
        extra["permit"] = False
        existing = acl_group("test2", {"web-acl": {"entry": {"1000": rules[0].entry, "2000": extra}}})
        group = plan_template_acl_deletions(rules, [existing], {"test2": ["acls"]}, {})["groups"][0]
        self.assertFalse(group["eligible"])
        self.assertIn("differs from the complete CSV definition", group["errors"][0])
        self.assertIn("web-acl", group["candidate_acl_value"]["data"])

    def test_parse_merge_overwrites_whole_priority_and_preserves_omitted_rules(self):
        fixture = TempCsv(ACL_HEADERS, [
            self.row(ApplicationGroup="Accounting"),
            self.row(Priority="2000", Protocol="tcp", EitherPort="443"),
        ])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        existing = acl_group("test2", {"web-acl": {"entry": {
            "1000": {"permit": True, "protocol": "udp", "either_port": "53", "comment": "old"},
            "3000": {"permit": False, "comment": "preserve"},
        }}})
        plan = plan_template_acls(rules, [existing], {"test2": ["acls"]}, {"0.NE": ["test2"]}, {"Accounting"}, set())
        group = plan["groups"][0]
        entries = group["candidate_acl_value"]["data"]["web-acl"]["entry"]
        self.assertEqual(entries["1000"], {"permit": True, "comment": "", "app_group": "Accounting"})
        self.assertEqual(entries["2000"]["additionalSwitch_port"], "ports")
        self.assertEqual(entries["3000"]["comment"], "preserve")
        self.assertEqual([item["priority"] for item in group["overwrites"]], ["1000"])
        self.assertEqual([item["priority"] for item in group["additions"]], ["2000"])

    def test_selected_match_criteria_use_native_directional_and_either_keys(self):
        fixture = TempCsv(ACL_HEADERS, [
            self.row(Priority="1000", Application="0-1"),
            self.row(Priority="1010", ApplicationGroup="Accounting"),
            self.row(Priority="1020", SourceIP="1.1.1.1-255/32", DestinationIP="10.10.10.1/24", DestinationPort="20-30"),
            self.row(Priority="1030", SourceDomain="*youtube.com", DestinationDomain="*google.com", Protocol="icmp"),
            self.row(Priority="1040", EitherIP="192.0.2.0/24", EitherPort="443", EitherDomain="*.example.com", Protocol="tcp"),
        ])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        entries = {rule.priority: rule.entry for rule in rules}
        self.assertEqual(entries["1020"]["additionalSwitch_ip"], "ips")
        self.assertEqual(entries["1020"]["src_ip"], "1.1.1.1-255/32")
        self.assertEqual(entries["1020"]["dst_port"], "20-30")
        self.assertEqual(entries["1030"]["src_dns"], "*youtube.com")
        self.assertEqual(entries["1030"]["dst_dns"], "*google.com")
        self.assertEqual(entries["1040"]["either_ip"], "192.0.2.0/24")
        self.assertEqual(entries["1040"]["either_port"], "443")
        self.assertEqual(entries["1040"]["either_dns"], "*.example.com")
        existing = acl_group("test2", {"web-acl": {"entry": {priority: entries[priority] for priority in ("1000", "1010", "1020", "1030")}}})
        plan = plan_template_acls(rules, [existing], {"test2": ["acls"]}, {}, {"0-1"}, {"Accounting"})
        group = plan["groups"][0]
        self.assertEqual([item["priority"] for item in group["no_ops"]], ["1000", "1010", "1020", "1030"])
        self.assertEqual([item["priority"] for item in group["additions"]], ["1040"])

    def test_parser_rejects_directional_and_either_mix(self):
        fixture = TempCsv(ACL_HEADERS, [self.row(SourceIP="192.0.2.1/32", EitherIP="198.51.100.1/32")])
        try:
            with self.assertRaisesRegex(ValidationError, "EitherIP is mutually exclusive"):
                parse_template_acls(str(fixture.path))
        finally:
            fixture.close()

    def test_parser_rejects_inconsistent_modes_for_same_group_and_acl(self):
        fixture = TempCsv(ACL_HEADERS, [
            self.row(Application="App"),
            self.row(Priority="2000", ACLUpdateMode="REPLACE", Application="App"),
        ])
        try:
            with self.assertRaisesRegex(ValidationError, r"ACL-23.*row 2 uses MERGE/MERGE"):
                parse_template_acls(str(fixture.path))
        finally:
            fixture.close()

    def test_parser_rejects_replace_duplicates_missing_dependencies_and_unacknowledged_broad_rule(self):
        cases = [
            ([self.row(ACLUpdateMode="REPLACE", Application="App")], "MERGE"),
            ([self.row(Application="App"), self.row(Application="App")], "duplicate"),
            ([self.row(Application="Missing")], "missing application"),
            ([self.row()], "BroadMatchAck"),
        ]
        for rows, message in cases:
            with self.subTest(message=message):
                fixture = TempCsv(ACL_HEADERS, rows)
                try:
                    rules = parse_template_acls(str(fixture.path))
                    if message == "missing application":
                        plan = plan_template_acls(rules, [acl_group("test2")], {"test2": ["acls"]}, {}, set(), set())
                        self.assertIn(message, " ".join(plan["groups"][0]["errors"]))
                    else:
                        self.fail("expected parser failure")
                except ValidationError as error:
                    self.assertIn(message, str(error))
                finally:
                    fixture.close()

    def test_missing_group_builds_unassociated_merge_candidate(self):
        fixture = TempCsv(ACL_HEADERS, [self.row(TemplateGroup="new-group", ACLName="catch-all", BroadMatchAck="TRUE")])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        plan = plan_template_acls(rules, [acl_group("Default Template Group")], {"Default Template Group": []}, {"0.NE": ["Default Template Group"]}, set(), set())
        group = plan["groups"][0]
        self.assertTrue(group["create"])
        self.assertEqual(group["associations"], [])
        self.assertTrue(group["candidate_acl_value"]["options"]["merge"])
        self.assertEqual(group["candidate_acl_value"]["data"]["catch-all"]["entry"]["1000"], {"permit": True, "comment": ""})

    def test_conflicting_same_priority_on_shared_appliance_blocks_group(self):
        target = acl_group("target", {"shared": {"entry": {}}})
        other = acl_group("other", {"shared": {"entry": {"1000": {"permit": False, "comment": ""}}}})
        fixture = TempCsv(ACL_HEADERS, [self.row(TemplateGroup="target", ACLName="shared", BroadMatchAck="TRUE")])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        plan = plan_template_acls(rules, [target, other], {"target": ["acls"], "other": ["acls"]}, {"0.NE": ["target", "other"]}, set(), set())
        self.assertFalse(plan["groups"][0]["eligible"])
        self.assertIn("conflicting priority 1000", " ".join(plan["groups"][0]["errors"]))

    def parse(self, rows, headers=ACL_HEADERS):
        fixture = TempCsv(headers, rows)
        try:
            return parse_template_acls(str(fixture.path))
        finally:
            fixture.close()

    def test_group_and_segment_columns_reproduce_gui_created_entries(self):
        gui = {
            "1040": {"additionalSwitch_ip": "groups", "comment": "", "either_addrgrp_groups": "allowed-hosts", "permit": True},
            "1050": {"additionalSwitch_ip": "ips", "comment": "", "dst_additionalSwitch_ip": "groups", "dst_addrgrp_groups": "servers-b", "dst_vrf": 0, "either_vrf": 0, "permit": False, "src_additionalSwitch_ip": "groups", "src_addrgrp_groups": "servers-a", "src_vrf": 0},
            "1080": {"additionalSwitch_port": "ports", "comment": "", "dst_port": "80", "permit": False, "src_additionalSwitch_port": "groups", "src_srvcgrp_groups": "web-services"},
            "1090": {"additionalSwitch_ip": "ips", "additionalSwitch_port": "ports", "comment": "", "dst_additionalSwitch_ip": "groups", "dst_additionalSwitch_port": "groups", "dst_addrgrp_groups": "isp-hosts", "dst_srvcgrp_groups": "web-services", "permit": True, "src_ip": "1.1.1.1/32", "src_port": "2-30"},
            "1110": {"additionalSwitch_port": "groups", "comment": "", "either_srvcgrp_groups": "web-services", "permit": False},
            "1120": {"additionalSwitch_ip": "groups", "additionalSwitch_port": "ports", "comment": "", "dst_port": "80", "either_addrgrp_groups": "servers-a", "either_vrf": 1, "permit": False, "src_additionalSwitch_port": "groups", "src_srvcgrp_groups": "web-services", "src_vrf": 1},
            "1130": {"additionalSwitch_port": "ports", "comment": "", "dst_vrf": 2, "either_port": "20-35", "permit": True, "src_vrf": 0},
        }
        rules = self.parse([
            self.row(Priority="1040", EitherAddressGroup="allowed-hosts"),
            self.row(Priority="1050", Permit="FALSE", SourceAddressGroup="servers-a", DestinationAddressGroup="servers-b", SourceSegment="Default", DestinationSegment="Default", EitherSegment="Default"),
            self.row(Priority="1080", Permit="FALSE", SourceServiceGroup="web-services", DestinationPort="80"),
            self.row(Priority="1090", SourceIP="1.1.1.1/32", SourcePort="2-30", DestinationAddressGroup="isp-hosts", DestinationServiceGroup="web-services"),
            self.row(Priority="1110", Permit="FALSE", EitherServiceGroup="web-services"),
            self.row(Priority="1120", Permit="FALSE", EitherAddressGroup="servers-a", SourceServiceGroup="web-services", DestinationPort="80", EitherSegment="TEST5", SourceSegment="TEST5"),
            self.row(Priority="1130", EitherPort="20-35", SourceSegment="Default", DestinationSegment="TEST6"),
        ])
        plan = plan_template_acls(rules, [acl_group("test2")], {"test2": ["acls"]}, {}, set(), set(), {"allowed-hosts", "servers-a", "servers-b", "isp-hosts"}, {"web-services"}, {"Default": 0, "TEST5": 1, "TEST6": 2})
        group = plan["groups"][0]
        self.assertTrue(group["eligible"], group["errors"])
        self.assertEqual(group["candidate_acl_value"]["data"]["web-acl"]["entry"], gui)
        self.assertEqual(plan["address_group_dependencies"], ["allowed-hosts", "isp-hosts", "servers-a", "servers-b"])
        self.assertEqual(plan["segment_dependencies"], ["Default", "TEST5", "TEST6"])
        appliance = {priority: dict(entry, gms_marked=False, self=int(priority), **{key: str(value) for key, value in entry.items() if key.endswith("_vrf")}) for priority, entry in gui.items()}
        rerun = plan_template_acls(rules, [acl_group("test2", {"web-acl": {"entry": appliance}})], {"test2": ["acls"]}, {}, set(), set(), {"allowed-hosts", "servers-a", "servers-b", "isp-hosts"}, {"web-services"}, {"Default": 0, "TEST5": 1, "TEST6": 2})
        self.assertEqual(len(rerun["groups"][0]["no_ops"]), 7)

    def test_group_columns_reject_unverified_and_unsafe_shapes(self):
        cases = [
            (dict(SourceIP="10.0.0.1", SourceAddressGroup="servers-a"), "ACL-24"),
            (dict(EitherPort="80", EitherServiceGroup="web"), "ACL-24"),
            (dict(EitherAddressGroup="servers-a", SourceAddressGroup="servers-b"), "DIR-01"),
            (dict(EitherAddressGroup="servers-a", DestinationIP="10.0.0.1"), "DIR-01"),
            (dict(EitherIP="10.0.0.1", SourceAddressGroup="servers-a"), "DIR-01"),
            (dict(EitherServiceGroup="web", SourcePort="80"), "DIR-01"),
            (dict(SourceAddressGroup="servers-a,servers-b"), "VAL-02"),
            (dict(SourceAddressGroup="servers-a|servers-a"), "VAL-03"),
            (dict(SourceAddressGroup="bad name"), "ACL-26"),
            (dict(SourceAddressGroup="servers-a", SourceSegment="Default|TEST5"), "ACL-27"),
        ]
        for values, code in cases:
            with self.subTest(values=values):
                with self.assertRaisesRegex(ValidationError, code):
                    self.parse([self.row(**values)])

    def test_group_lists_are_normalized_and_legacy_headers_still_parse(self):
        rule = self.parse([self.row(SourceAddressGroup=" servers-a | servers-b ", DestinationServiceGroup="web")])[0]
        self.assertEqual(rule.entry["src_addrgrp_groups"], "servers-a|servers-b")
        self.assertEqual(rule.entry["additionalSwitch_port"], "ports")
        legacy = {key: value for key, value in self.row(Application="App").items() if key in ACL_HEADERS_LEGACY}
        self.assertEqual(self.parse([legacy], ACL_HEADERS_LEGACY)[0].entry, {"permit": True, "comment": "", "application": "App"})

    def test_group_and_segment_dependencies_block_plan(self):
        rules = self.parse([self.row(SourceAddressGroup="servers-a|gone", DestinationServiceGroup="web", SourceSegment="Nope")])
        plan = plan_template_acls(rules, [acl_group("test2")], {"test2": ["acls"]}, {}, set(), set(), {"servers-a"}, set(), {"Default": 0})
        errors = " ".join(plan["groups"][0]["errors"])
        self.assertFalse(plan["groups"][0]["eligible"])
        for text in ("missing address group gone", "missing service group web", "unknown segment Nope"):
            self.assertIn(text, errors)
        self.assertFalse(plan_template_acls(rules, [acl_group("test2")], {"test2": ["acls"]}, {}, set(), set())["groups"][0]["eligible"])

    def test_application_group_any_needs_no_dependency(self):
        rules = self.parse([self.row(ApplicationGroup="any")])
        plan = plan_template_acls(rules, [acl_group("test2")], {"test2": ["acls"]}, {}, set(), set())
        self.assertTrue(plan["groups"][0]["eligible"], plan["groups"][0]["errors"])
        self.assertEqual(plan["application_group_dependencies"], [])

    def test_replace_mode_security_policies_template_is_guarded(self):
        rules = self.parse([self.row(Application="App")])
        group = acl_group("test2")
        group["templates"].append({"name": "securityMaps", "value": {"data": {"map1": {}}, "options": {"merge": False}}})
        plan = plan_template_acls(rules, [group], {"test2": ["acls", "securityMaps"]}, {}, {"App"}, set())
        self.assertFalse(plan["groups"][0]["eligible"])
        self.assertIn("ACL-25", " ".join(plan["groups"][0]["errors"]))
        group["templates"][-1]["value"]["data"]["map1"]["1_2"] = {"prio": {"1000": {"match": {}, "set": {"action": "allow"}}}}
        plan = plan_template_acls(rules, [group], {"test2": ["acls", "securityMaps"]}, {}, {"App"}, set())
        self.assertTrue(plan["groups"][0]["eligible"])
        self.assertIn("ACL-25", " ".join(plan["groups"][0]["warnings"]))
        self.assertTrue(plan_template_acls(rules, [group], {"test2": ["acls"]}, {}, {"App"}, set())["groups"][0]["eligible"])


class TemplateAclApplyGateway:
    def __init__(self, groups, selections, associations):
        self.groups = {group["name"]: copy.deepcopy(group) for group in groups}
        self.selections = copy.deepcopy(selections)
        self.associations = copy.deepcopy(associations)
        self.appliance_acls = {}
        self.posts = []

    def get_template_groups(self):
        return list(copy.deepcopy(self.groups).values())

    def get_template_group(self, name):
        return copy.deepcopy(self.groups.get(name))

    def get_template_selection(self, name):
        return copy.deepcopy(self.selections.get(name, []))

    def get_template_associations(self):
        return copy.deepcopy(self.associations)

    def post_template_group(self, name, value):
        self.posts.append(("update", name))
        group = self.groups[name]
        template = next(item for item in group["templates"] if item["name"] == "acls")
        template["value"] = copy.deepcopy(value["templates"][0]["valObject"])

    def create_template_group(self, value):
        self.posts.append(("create", value["name"]))
        self.groups[value["name"]] = {"name": value["name"], "selectedTemplateNames": [], "templates": [{"name": "acls", "value": copy.deepcopy(value["templates"][0]["valObject"])}]}
        self.selections[value["name"]] = []

    def select_template_group(self, name, templates):
        self.posts.append(("select", name))
        self.selections[name] = list(templates)
        self.groups[name]["selectedTemplateNames"] = list(templates)

    def get_appliances(self):
        return [{"nePk": target, "state": 1} for target in self.associations]

    def get_reachability(self, target):
        return {"state": 1}

    def get_appliance_acls(self, target):
        return copy.deepcopy(self.appliance_acls.get(target, {}))

    def get_actions(self, start, end):
        return []


class TemplateAclApplyTests(unittest.TestCase):
    def test_existing_group_update_and_new_group_creation_verify_without_association(self):
        existing = acl_group("test2", {"web": {"entry": {"1000": {"permit": True, "comment": ""}}}})
        rows = []
        for group, acl, priority in (("test2", "web", "2000"), ("new-group", "new", "1000")):
            rows.append({"TemplateGroup": group, "ACLName": acl, "ACLUpdateMode": "MERGE", "TemplateApplyMode": "MERGE", "Priority": priority, "Permit": "TRUE", "Application": "", "ApplicationGroup": "", "Protocol": "", "EitherPort": "", "Comment": "", "BroadMatchAck": "TRUE"})
        fixture = TempCsv(ACL_HEADERS, rows)
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        default = acl_group("Default Template Group")
        plan = plan_template_acls(rules, [default, existing], {"Default Template Group": [], "test2": ["acls"]}, {}, set(), set())
        gateway = TemplateAclApplyGateway([default, existing], {"Default Template Group": [], "test2": ["acls"]}, {})
        result = apply_template_acls(gateway, plan)
        self.assertEqual(result["status"], "success")
        self.assertEqual(gateway.posts, [("update", "test2"), ("create", "new-group"), ("select", "new-group")])
        self.assertEqual(gateway.associations, {})

    def test_create_race_aborts_before_write(self):
        default = acl_group("Default Template Group")
        fixture = TempCsv(ACL_HEADERS, [{"TemplateGroup": "new-group", "ACLName": "new", "ACLUpdateMode": "MERGE", "TemplateApplyMode": "MERGE", "Priority": "1000", "Permit": "TRUE", "Application": "", "ApplicationGroup": "", "Protocol": "", "EitherPort": "", "Comment": "", "BroadMatchAck": "TRUE"}])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        plan = plan_template_acls(rules, [default], {"Default Template Group": []}, {}, set(), set())
        gateway = TemplateAclApplyGateway([default, acl_group("new-group")], {"Default Template Group": [], "new-group": []}, {})
        with self.assertRaisesRegex(DriftError, "changed before write"):
            apply_template_acls(gateway, plan)
        self.assertEqual(gateway.posts, [])

    def test_associated_appliance_exact_acl_is_verified(self):
        existing = acl_group("test2", {"web": {"entry": {}}})
        fixture = TempCsv(ACL_HEADERS, [{"TemplateGroup": "test2", "ACLName": "web", "ACLUpdateMode": "MERGE", "TemplateApplyMode": "MERGE", "Priority": "1000", "Permit": "TRUE", "Application": "", "ApplicationGroup": "", "Protocol": "", "EitherPort": "", "Comment": "", "BroadMatchAck": "TRUE"}])
        try:
            rules = parse_template_acls(str(fixture.path))
        finally:
            fixture.close()
        associations = {"0.NE": ["test2"]}
        plan = plan_template_acls(rules, [existing], {"test2": ["acls"]}, associations, set(), set())
        gateway = TemplateAclApplyGateway([existing], {"test2": ["acls"]}, associations)
        gateway.appliance_acls["0.NE"] = {"web": {"1000": {"permit": True, "comment": ""}}}
        result = apply_template_acls(gateway, plan)
        self.assertEqual(result["groups"][0]["targets"], {"0.NE": "verified"})
        self.assertEqual(result["status"], "success")


class RepositoryTemplateTests(unittest.TestCase):
    def test_current_templates_validate(self):
        root = Path(__file__).resolve().parents[1] / "templates" / "edgeconnect"
        addresses = parse_address_groups(str(root / "address_groups.csv"))
        services = parse_service_groups(str(root / "service_groups.csv"))
        definitions = parse_application_definitions(str(root / "application_definitions.csv"))
        groups = parse_application_groups(str(root / "application_groups.csv"))
        acls = parse_template_acls(str(root / "template_acls.csv"))
        firewall = parse_firewall_csv(str(root / "firewall_rules.csv"))
        self.assertEqual((len(addresses), len(services), len(definitions), len(groups), len(acls), len(firewall)), (4, 5, 8, 3, 9, 9))
        address_names = {row["Name"] for row in addresses}
        service_names = {row["Name"] for row in services}
        application_names = {item.name for item in definitions}
        group_names = {row["Name"] for row in groups}
        for rule in firewall:
            self.assertTrue(set(filter(None, (rule.source_address_group, rule.destination_address_group, rule.either_address_group))) <= address_names)
            self.assertTrue(set(filter(None, (rule.source_service_group, rule.destination_service_group, rule.either_service_group))) <= service_names)
            self.assertTrue(not rule.application or rule.application in application_names)
            self.assertTrue(not rule.application_group or rule.application_group == "any" or rule.application_group in group_names)
        for rule in acls:
            self.assertTrue(not rule.entry.get("application") or rule.entry["application"] in application_names)
            self.assertTrue(not rule.entry.get("app_group") or rule.entry["app_group"] in group_names)
            self.assertTrue({name for key in ("src_addrgrp_groups", "dst_addrgrp_groups", "either_addrgrp_groups") for name in rule.entry.get(key, "").split("|") if name} <= address_names)
            self.assertTrue({name for key in ("src_srvcgrp_groups", "dst_srvcgrp_groups", "either_srvcgrp_groups") for name in rule.entry.get(key, "").split("|") if name} <= service_names)

    def test_published_valid_and_mixed_examples(self):
        root = Path(__file__).resolve().parents[1] / "examples" / "edgeconnect"
        parsers = {
            "address_groups": parse_address_groups,
            "service_groups": parse_service_groups,
            "application_definitions": parse_application_definitions,
            "application_groups": parse_application_groups,
            "template_acls": parse_template_acls,
            "firewall_rules": parse_firewall_csv,
        }
        parsed = {}
        for name, parser in parsers.items():
            with self.subTest(name=name, kind="valid"):
                parsed[name] = parser(str(root / "{}_valid.csv".format(name)))
            with self.subTest(name=name, kind="mixed"):
                with self.assertRaises(ValidationError):
                    parser(str(root / "{}_mixed.csv".format(name)))
        self.assertEqual(tuple(len(parsed[name]) for name in parsers), (27, 31, 48, 11, 15, 54))
        address_names = {row["Name"] for row in parsed["address_groups"]}
        service_names = {row["Name"] for row in parsed["service_groups"]}
        application_names = {item.name for item in parsed["application_definitions"]}
        group_names = {row["Name"] for row in parsed["application_groups"]}
        for rule in parsed["firewall_rules"]:
            self.assertTrue(set(filter(None, (rule.source_address_group, rule.destination_address_group, rule.either_address_group))) <= address_names)
            self.assertTrue(set(filter(None, (rule.source_service_group, rule.destination_service_group, rule.either_service_group))) <= service_names)
            self.assertTrue(not rule.application or rule.application in application_names)
            self.assertTrue(not rule.application_group or rule.application_group == "any" or rule.application_group in group_names)
        empty = {"portProtocolClassification": {}, "dnsClassification": [], "compoundClassification": {}}
        self.assertEqual(plan_application_definitions(parsed["application_definitions"], empty).conflicts, [])
        self.assertEqual(plan_native_groups("address", parsed["address_groups"], []).conflicts, [])
        self.assertEqual(plan_native_groups("service", parsed["service_groups"], []).conflicts, [])
        self.assertEqual(plan_application_groups(parsed["application_groups"], {}, application_names)["skipped_conflicts"], [])
        for rule in parsed["template_acls"]:
            self.assertTrue(not rule.entry.get("application") or rule.entry["application"] in application_names)
            self.assertTrue(not rule.entry.get("app_group") or rule.entry["app_group"] in group_names)
            self.assertTrue({name for key in ("src_addrgrp_groups", "dst_addrgrp_groups", "either_addrgrp_groups") for name in rule.entry.get(key, "").split("|") if name} <= address_names)
            self.assertTrue({name for key in ("src_srvcgrp_groups", "dst_srvcgrp_groups", "either_srvcgrp_groups") for name in rule.entry.get(key, "").split("|") if name} <= service_names)


class Test3AclExampleTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1] / "examples" / "edgeconnect"

    def test_test3_valid_file_plans_against_the_example_dependencies(self):
        rules = parse_template_acls(str(self.ROOT / "template_acls_test3_valid.csv"))
        self.assertGreaterEqual(len(rules), 50)
        self.assertEqual({rule.template_group for rule in rules}, {"test3"})
        addresses = {row["Name"] for row in parse_address_groups(str(self.ROOT / "address_groups_valid.csv"))}
        services = {row["Name"] for row in parse_service_groups(str(self.ROOT / "service_groups_valid.csv"))}
        applications = {item.name for item in parse_application_definitions(str(self.ROOT / "application_definitions_valid.csv"))}
        groups = {row["Name"] for row in parse_application_groups(str(self.ROOT / "application_groups_valid.csv"))}
        plan = plan_template_acls(rules, [acl_group("test3")], {"test3": ["acls"]}, {}, applications, groups, addresses, services, {"Default": 0, "TEST5": 1, "TEST6": 2})
        self.assertTrue(plan["groups"][0]["eligible"], plan["groups"][0]["errors"])
        self.assertEqual(len(plan["groups"][0]["additions"]), len(rules))

    def test_test3_invalid_file_reports_the_expected_rule_for_every_row(self):
        with open(self.ROOT / "template_acls_test3_invalid.csv", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        with self.assertRaises(ValidationError) as caught:
            parse_template_acls(str(self.ROOT / "template_acls_test3_invalid.csv"))
        found = {}
        for issue in caught.exception.issues:
            found.setdefault(issue["row"], set()).add(issue["rule"])
        self.assertGreaterEqual(len(rows), 30)
        for number, row in enumerate(rows, 2):
            expected = row["Comment"].split()[1].rstrip(":")
            self.assertIn(expected, found.get(number, set()), row["Comment"])


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
        dotted = self._row("DOMAIN", "good.name")
        dotted["Domain"] = "example.com"
        fixture = TempCsv(APP_DEF_HEADERS, [dotted])
        try:
            self.assertEqual(parse_application_definitions(str(fixture.path))[0].name, "good.name")
        finally:
            fixture.close()
        bad_name = self._row("COMPOUND", "bad.name")
        bad_name.update({"Protocol": "ip", "SourcePort": "80"})
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
