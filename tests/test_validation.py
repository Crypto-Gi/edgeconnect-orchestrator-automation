import copy
import csv
import io
import itertools
import unittest
from pathlib import Path
from unittest.mock import patch

from edgeconnect_automation.cli import DELETE_ACKNOWLEDGMENT, main
from edgeconnect_automation.errors import ValidationError
from edgeconnect_automation.firewall import FIREWALL_HEADERS, build_firewall_plan, parse_firewall_document, parse_firewall_text, rule_payload
from edgeconnect_automation.models import Inventory
from edgeconnect_automation.validation import policy_ip, valid_domain
from edgeconnect_automation.workflows import ACL_HEADERS, ADDRESS_HEADERS, APP_DEF_HEADERS, SERVICE_HEADERS, parse_address_groups, parse_application_definitions, parse_application_groups_partial, parse_service_groups, parse_template_acls, plan_appexpress_modes, plan_application_groups, plan_native_groups, resolve_compound_references

from tests.test_workflows import TempCsv

FIREWALL_COLUMNS = sorted(FIREWALL_HEADERS)
COMBINATIONS = [
    ((), True), (("source",), True), (("destination",), True), (("source", "destination"), True), (("either",), True),
    (("either", "source"), False), (("either", "destination"), False), (("either", "source", "destination"), False),
]


def firewall_csv(**values):
    row = {name: "" for name in FIREWALL_COLUMNS}
    row.update(rule_key="r1", source_segment="A", destination_segment="B", source_zone="ZA", destination_zone="ZB", action="allow", priority="100", protocol="tcp", destination_port="443")
    row.update(values)
    stream = io.StringIO()
    writer = csv.DictWriter(stream, FIREWALL_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
    return stream.getvalue()


def parse_one(**values):
    return parse_firewall_text(firewall_csv(**values))[0]


def acl_row(**values):
    row = {header: "" for header in ACL_HEADERS}
    row.update({"TemplateGroup": "g", "ACLName": "acl", "ACLUpdateMode": "MERGE", "TemplateApplyMode": "MERGE", "Priority": "1000", "Permit": "TRUE", "BroadMatchAck": "FALSE", "Protocol": "tcp", "EitherPort": "443"})
    row.update(values)
    return row


def parse_csv(parser, headers, rows):
    fixture = TempCsv(headers, rows)
    try:
        return parser(str(fixture.path))
    finally:
        fixture.close()


def app_row(definition_type="COMPOUND", name="cmp", **values):
    row = {header: "" for header in APP_DEF_HEADERS}
    row.update({"DefinitionType": definition_type, "Name": name, "Enabled": "TRUE", "Confidence": "100", "AppExpressMode": "OFF"})
    row.update(values)
    return row


def address(name="ag", **values):
    row = {header: "" for header in ADDRESS_HEADERS}
    row.update(Name=name, IncludedIPs="10.0.0.0/24")
    row.update(values)
    return row


def service(name="sg", **values):
    row = {header: "" for header in SERVICE_HEADERS}
    row.update(Name=name, Protocol="TCP", IncludedPorts="443")
    row.update(values)
    return row


class DirectionalFamilyTests(unittest.TestCase):
    def assert_matrix(self, families, sample, build):
        for (source, destination, either), (combo, valid) in itertools.product(families, COMBINATIONS):
            values = {{"source": source, "destination": destination, "either": either}[part]: sample[source] for part in combo}
            with self.subTest(family=either, combo=combo):
                if valid:
                    build(values)
                else:
                    with self.assertRaisesRegex(ValidationError, "{} is mutually exclusive".format(either)):
                        build(values)

    def test_firewall_every_family(self):
        families = [
            ("source_address", "destination_address", "either_address"),
            ("source_address_group", "destination_address_group", "either_address_group"),
            ("source_port", "destination_port", "either_port"),
            ("source_service_group", "destination_service_group", "either_service_group"),
            ("source_domain", "destination_domain", "either_domain"),
        ]
        sample = {"source_address": "10.0.0.1", "source_address_group": "ag", "source_port": "80", "source_service_group": "sg", "source_domain": "*.example.com"}
        self.assert_matrix(families, sample, lambda values: parse_one(**dict({"destination_port": "", "broad_match_ack": "FALSE" if values else "TRUE"}, **values)))

    def test_template_acl_every_family(self):
        families = [("SourceIP", "DestinationIP", "EitherIP"), ("SourcePort", "DestinationPort", "EitherPort"), ("SourceDomain", "DestinationDomain", "EitherDomain")]
        sample = {"SourceIP": "10.0.0.1", "SourcePort": "80", "SourceDomain": "example.com"}
        self.assert_matrix(families, sample, lambda values: parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(**dict({"EitherPort": "", "BroadMatchAck": "TRUE"}, **values))]))

    def test_compound_every_family(self):
        families = [
            ("SourcePort", "DestinationPort", "EitherPort"), ("SourceIP", "DestinationIP", "EitherIP"), ("SourceGeo", "DestinationGeo", "EitherGeo"),
            ("SourceDomain", "DestinationDomain", "EitherDomain"), ("SourceAddressMap", "DestinationAddressMap", "EitherAddressMap"),
        ]
        sample = {"SourcePort": "80", "SourceIP": "10.0.0.1", "SourceGeo": "US", "SourceDomain": "example.com", "SourceAddressMap": "Salesforce"}
        self.assert_matrix(families, sample, lambda values: parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row(Protocol="ip", DSCP="ef", **values)]))

    def test_cross_family_mixed_direction_is_allowed(self):
        rule = parse_one(destination_address="10.0.0.1", either_address_group="ag", destination_port="", source_port="80", either_service_group="sg")
        self.assertEqual(rule_payload(rule)["match"]["either_addrgrp_groups"], "ag")


class ValueFormatTests(unittest.TestCase):
    def test_policy_ip_formats(self):
        accepted = {
            "10.1.1.1": None, "10.0.0.0/24": None, "0.0.0.0/0": None, "10.0.0.0/255.255.0.0": None,
            "10.10.10.10-20": None, "10.10.10.*": None, "10.136-137.*.64-95": None,
            "2001:db8::/32": None, "2001:db8:*:*:*:*:*:*": None, "2001:db8:0:0:0:0:0:1-ff": None,
        }
        for value, warning in accepted.items():
            with self.subTest(value=value):
                self.assertEqual(policy_ip(value), warning)
        for value in ("10.0.0.5/24", "2001:db8::1/32"):
            self.assertIn("host bits", policy_ip(value))
        for value in ("192.168.0.1-127/24", "10.10-20.0.0/16"):
            self.assertIn("compatibility", policy_ip(value))
        for value in ("10.13*.*.64-95", "10.0.0.20-10", "999.1.1.1", "10.0.0.0/33", "10.0.0.0/255.0.255.0", "10.0.*", "2001:db8:*", "2001:db8::zz"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy_ip(value)

    def test_firewall_accepts_documented_ranges_and_warns_on_host_bits(self):
        document = parse_firewall_document(firewall_csv(source_address="10.136-137.*.64-95|10.0.0.5/24", protocol="tcp/udp"))
        self.assertFalse(document.errors)
        self.assertIn("FW-12", " ".join(document.warnings))
        plan = build_firewall_plan(document.rules, Inventory({"A": 1, "B": 2}, {("A", "ZA"): 1, ("B", "ZB"): 2}, {("A", "B"): {"data": {"map1": {}}}}), pair_warnings=document.pair_warnings)
        self.assertIn("host bits", " ".join(plan.pairs[0].warnings))

    def test_domain_formats(self):
        for value in ("example.com", "*.example.com", "*example.com", "a-b_c.example.org", "localhost"):
            self.assertTrue(valid_domain(value), value)
        for value in ("ex*ample.com", ".example.com", "example.com.", "a..b", "*", "*gamma*", "https://example.com/path", "a" * 64 + ".com"):
            self.assertFalse(valid_domain(value), value)

    def test_list_hygiene(self):
        cases = {"source_port": ("80|80", "VAL-03"), "destination_port": ("80||443", "VAL-04"), "source_address": ("10.0.0.1,10.0.0.2", "VAL-02")}
        for field, (value, rule) in cases.items():
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, rule):
                parse_one(**{field: value, "destination_port": "" if field != "destination_port" else value})

    def test_protocol_vocabulary_and_port_compatibility(self):
        for protocol in ("", "tcp", "udp", "tcp/udp", "6", "17"):
            self.assertEqual(parse_one(protocol=protocol).destination_port, "443")
        for protocol in ("ip", "icmp", "1"):
            with self.subTest(protocol=protocol), self.assertRaisesRegex(ValidationError, "FW-06"):
                parse_one(protocol=protocol)
        with self.assertRaisesRegex(ValidationError, "VAL-06"):
            parse_one(protocol="gre", destination_port="")
        self.assertEqual(parse_one(protocol="47", destination_port="", source_address="10.0.0.1").protocol, "47")


class FirewallRuleTests(unittest.TestCase):
    def test_all_errors_on_a_row_are_reported_with_structure(self):
        document = parse_firewall_document(firewall_csv(action="drop", priority="70000", either_port="80", source_port="81", logging="FALSE", logging_level="3", application="any"))
        messages = " ".join(document.errors)
        for rule in ("FW-03", "FW-20", "DIR-01", "FW-19", "FW-18"):
            self.assertIn(rule, messages)
        issue = next(item for item in document.issues if item["rule"] == "FW-18")
        self.assertEqual(issue["field"], "application")
        self.assertIn("application_group=any", issue["fix"])
        self.assertEqual(issue["blocks"], "segment pair A -> B")

    def test_logging_level_rules(self):
        self.assertEqual(parse_one(logging="FALSE", logging_level="0").logging_level, 0)
        self.assertEqual(parse_one(logging="TRUE").logging_level, 2)
        with self.assertRaisesRegex(ValidationError, "requires logging=TRUE"):
            parse_one(logging="FALSE", logging_level="4")

    def test_redundant_broad_ack_warns(self):
        document = parse_firewall_document(firewall_csv(broad_match_ack="TRUE"))
        self.assertFalse(document.errors)
        self.assertIn("FW-05", " ".join(document.warnings))

    def test_domain_columns_map_to_native_keys_and_are_acl_exclusive(self):
        rule = parse_one(either_domain="*nametests.com", destination_port="", protocol="")
        self.assertEqual(rule_payload(rule)["match"], {"either_dns": "*nametests.com"})
        with self.assertRaisesRegex(ValidationError, "acl is mutually exclusive"):
            parse_one(acl="acl1", source_domain="example.com", destination_port="", protocol="")

    def test_application_dependencies_are_case_insensitive(self):
        rule = parse_one(application="Teams-Video")
        inventory = Inventory({"A": 1, "B": 2}, {("A", "ZA"): 1, ("B", "ZB"): 2}, {("A", "B"): {"data": {"map1": {}}}}, applications={"teams-video"})
        self.assertTrue(build_firewall_plan([rule], inventory).pairs[0].eligible)

    def test_short_row_and_control_characters(self):
        text = firewall_csv()
        short = text.rsplit(",", 1)[0] + "\n"
        with self.assertRaisesRegex(ValidationError, "CSV-06"):
            parse_firewall_text(short)
        with self.assertRaisesRegex(ValidationError, "CSV-10"):
            parse_one(description="bad\x01text")


class TemplateAclTests(unittest.TestCase):
    def test_priority_bounds_and_explicit_permit(self):
        self.assertEqual(parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(Priority="65535")])[0].priority, "65535")
        for priority in ("0", "65536", "x"):
            with self.subTest(priority=priority), self.assertRaisesRegex(ValidationError, "ACL-09"):
                parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(Priority=priority)])
        with self.assertRaisesRegex(ValidationError, "Permit must be"):
            parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(Permit="")])

    def test_ports_protocol_and_ip_formats(self):
        rules = parse_csv(parse_template_acls, ACL_HEADERS, [
            acl_row(Priority="10", Protocol="tcp/udp"),
            acl_row(Priority="20", Protocol="", DestinationPort="20-30", EitherPort=""),
            acl_row(Priority="30", EitherPort="", Protocol="", SourceIP="10.0.0.0/255.255.0.0|2001:db8::/32"),
            acl_row(Priority="40", EitherPort="", Protocol="", SourceIP="192.168.0.1-127/24"),
        ])
        self.assertEqual(rules[0].entry["protocol"], "tcp/udp")
        self.assertIn("compatibility", " ".join(rules[3].warnings))
        with self.assertRaisesRegex(ValidationError, "ACL-03"):
            parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(Protocol="ip")])
        with self.assertRaisesRegex(ValidationError, "VAL-09"):
            parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(EitherPort="", EitherDomain="ex*ample.com")])

    def test_errors_from_several_rows_are_collected(self):
        with self.assertRaises(ValidationError) as caught:
            parse_csv(parse_template_acls, ACL_HEADERS, [acl_row(Priority="0"), acl_row(Priority="20", Permit="maybe")])
        self.assertEqual([issue["row"] for issue in caught.exception.issues], [2, 3])


class NativeGroupTests(unittest.TestCase):
    def test_name_length_limit(self):
        self.assertEqual(len(parse_csv(parse_address_groups, ADDRESS_HEADERS, [address("a" * 64)])), 1)
        with self.assertRaisesRegex(ValidationError, "AG-01"):
            parse_csv(parse_address_groups, ADDRESS_HEADERS, [address("a" * 65)])
        with self.assertRaisesRegex(ValidationError, "AG-01"):
            parse_csv(parse_service_groups, SERVICE_HEADERS, [service("s" * 65)])

    def test_address_include_required_and_overlap(self):
        with self.assertRaisesRegex(ValidationError, "AG-05"):
            parse_csv(parse_address_groups, ADDRESS_HEADERS, [address(IncludedIPs="", ExcludedIPs="10.0.0.1")])
        with self.assertRaisesRegex(ValidationError, "AG-07"):
            parse_csv(parse_address_groups, ADDRESS_HEADERS, [address(ExcludedIPs="10.0.0.0/24")])
        self.assertEqual(parse_csv(parse_address_groups, ADDRESS_HEADERS, [address(IncludedIPs="10.10.0-10.1/24")])[0]["IncludedIPs"], "10.10.0-10.1/24")

    def test_icmp_type_ranges_and_codes(self):
        rows = parse_csv(parse_service_groups, SERVICE_HEADERS, [service(Protocol="ICMP", IncludedPorts="", IcmpTypes="1,2,4-8")])
        self.assertEqual(rows[0]["IcmpTypes"], "1,2,4-8")
        with self.assertRaisesRegex(ValidationError, "SG-11"):
            parse_csv(parse_service_groups, SERVICE_HEADERS, [service(Protocol="ICMP", IncludedPorts="", IcmpTypes="4-8", IcmpCodes="0")])
        for value in ("8-4", "256", "a"):
            with self.subTest(value=value), self.assertRaisesRegex(ValidationError, "SG-05"):
                parse_csv(parse_service_groups, SERVICE_HEADERS, [service(Protocol="ICMP", IncludedPorts="", IcmpTypes=value)])

    def test_service_wildcard_and_overlap(self):
        with self.assertRaisesRegex(ValidationError, "SG-04"):
            parse_csv(parse_service_groups, SERVICE_HEADERS, [service(IncludedPorts="*,443")])
        with self.assertRaisesRegex(ValidationError, "SG-07"):
            parse_csv(parse_service_groups, SERVICE_HEADERS, [service(IncludedPorts="443,80", ExcludedPorts="80")])

    def test_existing_group_depth_is_enforced(self):
        existing = [
            {"name": "leaf", "type": "AG", "rules": [{"includedIPs": ["10.0.0.1"], "excludedIPs": [], "includedGroups": [], "comment": None}]},
            {"name": "mid", "type": "AG", "rules": [{"includedIPs": [], "excludedIPs": [], "includedGroups": ["leaf"], "comment": None}]},
        ]
        ok = parse_csv(lambda path: parse_address_groups(path, {"leaf", "mid"}), ADDRESS_HEADERS, [address("top", IncludedIPs="", IncludedGroups="mid")])
        self.assertEqual(plan_native_groups("address", ok, existing).new_rows[0]["Name"], "top")
        existing.append({"name": "top", "type": "AG", "rules": [{"includedIPs": [], "excludedIPs": [], "includedGroups": ["mid"], "comment": None}]})
        deep = parse_csv(lambda path: parse_address_groups(path, {"leaf", "mid", "top"}), ADDRESS_HEADERS, [address("too-deep", IncludedIPs="", IncludedGroups="top")])
        with self.assertRaisesRegex(ValidationError, "depth 2"):
            plan_native_groups("address", deep, existing)

    def test_bulk_plan_warnings(self):
        rows = parse_csv(parse_service_groups, SERVICE_HEADERS, [service(IncludedPorts="1000-2000", ExcludedPorts="1500,3000")])
        warnings = plan_native_groups("service", rows, []).warnings
        self.assertEqual(len(warnings), 1)
        self.assertIn("excluded port 3000", warnings[0])
        with patch("edgeconnect_automation.workflows.SERVICE_GROUP_LIMIT", 10):
            self.assertIn("SG-14", " ".join(plan_native_groups("service", rows, []).warnings))


class CsvStructureTests(unittest.TestCase):
    def test_empty_short_and_control_character_rows(self):
        with self.assertRaisesRegex(ValidationError, "CSV-08"):
            parse_csv(parse_address_groups, ADDRESS_HEADERS, [])
        fixture = TempCsv(ADDRESS_HEADERS, [])
        try:
            with Path(fixture.path).open("a", encoding="utf-8") as handle:
                handle.write("short,10.0.0.1\n")
            with self.assertRaisesRegex(ValidationError, "CSV-06"):
                parse_address_groups(str(fixture.path))
        finally:
            fixture.close()
        with self.assertRaisesRegex(ValidationError, "CSV-10"):
            parse_csv(parse_address_groups, ADDRESS_HEADERS, [address(Comment="line\nbreak")])


class ApplicationTests(unittest.TestCase):
    def test_names_are_case_insensitive_and_type_specific(self):
        with self.assertRaisesRegex(ValidationError, "not case-sensitive"):
            parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row("TCP_PORT", "Web", Port="8080"), app_row("TCP_PORT", "web", Port="8081")])
        same = parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row("TCP_PORT", "web", Port="8080"), app_row("DOMAIN", "web", Domain="web.example.com")])
        self.assertEqual(len(same), 2)

    def test_compound_payload_encoding_and_local_rules(self):
        definition = parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row(Protocol="tcp/udp", DestinationPort="443|8443", EitherIP="10.1.1.0/24|10.2.2.1-20", DSCP="EF", Interface="Data", SourceGeo="United States of America", EitherAddressMap="office365common")])[0]
        self.assertEqual(definition.payload["dst_port"], "443,8443")
        self.assertEqual(definition.payload["either_ip"], "10.1.1.0/24,10.2.2.1-20")
        self.assertEqual(definition.payload["dscp"], "ef")
        cases = [
            (dict(Protocol="icmp", SourcePort="80", DSCP="ef"), "CMP-06"),
            (dict(Protocol="ip", EitherDomain="example.com"), "CMP-03"),
            (dict(Protocol="ip", DSCP="64"), "CMP-07"),
            (dict(Protocol="ip", SourceIP="2001:db8::/32"), "CMP-11"),
            (dict(Protocol="ip", SourceIP="10.*.0.0/16"), "CMP-11"),
            (dict(Protocol="ip", SourceIP="10.0.0.1-20/24"), "CMP-11"),
        ]
        for values, rule in cases:
            with self.subTest(rule=rule, values=values), self.assertRaisesRegex(ValidationError, rule):
                parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row(**values)])
        self.assertEqual(parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row(Protocol="ip", SourcePort="80|81")])[0].payload["src_port"], "80,81")

    def test_compound_reference_resolution(self):
        class Gateway:
            def get_countries(self):
                return {"United States of America": ["1", "0", "United States of America", "US"], "Canada": ["2", "0", "Canada", "CA"]}

            def get_interface_labels(self):
                return {"lan": {"5": {"name": "Data", "active": True}, "9": {"name": "Old", "active": False}}, "wan": {"1": {"name": "MPLS1", "active": True}}}

            def search_address_map(self, name):
                return [{"name": "Office365Common"}] if "office365" in name.lower() else []

        definition = parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row(Protocol="ip", SourceGeo="United States of America|ca", EitherAddressMap="office365common", Interface="data")])[0]
        resolved = resolve_compound_references([definition], Gateway())[0].payload
        self.assertEqual((resolved["src_geo"], resolved["either_service"], resolved["vlan"]), ("US,CA", "Office365Common", "5"))
        bad = parse_csv(parse_application_definitions, APP_DEF_HEADERS, [app_row(Protocol="ip", SourceGeo="Atlantis", EitherAddressMap="Missing", Interface="Old")])[0]
        with self.assertRaises(ValidationError) as caught:
            resolve_compound_references([bad], Gateway())
        self.assertEqual({issue["rule"] for issue in caught.exception.issues}, {"CMP-08", "CMP-09", "CMP-10"})

    def test_appexpress_limit(self):
        current = {"app{}".format(index): {"id": index, "name": "app{}".format(index), "monitor": True, "appExpressEnabled": False} for index in range(50)}
        self.assertFalse(plan_appexpress_modes({"app1": "MONITOR"}, current)["changed"])
        with self.assertRaisesRegex(ValidationError, "AD-08"):
            plan_appexpress_modes({"new": "MONITOR"}, current)

    def test_application_groups_empty_members_and_case(self):
        fixture = TempCsv(["Name", "Applications", "ParentGroups"], [
            {"Name": "empty", "Applications": "", "ParentGroups": ""},
            {"Name": "dup", "Applications": "a,a", "ParentGroups": ""},
            {"Name": "ok", "Applications": "Teams-Video", "ParentGroups": ""},
        ])
        try:
            rows, skipped = parse_application_groups_partial(str(fixture.path))
        finally:
            fixture.close()
        self.assertEqual([item["name"] for item in skipped], ["empty", "dup"])
        self.assertIn("APG-03", skipped[0]["reason"])
        self.assertFalse(plan_application_groups(rows, {}, {"teams-video"})["skipped_conflicts"])


class DeletionSafetyTests(unittest.TestCase):
    class Gateway:
        def __init__(self, match, acls=None):
            self.policy = {"data": {"map1": {"1_2": {"prio": {"100": {"match": match}}}}}}
            self.acls = acls or {}
            self.groups = [{"name": "ag", "type": "AG", "rules": [{"includedIPs": ["10.0.0.0/24"], "excludedIPs": [], "includedGroups": [], "comment": None}]}]
            self.app_groups = {"apps": {"apps": ["web"], "parentGroup": None}}
            self.definitions = {"portProtocolClassification": {"8080": [{"port": "8080", "protocol": 6, "name": "web", "description": "", "priority": 100, "disabled": False}]}, "dnsClassification": [], "compoundClassification": {}}

        def get_segments(self):
            return {"0": {"id": 0, "name": "Default"}}

        def get_policy(self, segment_map):
            return copy.deepcopy(self.policy)

        def get_central_acls(self, names=None):
            return copy.deepcopy(self.acls)

        def get_address_groups(self):
            return copy.deepcopy(self.groups)

        def get_application_groups(self):
            return copy.deepcopy(self.app_groups)

        def get_application_definitions(self, base):
            return copy.deepcopy(self.definitions[base])

        def get_appexpress(self):
            return {}

    def run_delete(self, gateway, command, headers, rows):
        fixture = TempCsv(headers, rows)
        try:
            with patch("edgeconnect_automation.cli._gateway", return_value=gateway), patch("sys.stdin.isatty", return_value=True), patch("secrets.choice", return_value="A"), patch("builtins.input", side_effect=["DELETE-AAAAAAAA", DELETE_ACKNOWLEDGMENT]):
                return main([command, "delete", "--csv", str(fixture.path)])
        finally:
            fixture.close()

    def test_address_group_referenced_by_firewall_is_blocked(self):
        gateway = self.Gateway({"either_addrgrp_groups": "other|ag"})
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(self.run_delete(gateway, "address-groups", ADDRESS_HEADERS, [address(ExcludedIPs="")]), 2)
        self.assertIn("DEL-05", stderr.getvalue())

    def test_application_group_referenced_by_template_acl_is_blocked(self):
        acls = {"acl": [{"template_group": "test3", "entries": {"1000": {"app_group": "apps", "permit": True}}}]}
        gateway = self.Gateway({}, acls)
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(self.run_delete(gateway, "app-groups", ["Name", "Applications", "ParentGroups"], [{"Name": "apps", "Applications": "web", "ParentGroups": ""}]), 2)
        self.assertIn("template group test3 ACL acl priority 1000", stderr.getvalue())

    def test_application_referenced_by_firewall_is_blocked_case_insensitively(self):
        gateway = self.Gateway({"application": "WEB"})
        gateway.app_groups = {}
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(self.run_delete(gateway, "app-definitions", APP_DEF_HEADERS, [app_row("TCP_PORT", "web", Port="8080")]), 2)
        self.assertIn("DEL-06", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
