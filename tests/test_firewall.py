import copy
import tempfile
import unittest
from pathlib import Path

from edgeconnect_automation.errors import ApprovalError, ValidationError
from edgeconnect_automation.firewall import FirewallExecutor, build_firewall_plan, parse_firewall_document, parse_firewall_text, rule_payload
from edgeconnect_automation.models import Inventory


HEADERS = "rule_key,rule_name,description,enabled,priority,source_segment,destination_segment,source_zone,destination_zone,source_address,source_address_group,destination_address,destination_address_group,either_address,either_address_group,application,application_group,protocol,source_port,destination_port,either_port,source_service_group,destination_service_group,either_service_group,action,logging,logging_level,broad_match_ack"


def row(key="r1", priority="", source_segment="A", destination_segment="B", source_zone="ZA", destination_zone="ZB", source_address="10.0.0.0/24", source_group="", destination_address="", destination_group="", protocol="tcp", source_port="", destination_port="443", action="allow", logging="true", level=""):
    values = [key, "name", "desc", "true", priority, source_segment, destination_segment, source_zone, destination_zone, source_address, source_group, destination_address, destination_group, "", "", "", "", protocol, source_port, destination_port, "", "", "", "", action, logging, level, "false"]
    return ",".join(values)


def policy(rules=None, marker=None):
    value = {"data": {"map1": {}}, "options": {"merge": False, "templateApply": False}, "settings": {"marker": marker}}
    if rules is not None:
        value["data"]["map1"]["1_2"] = {"prio": rules}
    return value


def inventory(policies=None, local=None, address_groups=None):
    return Inventory(
        segments={"A": 10, "B": 20, "C": 30, "D": 40},
        zones={("A", "ZA"): 1, ("B", "ZB"): 2, ("C", "ZC"): 3, ("D", "ZD"): 4},
        policies=policies or {("A", "B"): policy()},
        address_groups=set(address_groups or []),
        service_groups=set(),
        applications=set(),
        application_groups=set(),
        local_priorities=local or {},
        statuses={"all": "complete"},
        segmentation_enabled=True,
    )


class FirewallParsingTests(unittest.TestCase):
    def test_parse_lists_ranges_and_defaults(self):
        rules = parse_firewall_text(HEADERS + "\n" + row(source_address="10.0.0.1/32|10.0.0.2/32", source_port="1000-1002|1010", destination_port=""))
        self.assertEqual(rules[0].logging_level, 2)
        self.assertEqual(rules[0].source_port, "1000-1002|1010")
        self.assertIsNone(rules[0].priority)

    def test_unknown_url_header_rejected(self):
        with self.assertRaisesRegex(ValidationError, "unknown firewall headers"):
            parse_firewall_text(HEADERS + ",url\n" + row() + ",https://example.invalid")

    def test_duplicate_header_and_bad_shape(self):
        with self.assertRaisesRegex(ValidationError, "duplicate headers"):
            parse_firewall_text(HEADERS + ",rule_key\n" + row() + ",x")
        with self.assertRaisesRegex(ValidationError, "fields"):
            parse_firewall_text(HEADERS + "\n" + row() + ",extra")

    def test_port_requires_protocol_and_either_exclusive(self):
        with self.assertRaisesRegex(ValidationError, "literal ports require"):
            parse_firewall_text(HEADERS + "\n" + row(protocol=""))
        values = row().split(",")
        values[13] = "192.0.2.1/32"
        with self.assertRaisesRegex(ValidationError, "either_address"):
            parse_firewall_text(HEADERS + "\n" + ",".join(values))

    def test_port_zero_and_either_service_group(self):
        values = row(destination_port="0").split(",")
        values[23] = "EitherServices"
        rule = parse_firewall_text(HEADERS + "\n" + ",".join(values))[0]
        self.assertEqual(rule.destination_port, "0")
        self.assertEqual(rule.either_service_group, "EitherServices")

    def test_match_all_requires_ack(self):
        values = row(source_address="", protocol="", destination_port="").split(",")
        with self.assertRaisesRegex(ValidationError, "broad_match_ack"):
            parse_firewall_text(HEADERS + "\n" + ",".join(values))
        values[-1] = "true"
        self.assertEqual(len(parse_firewall_text(HEADERS + "\n" + ",".join(values))), 1)


class FirewallPlanningTests(unittest.TestCase):
    def test_auto_priority_reserves_explicit_and_preserves_catchall(self):
        catchall = {"match": {}, "set": {"action": "deny"}}
        inv = inventory({("A", "B"): policy({"65535": catchall}, "keep")})
        rules = parse_firewall_text(HEADERS + "\n" + row("implicit") + "\n" + row("explicit", "20000", source_address="10.1.0.0/24"))
        plan = build_firewall_plan(rules, inv)
        self.assertTrue(plan.pairs[0].eligible)
        priorities = [rule.priority for rule in plan.pairs[0].rules]
        self.assertEqual(priorities, [20010, 20000])
        candidate_rules = plan.pairs[0].candidate["data"]["map1"]["1_2"]["prio"]
        self.assertIn("65535", candidate_rules)
        self.assertEqual(plan.pairs[0].candidate["settings"]["marker"], "keep")

    def test_non_catchall_blocks_automatic(self):
        existing = {"100": {"match": {"protocol": "tcp"}, "set": {"action": "deny"}}}
        plan = build_firewall_plan(parse_firewall_text(HEADERS + "\n" + row()), inventory({("A", "B"): policy(existing)}))
        self.assertFalse(plan.pairs[0].eligible)
        self.assertIn("occupied", " ".join(plan.pairs[0].errors))

    def test_bad_row_isolated_to_its_segment_pair(self):
        text = HEADERS + "\n" + row("bad", action="invalid") + "\n" + row("good", source_segment="C", destination_segment="D", source_zone="ZC", destination_zone="ZD", source_address="10.2.0.0/24")
        document = parse_firewall_document(text)
        inv = inventory({("A", "B"): policy(), ("C", "D"): policy()})
        plan = build_firewall_plan(document.rules, inv, document.pair_errors, document.global_errors)
        by_pair = {item.pair: item for item in plan.pairs}
        self.assertFalse(by_pair[("A", "B")].eligible)
        self.assertTrue(by_pair[("C", "D")].eligible)

    def test_dependency_invalidates_only_its_segment_pair(self):
        text = HEADERS + "\n" + row("bad", source_group="missing") + "\n" + row("good", source_segment="C", destination_segment="D", source_zone="ZC", destination_zone="ZD", source_address="10.2.0.0/24")
        inv = inventory({("A", "B"): policy(), ("C", "D"): policy()})
        plan = build_firewall_plan(parse_firewall_text(text), inv)
        self.assertFalse(plan.pairs[0].eligible)
        self.assertTrue(plan.pairs[1].eligible)

    def test_application_group_any_is_special_without_inventory_dependency(self):
        values = row().split(",")
        values[16] = "any"
        rule = parse_firewall_text(HEADERS + "\n" + ",".join(values))[0]
        plan = build_firewall_plan([rule], inventory())
        self.assertTrue(plan.pairs[0].eligible)

    def test_local_exact_collision_blocks_pair(self):
        rules = parse_firewall_text(HEADERS + "\n" + row(priority="20000"))
        local = {("A", "B", "ZA", "ZB"): {20000, 30000}}
        plan = build_firewall_plan(rules, inventory(local=local))
        self.assertFalse(plan.pairs[0].eligible)
        self.assertIn("appliance-local", " ".join(plan.pairs[0].errors))

    def test_identical_existing_is_noop_but_different_conflicts(self):
        rule = parse_firewall_text(HEADERS + "\n" + row(priority="100"))[0]
        same = policy({"100": rule_payload(rule)})
        noop = build_firewall_plan([rule], inventory({("A", "B"): same}))
        self.assertTrue(noop.pairs[0].eligible)
        self.assertEqual(noop.pairs[0].no_op_rows, [2])
        different = copy.deepcopy(same)
        different["data"]["map1"]["1_2"]["prio"]["100"]["set"]["action"] = "deny"
        conflict = build_firewall_plan([rule], inventory({("A", "B"): different}))
        self.assertFalse(conflict.pairs[0].eligible)

    def test_duplicate_priority_invalidates_pair(self):
        rules = parse_firewall_text(HEADERS + "\n" + row("one", "100") + "\n" + row("two", "100", source_address="10.3.0.0/24"))
        plan = build_firewall_plan(rules, inventory())
        self.assertFalse(plan.pairs[0].eligible)
        self.assertIn("duplicates CSV priority", " ".join(plan.pairs[0].errors))


class FakeGateway:
    def __init__(self, policies, corrupt_map=None, target_states=None):
        self.policies = copy.deepcopy(policies)
        self.corrupt_map = corrupt_map
        self.target_states = target_states or {}
        self.posts = []
        self.corrupted = False

    def get_policy(self, segment_map):
        return copy.deepcopy(self.policies[segment_map])

    def post_policy(self, segment_map, value, comment):
        self.posts.append((segment_map, copy.deepcopy(value), comment))
        self.policies[segment_map] = copy.deepcopy(value)
        if segment_map == self.corrupt_map and not comment.endswith("-rollback") and not self.corrupted:
            maps = self.policies[segment_map]["data"]["map1"]
            first_pair = next(iter(maps.values()))
            first_rule = next(iter(first_pair["prio"].values()))
            first_rule["match"] = {}
            self.corrupted = True

    def verify_targets(self, segment_map, candidate, reference):
        return dict(self.target_states or {"target": "verified"})


class FirewallExecutionTests(unittest.TestCase):
    def test_readback_loss_rolls_back_and_continues_other_pair(self):
        text = HEADERS + "\n" + row("one") + "\n" + row("two", source_segment="C", destination_segment="D", source_zone="ZC", destination_zone="ZD", source_address="10.2.0.0/24")
        inv = inventory({("A", "B"): policy(marker="first"), ("C", "D"): policy(marker="second")})
        plan = build_firewall_plan(parse_firewall_text(text), inv)
        fake = FakeGateway({"10_20": policy(marker="first"), "30_40": policy(marker="second")}, corrupt_map="10_20")
        result = FirewallExecutor(fake).apply(plan, "run")
        self.assertEqual(result.status, "PARTIAL")
        self.assertEqual(result.pairs[0].rollback_status, "verified")
        self.assertEqual(result.pairs[1].status, "success")
        self.assertEqual(fake.policies["10_20"], policy(marker="first"))

    def test_unverified_target_is_partial(self):
        plan = build_firewall_plan(parse_firewall_text(HEADERS + "\n" + row()), inventory())
        fake = FakeGateway({"10_20": policy()}, target_states={"one": "verified", "two": "unreachable"})
        result = FirewallExecutor(fake).apply(plan, "run")
        self.assertEqual(result.status, "PARTIAL")
        self.assertEqual(result.pairs[0].targets["two"], "unreachable")


if __name__ == "__main__":
    unittest.main()
