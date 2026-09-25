import copy
import csv
import io
import os
import re
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .errors import DriftError, ValidationError
from .models import FirewallPlan, FirewallRule, Inventory, PairPlan, PairResult, RunResult, ScopeKey
from .util import fingerprint, normalize_acl_entries, semantic_equal, split_values
from .validation import PORT_PROTOCOLS, Issues, check_families, check_ports, control_characters, members, policy_ip, valid_domain, valid_protocol


FAMILIES = (
    ("source_address", "destination_address", "either_address"),
    ("source_address_group", "destination_address_group", "either_address_group"),
    ("source_port", "destination_port", "either_port"),
    ("source_service_group", "destination_service_group", "either_service_group"),
    ("source_domain", "destination_domain", "either_domain"),
)
ORDINARY_MATCH_FIELDS = tuple(name for family in FAMILIES for name in family) + ("application", "application_group", "protocol")
FIREWALL_HEADERS = {
    "rule_key", "rule_name", "description", "enabled", "priority", "source_segment", "destination_segment",
    "source_zone", "destination_zone", "acl", "action", "logging", "logging_level", "broad_match_ack",
} | set(ORDINARY_MATCH_FIELDS)
REQUIRED_HEADERS = {
    "rule_key", "source_segment", "destination_segment", "source_zone", "destination_zone", "action",
}
TRUE_VALUES = {"true", "yes", "1", "enabled", "enable"}
FALSE_VALUES = {"false", "no", "0", "disabled", "disable"}


def parse_bool(value: str, field: str, default: Optional[bool] = None) -> bool:
    normalized = value.strip().lower()
    if not normalized and default is not None:
        return default
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValidationError("{} must be true or false".format(field))


def _bool(row: Mapping[str, str], field: str, default: Optional[bool], issues: Issues, number: int) -> bool:
    try:
        return parse_bool(row.get(field, ""), field, default)
    except ValidationError as error:
        issues.add("VAL-01", str(error), number, field, row.get(field, ""), "use TRUE or FALSE")
        return bool(default)


@dataclass
class FirewallParseResult:
    rules: List[FirewallRule] = field(default_factory=list)
    pair_errors: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    global_errors: List[str] = field(default_factory=list)
    pair_warnings: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    issues: List[Mapping[str, Any]] = field(default_factory=list)

    @property
    def errors(self) -> List[str]:
        return self.global_errors + [error for errors in self.pair_errors.values() for error in errors]

    @property
    def warnings(self) -> List[str]:
        return [warning for warnings in self.pair_warnings.values() for warning in warnings]


def parse_firewall_csv(path: str) -> List[FirewallRule]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        return parse_firewall_text(handle.read())


def parse_firewall_document(text: str) -> FirewallParseResult:
    handle = io.StringIO(text, newline="")
    reader = csv.reader(handle, strict=True)
    try:
        headers = next(reader)
    except StopIteration as error:
        raise ValidationError("firewall CSV is empty") from error
    normalized_headers = [header.strip() for header in headers]
    if len(normalized_headers) != len(set(normalized_headers)):
        raise ValidationError("firewall CSV contains duplicate headers")
    unknown = set(normalized_headers) - FIREWALL_HEADERS
    missing = REQUIRED_HEADERS - set(normalized_headers)
    if unknown:
        raise ValidationError("unknown firewall headers: {}".format(", ".join(sorted(unknown))))
    if missing:
        raise ValidationError("missing firewall headers: {}".format(", ".join(sorted(missing))))
    result = FirewallParseResult()
    saw_row = False
    for row_number, values in enumerate(reader, 2):
        if not values or all(not value.strip() for value in values):
            continue
        saw_row = True
        if len(values) != len(normalized_headers):
            result.global_errors.append("row {} [CSV-06] has {} fields; expected {}".format(row_number, len(values), len(normalized_headers)))
            continue
        row = {key: value.strip() for key, value in zip(normalized_headers, values)}
        pair = (row.get("source_segment", ""), row.get("destination_segment", ""))
        issues = Issues("segment pair {} -> {}".format(*pair) if all(pair) else "the whole CSV")
        warnings = Issues("")
        control_characters(row, issues, row_number)
        rule = _parse_rule(row_number, row, issues, warnings)
        result.issues.extend(issues.items)
        if issues:
            (result.pair_errors.setdefault(pair, []) if all(pair) else result.global_errors).extend(issues.messages())
        elif rule is not None:
            result.rules.append(rule)
            if warnings:
                result.pair_warnings.setdefault(pair, []).extend(warnings.messages())
    if not saw_row:
        raise ValidationError("firewall CSV has no rules")
    return result


def parse_firewall_text(text: str) -> List[FirewallRule]:
    result = parse_firewall_document(text)
    if result.errors:
        raise ValidationError("\n".join(result.errors), result.issues)
    return result.rules


def _parse_rule(number: int, row: Mapping[str, str], issues: Issues, warnings: Issues) -> Optional[FirewallRule]:
    start = len(issues)
    for name in sorted(REQUIRED_HEADERS):
        if not row.get(name, ""):
            issues.add("FW-01", "{} is required".format(name), number, name, fix="fill in {}".format(name))
    priority: Optional[int] = None
    if row.get("priority"):
        if not re.fullmatch(r"-?[0-9]+", row["priority"]):
            issues.add("FW-20", "priority must be an integer", number, "priority", row["priority"], "use a whole number 0-65535 or leave blank for automatic allocation")
        elif not 0 <= int(row["priority"]) <= 65535:
            issues.add("FW-20", "priority must be between 0 and 65535", number, "priority", row["priority"], "use 0-65535")
        else:
            priority = int(row["priority"])
    acl = row.get("acl", "")
    if "|" in acl:
        issues.add("FW-02", "acl must be a single exact name", number, "acl", acl, "reference one ACL per rule")
    used = [name for name in ORDINARY_MATCH_FIELDS if row.get(name, "")]
    if acl and used:
        issues.add("FW-02", "acl is mutually exclusive with all ordinary match criteria ({})".format(", ".join(used)), number, "acl", acl, "put the criteria in the ACL or remove the acl reference")
    lists = {name: members(row.get(name, ""), issues, number, name) for name in ORDINARY_MATCH_FIELDS if name != "protocol"}
    check_families(row, FAMILIES, issues, number)
    for name in FAMILIES[0]:
        for value in lists[name]:
            try:
                warning = policy_ip(value)
            except ValueError as error:
                issues.add("FW-14", "{} contains invalid IP/CIDR {}: {}".format(name, value, error), number, name, value, "use an IPv4/IPv6 address, prefix, dotted mask, octet range, or whole-octet wildcard")
            else:
                if warning:
                    warnings.add("FW-12", warning, number, name, value)
    for name in FAMILIES[2]:
        check_ports(lists[name], issues, number, name)
    for name in FAMILIES[4]:
        for value in lists[name]:
            if not valid_domain(value):
                issues.add("VAL-09", "invalid domain {}".format(value), number, name, value, "use example.com, *.example.com, or *example.com")
    protocol = row.get("protocol", "").lower()
    if protocol and not valid_protocol(protocol):
        issues.add("VAL-06", "protocol is invalid", number, "protocol", protocol, "use ip, tcp, udp, tcp/udp, icmp, icmpv6, or a protocol number 0-255")
    if any(lists[name] for name in FAMILIES[2]) and protocol not in PORT_PROTOCOLS:
        issues.add("FW-06", "literal ports require protocol tcp, udp, tcp/udp, or blank", number, "protocol", protocol, "change the protocol or remove the port criteria")
    if any(value.lower() == "any" for value in lists["application"]):
        issues.add("FW-18", "application=any is not supported", number, "application", row.get("application", ""), "leave application blank or use application_group=any")
    action = row.get("action", "").lower()
    if action and action not in {"allow", "deny", "inspect"}:
        issues.add("FW-03", "action must be allow, deny, or inspect", number, "action", row.get("action", ""), "use allow, deny, or inspect")
    enabled = _bool(row, "enabled", True, issues, number)
    logging = _bool(row, "logging", False, issues, number)
    broad_match_ack = _bool(row, "broad_match_ack", False, issues, number)
    level_text = row.get("logging_level", "")
    logging_level = 2 if logging else 0
    if level_text:
        if not re.fullmatch(r"-?[0-9]+", level_text):
            issues.add("FW-19", "logging_level must be an integer", number, "logging_level", level_text, "use 0-7")
        elif not 0 <= int(level_text) <= 7:
            issues.add("FW-19", "logging_level must be between 0 and 7", number, "logging_level", level_text, "use 0-7")
        elif int(level_text) and not logging:
            issues.add("FW-19", "a nonzero logging_level requires logging=TRUE", number, "logging_level", level_text, "set logging=TRUE or clear logging_level")
        else:
            logging_level = int(level_text)
    if len(issues) != start:
        return None
    values = {name: row.get(name, "") for name in ORDINARY_MATCH_FIELDS}
    values["protocol"] = protocol
    rule = FirewallRule(
        row=number, rule_key=row["rule_key"], rule_name=row.get("rule_name", ""), description=row.get("description", ""),
        enabled=enabled, priority=priority, source_segment=row["source_segment"], destination_segment=row["destination_segment"],
        source_zone=row["source_zone"], destination_zone=row["destination_zone"], acl=acl, action=action,
        logging=logging, logging_level=logging_level, broad_match_ack=broad_match_ack, **values,
    )
    if not rule_match(rule) and not rule.broad_match_ack:
        issues.add("FW-04", "a rule without match conditions requires broad_match_ack=true", number, "broad_match_ack", row.get("broad_match_ack", ""), "add match criteria or set broad_match_ack=TRUE to confirm a match-all rule")
        return None
    if rule_match(rule) and rule.broad_match_ack:
        warnings.add("FW-05", "broad_match_ack=TRUE has no effect because the rule has match criteria", number, "broad_match_ack")
    return rule


MATCH_KEYS = {
    "acl": "acl", "source_address": "src_ip", "destination_address": "dst_ip", "either_address": "either_ip",
    "source_address_group": "src_addrgrp_groups", "destination_address_group": "dst_addrgrp_groups", "either_address_group": "either_addrgrp_groups",
    "application": "application", "application_group": "app_group", "protocol": "protocol",
    "source_port": "src_port", "destination_port": "dst_port", "either_port": "either_port",
    "source_service_group": "src_srvcgrp_groups", "destination_service_group": "dst_srvcgrp_groups", "either_service_group": "either_srvcgrp_groups",
    "source_domain": "src_dns", "destination_domain": "dst_dns", "either_domain": "either_dns",
}


def rule_match(rule: FirewallRule) -> Dict[str, str]:
    return {key: getattr(rule, name) for name, key in MATCH_KEYS.items() if getattr(rule, name)}


def rule_payload(rule: FirewallRule) -> Dict[str, Any]:
    return {
        "match": rule_match(rule),
        "set": {"action": rule.action},
        "comment": rule.description,
        "gms_marked": True,
        "misc": {
            "rule": "enable" if rule.enabled else "disable",
            "logging": "enable" if rule.logging else "disable",
            "logging_priority": rule.logging_level,
        },
    }


def normalize_rule(value: Mapping[str, Any], appliance: bool = False) -> Dict[str, Any]:
    result = copy.deepcopy(dict(value))
    if appliance:
        if result.get("match", {}).get("acl") == "":
            result.get("match", {}).pop("acl", None)
        misc = result.get("misc", {})
        if "logging_priority" in misc:
            misc["logging_priority"] = int(misc["logging_priority"])
    return result


def is_catchall(value: Mapping[str, Any]) -> bool:
    return not value.get("match") and value.get("set", {}).get("action") in {"allow", "deny"}


def _policy_rules(policy: Mapping[str, Any], zone_key: str) -> Dict[str, Any]:
    return dict(policy.get("data", {}).get("map1", {}).get(zone_key, {}).get("prio", {}))


def _ensure_candidate_shape(baseline: Mapping[str, Any]) -> Dict[str, Any]:
    candidate = copy.deepcopy(dict(baseline))
    candidate.setdefault("data", {}).setdefault("map1", {})
    candidate["options"] = {"merge": False, "templateApply": False}
    candidate.setdefault("settings", {})
    return candidate


def _acl_snapshot(acls: Mapping[str, Sequence[Mapping[str, Any]]], names: Iterable[str]) -> Dict[str, Any]:
    result = {}
    for name in sorted(set(names)):
        occurrences = []
        for occurrence in acls.get(name, []):
            occurrences.append({
                "template_group": str(occurrence.get("template_group", "")),
                "entries": normalize_acl_entries(occurrence.get("entries", {})),
                "selected": occurrence.get("selected") is True,
                "associated_targets": sorted(str(target) for target in occurrence.get("associated_targets", [])),
            })
        result[name] = sorted(occurrences, key=lambda item: (item["template_group"], fingerprint(item["entries"])))
    return result


def _resolve_acl_dependencies(names: Iterable[str], inventory: Inventory, errors: List[str], warnings: List[str]) -> Dict[str, Mapping[str, Any]]:
    dependencies = {}
    for name in sorted(set(names)):
        occurrences = list(inventory.acls.get(name, []))
        usable = [item for item in occurrences if item.get("selected") is True and item.get("entries")]
        if not usable:
            errors.append("missing central ACL {} in a selected Access Lists template with at least one entry".format(name))
            continue
        definitions: Dict[str, Mapping[str, Any]] = {}
        for occurrence in usable:
            entries = normalize_acl_entries(occurrence.get("entries", {}))
            definitions.setdefault(fingerprint(entries), entries)
        if len(definitions) != 1:
            groups = sorted(str(item.get("template_group", "")) for item in usable)
            errors.append("ACL {} has conflicting central definitions in template groups: {}".format(name, ", ".join(groups)))
            continue
        dependencies[name] = next(iter(definitions.values()))
        groups = sorted({str(item.get("template_group", "")) for item in usable})
        associations = sorted({str(target) for item in usable for target in item.get("associated_targets", [])})
        if len(groups) > 1:
            warnings.append("ACL {} has identical definitions in multiple template groups: {}".format(name, ", ".join(groups)))
        if not associations:
            warnings.append("ACL {} is central but its source template has no appliance associations".format(name))
        for target, state in inventory.target_states.items():
            if state != "reachable":
                continue
            appliance = inventory.appliance_acls.get(target, {})
            if name not in appliance:
                errors.append("[FW-29] ACL {} is missing on reachable target {}; Orchestrator will reject the complete security-map update".format(name, target))
            elif not semantic_equal(normalize_acl_entries(appliance[name]), dependencies[name]):
                errors.append("[FW-29] ACL {} differs on reachable target {}; Orchestrator will reject or misapply the complete security-map update".format(name, target))
    return dependencies


def build_firewall_plan(
    rules: Sequence[FirewallRule],
    inventory: Inventory,
    pair_errors: Optional[Mapping[Tuple[str, str], Sequence[str]]] = None,
    parse_global_errors: Sequence[str] = (),
    pair_warnings: Optional[Mapping[Tuple[str, str], Sequence[str]]] = None,
) -> FirewallPlan:
    grouped: Dict[Tuple[str, str], List[FirewallRule]] = {}
    for rule in rules:
        grouped.setdefault(rule.pair, []).append(rule)
    for pair in (pair_errors or {}):
        grouped.setdefault(pair, [])
    duplicate_keys: Dict[str, List[FirewallRule]] = {}
    for rule in rules:
        duplicate_keys.setdefault(rule.rule_key, []).append(rule)
    global_errors = list(parse_global_errors)
    if not inventory.segmentation_enabled:
        global_errors.append("routing segmentation is disabled")
    incomplete = sorted(name for name, status in inventory.statuses.items() if status != "complete")
    if incomplete:
        global_errors.append("required inventories are incomplete: {}".format(", ".join(incomplete)))
    pair_plans: List[PairPlan] = []
    resolved: List[FirewallRule] = []
    for pair, pair_rules in grouped.items():
        errors = list(global_errors) + list((pair_errors or {}).get(pair, ())) + list(inventory.pair_errors.get(pair, ()))
        warnings: List[str] = list((pair_warnings or {}).get(pair, ()))
        acl_names = {rule.acl for rule in pair_rules if rule.acl}
        acl_dependencies = _resolve_acl_dependencies(acl_names, inventory, errors, warnings)
        acl_inventory_fingerprint = fingerprint(_acl_snapshot(inventory.acls, acl_names)) if acl_names else ""
        for values in duplicate_keys.values():
            if len(values) > 1 and any(value.pair == pair for value in values):
                errors.append("duplicate rule_key {}".format(values[0].rule_key))
        source_id = inventory.segments.get(pair[0])
        destination_id = inventory.segments.get(pair[1])
        if source_id is None or destination_id is None:
            errors.append("unknown segment pair {} -> {}".format(*pair))
            segment_map = "unresolved"
        else:
            segment_map = "{}_{}".format(source_id, destination_id)
        baseline = copy.deepcopy(dict(inventory.policies.get(pair, {})))
        options = baseline.get("options")
        if options is not None and (options.get("merge") is not False or options.get("templateApply") is not False):
            errors.append("baseline options are incompatible with the contract-tested merge=false/templateApply=false adapter")
        candidate = _ensure_candidate_shape(baseline)
        seen: Dict[Tuple[str, str], Set[int]] = {}
        allocated_by_scope: Dict[ScopeKey, int] = {}
        resolved_pair: List[FirewallRule] = []
        for rule in pair_rules:
            scope = rule.scope
            source_zone_id = inventory.zones.get((rule.source_segment, rule.source_zone))
            destination_zone_id = inventory.zones.get((rule.destination_segment, rule.destination_zone))
            if source_zone_id is None:
                errors.append("row {} missing source zone {} in segment {}".format(rule.row, rule.source_zone, rule.source_segment))
            if destination_zone_id is None:
                errors.append("row {} missing destination zone {} in segment {}".format(rule.row, rule.destination_zone, rule.destination_segment))
            _check_dependencies(rule, inventory, errors)
            if source_zone_id is None or destination_zone_id is None:
                continue
            zone_key = "{}_{}".format(source_zone_id, destination_zone_id)
            existing = _policy_rules(baseline, zone_key)
            priority = rule.priority
            if priority is None:
                if not (not existing or set(existing) == {"65535"} and is_catchall(existing["65535"])):
                    errors.append("row {} cannot auto-allocate priority in occupied zone pair".format(rule.row))
                    continue
                next_priority = allocated_by_scope.get(scope, 20000)
                reserved = {item.priority for item in pair_rules if item.scope == scope and item.priority is not None}
                while next_priority in reserved or str(next_priority) in existing:
                    next_priority += 10
                if next_priority >= 65535:
                    errors.append("row {} has no available automatic priority below 65535".format(rule.row))
                    continue
                priority = next_priority
                allocated_by_scope[scope] = next_priority + 10
            used = seen.setdefault((zone_key, segment_map), set())
            if priority in used:
                errors.append("row {} duplicates CSV priority {} in its scope".format(rule.row, priority))
            used.add(priority)
            if priority in inventory.local_priorities.get(scope, set()):
                errors.append("row {} priority {} collides with an appliance-local rule".format(rule.row, priority))
            resolved_rule = replace(rule, priority=priority)
            resolved_pair.append(resolved_rule)
        if not errors:
            for rule in resolved_pair:
                source_zone_id = inventory.zones[(rule.source_segment, rule.source_zone)]
                destination_zone_id = inventory.zones[(rule.destination_segment, rule.destination_zone)]
                zone_key = "{}_{}".format(source_zone_id, destination_zone_id)
                pair_container = candidate["data"]["map1"].setdefault(zone_key, {})
                priorities = pair_container.setdefault("prio", {})
                key = str(rule.priority)
                payload = rule_payload(rule)
                if key in priorities:
                    if semantic_equal(normalize_rule(priorities[key]), normalize_rule(payload)):
                        continue
                    errors.append("row {} priority {} conflicts with a different existing rule".format(rule.row, rule.priority))
                    continue
                priorities[key] = payload
        created: List[Tuple[str, int]] = []
        no_ops: List[int] = []
        if not errors:
            for rule in resolved_pair:
                zone_key = "{}_{}".format(inventory.zones[(rule.source_segment, rule.source_zone)], inventory.zones[(rule.destination_segment, rule.destination_zone)])
                existing = _policy_rules(baseline, zone_key)
                if str(rule.priority) in existing:
                    no_ops.append(rule.row)
                else:
                    created.append((zone_key, int(rule.priority)))
            resolved.extend(resolved_pair)
        for target, state in inventory.target_states.items():
            if state != "reachable":
                warnings.append("target {} is {} and will remain unverified".format(target, state))
        pair_plans.append(PairPlan(
            pair=pair,
            segment_map=segment_map,
            eligible=not errors,
            baseline=baseline,
            candidate=candidate,
            baseline_fingerprint=fingerprint(baseline),
            rules=resolved_pair,
            created_priorities=created,
            no_op_rows=no_ops,
            errors=errors,
            warnings=warnings,
            target_states=dict(inventory.target_states),
            acl_dependencies=acl_dependencies,
            acl_inventory_fingerprint=acl_inventory_fingerprint,
        ))
    return FirewallPlan(pair_plans, errors=global_errors, resolved_rows=resolved)


def _check_dependencies(rule: FirewallRule, inventory: Inventory, errors: List[str]) -> None:
    checks = (
        (rule.source_address_group, inventory.address_groups, "address group"),
        (rule.destination_address_group, inventory.address_groups, "address group"),
        (rule.either_address_group, inventory.address_groups, "address group"),
        (rule.source_service_group, inventory.service_groups, "service group"),
        (rule.destination_service_group, inventory.service_groups, "service group"),
        (rule.either_service_group, inventory.service_groups, "service group"),
        (rule.application, inventory.applications, "application"),
        (rule.application_group, inventory.application_groups, "application group"),
    )
    applications = {name.lower() for name in inventory.applications}
    for value, namespace, label in checks:
        for name in split_values(value):
            if label == "application group" and name.lower() == "any":
                continue
            if name.lower() not in applications if label == "application" else name not in namespace:
                errors.append("row {} [DEP-01] missing {} {}".format(rule.row, label, name))


class FirewallExecutor:
    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    def apply(self, plan: FirewallPlan, run_reference: Optional[str] = None) -> RunResult:
        reference = run_reference or "edgeconnect-auto-{}".format(uuid.uuid4().hex[:12])
        results: List[PairResult] = []
        for pair in plan.pairs:
            if not pair.eligible:
                results.append(PairResult(pair.pair, "ineligible", "; ".join(pair.errors)))
                continue
            if pair.acl_dependencies:
                current_acls = self.gateway.get_central_acls(set(pair.acl_dependencies))
                if fingerprint(_acl_snapshot(current_acls, pair.acl_dependencies)) != pair.acl_inventory_fingerprint:
                    results.append(PairResult(pair.pair, "drift", "central ACL dependency changed before write"))
                    continue
            current = self.gateway.get_policy(pair.segment_map)
            if fingerprint(current) != pair.baseline_fingerprint:
                results.append(PairResult(pair.pair, "drift", "baseline changed before write"))
                continue
            if not pair.created_priorities:
                if not pair.acl_dependencies:
                    results.append(PairResult(pair.pair, "no_op"))
                    continue
                if hasattr(self.gateway, "targets"):
                    self.gateway.targets = dict(pair.target_states)
                targets = self.gateway.verify_targets(pair.segment_map, pair.candidate, reference, pair.acl_dependencies)
                unresolved = any(status != "verified" for status in targets.values())
                results.append(PairResult(pair.pair, "partial" if unresolved else "no_op", targets=targets))
                continue
            try:
                self.gateway.post_policy(pair.segment_map, pair.candidate, reference)
                readback = self.gateway.get_policy(pair.segment_map)
                if not semantic_equal(readback, pair.candidate):
                    raise DriftError("normalized readback differs from candidate")
                if hasattr(self.gateway, "targets"):
                    self.gateway.targets = dict(pair.target_states)
                targets = self.gateway.verify_targets(pair.segment_map, pair.candidate, reference, pair.acl_dependencies) if pair.acl_dependencies else self.gateway.verify_targets(pair.segment_map, pair.candidate, reference)
                if not targets:
                    targets = {"expected_targets": "unknown"}
                audit_verified = self.gateway.correlate_audit(pair.segment_map, reference) if hasattr(self.gateway, "correlate_audit") else True
                unresolved = any(status != "verified" for status in targets.values()) or not audit_verified
                message = "audit correlation unresolved" if not audit_verified else ""
                results.append(PairResult(pair.pair, "partial" if unresolved else "success", message, targets=targets))
            except Exception as error:
                rollback = self._rollback(pair, reference)
                results.append(PairResult(pair.pair, "critical" if rollback != "verified" else "failed", str(error), rollback))
        statuses = {result.status for result in results}
        if statuses <= {"success", "no_op"}:
            status = "SUCCESS"
        elif statuses == {"ineligible"}:
            status = "VALIDATION"
        elif "drift" in statuses and statuses <= {"drift", "ineligible"}:
            status = "DRIFT"
        else:
            status = "PARTIAL"
        return RunResult(status=status, pairs=results, run_reference=reference)

    def _rollback(self, pair: PairPlan, reference: str) -> str:
        try:
            current = self.gateway.get_policy(pair.segment_map)
            if semantic_equal(current, pair.baseline):
                return "verified"
            rollback_candidate = copy.deepcopy(current)
            for zone_key, priority in pair.created_priorities:
                existing = rollback_candidate.get("data", {}).get("map1", {}).get(zone_key, {}).get("prio", {})
                baseline_rule = _policy_rules(pair.baseline, zone_key).get(str(priority))
                if str(priority) in existing and baseline_rule is None:
                    del existing[str(priority)]
                baseline_maps = pair.baseline.get("data", {}).get("map1", {})
                rollback_maps = rollback_candidate.get("data", {}).get("map1", {})
                if zone_key not in baseline_maps and not rollback_maps.get(zone_key, {}).get("prio"):
                    rollback_maps.pop(zone_key, None)
            for key in set(rollback_candidate) - set(pair.baseline):
                if key in {"options", "settings"}:
                    rollback_candidate.pop(key, None)
            if not semantic_equal(rollback_candidate, pair.baseline):
                return "unresolved"
            self.gateway.post_policy(pair.segment_map, rollback_candidate, reference + "-rollback")
            restored = self.gateway.get_policy(pair.segment_map)
            return "verified" if semantic_equal(restored, pair.baseline) else "unverified"
        except Exception:
            return "unresolved"


def write_resolved_csv(path: str, rules: Sequence[FirewallRule]) -> None:
    headers = sorted(FIREWALL_HEADERS)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, headers, extrasaction="ignore")
        writer.writeheader()
        for rule in rules:
            values = dict(vars(rule))
            values.pop("row", None)
            values["enabled"] = "TRUE" if rule.enabled else "FALSE"
            values["logging"] = "TRUE" if rule.logging else "FALSE"
            values["broad_match_ack"] = "TRUE" if rule.broad_match_ack else "FALSE"
            writer.writerow(values)
    os.chmod(str(target), 0o600)
