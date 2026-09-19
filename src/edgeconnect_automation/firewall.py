import copy
import csv
import io
import ipaddress
import os
import re
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .errors import DriftError, ValidationError
from .models import FirewallPlan, FirewallRule, Inventory, PairPlan, PairResult, RunResult, ScopeKey
from .util import fingerprint, semantic_equal, split_values


FIREWALL_HEADERS = {
    "rule_key", "rule_name", "description", "enabled", "priority", "source_segment", "destination_segment",
    "source_zone", "destination_zone", "source_address", "source_address_group", "destination_address",
    "destination_address_group", "either_address", "either_address_group", "application", "application_group",
    "protocol", "source_port", "destination_port", "either_port", "source_service_group",
    "destination_service_group", "either_service_group", "action", "logging", "logging_level", "broad_match_ack",
}
REQUIRED_HEADERS = {
    "rule_key", "source_segment", "destination_segment", "source_zone", "destination_zone", "action",
}
TRUE_VALUES = {"true", "yes", "1", "enabled", "enable"}
FALSE_VALUES = {"false", "no", "0", "disabled", "disable"}
PORT_PATTERN = re.compile(r"^[0-9]+(?:-[0-9]+)?$")
PROTOCOL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def parse_bool(value: str, field: str, default: Optional[bool] = None) -> bool:
    normalized = value.strip().lower()
    if not normalized and default is not None:
        return default
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValidationError("{} must be true or false".format(field))


def _validate_ip_list(value: str, field: str) -> None:
    for item in split_values(value):
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as error:
            raise ValidationError("{} contains invalid IP/CIDR {}".format(field, item)) from error


def _validate_ports(value: str, field: str) -> None:
    for item in split_values(value):
        if not PORT_PATTERN.fullmatch(item):
            raise ValidationError("{} contains invalid port {}".format(field, item))
        parts = [int(part) for part in item.split("-")]
        if any(part < 0 or part > 65535 for part in parts) or len(parts) == 2 and parts[0] > parts[1]:
            raise ValidationError("{} contains out-of-range port {}".format(field, item))


@dataclass
class FirewallParseResult:
    rules: List[FirewallRule] = field(default_factory=list)
    pair_errors: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    global_errors: List[str] = field(default_factory=list)

    @property
    def errors(self) -> List[str]:
        return self.global_errors + [error for errors in self.pair_errors.values() for error in errors]


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
            result.global_errors.append("row {} has {} fields; expected {}".format(row_number, len(values), len(normalized_headers)))
            continue
        row = {key: value.strip() for key, value in zip(normalized_headers, values)}
        pair = (row.get("source_segment", ""), row.get("destination_segment", ""))
        try:
            result.rules.append(_parse_rule(row_number, row))
        except ValidationError as error:
            message = "row {}: {}".format(row_number, error)
            if all(pair):
                result.pair_errors.setdefault(pair, []).append(message)
            else:
                result.global_errors.append(message)
    if not saw_row:
        raise ValidationError("firewall CSV has no rules")
    return result


def parse_firewall_text(text: str) -> List[FirewallRule]:
    result = parse_firewall_document(text)
    if result.errors:
        raise ValidationError("\n".join(result.errors))
    return result.rules


def _parse_rule(row_number: int, row: Mapping[str, str]) -> FirewallRule:
    for field in REQUIRED_HEADERS:
        if not row.get(field, ""):
            raise ValidationError("{} is required".format(field))
    priority: Optional[int] = None
    if row.get("priority"):
        try:
            priority = int(row["priority"])
        except ValueError as error:
            raise ValidationError("priority must be an integer") from error
        if priority < 0 or priority > 65535:
            raise ValidationError("priority must be between 0 and 65535")
    for field in ("source_address", "destination_address", "either_address"):
        _validate_ip_list(row.get(field, ""), field)
    for field in ("source_port", "destination_port", "either_port"):
        _validate_ports(row.get(field, ""), field)
    protocol = row.get("protocol", "").lower()
    if protocol and not PROTOCOL_PATTERN.fullmatch(protocol):
        raise ValidationError("protocol is invalid")
    if any(row.get(field, "") for field in ("source_port", "destination_port", "either_port")) and protocol not in {"tcp", "udp"}:
        raise ValidationError("literal ports require protocol tcp or udp")
    if row.get("either_address") and (row.get("source_address") or row.get("destination_address")):
        raise ValidationError("either_address is mutually exclusive with directional addresses")
    if row.get("either_address_group") and (row.get("source_address_group") or row.get("destination_address_group")):
        raise ValidationError("either_address_group is mutually exclusive with directional address groups")
    if row.get("either_port") and (row.get("source_port") or row.get("destination_port")):
        raise ValidationError("either_port is mutually exclusive with directional ports")
    if row.get("either_service_group") and (row.get("source_service_group") or row.get("destination_service_group")):
        raise ValidationError("either_service_group is mutually exclusive with directional service groups")
    action = row["action"].lower()
    if action not in {"allow", "deny", "inspect"}:
        raise ValidationError("action must be allow, deny, or inspect")
    logging = parse_bool(row.get("logging", ""), "logging", False)
    level_text = row.get("logging_level", "")
    if level_text:
        try:
            logging_level = int(level_text)
        except ValueError as error:
            raise ValidationError("logging_level must be an integer") from error
        if logging_level < 0 or logging_level > 7:
            raise ValidationError("logging_level must be between 0 and 7")
    else:
        logging_level = 2 if logging else 0
    rule = FirewallRule(
        row=row_number,
        rule_key=row["rule_key"],
        rule_name=row.get("rule_name", ""),
        description=row.get("description", ""),
        enabled=parse_bool(row.get("enabled", ""), "enabled", True),
        priority=priority,
        source_segment=row["source_segment"],
        destination_segment=row["destination_segment"],
        source_zone=row["source_zone"],
        destination_zone=row["destination_zone"],
        source_address=row.get("source_address", ""),
        source_address_group=row.get("source_address_group", ""),
        destination_address=row.get("destination_address", ""),
        destination_address_group=row.get("destination_address_group", ""),
        either_address=row.get("either_address", ""),
        either_address_group=row.get("either_address_group", ""),
        application=row.get("application", ""),
        application_group=row.get("application_group", ""),
        protocol=protocol,
        source_port=row.get("source_port", ""),
        destination_port=row.get("destination_port", ""),
        either_port=row.get("either_port", ""),
        source_service_group=row.get("source_service_group", ""),
        destination_service_group=row.get("destination_service_group", ""),
        either_service_group=row.get("either_service_group", ""),
        action=action,
        logging=logging,
        logging_level=logging_level,
        broad_match_ack=parse_bool(row.get("broad_match_ack", ""), "broad_match_ack", False),
    )
    if not rule_match(rule) and not rule.broad_match_ack:
        raise ValidationError("a rule without match conditions requires broad_match_ack=true")
    return rule


def rule_match(rule: FirewallRule) -> Dict[str, str]:
    values = {
        "src_ip": rule.source_address,
        "dst_ip": rule.destination_address,
        "either_ip": rule.either_address,
        "src_addrgrp_groups": rule.source_address_group,
        "dst_addrgrp_groups": rule.destination_address_group,
        "either_addrgrp_groups": rule.either_address_group,
        "application": rule.application,
        "app_group": rule.application_group,
        "protocol": rule.protocol,
        "src_port": rule.source_port,
        "dst_port": rule.destination_port,
        "either_port": rule.either_port,
        "src_srvcgrp_groups": rule.source_service_group,
        "dst_srvcgrp_groups": rule.destination_service_group,
        "either_srvcgrp_groups": rule.either_service_group,
    }
    return {key: value for key, value in values.items() if value}


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


def build_firewall_plan(
    rules: Sequence[FirewallRule],
    inventory: Inventory,
    pair_errors: Optional[Mapping[Tuple[str, str], Sequence[str]]] = None,
    parse_global_errors: Sequence[str] = (),
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
        warnings: List[str] = []
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
    for value, namespace, label in checks:
        for name in split_values(value):
            if label == "application group" and name.lower() == "any":
                continue
            if name not in namespace:
                errors.append("row {} missing {} {}".format(rule.row, label, name))


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
            if not pair.created_priorities:
                results.append(PairResult(pair.pair, "no_op"))
                continue
            current = self.gateway.get_policy(pair.segment_map)
            if fingerprint(current) != pair.baseline_fingerprint:
                results.append(PairResult(pair.pair, "drift", "baseline changed before write"))
                continue
            try:
                self.gateway.post_policy(pair.segment_map, pair.candidate, reference)
                readback = self.gateway.get_policy(pair.segment_map)
                if not semantic_equal(readback, pair.candidate):
                    raise DriftError("normalized readback differs from candidate")
                if hasattr(self.gateway, "targets"):
                    self.gateway.targets = dict(pair.target_states)
                targets = self.gateway.verify_targets(pair.segment_map, pair.candidate, reference)
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
