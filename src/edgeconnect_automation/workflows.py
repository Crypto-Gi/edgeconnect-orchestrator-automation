import copy
import csv
import io
import json
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .errors import DriftError, ValidationError
from .firewall import parse_bool
from .util import canonical_json, detect_cycle, fingerprint, normalize_acl_entries, semantic_equal
from .validation import PORT_PROTOCOLS, Issues, address_group_ipv4, check_families, check_ports, compound_ipv4, control_characters, members, normalize_dscp, policy_ip, valid_domain, valid_protocol


ADDRESS_HEADERS = ["Name", "IncludedIPs", "ExcludedIPs", "IncludedGroups", "Comment"]
SERVICE_HEADERS = ["Name", "Protocol", "IncludedPorts", "ExcludedPorts", "IncludedGroups", "ExcludedGroups", "IcmpTypes", "IcmpCodes", "Comment"]
APP_GROUP_HEADERS = ["Name", "Applications", "ParentGroups"]
APP_DEF_HEADERS = ["DefinitionType", "Name", "Notes", "Enabled", "Confidence", "ProtocolNumber", "Port", "Domain", "Protocol", "SourcePort", "DestinationPort", "EitherPort", "SourceIP", "DestinationIP", "EitherIP", "SourceGeo", "DestinationGeo", "EitherGeo", "SourceDomain", "DestinationDomain", "EitherDomain", "DSCP", "SourceAddressMap", "DestinationAddressMap", "EitherAddressMap", "Interface", "AppExpressMode"]
ACL_HEADERS = ["TemplateGroup", "ACLName", "ACLUpdateMode", "TemplateApplyMode", "Priority", "Permit", "Application", "ApplicationGroup", "SourceIP", "DestinationIP", "EitherIP", "SourcePort", "DestinationPort", "EitherPort", "SourceDomain", "DestinationDomain", "EitherDomain", "Protocol", "Comment", "BroadMatchAck"]
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
GROUP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
APP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,31}$")
SIMPLE_APP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,31}$")
GEO_PATTERN = re.compile(r"^[A-Za-z][A-Za-z .,'()&-]{1,63}$")
REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.&()+-]{0,63}$")
ZONE_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")
ICMP_TYPE_PATTERN = re.compile(r"^[0-9]{1,3}(?:-[0-9]{1,3})?$")
ACL_FAMILIES = (("SourceIP", "DestinationIP", "EitherIP"), ("SourcePort", "DestinationPort", "EitherPort"), ("SourceDomain", "DestinationDomain", "EitherDomain"))
ADDRESS_GROUP_LIMIT = 8 * 1024 * 1024
SERVICE_GROUP_LIMIT = 4 * 1024 * 1024
APPEXPRESS_LIMIT = 50


def _members(value: str) -> List[str]:
    return [item.strip() for item in value.split("|") if item.strip()]


def _csv_members(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _read_exact_csv(path: str, expected: Sequence[str], issues: Optional[Issues] = None) -> List[Dict[str, str]]:
    own = issues is None
    issues = Issues() if issues is None else issues
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames != list(expected):
            raise ValidationError("[CSV-03] CSV headers must exactly match: {}".format(",".join(expected)))
        rows = []
        for number, row in enumerate(reader, 2):
            if None in row:
                issues.add("CSV-05", "row has extra fields", number, fix="remove the extra columns or quote values containing commas")
            if any(value is None for key, value in row.items() if key is not None):
                issues.add("CSV-06", "row has fewer fields than the header", number, fix="add the missing empty columns")
            clean = {key: (value or "").strip() for key, value in row.items() if key is not None}
            if any(clean.values()):
                control_characters(clean, issues, number)
                clean["_row"] = str(number)
                rows.append(clean)
    if not rows:
        raise ValidationError("[CSV-08] CSV has no data rows")
    if own:
        issues.raise_if_any()
    return rows


@dataclass
class TemplateACLRule:
    row: int
    template_group: str
    acl_name: str
    priority: str
    entry: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)


def parse_template_acls(path: str) -> List[TemplateACLRule]:
    issues = Issues()
    rows = _read_exact_csv(path, ACL_HEADERS, issues)
    rules = []
    identities = set()
    modes = {}
    for row in rows:
        number = int(row["_row"])
        start = len(issues)
        warnings = Issues("")
        group = row["TemplateGroup"]
        name = row["ACLName"]
        if not group:
            issues.add("ACL-20", "invalid TemplateGroup", number, "TemplateGroup", fix="name the target template group")
        if not name or name == "NewACL":
            issues.add("ACL-20", "invalid or reserved ACLName", number, "ACLName", name, "use a real ACL name other than NewACL")
        mode = (row["ACLUpdateMode"].upper(), row["TemplateApplyMode"].upper())
        if group and name:
            first_mode, first_row = modes.setdefault((group, name), (mode, number))
            if mode != first_mode:
                issues.add("ACL-23", "rows for the same TemplateGroup + ACLName must use identical ACLUpdateMode and TemplateApplyMode values; row {} uses {}/{}".format(first_row, *first_mode), number, "ACLUpdateMode/TemplateApplyMode", "{}/{}".format(*mode), "use MERGE/MERGE on every row for this TemplateGroup + ACLName")
        if mode != ("MERGE", "MERGE"):
            issues.add("ACL-21", "ACLUpdateMode and TemplateApplyMode must be MERGE", number, "ACLUpdateMode", row["ACLUpdateMode"], "REPLACE is not supported; use MERGE")
        priority = row["Priority"]
        if not priority.isdigit() or not 1 <= int(priority) <= 65535:
            issues.add("ACL-09", "Priority must be an integer 1-65535", number, "Priority", priority, "use 1-65535")
        else:
            priority = str(int(priority))
            identity = (group, name, priority)
            if identity in identities:
                issues.add("ACL-10", "duplicates TemplateGroup + ACLName + Priority", number, "Priority", priority, "use a unique priority for this ACL")
            identities.add(identity)
        for field_name in ("Application", "ApplicationGroup"):
            if "|" in row[field_name] or "," in row[field_name]:
                issues.add("ACL-22", "{} must be a single name".format(field_name), number, field_name, row[field_name], "use one name per ACL rule")
        lists = {field_name: members(row[field_name], issues, number, field_name) for family in ACL_FAMILIES for field_name in family}
        check_families(row, ACL_FAMILIES, issues, number)
        for field_name in ACL_FAMILIES[0]:
            for value in lists[field_name]:
                try:
                    warning = policy_ip(value)
                except ValueError as error:
                    issues.add("ACL-08", "invalid {} value {}: {}".format(field_name, value, error), number, field_name, value, "use an IPv4/IPv6 address, prefix, dotted mask, octet range, or whole-octet wildcard")
                else:
                    if warning:
                        warnings.add("ACL-07", warning, number, field_name, value)
        for field_name in ACL_FAMILIES[1]:
            check_ports(lists[field_name], issues, number, field_name)
        for field_name in ACL_FAMILIES[2]:
            for value in lists[field_name]:
                if not valid_domain(value):
                    issues.add("VAL-09", "invalid {} value {}".format(field_name, value), number, field_name, value, "use example.com, *.example.com, or *example.com")
        protocol = row["Protocol"].lower()
        if protocol and not valid_protocol(protocol):
            issues.add("VAL-06", "invalid Protocol", number, "Protocol", row["Protocol"], "use ip, tcp, udp, tcp/udp, icmp, icmpv6, or 0-255")
        if any(lists[field_name] for field_name in ACL_FAMILIES[1]) and protocol not in PORT_PROTOCOLS:
            issues.add("ACL-03", "ports require Protocol tcp, udp, tcp/udp, or blank", number, "Protocol", row["Protocol"], "change the protocol or remove the port criteria")
        try:
            permit = parse_bool(row["Permit"], "Permit")
        except ValidationError as error:
            issues.add("VAL-01", str(error), number, "Permit", row["Permit"], "Permit must be explicitly TRUE or FALSE")
        try:
            broad_ack = parse_bool(row["BroadMatchAck"], "BroadMatchAck", False)
        except ValidationError as error:
            issues.add("VAL-01", str(error), number, "BroadMatchAck", row["BroadMatchAck"], "use TRUE or FALSE")
        if len(issues) != start:
            continue
        criteria = {"application": row["Application"], "app_group": row["ApplicationGroup"], "protocol": protocol}
        keys = (("src_ip", "dst_ip", "either_ip"), ("src_port", "dst_port", "either_port"), ("src_dns", "dst_dns", "either_dns"))
        for family, family_keys in zip(ACL_FAMILIES, keys):
            criteria.update({key: row[field_name] for field_name, key in zip(family, family_keys) if row[field_name]})
        if not any(criteria.values()) and not broad_ack:
            issues.add("ACL-02", "unconditional ACL entry requires BroadMatchAck=TRUE", number, "BroadMatchAck", row["BroadMatchAck"], "add match criteria or set BroadMatchAck=TRUE")
            continue
        entry = {"permit": permit, "comment": row["Comment"]}
        entry.update({key: value for key, value in criteria.items() if value})
        if any(row[field_name] for field_name in ACL_FAMILIES[0]):
            entry["additionalSwitch_ip"] = "ips"
        if any(row[field_name] for field_name in ACL_FAMILIES[1]):
            entry["additionalSwitch_port"] = "ports"
        rules.append(TemplateACLRule(number, group, name, priority, entry, warnings.messages()))
    issues.raise_if_any()
    return rules


def _template_acl_value(group: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    for template in group.get("templates", []):
        if template.get("name") != "acls":
            continue
        value = template.get("valObject")
        if not isinstance(value, (dict, str)):
            value = template.get("value")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError as error:
                raise ValidationError("Access Lists template contains invalid JSON") from error
        if not isinstance(value, dict) or not isinstance(value.get("data", {}), dict) or not isinstance(value.get("options", {}), dict):
            raise ValidationError("Access Lists template has an invalid value")
        return copy.deepcopy(value)
    return None


def _template_group_snapshot(group: Optional[Mapping[str, Any]], selection: Sequence[str], associations: Sequence[str]) -> str:
    return fingerprint({"group": group, "selection": list(selection), "associations": sorted(associations)})


def _group_associations(name: str, associations: Mapping[str, Sequence[str]]) -> List[str]:
    return sorted(str(target) for target, groups in associations.items() if name in groups)


def _unrelated_templates(group: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    return [copy.deepcopy(template) for template in group.get("templates", []) if template.get("name") != "acls"]


def plan_template_acls(
    rules: Sequence[TemplateACLRule],
    groups: Sequence[Mapping[str, Any]],
    selections: Mapping[str, Sequence[str]],
    associations: Mapping[str, Sequence[str]],
    applications: Set[str],
    application_groups: Set[str],
) -> Dict[str, Any]:
    current = {str(group.get("name")): group for group in groups}
    default = _template_acl_value(current.get("Default Template Group", {})) if "Default Template Group" in current else None
    grouped: Dict[str, List[TemplateACLRule]] = {}
    for rule in rules:
        grouped.setdefault(rule.template_group, []).append(rule)
    plans = []
    for name, group_rules in grouped.items():
        baseline = current.get(name)
        selection = list(selections.get(name, []))
        targets = _group_associations(name, associations)
        errors = []
        warnings = [warning for rule in group_rules for warning in rule.warnings]
        known_applications = {name.lower() for name in applications}
        for rule in group_rules:
            application = rule.entry.get("application")
            application_group = rule.entry.get("app_group")
            if application and application.lower() not in known_applications:
                errors.append("row {} [DEP-03] missing application {}".format(rule.row, application))
            if application_group and application_group not in application_groups:
                errors.append("row {} [DEP-03] missing application group {}".format(rule.row, application_group))
        if baseline is None:
            if default is None:
                errors.append("cannot create template group without default Access Lists template options")
                baseline_value = {"data": {}, "options": {}}
            else:
                baseline_value = copy.deepcopy(default)
        else:
            value = _template_acl_value(baseline)
            if value is None:
                errors.append("template group {} has no Access Lists template".format(name))
                baseline_value = {"data": {}, "options": {}}
            else:
                baseline_value = value
        candidate = copy.deepcopy(baseline_value)
        candidate.setdefault("data", {})
        candidate.setdefault("options", {})["merge"] = True
        additions = []
        overwrites = []
        no_ops = []
        touched = set()
        for rule in group_rules:
            touched.add(rule.acl_name)
            body = candidate["data"].setdefault(rule.acl_name, {"entry": {}})
            if not isinstance(body, dict):
                errors.append("ACL {} in template group {} has an invalid body".format(rule.acl_name, name))
                continue
            entries = body.setdefault("entry", {})
            if not isinstance(entries, dict):
                errors.append("ACL {} in template group {} has invalid entries".format(rule.acl_name, name))
                continue
            before = entries.get(rule.priority)
            if before is None:
                entries[rule.priority] = copy.deepcopy(rule.entry)
                additions.append({"acl": rule.acl_name, "priority": rule.priority, "after": rule.entry})
            elif semantic_equal(normalize_acl_entries({rule.priority: before})[rule.priority], rule.entry):
                no_ops.append({"acl": rule.acl_name, "priority": rule.priority})
            else:
                entries[rule.priority] = copy.deepcopy(rule.entry)
                overwrites.append({"acl": rule.acl_name, "priority": rule.priority, "before": before, "after": rule.entry})
        requested = {(rule.acl_name, rule.priority) for rule in group_rules}
        preserved = []
        for acl_name, body in baseline_value.get("data", {}).items():
            if isinstance(body, dict) and isinstance(body.get("entry", {}), dict):
                preserved.extend({"acl": acl_name, "priority": str(priority)} for priority in body.get("entry", {}) if (acl_name, str(priority)) not in requested)
        candidate_selection = selection if "acls" in selection else selection + ["acls"]
        plans.append({
            "template_group": name,
            "eligible": not errors,
            "errors": errors,
            "warnings": warnings,
            "create": baseline is None,
            "baseline_group": copy.deepcopy(baseline),
            "baseline_acl_value": baseline_value,
            "candidate_acl_value": candidate,
            "baseline_selection": selection,
            "candidate_selection": candidate_selection,
            "associations": targets,
            "baseline_fingerprint": _template_group_snapshot(baseline, selection, targets),
            "unrelated_templates": _unrelated_templates(baseline) if baseline else [],
            "payload": {"name": name, "templates": [{"name": "acls", "valObject": candidate}]},
            "selection_change": "acls" not in selection,
            "template_mode_change": baseline is not None and baseline_value.get("options", {}).get("merge") is not True,
            "additions": additions,
            "overwrites": overwrites,
            "no_ops": no_ops,
            "preserved": sorted(preserved, key=lambda item: (item["acl"], item["priority"])),
            "selection_activates_acls": sorted(acl for acl, body in baseline_value.get("data", {}).items() if isinstance(body, dict) and body.get("entry")) if "acls" not in selection else [],
            "touched_acls": sorted(touched),
        })
    for plan in plans:
        shared_targets = set(plan["associations"])
        for acl_name in plan["touched_acls"]:
            candidate_entries = plan["candidate_acl_value"]["data"][acl_name]["entry"]
            for other_name, other in current.items():
                if other_name == plan["template_group"] or "acls" not in selections.get(other_name, []):
                    continue
                other_value = _template_acl_value(other)
                other_acl = other_value.get("data", {}).get(acl_name) if other_value else None
                if not isinstance(other_acl, dict) or not isinstance(other_acl.get("entry"), dict):
                    continue
                overlap = shared_targets & set(_group_associations(other_name, associations))
                conflicts = [priority for priority in set(candidate_entries) & set(other_acl["entry"]) if not semantic_equal(normalize_acl_entries({priority: candidate_entries[priority]})[priority], normalize_acl_entries({priority: other_acl["entry"][priority]})[priority])]
                if overlap and conflicts:
                    plan["errors"].append("ACL {} has conflicting priority {} in template group {} on shared targets {}".format(acl_name, ",".join(sorted(conflicts)), other_name, ",".join(sorted(overlap))))
                    plan["eligible"] = False
                else:
                    plan["warnings"].append("ACL {} also exists in template group {}{}".format(acl_name, other_name, " on shared targets" if overlap else ""))
    return {
        "groups": plans,
        "errors": [],
        "eligible_groups": [plan["template_group"] for plan in plans if plan["eligible"]],
        "application_dependencies": sorted({str(rule.entry["application"]) for rule in rules if rule.entry.get("application")}),
        "application_group_dependencies": sorted({str(rule.entry["app_group"]) for rule in rules if rule.entry.get("app_group")}),
    }


def _verify_template_acl_targets(gateway: Any, plan: Mapping[str, Any]) -> Dict[str, str]:
    targets = set(plan["associations"])
    if not targets:
        return {}
    appliances = {str(item.get("nePk") or item.get("id")): item for item in gateway.get_appliances()}
    results = {}
    expected = {name: plan["candidate_acl_value"]["data"][name]["entry"] for name in plan["touched_acls"]}
    timeout = getattr(getattr(gateway, "client", None), "config", None)
    deadline = time.monotonic() + getattr(timeout, "verification_timeout", 120.0)
    poll = getattr(timeout, "poll_interval", 5.0)
    pending = set(targets)
    while pending and time.monotonic() < deadline:
        for target in list(pending):
            appliance = appliances.get(target, {})
            try:
                reachability = gateway.get_reachability(target)
            except Exception:
                results[target] = "unverified"
                pending.remove(target)
                continue
            if int(reachability.get("state", appliance.get("state", 2))) != 1:
                results[target] = "unreachable"
                pending.remove(target)
                continue
            try:
                actual = gateway.get_appliance_acls(target)
            except Exception:
                continue
            missing = [name for name in expected if name not in actual]
            mismatched = [name for name in expected if name in actual and not semantic_equal(normalize_acl_entries(actual[name]), normalize_acl_entries(expected[name]))]
            if missing:
                results[target] = "acl_missing:{}".format(",".join(sorted(missing)))
            elif mismatched:
                results[target] = "acl_mismatch:{}".format(",".join(sorted(mismatched)))
            else:
                results[target] = "verified"
                pending.remove(target)
        if pending:
            time.sleep(poll)
    for target in pending:
        results[target] = "unverified"
    return results


def apply_template_acls(gateway: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    results = []
    wrote = False
    ineligible = [group["template_group"] for group in plan["groups"] if not group["eligible"]]
    for group in [item for item in plan["groups"] if item["eligible"]]:
        name = group["template_group"]
        current = gateway.get_template_group(name)
        selection = gateway.get_template_selection(name) if current is not None else []
        associations = _group_associations(name, gateway.get_template_associations())
        if _template_group_snapshot(current, selection, associations) != group["baseline_fingerprint"]:
            if wrote:
                results.append({"template_group": name, "status": "drift"})
                return {"status": "partial", "groups": results, "ineligible_groups": ineligible}
            raise DriftError("template group {} changed before write".format(name))
        changed = group["create"] or not semantic_equal(group["baseline_acl_value"], group["candidate_acl_value"])
        group_wrote = False
        start = int(time.time() * 1000)
        try:
            if group["create"]:
                gateway.create_template_group(group["payload"])
                wrote = group_wrote = True
            elif changed:
                gateway.post_template_group(name, group["payload"])
                wrote = group_wrote = True
            if group["selection_change"]:
                gateway.select_template_group(name, group["candidate_selection"])
                wrote = group_wrote = True
        except Exception as error:
            results.append({"template_group": name, "status": "partial", "error": str(error)})
            return {"status": "partial", "groups": results, "ineligible_groups": ineligible}
        readback = gateway.get_template_group(name)
        selected = gateway.get_template_selection(name)
        current_associations = _group_associations(name, gateway.get_template_associations())
        value = _template_acl_value(readback or {})
        central_verified = value is not None and semantic_equal(value, group["candidate_acl_value"])
        selection_verified = set(selected) == set(group["candidate_selection"])
        associations_verified = current_associations == group["associations"]
        unrelated_verified = group["create"] or semantic_equal(_unrelated_templates(readback or {}), group["unrelated_templates"])
        targets = _verify_template_acl_targets(gateway, dict(group, associations=current_associations)) if central_verified else {}
        actions = gateway.get_actions(start, int(time.time() * 1000)) if group_wrote else []
        audit = [item for item in actions if name in json.dumps(item, sort_keys=True)] if isinstance(actions, list) else []
        failed_audit = any(item.get("completionStatus") is False or item.get("taskStatus") == "FAILED" for item in audit)
        unresolved = not all((central_verified, selection_verified, associations_verified, unrelated_verified)) or any(status != "verified" for status in targets.values()) or failed_audit
        results.append({
            "template_group": name,
            "status": "partial" if unresolved else "no_op" if not changed and not group["selection_change"] else "success",
            "central_verified": central_verified,
            "selection_verified": selection_verified,
            "associations_verified": associations_verified,
            "unrelated_templates_verified": unrelated_verified,
            "targets": targets,
            "audit_matches": audit,
        })
        if not central_verified or not selection_verified or not associations_verified or not unrelated_verified:
            return {"status": "partial", "groups": results, "ineligible_groups": ineligible}
    partial = ineligible or any(item["status"] == "partial" for item in results)
    no_op = results and all(item["status"] == "no_op" for item in results)
    return {"status": "partial" if partial else "no_op" if no_op else "success", "groups": results, "ineligible_groups": ineligible}


def _validate_graph(rows: Sequence[Mapping[str, str]], existing: Set[str], included: str, excluded: Optional[str], issues: Issues) -> None:
    names = {row["Name"] for row in rows}
    graph: Dict[str, List[str]] = {name: [] for name in names}
    for row in rows:
        references = _csv_members(row[included])
        if excluded:
            references += _csv_members(row[excluded])
        missing = set(references) - names - existing
        if missing:
            issues.add("DEP-05", "references missing groups: {}".format(", ".join(sorted(missing))), row["_row"], included, fix="create the referenced groups first or add them to this CSV")
        graph[row["Name"]].extend(reference for reference in references if reference in names)
    if detect_cycle(graph):
        issues.add("AG-11", "group references contain a cycle", fix="remove the circular group reference")
        return

    def depth(node: str) -> int:
        children = [child for child in graph[node] if child in graph]
        return 0 if not children else 1 + max(depth(child) for child in children)

    if any(depth(name) > 2 for name in graph):
        issues.add("AG-12", "group nesting exceeds maximum depth 2", fix="flatten the nesting to a leaf plus at most two parent levels")


def _group_name(row: Mapping[str, str], issues: Issues) -> None:
    if not GROUP_NAME_PATTERN.fullmatch(row["Name"]):
        issues.add("AG-01", "invalid Name (1-64 letters, digits, dot, underscore, or hyphen)", row["_row"], "Name", row["Name"], "shorten the name or remove unsupported characters")


def parse_address_groups(path: str, existing_names: Iterable[str] = ()) -> List[Dict[str, str]]:
    issues = Issues()
    rows = _read_exact_csv(path, ADDRESS_HEADERS, issues)
    for row in rows:
        number = row["_row"]
        _group_name(row, issues)
        values = {name: members(row[name], issues, number, name, ",") for name in ("IncludedIPs", "ExcludedIPs", "IncludedGroups")}
        for name in ("IncludedIPs", "ExcludedIPs"):
            for value in values[name]:
                try:
                    address_group_ipv4(value)
                except ValueError as error:
                    issues.add("AG-02", "invalid {} value {}: {}".format(name, value, error), number, name, value, "use an IPv4 address, prefix, dotted mask, octet range, or wildcard octet")
        if not values["IncludedIPs"] and not values["IncludedGroups"]:
            issues.add("AG-05", "requires IncludedIPs or IncludedGroups", number, "IncludedIPs", fix="add included addresses or groups; exclusions alone match nothing")
        overlap = sorted(set(values["IncludedIPs"]) & set(values["ExcludedIPs"]))
        if overlap:
            issues.add("AG-07", "the same value is both included and excluded: {}".format(", ".join(overlap)), number, "ExcludedIPs", fix="remove the value from one of the columns")
    _validate_graph(rows, set(existing_names), "IncludedGroups", None, issues)
    issues.raise_if_any()
    return rows


def _icmp_type_values(values: Sequence[str], issues: Issues, number: Any, field_name: str, allow_range: bool) -> None:
    for value in values:
        pattern = ICMP_TYPE_PATTERN if allow_range else re.compile(r"^[0-9]{1,3}$")
        ends = [int(part) for part in value.split("-")] if pattern.fullmatch(value) else []
        if not ends or any(end > 255 for end in ends) or len(ends) == 2 and ends[0] > ends[1]:
            issues.add("SG-05", "invalid {} value {}".format(field_name, value), number, field_name, value, "use 0-255{}".format(" or a range such as 4-8" if allow_range else ""))


def parse_service_groups(path: str, existing_names: Iterable[str] = ()) -> List[Dict[str, str]]:
    issues = Issues()
    rows = _read_exact_csv(path, SERVICE_HEADERS, issues)
    for row in rows:
        number = row["_row"]
        _group_name(row, issues)
        protocol = row["Protocol"].upper()
        if protocol not in {"TCP", "UDP", "ICMP", "ICMPV6"}:
            issues.add("SG-01", "invalid Protocol", number, "Protocol", row["Protocol"], "use TCP, UDP, ICMP, or ICMPV6")
        values = {name: members(row[name], issues, number, name, ",") for name in ("IncludedPorts", "ExcludedPorts", "IncludedGroups", "ExcludedGroups", "IcmpTypes", "IcmpCodes")}
        check_ports(values["IncludedPorts"], issues, number, "IncludedPorts", True)
        check_ports(values["ExcludedPorts"], issues, number, "ExcludedPorts", True)
        _icmp_type_values(values["IcmpTypes"], issues, number, "IcmpTypes", True)
        _icmp_type_values(values["IcmpCodes"], issues, number, "IcmpCodes", False)
        for included, excluded in (("IncludedPorts", "ExcludedPorts"), ("IncludedGroups", "ExcludedGroups")):
            overlap = sorted(set(values[included]) & set(values[excluded]))
            if overlap:
                issues.add("SG-07", "the same value is both included and excluded: {}".format(", ".join(overlap)), number, excluded, fix="remove the value from one of the columns")
        if protocol in {"TCP", "UDP"}:
            if not values["IncludedPorts"] and not values["IncludedGroups"]:
                issues.add("SG-02", "TCP/UDP requires IncludedPorts or IncludedGroups", number, "IncludedPorts", fix="add included ports or groups")
            if values["IcmpTypes"] or values["IcmpCodes"]:
                issues.add("SG-02", "TCP/UDP cannot include ICMP fields", number, "IcmpTypes", fix="clear IcmpTypes and IcmpCodes")
        elif protocol in {"ICMP", "ICMPV6"}:
            if not values["IcmpTypes"]:
                issues.add("SG-02", "ICMP/ICMPV6 requires IcmpTypes", number, "IcmpTypes", fix="add at least one ICMP type")
            if any(values[name] for name in ("IncludedPorts", "ExcludedPorts", "IncludedGroups", "ExcludedGroups")):
                issues.add("SG-02", "ICMP/ICMPV6 cannot include port/group fields", number, "IncludedPorts", fix="clear port and group columns")
            if values["IcmpCodes"] and (len(values["IcmpTypes"]) != 1 or "-" in values["IcmpTypes"][0]):
                issues.add("SG-11", "IcmpCodes requires exactly one IcmpType (not a range)", number, "IcmpCodes", fix="use a single ICMP type or clear IcmpCodes")
    _validate_graph(rows, set(existing_names), "IncludedGroups", "ExcludedGroups", issues)
    issues.raise_if_any()
    return rows


def _port_ranges(values: Sequence[str]) -> List[Tuple[int, int]]:
    result = []
    for value in values:
        ends = [int(part) for part in value.split("-")]
        result.append((ends[0], ends[-1]))
    return result


def _native_group_warnings(kind: str, rows: Sequence[Mapping[str, str]], existing: Sequence[Mapping[str, Any]], content: bytes) -> List[str]:
    warnings = Issues("")
    limit = ADDRESS_GROUP_LIMIT if kind == "address" else SERVICE_GROUP_LIMIT
    size = len(canonical_json(list(existing)).encode("utf-8")) + len(content)
    if size > limit:
        warnings.add("AG-16" if kind == "address" else "SG-14", "estimated group definitions size {} bytes exceeds the documented {} MB limit".format(size, limit // (1024 * 1024)))
    if kind == "service":
        for row in rows:
            included = _csv_members(row["IncludedPorts"])
            if not included or "*" in included or row["IncludedGroups"]:
                continue
            ranges = _port_ranges(included)
            for low, high in _port_ranges([port for port in _csv_members(row["ExcludedPorts"]) if port != "*"]):
                if not any(start <= low and high <= end for start, end in ranges):
                    warnings.add("SG-06", "excluded ports {}-{} are outside the included ports and have no effect".format(low, high) if low != high else "excluded port {} is outside the included ports and has no effect".format(low), row["_row"], "ExcludedPorts")
    return warnings.messages()


def native_csv_bytes(rows: Sequence[Mapping[str, str]], headers: Sequence[str]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, headers, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in headers})
    return stream.getvalue().encode("utf-8")


def _address_semantic(rows: Sequence[Mapping[str, str]]) -> Dict[str, Any]:
    return {"name": rows[0]["Name"], "type": "AG", "rules": [{"includedIPs": _csv_members(row["IncludedIPs"]), "excludedIPs": _csv_members(row["ExcludedIPs"]), "includedGroups": _csv_members(row["IncludedGroups"]), "comment": row["Comment"] or None} for row in rows]}


def _service_semantic(rows: Sequence[Mapping[str, str]]) -> Dict[str, Any]:
    return {"name": rows[0]["Name"], "type": "SG", "rules": [{"protocol": row["Protocol"].upper(), "includedPorts": _csv_members(row["IncludedPorts"]), "excludedPorts": _csv_members(row["ExcludedPorts"]), "includedGroups": _csv_members(row["IncludedGroups"]), "excludedGroups": _csv_members(row["ExcludedGroups"]), "icmpTypes": _csv_members(row["IcmpTypes"]), "icmpCodes": _csv_members(row["IcmpCodes"]), "comment": row["Comment"] or None} for row in rows]}


def native_group_semantic_equal(actual: Any, expected: Mapping[str, Any]) -> bool:
    if not isinstance(actual, Mapping) or actual.get("type") not in {None, expected.get("type")}:
        return False
    normalized_actual = dict(actual)
    normalized_expected = dict(expected)
    normalized_actual.pop("type", None)
    normalized_expected.pop("type", None)
    return semantic_equal(normalized_actual, normalized_expected)


@dataclass
class BulkPlan:
    kind: str
    new_rows: List[Dict[str, str]]
    no_ops: List[str]
    conflicts: List[str]
    content: bytes
    baseline_fingerprint: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


def plan_native_groups(kind: str, rows: Sequence[Mapping[str, str]], existing: Sequence[Mapping[str, Any]]) -> BulkPlan:
    if kind not in {"address", "service"}:
        raise ValueError("kind must be address or service")
    current = {str(item.get("name")): item for item in existing}
    normalizer = _address_semantic if kind == "address" else _service_semantic
    new_rows: List[Dict[str, str]] = []
    no_ops: List[str] = []
    conflicts: List[str] = []
    grouped: Dict[str, List[Mapping[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row["Name"], []).append(row)
    graph: Dict[str, List[str]] = {}
    for name, item in current.items():
        graph[name] = [str(reference) for rule in item.get("rules", []) for field in (("includedGroups", "excludedGroups") if kind == "service" else ("includedGroups",)) for reference in rule.get(field, [])]
    for name, group_rows in grouped.items():
        fields = ("IncludedGroups", "ExcludedGroups") if kind == "service" else ("IncludedGroups",)
        graph[name] = [reference for row in group_rows for field in fields for reference in _csv_members(row[field])]
    if detect_cycle(graph):
        raise ValidationError("group references contain a cycle")

    def graph_depth(name: str) -> int:
        children = [child for child in graph.get(name, []) if child in graph]
        return 0 if not children else 1 + max(graph_depth(child) for child in children)

    if any(graph_depth(name) > 2 for name in grouped):
        raise ValidationError("group nesting exceeds maximum depth 2")
    for name, group_rows in grouped.items():
        expected = normalizer(group_rows)
        actual = current.get(name)
        if actual is None:
            new_rows.extend(dict(row) for row in group_rows)
        elif native_group_semantic_equal(actual, expected):
            no_ops.append(name)
        else:
            conflicts.append(name)
    headers = ADDRESS_HEADERS if kind == "address" else SERVICE_HEADERS
    content = native_csv_bytes(new_rows, headers)
    return BulkPlan(kind, new_rows, no_ops, conflicts, content, fingerprint(existing), _native_group_warnings(kind, rows, existing, content))


def apply_native_groups(gateway: Any, plan: BulkPlan) -> Dict[str, Any]:
    if plan.conflicts:
        raise ValidationError("conflicting existing groups: {}".format(", ".join(plan.conflicts)))
    if plan.kind == "address":
        current = gateway.get_address_groups()
        normalizer = _address_semantic
    else:
        current = gateway.get_service_groups()
        normalizer = _service_semantic
    if plan.baseline_fingerprint is not None and fingerprint(current) != plan.baseline_fingerprint:
        raise DriftError("native group inventory changed before write")
    if not plan.new_rows:
        return {"status": "no_op", "created": []}
    grouped: Dict[str, List[Mapping[str, str]]] = {}
    for row in plan.new_rows:
        grouped.setdefault(row["Name"], []).append(row)
    try:
        if plan.kind == "address":
            response = gateway.upload_address_groups(plan.content)
        else:
            response = gateway.upload_service_groups(plan.content)
    except Exception as error:
        return {"status": "partial", "created": [], "error": str(error), "all_or_nothing": True}
    try:
        readback = gateway.get_address_groups() if plan.kind == "address" else gateway.get_service_groups()
    except Exception as error:
        return {"status": "partial", "created": list(grouped), "error": str(error), "verification": "unknown", "all_or_nothing": True}
    current = {str(item.get("name")): item for item in readback}
    missing = [name for name, rows in grouped.items() if not native_group_semantic_equal(current.get(name), normalizer(rows))]
    return {"status": "success" if not missing else "partial", "created": list(grouped), "unverified": missing, "bulk_response": response}


@dataclass
class ZonePlan:
    baseline: Mapping[str, Any]
    candidate: Mapping[str, Any]
    baseline_fingerprint: str
    created: Mapping[str, int]
    all_vrf_fingerprint: Optional[str] = None
    mappings_fingerprint: Optional[str] = None


def plan_zones(existing: Mapping[str, Any], next_id: int, names: Sequence[str], all_vrf: Any = None, mappings: Any = None) -> ZonePlan:
    if len(set(names)) != len(names):
        raise ValidationError("missing zone names must be unique")
    current_names = {str(value.get("name")) for value in existing.values()}
    candidate = copy.deepcopy(dict(existing))
    created: Dict[str, int] = {}
    zone_id = next_id
    for name in names:
        if not ZONE_PATTERN.fullmatch(name) or name == "Default":
            raise ValidationError("invalid or reserved zone name {}".format(name))
        if name in current_names:
            continue
        while str(zone_id) in candidate:
            zone_id += 1
        candidate[str(zone_id)] = {"name": name}
        created[name] = zone_id
        zone_id += 1
    return ZonePlan(existing, candidate, fingerprint(existing), created, fingerprint(all_vrf) if all_vrf is not None else None, fingerprint(mappings) if mappings is not None else None)


def apply_zones(gateway: Any, plan: ZonePlan) -> Dict[str, Any]:
    current = gateway.get_zones()
    if fingerprint(current) != plan.baseline_fingerprint:
        raise DriftError("zone collection changed before write")
    if plan.all_vrf_fingerprint is not None and fingerprint(gateway.get_all_vrf_zones()) != plan.all_vrf_fingerprint:
        raise DriftError("all-VRF zone collection changed before write")
    if plan.mappings_fingerprint is not None and fingerprint(gateway.get_zone_mappings()) != plan.mappings_fingerprint:
        raise DriftError("segment-zone mappings changed before write")
    if not plan.created:
        return {"status": "no_op", "created": {}}
    gateway.post_zones(plan.candidate)
    readback = gateway.get_zones()
    mappings = gateway.get_zone_mappings()
    all_vrf = gateway.get_all_vrf_zones() if hasattr(gateway, "get_all_vrf_zones") else None
    mapped = {(item.get("zoneName"), int(item.get("zoneId"))) for item in mappings if isinstance(item, dict)}
    collection_verified = semantic_equal(readback, plan.candidate)
    mappings_verified = all((name, zone_id) in mapped for name, zone_id in plan.created.items())
    all_vrf_verified = all_vrf is None or all(name in str(all_vrf) for name in plan.created)
    valid = collection_verified and mappings_verified and all_vrf_verified
    return {"status": "success" if valid else "partial", "created": dict(plan.created), "collection_verified": collection_verified, "mappings_verified": mappings_verified, "all_vrf_verified": all_vrf_verified}


def parse_application_groups(path: str) -> List[Dict[str, str]]:
    rows = _read_exact_csv(path, APP_GROUP_HEADERS)
    names = {row["Name"] for row in rows}
    if len(names) != len(rows):
        raise ValidationError("application group names must be unique")
    graph = {row["Name"]: _csv_members(row["ParentGroups"]) for row in rows}
    if detect_cycle(graph):
        raise ValidationError("application group parents contain a cycle")
    return rows


def parse_application_groups_partial(path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]]]:
    rows = _read_exact_csv(path, APP_GROUP_HEADERS)
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["Name"]] = counts.get(row["Name"], 0) + 1
    skipped = []
    eligible = []
    for row in rows:
        hygiene = Issues("this application group")
        for name in ("Applications", "ParentGroups"):
            members(row[name], hygiene, row["_row"], name, ",")
        if not row["Name"] or not NAME_PATTERN.fullmatch(row["Name"]):
            skipped.append({"row": int(row["_row"]), "name": row["Name"] or "<blank>", "reason": "invalid application group name"})
        elif counts[row["Name"]] > 1:
            skipped.append({"row": int(row["_row"]), "name": row["Name"], "reason": "duplicate application group name in CSV"})
        elif not _csv_members(row["Applications"]) and not _csv_members(row["ParentGroups"]):
            skipped.append({"row": int(row["_row"]), "name": row["Name"], "reason": "[APG-03] empty application group requires Applications or ParentGroups"})
        elif hygiene:
            skipped.append({"row": int(row["_row"]), "name": row["Name"], "reason": "; ".join(hygiene.messages())})
        else:
            eligible.append(row)
    return eligible, skipped


def _cycle_nodes(graph: Mapping[str, Sequence[str]]) -> Set[str]:
    state: Dict[str, int] = {}
    stack: List[str] = []
    cyclic: Set[str] = set()

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for child in graph.get(node, []):
            if child not in graph:
                continue
            if state.get(child, 0) == 0:
                visit(child)
            elif state.get(child) == 1:
                cyclic.update(stack[stack.index(child):])
        stack.pop()
        state[node] = 2

    for node in graph:
        if state.get(node, 0) == 0:
            visit(node)
    return cyclic


def plan_application_groups(rows: Sequence[Mapping[str, str]], existing: Mapping[str, Any], applications: Set[str], initial_skips: Sequence[Mapping[str, Any]] = ()) -> Dict[str, Any]:
    row_map = {row["Name"]: row for row in rows}
    row_names = set(row_map)
    skipped: Dict[str, Dict[str, Any]] = {str(item["name"]): dict(item) for item in initial_skips}
    expected: Dict[str, Dict[str, Any]] = {}
    known_applications = {application.lower() for application in applications}
    for name, row in row_map.items():
        apps = sorted(set(_csv_members(row["Applications"])))
        parents = sorted(set(_csv_members(row["ParentGroups"])))
        missing_apps = sorted(app for app in apps if app.lower() not in known_applications)
        missing_parents = sorted(set(parents) - row_names - set(existing))
        reason = ""
        if missing_apps:
            reason = "missing applications: {}".format(", ".join(missing_apps))
        elif missing_parents:
            reason = "missing parents: {}".format(", ".join(missing_parents))
        elif name in existing and not semantic_equal(existing[name], {"apps": apps, "parentGroup": parents or None}):
            reason = "existing application group has different semantics"
        if reason:
            skipped[name] = {"row": int(row["_row"]), "name": name, "reason": reason}
        expected[name] = {"apps": apps, "parentGroup": parents or None}
    graph = {name: list(value.get("parentGroup") or []) for name, value in expected.items()}
    for name in _cycle_nodes(graph):
        row = row_map[name]
        skipped[name] = {"row": int(row["_row"]), "name": name, "reason": "application group parent cycle"}
    changed = True
    while changed:
        changed = False
        for name, value in expected.items():
            if name in skipped:
                continue
            bad_parents = sorted(set(value.get("parentGroup") or []) & set(skipped))
            if bad_parents:
                skipped[name] = {"row": int(row_map[name]["_row"]), "name": name, "reason": "depends on skipped parents: {}".format(", ".join(bad_parents))}
                changed = True
    candidate = copy.deepcopy(dict(existing))
    no_ops = []
    for name, value in expected.items():
        if name in skipped:
            continue
        if name in existing:
            no_ops.append(name)
        else:
            candidate[name] = value
    return {"baseline": dict(existing), "candidate": candidate, "fingerprint": fingerprint(existing), "conflicts": [], "skipped_conflicts": sorted(skipped.values(), key=lambda item: (item.get("row", 0), item["name"])), "no_ops": no_ops}


def apply_application_groups(gateway: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    if plan["conflicts"]:
        raise ValidationError("conflicting application groups: {}".format(", ".join(plan["conflicts"])))
    current = gateway.get_application_groups()
    if fingerprint(current) != plan["fingerprint"]:
        raise DriftError("application group collection changed before write")
    if semantic_equal(plan["baseline"], plan["candidate"]):
        return {"status": "no_op"}
    gateway.post_application_groups(plan["candidate"])
    readback = gateway.get_application_groups()
    return {"status": "success" if semantic_equal(readback, plan["candidate"]) else "partial"}


@dataclass
class ApplicationDefinition:
    row: int
    definition_type: str
    name: str
    payload: Dict[str, Any]
    identity: Any
    app_express: str


COMPOUND_FAMILIES = (
    (("SourcePort", "DestinationPort", "EitherPort"), ("src_port", "dst_port", "either_port")),
    (("SourceIP", "DestinationIP", "EitherIP"), ("src_ip", "dst_ip", "either_ip")),
    (("SourceGeo", "DestinationGeo", "EitherGeo"), ("src_geo", "dst_geo", "either_geo")),
    (("SourceDomain", "DestinationDomain", "EitherDomain"), ("src_dns", "dst_dns", "either_dns")),
    (("SourceAddressMap", "DestinationAddressMap", "EitherAddressMap"), ("src_service", "dst_service", "either_service")),
)
DEFINITION_FIELDS = {
    "IP_PROTOCOL": {"ProtocolNumber", "Port"},
    "TCP_PORT": {"Port"},
    "UDP_PORT": {"Port"},
    "DOMAIN": {"Domain"},
    "COMPOUND": {"Protocol", "DSCP", "Interface"} | {name for fields, _ in COMPOUND_FAMILIES for name in fields},
}


def parse_application_definitions(path: str) -> List[ApplicationDefinition]:
    issues = Issues()
    rows = _read_exact_csv(path, APP_DEF_HEADERS, issues)
    definitions: List[ApplicationDefinition] = []
    spellings: Dict[str, Tuple[str, int]] = {}
    for row in rows:
        number = int(row["_row"])
        start = len(issues)
        definition_type = row["DefinitionType"].upper()
        if definition_type not in DEFINITION_FIELDS:
            issues.add("AD-01", "unsupported DefinitionType", number, "DefinitionType", row["DefinitionType"], "use IP_PROTOCOL, TCP_PORT, UDP_PORT, DOMAIN, or COMPOUND")
            continue
        name = row["Name"]
        if definition_type == "COMPOUND" and not APP_NAME_PATTERN.fullmatch(name):
            issues.add("AD-07", "Name must be 1-31 characters using letters, numbers, hyphen, or underscore for COMPOUND", number, "Name", name, "remove dots, spaces, and other characters")
        elif definition_type != "COMPOUND" and not SIMPLE_APP_NAME_PATTERN.fullmatch(name):
            issues.add("AD-07", "Name must be 1-31 characters using letters, numbers, dot, hyphen, or underscore", number, "Name", name, "shorten the name or remove unsupported characters")
        first = spellings.setdefault(name.lower(), (name, number))
        if first[0] != name:
            issues.add("AD-07", "application names are not case-sensitive; row {} spells this name {!r}".format(first[1], first[0]), number, "Name", name, "use one spelling for the same application")
        if "|" in row["Notes"]:
            issues.add("AD-02", "Notes cannot contain |", number, "Notes", fix="remove the | character")
        common_fields = {"DefinitionType", "Name", "Notes", "Enabled", "Confidence", "AppExpressMode", "_row"}
        unexpected = sorted(name_ for name_ in APP_DEF_HEADERS if name_ not in common_fields | DEFINITION_FIELDS[definition_type] and row.get(name_))
        if unexpected:
            issues.add("AD-03", "fields are not valid for {}: {}".format(definition_type, ", ".join(unexpected)), number, unexpected[0], fix="clear the listed columns")
        try:
            enabled = parse_bool(row["Enabled"], "Enabled", True)
        except ValidationError as error:
            issues.add("VAL-01", str(error), number, "Enabled", row["Enabled"], "use TRUE or FALSE")
        confidence_text = row["Confidence"] or "100"
        if not confidence_text.isdigit() or not 1 <= int(confidence_text) <= 100:
            issues.add("AD-04", "Confidence must be 1..100", number, "Confidence", row["Confidence"], "use a whole number 1-100")
        mode = (row["AppExpressMode"] or "OFF").upper()
        if mode not in {"OFF", "MONITOR"}:
            issues.add("AD-05", "AppExpressMode must be OFF or MONITOR", number, "AppExpressMode", row["AppExpressMode"], "use OFF or MONITOR")
        if len(issues) != start:
            continue
        common = {"name": name, "description": row["Notes"], "priority": int(confidence_text), "disabled": not enabled}
        if definition_type == "DOMAIN":
            if not row["Domain"]:
                issues.add("AD-06", "DOMAIN requires Domain", number, "Domain", fix="add a domain such as example.com or *.example.com")
            elif not valid_domain(row["Domain"]):
                issues.add("VAL-09", "invalid Domain value {}".format(row["Domain"]), number, "Domain", row["Domain"], "use example.com, *.example.com, or *example.com")
            payload: Optional[Dict[str, Any]] = dict(common, domain=row["Domain"])
            identity: Any = row["Domain"]
        elif definition_type == "IP_PROTOCOL":
            if not row["ProtocolNumber"].isdigit() or int(row["ProtocolNumber"]) > 255:
                issues.add("AD-06", "IP_PROTOCOL requires ProtocolNumber 0..255", number, "ProtocolNumber", row["ProtocolNumber"], "use 0-255")
            if row["Port"] not in {"", "0"}:
                issues.add("AD-06", "IP_PROTOCOL Port must be blank or 0", number, "Port", row["Port"], "clear Port")
            protocol = int(row["ProtocolNumber"]) if row["ProtocolNumber"].isdigit() else 0
            payload, identity = dict(common, protocol=protocol, port="0"), ("0", protocol)
        elif definition_type in {"TCP_PORT", "UDP_PORT"}:
            if not row["Port"].isdigit() or not 1 <= int(row["Port"]) <= 65535:
                issues.add("AD-06", "{} requires one numeric Port from 1 to 65535".format(definition_type), number, "Port", row["Port"], "use one port; use COMPOUND for ranges or lists")
            protocol = 6 if definition_type == "TCP_PORT" else 17
            payload, identity = dict(common, protocol=protocol, port=row["Port"]), (row["Port"], protocol)
        else:
            payload, identity = _compound_payload(row, common, issues), None
        if len(issues) == start and payload is not None:
            definitions.append(ApplicationDefinition(number, definition_type, name, payload, identity, mode))
    issues.raise_if_any()
    return definitions


@dataclass
class ApplicationDefinitionPlan:
    new: List[ApplicationDefinition]
    no_ops: List[str]
    conflicts: List[Dict[str, Any]]
    fingerprints: Dict[str, str]


def plan_application_definitions(definitions: Sequence[ApplicationDefinition], inventories: Mapping[str, Any]) -> ApplicationDefinitionPlan:
    base_map = {"IP_PROTOCOL": "portProtocolClassification", "TCP_PORT": "portProtocolClassification", "UDP_PORT": "portProtocolClassification", "DOMAIN": "dnsClassification", "COMPOUND": "compoundClassification"}
    new: List[ApplicationDefinition] = []
    no_ops: List[str] = []
    conflicts: List[Dict[str, Any]] = []
    compounds = inventories.get("compoundClassification", {})

    def add_conflict(definition: ApplicationDefinition, reason: str) -> None:
        identity = definition.name if definition.definition_type == "COMPOUND" else definition.identity
        conflicts.append({"row": definition.row, "name": definition.name, "definition_type": definition.definition_type, "identity": identity, "reason": reason})
    seen_compounds: Set[str] = set()
    seen_identities: Set[Tuple[str, str]] = set()
    for definition in definitions:
        base = base_map[definition.definition_type]
        inventory = inventories.get(base, {})
        if definition.definition_type == "COMPOUND":
            if definition.name in seen_compounds:
                add_conflict(definition, "duplicate compound name in CSV")
                continue
            seen_compounds.add(definition.name)
            matches = [value for value in inventory.values() if isinstance(value, dict) and value.get("name") == definition.name]
            if matches:
                expected = dict(definition.payload)
                actual = dict(matches[0])
                actual.pop("id", None)
                if semantic_equal(actual, expected):
                    no_ops.append(definition.name)
                else:
                    add_conflict(definition, "existing compound name has different semantics")
            else:
                new.append(ApplicationDefinition(definition.row, definition.definition_type, definition.name, dict(definition.payload), definition.name, definition.app_express))
        elif definition.definition_type == "DOMAIN":
            identity_key = (base, str(definition.identity))
            if identity_key in seen_identities:
                add_conflict(definition, "duplicate domain identity in CSV")
                continue
            seen_identities.add(identity_key)
            matches = [item for item in inventory if item.get("domain") == definition.identity]
            if not matches:
                new.append(definition)
            elif any(_simple_definition_equal(item, definition.payload) for item in matches):
                no_ops.append(definition.name)
            else:
                add_conflict(definition, "existing domain identity has different semantics")
        else:
            identity_key = (base, "{}:{}".format(*definition.identity))
            if identity_key in seen_identities:
                add_conflict(definition, "duplicate port/protocol identity in CSV")
                continue
            seen_identities.add(identity_key)
            entries = inventory.get(str(definition.identity[0]), []) if isinstance(inventory, dict) else []
            matches = [item for item in entries if int(item.get("protocol", -1)) == definition.identity[1]]
            if not matches:
                new.append(definition)
            elif any(_simple_definition_equal(item, definition.payload) for item in matches):
                no_ops.append(definition.name)
            else:
                add_conflict(definition, "existing port/protocol identity has different semantics")
    return ApplicationDefinitionPlan(new, no_ops, conflicts, {base: fingerprint(value) for base, value in inventories.items()})


def _simple_definition_equal(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _compound_payload(row: Mapping[str, str], common: Mapping[str, Any], issues: Issues) -> Optional[Dict[str, Any]]:
    number = row["_row"]
    start = len(issues)
    payload = dict(common)
    attributes = 0
    lists: Dict[str, List[str]] = {}
    check_families(row, [fields for fields, _ in COMPOUND_FAMILIES], issues, number)
    for fields, keys in COMPOUND_FAMILIES:
        for field_name, key in zip(fields, keys):
            lists[key] = members(row[field_name], issues, number, field_name)
            payload[key] = ",".join(lists[key])
            attributes += len(lists[key])
    for key, field_name in zip(("src_port", "dst_port", "either_port"), COMPOUND_FAMILIES[0][0]):
        check_ports(lists[key], issues, number, field_name)
    for key, field_name in zip(("src_ip", "dst_ip", "either_ip"), COMPOUND_FAMILIES[1][0]):
        for value in lists[key]:
            try:
                compound_ipv4(value)
            except ValueError as error:
                issues.add("CMP-11", "contains invalid compound IP {}: {}".format(value, error), number, field_name, value, "use an IPv4 address, prefix, or octet range")
    for key, field_name in zip(("src_geo", "dst_geo", "either_geo"), COMPOUND_FAMILIES[2][0]):
        for value in lists[key]:
            if not GEO_PATTERN.fullmatch(value):
                issues.add("CMP-08", "invalid country {}".format(value), number, field_name, value, "use an ISO alpha-2 code such as US or the exact country name")
    for key, field_name in zip(("src_dns", "dst_dns", "either_dns"), COMPOUND_FAMILIES[3][0]):
        for value in lists[key]:
            if not valid_domain(value):
                issues.add("VAL-09", "invalid {} value {}".format(field_name, value), number, field_name, value, "use example.com, *.example.com, or *example.com")
    for key, field_name in zip(("src_service", "dst_service", "either_service"), COMPOUND_FAMILIES[4][0]):
        for value in lists[key]:
            if not REFERENCE_PATTERN.fullmatch(value):
                issues.add("CMP-10", "invalid address map name {}".format(value), number, field_name, value, "use the exact Address Map name")
    protocol = row["Protocol"].lower()
    if protocol and not valid_protocol(protocol):
        issues.add("VAL-06", "invalid compound Protocol {}".format(row["Protocol"]), number, "Protocol", row["Protocol"], "use ip, tcp, udp, tcp/udp, icmp, icmpv6, or 0-255")
    if protocol in {"icmp", "icmpv6", "1", "58"} and any(lists[key] for key in ("src_port", "dst_port", "either_port")):
        issues.add("CMP-06", "ICMP protocols cannot be combined with ports", number, "Protocol", row["Protocol"], "remove the ports or change the protocol")
    dscp = row["DSCP"]
    if dscp:
        try:
            dscp = normalize_dscp(dscp)
        except ValueError as error:
            issues.add("CMP-07", str(error), number, "DSCP", row["DSCP"], "use 0-63 or ef, af11-af43, cs0-cs7, be")
    if row["Interface"] and not REFERENCE_PATTERN.fullmatch(row["Interface"]):
        issues.add("CMP-09", "invalid Interface", number, "Interface", row["Interface"], "use an interface label name or numeric label ID")
    payload.update(protocol=protocol, dscp=dscp, vlan=row["Interface"])
    attributes += sum(1 for value in (protocol, dscp, row["Interface"]) if value)
    if attributes < 2:
        issues.add("CMP-02", "compound definition requires at least two attributes", number, fix="add another match attribute or use a dedicated definition type")
    non_port_match = any(payload.get(key) for key in ("src_ip", "dst_ip", "either_ip", "src_dns", "dst_dns", "either_dns", "src_geo", "dst_geo", "either_geo", "src_service", "dst_service", "either_service", "vlan", "dscp"))
    port_values = [lists[key] for key in ("src_port", "dst_port", "either_port") if lists[key]]
    if protocol in {"tcp", "udp"} and len(port_values) == 1 and len(port_values[0]) == 1 and not non_port_match:
        issues.add("CMP-03", "simple TCP/UDP port rule must use its dedicated definition type", number, fix="use TCP_PORT or UDP_PORT")
    other_than_either_dns = any(payload.get(key) for key in ("src_ip", "dst_ip", "either_ip", "src_port", "dst_port", "either_port", "src_dns", "dst_dns", "src_geo", "dst_geo", "either_geo", "src_service", "dst_service", "either_service", "vlan", "dscp"))
    if payload.get("either_dns") and not other_than_either_dns:
        issues.add("CMP-03", "simple either-direction domain rule must use the dedicated definition type", number, fix="use DOMAIN or add another compound criterion")
    criteria_length = sum(len(str(value)) for key, value in payload.items() if key not in {"name", "description", "disabled", "priority"} and value)
    if criteria_length > 512:
        issues.add("CMP-04", "compound definition exceeds 512 characters", number, fix="split the criteria into several definitions")
    if len(issues) != start:
        return None
    payload["confidence"] = payload.pop("priority")
    return payload


def _country_codes(raw: Mapping[str, Any]) -> Dict[str, str]:
    codes: Dict[str, str] = {}
    for name, value in raw.items():
        if isinstance(value, list) and len(value) > 3 and value[3]:
            code = str(value[3]).upper()
            codes[str(name).lower()] = code
            codes[code.lower()] = code
    return codes


def _label_ids(raw: Mapping[str, Any]) -> Tuple[Dict[str, List[str]], Set[str]]:
    names: Dict[str, List[str]] = {}
    ids: Set[str] = set()
    for labels in raw.values():
        for label_id, value in (labels or {}).items():
            if isinstance(value, dict) and value.get("active") is not False:
                ids.add(str(label_id))
                names.setdefault(str(value.get("name", "")).lower(), []).append(str(label_id))
    return names, ids


def resolve_compound_references(definitions: Sequence[ApplicationDefinition], gateway: Any) -> List[ApplicationDefinition]:
    issues = Issues()
    cache: Dict[str, Any] = {}

    def countries() -> Dict[str, str]:
        if "countries" not in cache:
            cache["countries"] = _country_codes(gateway.get_countries())
        return cache["countries"]

    def address_map(name: str) -> Optional[str]:
        key = "map:" + name.lower()
        if key not in cache:
            cache[key] = next((str(item["name"]) for item in gateway.search_address_map(name) if str(item.get("name", "")).lower() == name.lower()), None)
        return cache[key]

    resolved: List[ApplicationDefinition] = []
    for definition in definitions:
        if definition.definition_type != "COMPOUND":
            resolved.append(definition)
            continue
        payload = dict(definition.payload)
        for key in ("src_geo", "dst_geo", "either_geo"):
            if not payload.get(key):
                continue
            codes = countries()
            if not codes:
                issues.add("CMP-08", "country inventory is empty or still loading", definition.row, key, fix="retry after Orchestrator finishes loading IP intelligence data")
                continue
            values = [codes.get(member.lower()) for member in payload[key].split(",")]
            for member, code in zip(payload[key].split(","), values):
                if code is None:
                    issues.add("CMP-08", "unknown country {}".format(member), definition.row, key, member, "use an ISO alpha-2 code such as US or the exact country name")
            if len(set(values)) != len(values):
                issues.add("VAL-03", "countries resolve to duplicate codes", definition.row, key, payload[key], "list each country once")
            payload[key] = ",".join(code or "" for code in values)
        for key in ("src_service", "dst_service", "either_service"):
            if not payload.get(key):
                continue
            names = []
            for member in payload[key].split(","):
                name = address_map(member)
                if name is None:
                    issues.add("CMP-10", "unknown address map {}".format(member), definition.row, key, member, "use the exact Address Map name shown in Orchestrator")
                names.append(name or member)
            payload[key] = ",".join(names)
        if payload.get("vlan"):
            if "labels" not in cache:
                cache["labels"] = _label_ids(gateway.get_interface_labels())
            label_names, label_ids = cache["labels"]
            value = payload["vlan"]
            matches = [value] if value in label_ids else label_names.get(value.lower(), [])
            if len(matches) != 1:
                issues.add("CMP-09", "interface label {} is {}".format(value, "ambiguous" if matches else "unknown or inactive"), definition.row, "vlan", value, "use a unique active interface label name or its numeric ID")
            else:
                payload["vlan"] = matches[0]
        resolved.append(replace(definition, payload=payload))
    issues.raise_if_any()
    return resolved


def execute_application_definitions(gateway: Any, definitions: Sequence[ApplicationDefinition], inventories: Mapping[str, Any]) -> Dict[str, Any]:
    base_map = {"IP_PROTOCOL": "portProtocolClassification", "TCP_PORT": "portProtocolClassification", "UDP_PORT": "portProtocolClassification", "DOMAIN": "dnsClassification", "COMPOUND": "compoundClassification"}
    fingerprints = {base: fingerprint(value) for base, value in inventories.items()}
    created: List[str] = []
    for definition in definitions:
        base = base_map[definition.definition_type]
        current = gateway.get_application_definitions(base)
        if fingerprint(current) != fingerprints[base]:
            return {"status": "partial", "created": created, "error": "inventory drift before row {}".format(definition.row)}
        payload = dict(definition.payload)
        identity = definition.identity
        if definition.definition_type == "COMPOUND":
            ids = [int(key) for key in current if str(key).isdigit() and int(key) < 50000]
            ids.extend(int(value["id"]) for value in current.values() if isinstance(value, dict) and str(value.get("id", "")).isdigit() and int(value["id"]) < 50000)
            identity = max(ids, default=0) + 1
            payload["id"] = identity
        try:
            gateway.post_application_definition(base, payload, identity)
        except Exception as error:
            return {"status": "partial", "created": created, "error": str(error)}
        created.append(definition.name)
        refreshed = gateway.get_application_definitions(base)
        verified = ApplicationDefinition(definition.row, definition.definition_type, definition.name, payload, definition.identity, definition.app_express)
        if not _definition_present(verified, refreshed):
            return {"status": "partial", "created": created, "error": "readback verification failed"}
        fingerprints[base] = fingerprint(refreshed)
    return {"status": "success", "created": created}


def _definition_present(definition: ApplicationDefinition, inventory: Any) -> bool:
    if definition.definition_type == "COMPOUND":
        expected = dict(definition.payload)
        expected.pop("id", None)
        for value in inventory.values() if isinstance(inventory, dict) else ():
            if not isinstance(value, dict) or value.get("name") != definition.name:
                continue
            actual = dict(value)
            actual.pop("id", None)
            if _simple_definition_equal(actual, expected) and _simple_definition_equal(expected, actual):
                return True
        return False
    if definition.definition_type == "DOMAIN":
        return any(item.get("domain") == definition.identity and _simple_definition_equal(item, definition.payload) for item in inventory)
    if isinstance(inventory, dict):
        entries = inventory.get(str(definition.identity[0]), [])
        return any(int(item.get("protocol", -1)) == definition.identity[1] and _simple_definition_equal(item, definition.payload) for item in entries)
    return False


def plan_appexpress_modes(modes: Mapping[str, str], current: Mapping[str, Any]) -> Dict[str, Any]:
    candidate = copy.deepcopy(dict(current))
    next_id = max((int(value.get("id", -1)) for value in current.values()), default=-1) + 1
    monitor = []
    off = []
    no_ops = []
    for name, mode in modes.items():
        normalized_mode = mode.upper()
        if normalized_mode not in {"OFF", "MONITOR"}:
            raise ValidationError("AppExpress mode for {} must be OFF or MONITOR".format(name))
        keys = [key for key, value in candidate.items() if str(value.get("name", key)).lower() == name.lower()]
        if len(keys) > 1:
            raise ValidationError("duplicate AppExpress entries for {}".format(name))
        if normalized_mode == "OFF":
            if keys:
                del candidate[keys[0]]
                off.append(name)
            else:
                no_ops.append(name)
            continue
        if keys:
            value = candidate[keys[0]]
            if value.get("monitor") is True and value.get("appExpressEnabled") is False:
                no_ops.append(name)
                continue
            value["monitor"] = True
            value["appExpressEnabled"] = False
            monitor.append(name)
            continue
        candidate[name.lower()] = {"id": next_id, "appIndex": None, "name": name, "type": "app", "monitor": True, "appExpressEnabled": False, "useCloudPortalConfig": False, "cloudPortalDataAvailable": None, "satisfiedQoEThreshold": None, "tolerableQoEThreshold": None, "probes": None}
        next_id += 1
        monitor.append(name)
    monitored = sum(1 for value in candidate.values() if value.get("monitor") is True)
    if monitor and monitored > APPEXPRESS_LIMIT:
        raise ValidationError("[AD-08] AppExpress would monitor {} applications; Orchestrator supports at most {}".format(monitored, APPEXPRESS_LIMIT))
    return {"baseline": dict(current), "candidate": candidate, "fingerprint": fingerprint(current), "monitor": monitor, "off": off, "no_ops": no_ops, "changed": bool(monitor or off)}


def _appexpress_semantic(value: Mapping[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, config in value.items():
        normalized = dict(config)
        normalized.pop("id", None)
        result[str(normalized.get("name", key)).lower()] = normalized
    return result


def apply_appexpress(gateway: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    current = gateway.get_appexpress()
    if fingerprint(current) != plan["fingerprint"]:
        raise DriftError("AppExpress collection changed before write")
    changed = plan.get("changed", bool(plan.get("created")))
    if not changed:
        return {"status": "no_op"}
    gateway.post_appexpress(plan["candidate"])
    readback = gateway.get_appexpress()
    verified = semantic_equal(_appexpress_semantic(readback), _appexpress_semantic(plan["candidate"]))
    return {"status": "success" if verified else "partial", "monitor": plan.get("monitor", plan.get("created", [])), "off": plan.get("off", [])}


def execute_application_definitions_with_appexpress(gateway: Any, definitions: Sequence[ApplicationDefinition], inventories: Mapping[str, Any], appexpress_plan: Mapping[str, Any]) -> Dict[str, Any]:
    definition_result = execute_application_definitions(gateway, definitions, inventories)
    if definition_result["status"] != "success":
        return {"status": "partial", "application_definitions": definition_result, "appexpress": {"status": "not_attempted"}}
    try:
        appexpress_result = apply_appexpress(gateway, appexpress_plan)
    except Exception as error:
        return {"status": "partial", "application_definitions": definition_result, "appexpress": {"status": "failed", "error": str(error)}}
    status = "success" if appexpress_result["status"] in {"success", "no_op"} else "partial"
    return {"status": status, "application_definitions": definition_result, "appexpress": appexpress_result}
