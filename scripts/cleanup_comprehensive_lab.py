import argparse
import copy
import csv
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple

from edgeconnect_automation.client import ApiClient
from edgeconnect_automation.config import load_config
from edgeconnect_automation.errors import ApprovalError, DriftError, EdgeConnectError, ValidationError
from edgeconnect_automation.firewall import parse_firewall_csv, rule_payload
from edgeconnect_automation.gateway import OrchestratorGateway
from edgeconnect_automation.util import fingerprint, safe_report, semantic_equal
from edgeconnect_automation.workflows import parse_address_groups, parse_application_definitions, parse_application_groups, parse_service_groups


PREFIX = "lab25-"
COMMENT_PREFIX = "LAB25:"
FINAL_ACKNOWLEDGMENT = "I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Remove only resources created by the comprehensive lab CSV suite")
    parser.add_argument("--dotenv", required=True)
    parser.add_argument("--data-dir", default="examples/comprehensive_lab")
    parser.add_argument("--report", default="reports/comprehensive_lab_cleanup.json")
    parser.add_argument("--apply", action="store_true", help="perform deletion after exact confirmation; default is dry-run")
    return parser.parse_args(argv)


def require_prefix(names: Iterable[str], label: str) -> Set[str]:
    values = {name for name in names if name}
    unsafe = sorted(name for name in values if not name.startswith(PREFIX))
    if unsafe:
        raise ValidationError("{} contains names outside prefix {}: {}".format(label, PREFIX, ", ".join(unsafe)))
    return values


def load_suite(directory: Path) -> Dict[str, Any]:
    address_rows = parse_address_groups(str(directory / "address_groups_valid.csv"))
    service_rows = parse_service_groups(str(directory / "service_groups_valid.csv"))
    service_runtime_rows = parse_service_groups(str(directory / "invalid_cases" / "service_05.csv"))
    definitions = parse_application_definitions(str(directory / "application_definitions_valid_40.csv"))
    app_group_rows = parse_application_groups(str(directory / "application_groups_valid.csv"))
    firewall_rules = parse_firewall_csv(str(directory / "firewall_rules_valid_45.csv"))
    app_express = [definition.name for definition in definitions if definition.app_express == "MONITOR"]
    require_prefix((row["Name"] for row in address_rows), "address groups")
    require_prefix((row["Name"] for row in service_rows + service_runtime_rows), "service groups")
    require_prefix((definition.name for definition in definitions), "application definitions")
    require_prefix((row["Name"] for row in app_group_rows), "application groups")
    require_prefix(app_express, "AppExpress")
    for rule in firewall_rules:
        if not rule.rule_key.startswith(PREFIX) or not rule.description.startswith(COMMENT_PREFIX) or rule.priority is None:
            raise ValidationError("unsafe firewall cleanup identity on row {}".format(rule.row))
    return {"address_rows": address_rows, "service_rows": service_rows, "service_cleanup_rows": service_rows + service_runtime_rows, "definitions": definitions, "app_group_rows": app_group_rows, "firewall_rules": firewall_rules, "app_express": app_express}


def index_groups(values: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(item.get("name")): item for item in values if item.get("name")}


def csv_members(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def expected_groups(rows: Sequence[Mapping[str, str]], kind: str) -> Dict[str, Any]:
    grouped: Dict[str, List[Mapping[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row["Name"], []).append(row)
    result = {}
    for name, values in grouped.items():
        if kind == "address":
            rules = [{"includedIPs": csv_members(row["IncludedIPs"]), "excludedIPs": csv_members(row["ExcludedIPs"]), "includedGroups": csv_members(row["IncludedGroups"]), "comment": row["Comment"] or None} for row in values]
            result[name] = {"name": name, "type": "AG", "rules": rules}
        else:
            rules = [{"protocol": row["Protocol"].upper(), "includedPorts": csv_members(row["IncludedPorts"]), "excludedPorts": csv_members(row["ExcludedPorts"]), "includedGroups": csv_members(row["IncludedGroups"]), "excludedGroups": csv_members(row["ExcludedGroups"]), "icmpTypes": csv_members(row["IcmpTypes"]), "icmpCodes": csv_members(row["IcmpCodes"]), "comment": row["Comment"] or None} for row in values]
            result[name] = {"name": name, "type": "SG", "rules": rules}
    return result


def references(group: Mapping[str, Any]) -> Set[str]:
    return {str(name) for rule in group.get("rules", []) for field in ("includedGroups", "excludedGroups") for name in rule.get(field, [])}


def deletion_order(names: Set[str], current: Mapping[str, Mapping[str, Any]]) -> List[str]:
    remaining = set(names)
    result = []
    while remaining:
        referenced = {name for item in remaining for name in references(current[item]) if name in remaining}
        candidates = sorted(remaining - referenced)
        if not candidates:
            raise ValidationError("cannot calculate dependency-safe group deletion order")
        for name in candidates:
            result.append(name)
            remaining.remove(name)
    return result


def normalized_appexpress(values: Mapping[str, Any]) -> Dict[str, Any]:
    result = {}
    for key, value in values.items():
        item = dict(value)
        item.pop("id", None)
        result[str(item.get("name", key)).lower()] = item
    return result


def build_plan(gateway: OrchestratorGateway, suite: Mapping[str, Any]) -> Dict[str, Any]:
    segments_raw = gateway.get_segments()
    segments = {str(value["name"]): int(value.get("id", key)) for key, value in segments_raw.items()}
    zone_items = gateway.get_segment_zones()
    zones = {(str(item["vrfName"]), str(item["zoneName"])): int(item["zoneId"]) for item in zone_items}
    firewall_plans = []
    grouped: Dict[Tuple[str, str], list] = {}
    for rule in suite["firewall_rules"]:
        grouped.setdefault(rule.pair, []).append(rule)
    for pair, rules in sorted(grouped.items()):
        if pair[0] not in segments or pair[1] not in segments:
            raise ValidationError("cleanup segment pair no longer exists: {} -> {}".format(*pair))
        segment_map = "{}_{}".format(segments[pair[0]], segments[pair[1]])
        baseline = gateway.get_policy(segment_map)
        candidate = copy.deepcopy(baseline)
        removed = []
        conflicts = []
        for rule in rules:
            source_id = zones.get((rule.source_segment, rule.source_zone))
            destination_id = zones.get((rule.destination_segment, rule.destination_zone))
            if source_id is None or destination_id is None:
                conflicts.append("row {} zone mapping missing".format(rule.row))
                continue
            zone_key = "{}_{}".format(source_id, destination_id)
            priorities = candidate.get("data", {}).get("map1", {}).get(zone_key, {}).get("prio", {})
            current = priorities.get(str(rule.priority))
            if current is None:
                continue
            if not current.get("comment", "").startswith(COMMENT_PREFIX) or not semantic_equal(current, rule_payload(rule)):
                conflicts.append("{} priority {} does not exactly match the lab CSV".format(zone_key, rule.priority))
                continue
            del priorities[str(rule.priority)]
            removed.append({"zone_pair": zone_key, "priority": rule.priority, "rule_key": rule.rule_key})
        if conflicts:
            raise ValidationError("firewall cleanup conflicts: {}".format("; ".join(conflicts)))
        firewall_plans.append({"pair": pair, "segment_map": segment_map, "baseline": baseline, "candidate": candidate, "baseline_fingerprint": fingerprint(baseline), "removed": removed})

    app_groups = gateway.get_application_groups()
    app_group_names = require_prefix((row["Name"] for row in suite["app_group_rows"]), "application groups")
    expected_app_groups = {row["Name"]: {"apps": sorted({item.strip() for item in row["Applications"].split(",") if item.strip()}), "parentGroup": sorted({item.strip() for item in row["ParentGroups"].split(",") if item.strip()}) or None} for row in suite["app_group_rows"]}
    for name in app_group_names & set(app_groups):
        if not semantic_equal(app_groups[name], expected_app_groups[name]):
            raise ValidationError("application group changed since suite creation: {}".format(name))
    for name, value in app_groups.items():
        if name in app_group_names:
            continue
        if app_group_names & set(value.get("parentGroup") or []):
            raise ValidationError("non-test application group {} references test parent".format(name))
        test_apps = {definition.name for definition in suite["definitions"]}
        if test_apps & set(value.get("apps") or []):
            raise ValidationError("non-test application group {} references test application".format(name))
    app_group_candidate = {name: value for name, value in app_groups.items() if name not in app_group_names}

    app_express = gateway.get_appexpress()
    app_express_names = set(suite["app_express"])
    app_express_candidate = {key: value for key, value in app_express.items() if str(value.get("name", key)) not in app_express_names}

    definitions = suite["definitions"]
    definition_plan = []
    port_inventory = gateway.get_application_definitions("portProtocolClassification")
    dns_inventory = gateway.get_application_definitions("dnsClassification")
    compound_inventory = gateway.get_application_definitions("compoundClassification")
    for definition in definitions:
        if definition.definition_type == "DOMAIN":
            matches = [item for item in dns_inventory if item.get("domain") == definition.identity and item.get("name") == definition.name]
            if matches:
                if not any(all(item.get(key) == value for key, value in definition.payload.items()) for item in matches):
                    raise ValidationError("domain definition changed since suite creation: {}".format(definition.name))
                definition_plan.append({"type": "DOMAIN", "name": definition.name, "domain": definition.identity, "expected": definition.payload})
        elif definition.definition_type == "COMPOUND":
            matches = [item for item in compound_inventory.values() if item.get("name") == definition.name]
            if matches:
                expected = dict(definition.payload)
                if not any(semantic_equal({key: value for key, value in item.items() if key != "id"}, expected) for item in matches):
                    raise ValidationError("compound definition changed since suite creation: {}".format(definition.name))
                definition_plan.append({"type": "COMPOUND", "name": definition.name, "expected": definition.payload})
        else:
            port, protocol = definition.identity
            matches = [item for item in port_inventory.get(str(port), []) if int(item.get("protocol", -1)) == protocol and item.get("name") == definition.name]
            if matches:
                if not any(all(item.get(key) == value for key, value in definition.payload.items()) for item in matches):
                    raise ValidationError("port/protocol definition changed since suite creation: {}".format(definition.name))
                definition_plan.append({"type": definition.definition_type, "name": definition.name, "port": port, "protocol": protocol, "expected": definition.payload})

    address_values = gateway.get_address_groups()
    service_values = gateway.get_service_groups()
    address = index_groups(address_values)
    service = index_groups(service_values)
    address_names = require_prefix((row["Name"] for row in suite["address_rows"]), "address groups") & set(address)
    service_names = require_prefix((row["Name"] for row in suite["service_cleanup_rows"]), "service groups") & set(service)
    expected_address = expected_groups(suite["address_rows"], "address")
    expected_service = expected_groups(suite["service_cleanup_rows"], "service")
    for name in address_names:
        if not semantic_equal(address[name], expected_address[name]):
            raise ValidationError("address group changed since suite creation: {}".format(name))
    for name in service_names:
        if not semantic_equal(service[name], expected_service[name]):
            raise ValidationError("service group changed since suite creation: {}".format(name))
    for name, value in address.items():
        if name not in address_names and references(value) & address_names:
            raise ValidationError("non-test address group {} references test group".format(name))
    for name, value in service.items():
        if name not in service_names and references(value) & service_names:
            raise ValidationError("non-test service group {} references test group".format(name))

    return {
        "prefix": PREFIX,
        "firewall": firewall_plans,
        "application_groups": {"baseline": app_groups, "candidate": app_group_candidate, "fingerprint": fingerprint(app_groups), "remove": sorted(app_group_names & set(app_groups))},
        "appexpress": {"baseline": app_express, "candidate": app_express_candidate, "fingerprint": fingerprint(app_express), "remove": sorted(app_express_names & {str(value.get('name', key)) for key, value in app_express.items()})},
        "application_definitions": definition_plan,
        "application_definition_fingerprints": {"portProtocolClassification": fingerprint(port_inventory), "dnsClassification": fingerprint(dns_inventory), "compoundClassification": fingerprint(compound_inventory)},
        "service_groups": {"fingerprint": fingerprint(service_values), "remove": deletion_order(service_names, service) if service_names else []},
        "address_groups": {"fingerprint": fingerprint(address_values), "remove": deletion_order(address_names, address) if address_names else []},
    }


def deletion_rows(plan: Mapping[str, Any]) -> List[Tuple[str, str, str]]:
    rows: List[Tuple[str, str, str]] = []
    for item in plan["firewall"]:
        pair = "{} -> {}".format(*item["pair"])
        for removed in item["removed"]:
            identity = "{}; segment {}; zones {}; priority {}".format(pair, item["segment_map"], removed["zone_pair"], removed["priority"])
            rows.append(("Firewall rule", removed["rule_key"], identity))
    for name in plan["application_groups"]["remove"]:
        rows.append(("Application group", name, "user-defined collection"))
    for name in plan["appexpress"]["remove"]:
        rows.append(("AppExpress Monitor", name, "user-defined monitor entry"))
    for item in plan["application_definitions"]:
        if item["type"] == "DOMAIN":
            identity = "domain={}".format(item["domain"])
        elif item["type"] == "COMPOUND":
            identity = "compound name identity; current ID resolved at deletion"
        else:
            identity = "port={}; protocol={}".format(item["port"], item["protocol"])
        rows.append(("Application definition", item["name"], identity))
    for name in plan["service_groups"]["remove"]:
        rows.append(("Service group", name, "dependency-safe deletion order"))
    for name in plan["address_groups"]["remove"]:
        rows.append(("Address group", name, "dependency-safe deletion order"))
    return rows


def format_deletion_table(rows: Sequence[Tuple[str, str, str]]) -> str:
    values = [(str(index), resource, name, identity) for index, (resource, name, identity) in enumerate(rows, 1)]
    table = [("#", "RESOURCE TYPE", "NAME", "IDENTITY / SCOPE")] + values
    widths = [max(len(row[column]) for row in table) for column in range(4)]
    separator = "+-{}-+-{}-+-{}-+-{}-+".format(*(width * "-" for width in widths))
    lines = [separator]
    for index, row in enumerate(table):
        lines.append("| {} | {} | {} | {} |".format(*(value.ljust(widths[column]) for column, value in enumerate(row))))
        if index == 0:
            lines.append(separator)
    lines.append(separator)
    return "\n".join(lines)


def generate_confirmation_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "DELETE-LAB25-{}".format("".join(secrets.choice(alphabet) for _ in range(8)))


def confirm(plan: Mapping[str, Any]) -> None:
    if not sys.stdin.isatty():
        raise ApprovalError("non-interactive cleanup is refused")
    rows = deletion_rows(plan)
    print("\nCOMPLETE DELETION TABLE — {} resources\n".format(len(rows)))
    print(format_deletion_table(rows))
    code = generate_confirmation_code()
    print("\nFirst confirmation required. Type this system-generated code exactly:\n\n{}\n".format(code))
    if input("Confirmation code: ") != code:
        raise ApprovalError("cleanup confirmation code refused")
    print("\nFINAL WARNING: This is a destructive operation. The listed configuration will be deleted, dependencies may immediately stop working, and this script cannot automatically restore the abyss you are about to open.")
    print("You are responsible for reviewing the full table, validating the target lab, and accepting this abyss action.")
    print("\nTo answer 'Are you absolutely sure?' type exactly:\n\n{}\n".format(FINAL_ACKNOWLEDGMENT))
    if input("Final acknowledgment: ") != FINAL_ACKNOWLEDGMENT:
        raise ApprovalError("final cleanup acknowledgment refused")


def delete(client: ApiClient, path: str, query: Mapping[str, Any]) -> None:
    client.request("DELETE", path, query=query, expected_status=(200, 204), expect_json=False)


def apply_plan(gateway: OrchestratorGateway, plan: Mapping[str, Any]) -> Dict[str, Any]:
    results = []
    for item in plan["firewall"]:
        if fingerprint(gateway.get_policy(item["segment_map"])) != item["baseline_fingerprint"]:
            raise DriftError("firewall baseline changed for {}".format(item["segment_map"]))
        if item["removed"]:
            gateway.post_policy(item["segment_map"], item["candidate"], "lab25-cleanup-{}".format(int(time.time())))
            verified = semantic_equal(gateway.get_policy(item["segment_map"]), item["candidate"])
            results.append({"kind": "firewall", "segment_map": item["segment_map"], "verified": verified})
            if not verified:
                raise ValidationError("firewall cleanup readback failed")

    app_groups = plan["application_groups"]
    if app_groups["remove"]:
        if fingerprint(gateway.get_application_groups()) != app_groups["fingerprint"]:
            raise DriftError("application group collection changed")
        gateway.post_application_groups(app_groups["candidate"])
        verified = semantic_equal(gateway.get_application_groups(), app_groups["candidate"])
        results.append({"kind": "application_groups", "verified": verified})
        if not verified:
            raise ValidationError("application group cleanup readback failed")

    appexpress = plan["appexpress"]
    if appexpress["remove"]:
        if fingerprint(gateway.get_appexpress()) != appexpress["fingerprint"]:
            raise DriftError("AppExpress collection changed")
        gateway.post_appexpress(appexpress["candidate"])
        verified = semantic_equal(normalized_appexpress(gateway.get_appexpress()), normalized_appexpress(appexpress["candidate"]))
        results.append({"kind": "appexpress", "verified": verified})
        if not verified:
            raise ValidationError("AppExpress cleanup readback failed")

    if plan["application_definitions"]:
        for base, expected in plan["application_definition_fingerprints"].items():
            if fingerprint(gateway.get_application_definitions(base)) != expected:
                raise DriftError("{} application definitions changed".format(base))
    for item in plan["application_definitions"]:
        if item["type"] == "COMPOUND":
            current = gateway.get_application_definitions("compoundClassification")
            matches = [(int(value.get("id", key)), value) for key, value in current.items() if value.get("name") == item["name"]]
            if len(matches) != 1 or not semantic_equal({key: value for key, value in matches[0][1].items() if key != "id"}, item["expected"]):
                raise DriftError("compound application definition changed: {}".format(item["name"]))
            delete(gateway.client, "/applicationDefinition/compoundClassification", {"id": matches[0][0]})
        elif item["type"] == "DOMAIN":
            current = gateway.get_application_definitions("dnsClassification")
            matches = [value for value in current if value.get("domain") == item["domain"] and value.get("name") == item["name"] and all(value.get(key) == expected for key, expected in item["expected"].items())]
            if len(matches) != 1:
                raise DriftError("domain application definition changed: {}".format(item["name"]))
            delete(gateway.client, "/applicationDefinition/dnsClassification", {"domain": item["domain"]})
        else:
            current = gateway.get_application_definitions("portProtocolClassification")
            matches = [value for value in current.get(str(item["port"]), []) if int(value.get("protocol", -1)) == item["protocol"] and value.get("name") == item["name"] and all(value.get(key) == expected for key, expected in item["expected"].items())]
            if len(matches) != 1:
                raise DriftError("port/protocol application definition changed: {}".format(item["name"]))
            delete(gateway.client, "/applicationDefinition/portProtocolClassification", {"port": item["port"], "protocol": item["protocol"]})
        results.append({"kind": "application_definition", "name": item["name"], "requested": "delete"})

    if plan["service_groups"]["remove"] and fingerprint(gateway.get_service_groups()) != plan["service_groups"]["fingerprint"]:
        raise DriftError("service group collection changed")
    for name in plan["service_groups"]["remove"]:
        delete(gateway.client, "/ipObjects/serviceGroup", {"name": name})
        results.append({"kind": "service_group", "name": name, "requested": "delete"})
    if plan["address_groups"]["remove"] and fingerprint(gateway.get_address_groups()) != plan["address_groups"]["fingerprint"]:
        raise DriftError("address group collection changed")
    for name in plan["address_groups"]["remove"]:
        delete(gateway.client, "/ipObjects/addressGroup", {"name": name})
        results.append({"kind": "address_group", "name": name, "requested": "delete"})
    return {"status": "completed", "results": results}


def normalized_appexpress(value: Mapping[str, Any]) -> Dict[str, Any]:
    result = {}
    for key, config in value.items():
        item = dict(config)
        item.pop("id", None)
        result[str(item.get("name", key)).lower()] = item
    return result


def verify_absent(gateway: OrchestratorGateway, plan: Mapping[str, Any]) -> Dict[str, Any]:
    failures = []
    for item in plan["firewall"]:
        policy = gateway.get_policy(item["segment_map"])
        for zone in policy.get("data", {}).get("map1", {}).values():
            for priority, rule in zone.get("prio", {}).items():
                if str(rule.get("comment", "")).startswith(COMMENT_PREFIX):
                    failures.append("firewall {} priority {} remains".format(item["segment_map"], priority))
    if any(name.startswith(PREFIX) for name in gateway.get_application_groups()):
        failures.append("application groups remain")
    if any(str(value.get("name", key)).startswith(PREFIX) for key, value in gateway.get_appexpress().items()):
        failures.append("AppExpress entries remain")
    port = gateway.get_application_definitions("portProtocolClassification")
    dns = gateway.get_application_definitions("dnsClassification")
    compound = gateway.get_application_definitions("compoundClassification")
    if any(item.get("name", "").startswith(PREFIX) for values in port.values() for item in values):
        failures.append("port/protocol definitions remain")
    if any(item.get("name", "").startswith(PREFIX) for item in dns):
        failures.append("DNS definitions remain")
    if any(item.get("name", "").startswith(PREFIX) for item in compound.values()):
        failures.append("compound definitions remain")
    if any(item.get("name", "").startswith(PREFIX) for item in gateway.get_service_groups()):
        failures.append("service groups remain")
    if any(item.get("name", "").startswith(PREFIX) for item in gateway.get_address_groups()):
        failures.append("address groups remain")
    if failures:
        raise ValidationError("cleanup verification failed: {}".format("; ".join(failures)))
    return {"verified_absent": True, "prefix": PREFIX}


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        suite = load_suite(Path(args.data_dir))
        gateway = OrchestratorGateway(ApiClient(load_config(args.dotenv)))
        plan = build_plan(gateway, suite)
        preview = {"mode": "APPLY" if args.apply else "DRY_RUN", **plan}
        if not args.apply:
            safe_report(args.report, preview)
            print(json.dumps(preview, indent=2, default=str))
            return 0
        confirm(preview)
        result = apply_plan(gateway, plan)
        result["verification"] = verify_absent(gateway, plan)
        safe_report(args.report, {"plan": preview, "result": result})
        print(json.dumps(result, indent=2))
        return 0
    except EdgeConnectError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code
    except (OSError, ValueError, TypeError, json.JSONDecodeError, csv.Error) as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
