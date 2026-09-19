import argparse
import base64
import csv
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .client import ApiClient
from .config import load_config
from .errors import ApprovalError, EdgeConnectError, ValidationError
from .firewall import FirewallExecutor, build_firewall_plan, parse_firewall_csv, parse_firewall_document, write_resolved_csv
from .gateway import OrchestratorGateway
from .models import FirewallPlan, FirewallRule, Inventory, PairPlan
from .util import fingerprint, redact, safe_report
from .workflows import ApplicationDefinition, BulkPlan, ZonePlan, apply_appexpress, apply_application_groups, apply_native_groups, apply_zones, execute_application_definitions_with_appexpress, parse_address_groups, parse_application_definitions, parse_application_groups, parse_service_groups, plan_appexpress, plan_appexpress_modes, plan_application_definitions, plan_application_groups, plan_native_groups, plan_zones


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="edgeconnect-auto", description="Safety-focused EdgeConnect Orchestrator automation")
    parser.add_argument("--dotenv", help="explicit dotenv path; never read automatically")
    parser.add_argument("--allow-http", action="store_true", help="allow HTTP for isolated test fixtures only")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    subparsers = parser.add_subparsers(dest="command", required=True)

    discovery = subparsers.add_parser("discovery", help="read-only Orchestrator inventory")
    discovery.add_argument("--output")
    discovery.set_defaults(handler=_discovery)

    firewall = subparsers.add_parser("firewall")
    firewall_sub = firewall.add_subparsers(dest="firewall_command", required=True)
    validate = firewall_sub.add_parser("validate", help="locally validate firewall CSV")
    validate.add_argument("--csv", required=True)
    validate.set_defaults(handler=_firewall_validate)
    plan = firewall_sub.add_parser("plan", help="build a read-only firewall plan")
    plan.add_argument("--csv", required=True)
    plan.add_argument("--inventory", help="offline inventory JSON")
    plan.add_argument("--output", required=True)
    plan.add_argument("--resolved-csv")
    plan.add_argument("--dry-run", action="store_true")
    plan.set_defaults(handler=_firewall_plan)
    apply = firewall_sub.add_parser("apply", help="apply an approved firewall plan")
    apply.add_argument("--approved-plan", required=True)
    apply.add_argument("--dry-run", action="store_true")
    apply.add_argument("--report")
    apply.set_defaults(handler=_firewall_apply)
    deploy = firewall_sub.add_parser("deploy", help="discover, preview, approve, apply, and verify in one command")
    deploy.add_argument("--csv", required=True)
    deploy.add_argument("--inventory", help="offline inventory JSON for contract tests")
    deploy.add_argument("--resolved-csv")
    deploy.add_argument("--report")
    deploy.add_argument("--dry-run", action="store_true")
    deploy.set_defaults(handler=_firewall_deploy)
    verify = firewall_sub.add_parser("verify", help="read audit evidence for a run reference")
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--output")
    verify.set_defaults(handler=_firewall_verify)

    zones = subparsers.add_parser("zones")
    zone_sub = zones.add_subparsers(dest="zone_command", required=True)
    zone_plan = zone_sub.add_parser("plan-missing")
    zone_plan.add_argument("--name", action="append", required=True)
    zone_plan.add_argument("--output", required=True)
    zone_plan.add_argument("--dry-run", action="store_true")
    zone_plan.set_defaults(handler=_zones_plan)
    zone_apply = zone_sub.add_parser("apply")
    zone_apply.add_argument("--approved-plan", required=True)
    zone_apply.add_argument("--dry-run", action="store_true")
    zone_apply.set_defaults(handler=_zones_apply)
    zone_create = zone_sub.add_parser("create", help="discover, preview, approve, create, and verify zones")
    zone_create.add_argument("--name", action="append", required=True)
    zone_create.add_argument("--report")
    zone_create.add_argument("--dry-run", action="store_true")
    zone_create.set_defaults(handler=_zones_create)

    _add_bulk_commands(subparsers, "address-groups", "address")
    _add_bulk_commands(subparsers, "service-groups", "service")

    app_groups = subparsers.add_parser("app-groups")
    app_group_sub = app_groups.add_subparsers(dest="app_group_command", required=True)
    app_group_plan = app_group_sub.add_parser("plan")
    app_group_plan.add_argument("--csv", required=True)
    app_group_plan.add_argument("--applications", help="optional offline JSON list of complete application names")
    app_group_plan.add_argument("--output", required=True)
    app_group_plan.add_argument("--dry-run", action="store_true")
    app_group_plan.set_defaults(handler=_app_groups_plan)
    app_group_apply = app_group_sub.add_parser("apply")
    app_group_apply.add_argument("--approved-plan", required=True)
    app_group_apply.add_argument("--dry-run", action="store_true")
    app_group_apply.set_defaults(handler=_app_groups_apply)
    app_group_deploy = app_group_sub.add_parser("deploy", help="discover, preview, approve, apply, and verify")
    app_group_deploy.add_argument("--csv", required=True)
    app_group_deploy.add_argument("--applications", help="optional offline JSON list of complete application names")
    app_group_deploy.add_argument("--report")
    app_group_deploy.add_argument("--dry-run", action="store_true")
    app_group_deploy.set_defaults(handler=_app_groups_deploy)

    definitions = subparsers.add_parser("app-definitions")
    definition_sub = definitions.add_subparsers(dest="definition_command", required=True)
    definition_plan = definition_sub.add_parser("plan")
    definition_plan.add_argument("--csv", required=True)
    definition_plan.add_argument("--output", required=True)
    definition_plan.add_argument("--dry-run", action="store_true")
    definition_plan.set_defaults(handler=_definitions_plan)
    definition_apply = definition_sub.add_parser("apply")
    definition_apply.add_argument("--approved-plan", required=True)
    definition_apply.add_argument("--dry-run", action="store_true")
    definition_apply.set_defaults(handler=_definitions_apply)
    definition_deploy = definition_sub.add_parser("deploy", help="discover, preview, approve, create, and verify")
    definition_deploy.add_argument("--csv", required=True)
    definition_deploy.add_argument("--report")
    definition_deploy.add_argument("--dry-run", action="store_true")
    definition_deploy.set_defaults(handler=_definitions_deploy)

    appexpress = subparsers.add_parser("appexpress")
    appexpress_sub = appexpress.add_subparsers(dest="appexpress_command", required=True)
    appexpress_plan = appexpress_sub.add_parser("plan")
    appexpress_input = appexpress_plan.add_mutually_exclusive_group(required=True)
    appexpress_input.add_argument("--application", action="append")
    appexpress_input.add_argument("--csv")
    appexpress_plan.add_argument("--applications", help="optional offline JSON list of complete application names")
    appexpress_plan.add_argument("--output", required=True)
    appexpress_plan.add_argument("--dry-run", action="store_true")
    appexpress_plan.set_defaults(handler=_appexpress_plan)
    appexpress_apply = appexpress_sub.add_parser("apply")
    appexpress_apply.add_argument("--approved-plan", required=True)
    appexpress_apply.add_argument("--dry-run", action="store_true")
    appexpress_apply.set_defaults(handler=_appexpress_apply)
    appexpress_deploy = appexpress_sub.add_parser("deploy", help="discover, preview, approve, apply, and verify monitor mode")
    appexpress_deploy_input = appexpress_deploy.add_mutually_exclusive_group(required=True)
    appexpress_deploy_input.add_argument("--application", action="append")
    appexpress_deploy_input.add_argument("--csv")
    appexpress_deploy.add_argument("--applications", help="optional offline JSON list of complete application names")
    appexpress_deploy.add_argument("--report")
    appexpress_deploy.add_argument("--dry-run", action="store_true")
    appexpress_deploy.set_defaults(handler=_appexpress_deploy)
    return parser


def _add_bulk_commands(subparsers: Any, name: str, kind: str) -> None:
    parser = subparsers.add_parser(name)
    commands = parser.add_subparsers(dest=name.replace("-", "_") + "_command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--csv", required=True)
    plan.add_argument("--output", required=True)
    plan.add_argument("--dry-run", action="store_true")
    plan.set_defaults(handler=_bulk_plan, bulk_kind=kind)
    apply = commands.add_parser("apply")
    apply.add_argument("--approved-plan", required=True)
    apply.add_argument("--dry-run", action="store_true")
    apply.set_defaults(handler=_bulk_apply, bulk_kind=kind)
    deploy = commands.add_parser("deploy", help="discover, preview, approve, upload, and verify")
    deploy.add_argument("--csv", required=True)
    deploy.add_argument("--report")
    deploy.add_argument("--dry-run", action="store_true")
    deploy.set_defaults(handler=_bulk_deploy, bulk_kind=kind)


def _gateway(args: argparse.Namespace) -> OrchestratorGateway:
    config = load_config(args.dotenv, allow_http=args.allow_http)
    gateway = OrchestratorGateway(ApiClient(config, verbosity=args.verbose))
    release = str(gateway.get_version().get("release", ""))
    try:
        parts = tuple(int(part) for part in release.split(".")[:2])
    except ValueError as error:
        raise ValidationError("unable to parse Orchestrator release {}".format(release)) from error
    if len(parts) < 2 or parts < (9, 3):
        raise ValidationError("Orchestrator 9.3 or later is required; found {}".format(release or "unknown"))
    return gateway


def _print(value: Any) -> None:
    print(json.dumps(redact(value), indent=2, sort_keys=True, ensure_ascii=False))


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _approve(preview: Any, dry_run: bool, zone_names: Sequence[str] = ()) -> bool:
    _print({"preview": preview, "impact": "configuration write", "validation": "fresh readback and normalized comparison", "recovery": "workflow-specific preservation or rollback"})
    if dry_run:
        return False
    if not sys.stdin.isatty():
        raise ApprovalError("non-interactive writes are refused")
    for name in zone_names:
        expected = "CREATE {}".format(name)
        if input("Type {} to confirm this zone: ".format(expected)) != expected:
            raise ApprovalError("zone confirmation refused")
    if input("Type APPLY to execute the exact preview: ") != "APPLY":
        raise ApprovalError("write approval refused")
    return True


def _discovery(args: argparse.Namespace) -> int:
    result = _gateway(args).discover()
    result["fingerprint"] = fingerprint(result)
    if args.output:
        safe_report(args.output, result)
    _print(result)
    return 0


def _firewall_validate(args: argparse.Namespace) -> int:
    document = parse_firewall_document(Path(args.csv).read_text(encoding="utf-8-sig"))
    result = {"status": "valid" if not document.errors else "invalid", "rules": len(document.rules), "segment_pairs": sorted({"{} -> {}".format(*rule.pair) for rule in document.rules}), "errors": document.errors}
    _print(result)
    return 0 if not document.errors else 2


def _firewall_plan(args: argparse.Namespace) -> int:
    document = parse_firewall_document(Path(args.csv).read_text(encoding="utf-8-sig"))
    pairs = set(document.pair_errors) | {rule.pair for rule in document.rules}
    if args.inventory:
        inventory = _inventory_from_dict(_load_json(args.inventory))
    else:
        inventory = _discover_inventory(_gateway(args), document.rules, pairs)
    plan = build_firewall_plan(document.rules, inventory, document.pair_errors, document.global_errors)
    auto_allocated = any(rule.priority is None for rule in document.rules if any(resolved.row == rule.row for resolved in plan.resolved_rows))
    if auto_allocated and not args.resolved_csv:
        raise ValidationError("--resolved-csv is required when priorities are automatically allocated")
    report = {"kind": "firewall", "plan": plan.to_dict(), "fingerprint": fingerprint(plan.to_dict())}
    safe_report(args.output, report)
    if args.resolved_csv and plan.resolved_rows:
        write_resolved_csv(args.resolved_csv, plan.resolved_rows)
    _print({"output": args.output, "eligible_pairs": len(plan.eligible_pairs), "ineligible_pairs": sum(not pair.eligible for pair in plan.pairs), "warnings": [warning for pair in plan.pairs for warning in pair.warnings]})
    return 2 if not plan.eligible_pairs else 5 if plan.has_ineligible_pairs else 0


def _firewall_deploy(args: argparse.Namespace) -> int:
    document = parse_firewall_document(Path(args.csv).read_text(encoding="utf-8-sig"))
    pairs = set(document.pair_errors) | {rule.pair for rule in document.rules}
    gateway = _gateway(args)
    inventory = _inventory_from_dict(_load_json(args.inventory)) if args.inventory else _discover_inventory(gateway, document.rules, pairs)
    if not args.inventory:
        zone_result = _handle_firewall_missing_zones(gateway, document.rules, inventory, args.dry_run, args.report)
        if zone_result is not None:
            return zone_result
    plan = build_firewall_plan(document.rules, inventory, document.pair_errors, document.global_errors)
    auto_allocated = any(rule.priority is None for rule in document.rules if any(resolved.row == rule.row for resolved in plan.resolved_rows))
    if auto_allocated and not args.resolved_csv:
        raise ValidationError("--resolved-csv is required when priorities are automatically allocated")
    preview = {"kind": "firewall", "plan": plan.to_dict(), "fingerprint": fingerprint(plan.to_dict())}
    if args.resolved_csv and plan.resolved_rows:
        write_resolved_csv(args.resolved_csv, plan.resolved_rows)
    if not plan.eligible_pairs:
        _print(preview)
        return 2
    if not _approve(preview, args.dry_run):
        if args.report:
            safe_report(args.report, {"preview": preview, "status": "DRY_RUN", "report_fingerprint": fingerprint(preview)})
        return 0
    result = FirewallExecutor(gateway).apply(plan)
    report = {"preview": preview, "result": asdict(result)}
    report["report_fingerprint"] = fingerprint(report)
    if args.report:
        safe_report(args.report, report)
    _print(report)
    return result.exit_code


def _handle_firewall_missing_zones(
    gateway: OrchestratorGateway,
    rules: Sequence[FirewallRule],
    inventory: Inventory,
    dry_run: bool,
    report_path: Optional[str],
) -> Optional[int]:
    missing = sorted({(rule.source_segment, rule.source_zone) for rule in rules if (rule.source_segment, rule.source_zone) not in inventory.zones} | {(rule.destination_segment, rule.destination_zone) for rule in rules if (rule.destination_segment, rule.destination_zone) not in inventory.zones})
    if not missing:
        return None
    baseline = gateway.get_zones()
    base_names = {str(value.get("name")) for value in baseline.values()}
    creatable = sorted({zone for _, zone in missing if zone not in base_names})
    mapping_only = sorted((segment, zone) for segment, zone in missing if zone in base_names)
    preview: Dict[str, Any] = {"kind": "missing-firewall-zones", "missing": [{"segment": segment, "zone": zone} for segment, zone in missing], "creatable_base_zones": creatable, "existing_base_zones_missing_segment_mapping": [{"segment": segment, "zone": zone} for segment, zone in mapping_only]}
    if mapping_only:
        preview["status"] = "BLOCKED_SEGMENT_MAPPING"
        _print(preview)
        if report_path:
            safe_report(report_path, preview)
        return 2
    all_vrf = gateway.get_all_vrf_zones()
    mappings = gateway.get_zone_mappings()
    plan = plan_zones(baseline, gateway.get_next_zone_id(), creatable, all_vrf, mappings)
    preview.update({"baseline": plan.baseline, "candidate": plan.candidate, "baseline_fingerprint": plan.baseline_fingerprint, "created": plan.created, "all_vrf_fingerprint": plan.all_vrf_fingerprint, "mappings_fingerprint": plan.mappings_fingerprint, "next_step": "Rerun the firewall command after zone creation verification"})
    if not _approve(preview, dry_run, list(plan.created)):
        if report_path:
            safe_report(report_path, {"preview": preview, "status": "DRY_RUN_MISSING_ZONES"})
        return 2
    result = apply_zones(gateway, plan)
    output = {"preview": preview, "result": result, "firewall_status": "NOT_ATTEMPTED_RERUN_REQUIRED"}
    if report_path:
        safe_report(report_path, output)
    _print(output)
    return 2 if result["status"] in {"success", "no_op"} else 5


def _inventory_from_dict(value: Mapping[str, Any]) -> Inventory:
    zones = {}
    for key, zone_id in value.get("zones", {}).items():
        segment, zone = key.split("|", 1)
        zones[(segment, zone)] = int(zone_id)
    policies = {}
    for key, policy in value.get("policies", {}).items():
        source, destination = key.split("|", 1)
        policies[(source, destination)] = policy
    local = {}
    for key, priorities in value.get("local_priorities", {}).items():
        local[tuple(key.split("|", 3))] = {int(item) for item in priorities}
    return Inventory(
        segments={str(key): int(item) for key, item in value.get("segments", {}).items()},
        zones=zones,
        policies=policies,
        address_groups=set(value.get("address_groups", [])),
        service_groups=set(value.get("service_groups", [])),
        applications=set(value.get("applications", [])),
        application_groups=set(value.get("application_groups", [])),
        local_priorities=local,
        statuses=value.get("statuses", {}),
        segmentation_enabled=bool(value.get("segmentation_enabled", False)),
        target_states=value.get("target_states", {}),
        pair_errors={tuple(key.split("|", 1)): list(errors) for key, errors in value.get("pair_errors", {}).items()},
    )


def _version_at_least(value: str, minimum: Tuple[int, int]) -> bool:
    try:
        parts = tuple(int(part) for part in value.split("_")[0].split(".")[:2])
    except ValueError:
        return False
    return len(parts) >= 2 and parts >= minimum


def _discover_inventory(gateway: OrchestratorGateway, rules: Sequence[FirewallRule], pairs: Optional[Set[Tuple[str, str]]] = None) -> Inventory:
    segmentation = gateway.get_segmentation()
    segment_raw = gateway.get_segments()
    segments = {str(item["name"]): int(item.get("id", key)) for key, item in segment_raw.items()}
    mapping = gateway.get_segment_zones()
    zones = {(str(item["vrfName"]), str(item["zoneName"])): int(item["zoneId"]) for item in mapping}
    requested_pairs = pairs or {rule.pair for rule in rules}
    policies = {}
    pair_errors: Dict[Tuple[str, str], List[str]] = {}
    for pair in requested_pairs:
        if pair[0] in segments and pair[1] in segments:
            policies[pair] = gateway.get_policy("{}_{}".format(segments[pair[0]], segments[pair[1]]))
    address = gateway.get_address_groups()
    service = gateway.get_service_groups()
    port = gateway.get_application_definitions("portProtocolClassification")
    dns = gateway.get_application_definitions("dnsClassification")
    compound = gateway.get_application_definitions("compoundClassification")
    groups = gateway.get_application_groups()
    applications = _application_names(port, dns, compound)
    requested_apps = {name for rule in rules for name in rule.application.split("|") if name}
    requested_groups = {name for rule in rules for name in rule.application_group.split("|") if name and name.lower() != "any"}
    for name in requested_apps - applications:
        if _wildcard_has_exact_name(gateway.search_application(name), name):
            applications.add(name)
    application_groups = set(groups)
    for name in requested_groups - application_groups:
        if _wildcard_has_exact_name(gateway.search_application_group(name), name):
            application_groups.add(name)
    appliances = gateway.get_appliances()
    paused_raw = gateway.get_paused_orchestration()
    paused_ids = _collect_ids(paused_raw)
    target_states: Dict[str, str] = {}
    security_maps: Dict[str, Mapping[str, Any]] = {}
    for appliance in appliances:
        nepk = str(appliance.get("nePk") or appliance.get("id"))
        reachability = gateway.get_reachability(nepk)
        if nepk in paused_ids:
            state = "paused"
        elif int(reachability.get("state", appliance.get("state", 2))) == 1:
            state = "reachable" if _version_at_least(str(appliance.get("softwareVersion", "")), (9, 5)) else "unsupported"
        else:
            state = "unreachable"
        target_states[nepk] = state
        if state == "reachable":
            security_maps[nepk] = gateway.get_security_map(nepk)
    local_priorities: Dict[Tuple[str, str, str, str], Set[int]] = {}
    for pair in requested_pairs:
        for rule in [item for item in rules if item.pair == pair]:
            source_zone = zones.get((rule.source_segment, rule.source_zone))
            destination_zone = zones.get((rule.destination_segment, rule.destination_zone))
            if source_zone is None or destination_zone is None:
                continue
            zone_key = "{}_{}".format(source_zone, destination_zone)
            priorities = local_priorities.setdefault(rule.scope, set())
            for security_map in security_maps.values():
                entries = security_map.get("map1", {}).get(zone_key, {}).get("prio", {})
                priorities.update(int(priority) for priority, value in entries.items() if value.get("gms_marked") is False)
    return Inventory(
        segments=segments,
        zones=zones,
        policies=policies,
        address_groups={str(item["name"]) for item in address},
        service_groups={str(item["name"]) for item in service},
        applications=applications,
        application_groups=application_groups,
        local_priorities=local_priorities,
        statuses={name: "complete" for name in ("segments", "zones", "policies", "address_groups", "service_groups", "applications", "application_groups", "appliance_local_policies", "targets")},
        segmentation_enabled=segmentation.get("enable") is True,
        target_states=target_states,
        pair_errors=pair_errors,
    )


def _collect_ids(value: Any) -> Set[str]:
    result: Set[str] = set()
    if isinstance(value, dict):
        for key in ("nePk", "id", "nepk"):
            if value.get(key):
                result.add(str(value[key]))
        for item in value.values():
            result.update(_collect_ids(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_collect_ids(item))
    elif isinstance(value, str):
        result.add(value)
    return result


def _wildcard_has_exact_name(value: Any, name: str) -> bool:
    if isinstance(value, dict):
        if name in {str(key) for key in value} or any(str(value.get(key, "")) == name for key in ("name", "group", "displayName")):
            return True
        return any(_wildcard_has_exact_name(item, name) for item in value.values())
    if isinstance(value, list):
        return any(_wildcard_has_exact_name(item, name) for item in value)
    return str(value) == name


def _application_names(port: Any, dns: Any, compound: Any) -> Set[str]:
    names = {str(item["name"]) for entries in port.values() for item in entries}
    names.update(str(item["name"]) for item in dns)
    names.update(str(item["name"]) for item in compound.values())
    return names


def _firewall_plan_from_dict(value: Mapping[str, Any]) -> FirewallPlan:
    pair_plans = []
    for item in value["pairs"]:
        rules = [FirewallRule(**rule) for rule in item.get("rules", [])]
        pair_plans.append(PairPlan(
            pair=tuple(item["pair"]), segment_map=item["segment_map"], eligible=item["eligible"], baseline=item["baseline"], candidate=item["candidate"], baseline_fingerprint=item["baseline_fingerprint"], rules=rules, created_priorities=[tuple(entry) for entry in item.get("created_priorities", [])], no_op_rows=item.get("no_op_rows", []), errors=item.get("errors", []), warnings=item.get("warnings", []), target_states=item.get("target_states", {}),
        ))
    return FirewallPlan(pair_plans, value.get("errors", []), value.get("warnings", []), [FirewallRule(**rule) for rule in value.get("resolved_rows", [])])


def _firewall_apply(args: argparse.Namespace) -> int:
    report = _load_json(args.approved_plan)
    if report.get("kind") != "firewall" or fingerprint(report["plan"]) != report.get("fingerprint"):
        raise ValidationError("approved firewall plan is invalid or changed")
    plan = _firewall_plan_from_dict(report["plan"])
    if not _approve(report, args.dry_run):
        return 0
    result = FirewallExecutor(_gateway(args)).apply(plan)
    if args.report:
        report_value = asdict(result)
        report_value["report_fingerprint"] = fingerprint(report_value)
        safe_report(args.report, report_value)
    _print(asdict(result))
    return result.exit_code


def _firewall_verify(args: argparse.Namespace) -> int:
    end_time = int(time.time() * 1000)
    actions = _gateway(args).get_actions(end_time - 86400000, end_time)
    matches = [item for item in actions if args.run_id in json.dumps(item, sort_keys=True)] if isinstance(actions, list) else []
    result = {"run_reference": args.run_id, "audit_matches": matches, "note": "audit evidence supports but does not prove appliance convergence"}
    if args.output:
        result["report_fingerprint"] = fingerprint(result)
        safe_report(args.output, result)
    _print(result)
    return 0 if matches else 5


def _zones_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    baseline = gateway.get_zones()
    all_vrf = gateway.get_all_vrf_zones()
    mappings = gateway.get_zone_mappings()
    plan = plan_zones(baseline, gateway.get_next_zone_id(), args.name, all_vrf, mappings)
    value = {"kind": "zones", "baseline": plan.baseline, "candidate": plan.candidate, "baseline_fingerprint": plan.baseline_fingerprint, "created": plan.created, "all_vrf_fingerprint": plan.all_vrf_fingerprint, "mappings_fingerprint": plan.mappings_fingerprint}
    value["report_fingerprint"] = fingerprint({key: item for key, item in value.items() if key != "report_fingerprint"})
    safe_report(args.output, value)
    _print({"output": args.output, "created": plan.created})
    return 0


def _zones_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "zones")
    plan = ZonePlan(value["baseline"], value["candidate"], value["baseline_fingerprint"], value["created"], value.get("all_vrf_fingerprint"), value.get("mappings_fingerprint"))
    if not _approve(value, args.dry_run, list(plan.created)):
        return 0
    result = apply_zones(_gateway(args), plan)
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _zones_create(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    baseline = gateway.get_zones()
    all_vrf = gateway.get_all_vrf_zones()
    mappings = gateway.get_zone_mappings()
    plan = plan_zones(baseline, gateway.get_next_zone_id(), args.name, all_vrf, mappings)
    preview = {"kind": "zones", "baseline": plan.baseline, "candidate": plan.candidate, "baseline_fingerprint": plan.baseline_fingerprint, "created": plan.created, "all_vrf_fingerprint": plan.all_vrf_fingerprint, "mappings_fingerprint": plan.mappings_fingerprint}
    if not _approve(preview, args.dry_run, list(plan.created)):
        return 0
    result = apply_zones(gateway, plan)
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _bulk_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    existing = gateway.get_address_groups() if args.bulk_kind == "address" else gateway.get_service_groups()
    existing_names = {str(item.get("name")) for item in existing}
    rows = parse_address_groups(args.csv, existing_names) if args.bulk_kind == "address" else parse_service_groups(args.csv, existing_names)
    plan = plan_native_groups(args.bulk_kind, rows, existing)
    value = {"kind": args.bulk_kind + "-groups", "new_rows": plan.new_rows, "no_ops": plan.no_ops, "conflicts": plan.conflicts, "content": base64.b64encode(plan.content).decode("ascii"), "baseline_fingerprint": plan.baseline_fingerprint}
    _seal_report(value, args.output)
    _print({"output": args.output, "create": len(plan.new_rows), "no_ops": plan.no_ops, "conflicts": plan.conflicts})
    return 2 if plan.conflicts else 0


def _bulk_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, args.bulk_kind + "-groups")
    plan = BulkPlan(args.bulk_kind, value["new_rows"], value["no_ops"], value["conflicts"], base64.b64decode(value["content"]), value.get("baseline_fingerprint"))
    if not _approve(value, args.dry_run):
        return 0
    result = apply_native_groups(_gateway(args), plan)
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _bulk_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    existing = gateway.get_address_groups() if args.bulk_kind == "address" else gateway.get_service_groups()
    existing_names = {str(item.get("name")) for item in existing}
    rows = parse_address_groups(args.csv, existing_names) if args.bulk_kind == "address" else parse_service_groups(args.csv, existing_names)
    plan = plan_native_groups(args.bulk_kind, rows, existing)
    preview = {"kind": args.bulk_kind + "-groups", "new_rows": plan.new_rows, "no_ops": plan.no_ops, "conflicts": plan.conflicts, "baseline_fingerprint": plan.baseline_fingerprint, "multipart_field": "csvFile", "content_fingerprint": fingerprint(plan.content.decode("utf-8"))}
    if plan.conflicts:
        _print(preview)
        return 2
    if not _approve(preview, args.dry_run):
        return 0
    result = apply_native_groups(gateway, plan)
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _resolve_applications(gateway: OrchestratorGateway, requested: Set[str], offline_path: Optional[str]) -> Set[str]:
    if offline_path:
        return set(_load_json(offline_path))
    port = gateway.get_application_definitions("portProtocolClassification")
    dns = gateway.get_application_definitions("dnsClassification")
    compound = gateway.get_application_definitions("compoundClassification")
    available = _application_names(port, dns, compound)
    for name in requested - available:
        if _wildcard_has_exact_name(gateway.search_application(name), name):
            available.add(name)
    return available


def _app_groups_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    rows = parse_application_groups(args.csv)
    requested = {name.strip() for row in rows for name in row["Applications"].split(",") if name.strip()}
    applications = _resolve_applications(gateway, requested, args.applications)
    plan = plan_application_groups(rows, gateway.get_application_groups(), applications)
    value = {"kind": "app-groups", **plan}
    _seal_report(value, args.output)
    _print({"output": args.output, "conflicts": plan["conflicts"], "no_ops": plan["no_ops"]})
    return 2 if plan["conflicts"] else 0


def _app_groups_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "app-groups")
    if not _approve(value, args.dry_run):
        return 0
    result = apply_application_groups(_gateway(args), value)
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _app_groups_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    rows = parse_application_groups(args.csv)
    requested = {name.strip() for row in rows for name in row["Applications"].split(",") if name.strip()}
    plan = plan_application_groups(rows, gateway.get_application_groups(), _resolve_applications(gateway, requested, args.applications))
    preview = {"kind": "app-groups", **plan}
    if plan["conflicts"]:
        _print(preview)
        return 2
    if not _approve(preview, args.dry_run):
        return 0
    result = apply_application_groups(gateway, plan)
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _definition_appexpress_modes(definitions: Sequence[ApplicationDefinition]) -> Dict[str, str]:
    modes: Dict[str, str] = {}
    names: Dict[str, str] = {}
    for definition in definitions:
        key = definition.name.lower()
        if key in names and modes[names[key]] != definition.app_express:
            raise ValidationError("application definition {} has conflicting AppExpressMode values".format(definition.name))
        if key not in names:
            names[key] = definition.name
            modes[definition.name] = definition.app_express
    return modes


def _definitions_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    definitions = parse_application_definitions(args.csv)
    inventories = {base: gateway.get_application_definitions(base) for base in ("portProtocolClassification", "dnsClassification", "compoundClassification")}
    plan = plan_application_definitions(definitions, inventories)
    appexpress = plan_appexpress_modes(_definition_appexpress_modes(definitions), gateway.get_appexpress())
    value = {"kind": "app-definitions", "new": [asdict(item) for item in plan.new], "no_ops": plan.no_ops, "conflicts": plan.conflicts, "inventories": inventories, "fingerprints": plan.fingerprints, "appexpress": appexpress}
    _seal_report(value, args.output)
    _print({"output": args.output, "create": len(plan.new), "no_ops": plan.no_ops, "conflicts": plan.conflicts, "appexpress_monitor": appexpress["monitor"], "appexpress_off": appexpress["off"]})
    return 2 if plan.conflicts else 0


def _definitions_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "app-definitions")
    if value["conflicts"]:
        raise ValidationError("application definition plan has conflicts")
    definitions = [ApplicationDefinition(**item) for item in value["new"]]
    if not _approve(value, args.dry_run):
        return 0
    result = execute_application_definitions_with_appexpress(_gateway(args), definitions, value["inventories"], value["appexpress"])
    _print(result)
    return 0 if result["status"] == "success" else 5


def _definitions_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    definitions = parse_application_definitions(args.csv)
    inventories = {base: gateway.get_application_definitions(base) for base in ("portProtocolClassification", "dnsClassification", "compoundClassification")}
    plan = plan_application_definitions(definitions, inventories)
    appexpress = plan_appexpress_modes(_definition_appexpress_modes(definitions), gateway.get_appexpress())
    preview = {"kind": "app-definitions", "new": [asdict(item) for item in plan.new], "no_ops": plan.no_ops, "conflicts": plan.conflicts, "fingerprints": plan.fingerprints, "appexpress": appexpress}
    if plan.conflicts:
        _print(preview)
        return 2
    if not _approve(preview, args.dry_run):
        return 0
    result = execute_application_definitions_with_appexpress(gateway, plan.new, inventories, appexpress)
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] == "success" else 5


def _read_appexpress_csv(path: str) -> List[str]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames != ["Application", "Mode"]:
            raise ValidationError("AppExpress CSV headers must be Application,Mode")
        names = []
        for number, row in enumerate(reader, 2):
            if (row.get("Mode") or "").strip().upper() != "MONITOR":
                raise ValidationError("AppExpress row {} mode must be MONITOR".format(number))
            name = (row.get("Application") or "").strip()
            if not name:
                raise ValidationError("AppExpress row {} requires Application".format(number))
            names.append(name)
        return names


def _appexpress_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    names = args.application or _read_appexpress_csv(args.csv)
    plan = plan_appexpress(names, _resolve_applications(gateway, set(names), args.applications), gateway.get_appexpress())
    value = {"kind": "appexpress", **plan}
    _seal_report(value, args.output)
    _print({"output": args.output, "created": plan["created"]})
    return 0


def _appexpress_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "appexpress")
    if not _approve(value, args.dry_run):
        return 0
    result = apply_appexpress(_gateway(args), value)
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _appexpress_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    names = args.application or _read_appexpress_csv(args.csv)
    plan = plan_appexpress(names, _resolve_applications(gateway, set(names), args.applications), gateway.get_appexpress())
    preview = {"kind": "appexpress", **plan}
    if not _approve(preview, args.dry_run):
        return 0
    result = apply_appexpress(gateway, plan)
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _seal_report(value: Dict[str, Any], output: str) -> None:
    value["report_fingerprint"] = fingerprint({key: item for key, item in value.items() if key != "report_fingerprint"})
    safe_report(output, value)


def _validate_report(value: Mapping[str, Any], kind: str) -> None:
    if value.get("kind") != kind:
        raise ValidationError("approved plan has wrong workflow kind")
    content = {key: item for key, item in value.items() if key != "report_fingerprint"}
    if fingerprint(content) != value.get("report_fingerprint"):
        raise ValidationError("approved plan fingerprint does not match")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except ApprovalError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code
    except EdgeConnectError as error:
        print(str(redact(str(error))), file=sys.stderr)
        return error.exit_code
    except (OSError, ValueError, TypeError, json.JSONDecodeError, csv.Error) as error:
        print("error: {}".format(redact(str(error))), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
