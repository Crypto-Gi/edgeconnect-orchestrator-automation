import argparse
import base64
import copy
import csv
import json
import secrets
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .client import ApiClient
from .config import load_config
from .errors import ApprovalError, DriftError, EdgeConnectError, ValidationError
from .firewall import FirewallExecutor, build_firewall_plan, normalize_rule, parse_firewall_csv, parse_firewall_document, rule_payload, write_resolved_csv
from .gateway import OrchestratorGateway
from .models import FirewallPlan, FirewallRule, Inventory, PairPlan
from .util import fingerprint, redact, safe_report, semantic_equal, split_values
from .workflows import ApplicationDefinition, BulkPlan, ZonePlan, _address_semantic, _service_semantic, apply_application_groups, apply_native_groups, apply_template_acls, apply_zones, execute_application_definitions_with_appexpress, native_group_semantic_equal, parse_address_groups, parse_application_definitions, parse_application_groups, parse_application_groups_partial, parse_service_groups, parse_template_acls, plan_appexpress_modes, plan_application_definitions, plan_application_groups, plan_native_groups, plan_template_acls, plan_zones, resolve_compound_references


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="edgeconnect-auto", description="Safety-focused EdgeConnect Orchestrator automation")
    parser.add_argument("--dotenv", help="dotenv path override; defaults to ./.env when present")
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
    delete = firewall_sub.add_parser("delete", help="preview, confirm, delete exact CSV-matched rules, and verify")
    _add_delete_args(delete)
    delete.set_defaults(handler=_firewall_delete)
    verify = firewall_sub.add_parser("verify", help="read audit evidence for a run reference")
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--output")
    verify.set_defaults(handler=_firewall_verify)

    template_acls = subparsers.add_parser("template-acls")
    template_acl_sub = template_acls.add_subparsers(dest="template_acl_command", required=True)
    template_acl_plan = template_acl_sub.add_parser("plan", help="build a read-only template ACL merge plan")
    template_acl_plan.add_argument("--csv", required=True)
    template_acl_plan.add_argument("--output", required=True)
    template_acl_plan.add_argument("--dry-run", action="store_true")
    template_acl_plan.set_defaults(handler=_template_acls_plan)
    template_acl_apply = template_acl_sub.add_parser("apply", help="apply an approved template ACL merge plan")
    template_acl_apply.add_argument("--approved-plan", required=True)
    template_acl_apply.add_argument("--report")
    template_acl_apply.add_argument("--dry-run", action="store_true")
    template_acl_apply.set_defaults(handler=_template_acls_apply)
    template_acl_deploy = template_acl_sub.add_parser("deploy", help="discover, preview, confirm, merge, and verify template ACLs")
    template_acl_deploy.add_argument("--csv", required=True)
    template_acl_deploy.add_argument("--report")
    template_acl_deploy.add_argument("--dry-run", action="store_true")
    template_acl_deploy.set_defaults(handler=_template_acls_deploy)

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
    app_group_delete = app_group_sub.add_parser("delete", help="preview, confirm, delete exact CSV-matched application groups, and verify")
    _add_delete_args(app_group_delete)
    app_group_delete.set_defaults(handler=_app_groups_delete)

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
    definition_delete = definition_sub.add_parser("delete", help="preview, confirm, delete exact CSV-matched definitions and AppExpress entries, and verify")
    _add_delete_args(definition_delete)
    definition_delete.set_defaults(handler=_definitions_delete)

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
    delete = commands.add_parser("delete", help="preview, confirm, delete exact CSV-matched groups, and verify")
    _add_delete_args(delete)
    delete.set_defaults(handler=_bulk_delete, bulk_kind=kind)


def _add_delete_args(parser: Any) -> None:
    parser.add_argument("--csv", required=True)
    parser.add_argument("--report")
    parser.add_argument("--dry-run", action="store_true")


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


DELETE_ACKNOWLEDGMENT = "I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION"


def _approve_template_acls(preview: Mapping[str, Any], dry_run: bool) -> bool:
    _print({"preview": preview, "impact": "template-group Access Lists write", "validation": "fresh central and associated-appliance readback", "recovery": "no automatic rollback; exact recovery requires separate review"})
    if dry_run:
        return False
    if not sys.stdin.isatty():
        raise ApprovalError("non-interactive writes are refused")
    for group in preview["plan"]["groups"]:
        if not group["eligible"]:
            continue
        name = group["template_group"]
        if group["create"] and input("Type the exact template group name {} to authorize creation: ".format(name)) != name:
            raise ApprovalError("template group creation confirmation refused")
        if not group["create"] and group["selection_change"]:
            expected = "SELECT ACLS {}".format(name)
            if input("Type {} to select Access Lists: ".format(expected)) != expected:
                raise ApprovalError("Access Lists selection confirmation refused")
        if group["template_mode_change"]:
            expected = "MERGE ACLS {}".format(name)
            if input("Type {} to change appliance template mode: ".format(expected)) != expected:
                raise ApprovalError("template merge-mode confirmation refused")
    if input("Type APPLY to execute the exact preview: ") != "APPLY":
        raise ApprovalError("write approval refused")
    return True


def _deletion_table(rows: Sequence[Tuple[str, str, str]]) -> str:
    values = [(str(index), kind, name, identity) for index, (kind, name, identity) in enumerate(rows, 1)]
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


def _approve_delete(rows: Sequence[Tuple[str, str, str]], dry_run: bool) -> bool:
    print("\nWARNING 1 OF 3 — COMPLETE DELETION TABLE ({} resources)\n".format(len(rows)))
    print(_deletion_table(rows))
    if dry_run or not rows:
        return False
    if not sys.stdin.isatty():
        raise ApprovalError("non-interactive deletion is refused")
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "DELETE-{}".format("".join(secrets.choice(alphabet) for _ in range(8)))
    print("\nWARNING 2 OF 3 — Type this system-generated code exactly:\n\n{}\n".format(code))
    if input("Deletion code: ") != code:
        raise ApprovalError("deletion confirmation code refused")
    print("\nWARNING 3 OF 3 — FINAL DESTRUCTIVE ACTION WARNING")
    print("The complete table above will be deleted. Dependencies may stop working, rollback is not automatic, and you are responsible for this abyss action.")
    print("\nTo answer 'Are you absolutely sure?' type exactly:\n\n{}\n".format(DELETE_ACKNOWLEDGMENT))
    if input("Final acknowledgment: ") != DELETE_ACKNOWLEDGMENT:
        raise ApprovalError("final deletion acknowledgment refused")
    return True


def _delete_output(args: argparse.Namespace, preview: Mapping[str, Any], result: Optional[Mapping[str, Any]] = None) -> None:
    value = {"preview": preview, "status": "DRY_RUN"} if result is None else {"preview": preview, "result": result}
    value["report_fingerprint"] = fingerprint(value)
    if args.report:
        safe_report(args.report, value)
    _print(value)


def _discovery(args: argparse.Namespace) -> int:
    result = _gateway(args).discover()
    result["fingerprint"] = fingerprint(result)
    if args.output:
        safe_report(args.output, result)
    _print(result)
    return 0


def _firewall_validate(args: argparse.Namespace) -> int:
    document = parse_firewall_document(Path(args.csv).read_text(encoding="utf-8-sig"))
    result = {"status": "valid" if not document.errors else "invalid", "rules": len(document.rules), "segment_pairs": sorted({"{} -> {}".format(*rule.pair) for rule in document.rules}), "errors": document.errors, "issues": document.issues, "warnings": document.warnings}
    _print(result)
    return 0 if not document.errors else 2


def _firewall_plan(args: argparse.Namespace) -> int:
    document = parse_firewall_document(Path(args.csv).read_text(encoding="utf-8-sig"))
    pairs = set(document.pair_errors) | {rule.pair for rule in document.rules}
    if args.inventory:
        inventory = _inventory_from_dict(_load_json(args.inventory))
    else:
        inventory = _discover_inventory(_gateway(args), document.rules, pairs)
    plan = build_firewall_plan(document.rules, inventory, document.pair_errors, document.global_errors, document.pair_warnings)
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
    plan = build_firewall_plan(document.rules, inventory, document.pair_errors, document.global_errors, document.pair_warnings)
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


def _firewall_delete(args: argparse.Namespace) -> int:
    document = parse_firewall_document(Path(args.csv).read_text(encoding="utf-8-sig"))
    if document.errors:
        raise ValidationError("\n".join(document.errors))
    if any(rule.priority is None for rule in document.rules):
        raise ValidationError("firewall delete requires explicit priority on every CSV row")
    gateway = _gateway(args)
    segment_raw = gateway.get_segments()
    segments = {str(value["name"]): int(value.get("id", key)) for key, value in segment_raw.items()}
    zone_rows = gateway.get_segment_zones()
    zones = {(str(item["vrfName"]), str(item["zoneName"])): int(item["zoneId"]) for item in zone_rows}
    grouped: Dict[Tuple[str, str], List[FirewallRule]] = {}
    for rule in document.rules:
        grouped.setdefault(rule.pair, []).append(rule)
    plans = []
    table = []
    absent = []
    conflicts = []
    for pair, rules in sorted(grouped.items()):
        if pair[0] not in segments or pair[1] not in segments:
            conflicts.append("missing segment pair {} -> {}".format(*pair))
            continue
        segment_map = "{}_{}".format(segments[pair[0]], segments[pair[1]])
        baseline = gateway.get_policy(segment_map)
        candidate = copy.deepcopy(baseline)
        removed = []
        for rule in rules:
            source_id = zones.get((rule.source_segment, rule.source_zone))
            destination_id = zones.get((rule.destination_segment, rule.destination_zone))
            if source_id is None or destination_id is None:
                conflicts.append("row {} zone mapping is missing".format(rule.row))
                continue
            zone_key = "{}_{}".format(source_id, destination_id)
            priorities = candidate.get("data", {}).get("map1", {}).get(zone_key, {}).get("prio", {})
            actual = priorities.get(str(rule.priority))
            if actual is None:
                absent.append(rule.rule_key)
            elif not semantic_equal(normalize_rule(actual), normalize_rule(rule_payload(rule))):
                conflicts.append("row {} priority {} contains a semantically different live rule".format(rule.row, rule.priority))
            else:
                del priorities[str(rule.priority)]
                zone = candidate.get("data", {}).get("map1", {}).get(zone_key, {})
                if not priorities and set(zone) <= {"prio"}:
                    candidate["data"]["map1"].pop(zone_key, None)
                removed.append({"rule_key": rule.rule_key, "zone_key": zone_key, "priority": int(rule.priority)})
                table.append(("Firewall rule", rule.rule_key, "{} -> {}; zones {}; priority {}".format(*pair, zone_key, rule.priority)))
        plans.append({"pair": pair, "segment_map": segment_map, "baseline": baseline, "candidate": candidate, "fingerprint": fingerprint(baseline), "removed": removed})
    if conflicts:
        raise ValidationError("CSV deletion blocked: {}".format("; ".join(conflicts)))
    preview = {"kind": "firewall-delete", "plans": plans, "absent": sorted(absent)}
    approved = _approve_delete(table, args.dry_run)
    if not approved:
        _delete_output(args, preview, {"status": "no_op"} if not table and not args.dry_run else None)
        return 0
    results = []
    for plan in plans:
        if not plan["removed"]:
            continue
        if fingerprint(gateway.get_policy(plan["segment_map"])) != plan["fingerprint"]:
            raise DriftError("firewall policy changed after confirmation for {}".format(plan["segment_map"]))
        reference = "edgeconnect-auto-delete-{}".format(int(time.time()))
        gateway.post_policy(plan["segment_map"], plan["candidate"], reference)
        verified = semantic_equal(gateway.get_policy(plan["segment_map"]), plan["candidate"])
        audit = gateway.correlate_audit(plan["segment_map"], reference) if hasattr(gateway, "correlate_audit") else True
        results.append({"pair": plan["pair"], "deleted": plan["removed"], "readback_verified": verified, "audit_verified": audit})
    success = all(item["readback_verified"] and item["audit_verified"] for item in results)
    result = {"status": "success" if success else "partial", "pairs": results}
    _delete_output(args, preview, result)
    return 0 if success else 5


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
        acls=value.get("acls", {}),
        appliance_acls=value.get("appliance_acls", {}),
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
    requested_acls = {rule.acl for rule in rules if rule.acl}
    acls = gateway.get_central_acls(requested_acls) if requested_acls else {}
    known = {name.lower() for name in applications}
    for name in requested_apps:
        if name.lower() not in known and _wildcard_has_exact_name(gateway.search_application(name), name, casefold=True):
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
    appliance_acls: Dict[str, Mapping[str, Mapping[str, Any]]] = {}
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
            if requested_acls:
                appliance_acls[nepk] = gateway.get_appliance_acls(nepk)
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
        acls=acls,
        appliance_acls=appliance_acls,
        local_priorities=local_priorities,
        statuses={name: "complete" for name in ("segments", "zones", "policies", "address_groups", "service_groups", "applications", "application_groups", "appliance_local_policies", "targets") + (("acls",) if requested_acls else ())},
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


def _wildcard_has_exact_name(value: Any, name: str, casefold: bool = False) -> bool:
    def same(candidate: Any) -> bool:
        return str(candidate).lower() == name.lower() if casefold else str(candidate) == name

    if isinstance(value, dict):
        if any(same(key) for key in value) or any(same(value.get(key, "")) for key in ("name", "group", "displayName")):
            return True
        return any(_wildcard_has_exact_name(item, name, casefold) for item in value.values())
    if isinstance(value, list):
        return any(_wildcard_has_exact_name(item, name, casefold) for item in value)
    return same(value)


def _application_name_list(port: Any, dns: Any, compound: Any) -> List[str]:
    return [str(item["name"]) for entries in port.values() for item in entries] + [str(item["name"]) for item in dns] + [str(item["name"]) for item in compound.values() if isinstance(item, dict)]


def _application_names(port: Any, dns: Any, compound: Any) -> Set[str]:
    return set(_application_name_list(port, dns, compound))


def _firewall_plan_from_dict(value: Mapping[str, Any]) -> FirewallPlan:
    pair_plans = []
    for item in value["pairs"]:
        rules = [FirewallRule(**rule) for rule in item.get("rules", [])]
        pair_plans.append(PairPlan(
            pair=tuple(item["pair"]), segment_map=item["segment_map"], eligible=item["eligible"], baseline=item["baseline"], candidate=item["candidate"], baseline_fingerprint=item["baseline_fingerprint"], rules=rules, created_priorities=[tuple(entry) for entry in item.get("created_priorities", [])], no_op_rows=item.get("no_op_rows", []), errors=item.get("errors", []), warnings=item.get("warnings", []), target_states=item.get("target_states", {}), acl_dependencies=item.get("acl_dependencies", {}), acl_inventory_fingerprint=item.get("acl_inventory_fingerprint", ""),
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


def _discover_template_acl_plan(gateway: OrchestratorGateway, csv_path: str) -> Dict[str, Any]:
    rules = parse_template_acls(csv_path)
    groups = gateway.get_template_groups()
    selections = {str(group["name"]): gateway.get_template_selection(str(group["name"])) for group in groups}
    associations = gateway.get_template_associations()
    applications = {str(rule.entry["application"]) for rule in rules if rule.entry.get("application")}
    application_groups = {str(rule.entry["app_group"]) for rule in rules if rule.entry.get("app_group")}
    available_apps = {name for name in applications if _wildcard_has_exact_name(gateway.search_application(name), name, casefold=True)}
    available_groups = {name for name in application_groups if _wildcard_has_exact_name(gateway.search_application_group(name), name)}
    return plan_template_acls(rules, groups, selections, associations, available_apps, available_groups)


def _template_acl_preview(plan: Mapping[str, Any]) -> Dict[str, Any]:
    value = {"kind": "template-acls", "plan": plan}
    value["fingerprint"] = fingerprint(plan)
    return value


def _template_acl_result_code(plan: Mapping[str, Any], result: Optional[Mapping[str, Any]] = None) -> int:
    if not plan["eligible_groups"]:
        return 2
    if result is None:
        return 5 if len(plan["eligible_groups"]) != len(plan["groups"]) else 0
    return 0 if result["status"] in {"success", "no_op"} else 5


def _validate_template_acl_dependencies(gateway: OrchestratorGateway, plan: Mapping[str, Any]) -> None:
    for name in plan.get("application_dependencies", []):
        if not _wildcard_has_exact_name(gateway.search_application(name), name, casefold=True):
            raise DriftError("application dependency {} changed before write".format(name))
    for name in plan.get("application_group_dependencies", []):
        if not _wildcard_has_exact_name(gateway.search_application_group(name), name):
            raise DriftError("application group dependency {} changed before write".format(name))


def _template_acls_plan(args: argparse.Namespace) -> int:
    plan = _discover_template_acl_plan(_gateway(args), args.csv)
    value = _template_acl_preview(plan)
    _seal_report(value, args.output)
    _print({"output": args.output, "eligible_groups": plan["eligible_groups"], "ineligible_groups": [group["template_group"] for group in plan["groups"] if not group["eligible"]]})
    return _template_acl_result_code(plan)


def _template_acls_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "template-acls")
    preview = {"kind": value["kind"], "plan": value["plan"], "fingerprint": value.get("fingerprint")}
    if fingerprint(value["plan"]) != value.get("fingerprint"):
        raise ValidationError("approved template ACL plan is invalid or changed")
    if not value["plan"]["eligible_groups"]:
        _print(preview)
        return 2
    if not _approve_template_acls(preview, args.dry_run):
        return _template_acl_result_code(value["plan"])
    gateway = _gateway(args)
    _validate_template_acl_dependencies(gateway, value["plan"])
    result = apply_template_acls(gateway, value["plan"])
    report = {"preview": preview, "result": result}
    report["report_fingerprint"] = fingerprint(report)
    if args.report:
        safe_report(args.report, report)
    _print(report)
    return _template_acl_result_code(value["plan"], result)


def _template_acls_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    plan = _discover_template_acl_plan(gateway, args.csv)
    preview = _template_acl_preview(plan)
    if not plan["eligible_groups"]:
        _print(preview)
        return 2
    if not _approve_template_acls(preview, args.dry_run):
        if args.report:
            safe_report(args.report, {"preview": preview, "status": "DRY_RUN", "report_fingerprint": fingerprint(preview)})
        return _template_acl_result_code(plan)
    _validate_template_acl_dependencies(gateway, plan)
    result = apply_template_acls(gateway, plan)
    report = {"preview": preview, "result": result}
    report["report_fingerprint"] = fingerprint(report)
    if args.report:
        safe_report(args.report, report)
    _print(report)
    return _template_acl_result_code(plan, result)


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
    value = {"kind": args.bulk_kind + "-groups", "new_rows": plan.new_rows, "no_ops": plan.no_ops, "conflicts": plan.conflicts, "content": base64.b64encode(plan.content).decode("ascii"), "baseline_fingerprint": plan.baseline_fingerprint, "warnings": plan.warnings}
    _seal_report(value, args.output)
    _print({"output": args.output, "create": len(plan.new_rows), "no_ops": plan.no_ops, "conflicts": plan.conflicts, "warnings": plan.warnings})
    return 2 if plan.conflicts else 0


def _bulk_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, args.bulk_kind + "-groups")
    plan = BulkPlan(args.bulk_kind, value["new_rows"], value["no_ops"], value["conflicts"], base64.b64decode(value["content"]), value.get("baseline_fingerprint"), value.get("warnings", []))
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
    preview = {"kind": args.bulk_kind + "-groups", "new_rows": plan.new_rows, "no_ops": plan.no_ops, "conflicts": plan.conflicts, "baseline_fingerprint": plan.baseline_fingerprint, "multipart_field": "csvFile", "content_fingerprint": fingerprint(plan.content.decode("utf-8")), "warnings": plan.warnings}
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


def _firewall_references(gateway: OrchestratorGateway, keys: Sequence[str], names: Set[str], casefold: bool = False) -> List[str]:
    if not names:
        return []
    wanted = {name.lower() for name in names} if casefold else set(names)
    segments = sorted({int(value.get("id", key)) for key, value in gateway.get_segments().items()})
    hits = []
    for source in segments:
        for destination in segments:
            segment_map = "{}_{}".format(source, destination)
            for zone_key, zone in gateway.get_policy(segment_map).get("data", {}).get("map1", {}).items():
                for priority, rule in (zone.get("prio") or {}).items():
                    match = rule.get("match") or {}
                    for key in keys:
                        for value in split_values(str(match.get(key, ""))):
                            if (value.lower() if casefold else value) in wanted:
                                hits.append("global firewall {} zones {} priority {} ({}={})".format(segment_map, zone_key, priority, key, value))
    return hits


def _template_acl_references(gateway: OrchestratorGateway, key: str, names: Set[str], casefold: bool = False) -> List[str]:
    if not names:
        return []
    wanted = {name.lower() for name in names} if casefold else set(names)
    hits = []
    for acl_name, occurrences in gateway.get_central_acls().items():
        for occurrence in occurrences:
            for priority, entry in (occurrence.get("entries") or {}).items():
                value = str(entry.get(key, ""))
                if value and (value.lower() if casefold else value) in wanted:
                    hits.append("template group {} ACL {} priority {} ({}={})".format(occurrence.get("template_group"), acl_name, priority, key, value))
    return hits


def _block_referenced_deletion(references: Sequence[str], label: str, rule: str) -> None:
    if references:
        raise ValidationError("[{}] deletion blocked because {} still reference the requested objects:\n{}".format(rule, label, "\n".join(references)))


def _group_references(group: Mapping[str, Any], kind: str) -> Set[str]:
    fields = ("includedGroups", "excludedGroups") if kind == "service" else ("includedGroups",)
    return {str(value) for rule in group.get("rules", []) for field in fields for value in rule.get(field, [])}


def _group_delete_order(names: Set[str], current: Mapping[str, Mapping[str, Any]], kind: str) -> List[str]:
    remaining = set(names)
    ordered: List[str] = []
    while remaining:
        referenced = {name for item in remaining for name in _group_references(current[item], kind) if name in remaining}
        candidates = sorted(remaining - referenced)
        if not candidates:
            raise ValidationError("cannot calculate dependency-safe group deletion order")
        for name in candidates:
            ordered.append(name)
            remaining.remove(name)
    return ordered


def _bulk_delete(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    existing = gateway.get_address_groups() if args.bulk_kind == "address" else gateway.get_service_groups()
    current = {str(item.get("name")): item for item in existing}
    existing_names = set(current)
    rows = parse_address_groups(args.csv, existing_names) if args.bulk_kind == "address" else parse_service_groups(args.csv, existing_names)
    grouped: Dict[str, List[Mapping[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row["Name"], []).append(row)
    normalizer = _address_semantic if args.bulk_kind == "address" else _service_semantic
    conflicts = [name for name, values in grouped.items() if name in current and not native_group_semantic_equal(current[name], normalizer(values))]
    if conflicts:
        raise ValidationError("CSV deletion blocked by semantically different existing groups: {}".format(", ".join(sorted(conflicts))))
    targets = set(grouped) & set(current)
    for name, value in current.items():
        if name not in targets and _group_references(value, args.bulk_kind) & targets:
            raise ValidationError("non-target group {} references a requested deletion".format(name))
    group_keys = ("src_addrgrp_groups", "dst_addrgrp_groups", "either_addrgrp_groups") if args.bulk_kind == "address" else ("src_srvcgrp_groups", "dst_srvcgrp_groups", "either_srvcgrp_groups")
    _block_referenced_deletion(_firewall_references(gateway, group_keys, targets), "firewall rules", "DEL-05")
    order = _group_delete_order(targets, current, args.bulk_kind)
    kind_label = "Address group" if args.bulk_kind == "address" else "Service group"
    table = [(kind_label, name, "exact CSV semantic match") for name in order]
    preview = {"kind": args.bulk_kind + "-groups-delete", "delete": order, "absent": sorted(set(grouped) - set(current)), "baseline_fingerprint": fingerprint(existing)}
    approved = _approve_delete(table, args.dry_run)
    if not approved:
        _delete_output(args, preview, {"status": "no_op"} if not table and not args.dry_run else None)
        return 0
    fresh = gateway.get_address_groups() if args.bulk_kind == "address" else gateway.get_service_groups()
    if fingerprint(fresh) != preview["baseline_fingerprint"]:
        raise DriftError("native group collection changed after confirmation")
    deleted = []
    for name in order:
        live = {str(item.get("name")): item for item in (gateway.get_address_groups() if args.bulk_kind == "address" else gateway.get_service_groups())}
        if not native_group_semantic_equal(live.get(name), normalizer(grouped[name])):
            raise ValidationError("group changed before deletion: {}".format(name))
        if args.bulk_kind == "address":
            gateway.delete_address_group(name)
        else:
            gateway.delete_service_group(name)
        deleted.append(name)
    remaining = {str(item.get("name")) for item in (gateway.get_address_groups() if args.bulk_kind == "address" else gateway.get_service_groups())}
    unverified = sorted(set(deleted) & remaining)
    result = {"status": "success" if not unverified else "partial", "deleted": deleted, "unverified": unverified}
    _delete_output(args, preview, result)
    return 0 if result["status"] == "success" else 5


def _resolve_applications(gateway: OrchestratorGateway, requested: Set[str], offline_path: Optional[str]) -> Set[str]:
    if offline_path:
        return set(_load_json(offline_path))
    port = gateway.get_application_definitions("portProtocolClassification")
    dns = gateway.get_application_definitions("dnsClassification")
    compound = gateway.get_application_definitions("compoundClassification")
    available = _application_names(port, dns, compound)
    known = {name.lower() for name in available}
    for name in requested:
        if name.lower() not in known and _wildcard_has_exact_name(gateway.search_application(name), name, casefold=True):
            available.add(name)
    return available


def _app_group_result_with_skips(result: Mapping[str, Any], skipped: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    value = dict(result)
    value["skipped_conflicts"] = list(skipped)
    if skipped:
        value["status"] = "partial"
    return value


def _app_groups_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    rows, initial_skips = parse_application_groups_partial(args.csv)
    requested = {name.strip() for row in rows for name in row["Applications"].split(",") if name.strip()}
    applications = _resolve_applications(gateway, requested, args.applications)
    plan = plan_application_groups(rows, gateway.get_application_groups(), applications, initial_skips)
    value = {"kind": "app-groups", **plan}
    _seal_report(value, args.output)
    _print({"output": args.output, "skipped_conflicts": plan["skipped_conflicts"], "no_ops": plan["no_ops"]})
    return 5 if plan["skipped_conflicts"] else 0


def _app_groups_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "app-groups")
    skipped = value.get("skipped_conflicts")
    if skipped is None:
        raise ValidationError("application group plan must be regenerated with skipped conflict details")
    if not _approve(value, args.dry_run):
        return 5 if skipped else 0
    result = _app_group_result_with_skips(apply_application_groups(_gateway(args), value), skipped)
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _app_groups_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    rows, initial_skips = parse_application_groups_partial(args.csv)
    requested = {name.strip() for row in rows for name in row["Applications"].split(",") if name.strip()}
    plan = plan_application_groups(rows, gateway.get_application_groups(), _resolve_applications(gateway, requested, args.applications), initial_skips)
    preview = {"kind": "app-groups", **plan}
    if not _approve(preview, args.dry_run):
        return 5 if plan["skipped_conflicts"] else 0
    result = _app_group_result_with_skips(apply_application_groups(gateway, plan), plan["skipped_conflicts"])
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] in {"success", "no_op"} else 5


def _app_groups_delete(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    rows = parse_application_groups(args.csv)
    current = gateway.get_application_groups()
    requested = {row["Name"] for row in rows}
    expected = {row["Name"]: {"apps": sorted(set(item.strip() for item in row["Applications"].split(",") if item.strip())), "parentGroup": sorted(set(item.strip() for item in row["ParentGroups"].split(",") if item.strip())) or None} for row in rows}
    conflicts = [name for name in requested & set(current) if not semantic_equal(current[name], expected[name])]
    if conflicts:
        raise ValidationError("CSV deletion blocked by semantically different application groups: {}".format(", ".join(sorted(conflicts))))
    targets = requested & set(current)
    for name, value in current.items():
        if name not in targets and targets & set(value.get("parentGroup") or []):
            raise ValidationError("non-target application group {} references a requested parent deletion".format(name))
    _block_referenced_deletion(_firewall_references(gateway, ("app_group",), targets) + _template_acl_references(gateway, "app_group", targets), "firewall rules or template ACLs", "DEL-06")
    candidate = {name: value for name, value in current.items() if name not in targets}
    table = [("Application group", name, "exact CSV semantic match") for name in sorted(targets)]
    preview = {"kind": "app-groups-delete", "delete": sorted(targets), "absent": sorted(requested - set(current)), "baseline_fingerprint": fingerprint(current), "candidate": candidate}
    approved = _approve_delete(table, args.dry_run)
    if not approved:
        _delete_output(args, preview, {"status": "no_op"} if not table and not args.dry_run else None)
        return 0
    if fingerprint(gateway.get_application_groups()) != preview["baseline_fingerprint"]:
        raise DriftError("application group collection changed after confirmation")
    gateway.post_application_groups(candidate)
    readback = gateway.get_application_groups()
    verified = semantic_equal(readback, candidate)
    result = {"status": "success" if verified else "partial", "deleted": sorted(targets), "verified": verified}
    _delete_output(args, preview, result)
    return 0 if verified else 5


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


def _eligible_definitions(definitions: Sequence[ApplicationDefinition], conflicts: Sequence[Mapping[str, Any]]) -> List[ApplicationDefinition]:
    conflict_rows = {int(conflict["row"]) for conflict in conflicts}
    return [definition for definition in definitions if definition.row not in conflict_rows]


def _definition_result_with_conflicts(result: Mapping[str, Any], conflicts: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    value = dict(result)
    value["skipped_conflicts"] = list(conflicts)
    if conflicts:
        value["status"] = "partial"
    return value


def _definitions_plan(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    definitions = resolve_compound_references(parse_application_definitions(args.csv), gateway)
    inventories = {base: gateway.get_application_definitions(base) for base in ("portProtocolClassification", "dnsClassification", "compoundClassification")}
    plan = plan_application_definitions(definitions, inventories)
    eligible = _eligible_definitions(definitions, plan.conflicts)
    appexpress = plan_appexpress_modes(_definition_appexpress_modes(eligible), gateway.get_appexpress())
    value = {"kind": "app-definitions", "new": [asdict(item) for item in plan.new], "no_ops": plan.no_ops, "skipped_conflicts": plan.conflicts, "inventories": inventories, "fingerprints": plan.fingerprints, "appexpress": appexpress}
    _seal_report(value, args.output)
    _print({"output": args.output, "create": len(plan.new), "no_ops": plan.no_ops, "skipped_conflicts": plan.conflicts, "appexpress_monitor": appexpress["monitor"], "appexpress_off": appexpress["off"]})
    return 5 if plan.conflicts else 0


def _definitions_apply(args: argparse.Namespace) -> int:
    value = _load_json(args.approved_plan)
    _validate_report(value, "app-definitions")
    conflicts = value.get("skipped_conflicts")
    if conflicts is None:
        raise ValidationError("application definition plan must be regenerated with conflict details")
    if any(not isinstance(conflict, dict) or "row" not in conflict for conflict in conflicts):
        raise ValidationError("application definition plan must be regenerated with conflict details")
    definitions = [ApplicationDefinition(**item) for item in value["new"]]
    if not _approve(value, args.dry_run):
        return 5 if conflicts else 0
    result = _definition_result_with_conflicts(execute_application_definitions_with_appexpress(_gateway(args), definitions, value["inventories"], value["appexpress"]), conflicts)
    _print(result)
    return 0 if result["status"] == "success" else 5


def _definitions_deploy(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    definitions = resolve_compound_references(parse_application_definitions(args.csv), gateway)
    inventories = {base: gateway.get_application_definitions(base) for base in ("portProtocolClassification", "dnsClassification", "compoundClassification")}
    plan = plan_application_definitions(definitions, inventories)
    eligible = _eligible_definitions(definitions, plan.conflicts)
    appexpress = plan_appexpress_modes(_definition_appexpress_modes(eligible), gateway.get_appexpress())
    preview = {"kind": "app-definitions", "new": [asdict(item) for item in plan.new], "no_ops": plan.no_ops, "skipped_conflicts": plan.conflicts, "fingerprints": plan.fingerprints, "appexpress": appexpress}
    if not _approve(preview, args.dry_run):
        return 5 if plan.conflicts else 0
    result = _definition_result_with_conflicts(execute_application_definitions_with_appexpress(gateway, plan.new, inventories, appexpress), plan.conflicts)
    if args.report:
        safe_report(args.report, {"preview": preview, "result": result, "report_fingerprint": fingerprint({"preview": preview, "result": result})})
    _print(result)
    return 0 if result["status"] == "success" else 5


def _definition_delete_match(definition: ApplicationDefinition, inventory: Any) -> Tuple[str, Any]:
    if definition.definition_type == "COMPOUND":
        matches = [(int(value.get("id", key)), value) for key, value in inventory.items() if isinstance(value, dict) and value.get("name") == definition.name]
        if not matches:
            return "absent", None
        exact = [(identity, value) for identity, value in matches if semantic_equal({key: item for key, item in value.items() if key != "id"}, definition.payload)]
    elif definition.definition_type == "DOMAIN":
        matches = [(definition.identity, value) for value in inventory if value.get("domain") == definition.identity]
        if not matches:
            return "absent", None
        exact = [(identity, value) for identity, value in matches if all(value.get(key) == expected for key, expected in definition.payload.items())]
    else:
        port, protocol = definition.identity
        matches = [(definition.identity, value) for value in inventory.get(str(port), []) if int(value.get("protocol", -1)) == protocol]
        if not matches:
            return "absent", None
        exact = [(identity, value) for identity, value in matches if all(value.get(key) == expected for key, expected in definition.payload.items())]
    return ("exact", exact[0][0]) if len(matches) == 1 and len(exact) == 1 else ("conflict", None)


def _definitions_delete(args: argparse.Namespace) -> int:
    gateway = _gateway(args)
    definitions = resolve_compound_references(parse_application_definitions(args.csv), gateway)
    bases = {"IP_PROTOCOL": "portProtocolClassification", "TCP_PORT": "portProtocolClassification", "UDP_PORT": "portProtocolClassification", "DOMAIN": "dnsClassification", "COMPOUND": "compoundClassification"}
    inventories = {base: gateway.get_application_definitions(base) for base in set(bases.values())}
    deletion_plan = []
    absent = []
    conflicts = []
    target_names = {definition.name for definition in definitions}
    seen_identities = set()
    for definition in definitions:
        base = bases[definition.definition_type]
        key = (base, str(definition.name if definition.definition_type == "COMPOUND" else definition.identity))
        if key in seen_identities:
            raise ValidationError("application definition delete CSV contains duplicate identity {}".format(key[1]))
        seen_identities.add(key)
        status, identity = _definition_delete_match(definition, inventories[base])
        if status == "exact":
            deletion_plan.append((definition, bases[definition.definition_type], identity))
        elif status == "absent":
            absent.append(definition.name)
        else:
            conflicts.append(definition.name)
    if conflicts:
        raise ValidationError("CSV deletion blocked by semantically different application definitions: {}".format(", ".join(sorted(set(conflicts)))))
    app_groups = gateway.get_application_groups()
    lowered = {name.lower() for name in target_names}
    references = [name for name, value in app_groups.items() if lowered & {str(app).lower() for app in value.get("apps") or []}]
    if references:
        raise ValidationError("application groups reference requested definition deletions: {}".format(", ".join(sorted(references))))
    remaining: Dict[str, int] = {}
    for name in _application_name_list(inventories["portProtocolClassification"], inventories["dnsClassification"], inventories["compoundClassification"]):
        remaining[name.lower()] = remaining.get(name.lower(), 0) + 1
    for definition, _, _ in deletion_plan:
        remaining[definition.name.lower()] = remaining.get(definition.name.lower(), 0) - 1
    vanishing = {definition.name for definition, _, _ in deletion_plan if remaining[definition.name.lower()] <= 0}
    _block_referenced_deletion(_firewall_references(gateway, ("application",), vanishing, True) + _template_acl_references(gateway, "application", vanishing, True), "firewall rules or template ACLs", "DEL-06")
    modes = _definition_appexpress_modes(definitions)
    appexpress = gateway.get_appexpress()
    appexpress_keys = {}
    for name, mode in modes.items():
        matches = [key for key, value in appexpress.items() if str(value.get("name", key)).lower() == name.lower()]
        if len(matches) > 1:
            conflicts.append(name)
        elif matches:
            value = appexpress[matches[0]]
            if mode != "MONITOR" or value.get("monitor") is not True or value.get("appExpressEnabled") is not False:
                conflicts.append(name)
            else:
                appexpress_keys[name] = matches[0]
    if conflicts:
        raise ValidationError("CSV deletion blocked by conflicting AppExpress desired state: {}".format(", ".join(sorted(set(conflicts)))))
    appexpress_candidate = {key: value for key, value in appexpress.items() if key not in set(appexpress_keys.values())}
    table = [("AppExpress Monitor", name, "MONITOR from application-definition CSV") for name in appexpress_keys]
    for definition, base, identity in deletion_plan:
        if base == "compoundClassification":
            detail = "compound name; current ID resolved before deletion"
        elif base == "dnsClassification":
            detail = "domain={}".format(identity)
        else:
            detail = "port={}; protocol={}".format(*identity)
        table.append(("Application definition", definition.name, detail))
    preview = {"kind": "app-definitions-delete", "delete": [{"name": definition.name, "type": definition.definition_type} for definition, _, _ in deletion_plan], "delete_appexpress": list(appexpress_keys), "absent": sorted(set(absent)), "fingerprints": {base: fingerprint(value) for base, value in inventories.items()}, "application_groups_fingerprint": fingerprint(app_groups), "appexpress_fingerprint": fingerprint(appexpress)}
    approved = _approve_delete(table, args.dry_run)
    if not approved:
        _delete_output(args, preview, {"status": "no_op"} if not table and not args.dry_run else None)
        return 0
    if fingerprint(gateway.get_application_groups()) != preview["application_groups_fingerprint"] or fingerprint(gateway.get_appexpress()) != preview["appexpress_fingerprint"]:
        raise DriftError("application dependency collections changed after confirmation")
    for base, expected in preview["fingerprints"].items():
        if fingerprint(gateway.get_application_definitions(base)) != expected:
            raise DriftError("application definition collection changed after confirmation")
    if appexpress_keys:
        gateway.post_appexpress(appexpress_candidate)
        if not semantic_equal(_appexpress_without_ids(gateway.get_appexpress()), _appexpress_without_ids(appexpress_candidate)):
            result = {"status": "partial", "deleted": [], "error": "AppExpress deletion verification failed"}
            _delete_output(args, preview, result)
            return 5
    deleted = []
    for definition, base, _ in deletion_plan:
        live = gateway.get_application_definitions(base)
        status, identity = _definition_delete_match(definition, live)
        if status != "exact":
            raise DriftError("application definition changed before deletion: {}".format(definition.name))
        gateway.delete_application_definition(base, identity)
        deleted.append(definition.name)
    unverified = []
    for definition, base, _ in deletion_plan:
        status, _ = _definition_delete_match(definition, gateway.get_application_definitions(base))
        if status != "absent":
            unverified.append(definition.name)
    result = {"status": "success" if not unverified else "partial", "deleted": deleted, "deleted_appexpress": list(appexpress_keys), "unverified": unverified}
    _delete_output(args, preview, result)
    return 0 if not unverified else 5


def _appexpress_without_ids(value: Mapping[str, Any]) -> Dict[str, Any]:
    result = {}
    for key, item in value.items():
        normalized = dict(item)
        normalized.pop("id", None)
        result[str(normalized.get("name", key)).lower()] = normalized
    return result


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
