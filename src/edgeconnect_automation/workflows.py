import copy
import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .errors import DriftError, ValidationError
from .firewall import PORT_PATTERN, parse_bool
from .util import detect_cycle, fingerprint, semantic_equal


ADDRESS_HEADERS = ["Name", "IncludedIPs", "ExcludedIPs", "IncludedGroups", "Comment"]
SERVICE_HEADERS = ["Name", "Protocol", "IncludedPorts", "ExcludedPorts", "IncludedGroups", "ExcludedGroups", "IcmpTypes", "IcmpCodes", "Comment"]
APP_GROUP_HEADERS = ["Name", "Applications", "ParentGroups"]
APP_DEF_HEADERS = ["DefinitionType", "Name", "Notes", "Enabled", "Confidence", "ProtocolNumber", "Port", "Domain", "Protocol", "SourcePort", "DestinationPort", "EitherPort", "SourceIP", "DestinationIP", "EitherIP", "SourceGeo", "DestinationGeo", "EitherGeo", "SourceDomain", "DestinationDomain", "EitherDomain", "DSCP", "SourceAddressMap", "DestinationAddressMap", "EitherAddressMap", "Interface", "AppExpressMode"]
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
APP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,31}$")
DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9*_.-]{1,253}$")
ZONE_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")


def _members(value: str) -> List[str]:
    return [item.strip() for item in value.split("|") if item.strip()]


def _csv_members(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _read_exact_csv(path: str, expected: Sequence[str]) -> List[Dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames != list(expected):
            raise ValidationError("CSV headers must exactly match: {}".format(",".join(expected)))
        rows = []
        for number, row in enumerate(reader, 2):
            if None in row:
                raise ValidationError("row {} has extra fields".format(number))
            clean = {key: (value or "").strip() for key, value in row.items()}
            if any(clean.values()):
                clean["_row"] = str(number)
                rows.append(clean)
        return rows


def _validate_graph(rows: Sequence[Mapping[str, str]], existing: Set[str], included: str, excluded: Optional[str] = None) -> None:
    names = {row["Name"] for row in rows}
    graph: Dict[str, List[str]] = {name: [] for name in names}
    for row in rows:
        references = _csv_members(row[included])
        if excluded:
            references += _csv_members(row[excluded])
        missing = set(references) - names - existing
        if missing:
            raise ValidationError("row {} references missing groups: {}".format(row["_row"], ", ".join(sorted(missing))))
        graph[row["Name"]].extend(reference for reference in references if reference in names)
    if detect_cycle(graph):
        raise ValidationError("group references contain a cycle")

    def depth(node: str, visited: Set[str]) -> int:
        children = [child for child in graph[node] if child in graph]
        if not children:
            return 0
        return 1 + max(depth(child, visited | {node}) for child in children)

    if any(depth(name, set()) > 2 for name in graph):
        raise ValidationError("group nesting exceeds maximum depth 2")


def parse_address_groups(path: str, existing_names: Iterable[str] = ()) -> List[Dict[str, str]]:
    rows = _read_exact_csv(path, ADDRESS_HEADERS)
    for row in rows:
        if not row["Name"] or not NAME_PATTERN.fullmatch(row["Name"]):
            raise ValidationError("row {} has invalid Name".format(row["_row"]))
        for field in ("IncludedIPs", "ExcludedIPs"):
            for value in _csv_members(row[field]):
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError as error:
                    raise ValidationError("row {} has invalid {} value {}".format(row["_row"], field, value)) from error
    _validate_graph(rows, set(existing_names), "IncludedGroups")
    return rows


def _check_port_members(value: str, row: str, field: str, comma_separated: bool = False) -> None:
    for member in (_csv_members(value) if comma_separated else _members(value)):
        if not PORT_PATTERN.fullmatch(member):
            raise ValidationError("row {} has invalid {} value {}".format(row, field, member))
        ends = [int(part) for part in member.split("-")]
        if any(part < 0 or part > 65535 for part in ends) or len(ends) == 2 and ends[0] > ends[1]:
            raise ValidationError("row {} has out-of-range {} value {}".format(row, field, member))


def parse_service_groups(path: str, existing_names: Iterable[str] = ()) -> List[Dict[str, str]]:
    rows = _read_exact_csv(path, SERVICE_HEADERS)
    for row in rows:
        if not row["Name"] or not NAME_PATTERN.fullmatch(row["Name"]):
            raise ValidationError("row {} has invalid Name".format(row["_row"]))
        if row["Protocol"].upper() not in {"TCP", "UDP", "ICMP", "ICMPV6"}:
            raise ValidationError("row {} has invalid Protocol".format(row["_row"]))
        _check_port_members(row["IncludedPorts"], row["_row"], "IncludedPorts", True)
        _check_port_members(row["ExcludedPorts"], row["_row"], "ExcludedPorts", True)
        for field in ("IcmpTypes", "IcmpCodes"):
            for value in _csv_members(row[field]):
                if not value.isdigit() or int(value) > 255:
                    raise ValidationError("row {} has invalid {}".format(row["_row"], field))
    _validate_graph(rows, set(existing_names), "IncludedGroups", "ExcludedGroups")
    return rows


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


@dataclass
class BulkPlan:
    kind: str
    new_rows: List[Dict[str, str]]
    no_ops: List[str]
    conflicts: List[str]
    content: bytes
    baseline_fingerprint: Optional[str] = None


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
        elif semantic_equal(actual, expected):
            no_ops.append(name)
        else:
            conflicts.append(name)
    headers = ADDRESS_HEADERS if kind == "address" else SERVICE_HEADERS
    return BulkPlan(kind, new_rows, no_ops, conflicts, native_csv_bytes(new_rows, headers), fingerprint(existing))


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
    missing = [name for name, rows in grouped.items() if not semantic_equal(current.get(name), normalizer(rows))]
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


def plan_application_groups(rows: Sequence[Mapping[str, str]], existing: Mapping[str, Any], applications: Set[str]) -> Dict[str, Any]:
    candidate = copy.deepcopy(dict(existing))
    conflicts: List[str] = []
    no_ops: List[str] = []
    row_names = {row["Name"] for row in rows}
    for row in rows:
        apps = sorted(set(_csv_members(row["Applications"])))
        missing_apps = set(apps) - applications
        if missing_apps:
            raise ValidationError("group {} references missing applications: {}".format(row["Name"], ", ".join(sorted(missing_apps))))
        parents = sorted(set(_csv_members(row["ParentGroups"])))
        missing_parents = set(parents) - row_names - set(existing)
        if missing_parents:
            raise ValidationError("group {} references missing parents: {}".format(row["Name"], ", ".join(sorted(missing_parents))))
        expected = {"apps": apps, "parentGroup": parents or None}
        if row["Name"] in existing:
            if semantic_equal(existing[row["Name"]], expected):
                no_ops.append(row["Name"])
            else:
                conflicts.append(row["Name"])
        else:
            candidate[row["Name"]] = expected
    graph = {name: list(value.get("parentGroup") or []) for name, value in candidate.items()}
    if detect_cycle(graph):
        raise ValidationError("application group parents contain a cycle")
    return {"baseline": dict(existing), "candidate": candidate, "fingerprint": fingerprint(existing), "conflicts": conflicts, "no_ops": no_ops}


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


def _reject_unused_fields(row: Mapping[str, str], allowed: Set[str]) -> None:
    common = {"DefinitionType", "Name", "Notes", "Enabled", "Confidence", "AppExpressMode", "_row"}
    unexpected = sorted(field for field in APP_DEF_HEADERS if field not in common | allowed and row.get(field))
    if unexpected:
        raise ValidationError("row {} fields are not valid for {}: {}".format(row["_row"], row["DefinitionType"], ", ".join(unexpected)))


def _validate_domain(value: str, row: str, field: str) -> None:
    if not DOMAIN_PATTERN.fullmatch(value) or "/" in value or ".." in value:
        raise ValidationError("row {} has invalid {} value {}".format(row, field, value))


def parse_application_definitions(path: str) -> List[ApplicationDefinition]:
    rows = _read_exact_csv(path, APP_DEF_HEADERS)
    definitions: List[ApplicationDefinition] = []
    for row in rows:
        number = int(row["_row"])
        definition_type = row["DefinitionType"].upper()
        if definition_type not in {"IP_PROTOCOL", "TCP_PORT", "UDP_PORT", "DOMAIN", "COMPOUND"}:
            raise ValidationError("row {} has unsupported DefinitionType".format(number))
        if not APP_NAME_PATTERN.fullmatch(row["Name"]):
            raise ValidationError("row {} Name must be 1-31 characters using letters, numbers, hyphen, or underscore".format(number))
        if "|" in row["Notes"]:
            raise ValidationError("row {} Notes cannot contain |".format(number))
        allowed_fields = {
            "IP_PROTOCOL": {"ProtocolNumber", "Port"},
            "TCP_PORT": {"Port"},
            "UDP_PORT": {"Port"},
            "DOMAIN": {"Domain"},
            "COMPOUND": {"Protocol", "SourcePort", "DestinationPort", "EitherPort", "SourceIP", "DestinationIP", "EitherIP", "SourceGeo", "DestinationGeo", "EitherGeo", "SourceDomain", "DestinationDomain", "EitherDomain", "DSCP", "SourceAddressMap", "DestinationAddressMap", "EitherAddressMap", "Interface"},
        }
        _reject_unused_fields(row, allowed_fields[definition_type])
        enabled = parse_bool(row["Enabled"], "Enabled", True)
        try:
            confidence = int(row["Confidence"] or "100")
        except ValueError as error:
            raise ValidationError("row {} has invalid Confidence".format(number)) from error
        if confidence < 1 or confidence > 100:
            raise ValidationError("row {} Confidence must be 1..100".format(number))
        mode = (row["AppExpressMode"] or "OFF").upper()
        if mode not in {"OFF", "MONITOR"}:
            raise ValidationError("row {} AppExpressMode must be OFF or MONITOR".format(number))
        common = {"name": row["Name"], "description": row["Notes"], "priority": confidence, "disabled": not enabled}
        if definition_type == "DOMAIN":
            if not row["Domain"]:
                raise ValidationError("row {} DOMAIN requires Domain".format(number))
            _validate_domain(row["Domain"], str(number), "Domain")
            payload = dict(common, domain=row["Domain"])
            identity = row["Domain"]
        elif definition_type in {"IP_PROTOCOL", "TCP_PORT", "UDP_PORT"}:
            protocol = {"TCP_PORT": 6, "UDP_PORT": 17}.get(definition_type)
            if definition_type == "IP_PROTOCOL":
                if not row["ProtocolNumber"].isdigit() or int(row["ProtocolNumber"]) > 255:
                    raise ValidationError("row {} IP_PROTOCOL requires ProtocolNumber 0..255".format(number))
                if row["Port"] not in {"", "0"}:
                    raise ValidationError("row {} IP_PROTOCOL Port must be blank or 0".format(number))
                protocol = int(row["ProtocolNumber"])
                port = "0"
            else:
                if not row["Port"].isdigit() or int(row["Port"]) < 1 or int(row["Port"]) > 65535:
                    raise ValidationError("row {} {} requires one numeric Port from 1 to 65535".format(number, definition_type))
                port = row["Port"]
            payload = dict(common, protocol=protocol, port=port)
            identity = (port, protocol)
        else:
            payload = _compound_payload(row, common)
            identity = None
        definitions.append(ApplicationDefinition(number, definition_type, row["Name"], payload, identity, mode))
    return definitions


@dataclass
class ApplicationDefinitionPlan:
    new: List[ApplicationDefinition]
    no_ops: List[str]
    conflicts: List[str]
    fingerprints: Dict[str, str]


def plan_application_definitions(definitions: Sequence[ApplicationDefinition], inventories: Mapping[str, Any]) -> ApplicationDefinitionPlan:
    base_map = {"IP_PROTOCOL": "portProtocolClassification", "TCP_PORT": "portProtocolClassification", "UDP_PORT": "portProtocolClassification", "DOMAIN": "dnsClassification", "COMPOUND": "compoundClassification"}
    new: List[ApplicationDefinition] = []
    no_ops: List[str] = []
    conflicts: List[str] = []
    compounds = inventories.get("compoundClassification", {})
    seen_compounds: Set[str] = set()
    seen_identities: Set[Tuple[str, str]] = set()
    for definition in definitions:
        base = base_map[definition.definition_type]
        inventory = inventories.get(base, {})
        if definition.definition_type == "COMPOUND":
            if definition.name in seen_compounds:
                conflicts.append(definition.name)
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
                    conflicts.append(definition.name)
            else:
                new.append(ApplicationDefinition(definition.row, definition.definition_type, definition.name, dict(definition.payload), definition.name, definition.app_express))
        elif definition.definition_type == "DOMAIN":
            identity_key = (base, str(definition.identity))
            if identity_key in seen_identities:
                conflicts.append(str(definition.identity))
                continue
            seen_identities.add(identity_key)
            matches = [item for item in inventory if item.get("domain") == definition.identity]
            if not matches:
                new.append(definition)
            elif any(_simple_definition_equal(item, definition.payload) for item in matches):
                no_ops.append(definition.name)
            else:
                conflicts.append(str(definition.identity))
        else:
            identity_key = (base, "{}:{}".format(*definition.identity))
            if identity_key in seen_identities:
                conflicts.append(identity_key[1])
                continue
            seen_identities.add(identity_key)
            entries = inventory.get(str(definition.identity[0]), []) if isinstance(inventory, dict) else []
            matches = [item for item in entries if int(item.get("protocol", -1)) == definition.identity[1]]
            if not matches:
                new.append(definition)
            elif any(_simple_definition_equal(item, definition.payload) for item in matches):
                no_ops.append(definition.name)
            else:
                conflicts.append("{}:{}".format(*definition.identity))
    return ApplicationDefinitionPlan(new, no_ops, conflicts, {base: fingerprint(value) for base, value in inventories.items()})


def _simple_definition_equal(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _compound_payload(row: Mapping[str, str], common: Mapping[str, Any]) -> Dict[str, Any]:
    directional = [
        ("SourcePort", "DestinationPort", "EitherPort", "src_port", "dst_port", "either_port"),
        ("SourceIP", "DestinationIP", "EitherIP", "src_ip", "dst_ip", "either_ip"),
        ("SourceGeo", "DestinationGeo", "EitherGeo", "src_geo", "dst_geo", "either_geo"),
        ("SourceDomain", "DestinationDomain", "EitherDomain", "src_dns", "dst_dns", "either_dns"),
        ("SourceAddressMap", "DestinationAddressMap", "EitherAddressMap", "src_service", "dst_service", "either_service"),
    ]
    payload = dict(common)
    attributes = 0
    for source, destination, either, source_key, destination_key, either_key in directional:
        if row[either] and (row[source] or row[destination]):
            raise ValidationError("row {} {} is mutually exclusive with source/destination".format(row["_row"], either))
        for field, key in ((source, source_key), (destination, destination_key), (either, either_key)):
            payload[key] = row[field]
            attributes += len(_members(row[field]))
    for field, key in (("Protocol", "protocol"), ("DSCP", "dscp"), ("Interface", "vlan")):
        payload[key] = row[field]
        attributes += 1 if row[field] else 0
    for field in ("SourceIP", "DestinationIP", "EitherIP"):
        for value in _members(row[field]):
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as error:
                raise ValidationError("row {} contains invalid compound IP {}".format(row["_row"], value)) from error
    for field in ("SourcePort", "DestinationPort", "EitherPort"):
        _check_port_members(row[field], row["_row"], field)
    for field in ("SourceDomain", "DestinationDomain", "EitherDomain"):
        for value in _members(row[field]):
            _validate_domain(value, row["_row"], field)
    protocol = row["Protocol"].lower()
    if protocol and protocol not in {"ip", "tcp", "udp", "icmp", "icmpv6"} and not (protocol.isdigit() and 0 <= int(protocol) <= 255):
        raise ValidationError("row {} has invalid compound Protocol {}".format(row["_row"], row["Protocol"]))
    payload["protocol"] = protocol
    if attributes < 2:
        raise ValidationError("row {} compound definition requires at least two attributes".format(row["_row"]))
    non_port_match = any(payload.get(key) for key in ("src_ip", "dst_ip", "either_ip", "src_dns", "dst_dns", "either_dns", "src_geo", "dst_geo", "either_geo", "src_service", "dst_service", "either_service", "vlan", "dscp"))
    port_values = [payload.get(key, "") for key in ("src_port", "dst_port", "either_port") if payload.get(key)]
    if protocol in {"tcp", "udp"} and len(port_values) == 1 and len(_members(port_values[0])) == 1 and not non_port_match:
        raise ValidationError("row {} simple TCP/UDP port rule must use its dedicated definition type".format(row["_row"]))
    criteria_length = sum(len(str(value)) for key, value in payload.items() if key not in {"name", "description", "disabled", "priority"} and value)
    if criteria_length > 512:
        raise ValidationError("row {} compound definition exceeds 512 characters".format(row["_row"]))
    payload["confidence"] = payload.pop("priority")
    return payload


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


def plan_appexpress(names: Sequence[str], applications: Set[str], current: Mapping[str, Any]) -> Dict[str, Any]:
    missing = set(names) - applications
    if missing:
        raise ValidationError("AppExpress applications do not exist: {}".format(", ".join(sorted(missing))))
    candidate = copy.deepcopy(dict(current))
    next_id = max((int(value.get("id", -1)) for value in current.values()), default=-1) + 1
    created = []
    for name in names:
        key = name.lower()
        if key in candidate:
            value = candidate[key]
            if not value.get("monitor") or value.get("appExpressEnabled"):
                raise ValidationError("conflicting AppExpress entry {}".format(name))
            continue
        candidate[key] = {"id": next_id, "appIndex": None, "name": name, "type": "app", "monitor": True, "appExpressEnabled": False, "useCloudPortalConfig": False, "cloudPortalDataAvailable": None, "satisfiedQoEThreshold": None, "tolerableQoEThreshold": None, "probes": None}
        next_id += 1
        created.append(name)
    return {"baseline": dict(current), "candidate": candidate, "fingerprint": fingerprint(current), "created": created}


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
    if not plan["created"]:
        return {"status": "no_op"}
    gateway.post_appexpress(plan["candidate"])
    readback = gateway.get_appexpress()
    verified = semantic_equal(_appexpress_semantic(readback), _appexpress_semantic(plan["candidate"]))
    return {"status": "success" if verified else "partial", "created": plan["created"]}
