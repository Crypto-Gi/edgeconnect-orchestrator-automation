"""The GUI's CSV editor: what each firewall column holds, the choices for it from the live inventory, and CSV in and out.

The browser edits rows and shows these choices; it never decides whether a row is valid. Checking stays with the
firewall validate and plan tasks, as for a CSV loaded from disk.
"""
import csv
import io
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence

from . import gui_tables
from .client import ApiClient
from .cli import _application_name_list
from .config import load_config
from .gateway import OrchestratorGateway

# shortcut: templates and examples ship with the source checkout (setup.sh installs it editable), not inside a wheel;
# a wheel install offers a blank start only. Move them into the package if wheels are ever published.
_ROOT = Path(__file__).resolve().parents[2]
TEMPLATES, EXAMPLES = _ROOT / "templates" / "edgeconnect", _ROOT / "examples" / "edgeconnect"

BOOL = ("TRUE", "FALSE")


def _field(name: str, label: str, kind: str = "text", source: str = "", choices: Sequence[str] = (), group: str = "") -> Dict[str, Any]:
    return {"name": name, "label": label, "kind": kind, "source": source, "choices": list(choices), "group": group}


# kind: text (typed), choice (one of choices), name (one inventory name), names (inventory names joined by |),
# search (names found by searching Orchestrator, joined by |). Column order is the template's.
FIREWALL_FIELDS = [
    _field("rule_key", "Rule key", group="Rule"),
    _field("rule_name", "Rule name", group="Rule"),
    _field("description", "Description", group="Rule"),
    _field("enabled", "Enabled", "choice", choices=BOOL, group="Rule"),
    _field("priority", "Priority", group="Rule"),
    _field("source_segment", "Source segment", "name", "segments", group="Where"),
    _field("destination_segment", "Destination segment", "name", "segments", group="Where"),
    _field("source_zone", "Source zone", "name", "zones:source_segment", group="Where"),
    _field("destination_zone", "Destination zone", "name", "zones:destination_segment", group="Where"),
    _field("acl", "Central ACL (instead of the match fields)", group="Match"),
    _field("source_address", "Source addresses", group="Match"),
    _field("source_address_group", "Source address groups", "names", "address_groups", group="Match"),
    _field("destination_address", "Destination addresses", group="Match"),
    _field("destination_address_group", "Destination address groups", "names", "address_groups", group="Match"),
    _field("either_address", "Either-direction addresses", group="Match"),
    _field("either_address_group", "Either-direction address groups", "names", "address_groups", group="Match"),
    _field("application", "Applications", "search", "applications", group="Match"),
    _field("application_group", "Application groups", "search", "application_groups", group="Match"),
    _field("protocol", "Protocol", "choice", choices=("", "ip", "tcp", "udp", "tcp/udp", "icmp", "icmpv6"), group="Match"),
    _field("source_port", "Source ports", group="Match"),
    _field("destination_port", "Destination ports", group="Match"),
    _field("either_port", "Either-direction ports", group="Match"),
    _field("source_service_group", "Source service groups", "names", "service_groups", group="Match"),
    _field("destination_service_group", "Destination service groups", "names", "service_groups", group="Match"),
    _field("either_service_group", "Either-direction service groups", "names", "service_groups", group="Match"),
    _field("source_domain", "Source domains", group="Match"),
    _field("destination_domain", "Destination domains", group="Match"),
    _field("either_domain", "Either-direction domains", group="Match"),
    _field("action", "Action", "choice", choices=("allow", "deny", "inspect"), group="Action"),
    _field("logging", "Logging", "choice", choices=BOOL, group="Action"),
    _field("logging_level", "Logging level", "choice", choices=("",) + tuple(str(level) for level in range(8)), group="Action"),
    _field("broad_match_ack", "Matches all traffic on purpose", "choice", choices=("FALSE", "TRUE"), group="Action"),
]
FIELD_NAMES = [field["name"] for field in FIREWALL_FIELDS]
BLANK_ROW = {"enabled": "TRUE", "action": "allow", "logging": "FALSE", "broad_match_ack": "FALSE"}


def spec() -> Dict[str, Any]:
    return {"fields": FIREWALL_FIELDS, "blank": dict({name: "" for name in FIELD_NAMES}, **BLANK_ROW), "sources": sources()}


def sources() -> List[Dict[str, str]]:
    """The CSVs a new firewall CSV can start from: the template, then each example."""
    found = [{"id": "template", "label": "Template (" + path.name + ")"} for path in [TEMPLATES / "firewall_rules.csv"] if path.is_file()]
    found += [{"id": "example:" + path.name, "label": "Example (" + path.name + ")"} for path in sorted(EXAMPLES.glob("firewall_rules_*.csv"))]
    return found


def source(source_id: str) -> str:
    """The text of one of sources(); only those ids are accepted, so no other file can be read."""
    paths = {"template": TEMPLATES / "firewall_rules.csv"}
    paths.update({"example:" + path.name: path for path in EXAMPLES.glob("firewall_rules_*.csv")})
    if source_id not in paths or not paths[source_id].is_file():
        raise ValueError("unknown starting point {!r}".format(source_id))
    return paths[source_id].read_text(encoding="utf-8-sig")


def parse(text: str) -> Dict[str, Any]:
    """Rows of a CSV as dicts over every firewall column, keeping any other columns so a save loses nothing."""
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    headers = [name.strip() for name in reader.fieldnames or []]
    extra = [name for name in headers if name and name not in FIELD_NAMES]
    rows = []
    for raw in reader:
        values = {(key or "").strip(): "" if value is None else value for key, value in raw.items() if key is not None}
        rows.append({name: values.get(name, "") for name in FIELD_NAMES + extra})
    return {"rows": rows, "extra": extra}


def write(rows: Sequence[Mapping[str, Any]], extra: Sequence[str] = ()) -> str:
    """The CSV for these rows: every firewall column in the template's order, then any extra columns as loaded."""
    columns = FIELD_NAMES + [name for name in extra if name not in FIELD_NAMES]
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow(["" if row.get(name) is None else str(row.get(name)) for name in columns])
    return out.getvalue()


def options(discovery: Mapping[str, Any]) -> Dict[str, Any]:
    """Choices for the name columns from a discover task: segments, zones per segment, address and service groups."""
    tables = gui_tables.inventory_tables(discovery)

    def names(key: str) -> List[str]:
        return sorted({str(row["name"]) for row in tables[key] if row.get("name")}, key=str.lower)

    zones: Dict[str, List[str]] = {}
    for row in tables["segment_zones"]:
        if row["segment"] and row["zone"]:
            zones.setdefault(str(row["segment"]), []).append(str(row["zone"]))
    return {
        "segments": names("segments"),
        "zones": {segment: sorted(set(found), key=str.lower) for segment, found in zones.items()},
        "all_zones": names("zones"),
        "address_groups": names("address_groups"),
        "service_groups": names("service_groups"),
    }


def search(kind: str, query: str, orchestrator: str = "", environ: Optional[Mapping[str, str]] = None, gateway: Optional[OrchestratorGateway] = None, limit: int = 100) -> List[str]:
    """Application or application group names containing query: user-defined ones, plus built-in ones Orchestrator's search finds."""
    if kind not in ("applications", "application_groups"):
        raise ValueError("search applications or application_groups")
    query = query.strip()
    if not query:
        return []
    if gateway is None:
        gateway = OrchestratorGateway(ApiClient(load_config(None, environ, orchestrator=orchestrator or None, interactive=False)))
    if kind == "applications":
        known = _application_name_list(*(gateway.get_application_definitions(base) for base in ("portProtocolClassification", "dnsClassification", "compoundClassification")))
        found = gateway.search_application("*{}*".format(query))
    else:
        groups = gateway.get_application_groups()
        known = ["any"] + [str(name) for name in groups] if isinstance(groups, Mapping) else ["any"]
        found = gateway.search_application_group("*{}*".format(query))
    wanted = query.lower()
    names = {name for name in known if wanted in name.lower()} | {name for name in _names(found) if wanted in name.lower()}
    return sorted(names, key=lambda name: (not name.lower().startswith(wanted), name.lower()))[:limit]


def _names(value: Any, depth: int = 0) -> Iterator[str]:
    """Every name in a wildcard search answer, whatever its shape (the search endpoint's answer is not documented)."""
    if depth > 6:
        return
    if isinstance(value, Mapping):
        for key in ("name", "group", "displayName"):
            if isinstance(value.get(key), str) and value[key]:
                yield value[key]
        for item in value.values():
            if isinstance(item, (Mapping, list)):
                yield from _names(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                yield item
            else:
                yield from _names(item, depth + 1)
