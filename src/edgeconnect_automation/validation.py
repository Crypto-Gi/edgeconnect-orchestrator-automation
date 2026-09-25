import ipaddress
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .errors import ValidationError

PROTOCOLS = {"ip", "tcp", "udp", "tcp/udp", "icmp", "icmpv6"}
PORT_PROTOCOLS = {"", "tcp", "udp", "tcp/udp", "6", "17"}
PORT_PATTERN = re.compile(r"^[0-9]+(?:-[0-9]+)?$")
DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
IPV6_GROUP = re.compile(r"^(?:\*|[0-9A-Fa-f]{1,4}(?:-[0-9A-Fa-f]{1,4})?)$")
DSCP_NAMES = {"be", "ef"} | {"cs{}".format(index) for index in range(8)} | {"af{}{}".format(klass, drop) for klass in range(1, 5) for drop in range(1, 4)}


class Issues:
    def __init__(self, blocks: str = "the whole CSV") -> None:
        self.blocks = blocks
        self.items: List[Dict[str, Any]] = []

    def add(self, rule: str, message: str, row: Any = None, field: str = "", value: Any = "", fix: str = "") -> None:
        self.items.append({"rule": rule, "row": row, "field": field, "value": value, "message": message, "fix": fix, "blocks": self.blocks})

    def __bool__(self) -> bool:
        return bool(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def messages(self) -> List[str]:
        return [format_issue(item) for item in self.items]

    def raise_if_any(self) -> None:
        if self.items:
            raise ValidationError("\n".join(self.messages()), self.items)


def format_issue(item: Mapping[str, Any]) -> str:
    text = "row {} ".format(item["row"]) if item.get("row") is not None else ""
    text += "[{}] ".format(item["rule"])
    if item.get("field"):
        value = item.get("value")
        text += "{}{}: ".format(item["field"], "={!r}".format(value) if value not in (None, "") else "")
    text += item["message"]
    if item.get("fix"):
        text += "; fix: " + item["fix"]
    if item.get("blocks"):
        text += " (blocks {})".format(item["blocks"])
    return text


def members(value: str, issues: Optional[Issues] = None, row: Any = None, field: str = "", delimiter: str = "|") -> List[str]:
    if not value:
        return []
    parts = [part.strip() for part in value.split(delimiter)]
    result = [part for part in parts if part]
    if issues is not None:
        if len(result) != len(parts):
            issues.add("VAL-04", "contains an empty list member", row, field, value, "remove the extra {!r}".format(delimiter))
        other = "," if delimiter == "|" else "|"
        if other in value:
            issues.add("VAL-02", "uses {!r} as a separator".format(other), row, field, value, "separate values with {!r}".format(delimiter))
        duplicates = sorted({part for part in result if result.count(part) > 1})
        if duplicates:
            issues.add("VAL-03", "contains duplicate values: {}".format(", ".join(duplicates)), row, field, value, "list each value once")
    return result


def check_families(row: Mapping[str, str], families: Sequence[Tuple[str, str, str]], issues: Issues, number: Any) -> None:
    for source, destination, either in families:
        if row.get(either) and (row.get(source) or row.get(destination)):
            issues.add("DIR-01", "{} is mutually exclusive with {}/{}".format(either, source, destination), number, either, row.get(either), "use {} alone, or move the value to {}/{}".format(either, source, destination))


def check_ports(values: Sequence[str], issues: Issues, row: Any, field: str, allow_wildcard: bool = False) -> None:
    for member in values:
        if allow_wildcard and member == "*":
            if len(values) > 1:
                issues.add("SG-04", "wildcard * must be the only port in the cell", row, field, member, "use * alone or list explicit ports")
            continue
        if not PORT_PATTERN.fullmatch(member):
            issues.add("VAL-05", "invalid port {}".format(member), row, field, member, "use a port 0-65535 or a range such as 1000-2000")
            continue
        ends = [int(part) for part in member.split("-")]
        if any(part > 65535 for part in ends) or len(ends) == 2 and ends[0] > ends[1]:
            issues.add("VAL-05", "out-of-range port {}".format(member), row, field, member, "use 0-65535 with the lower bound first")


def valid_protocol(value: str) -> bool:
    return value in PROTOCOLS or value.isdigit() and int(value) <= 255


def valid_domain(value: str) -> bool:
    rest = value[2:] if value.startswith("*.") else value[1:] if value.startswith("*") else value
    if len(value) > 253 or not rest or "*" in rest:
        return False
    return all(DOMAIN_LABEL.fullmatch(label) for label in rest.split("."))


def address_group_ipv4(value: str) -> None:
    if ":" in value:
        raise ValueError("IPv6 is not supported by the native address-group importer")
    parts = value.split("/")
    if len(parts) > 2:
        raise ValueError("multiple subnet masks")
    octets = parts[0].split(".")
    if len(octets) != 4:
        raise ValueError("IPv4 address must contain four octets")
    for octet in octets:
        if octet == "*":
            continue
        ends = octet.split("-")
        if len(ends) > 2 or any(not end.isdigit() for end in ends):
            raise ValueError("invalid IPv4 octet")
        numbers = [int(end) for end in ends]
        if any(number > 255 for number in numbers) or len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ValueError("IPv4 octet is out of range")
    if len(parts) == 1:
        return
    mask = parts[1]
    if mask.isdigit():
        if int(mask) > 32:
            raise ValueError("IPv4 prefix length is out of range")
        return
    mask_octets = mask.split(".")
    if len(mask_octets) != 4 or any(not octet.isdigit() or int(octet) > 255 for octet in mask_octets):
        raise ValueError("invalid dotted-decimal subnet mask")
    mask_value = sum(int(octet) << (24 - index * 8) for index, octet in enumerate(mask_octets))
    inverse = (~mask_value) & 0xFFFFFFFF
    if inverse & (inverse + 1):
        raise ValueError("dotted-decimal subnet mask is not contiguous")


def _host_bits_warning(value: str) -> Optional[str]:
    if "/" not in value:
        return None
    network = ipaddress.ip_network(value, strict=False)
    if ipaddress.ip_address(value.split("/")[0]) != network.network_address:
        return "host bits are set; the effective network is {}".format(network.with_prefixlen)
    return None


def policy_ip(value: str) -> Optional[str]:
    """Validate a firewall/ACL IP value; return a warning for compatibility-only forms."""
    if ":" in value:
        if "*" in value or "-" in value:
            groups = value.split(":")
            if len(groups) != 8 or not all(IPV6_GROUP.fullmatch(group) for group in groups):
                raise ValueError("IPv6 wildcard/range must use eight groups of hex, a hex range, or *")
            for group in groups:
                if "-" in group and int(group.split("-")[0], 16) > int(group.split("-")[1], 16):
                    raise ValueError("IPv6 group range is reversed")
            return None
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise ValueError("invalid IPv6 address or prefix") from error
        return _host_bits_warning(value)
    address_group_ipv4(value)
    address, _, mask = value.partition("/")
    if "*" in address or "-" in address:
        return "range/wildcard with a mask is a GUI-compatibility form that the vendor documentation lists as unsupported for policies" if mask else None
    return _host_bits_warning(value)


def compound_ipv4(value: str) -> None:
    if ":" in value:
        raise ValueError("compound applications support IPv4 only")
    if "*" in value:
        raise ValueError("compound applications do not support wildcard octets")
    address_group_ipv4(value)
    address, _, mask = value.partition("/")
    if mask and not mask.isdigit():
        raise ValueError("use a prefix length instead of a dotted mask")
    if mask and "-" in address:
        raise ValueError("a range cannot be combined with a prefix")


def normalize_dscp(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.isdigit() and int(normalized) <= 63:
        return str(int(normalized))
    if normalized in DSCP_NAMES:
        return normalized
    raise ValueError("DSCP must be 0-63 or a standard name such as ef, af31, cs5, or be")


def control_characters(row: Mapping[str, Any], issues: Issues, number: Any) -> None:
    for field, value in row.items():
        if isinstance(value, str) and field != "_row" and any(ord(character) < 32 for character in value):
            issues.add("CSV-10", "contains a control character or line break", number, field, fix="remove tabs, line breaks, and other control characters")
