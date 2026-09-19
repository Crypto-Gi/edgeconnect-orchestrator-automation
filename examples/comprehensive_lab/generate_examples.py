import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PREFIX = "lab25-"
ADDRESS_HEADERS = ["Name", "IncludedIPs", "ExcludedIPs", "IncludedGroups", "Comment"]
SERVICE_HEADERS = ["Name", "Protocol", "IncludedPorts", "ExcludedPorts", "IncludedGroups", "ExcludedGroups", "IcmpTypes", "IcmpCodes", "Comment"]
APP_HEADERS = ["DefinitionType", "Name", "Notes", "Enabled", "Confidence", "ProtocolNumber", "Port", "Domain", "Protocol", "SourcePort", "DestinationPort", "EitherPort", "SourceIP", "DestinationIP", "EitherIP", "SourceGeo", "DestinationGeo", "EitherGeo", "SourceDomain", "DestinationDomain", "EitherDomain", "DSCP", "SourceAddressMap", "DestinationAddressMap", "EitherAddressMap", "Interface", "AppExpressMode"]
APP_GROUP_HEADERS = ["Name", "Applications", "ParentGroups"]
FIREWALL_HEADERS = ["rule_key", "rule_name", "description", "enabled", "priority", "source_segment", "destination_segment", "source_zone", "destination_zone", "source_address", "source_address_group", "destination_address", "destination_address_group", "either_address", "either_address_group", "application", "application_group", "protocol", "source_port", "destination_port", "either_port", "source_service_group", "destination_service_group", "either_service_group", "action", "logging", "logging_level", "broad_match_ack"]


def write_csv(name, headers, rows):
    target = ROOT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def empty(headers, **values):
    row = {header: "" for header in headers}
    row.update(values)
    return row


def address_rows():
    valid = [
        empty(ADDRESS_HEADERS, Name="lab25-ag-base-v4", IncludedIPs="198.18.1.0/24", Comment="single IPv4 network"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-multi-v4", IncludedIPs="198.18.2.0/24,198.18.3.10/32", Comment="multiple IPv4 members"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-exclude-v4", IncludedIPs="198.18.4.0/24", ExcludedIPs="198.18.4.128/25", Comment="IPv4 exclusion"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-ipv6", IncludedIPs="2001:db8:25::/64,2001:db8:25::10/128", Comment="IPv6 members"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-hosts", IncludedIPs="198.18.5.1/32,198.18.5.2/32,198.18.5.3/32", Comment="host members"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-child-one", IncludedIPs="198.18.6.0/24", IncludedGroups="lab25-ag-base-v4", Comment="one nested group"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-child-two", IncludedIPs="198.18.7.0/24", IncludedGroups="lab25-ag-multi-v4", Comment="second nested group"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-depth-two", IncludedIPs="198.18.8.0/24", IncludedGroups="lab25-ag-child-one", Comment="maximum nesting depth two"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-two-groups", IncludedGroups="lab25-ag-base-v4,lab25-ag-multi-v4", Comment="two included groups"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-multi-rule", IncludedIPs="198.18.9.0/24", Comment="multi-rule first"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-multi-rule", IncludedIPs="198.18.10.0/24", Comment="multi-rule second"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-comment", IncludedIPs="198.18.11.0/24", Comment="comment with comma, quoted by CSV"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-two-exclusions", IncludedIPs="198.18.12.0/24", ExcludedIPs="198.18.12.10/32,198.18.12.20/32", Comment="two exclusions"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-mixed-host-net", IncludedIPs="198.18.13.0/24,198.18.14.14/32", Comment="network and host"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-ipv6-child", IncludedGroups="lab25-ag-ipv6", Comment="nested IPv6 group"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-nested-pair", IncludedGroups="lab25-ag-child-one,lab25-ag-child-two", Comment="two child groups"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-exact-exclude", IncludedIPs="198.18.15.1/32,198.18.15.2/32", ExcludedIPs="198.18.15.2/32", Comment="exact host exclusion"),
        empty(ADDRESS_HEADERS, Name="lab25-ag.dot-17", IncludedIPs="198.18.16.0/24", Comment="dot and hyphen name"),
        empty(ADDRESS_HEADERS, Name="lab25-ag_underscore_18", IncludedIPs="198.18.17.0/24", Comment="underscore name"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-long-name-19", IncludedIPs="198.18.18.0/24", Comment="long valid name"),
        empty(ADDRESS_HEADERS, Name="lab25-ag-final-20", IncludedIPs="198.18.19.0/24", Comment="final valid group"),
    ]
    invalid = [
        empty(ADDRESS_HEADERS, Name="lab25-bad-ag-ip", IncludedIPs="999.1.1.1/24", Comment="INVALID bad IP"),
        empty(ADDRESS_HEADERS, Name="lab25-bad-ag-missing", IncludedGroups="lab25-no-such-group", Comment="INVALID missing nested group"),
        empty(ADDRESS_HEADERS, Name="lab25-bad-ag-self", IncludedGroups="lab25-bad-ag-self", Comment="INVALID self cycle"),
        empty(ADDRESS_HEADERS, Name="lab25-bad-ag-cycle-a", IncludedGroups="lab25-bad-ag-cycle-b", Comment="INVALID cycle A"),
        empty(ADDRESS_HEADERS, Name="lab25-bad-ag-cycle-b", IncludedGroups="lab25-bad-ag-cycle-a", Comment="INVALID cycle B"),
    ]
    return valid, invalid


def service_rows():
    valid = [
        empty(SERVICE_HEADERS, Name="lab25-sg-tcp-web", Protocol="TCP", IncludedPorts="80,443", Comment="web ports"),
        empty(SERVICE_HEADERS, Name="lab25-sg-tcp-range", Protocol="TCP", IncludedPorts="8000-8010", Comment="TCP range"),
        empty(SERVICE_HEADERS, Name="lab25-sg-tcp-exclude", Protocol="TCP", IncludedPorts="9000-9010", ExcludedPorts="9005", Comment="TCP exclusion"),
        empty(SERVICE_HEADERS, Name="lab25-sg-udp-dns", Protocol="UDP", IncludedPorts="53", Comment="DNS"),
        empty(SERVICE_HEADERS, Name="lab25-sg-udp-range", Protocol="UDP", IncludedPorts="5000-5010", Comment="UDP range"),
        empty(SERVICE_HEADERS, Name="lab25-sg-wildcard", Protocol="TCP", IncludedPorts="*", Comment="wildcard port"),
        empty(SERVICE_HEADERS, Name="lab25-sg-tcp-child", Protocol="TCP", IncludedPorts="8443", IncludedGroups="lab25-sg-tcp-web", Comment="nested TCP group"),
        empty(SERVICE_HEADERS, Name="lab25-sg-udp-child", Protocol="UDP", IncludedPorts="5353", IncludedGroups="lab25-sg-udp-dns", Comment="nested UDP group"),
        empty(SERVICE_HEADERS, Name="lab25-sg-multi-rule", Protocol="TCP", IncludedPorts="22", Comment="multi-rule TCP"),
        empty(SERVICE_HEADERS, Name="lab25-sg-multi-rule", Protocol="UDP", IncludedPorts="161", Comment="multi-rule UDP"),
        empty(SERVICE_HEADERS, Name="lab25-sg-icmp-echo", Protocol="ICMP", IcmpTypes="8", IcmpCodes="0", Comment="ICMP echo request"),
        empty(SERVICE_HEADERS, Name="lab25-sg-icmp-multi", Protocol="ICMP", IcmpTypes="8,0", Comment="ICMP echo request/reply"),
        empty(SERVICE_HEADERS, Name="lab25-sg-icmp-unreach", Protocol="ICMP", IcmpTypes="3", IcmpCodes="1", Comment="ICMP destination unreachable"),
        empty(SERVICE_HEADERS, Name="lab25-sg-port-zero", Protocol="TCP", IncludedPorts="0", Comment="port zero boundary"),
        empty(SERVICE_HEADERS, Name="lab25-sg-port-max", Protocol="TCP", IncludedPorts="65535", Comment="max TCP port"),
        empty(SERVICE_HEADERS, Name="lab25-sg-udp-max", Protocol="UDP", IncludedPorts="65535", Comment="max UDP port"),
        empty(SERVICE_HEADERS, Name="lab25-sg-excluded-group", Protocol="TCP", IncludedPorts="10000", IncludedGroups="lab25-sg-tcp-web", ExcludedGroups="lab25-sg-tcp-range", Comment="include and exclude groups"),
        empty(SERVICE_HEADERS, Name="lab25-sg-depth-two", Protocol="TCP", IncludedPorts="10443", IncludedGroups="lab25-sg-tcp-child", Comment="maximum nesting depth two"),
        empty(SERVICE_HEADERS, Name="lab25-sg-many-ranges", Protocol="TCP", IncludedPorts="11000-11010,12000-12010,13000", ExcludedPorts="11005,12005", Comment="multiple ranges"),
        empty(SERVICE_HEADERS, Name="lab25-sg-comment", Protocol="UDP", IncludedPorts="1900", Comment="comment with comma, quoted by CSV"),
        empty(SERVICE_HEADERS, Name="lab25-sg-udp-group-only", Protocol="UDP", IncludedGroups="lab25-sg-udp-dns", Comment="group-only UDP rule"),
    ]
    invalid = [
        empty(SERVICE_HEADERS, Name="lab25-bad-sg-protocol", Protocol="SCTP", IncludedPorts="3868", Comment="INVALID unsupported protocol"),
        empty(SERVICE_HEADERS, Name="lab25-bad-sg-port", Protocol="TCP", IncludedPorts="70000", Comment="INVALID port out of range"),
        empty(SERVICE_HEADERS, Name="lab25-bad-sg-missing", Protocol="TCP", IncludedGroups="lab25-no-such-service", Comment="INVALID missing nested group"),
        empty(SERVICE_HEADERS, Name="lab25-bad-sg-self", Protocol="TCP", IncludedGroups="lab25-bad-sg-self", Comment="INVALID self cycle"),
        empty(SERVICE_HEADERS, Name="lab25-bad-sg-icmpv6", Protocol="ICMPV6", IcmpTypes="128", IcmpCodes="0", Comment="EXPECTED RUNTIME FAILURE on tested 9.7.1 importer"),
    ]
    return valid, invalid


def app_row(definition_type, name, **values):
    defaults = {"DefinitionType": definition_type, "Name": name, "Notes": "", "Enabled": "TRUE", "Confidence": "100", "AppExpressMode": "OFF"}
    defaults.update(values)
    return empty(APP_HEADERS, **defaults)


def application_rows():
    valid = []
    for index, protocol in enumerate([1, 4, 41, 47, 50, 51, 89, 112], 1):
        valid.append(app_row("IP_PROTOCOL", f"lab25-ip-{index:02d}", Notes=f"IP protocol {protocol}", ProtocolNumber=str(protocol), Port="0", AppExpressMode="MONITOR" if index == 1 else "OFF"))
    valid.extend([
        app_row("TCP_PORT", "lab25-tcp-01", Port="22", Notes="SSH"), app_row("TCP_PORT", "lab25-tcp-02", Port="80", Notes="HTTP"),
        app_row("TCP_PORT", "lab25-tcp-03", Port="443", Notes="HTTPS", AppExpressMode="MONITOR"), app_row("TCP_PORT", "lab25-tcp-04", Port="8443"),
        app_row("TCP_PORT", "lab25-tcp-05", Port="3389"), app_row("TCP_PORT", "lab25-tcp-06", Port="1521"),
        app_row("TCP_PORT", "lab25-tcp-07", Port="5432"), app_row("TCP_PORT", "lab25-tcp-08", Port="65535"),
        app_row("UDP_PORT", "lab25-udp-01", Port="53", Notes="DNS"), app_row("UDP_PORT", "lab25-udp-02", Port="67"),
        app_row("UDP_PORT", "lab25-udp-03", Port="68"), app_row("UDP_PORT", "lab25-udp-04", Port="123", AppExpressMode="MONITOR"),
        app_row("UDP_PORT", "lab25-udp-05", Port="161"), app_row("UDP_PORT", "lab25-udp-06", Port="500"),
        app_row("UDP_PORT", "lab25-udp-07", Port="4500"), app_row("UDP_PORT", "lab25-udp-08", Port="65535"),
    ])
    for index, domain in enumerate(["*.alpha.example.com", "beta.example.com", "*gamma*", "api.delta.example.com", "*.epsilon.example.org", "zeta.example.net", "eta.example.com", "*.theta.example.com"], 1):
        valid.append(app_row("DOMAIN", f"lab25-domain-{index:02d}", Domain=domain, Notes=f"domain probe {index}", AppExpressMode="MONITOR" if index == 1 else "OFF"))
    valid.extend([
        app_row("COMPOUND", "lab25-cmp-01", Protocol="tcp", SourcePort="1024-2048", DestinationPort="443", Notes="directional ports"),
        app_row("COMPOUND", "lab25-cmp-02", Protocol="udp", EitherPort="53|443", EitherIP="198.18.100.1/32|198.18.100.2/32", Notes="either port and IP"),
        app_row("COMPOUND", "lab25-cmp-03", SourceIP="198.18.101.0/24", DestinationIP="198.18.102.0/24", SourceGeo="United States of America", DestinationGeo="Canada", Notes="IP and geo"),
        app_row("COMPOUND", "lab25-cmp-04", SourceDomain="*.source.example.com", DestinationDomain="*.destination.example.com", DSCP="af31", Notes="domain and DSCP"),
        app_row("COMPOUND", "lab25-cmp-05", SourceAddressMap="Office365Common", DestinationAddressMap="Salesforce", Interface="lan0", Notes="address map and interface"),
        app_row("COMPOUND", "lab25-cmp-06", Protocol="ip", EitherGeo="United States of America", EitherAddressMap="Office365Common", Notes="either geo/map"),
        app_row("COMPOUND", "lab25-cmp-07", Protocol="udp", SourceIP="2001:db8:25::/64", DestinationIP="2001:db8:26::/64", DSCP="ef", Notes="IPv6 and DSCP"),
        app_row("COMPOUND", "lab25-cmp-08", Protocol="tcp", SourcePort="2000-2010", DestinationPort="9443", SourceIP="198.18.103.0/24", DestinationIP="198.18.104.0/24", SourceDomain="*.src.example.net", DestinationDomain="*.dst.example.net", SourceGeo="United States of America", DestinationGeo="Canada", SourceAddressMap="Office365Common", DestinationAddressMap="Salesforce", DSCP="af21", Interface="lan0.10", Notes="combined directional criteria", AppExpressMode="MONITOR"),
    ])
    invalid = [
        app_row("IP_PROTOCOL", "lab25-bad-ip-09", ProtocolNumber="256", Port="0", Notes="INVALID protocol number"),
        app_row("IP_PROTOCOL", "lab25-bad-ip-10", ProtocolNumber="abc", Port="0", Notes="INVALID nonnumeric protocol"),
        app_row("TCP_PORT", "lab25-bad-tcp-09", Port="0", Notes="INVALID TCP port zero"),
        app_row("TCP_PORT", "lab25-bad-tcp-10", Port="80-90", Notes="INVALID dedicated TCP range"),
        app_row("UDP_PORT", "lab25-bad-udp-09", Port="70000", Notes="INVALID UDP port"),
        app_row("UDP_PORT", "lab25-bad-udp-10", Port="abc", Notes="INVALID nonnumeric UDP port"),
        app_row("DOMAIN", "lab25-bad-domain-09", Domain="https://bad.example.com/path", Notes="INVALID URL not domain"),
        app_row("DOMAIN", "lab25-bad-domain-10", Domain="bad..example.com", Notes="INVALID double dot"),
        app_row("COMPOUND", "lab25-bad-cmp-09", Protocol="tcp", Notes="INVALID only one attribute"),
        app_row("COMPOUND", "lab25-bad-cmp-10", SourceIP="198.18.200.1/32", EitherIP="198.18.200.2/32", Notes="INVALID directional/either conflict"),
    ]
    return valid, invalid


def application_group_rows(valid_apps):
    names = [row["Name"] for row in valid_apps]
    return [
        empty(APP_GROUP_HEADERS, Name="lab25-apps-network", Applications=",".join(names[:8])),
        empty(APP_GROUP_HEADERS, Name="lab25-apps-tcp", Applications=",".join(names[8:16])),
        empty(APP_GROUP_HEADERS, Name="lab25-apps-udp", Applications=",".join(names[16:24])),
        empty(APP_GROUP_HEADERS, Name="lab25-apps-domain", Applications=",".join(names[24:32])),
        empty(APP_GROUP_HEADERS, Name="lab25-apps-compound", Applications=",".join(names[32:40])),
        empty(APP_GROUP_HEADERS, Name="lab25-apps-all-simple", ParentGroups="lab25-apps-network,lab25-apps-tcp,lab25-apps-udp,lab25-apps-domain"),
        empty(APP_GROUP_HEADERS, Name="lab25-apps-all", ParentGroups="lab25-apps-all-simple,lab25-apps-compound"),
    ]


def firewall_row(index, app="", app_group="", **values):
    defaults = {
        "rule_key": f"lab25-fw-{index:03d}", "rule_name": f"LAB25 rule {index:03d}", "description": f"LAB25:lab25-fw-{index:03d}",
        "enabled": "TRUE" if index % 5 == 0 else "FALSE", "priority": str(30000 + (index - 1) * 10),
        "source_segment": "Default", "destination_segment": "Default", "source_zone": "H_INSIDE", "destination_zone": "H_OUTSIDE",
        "application": app, "application_group": app_group, "action": ["allow", "deny", "inspect"][(index - 1) % 3],
        "logging": "TRUE" if index % 3 == 0 else "FALSE", "logging_level": str(index % 8) if index % 3 == 0 else "", "broad_match_ack": "FALSE",
    }
    defaults.update(values)
    return empty(FIREWALL_HEADERS, **defaults)


def firewall_rows(valid_apps):
    apps = [row["Name"] for row in valid_apps]
    rows = []
    for index, app in enumerate(apps, 1):
        mode = index % 6
        values = {}
        if mode == 0:
            values.update(source_address=f"198.19.{index}.1/32", destination_address=f"198.19.{index}.2/32")
        elif mode == 1:
            values.update(source_address_group="lab25-ag-base-v4", destination_address_group="lab25-ag-child-one")
        elif mode == 2:
            values.update(either_address=f"198.19.{index}.1/32|198.19.{index}.2/32", either_address_group="lab25-ag-multi-v4")
        elif mode == 3:
            values.update(protocol="tcp", source_port=f"{1000 + index}", destination_port="443|8443")
        elif mode == 4:
            values.update(protocol="tcp", source_port="1200", source_service_group="lab25-sg-tcp-web", destination_port="2200", destination_service_group="lab25-sg-tcp-child")
        else:
            values.update(protocol="udp", either_port="53|161", either_service_group="lab25-sg-udp-dns")
        rows.append(firewall_row(index, app=app, app_group="any" if index % 7 == 0 else "", **values))
    group_names = ["lab25-apps-network", "lab25-apps-tcp", "lab25-apps-udp", "lab25-apps-domain", "lab25-apps-all"]
    for offset, group in enumerate(group_names, len(rows) + 1):
        rows.append(firewall_row(offset, app_group=group, protocol="tcp", destination_port=str(40000 + offset), source_address=f"198.19.{offset}.0/24"))
    invalid = [
        firewall_row(101, app="lab25-no-such-app", priority="35000", description="INVALID missing application"),
        firewall_row(102, app_group="lab25-no-such-app-group", priority="35010", description="INVALID missing application group"),
        firewall_row(103, priority="35020", source_address_group="lab25-no-such-address", description="INVALID missing address group"),
        firewall_row(104, priority="35030", protocol="tcp", destination_service_group="lab25-no-such-service", description="INVALID missing service group"),
        firewall_row(105, priority="35040", action="drop", source_address="198.18.1.1/32", description="INVALID action"),
        firewall_row(106, priority="35050", source_address="999.1.1.1/24", description="INVALID CIDR"),
        firewall_row(107, priority="35060", destination_port="443", protocol="", description="INVALID port without protocol"),
        firewall_row(108, priority="35070", source_address="198.18.1.1/32", either_address="198.18.1.2/32", description="INVALID directional and either address"),
        firewall_row(109, priority="35080", protocol="tcp", destination_port="443", logging="TRUE", logging_level="8", description="INVALID logging level"),
        firewall_row(110, priority="35090", source_address="198.18.10.1/32", description="INVALID duplicate priority first row"),
        firewall_row(111, priority="35090", source_address="198.18.11.1/32", description="INVALID duplicate priority second row"),
        firewall_row(112, priority="20010", source_address="198.18.12.1/32", description="INVALID expected collision with existing lab priority"),
    ]
    return rows, invalid


def expected_failures(address_invalid, service_invalid, app_invalid, firewall_invalid):
    rows = []
    for category, values in (("address_group", address_invalid), ("service_group", service_invalid), ("application_definition", app_invalid), ("firewall_rule", firewall_invalid)):
        for row in values:
            name = row.get("Name") or row.get("rule_key")
            rows.append({"Category": category, "Identifier": name, "Expected": "FAIL", "Reason": row.get("Comment") or row.get("Notes") or row.get("description")})
    return rows


def main():
    address_valid, address_invalid = address_rows()
    service_valid, service_invalid = service_rows()
    app_valid, app_invalid = application_rows()
    app_groups = application_group_rows(app_valid)
    firewall_valid, firewall_invalid = firewall_rows(app_valid)

    write_csv("address_groups_valid.csv", ADDRESS_HEADERS, address_valid)
    write_csv("address_groups_invalid.csv", ADDRESS_HEADERS, address_invalid)
    write_csv("address_groups_all_25.csv", ADDRESS_HEADERS, address_valid + address_invalid)
    write_csv("service_groups_valid.csv", SERVICE_HEADERS, service_valid)
    write_csv("service_groups_invalid.csv", SERVICE_HEADERS, service_invalid)
    write_csv("service_groups_all_25.csv", SERVICE_HEADERS, service_valid + service_invalid)
    write_csv("application_definitions_valid_40.csv", APP_HEADERS, app_valid)
    write_csv("application_definitions_invalid_10.csv", APP_HEADERS, app_invalid)
    write_csv("application_definitions_all_50.csv", APP_HEADERS, app_valid + app_invalid)
    write_csv("application_groups_valid.csv", APP_GROUP_HEADERS, app_groups)
    write_csv("firewall_rules_valid_45.csv", FIREWALL_HEADERS, firewall_valid)
    write_csv("firewall_rules_invalid_12.csv", FIREWALL_HEADERS, firewall_invalid)
    write_csv("firewall_rules_all_57.csv", FIREWALL_HEADERS, firewall_valid + firewall_invalid)
    write_csv("expected_failures.csv", ["Category", "Identifier", "Expected", "Reason"], expected_failures(address_invalid, service_invalid, app_invalid, firewall_invalid))
    for index, row in enumerate(address_invalid, 1):
        write_csv(f"invalid_cases/address_{index:02d}.csv", ADDRESS_HEADERS, [row])
    for index, row in enumerate(service_invalid, 1):
        write_csv(f"invalid_cases/service_{index:02d}.csv", SERVICE_HEADERS, [row])
    for index, row in enumerate(app_invalid, 1):
        write_csv(f"invalid_cases/application_{index:02d}.csv", APP_HEADERS, [row])
    for index, row in enumerate(firewall_invalid, 1):
        write_csv(f"invalid_cases/firewall_{index:02d}.csv", FIREWALL_HEADERS, [row])
    write_csv("invalid_cases/firewall_duplicate_priority.csv", FIREWALL_HEADERS, firewall_invalid[9:11])
    print("Generated comprehensive lab CSV suite in", ROOT)


if __name__ == "__main__":
    main()
