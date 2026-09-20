# CSV Template Reference

Use the templates under `templates/`. Header names are strict; unknown or misspelled headers fail validation.

## Firewall rules

Important fields:

| Field | Requirement |
|---|---|
| `rule_key` | Required stable local identity |
| `rule_name` | Local plans/reports only |
| `description` | Sent as API comment |
| `enabled` | TRUE/FALSE; default TRUE |
| `priority` | Optional only when auto-allocation is safe |
| `source_segment`, `destination_segment` | Required |
| `source_zone`, `destination_zone` | Required |
| `source_address`, `destination_address`, `either_address` | `|`-separated CIDRs |
| Address-group fields | Existing group names |
| `protocol` | Required for literal ports |
| Port fields | `|` lists and `-` ranges |
| Service-group fields | Existing service-group names |
| `application`, `application_group` | Existing names; group `any` is valid |
| `action` | allow, deny, inspect |
| `logging` | TRUE/FALSE |
| `logging_level` | 0–7; defaults to 2 when logging enabled |
| `broad_match_ack` | Must be TRUE for a match-all rule |

For a criterion family, either-direction fields cannot be mixed with source/destination fields. Literal source/destination criteria may coexist with corresponding source/destination groups.

When priorities are automatically allocated, `--resolved-csv` writes the eligible finalized rows with concrete priorities for reuse. See [Understanding the resolved firewall CSV](RESOLVED_FIREWALL_CSV.md).

## Address groups

Native GUI headers:

```csv
Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment
```

Lists are comma-separated inside quoted cells. Repeated names create multiple ordered rules.

Documented address-member formats are IPv4 addresses, CIDR prefixes, dotted-decimal masks, short ranges such as `10.10.10.10-20`, ranged octets with a prefix or dotted mask such as `10.10-20.0.0/16`, and wildcard octets with an optional mask such as `10.*.0.0/16`. IPv6 is rejected during local validation because the tested Orchestrator 9.7.1 native address-group importer returns an address-format error for IPv6.

## Service groups

Native GUI headers:

```csv
Name,Protocol,IncludedPorts,ExcludedPorts,IncludedGroups,ExcludedGroups,IcmpTypes,IcmpCodes,Comment
```

Protocols: TCP, UDP, ICMP, ICMPV6. Nested groups are limited to two levels. The tested 9.7.1 native importer rejected ICMPV6 type/code even though the schema documents it.

## Application groups

```csv
Name,Applications,ParentGroups
```

Applications and parent groups are comma-separated and quoted. A group with missing applications or parents, conflicting existing semantics, duplicate/invalid identity, or a parent cycle is skipped and reported. Groups depending on a skipped parent are also skipped; independent groups may proceed, but any skips produce partial exit code `5`.

## Application definitions

One conditional template supports:

- `IP_PROTOCOL`
- `TCP_PORT`
- `UDP_PORT`
- `DOMAIN`
- `COMPOUND`

Common defaults:

- Enabled TRUE
- Confidence 100
- AppExpressMode OFF

`AppExpressMode` is applied by the application-definition workflow after definition creation and verification. `MONITOR` ensures a Monitor entry exists. `OFF` ensures the named application has no AppExpress entry. Both changes are included in the same preview and approval. A row that conflicts with an existing different classifier identity is listed under `skipped_conflicts` and excluded together with its AppExpress intent. Independent rows may proceed, but the command returns partial exit code `5` whenever conflicts were skipped.

Compound supports source/destination/either fields for port, IP, geo, domain, and address map, plus protocol, DSCP, and interface. Either fields are mutually exclusive with source/destination fields of the same family. Simple single-port or single-domain definitions must use the dedicated type.

## AppExpress

```csv
Application,Mode
```

## Delete reuse

The same firewall, address-group, service-group, application-group, application-definition, and AppExpress CSVs are accepted by each workflow's `delete` subcommand. Delete never interprets a partial row as a selector: every live rule or object must match the complete parsed CSV semantics. Firewall deletion also requires explicit priorities on every row. Missing resources are no-ops; different live semantics block the command.

Phase one permits only `MONITOR`. Off means the application has no user-defined AppExpress entry.
