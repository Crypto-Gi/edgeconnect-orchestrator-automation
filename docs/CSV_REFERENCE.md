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

## Address groups

Native GUI headers:

```csv
Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment
```

Lists are comma-separated inside quoted cells. Repeated names create multiple ordered rules.

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

Applications and parent groups are comma-separated and quoted. Parent cycles and missing references fail validation.

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

`MONITOR` is recorded as follow-up intent but is applied using the separate AppExpress workflow.

Compound supports source/destination/either fields for port, IP, geo, domain, and address map, plus protocol, DSCP, and interface. Either fields are mutually exclusive with source/destination fields of the same family. Simple single-port or single-domain definitions must use the dedicated type.

## AppExpress

```csv
Application,Mode
```

Phase one permits only `MONITOR`. Off means the application has no user-defined AppExpress entry.
