# CSV Template Reference

`templates/edgeconnect/` contains six concise valid starter files. `examples/edgeconnect/` contains two files per workflow: `*_valid.csv` provides broader valid coverage and `*_mixed.csv` deliberately combines a valid row with invalid rows for validator testing. Mixed files are expected to fail and must never be applied. The valid files form one dependency chain: address groups and service groups → application definitions → application groups → template ACLs → firewall rules. Copy and edit valid files before use; replace placeholder zones, template-group name, interface label, and Address Map names with values from your Orchestrator. Header names are strict; unknown or misspelled headers fail validation. The complete rule catalogue, evidence, and rule IDs are in [CSV constraints and dependencies](CSV_CONSTRAINTS_AND_DEPENDENCIES.md).

## Validation messages

Every row is checked completely: all problems in a row, and all rows in a file, are reported together instead of stopping at the first one. Each message has the same shape:

```text
row 14 [DIR-01] either_port='443': either_port is mutually exclusive with source_port/destination_port; fix: use either_port alone, or move the value to source_port/destination_port (blocks segment pair Default -> Default)
```

- `[ID]` is the rule in the constraints catalogue.
- `blocks` is the isolation unit: a firewall segment pair, or the whole CSV for resource files.
- `firewall validate` also returns each issue as structured JSON (`rule`, `row`, `field`, `value`, `message`, `fix`, `blocks`).
- Warnings (for example host bits in a prefix) never block; they appear in the preview and plan.

Shared rules for every CSV:

- Rows with extra or missing fields, control characters or line breaks inside values, and files without data rows are rejected.
- `|` separates multi-value cells in firewall, template ACL and application-definition CSVs; native group and application-group CSVs use commas inside quoted cells. The wrong separator, empty list members (`443||80`) and duplicate members (`443|443`) are rejected.
- Booleans accept `TRUE/FALSE`, `YES/NO`, `1/0`, `ENABLED/DISABLED`.
- Domains accept `example.com`, `*.example.com`, or `*example.com`. A wildcard anywhere else, empty labels, leading or trailing dots, and labels over 63 characters are rejected.
- Protocol values are `ip`, `tcp`, `udp`, `tcp/udp`, `icmp`, `icmpv6`, or a protocol number 0–255.

## Firewall rules

Important fields:

| Field | Requirement |
|---|---|
| `rule_key` | Required stable local identity |
| `rule_name` | Local plans/reports only |
| `description` | Sent as API comment |
| `enabled` | TRUE/FALSE; default TRUE |
| `priority` | 0–65535; optional only when auto-allocation is safe |
| `source_segment`, `destination_segment` | Required |
| `source_zone`, `destination_zone` | Required |
| `acl` | Optional exact central ACL name; exclusive with every ordinary traffic-match field |
| `source_address`, `destination_address`, `either_address` | `|` lists of policy IP values (see below) |
| Address-group fields | Existing group names |
| `protocol` | Optional; see the protocol vocabulary above |
| Port fields | `|` lists and `-` ranges, 0–65535; allowed only when `protocol` is blank, `tcp`, `udp`, `tcp/udp`, `6`, or `17` |
| Service-group fields | Existing service-group names; may be combined with `protocol` (criteria are ANDed) |
| `source_domain`, `destination_domain`, `either_domain` | Optional `|` domain lists; sent as `src_dns`, `dst_dns`, `either_dns`. The columns are optional for backward compatibility |
| `application` | Existing application names, matched case-insensitively; `any` is rejected (leave blank or use `application_group=any`) |
| `application_group` | Existing group names; `any` is valid |
| `action` | allow, deny, inspect |
| `logging` | TRUE/FALSE |
| `logging_level` | 0–7; defaults to 2 when logging enabled; a nonzero value requires `logging=TRUE` |
| `broad_match_ack` | Local acknowledgment required when every traffic match field is blank; it does not alter matching. `TRUE` on a rule that has criteria produces a warning |

Directional families are IP address, address group, port, service group, and domain. Within one family use either-direction **or** source/destination values, never both:

| Combination in one family | Result |
|---|---|
| none, source, destination, source + destination, either | Valid |
| either + source, either + destination, all three | Rejected |

Different families may use different modes. For example `destination_address` with `either_address_group` is valid; Orchestrator's GUI produces such rules and all criteria are ANDed. Literal values may coexist with the matching group field.

Policy IP values (firewall and template ACL) accept:

- IPv4 addresses, prefixes (`10.0.0.0/24`), dotted masks (`10.0.0.0/255.255.0.0`), and `0.0.0.0/0`.
- Octet ranges and whole-octet wildcards such as `10.10.10.10-20`, `10.10.10.*`, and `10.136-137.*.64-95`.
- IPv6 addresses and prefixes, plus eight-group IPv6 wildcard or range forms such as `2001:db8:*:*:*:*:*:*`.
- Range or wildcard combined with a mask (`192.168.0.1-127/24`) is accepted with a warning. The GUI stores it, but vendor documentation lists it as unsupported for policies.
- Prefixes with host bits (`10.0.0.5/24`) are accepted with a warning that names the effective network.
- Partial-octet wildcards (`10.13*.1.1`), reversed ranges, and out-of-range octets are rejected.

### ACL match mode

A nonempty `acl` selects an exclusive match mode. Leave every address, address-group, application, application-group, protocol, port, service-group, and domain field blank. One row can reference one exact ACL name; `|` lists are rejected.

```csv
rule_key,enabled,priority,source_segment,destination_segment,source_zone,destination_zone,acl,action,logging,broad_match_ack
acl-001,FALSE,30000,Default,Default,H_INSIDE,H_OUTSIDE,lab25-test1,allow,FALSE,FALSE
```

The ACL must exist with at least one entry in a selected central Access Lists template. Identical definitions in multiple groups are accepted with a warning; conflicting definitions block the affected segment pair. An absent template association is reported. A missing or semantically different ACL on any reachable target blocks the affected segment pair because Orchestrator 9.7.1 rejects the complete appliance security-map update. Unreachable or paused targets warn and remain PARTIAL because their ACL state cannot be proven. Post-write verification requires the nonempty ACL name in global and effective policy readback and checks the ACL body on reachable appliances.

`broad_match_ack` is not required merely because the referenced ACL contains an unconditional rule. Broad ACL-entry intent belongs to the ACL-authoring workflow. Firewall deletion removes only the exact firewall rule and never deletes its ACL.

When priorities are automatically allocated, `--resolved-csv` writes the eligible finalized rows with concrete priorities for reuse. See [Understanding the resolved firewall CSV](RESOLVED_FIREWALL_CSV.md).

### Broad-match acknowledgment

A rule is structurally match-all when `acl` and all of these ordinary match fields are blank:

- `acl`
- `source_address`, `destination_address`, `either_address`
- `source_address_group`, `destination_address_group`, `either_address_group`
- `application`, `application_group`
- `protocol`
- `source_port`, `destination_port`, `either_port`
- `source_service_group`, `destination_service_group`, `either_service_group`
- `source_domain`, `destination_domain`, `either_domain`

Segments and zones define the rule's scope but do not narrow traffic inside that scope. Priority, action, logging, enabled state, names, and comments are also not match criteria.

| Criteria state | Acknowledgment | Validation and network meaning |
|---|---|---|
| All match fields blank | `TRUE` | Valid; API `match` is empty and the rule matches all traffic in the zone-pair scope |
| All match fields blank | `FALSE` or blank | Invalid locally; no rule is submitted |
| Any match field populated | Any valid Boolean or blank | Valid; populated fields determine the match |

`broad_match_ack` is consumed by the local CSV validator and is not included in the Orchestrator API payload. It therefore does not appear as a stored GUI property. In the GUI, the equivalent condition is the visible `Match everything` summary with no criteria selected.

Important boundaries:

- `FALSE` never converts an empty rule into match-nothing; it rejects the row.
- `TRUE` does not make a specific rule broader.
- A disabled match-all rule still requires `TRUE`.
- The check is structural: a populated but broad value such as `0.0.0.0/0` does not require the acknowledgment.
- The acknowledgment does not bypass priority, dependency, drift, `APPLY`, readback, or appliance-verification controls.

Recommended values are uppercase `TRUE` and `FALSE`; blank defaults to `FALSE`.

## Template-group ACLs

Template: `templates/edgeconnect/template_acls.csv`

| Field | Requirement |
|---|---|
| `TemplateGroup` | Exact existing or proposed group name |
| `ACLName` | ACL inside that exact group; `NewACL` is reserved |
| `ACLUpdateMode` | `MERGE` only |
| `TemplateApplyMode` | `MERGE` only |
| `Priority` | Required integer 1–65535 and rule identity inside the ACL |
| `Permit` | Required explicit TRUE/FALSE; blank is rejected even though the GUI defaults to permit |
| `Application`, `ApplicationGroup` | Optional single existing names; both may be set (criteria are ANDed). Applications match case-insensitively |
| `SourceIP`, `DestinationIP`, `EitherIP` | Optional `|` lists of policy IP values (see firewall section); `EitherIP` is exclusive with source/destination |
| `SourcePort`, `DestinationPort`, `EitherPort` | Optional `|` lists and ranges (`0` = any); `Protocol` must be blank, `tcp`, `udp`, `tcp/udp`, `6`, or `17`; `EitherPort` is exclusive with source/destination |
| `SourceDomain`, `DestinationDomain`, `EitherDomain` | Optional `|` domain lists; `EitherDomain` is exclusive with source/destination |
| `Protocol` | Optional; see the protocol vocabulary above |
| `Comment` | Optional rule comment |
| `BroadMatchAck` | Must be TRUE when all four match fields are blank |

Repeated `TemplateGroup + ACLName` rows create multiple rules. A duplicate priority in the same ACL is rejected. Merge replaces the complete matching-priority body, adds new priorities, and preserves omitted priorities, unrelated ACLs, and unrelated templates.

A missing group is proposed from the CSV and requires its exact name plus final `APPLY`. Existing Access Lists selection and native merge-mode changes have separate typed confirmations. No workflow associates groups with appliances. Groups sharing the same ACL name are reported; conflicting same-priority bodies on a shared appliance block that group. The IP, port, and domain families support either-direction or source/destination mode, never both in one row. Replace, groups inside IP/port selectors, address map, geo, interface, DSCP, segment, URL, web intelligence, traffic behavior, fabric/internet, and user selectors remain unsupported until their native ACL encodings are contract-tested.

## Address groups

Native GUI headers:

```csv
Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment
```

Lists are comma-separated inside quoted cells. Repeated names create multiple ordered rules.

- `Name`: 1–64 letters, digits, dots, underscores, or hyphens. The native importer rejects 65 characters.
- Each rule needs `IncludedIPs` or `IncludedGroups`; exclusions alone match nothing and are rejected.
- A value cannot appear in both `IncludedIPs` and `ExcludedIPs`.
- Nesting allows a leaf plus two parent levels, counting existing groups. The importer rejects a third level with `Only two levels of nesting allowed.`

Documented address-member formats are IPv4 addresses, CIDR prefixes, dotted-decimal masks, short ranges such as `10.10.10.10-20`, ranged octets with a prefix or dotted mask such as `10.10-20.0.0/16` or `10.10.0-10.1/24`, and wildcard octets with an optional mask such as `10.*.0.0/16`. IPv6 is rejected during local validation because the tested Orchestrator 9.7.1 native address-group importer returns an address-format error for IPv6. The plan warns when existing plus new definitions exceed the documented 8 MB limit.

## Service groups

Native GUI headers:

```csv
Name,Protocol,IncludedPorts,ExcludedPorts,IncludedGroups,ExcludedGroups,IcmpTypes,IcmpCodes,Comment
```

| Field | TCP / UDP | ICMP / ICMPV6 |
|---|---|---|
| `IncludedPorts` / `IncludedGroups` | At least one required | Rejected |
| `ExcludedPorts` / `ExcludedGroups` | Optional | Rejected |
| `IcmpTypes` | Rejected | Required; values or ranges 0–255 such as `1,2,4-8` |
| `IcmpCodes` | Rejected | Optional, only with exactly one non-range type |

- Names follow the address-group rule (1–64 characters).
- Ports are 0–65535 and ranges; `*` must be the only port in its cell.
- A value cannot be both included and excluded.
- Nesting is limited to two levels, including existing groups.
- The plan warns when an excluded port lies outside the included ports (it has no effect) and when definitions exceed the documented 4 MB limit.
- The tested 9.7.1 native importer rejected ICMPV6 type/code even though the schema documents it.

## Application groups

```csv
Name,Applications,ParentGroups
```

Applications and parent groups are comma-separated and quoted. Application references match case-insensitively. A group with missing applications or parents, conflicting existing semantics, duplicate/invalid identity, a parent cycle, no applications and no parents, or duplicate/empty list members is skipped and reported. Groups depending on a skipped parent are also skipped; independent groups may proceed, but any skips produce partial exit code `5`.

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

Type-specific fields:

| Field | IP_PROTOCOL | TCP_PORT / UDP_PORT | DOMAIN | COMPOUND |
|---|---|---|---|---|
| `ProtocolNumber` | Required 0–255 | — | — | — |
| `Port` | Blank or 0 | Required single 1–65535 | — | — |
| `Domain` | — | — | Required | — |
| Compound columns | — | — | — | Optional |

Fields marked `—` must be blank.

Names:

- `COMPOUND` names are 1–31 letters, digits, hyphens, or underscores.
- Other types also allow dots (for example `tiktokv.us`).
- Application names are not case-sensitive: every row for the same application must use one spelling. Several definitions may share one application name.
- Notes cannot contain `|`. Confidence is 1–100.
- The workflow blocks a run that would make AppExpress monitor more than 50 applications.

Compound rules:

- Directional families are port, IP, geo, domain, and address map; the either/source/destination rule from the firewall section applies to each.
- At least two attributes are required. A simple single TCP or UDP port must use the dedicated type.
- Criteria text is limited to 512 characters.
- Ports may be combined with a blank, `ip`, `tcp`, `udp`, or `tcp/udp` protocol, but not with ICMP.
- IP values are IPv4 addresses, prefixes, or octet ranges such as `10.2.2.1-20`. IPv6, wildcards, and masks combined with ranges are rejected.
- CSV lists use `|`; the payload sent to Orchestrator uses commas, which is the encoding the GUI stores.
- References are resolved against live inventory during plan, deploy, and delete. Any unresolved value blocks the CSV:

| Column | Accepted input | Sent to Orchestrator |
|---|---|---|
| Geo | ISO alpha-2 code or exact country name (`US`, `United States of America`) | ISO alpha-2 code |
| `DSCP` | `0`–`63` or `be`, `ef`, `cs0`–`cs7`, `af11`–`af43` | Number or lowercase name |
| `Interface` | Active interface-label name or numeric label ID (`Data`, `5`) | Label ID |
| Address map | Exact Address Map name (`Office365Common`) | Canonical name |

## Delete reuse

The same firewall, address-group, service-group, application-group, and application-definition CSVs are accepted by each workflow's `delete` subcommand. Delete never interprets a partial row as a selector: every live rule or object must match the complete parsed CSV semantics. Firewall deletion also requires explicit priorities on every row. Missing resources are no-ops; different live semantics block the command.

References also block deletion:

- Address and service groups referenced by any global firewall rule.
- Application groups referenced by a global firewall rule or a central template ACL.
- Application definitions whose application name would disappear while a global firewall rule or a central template ACL still references it (matched case-insensitively).

The error lists every referencing rule.

`AppExpressMode` in the application-definition CSV is the only AppExpress source of truth. Phase one permits `MONITOR` or `OFF`; `OFF` means the application has no user-defined AppExpress entry.
