# CSV Constraints and Dependencies

Status: **All decisions D1–D14 resolved (2026-09-24). Final plan in §16. Nothing in "Gap" rows is implemented yet.**

Scope: every CSV the CLI accepts, the rules each row must satisfy, the rules between rows, the
dependencies between workflows, and the implementation/test plan for the missing checks.

Baseline: Orchestrator 9.7.1.42046, ECOS 9.5.4.1 lab evidence, code as of this draft.

## Status legend

| Tag | Meaning |
|---|---|
| **Done** | Enforced today in code (file referenced). |
| **Gap** | Should be enforced; not enforced today. Local-only check, no API evidence needed. |
| **Test** | Needs a lab contract test before we can encode the rule. Until tested, the proposed default applies. |
| **Decision** | Needs owner approval (see [Decisions to approve](#decisions-to-approve)). |

Rule IDs (`FW-12`, `ACL-07`, ...) are stable so tests and error messages can reference them.

---

## 1. Shared rules (all CSVs)

### 1.1 File and header rules

| ID | Rule | Status |
|---|---|---|
| CSV-01 | UTF-8 with or without BOM. | Done |
| CSV-02 | Strict CSV quoting (`csv` module `strict=True`); malformed quotes fail the whole file. | Done |
| CSV-03 | Resource CSVs (address, service, app-group, app-definition, template ACL): headers must match **exactly, in order**. | Done (`_read_exact_csv`) |
| CSV-04 | Firewall CSV: headers may be in any order; duplicates, unknown headers and missing required headers are rejected. `acl` is optional for backward compatibility. | Done (`parse_firewall_document`) |
| CSV-05 | Row with more fields than headers is rejected. | Done |
| CSV-06 | Row with **fewer** fields than headers: firewall rejects; resource CSVs silently treat missing as blank. Should reject everywhere. | Gap |
| CSV-07 | Fully blank rows are ignored. | Done |
| CSV-08 | A file with zero data rows is rejected. | Done for firewall and ACL. Gap for address, service, app-group, app-definition. |
| CSV-09 | Leading/trailing whitespace is stripped from every cell. Internal whitespace is preserved. | Done |
| CSV-10 | Control characters (`ord < 32`) are rejected in every name/comment field. | Done only for ACL `TemplateGroup`/`ACLName`. Gap elsewhere. |

### 1.2 Value syntax

| ID | Rule | Status |
|---|---|---|
| VAL-01 | Booleans: `true/yes/1/enabled/enable` and `false/no/0/disabled/disable`, case-insensitive. Blank = field default. | Done (`parse_bool`) |
| VAL-02 | Multi-value delimiter is `\|` in firewall, template ACL and compound fields; `,` inside a quoted cell for the native address/service/app-group CSVs (native GUI format). Mixing delimiters is not detected. | Done. Detection of the wrong delimiter (e.g. `,` in a firewall cell) is a Gap. |
| VAL-03 | Duplicate values in one cell (`443\|443`) are rejected. | Gap |
| VAL-04 | Empty members (`443\|\|80`) are silently dropped today; should be rejected. | Gap |
| VAL-05 | Port: integer or `a-b` range, `0..65535`, `a <= b`. | Done |
| VAL-06 | Protocol keyword: firewall accepts any `[A-Za-z0-9_-]+`; ACL and compound accept `ip,tcp,udp,icmp,icmpv6` or `0..255`. Firewall should use the same list. | Gap (firewall) |
| VAL-07 | Host bits in CIDR are accepted/preserved for GUI compatibility; warn with the effective network (e.g. `10.0.0.5/24` → `10.0.0.0/24`). | D3 resolved |
| VAL-08 | Firewall/ACL accept IPv6 CIDR and documented policy range/wildcard grammar (API-confirmed syntax); native address groups and compound remain IPv4-only. | D4 resolved |
| VAL-09 | Domain: `[A-Za-z0-9*_.-]{1,253}`, no `/`, no `..`. Vendor doc allows only `example.com` or `*.example.com`. Today `ex*ample.com`, `*example.com`, `.example.com` are accepted. Must reject `*` except as a whole leading `*.` label, leading/trailing `.`, labels over 63 chars. | Gap |
| VAL-12 | Two IP grammars exist and must not be mixed up: **address-group grammar** (§14.1) and **policy grammar** (§14.2). | Gap (see §14) |
| VAL-10 | Name fields: resource name patterns differ (see each section). Max length is enforced only for application definitions (31). | Gap / Test (see per-resource limits) |
| VAL-11 | Every error message includes the rule ID, row, field, offending value and a suggested fix. | Gap (see §11) |

### 1.3 Directional selector families — the core pattern

A **family** is one kind of match criterion that has Source, Destination and Either variants.

For every family:

| Combination | Allowed? |
|---|---|
| Nothing | Yes (family unused) |
| Source only | Yes |
| Destination only | Yes |
| Source + Destination | Yes |
| Either only | Yes |
| Either + Source | **No** |
| Either + Destination | **No** |
| Either + Source + Destination | **No** |

Families per CSV:

| Family | Firewall columns | Template ACL columns | Compound columns |
|---|---|---|---|
| IP literal | `source_address`, `destination_address`, `either_address` | `SourceIP`, `DestinationIP`, `EitherIP` | `SourceIP`, `DestinationIP`, `EitherIP` |
| Address group | `source_address_group`, `destination_address_group`, `either_address_group` | not supported | not supported |
| Port literal | `source_port`, `destination_port`, `either_port` | `SourcePort`, `DestinationPort`, `EitherPort` | `SourcePort`, `DestinationPort`, `EitherPort` |
| Service group | `source_service_group`, `destination_service_group`, `either_service_group` | not supported | not supported |
| Domain | not supported | `SourceDomain`, `DestinationDomain`, `EitherDomain` | `SourceDomain`, `DestinationDomain`, `EitherDomain` |
| Geo | not supported | not supported | `SourceGeo`, `DestinationGeo`, `EitherGeo` |
| Address map | not supported | not supported | `SourceAddressMap`, `DestinationAddressMap`, `EitherAddressMap` |

Status: the within-family rule is **Done** for every family above
(`firewall._parse_rule`, `workflows.parse_template_acls`, `workflows._compound_payload`).

#### Cross-family rules (literal vs. group of the same dimension)

Firewall has two families per dimension: IP literal + address group, port literal + service group.

| Combination (same dimension) | Rule | Status |
|---|---|---|
| `source_address` + `source_address_group` | Allowed (lab-confirmed coexistence) | Done |
| `destination_port` + `destination_service_group` | Allowed (lab-confirmed coexistence) | Done |
| `either_address` + `either_address_group` | Allowed (same direction mode) | Done |
| `either_address` + `source_address_group` (or any Either literal with a directional group, or directional literal with Either group) | Allowed for compatibility. Existing GUI-created global rule 20030 uses `dst_ip` + `either_addrgrp_groups`, and central/effective readback preserves it. | Done / confirmed |
| Same for ports vs. service groups | Allowed for consistency; the criteria are ANDed. | D1 resolved: allow |

---

## 2. Firewall rules (`firewall_rules.csv`)

Code: `src/edgeconnect_automation/firewall.py`. Write/isolation unit: **source/destination segment pair**.

### 2.1 Fields

| Field | Required | Default | Constraint | Status |
|---|---|---|---|---|
| `rule_key` | Yes | — | Unique across the whole CSV. Syntax unchecked; should be `[A-Za-z0-9_.:-]{1,64}`. | Unique: Done. Syntax: Gap |
| `rule_name` | No | blank | Not sent to the API (informational). Document that. | Done (unused) |
| `description` | No | blank | Sent as `comment`. Max length unknown. | Test |
| `enabled` | No | TRUE | Boolean. | Done |
| `priority` | No | auto | `0..65535`. | Done |
| `source_segment`, `destination_segment` | Yes | — | Must exist in inventory. | Done |
| `source_zone`, `destination_zone` | Yes | — | Must exist in the named segment. Missing zones → `zones plan-missing`. | Done |
| `acl` | No | blank | One exact name, no `\|`. | Done |
| IP / address-group / port / service-group families | No | blank | §1.3 | Done (within family) |
| `application` | No | blank | Must exist. `\|` list. `application=any` is rejected with fix "leave blank or use application_group=any". | Gap (D11 approved) |
| `application_group` | No | blank | Must exist, or `any`. | Done |
| `protocol` | No | blank | See VAL-06. | Gap |
| `action` | Yes | — | `allow`, `deny`, `inspect`. | Done |
| `logging` | No | FALSE | Boolean. | Done |
| `logging_level` | No | 2 if logging, else 0 | `0..7`. Nonzero level while `logging=FALSE` is rejected. | Gap (D5 approved) |
| `broad_match_ack` | No | FALSE | Required TRUE when the rule has no match criteria. | Done |

### 2.2 Row rules

| ID | Rule | Status |
|---|---|---|
| FW-01 | All required fields nonblank. | Done |
| FW-02 | `acl` is mutually exclusive with every ordinary match field (IP, groups, app, app group, protocol, ports, service groups). | Done |
| FW-03 | ACL internal broadness never requires `broad_match_ack`. | Done |
| FW-04 | No match fields and no `acl` → `broad_match_ack=TRUE` required. | Done |
| FW-05 | `broad_match_ack=TRUE` on a rule that **does** have criteria is meaningless; should warn. | Gap (warning) |
| FW-06 | Literal ports require `protocol` = `tcp` or `udp`. | Done |
| FW-07 | `protocol=icmp`/`icmpv6`/number with any port field → reject (covered by FW-06). | Done |
| FW-08 | Service group + `protocol` allowed; criteria are ANDed. | Done (D8 approved) |
| FW-09 | Within-family Either exclusivity (§1.3). | Done |
| FW-10 | Cross-family mixed direction is allowed for compatibility; within-family Either exclusivity remains mandatory. | D1 resolved |
| FW-11 | Duplicate/empty list members (VAL-03, VAL-04). | Gap |
| FW-12 | Host bits in CIDR (e.g. `12.1.73.1/24`) are accepted and preserved verbatim for GUI compatibility; warn that the effective network is `12.1.73.0/24`. | D3 resolved: accept + warn |
| FW-14 | IP literals use the compatibility grammar (§14.2): address/CIDR/dotted mask/ranged octets/wildcard octets, including range/wildcard + mask combinations observed in GUI/API. Today firewall rejects ranges/wildcards. | Gap (confirmed) |
| FW-15 | Protocol `tcp/udp` is a valid literal (Swagger/portal definitions/API exact readback); allow with ports. | Gap (confirmed) |
| FW-16 | `application` + `application_group` together are ANDed (vendor ACL doc/readback); keep allowed. | Done |
| FW-17 | Add `source_domain`, `destination_domain`, `either_domain` to firewall CSV and apply §1.3. Existing global/effective policy uses `either_dns`; current CSV cannot express it. | Gap (confirmed) |
| FW-13 | IPv6 policy literals follow VAL-08. | D4 resolved |

### 2.3 Cross-row and existing-state rules

| ID | Rule | Status |
|---|---|---|
| FW-20 | `rule_key` unique across the CSV. | Done |
| FW-21 | Priority unique per zone pair within the segment pair. | Done |
| FW-22 | Explicit priorities are reserved before automatic allocation. | Done |
| FW-23 | Automatic allocation only in an empty zone pair or one holding only a verified `65535` catch-all; starts at 20000, step 10, must stay < 65535. | Done |
| FW-24 | Existing identical rule at the priority → no-op. Different rule → block the pair. | Done |
| FW-25 | Priority equal to an appliance-local rule priority → block the pair. | Done |
| FW-26 | Two CSV rows with identical match + action in the same zone pair at different priorities (shadowed duplicate). Proposed: warn. | Gap (warning) |
| FW-27 | Referenced address groups, service groups, applications, application groups exist in live inventory. | Done |
| FW-28 | `acl` resolves to exactly one selected, nonempty central definition; conflicting central definitions block; missing association/appliance copy warns. | Done |
| FW-29 | Routing segmentation must be enabled; inventories must be complete. | Done |
| FW-30 | Baseline `options` must be `merge=false`, `templateApply=false`. | Done |

### 2.4 Isolation and outcome

- Any error on a row blocks its **segment pair**; other pairs proceed. Rows with blank segments become global errors and block everything. — Done
- Only the **first** error per row is reported today. — Gap (§11)
- Unreachable appliance → PARTIAL, not failure. — Done

---

## 3. Template-group ACLs (`template_acls.csv`)

Code: `workflows.parse_template_acls`, `plan_template_acls`. Write unit: **template group**.

Headers (exact order):
`TemplateGroup,ACLName,ACLUpdateMode,TemplateApplyMode,Priority,Permit,Application,ApplicationGroup,SourceIP,DestinationIP,EitherIP,SourcePort,DestinationPort,EitherPort,SourceDomain,DestinationDomain,EitherDomain,Protocol,Comment,BroadMatchAck`

### 3.1 Fields

| Field | Required | Default | Constraint | Status |
|---|---|---|---|---|
| `TemplateGroup` | Yes | — | Nonblank, no control chars. Length/charset limit unknown. | Done / Test |
| `ACLName` | Yes | — | Nonblank, not `NewACL`, no control chars. Length/charset limit unknown. | Done / Test |
| `ACLUpdateMode` | Yes | — | `MERGE` only. `REPLACE` rejected. | Done |
| `TemplateApplyMode` | Yes | — | `MERGE` only. | Done |
| `Priority` | Yes | — | Vendor doc: `1..65535`. Today `0` and `>65535` are accepted. | Gap |
| `Permit` | Yes | — | Explicit Boolean; blank rejected even though vendor default is permit. | D13 approved |
| `Application` | No | — | One name (no `\|` split today). Must exist. | Done. Multi-value: Test |
| `ApplicationGroup` | No | — | One name. Must exist. | Done |
| IP family | No | — | IPv4/IPv6 literal or native address-group syntax (wildcard/range). | Done |
| Port family | No | — | VAL-05. | Done |
| Domain family | No | — | VAL-09. | Done |
| `Protocol` | No | — | `ip,tcp,udp,icmp,icmpv6,0..255`. | Done |
| `Comment` | No | — | Max length unknown. | Test |
| `BroadMatchAck` | No | FALSE | Required TRUE when no criteria. | Done |

### 3.2 Row rules

| ID | Rule | Status |
|---|---|---|
| ACL-01 | Within-family Either exclusivity for IP, port, domain. | Done |
| ACL-02 | Unconditional entry requires `BroadMatchAck=TRUE`. | Done |
| ACL-03 | Port fields require `Protocol` = `tcp`, `udp` or `tcp/udp`; port `0` = any. API also stores `ip` + port but vendor docs say it is not a valid port-capable protocol, so reject it. | Gap (confirmed) |
| ACL-04 | `Application` and `ApplicationGroup` both set: allowed; all criteria are ANDed (vendor doc and existing readback). | Done |
| ACL-08 | IP fields use compatibility grammar (§14.2), including dotted masks, ranges, wildcards, IPv6 CIDR and observed range+CIDR. All probe values had exact central readback; no appliance semantic claim because the group was unassociated. | Gap (API confirmed) |
| ACL-09 | Priority remains `1..65535`: API stored priority `0`, but vendor docs explicitly define 1 as minimum. `65535` was accepted and read back exactly. | Gap (confirmed) |
| ACL-05 | IP family uses `additionalSwitch_ip=ips`, port family `additionalSwitch_port=ports`. Group modes (address/service groups inside ACLs) are not supported and must stay rejected. | Done (no columns) |
| ACL-06 | Duplicate/empty list members (VAL-03/04). | Gap |
| ACL-07 | Host bits / IPv6 follow resolved VAL-07/08. | D3/D4 resolved |

### 3.3 Cross-row and existing-state rules

| ID | Rule | Status |
|---|---|---|
| ACL-10 | Identity `TemplateGroup + ACLName + Priority` unique in CSV. | Done |
| ACL-23 | Every row sharing `TemplateGroup + ACLName` must use the same normalized `ACLUpdateMode + TemplateApplyMode` pair; report the first conflicting row. | Done |
| ACL-11 | Existing identical rule → no-op; different rule at same priority → **complete replacement** (not a field patch), shown as overwrite in the plan. | Done |
| ACL-12 | Omitted priorities and unrelated ACLs/templates are preserved. | Done |
| ACL-13 | Same `ACLName` defined differently in two template groups associated with the same appliance → conflicting definitions. Proposed: block both groups. | Gap |
| ACL-14 | Missing group → typed exact group name + `APPLY`; created unassociated with Access Lists selected. | Done |
| ACL-15 | Existing group without Access Lists selected → typed `SELECT ACLS <group>`. | Done |
| ACL-16 | Existing native mode `merge=false` → typed `MERGE ACLS <group>`. | Done |
| ACL-17 | Never associate appliances. | Done |
| ACL-18 | Application/app-group dependencies re-checked before write (drift). | Done |
| ACL-19 | Omitting a priority does **not** remove it from appliances under native merge. Deletion needs the separate workflow in OI-032. | Documented limitation |

---

## 4. Application definitions (`application_definitions.csv`)

Code: `workflows.parse_application_definitions`, `_compound_payload`, `plan_application_definitions`.
Write unit: **individual definition**; conflicts are skipped and the run ends PARTIAL (exit 5).

### 4.1 Type → field matrix

`R` required, `O` optional, `—` must be blank (rejected if set). Common to all types:
`DefinitionType (R)`, `Name (R)`, `Notes (O)`, `Enabled (O, TRUE)`, `Confidence (O, 100)`, `AppExpressMode (O, OFF)`.

| Field | IP_PROTOCOL | TCP_PORT | UDP_PORT | DOMAIN | COMPOUND |
|---|---|---|---|---|---|
| `ProtocolNumber` | R `0..255` | — | — | — | — |
| `Port` | O, blank or `0` | R single `1..65535` | R single `1..65535` | — | — |
| `Domain` | — | — | — | R | — |
| `Protocol` | — | — | — | — | O |
| Port family | — | — | — | — | O |
| IP family | — | — | — | — | O |
| Geo family | — | — | — | — | O |
| Domain family | — | — | — | — | O |
| Address-map family | — | — | — | — | O |
| `DSCP` | — | — | — | — | O |
| `Interface` | — | — | — | — | O |

Status: matrix **Done** (`_reject_unused_fields`).

### 4.2 Row rules

| ID | Rule | Status |
|---|---|---|
| AD-01 | `Name` `[A-Za-z0-9_-]{1,31}`. | Done |
| AD-02 | `Notes` cannot contain `\|`. Max length unknown. | Done / Test |
| AD-03 | `Confidence` integer `1..100`. | Done |
| AD-04 | `AppExpressMode` `OFF` or `MONITOR` only (single source of truth). | Done |
| AD-05 | `DOMAIN` value passes VAL-09; wildcard only as leading `*.`. | Partial (VAL-09 Gap) |
| AD-07 | Application names are **not case-sensitive** (vendor doc). Duplicate detection and dependency lookups must compare case-insensitively. Name grammar is type-specific: compound stays `[A-Za-z0-9_-]{1,31}` (Swagger); TCP/UDP definitions accept dots (API exact-readback of `lab25.dot.probe`). | Gap (confirmed) |
| AD-08 | AppExpress monitoring is limited to **50 applications** (vendor doc). Existing MONITOR entries + new MONITOR rows > 50 must block. | Gap |
| AD-09 | Address Map definition type (IPv4 range, organization, country, Microsoft instance/category, proxy) is not supported by the CSV. | Unsupported (deferred) |
| AD-06 | `IP_PROTOCOL` with `ProtocolNumber` 6 or 17 should use `TCP_PORT`/`UDP_PORT` if a port is intended; `IP_PROTOCOL 6` with port `0` is legal (all TCP). Document only. | Done (doc) |

### 4.3 Compound rules

| ID | Rule | Status |
|---|---|---|
| CMP-01 | Within-family Either exclusivity for port, IP, geo, domain, address map. | Done |
| CMP-02 | At least two attributes (list members count individually). | Done |
| CMP-03 | A single TCP/UDP port with no other non-port attribute must use `TCP_PORT`/`UDP_PORT`. | Done |
| CMP-04 | Criteria text ≤ 512 characters. | Done |
| CMP-05 | Compound ports may coexist with blank, `ip`, `tcp`, `udp`, or `tcp/udp`; existing user/portal data and API readback confirm these forms. | Confirmed |
| CMP-06 | Protocol vocabulary: `ip,tcp,udp,tcp/udp,icmp,icmpv6` or `0..255`; do not impose ACL's tcp/udp-only port rule on compounds. | Gap |
| CMP-07 | `DSCP`: accept numeric `0..63` and standard names (`cs0..cs7`, `af11..af43`, `ef`, `be`), case-insensitive; normalize names lowercase. API exact-readback confirmed numeric `46`; existing appliance ACL confirms `ef`. | Gap (confirmed formats) |
| CMP-08 | `Geo`: accept ISO alpha-2 or the exact country name from the countries inventory; normalize to ISO alpha-2 for API. API exact-readback confirmed `US`. | Gap (confirmed encoding) |
| CMP-09 | `Interface`: accept numeric interface/label ID or an exact unique interface-label name; resolve names from `/gms/interfaceLabels` to ID. API exact-readback confirmed ID `15`; appliance ACLs use label IDs. Direct appliance interface-name support remains deferred. | Gap (confirmed label encoding) |
| CMP-10 | Address-map names must resolve from IP Intelligence inventory/search. API exact-readback confirmed `Office365Common` as `either_service`. | Gap (confirmed dependency) |
| CMP-11 | Compound IP accepts IPv4 address/CIDR/range per Swagger. IPv6 and wildcard forms remain deferred for compound specifically (the compound schema says IPv4). | Confirmed / deferred |
| CMP-14 | CSV multi-values stay `\|`; convert compound API payload lists to comma-separated strings. API exact-readback confirmed comma for ports/IPs; current code wrongly sends `\|`. | Gap (bug) |
| CMP-12 | Compound domains are stored inline; they do **not** require a `DOMAIN` definition. | Done (lab-confirmed) |
| CMP-13 | Reject DSCP/Geo/Interface/AddressMap values that cannot be normalized/resolved under CMP-07..10. | D10 resolved |

### 4.4 Cross-row and existing-state rules

| ID | Rule | Status |
|---|---|---|
| AD-10 | Duplicate identity in CSV (port+protocol, domain, compound name) → second row skipped as conflict. | Done |
| AD-11 | Same `Name` used by two rows of **different** types → not detected. Proposed: reject both rows. | Gap |
| AD-12 | `Name` colliding with a built-in/existing application of a different type → not detected. | Gap / Test |
| AD-13 | Existing identical definition → no-op; different → conflict, skipped, PARTIAL. Never overwrite. | Done |
| AD-14 | AppExpress intent of a skipped row is dropped; AppExpress applied only after the definition succeeds. | Done |
| AD-15 | Compound ID = `max(user IDs < 50000)+1`; re-read before POST; abort on drift. | Done |
| AD-16 | Compound deletion renumbers survivors; identity is name + semantic body, never ID. | Done |

---

## 5. Native address groups (`address_groups.csv`)

Code: `workflows.parse_address_groups`. Write unit: **whole import batch** (native importer is all-or-nothing).

Headers: `Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment`

| ID | Rule | Status |
|---|---|---|
| AG-01 | `Name` `[A-Za-z0-9_.-]{1,64}`. Native importer accepted 64 and rejected 65 with an explicit error. | Done / Gap (length, confirmed) |
| AG-15 | Nesting depth includes existing references: leaf + two parent levels accepted; a third parent rejected with `Only two levels of nesting allowed.` Today local validation treats existing groups as depth 0. | Gap (confirmed) |
| AG-17 | Range + dotted mask (`10.10-20.0.0/255.255.0.0`) was accepted and read back exactly by the native importer. | Done (confirmed) |
| AG-16 | Total address-group definitions ≤ 8 MB (vendor doc). Warn/block when existing + import exceeds it. | Gap |
| AG-02 | IPv4 member grammar: address, CIDR, dotted contiguous mask, ranged octet `10.1.1.1-20`, wildcard `10.*.1.1`. | Done |
| AG-03 | IPv6 rejected (tested 9.7.1 importer rejects). | Done |
| AG-04 | Members comma-separated inside a quoted cell. | Done |
| AG-05 | Row must have `IncludedIPs` or `IncludedGroups`. An exclude-only or empty row is accepted today. | Gap |
| AG-06 | `ExcludedIPs` requires `IncludedIPs` or `IncludedGroups` (covered by AG-05). | Gap |
| AG-07 | Same value in Included and Excluded of one row → reject. | Gap |
| AG-08 | Duplicate members in a cell → reject. | Gap |
| AG-09 | Multiple rows with the same `Name` = multiple rules of one group. | Done |
| AG-10 | `IncludedGroups` must exist in CSV or live inventory. | Done |
| AG-11 | No reference cycles; self-reference is a cycle. | Done |
| AG-12 | Nesting depth ≤ 2. | Done |
| AG-13 | Existing identical group → no-op; different → whole batch blocked. | Done |
| AG-14 | `Comment` length / forbidden characters. | Test |

## 6. Native service groups (`service_groups.csv`)

Code: `workflows.parse_service_groups`. Write unit: **whole import batch**.

Headers: `Name,Protocol,IncludedPorts,ExcludedPorts,IncludedGroups,ExcludedGroups,IcmpTypes,IcmpCodes,Comment`

Protocol → field matrix (`R` required, `O` optional, `—` rejected):

| Field | TCP / UDP | ICMP / ICMPV6 |
|---|---|---|
| `IncludedPorts` | R (or `IncludedGroups`) | — |
| `ExcludedPorts` | O | — |
| `IncludedGroups` | R (or `IncludedPorts`) | — |
| `ExcludedGroups` | O | — |
| `IcmpTypes` | — | R |
| `IcmpCodes` | — | O, only when exactly one type |

| ID | Rule | Status |
|---|---|---|
| SG-01 | Protocol `TCP/UDP/ICMP/ICMPV6`. | Done |
| SG-02 | Matrix above. | Done |
| SG-03 | Ports VAL-05, `*` wildcard allowed. | Done |
| SG-04 | `*` combined with other ports in the same cell → reject. | Gap |
| SG-05 | ICMP type/code `0..255`. | Done |
| SG-11 | ICMP types accept **ranges** (`1, 2, 4-8`). Native importer accepted/read back `4-8`. With a range, `IcmpCodes` stays forbidden (codes need exactly one scalar type). | Gap (confirmed) |
| SG-12 | `Name` `[A-Za-z0-9_.-]{1,64}`. Native importer accepted 64 and rejected 65 with an explicit error. | Gap (confirmed) |
| SG-13 | Nesting depth includes existing referenced groups (same as AG-15). Native address importer accepted leaf + two parent levels and rejected a third with `Only two levels of nesting allowed.` Repeat equivalent service-chain case in unit tests; live service probe unnecessary. | Gap (confirmed platform rule) |
| SG-14 | Total service-group definitions ≤ 4 MB (vendor doc). | Gap |
| SG-15 | Vendor doc lists no `IcmpCodes` column; the 9.7.1 export/import (lab CSVs) has it. Lab evidence wins for 9.7.1; keep the column. | Done (conflict recorded) |
| SG-06 | Excluded port not inside any included port/range → warn (has no effect). | Gap (warning) |
| SG-07 | Same value in Included and Excluded (ports or groups) → reject. | Gap |
| SG-08 | Included/excluded groups exist, no cycle, depth ≤ 2. | Done |
| SG-09 | A referenced group whose protocol differs from the row protocol → unknown behavior. | Test |
| SG-10 | ICMPv6 import limitation on 9.7.1 (documented release issue). | Done (doc) |

## 7. Application groups (`application_groups.csv`)

Code: `workflows.parse_application_groups_partial`, `plan_application_groups`.
Write unit: full collection POST, but **per-group eligibility**; skipped groups → PARTIAL.

Headers: `Name,Applications,ParentGroups`

| ID | Rule | Status |
|---|---|---|
| APG-01 | `Name` `[A-Za-z0-9_.-]+`; invalid → skipped. | Done |
| APG-02 | Duplicate `Name` in CSV → all copies skipped. | Done |
| APG-03 | Group with no `Applications` and no `ParentGroups` → accepted today. Proposed: reject. | Gap |
| APG-04 | Every application exists in live inventory. | Done |
| APG-05 | Every parent exists in CSV or live inventory. | Done |
| APG-06 | Cycles → all cycle members skipped. | Done |
| APG-07 | Dependents of skipped groups are skipped transitively. | Done |
| APG-08 | Nesting depth limit (address/service use 2) not enforced. | Gap / Test |
| APG-09 | Existing identical → no-op; different → skipped. | Done |
| APG-10 | Duplicate members in a cell → reject. | Gap |
| APG-11 | Name colliding with an application name (same namespace in firewall/ACL?) | Test |

## 8. Zones (CLI arguments, no CSV)

| ID | Rule | Status |
|---|---|---|
| ZN-01 | Names `[A-Za-z0-9_]+`, unique, not reserved. | Done |
| ZN-02 | Full collection replacement with typed `CREATE <zone>` per zone. | Done |

---

## 9. Cross-workflow dependency graph

### 9.1 Create order

```text
Zones ──────────────────────────────────────────────┐
Address groups ─────────────────────────────────────┤
Service groups ─────────────────────────────────────┤
Application definitions (+ AppExpress) ─┬→ App groups ┤
                                        └────────────┼→ Template ACLs ─→ Firewall rules (acl)
                                                     └→ Firewall rules
```

| ID | Rule | Status |
|---|---|---|
| DEP-01 | Every workflow checks dependencies against **live** inventory only. A dependency created in the same session must be deployed first. | Done (by design) |
| DEP-02 | Firewall `acl` requires the template ACL to exist centrally; appliance presence only warns. | Done |
| DEP-03 | Template ACL `Application`/`ApplicationGroup` must exist. | Done |
| DEP-04 | App-group applications must exist (built-in or user-defined). | Done |
| DEP-05 | Address/service group nesting only within the same object type. | Done |
| DEP-06 | Compound address maps must exist. | Test (CMP-10) |

### 9.2 Delete order

```text
Firewall rules → Template ACLs (separate, OI-032) → App groups
→ Application definitions (+ AppExpress) → Service groups → Address groups
```

| ID | Rule | Status |
|---|---|---|
| DEL-01 | Exact semantic match only; different existing object blocks deletion. | Done |
| DEL-02 | Full table + generated code + `I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION`. | Done |
| DEL-03 | Group deletion order computed within the batch; non-target group referencing a target blocks. | Done |
| DEL-04 | App definition deletion blocked if an app group references it. | Done |
| DEL-05 | Address/service group deletion **not** blocked when a global firewall rule references the group. | Gap — must block |
| DEL-06 | App definition / app group deletion **not** blocked when a firewall rule or a template ACL references it. | Gap — must block |
| DEL-07 | Compound deletion: resolve current ID immediately before delete, re-verify body. | Done |
| DEL-08 | Template ACL deletion: separate workflow, zero `secmap/rmap/qmap` references before appliance delete. | Gap (OI-032) |

---

## 10. Validation architecture (proposed)

Principle: reuse what exists, no framework.

1. **One shared family checker.** Replace the three copies of the Either loop (`firewall._parse_rule`,
   `parse_template_acls`, `_compound_payload`) with one small function taking `(row, families)` and
   returning error strings. Families are data (tuples), as they already are in the ACL/compound code.
2. **Shared value checkers** already exist: `_validate_ports`/`_check_port_members`, `_validate_ip_list`,
   `_validate_domain`, `_validate_address_group_member`. Merge the two port checkers; add the
   duplicate/empty-member check once in the splitter.
3. **Collect all errors per row** instead of raising on the first one. Parsers return
   `(valid_rows, errors)`; the existing isolation unit decides what is blocked.
4. **Isolation units stay as they are:**

   | Workflow | Error blocks |
   |---|---|
   | Firewall | segment pair (blank-segment rows block all) |
   | Template ACL | template group |
   | Address / service groups | whole batch (native all-or-nothing) |
   | Application definitions | the row (independent rows continue, exit 5) |
   | Application groups | the group + transitive dependents (exit 5) |
   | Zones | whole request |

5. **Warnings** (FW-05, FW-26, SG-06, FW-08) never block; they appear in preview and report.

## 11. Error report format (proposed)

Every error/warning in console output and JSON report:

```json
{
  "rule": "FW-09",
  "severity": "error",
  "row": 14,
  "field": "either_port",
  "value": "443",
  "resource": "rule_key=pos-001",
  "message": "either_port cannot be combined with source_port or destination_port",
  "fix": "Use either_port alone, or move the value to source_port/destination_port",
  "blocks": "segment_pair:Default->Default"
}
```

`blocks` ∈ `row`, `group:<name>`, `segment_pair:<a>-><b>`, `template_group:<name>`, `batch`.
Console form: `row 14 [FW-09] either_port=443: either_port cannot be combined with ... Fix: ...`

Exit codes unchanged: validation failure blocks everything → validation code; some units blocked and
others succeeded → 5 (PARTIAL).

---

## 12. Test plan (write failing tests first)

All local, no API writes. Files: `tests/test_firewall.py`, `tests/test_workflows.py`.

| Area | Cases |
|---|---|
| Family matrix | For **each** family in each CSV: 8 combinations from §1.3 → 5 accepted, 3 rejected. Table-driven, one test per CSV. |
| Cross-family (D1) | Either literal + directional group, directional literal + Either group, for IP and port dimensions. |
| Protocol/port | Ports without protocol, with `icmp`, with `6`; firewall, ACL, compound. Firewall protocol list (VAL-06). |
| List hygiene | `443\|443`, `443\|\|80`, `,` in a `\|` field, `*` mixed with ports. |
| IP | Host bits, IPv6 (per D3/D4), native wildcard in ACL vs. compound. |
| Domain | Accept `example.com`, `*.example.com`, `*example.com` (observed GUI form); reject `.example.com`, `a..b`, middle wildcard `ex*ample.com`, 64-char label. |
| Empty groups | AG-05, APG-03, exclude-only rows, Included = Excluded. |
| Names | Cross-type duplicate app name (AD-11), control characters in every name field. |
| Short rows / empty files | CSV-06, CSV-08 for every resource CSV. |
| ACL | Priority bounds, ports without tcp/udp, cross-group ACL name conflict (ACL-13). |
| Deletion deps | Group referenced by firewall rule (DEL-05), app referenced by firewall/ACL (DEL-06). |
| Reporting | Multiple errors on one row are all reported; each carries rule ID, field, fix, blocks. |
| Regression | Existing 120 tests still pass; CLI help unchanged; no `appexpress` command. |

Completed API/importer contract probes are recorded in §15.2. Remaining future tests: SG-09 protocol-mismatched nesting, APG-08/11, comment limits, direct appliance semantics of ACL IPv6/range/dotted-mask matches, and compound direct-interface (not label) names. Do not block implementation of the confirmed local rules on these deferred items.

## 13. Implementation phases (after approval)

1. **Phase A — shared parsers and correctness bugs:** policy/address IP grammars; compound `\|`→`,` API conversion; domain grammar; `tcp/udp`; ACL priority `1..65535`; ICMP type ranges; 64-char group names; nesting depth including existing groups. Write table-driven failing tests first.
2. **Phase B — cross-field completeness:** all directional-family matrices; protocol/port rules by workflow; duplicate/empty members; empty/exclude-only groups; short rows/empty files; type-specific/case-insensitive application names; AppExpress limit 50; firewall domain columns (FW-17).
3. **Phase C — dependency validation:** compound geo/DSCP/interface-label/address-map resolvers; application/group dependencies; cross-template ACL conflict; warnings (host bits, redundant acknowledgments, duplicate semantics).
4. **Phase D — deletion safety:** DEL-05/06; block deletes referenced by firewall or template ACL state. Template ACL deletion remains separate under OI-032.
5. **Phase E — structured errors:** collect all errors with rule ID/field/fix/block scope while preserving existing isolation units and exit codes.
6. Update templates, `CSV_REFERENCE.md`, requirements, operator guide and changelog; full tests; CLI/reference audit; read-only lab plans. Any deployment remains separately approved.

---

## Decisions to approve

| ID | Question | Recommendation |
|---|---|---|
| D1 | Mix Either and directional across literal/group of same dimension? | **Resolved: allow.** Existing GUI-created/effective rule uses it; criteria are ANDed. Within the *same family*, Either + Source/Destination remains rejected. |
| D3 | IP literal with host bits (`10.0.0.5/24`)? | **Resolved: accept + warning.** GUI/API preserve it verbatim; explain effective network. |
| D4 | IPv6 in firewall / ACL / compound? | **Resolved:** firewall/ACL accept IPv6 CIDR and documented policy wildcard/range grammar (API readback confirmed); native address groups and compound remain IPv4-only. |
| D5 | `logging_level` set while `logging=FALSE`? | **Approved: reject** nonzero level (owner, 2026-09-24). |
| D8 | Service group combined with `protocol`? | **Approved: allow.** Criteria are ANDed (owner, 2026-09-24). |
| D10 | Compound DSCP / Geo / Interface / AddressMap encoding? | **Resolved:** CMP-07..10 canonical forms above. |
| D11 | Treat `application=any` like `application_group=any`? | **Approved: reject** `application=any`; use blank or `application_group=any` (owner, 2026-09-24). |
| D12 | Collect all errors per row (vs. first error)? | **Approved: yes** (owner, 2026-09-24). |
| D13 | Blank ACL `Permit` = vendor default permit? | **Approved: No** — `Permit` stays explicit TRUE/FALSE (owner, 2026-09-23). |
| D14 | Policy dotted mask (`10.0.0.0/255.255.0.0`)? | **Resolved: accept.** Unassociated ACL API probe stored/read it exactly; address-group importer also supports dotted masks. Mark appliance semantics unverified until naturally encountered in a reviewed deployment. |

---

## 14. Accepted value formats (vendor docs vs. current code)

Sources (read 2026-09-23): Orchestrator techdocs pages *Address Groups*, *Service Groups*,
*Application Definitions*, *Access Lists Template*. "Now" = measured against current code.

### 14.1 Address-group IP grammar (native address groups only)

Vendor rule: an octet may be a number, a range `a-b`, or `*`; a CIDR prefix **or** dotted mask may be
combined with ranges/wildcards. IPv4 only (9.7.1 lab).

| Example | Meaning | Vendor | Now |
|---|---|---|---|
| `10.10.10.1` | host | valid | accept |
| `10.10.10.2, 10.10.10.3` | list (comma in quoted cell) | valid | accept |
| `10.10.0.0/16` | CIDR | valid | accept |
| `10.10.0.0/255.255.0.0` | dotted mask | valid | accept |
| `10.10.10.10-20` | range in last octet | valid | accept |
| `10.10-20.0.0/16` | range + CIDR | valid | accept |
| `10.10-20.0.0/255.255.0.0` | range + mask | valid | accept |
| `10.10.0-10.1/24` | range + CIDR (your example) | valid | accept |
| `10.10.10.*` | wildcard octet | valid | accept |
| `10.*.0.0/16`, `10.*.0.0/255.255.0.0` | wildcard + mask | valid | accept |
| `10.13*.*.64-95` | partial-octet wildcard | invalid | reject (correct) |
| `2001:db8::/32` | IPv6 | rejected by 9.7.1 importer | reject (correct) |

Result: address-group IP grammar already matches the vendor doc. Missing: name length 64 (AG-01),
existing-group depth (AG-15), size limit (AG-16), duplicate/overlap checks (AG-07/08).

### 14.2 Policy IP grammar (firewall, template ACL)

Vendor rule ("Wildcard-based Prefix Matching Rules", applies to Route, QoS, Optimization, NAT,
**Security** and **ACLs**): four dotted octets; an octet is a number, one range `a-b`, or a whole `*`;
**CIDR and range/wildcard are mutually exclusive in the same address**; same rules apply to IPv6;
`0.0.0.0/0` = any.

| Example | Vendor | Firewall now | ACL now |
|---|---|---|---|
| `10.10.10.0/24` | valid | accept | accept |
| `0.0.0.0/0` | valid (any) | accept | accept |
| `10.10.10.10-20` | valid | **reject (wrong)** | accept |
| `10.10.10.*` | valid | **reject (wrong)** | accept |
| `10.136-137.*.64-95` | valid | **reject (wrong)** | accept |
| `10.13*.*.64-95` | invalid | reject | reject |
| `192.168.0.1-127/24` | invalid (CIDR + range) | reject | **accept (wrong)** |
| `10.10-20.0.0/16` | invalid in policies | reject | **accept (wrong)** |
| `10.0.0.0/255.255.0.0` | not documented | accept | accept → D14 |
| `2001:db8::/32` | "same rules apply" | accept | accept → D4 |
| IPv6 range/wildcard | "same rules apply" | reject | reject → D4 |

Compatibility conclusion after API probe and existing GUI evidence: accept plain IPv4/IPv6, CIDR, dotted IPv4 mask, whole-octet wildcard and octet ranges. Also accept range/wildcard + CIDR/mask because 9.7.1 GUI-created ACL state already contains it and the API preserved it exactly, despite the general vendor-doc prohibition. Reject partial-octet wildcards (`13*`) and malformed/reversed ranges. Emit a compatibility warning for range/wildcard + mask.

Implementation: one `policy_ip()` checker for firewall and ACL, reusing the address-group octet parser. Compound stays its narrower Swagger IPv4 address/CIDR/range grammar.

### 14.3 Ports

| Context | Vendor formats | Now |
|---|---|---|
| Service group ports | `20`, `20, 22, 24-30` (comma list) | accept; also `*` (lab) |
| Service group ICMP types | `1, 2, 4-8` (ranges allowed) | **ranges rejected** (SG-11) |
| ACL / policy ports | number, range; `0` = any; only with `tcp`, `udp`, `tcp/udp` | ranges accept; `tcp/udp` not accepted (FW-15/ACL-03) |
| App definition TCP/UDP port | single port | accept (1..65535) |

### 14.4 Names and text

| Object | Vendor rule | Now |
|---|---|---|
| Address / service group name | letters, digits, `.`, `_`, `-`; ≤ 64 | charset ok, no length check |
| Application name | not case-sensitive | case-sensitive compare (AD-07) |
| Confidence | 1..100 | accept |
| Domain | `example.com` or `*.example.com` | too permissive (VAL-09) |
| ACL priority | 1..65535 | 0..unbounded (ACL priority row) |
| AppExpress monitored apps | ≤ 50 | not checked (AD-08) |

### 14.5 Documentation conflicts recorded

- Service-group doc omits `IcmpCodes`; 9.7.1 lab import/export includes it → keep (SG-15).
- App-definition doc says Domain "applies to UDP Port, TCP Port, and Compound"; the 9.7.1 API and GUI
  use a separate DNS definition type → keep current `DOMAIN` type; treat as a doc error.
- Address-group doc allows CIDR + range; ACL doc forbids it in policies → both are correct for their
  own context; hence two grammars (§14.1 vs. §14.2).

---

## 15. Read-only lab evidence (2026-09-23, Orchestrator 9.7.1.42046, appliance 0.NE)

Method: GET only — Swagger, central template ACLs, `0.NE` ACLs and security map, global policy,
user/portal compound definitions, interface labels, countries, AppExpress. No writes.

### 15.1 Key finding: the API and the appliance store values verbatim

Orchestrator and the appliance both accepted and kept, unchanged, values the vendor docs call invalid
or that our rules reject. **API success or appliance readback does not prove a value is valid.**
The GUI (and the native bulk importers) are the only real validators, so they are the reference for
"correct" values.

| Observed (GUI-created unless noted) | Where | Impact on spec |
|---|---|---|
| `src_port` **and** `either_port` in one rule (`20-30\|90` both) | global firewall 20030, also on 0.NE | API does not enforce Either exclusivity. Keep our rule (ambiguous semantics); likely a stale GUI toggle value. |
| `dst_ip` literal + `either_addrgrp_groups` in one rule | firewall 20030 | D1 resolved: allow cross-family mixed direction for compatibility. |
| `application` + `app_group` together (incl. `app_group=any`) | firewall 20040, ACLs | Coexistence is real (FW-16). Swagger says "mutually exclusive" for ACL entries — Swagger text is wrong or stale. |
| `dst_ip 12.1.73.1/24`, ACL `dst_ip 10.10.10.1/24` | firewall 20010, ACL test3 | Host bits kept verbatim, no normalization. D3 is a semantics question only; no readback mismatch. |
| ACL `src_ip 1.1.1.1-255/32` (range + CIDR) | test3 ACL | Compatibility form: GUI-created and API-preserved; accept with warning despite vendor-doc conflict. |
| Domain `*youtube.com`, `*google.com`, `*nametests.com` | ACL, compound, firewall | Wildcard **without** a dot is accepted by GUI. VAL-09 must allow a leading `*` prefix; do not force `*.`. |
| Firewall `either_dns` | firewall 20000 | Global firewall supports a domain family; our firewall CSV has no domain columns (new gap FW-17). |
| Compound `protocol=ip` with `src_port`/`dst_port` | compound id 2 | Ports do not require tcp/udp in compound (CMP-05 resolved: allowed). |
| Protocol `tcp/udp` | portal compound 50004/50005 | Literal value `tcp/udp` is a valid protocol token (FW-15/ACL-03 encoding). |
| Compound multi-IP uses **comma** (`a/32,b/32`) | compound id 1 (GUI) | Our tool sends `\|` for compound lists (e.g. `443\|8443`). Probable bug — GUI encoding is comma. |
| Firewall multi-values use `\|` (`443\|80\|6443`) | firewall | Current firewall encoding is correct. |
| ACL `dscp: "ef"`, `vlan: "15"` (15 = LAN label `KIDS`) | 0.NE overlay ACLs (system-generated) | DSCP by name, interface by **label ID**. Our compound sent `lan0`, `af31`, country names — stored verbatim, meaning unknown. |
| Countries: name → ISO code map (`Cambodia → KH`) | `/spPortal/internetDb/serviceIdToSaasId/countries` | Geo encoding (name vs ISO) must be taken from a GUI sample. |
| DNS app name `tiktokv.us` | DNS definition | App names may contain `.`; our pattern `[A-Za-z0-9_-]{1,31}` rejects it (Swagger pattern applies to compound only). |
| AppExpress: 2 monitored entries | AppExpress | 50-app limit check (AD-08) is cheap; no probe needed. |

### 15.2 Approved API/importer probes and cleanup

Owner approved temporary unassociated template/API probes and native importer probes. Every accepted object was read back, then deleted. Independent final inventory found zero temporary groups, associations, definitions, or ACLs. The temporary compound was the highest user ID; after deletion the exact compound baseline fingerprint was restored.

| Probe | Result |
|---|---|
| Unassociated ACL group | Created with zero associations; all entries below had exact central readback; group deleted. No appliance push. |
| ACL dotted mask `10.0.0.0/255.255.0.0` | API accepted/read back exactly → D14 accept. |
| ACL range/wildcard `10.136-137.*.64-95` | API accepted/read back exactly. |
| ACL range + CIDR `192.168.0.1-127/24` | API accepted/read back exactly; existing GUI-created ACL also has this form → compatibility accept + warning. |
| ACL IPv6 CIDR `2001:db8::/32` | API accepted/read back exactly; vendor docs say IPv6 uses same policy rules. |
| ACL IPv6 wildcard `2001:db8:*:*:*:*:*:*` | API accepted/read back exactly. |
| ACL multi-IP pipe separator | API accepted/read back `10.1.1.0/24\|10.2.2.0/24` exactly. |
| ACL protocol `tcp/udp` + port | API accepted/read back exactly; allow. |
| ACL protocol `ip` + port | API stores it, but vendor docs explicitly restrict ports to tcp/udp/tcp/udp → reject locally. |
| ACL domain `ex*ample.com` | API stores it, but no vendor/GUI evidence middle wildcards are valid → reject locally. |
| ACL priority `0` | API stores it, but vendor range is 1..65535 → reject locally. |
| ACL priority `65535` | Accepted/read back exactly → allow. |
| Disabled compound canonical payload | `tcp/udp`, comma-separated ports/IP, ISO geo `US`, DSCP `46`, label ID `15`, address map `Office365Common` accepted/read back exactly; deleted; baseline restored. |
| Disabled TCP definition `lab25.dot.probe` | Dot in non-compound app name accepted/read back; deleted. |
| Address group range + dotted mask | Native importer accepted/read back `10.10-20.0.0/255.255.0.0`. |
| Address group name length | 64 accepted; 65 rejected: `Group name cannot be longer than 64 characters.` |
| Service group ICMP type range | Native importer accepted/read back `4-8`. |
| Service group name length | 64 accepted; 65 rejected with same explicit error. |
| Existing-depth address chain | Leaf + two parent levels accepted; third parent rejected: `Only two levels of nesting allowed.` |

Raw result (gitignored): `reports/probe/api_format_probe_result.json`.

### 15.3 Evidence boundary

Unassociated template API readback proves the Orchestrator accepts and preserves syntax; it does not prove an appliance will match packets as intended. Therefore:

- Vendor-documented + API-confirmed forms are supported.
- Existing GUI-created + central/effective/appliance-read forms are supported for compatibility.
- API-only forms that contradict docs (`priority 0`, `ip` + port, middle wildcard) are rejected.
- Dotted masks and policy IPv6 are supported, but their packet-match semantics remain uncertified until they appear in a separately approved appliance deployment and traffic test.

---

## 16. Final approved implementation plan (2026-09-24)

Replaces §13. All decisions D1–D14 are resolved. Implementation is local code + tests only; any
lab deployment still needs separate approval.

### 16.1 Principles

- Tests first: each phase starts with failing table-driven tests in `tests/test_firewall.py` /
  `tests/test_workflows.py`, then the smallest code change that passes.
- Reuse existing helpers; no validation framework, no new dependency.
- Isolation units unchanged: firewall segment pair, template-ACL group, native importer batch,
  individual app definition, app-group dependency tree. Exit codes unchanged.
- Existing 120 tests must keep passing after every phase.

### 16.2 Phases

| Phase | Scope (rule IDs) | Main code touch points |
|---|---|---|
| **1. Error collection (D12)** | Parsers collect **all** errors per row instead of raising on the first; every message carries rule ID, row, field, value, resource, fix, and blocked scope (§11). Build this first so later phases emit rich errors. | `firewall._parse_rule`, `workflows.parse_*`, `_read_exact_csv` |
| **2. Shared value grammars** | `policy_ip()` for firewall + ACL (FW-14, ACL-08, D3 warning, D4 IPv6, D14 dotted mask, range/wildcard, compatibility warning for range+mask); address-group grammar unchanged; compound IPv4 address/CIDR/range; one port checker; domain grammar (`example.com`, `*.example.com`, `*example.com`; reject middle wildcard, leading/trailing dot, `..`, label >63) (VAL-09); list hygiene — duplicate/empty members, wrong delimiter (VAL-03/04, VAL-02). | `firewall._validate_ip_list/_validate_ports`, `workflows._validate_address_group_member/_check_port_members/_validate_domain` |
| **3. Protocol and field rules** | Protocol vocabulary incl. `tcp/udp` everywhere (VAL-06, FW-15); ports need tcp/udp/tcp/udp in firewall + ACL (FW-06, ACL-03); compound allows ports with blank/ip/tcp/udp/tcp/udp (CMP-05/06); ACL priority 1..65535 (ACL-09); D5 logging level; D11 `application=any`; FW-05 redundant ack warning. | `firewall._parse_rule`, `parse_template_acls`, `_compound_payload` |
| **4. Directional families** | Within-family Either exclusivity for every family (already present) consolidated into one helper; cross-family mixing allowed (D1); firewall domain columns `source_domain/destination_domain/either_domain` → `src_dns/dst_dns/either_dns` (FW-17), optional header for backward compatibility. | `firewall.py` headers/`rule_match`, shared family helper |
| **5. Compound encoding fix** | CSV `\|` lists → API comma lists (CMP-14, confirmed bug); geo → ISO alpha-2 from countries inventory (CMP-08); DSCP 0..63 or standard names (CMP-07); interface label name → ID from `/gms/interfaceLabels` (CMP-09); address map resolved via IP Intelligence search (CMP-10); unresolvable → reject (CMP-13). Existing compound no-op/conflict comparison must use the normalized payload. | `_compound_payload`, gateway read helpers, `plan_application_definitions` |
| **6. Native groups** | 64-char names (AG-01, SG-12); nesting depth including existing groups (AG-15, SG-13); ICMP type ranges, codes only with one scalar type (SG-11); non-empty include required (AG-05/06, SG); Included ≠ Excluded (AG-07, SG-07); `*` alone (SG-04); excluded-outside-included warning (SG-06); size limits 8 MB / 4 MB (AG-16, SG-14). | `parse_address_groups`, `parse_service_groups`, `_validate_graph` |
| **7. Application definitions & groups** | Type-specific names: compound `[A-Za-z0-9_-]{1,31}`, others allow `.` (AD-07); case-insensitive duplicate and dependency matching (AD-07, AD-11, APG); AppExpress MONITOR total ≤ 50 (AD-08); empty app groups rejected (APG-03); duplicate members (APG-10). | `parse_application_definitions`, `plan_application_*`, `_check_dependencies` |
| **8. CSV structure** | Short rows rejected everywhere (CSV-06); empty files rejected for all resource CSVs (CSV-08); control characters in names/comments (CSV-10). | `_read_exact_csv`, firewall parser |
| **9. Deletion safety** | Block address/service-group deletion referenced by global firewall rules (DEL-05); block app-definition/app-group deletion referenced by firewall or template ACLs (DEL-06). Template ACL deletion stays separate (OI-032). | `cli.py` delete handlers |
| **10. Docs and templates** | Update `CSV_REFERENCE.md`, `IMPLEMENTATION_REQUIREMENTS.md`, `OPERATOR_GUIDE.md`, CSV templates (firewall domain columns), example datasets (compound lists), `CHANGELOG.md`. | docs, templates, examples |

### 16.3 Verification per phase

1. New failing tests written and seen failing.
2. Implementation; full suite, `python -m compileall`, `git diff --check`.
3. Final: CLI help audit, repository reference audit, `--dry-run` plans against the lab for every
   workflow (read-only). Live writes only with a separate approval.

### 16.4 Compatibility impact to communicate

- Firewall CSVs with range/wildcard IPs, IPv6, `tcp/udp` now validate (previously rejected).
- Previously accepted inputs now rejected: `application=any`, nonzero `logging_level` with logging
  off, ACL priority `0`, ACL `ip`+port, middle-wildcard domains, duplicate/empty list members,
  65-char group names, empty groups.
- Compound definitions previously deployed with `|` lists, country names, `lan0`, or `af31` will show
  as semantic conflicts against the new normalized payload; they are skipped (never overwritten)
  and reported. Recreating them requires an explicit delete + redeploy.

### 16.5 Out of scope

Template ACL `REPLACE` and deletion (OI-032), Address Map definition type, compound IPv6 and direct
interface names, AppExpress steering, packet-level appliance verification of IPv6/dotted-mask
matches, URL matching.

---

## 17. Implementation status (2026-09-24)

Code: shared rules in `src/edgeconnect_automation/validation.py`. `templates/edgeconnect/` contains six clean starter files. `examples/edgeconnect/` contains one broader valid CSV and one intentionally mixed valid/invalid CSV per workflow; tests prove every valid file parses, every mixed file is rejected, and cross-file dependencies resolve. Additional edge cases are generated in temporary directories by the standard-library test suite.

### 17.1 Implemented

| Area | Rule IDs |
|---|---|
| Error model | D12: all errors per row and per file; rule ID, row, field, value, fix, blocked scope; structured issues in `firewall validate`; warnings separate from errors |
| CSV structure | CSV-05, CSV-06, CSV-08, CSV-10; VAL-02, VAL-03, VAL-04 |
| Value grammars | VAL-06 protocol vocabulary incl. `tcp/udp`; VAL-09 domains; policy IP (FW-14, ACL-08, D3 warning, D4, D14, compatibility warning); compound IPv4 (CMP-11) |
| Firewall | FW-01..FW-06, FW-12..FW-19 (FW-17 domain columns, FW-18 D11, FW-19 D5), FW-05 warning, DIR-01 within-family exclusivity, D1 cross-family allowed, case-insensitive application dependencies |
| Template ACL | ACL-02, ACL-03, ACL-07..ACL-10, ACL-20..ACL-23, explicit Permit (D13); ACL-13 (conflicting same-priority bodies on shared appliances) was already enforced by the planner |
| Compound | CMP-02..CMP-11, CMP-13, CMP-14 comma payload; live resolution of geo (ISO), interface label (ID), address map (canonical name); DSCP normalization |
| Application definitions | AD-01..AD-08 incl. type-specific names (dots allowed except COMPOUND), case-insensitive single spelling, AppExpress limit 50 |
| Native groups | AG-01, AG-02, AG-05, AG-07, AG-11, AG-12, AG-15 (existing depth, enforced by the planner), AG-16 warning; SG-01, SG-02, SG-04, SG-05, SG-06 warning, SG-07, SG-11, SG-12, SG-13, SG-14 warning |
| Application groups | APG-03 empty groups, APG-10 duplicate/empty members, case-insensitive application references |
| Deletion safety | DEL-05 address/service groups referenced by global firewall rules; DEL-06 application groups and vanishing application names referenced by global firewall rules or central template ACLs |

### 17.2 Deliberate deviations from the approved plan

| Plan item | Implemented behaviour | Evidence |
|---|---|---|
| FW-06 / ACL-03 "ports require tcp, udp or tcp/udp" | Ports are also allowed with a **blank** protocol (and `6`/`17`); any other explicit protocol is rejected | GUI-created firewall rule 20030 and GUI-created ACL `test3/lab25-test3` priority 1020 store ports with no protocol; rejecting blank would refuse real GUI configuration |
| AD-11 "reject the same name across definition types" | Allowed; instead, all rows for one application must use one spelling (case-insensitive) | Portal definitions reuse one application name across several entries (e.g. `Teams-Audio` compounds 50002/50003); an application defined by port plus domain is a normal pattern |
| Lab example `*gamma*` domain | Replaced with `*gamma.example.com` | All 108,605 vendor portal domain definitions use `*.` form; `*gamma*` was API-only |
| Lab/template compound interface `lan0`, `lan0.10` | Replaced with interface-label names (`Data`, `Voice`) | Interface is stored as a label ID; raw interface names remain deferred |
| Lab compound IPv6 row | Replaced with IPv4 range + `tcp/udp` + numeric DSCP | Compound schema is IPv4-only |
| Lab invalid case "port without protocol" | Now "port with ICMP protocol" | Blank protocol with ports is valid (see first row) |

### 17.3 Deferred (not implemented)

| Item | Reason |
|---|---|
| URL / web category / reputation matching | Owner deferred; Swagger lists `webcc_*` keys; URL classification is disabled on the lab appliance |
| FW-26 duplicate-semantics warning | Low value; no safety impact |
| APG-08 application-group nesting depth, APG-11 group/application namespace | No platform evidence of a limit |
| SG-09 protocol-mismatched nested service groups | No platform evidence |
| Comment/Notes/ACL name length limits | No platform evidence; importer and API errors remain the backstop |
| AD-12 name collision with built-in applications of another type | Built-in collisions are valid multi-definition applications on the platform |
| Compound IPv6, wildcard, direct interface names | Compound schema is IPv4 address/prefix/range; interface is a label ID |
| Template ACL `REPLACE` and deletion | OI-032 |
| Packet-level appliance verification of IPv6, dotted-mask and range+mask policy matches | Needs a separately approved deployment and traffic test |

### 17.4 Compatibility impact

- Newly accepted: firewall ranges, wildcards, dotted masks, and IPv6; `tcp/udp`; ports with a blank protocol in template ACLs; ICMP type ranges; dots in non-compound application names; firewall domain columns.
- Newly rejected:
  - `application=any`
  - a nonzero `logging_level` with logging off
  - ACL priority 0 or above 65535
  - ACL or firewall ports with `ip`/`icmp`
  - middle or trailing domain wildcards
  - duplicate or empty list members and wrong separators
  - 65-character group names
  - exclude-only address rules
  - include/exclude overlaps
  - empty application groups
  - short rows, empty files, and control characters
- Compound definitions deployed before this change with `|` lists, country names, interface names, or uppercase DSCP names will now compare as semantic conflicts. They are skipped, never overwritten; recreate them with exact delete plus redeploy if needed.
