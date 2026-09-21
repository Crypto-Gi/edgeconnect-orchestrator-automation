# EdgeConnect Automation Operator Guide

## Scope and safety

`edgeconnect-auto` is a Python 3.9+ standard-library-only tool for global routing-segmentation firewall policy, zones, native address/service groups, application groups, application definitions, AppExpress Monitor configuration, and strict exact-match CSV deletion. It does not manage templates, appliance-local rule modification, Routing Segmentation enablement, semantically different existing-object updates, or automatic dependency deletion.

The implementation is locally unit tested. API contracts were separately exercised in an isolated Orchestrator 9.7.1.42046 lab with one reachable ECOS 9.5.4.1 appliance: global policy create/readback/apply/rollback, native address/service imports, application definitions including compound, application groups, AppExpress monitor, audit correlation, and cleanup. This is not production certification or multi-appliance/multi-release validation. The global policy adapter uses the confirmed `merge=false` and `templateApply=false`; other releases require version-matched validation.

When `--dotenv` is omitted, commands load only `./.env` from the current working directory. The tool never searches parent or home directories. Process environment variables override file values; `--dotenv <PATH>` selects a different file. HTTPS certificate and hostname verification are enabled by default; configure a private CA bundle when required. Reports contain sensitive configuration, are redacted and fingerprinted, and are written with mode `0600`.

Every normal write command performs discovery, validation and preview in the same process, then:

1. Displays the sanitized exact candidate, target state, fingerprints, impact, verification and recovery information.
2. Refuses non-TTY execution.
3. Requires exact uppercase `APPLY` with no `--yes` bypass.
4. Re-reads the affected baseline and aborts on drift.
5. Verifies normalized saved-state readback.

Zone creation additionally requires `CREATE <zone>` for each new zone. `--dry-run` performs reads and preview only, makes no writes, requires no TTY, and returns success when validation succeeds.

## Installation and configuration

Run from the project root:

```text
PYTHONPATH=src python3 -m edgeconnect_automation --help
```

Supported runtime aliases include `orchestrator_base_url` / `ORCHESTRATOR_BASE_URL` / `EDGECONNECT_BASE_URL` / `EC_BASE_URL`, corresponding API-key aliases, CA-bundle aliases, and API-key-header aliases. Never place credentials in command arguments, reports, templates or source files.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success, verified no-op, or valid dry-run preview |
| 1 | Runtime or API error |
| 2 | Validation failure or no eligible firewall pair |
| 3 | Approval refusal or non-TTY write refusal |
| 4 | Baseline drift |
| 5 | PARTIAL or CRITICAL, including unresolved appliance verification |

## Default one-command workflows

### Firewall

Use `templates/edgeconnect/firewall_rules.csv`:

```text
PYTHONPATH=src python3 -m edgeconnect_automation firewall deploy --csv rules.csv --resolved-csv reports/rules-resolved.csv --report reports/firewall-run.json --dry-run
PYTHONPATH=src python3 -m edgeconnect_automation firewall deploy --csv rules.csv --resolved-csv reports/rules-resolved.csv --report reports/firewall-run.json
```

The CSV requires source/destination segments and zones. Multi-value firewall criteria use `|`; port ranges use `-` and allow 0 through 65535. The unambiguous either-direction service-group column is `either_service_group`. Unknown headers, including URL criteria, fail validation. `rule_name` is local metadata; `description` becomes the API comment. Logging enabled with a blank level defaults to 2. Match-all rules require `broad_match_ack=true`.

Discovery reads all managed appliances from `/appliance`, paused state from `/pauseOrchestration`, reachability per appliance from `/reachability/gms`, and fresh effective policy from `/securityMaps?cached=false` for reachable targets. Built-in applications and groups are resolved with exact wildcard searches in addition to user-defined inventories. Global policy targets every managed appliance. Unreachable and paused targets warn and continue, but remain unverified and therefore produce PARTIAL after a write.

Exact local/global priority collisions invalidate that segment pair. Different local priorities receive no semantic analysis or warning. Zone IDs are unique per segment in the all-VRF mapping, so local priorities are checked by the effective source/destination zone-ID pair for both default and non-default segment pairs.

Validation is isolated by source/destination segment pair. A bad row, dependency, zone pair, priority or local collision invalidates that pair; independent eligible pairs continue. Missing priorities allocate from 20000 by 10 only for an empty pair or one containing solely an actual 65535 allow/deny catch-all. Explicit priorities reserve their values first. Identical normalized rules are no-ops; differing collisions fail. Always use the generated resolved CSV for reruns. See [Understanding the resolved firewall CSV](RESOLVED_FIREWALL_CSV.md) for the input/output distinction, reduced-plan behavior, examples, and troubleshooting.

Each candidate preserves the complete baseline. Exact normalized readback detects silently dropped fields. A runtime pair failure removes only rules created by that run, verifies the exact baseline, and continues other pairs even when recovery remains unresolved. Audit reads always include `startTime` and `endTime`; audit evidence supports but does not replace saved/effective readback.

### Zones

```text
PYTHONPATH=src python3 -m edgeconnect_automation zones create --name POS --name RX --report reports/zones-run.json --dry-run
PYTHONPATH=src python3 -m edgeconnect_automation zones create --name POS --name RX --report reports/zones-run.json
```

`POST /zones` replaces the collection. The workflow preserves the full base collection, all-VRF state and segment mappings; allocates from `/zones/nextId`; uses `deleteDependencies=false`; and verifies complete readback. It never enables segmentation, deletes zones, renames zones, or performs automatic zone rollback.

### Native address and service groups

Use the exact GUI-native templates:

- `templates/edgeconnect/address_groups.csv`
- `templates/edgeconnect/service_groups.csv`

```text
PYTHONPATH=src python3 -m edgeconnect_automation address-groups deploy --csv address_groups.csv --report reports/address-run.json --dry-run
PYTHONPATH=src python3 -m edgeconnect_automation service-groups deploy --csv service_groups.csv --report reports/service-run.json --dry-run
```

List cells are comma-separated and CSV-quoted. Repeated rows with the same `Name` are preserved in input order and become multiple native rules in one group. References, cycles, existing identities and maximum nesting depth 2 are prevalidated. Address members support the documented IPv4 address, CIDR, dotted-mask, short-range, ranged-octet and wildcard-octet forms. IPv6 address members are rejected locally because the tested 9.7.1 native importer rejects them. Service protocols are TCP, UDP, ICMP and ICMPV6; native ports allow 0 through 65535.

Uploads use `multipart/form-data` with file field `csvFile`. The tool parses the native `BulkUploadResponse`. Native imports are all-or-nothing: a runtime importer rejection, including release-specific ICMPV6 validation, reports PARTIAL with no claimed creations. Only rows for entirely new groups are uploaded, followed by full semantic readback verification. The endpoint-implied group type is server-managed metadata because Orchestrator 9.7.1 may return `type: null`; verification accepts null or the expected type while rejecting an explicit wrong type and still comparing the complete rule body.

### Application groups

Use `templates/edgeconnect/application_groups.csv` with exact headers `Name,Applications,ParentGroups`. Applications and parent groups are comma-separated; `parentGroup` is serialized as an array or `null`.

```text
PYTHONPATH=src python3 -m edgeconnect_automation app-groups deploy --csv application_groups.csv --report reports/app-groups-run.json --dry-run
```

Application membership is resolved through user-defined inventories plus exact built-in wildcard searches. Parent references and cycles are validated. Missing applications or parents, conflicting existing semantics, duplicate/invalid names, and cycle members are listed under `skipped_conflicts`; groups depending on a skipped parent are skipped transitively. Independent groups may proceed after the normal `APPLY` approval, while any skips produce PARTIAL/exit 5. The complete existing collection and insertion semantics are preserved. POST does not add `resourceKey`.

### Application definitions

Use `templates/edgeconnect/application_definitions.csv`, which includes `IP_PROTOCOL`, `TCP_PORT`, `UDP_PORT`, `DOMAIN` and `COMPOUND` examples:

```text
PYTHONPATH=src python3 -m edgeconnect_automation app-definitions deploy --csv application_definitions.csv --report reports/app-definitions-run.json --dry-run
```

Inventory uses root GET `/applicationDefinition` with exact bases `portProtocolClassification`, `dnsClassification` and `compoundClassification`. Writes use the corresponding classifier endpoints with `port`/`protocol`, `domain`, or `id` query identity. Confidence is 1 through 100. Compound bodies use `confidence`, enforce directional-versus-either exclusivity, require at least two meaningful attributes, and limit criterion text to 512 characters. Compound DNS selectors are direct strings.

Compound name plus semantic body is the stable identity; numeric ID is not. Immediately before each compound POST, the tool fingerprints fresh inventory and allocates `max(existing user ID below 50000)+1`. Orchestrator can compact and renumber all compound IDs after deletion, so readback ignores ID while requiring unique name and exact semantic body. Exact-match CSV deletion resolves the current compound ID immediately before each delete and verifies absence afterward.

Preexisting semantic conflicts are isolated by CSV row: each appears under `skipped_conflicts` with row, name, type, identity and reason. Conflicting rows and their AppExpress intent are excluded, while independent definitions remain eligible for the normal `APPLY` approval. The completed command returns PARTIAL exit code 5 whenever any row was skipped; later application-group or firewall workflows still block references to a skipped name. Eligible creates are sequential. A runtime failure stops later creates, reports PARTIAL, and never deletes successful definitions. After all eligible definitions verify, the same workflow applies each eligible row's `AppExpressMode`: `MONITOR` ensures a Monitor entry exists and `OFF` ensures the named application has no AppExpress entry. Definition and AppExpress changes appear in one preview and use one approval. AppExpress is not attempted when eligible definition creation fails.

### AppExpress monitor

The standalone workflow remains available for changing Monitor mode on applications that are not managed by an application-definition CSV:

```text
PYTHONPATH=src python3 -m edgeconnect_automation appexpress deploy --csv templates/edgeconnect/appexpress_monitor.csv --report reports/appexpress-run.json --dry-run
```

The endpoint is `/applicationDefinition/appExpressAppConfig`. Existing unrelated entries and mapping order are preserved. Orchestrator may reassign numeric IDs according to collection order, so verification compares names and semantic configuration while ignoring server-managed IDs. If the collection drifts after approval, the combined application-definition run reports PARTIAL and does not overwrite the changed collection.

## CSV-driven delete commands

Each resource workflow provides a `delete` subcommand accepting the same `--csv`, `--report`, and `--dry-run` shape as deploy. Dry-run performs discovery, exact semantic comparison, dependency checks available to that workflow, and a complete deletion-table preview with zero Orchestrator writes. Apply mode has no prefix restriction and therefore can delete production-named objects when they exactly match the CSV.

Every apply requires three stages: review the complete untruncated deletion table, type a fresh random `DELETE-...` code, and type `I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION`. Non-interactive deletion is refused. After confirmation, collection fingerprints and individual object semantics are checked again. Missing objects are no-ops; semantic mismatches and detected external references block the entire command; incomplete readback returns nonzero PARTIAL.

Use dependency order across commands: firewall rules, application groups, AppExpress/application definitions, service groups, then address groups. `app-definitions delete` handles matching MONITOR entries before deleting definitions and blocks definitions referenced by application groups. Compound IDs are resolved from the current unique name and semantic body immediately before each delete.

## Advanced read-only and plan-file commands

`firewall validate`, `firewall plan`, object `plan`, and `firewall verify` remain available for diagnostics and offline contract tests. Advanced `apply --approved-plan` commands still show the exact preview and require TTY `APPLY`; they do not bypass drift checks. The default operator procedure is the one-command `deploy` or `zones create` workflow.

## Remaining release validation

Before production use, validate the exact target release for global policy options, non-default multi-segment appliance representation, multi-appliance convergence timing, new-zone propagation, paused/unreachable behavior, native ICMPV6 importer behavior, classifier writes and AppExpress collection writes. Never claim HTTP acceptance alone as convergence, and never treat this local test suite as integration testing.
