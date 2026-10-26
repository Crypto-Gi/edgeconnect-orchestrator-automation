# EdgeConnect Automation Operator Guide

## Scope and safety

`edgeconnect-auto` is a Python 3.9+ standard-library-only tool for global routing-segmentation firewall policy, template-group ACLs, zones, native address/service groups, application groups, application definitions with integrated AppExpress desired state, and strict exact-match CSV deletion. It does not manage firewall templates, appliance-local rule modification, Routing Segmentation enablement, semantically different existing-object updates, or automatic dependency deletion.

The implementation is locally unit tested. API contracts were separately exercised in an isolated Orchestrator 9.7.1.42046 lab with one reachable ECOS 9.5.4.1 appliance: global policy create/readback/apply/rollback, native address/service imports, application definitions including compound, application groups, AppExpress monitor, audit correlation, and cleanup. This is not production certification or multi-appliance/multi-release validation. The global policy adapter uses the confirmed `merge=false` and `templateApply=false`; other releases require version-matched validation.

When `--dotenv` is omitted, commands load only `./.env` from the current working directory. The tool never searches parent or home directories. Process environment variables override file values; `--dotenv <PATH>` selects a different file. HTTPS certificate and hostname verification are enabled by default; configure a private CA bundle when required. Reports contain sensitive configuration, are redacted and fingerprinted, and are written with mode `0600`.

Every normal write command performs discovery, validation and preview in the same process, then:

1. Displays a short change table (counts, skipped or blocked items, warnings, impact and recovery). The sanitized exact candidate, target state and fingerprints are saved in the report log and printed with `-v`.
2. Refuses non-TTY execution.
3. Requires exact uppercase `APPLY` with no `--yes` bypass.
4. Re-reads the affected baseline and aborts on drift.
5. Verifies normalized saved-state readback.

Zone creation additionally requires `CREATE <zone>` for each new zone. `--dry-run` performs reads and preview only, makes no writes, requires no TTY, and returns success when validation succeeds (exit 5 when application groups or definitions skip rows).

## Installation and configuration

Run from the project root:

```text
PYTHONPATH=src python3 -m edgeconnect_automation --help
```

Supported runtime aliases include `orchestrator_base_url` / `ORCHESTRATOR_BASE_URL` / `EDGECONNECT_BASE_URL` / `EC_BASE_URL`, the matching API-key, CA-bundle (including `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE`, so a value left in your shell is used) and API-key-header aliases, and `ORCHESTRATOR_TLS_SHA256`. `.env.example` lists every key with its accepted values.

Several Orchestrators can share one `.env`: register each with `orch_<N>=<nickname>` and set `<nickname>_base_url`, `<nickname>_api_key`, and optionally `<nickname>_ca_bundle` / `<nickname>_api_key_header` / `<nickname>_tls_sha256`. `orchestrator_ca_bundle` and `orchestrator_api_key_header` are the default for nicknames without their own; `orchestrator_tls_sha256` is not: it pins only the `orchestrator` choice made from the single-Orchestrator lines, because a pin belongs to one host. Selection order: global `--orchestrator <nickname>`, then `orch_default` (a nickname or slot such as `orch_1`), then the only listed Orchestrator, then an interactive numbered menu. Non-interactive runs with several Orchestrators and no choice stop with a configuration error. Duplicate, reserved or invalid nicknames are rejected. The selected nickname and host are printed before every `APPLY` and deletion confirmation and in the RUN SUMMARY. When `orch_<N>` lines exist alongside the single-Orchestrator keys, those keys become one more choice with the nickname `orchestrator`. Plan and inventory files record their Orchestrator (`orchestrator: {name, url}`); `apply --approved-plan` and `firewall deploy --inventory` refuse them on any other Orchestrator before approval, naming only the Orchestrator the file belongs to. Never place credentials in command arguments, reports, templates or source files.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success, verified no-op, or valid dry-run preview |
| 1 | Runtime or API error; after `APPLY` the summary says `Changes made: unknown`, so check Orchestrator |
| 2 | Validation failure, no eligible firewall pair, configuration error (for example a missing `.env` value) or command-line usage error |
| 3 | Approval refusal or non-TTY write refusal |
| 4 | Baseline drift |
| 5 | PARTIAL or CRITICAL, including unresolved appliance verification, and any run that stopped (drift, validation, refusal) after it had started writing; exit codes 2, 3 and 4 always mean nothing was written |
| 130 | Interrupted by the operator (Ctrl+C) |

## Run summary and report log

Every workflow command, including failed and refused runs, ends with a RUN SUMMARY on standard error (`report summarize` prints the saved summary instead and adds nothing to the log): result, whether changes were made, exit-code meaning, counts, every blocking issue with its rule code and fix, warnings, appliance states with hostnames, and the next step. Each run is also appended to `reports/<workflow>.log` (summary text) and `reports/<workflow>.jsonl` (summary plus the complete preview and result) in the current directory. Use `--report-dir <folder>` or the process environment variable `EDGECONNECT_REPORT_DIR` (it is not read from `.env`) to relocate the log and `--report-dir ""` to disable it. An explicit `--report <file>` is written on every outcome, including refusal and errors, and contains the same `summary`. Every report file and log record carries the same top-level `status`, `exit_code`, `changes_written`, `timestamp`, `run_id`, `workflow`, `orchestrator` (nickname), `orchestrator_url` and `source` (`cli` or `gui`; `not recorded` in logs written before it existed). The summary includes a per-row table (`BLOCKED`, `NOT ATTEMPTED`, `CREATED`, `ALREADY PRESENT` and so on). `edgeconnect-auto report summarize <file> [--last N] [--rows-csv rows.csv]` prints the summary and row table of any saved report or log, including reports from earlier versions, without contacting Orchestrator. See [Reports and troubleshooting](REPORTS_AND_TROUBLESHOOTING.md#run-summary-and-report-log).

## Default one-command workflows

### Firewall

Use `templates/edgeconnect/firewall_rules.csv`:

```text
PYTHONPATH=src python3 -m edgeconnect_automation firewall deploy --csv rules.csv --resolved-csv reports/rules-resolved.csv --report reports/firewall-run.json --dry-run
PYTHONPATH=src python3 -m edgeconnect_automation firewall deploy --csv rules.csv --resolved-csv reports/rules-resolved.csv --report reports/firewall-run.json
```

The CSV requires source/destination segments and zones. Multi-value firewall criteria use `|`; port ranges use `-` and allow 0 through 65535. The unambiguous either-direction service-group column is `either_service_group`. Optional `source_domain`, `destination_domain`, and `either_domain` columns add domain criteria. Unknown headers, including URL criteria, fail validation. Every problem in a row is reported at once with its rule ID and suggested fix; see the [CSV reference](CSV_REFERENCE.md). `rule_name` is local metadata; `description` becomes the API comment. Logging enabled with a blank level defaults to 2.

A rule with every traffic match field blank produces API `match: {}` and matches all traffic in its segment/zone-pair scope. Such a row requires `broad_match_ack=TRUE`; `FALSE` or blank causes local validation failure and no write. The field is only an acknowledgment: it does not change match semantics, is not sent to Orchestrator, and is not a stored GUI option. Disabled match-all rules still require it. A populated criterion makes the acknowledgment optional, although operators must still review broad values such as `0.0.0.0/0` manually. See [CSV reference](CSV_REFERENCE.md#broad-match-acknowledgment).

A populated `acl` is an exclusive match mode and produces `match.acl` in the policy payload. Leave all ordinary match fields blank. The central ACL must be selected and nonempty; conflicting central definitions block the affected segment pair. An absent template association is reported, but a missing or mismatched ACL on a reachable target blocks submission for that segment pair. Live 9.7.1 testing proved that Orchestrator otherwise rejects the complete appliance security-map update. Unreachable/paused targets warn and remain PARTIAL. Global/effective readback must preserve the nonempty ACL, and reachable appliance ACL semantics are checked. ACL internal broadness does not require firewall `broad_match_ack`; firewall deletion never deletes the ACL. See [ACL match mode](CSV_REFERENCE.md#acl-match-mode).

Discovery reads all managed appliances from `/appliance`, paused state from `/pauseOrchestration`, reachability per appliance from `/reachability/gms`, fresh effective policy from `/securityMaps?cached=false`, central ACLs from `/template/templateGroups`, template associations from `/template/applianceAssociation`, and fresh ACL inventories from `/acls?cached=false` for reachable targets when ACL references are requested. Built-in applications and groups are resolved with exact wildcard searches in addition to user-defined inventories. Global policy targets every managed appliance. Unreachable and paused targets, and reachable appliances running ECOS below 9.5 (reported `unsupported`), warn and continue, but remain unverified and therefore produce PARTIAL after a write. After a write the tool polls each reachable appliance for up to 120 seconds per segment pair and then reads appliance alarms for up to 30 seconds, so a run with many pairs takes minutes.

Exact local/global priority collisions invalidate that segment pair. Different local priorities receive no semantic analysis or warning. Zone IDs are unique per segment in the all-VRF mapping, so local priorities are checked by the effective source/destination zone-ID pair for both default and non-default segment pairs.

Validation is isolated by source/destination segment pair. A bad row, dependency, zone pair, priority or local collision invalidates that pair; independent eligible pairs continue. Missing priorities allocate from 20000 by 10 only for an empty pair or one containing solely an actual 65535 allow/deny catch-all. Explicit priorities reserve their values first. Identical normalized rules are no-ops; differing collisions fail. Always use the generated resolved CSV for reruns. See [Understanding the resolved firewall CSV](RESOLVED_FIREWALL_CSV.md) for the input/output distinction, reduced-plan behavior, examples, and troubleshooting.

Each candidate preserves the complete baseline. Exact normalized readback detects silently dropped fields. A runtime pair failure removes only rules created by that run, verifies the exact baseline, and continues other pairs even when recovery remains unresolved. Audit reads always include `startTime` and `endTime`; audit evidence supports but does not replace saved/effective readback.

### Template-group ACLs

```text
PYTHONPATH=src python3 -m edgeconnect_automation template-acls deploy --csv template_acls.csv --report reports/template-acls.json --dry-run
PYTHONPATH=src python3 -m edgeconnect_automation template-acls deploy --csv template_acls.csv --report reports/template-acls.json
```

The template-group name in each row is the exact edit scope. Priority is rule identity: matching priorities replace the complete entry, new priorities are added, and omitted priorities remain. Rules support application, application group, protocol, and source/destination-or-either IP, port, and domain criteria. Only central and native `MERGE` modes are accepted. Missing groups require typing the exact proposed group name before final `APPLY`; selecting Access Lists or changing an existing template from replace to merge requires its own typed confirmation.

Updates send only the `acls` template while preserving its complete ACL collection, then verify central readback, selection, associations, unrelated templates, and associated reachable appliances. Template write endpoints require `Accept: text/plain`. New groups inherit the current default Access Lists template baseline, remain unassociated, and are verified centrally. Runtime failure is not automatically rolled back because native merge may leave appliance state behind; exact recovery requires a separate reviewed operation.

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

List cells are comma-separated and CSV-quoted. Repeated rows with the same `Name` are preserved in input order and become multiple native rules in one group. References, cycles, existing identities and maximum nesting depth 2 (including existing groups) are prevalidated. Group names are limited to 64 characters. Every rule needs an inclusion, and a value cannot be both included and excluded. Address members support the documented IPv4 address, CIDR, dotted-mask, short-range, ranged-octet and wildcard-octet forms. IPv6 address members are rejected locally because the tested 9.7.1 native importer rejects them. Service protocols are TCP, UDP, ICMP and ICMPV6; native ports allow 0 through 65535, and ICMP types accept ranges such as `4-8`. The plan and preview include non-blocking `warnings` for excluded ports outside the included range and for the documented 8 MB / 4 MB definition limits.

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

Inventory uses root GET `/applicationDefinition` with exact bases `portProtocolClassification`, `dnsClassification` and `compoundClassification`. Writes use the corresponding classifier endpoints with `port`/`protocol`, `domain`, or `id` query identity. Confidence is 1 through 100. Compound bodies use `confidence`, enforce directional-versus-either exclusivity, require at least two meaningful attributes, and limit criterion text to 512 characters. Compound DNS selectors are direct strings. Compound list values are sent comma-separated. Plan, deploy, and delete resolve geo names to ISO codes, interface-label names to label IDs, and address-map names against IP Intelligence inventory before any comparison or write; unresolved references block the CSV. Application names are compared case-insensitively, and a run that would monitor more than 50 AppExpress applications is refused.

Compound name plus semantic body is the stable identity; numeric ID is not. Immediately before each compound POST, the tool fingerprints fresh inventory and allocates `max(existing user ID below 50000)+1`. Orchestrator can compact and renumber all compound IDs after deletion, so readback ignores ID while requiring unique name and exact semantic body. Exact-match CSV deletion resolves the current compound ID immediately before each delete and verifies absence afterward.

Preexisting semantic conflicts are isolated by CSV row: each appears under `skipped_conflicts` with row, name, type, identity and reason. Conflicting rows and their AppExpress intent are excluded, while independent definitions remain eligible for the normal `APPLY` approval. The completed command returns PARTIAL exit code 5 whenever any row was skipped; later application-group or firewall workflows still block references to a skipped name. Eligible creates are sequential. A runtime failure stops later creates, reports PARTIAL, and never deletes successful definitions. After all eligible definitions verify, the same workflow applies each eligible row's `AppExpressMode`: `MONITOR` ensures a Monitor entry exists and `OFF` ensures the named application has no AppExpress entry. Definition and AppExpress changes appear in one preview and use one approval; whenever AppExpress would change, the text before `APPLY` names the entries, for example `AppExpress: remove 1 (Zoom), change 1 to monitor-only (Teams), add 1 (Webex)`. A blank `AppExpressMode` means `OFF`, which removes an existing entry, including a fully configured one. AppExpress is not attempted when eligible definition creation fails.

## CSV-driven delete commands

Each resource workflow provides a `delete` subcommand accepting the same `--csv`, `--report`, and `--dry-run` shape as deploy. Dry-run performs discovery, exact semantic comparison, dependency checks, and a complete deletion-table preview with zero Orchestrator writes. Dependency checks read every global firewall segment map and every central template ACL. A group or application that is still referenced there blocks deletion, and the error lists each referencing rule. Apply mode has no prefix restriction and therefore can delete production-named objects when they exactly match the CSV.

Every apply requires three stages: review the complete untruncated deletion table, type a fresh random `DELETE-...` code, and type `I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION`. Non-interactive deletion is refused. After confirmation, collection fingerprints and individual object semantics are checked again. Missing objects are no-ops; semantic mismatches and detected external references block the entire command; incomplete readback returns nonzero PARTIAL.

Use dependency order across commands: firewall rules, template ACLs, application groups, application definitions with integrated AppExpress cleanup, service groups, then address groups. `template-acls delete` requires the complete ACL in the CSV to match every live entry exactly; it preserves the group, selection, associations and unrelated configuration, blocks firewall/template/route-map/unreachable-target references, removes exact associated-appliance copies through passthrough, and verifies absence. Native template merge omission alone is never considered deletion. `app-definitions delete` handles matching MONITOR entries before deleting definitions and blocks definitions referenced by application groups. Compound IDs are resolved from the current unique name and semantic body immediately before each delete.

## Advanced read-only and plan-file commands

`firewall validate`, `firewall plan`, object `plan`, and `firewall verify` remain available for diagnostics and offline contract tests. Advanced `apply --approved-plan` commands still show the exact preview and require TTY `APPLY`; they do not bypass drift checks. The default operator procedure is the one-command `deploy` or `zones create` workflow.

Global options (`--dotenv`, `--orchestrator`, `--allow-http`, `-v`, `--report-dir`) go before the workflow name. Every option below comes from the command's own `--help`.

| Command | Options | Notes |
|---|---|---|
| `discovery` | `[--output FILE]` | Read-only: release, segmentation state, segments, zones, segment-zone map, address and service groups, fingerprint |
| `firewall validate` | `--csv FILE` | Local only; exit 0 valid, 2 invalid |
| `firewall plan` | `--csv FILE --output PLAN [--inventory JSON] [--resolved-csv FILE]` | Read-only, so `--dry-run` is refused (exit 2). With `--inventory` it does not contact Orchestrator. Exit 0, 2 (no eligible pair) or 5 (some pairs ineligible) |
| `firewall apply` | `--approved-plan PLAN [--report FILE] [--dry-run]` | Re-reads each baseline; drift stops that pair |
| `firewall deploy` | `--csv FILE [--resolved-csv FILE] [--report FILE] [--inventory JSON] [--dry-run]` | `--inventory` (contract-test format, not a `discovery --output` file) replaces live discovery only: the release is still read, and a real run still writes, re-reads and verifies live |
| `firewall delete` | `--csv FILE [--report FILE] [--dry-run]` | Explicit priority on every row |
| `firewall verify` | `--run-id REF [--output FILE]` | Searches the last 24 hours of Orchestrator audit actions for `REF` (the `Run ref` of the summary); exit 5 when nothing matches |
| `template-acls plan` / `apply` / `deploy` / `delete` | `plan --csv FILE --output PLAN`; `apply --approved-plan PLAN [--report FILE]`; `deploy` and `delete --csv FILE [--report FILE]`; all `[--dry-run]` | |
| `zones plan-missing` / `apply` / `create` | `plan-missing --name ZONE [--name ZONE ...] --output PLAN`; `apply --approved-plan PLAN`; `create --name ZONE [...] [--report FILE]`; all `[--dry-run]` | Zone names: letters, digits, `_`; `Default` is reserved |
| `address-groups`, `service-groups`, `app-definitions` `plan` / `apply` / `deploy` / `delete` | `plan --csv FILE --output PLAN`; `apply --approved-plan PLAN`; `deploy` and `delete --csv FILE [--report FILE]`; all `[--dry-run]` | `apply` has no `--report`; the report log still records it |
| `app-groups plan` / `apply` / `deploy` / `delete` | as above, plus `[--applications JSON]` on `plan` and `deploy` | `--applications` is an offline JSON list of complete application names used instead of the live lookup |
| `report summarize` | `FILE [--last N] [--rows-csv FILE]` | Files only; `--last 0` shows every run of a `.jsonl` log |

Plan files carry a `report_fingerprint` and the Orchestrator they were made for. An edited plan fails with `approved plan fingerprint does not match` (firewall: `approved firewall plan is invalid or changed`); rebuild it with `plan` instead of editing it.

## Experimental GUI

`edgeconnect-auto gui` starts a local web GUI. It is experimental and still being built: it shows Orchestrator status, the tasks of this session, the run log, the inventory, a guided task for each object type, Remove by CSV and a firewall CSV editor; revert comes next. Run it from the folder that holds your `.env`. It prints a sign-in link and opens your browser; on WSL it opens the Windows browser with `wslview`, or with `explorer.exe` if that is missing. Use `--no-browser` to print the link only, and `--port N` to pick the port (by default, any free port). Ctrl+C stops it.

- It listens on 127.0.0.1 only and answers only to `127.0.0.1`, `localhost` or `[::1]` on its own port, so a web page cannot reach it through another host name (DNS rebinding).
- The printed link is your sign-in. Its token becomes an HttpOnly, SameSite=Strict cookie that every page and API call needs. A request that changes something must also come from the GUI's own page (Origin check), and the server never sends CORS headers.
- API keys stay in the server process and never appear in a response.
- Writes (apply and delete) are off for every Orchestrator unless that nickname has `<nickname>_gui_writes=on` in `.env` (see `.env.example`). The GUI runs the same commands as the CLI. A write first builds the preview, then waits up to 10 minutes for the same typed confirmations the terminal asks for, and stops as `rejected` on a wrong answer or `expired` when no answer comes. On each Orchestrator only one write runs at a time; any others wait as `queued`.
- Every GUI run is logged to `reports/` like a CLI run, with `source` set to `gui`.
- **See what changed** lists every run in the report folder (CLI and GUI) with search, filters, a problems-only switch, sorting and paging; open a run for its summary and per-row table. Both tables export to CSV; the per-row CSV is the one `report summarize --rows-csv` writes. A damaged log line is counted and left out, not fatal.
- **Firewall rules** is a guided task: load a firewall CSV, fix what the check finds (row, column, rule code and the fix), plan it against the chosen Orchestrator, review the changes (deletes and warnings first, then counts, then every object with its field-level changes), approve, apply, and see each row's outcome after the read-back. The approval dialog shows the Orchestrator's label, colour, nickname and address, asks for the same confirmations as the terminal plus the Orchestrator's nickname typed exactly, and expires after 10 minutes. A wrong answer ends the task as `rejected`, no answer as `expired`; nothing is written in either case. The run log records who approved it: the OS user, the time, the fingerprint of the exact preview, the Orchestrator and every confirmation as typed (`approval` in the summary, and an `Approved by` line in `reports/<workflow>.log`).
- **Applications**, **Application groups**, **Address groups**, **Service groups**, **Template ACLs** and **Missing zones** follow the same steps and gates. These object types have no offline check, so their rows are checked while planning (still read-only); Missing zones takes zone names, one per line, instead of a CSV, and asks for `CREATE <zone>` for each zone it creates.
- **Remove by CSV** deletes exactly the objects a CSV names, for any object type above except zones. It reads Orchestrator and shows the complete deletion table first (warning 1 of 3), with nothing deleted yet. You then tick "I understand", type the deletion code (warning 2) and the acknowledgement sentence (warning 3), as in the terminal, plus the Orchestrator's nickname. The server checks the tick box too: without it the task ends as `rejected` and nothing is deleted.
- **Build a firewall CSV** is an editor. Start from a blank CSV, the template, an example or your own CSV, then add, copy, edit and remove rules a page at a time. Each rule opens in a form where segments, zones (only those mapped to the chosen segment), address groups and service groups are picked from the Orchestrator's inventory, and applications and application groups are found by search and picked, so no name is typed. A value the Orchestrator does not have stays as it was, marked "not on this Orchestrator". **Check rows** runs the same offline check as `firewall validate`, and **Check against** runs a read-only plan that reports missing names and conflicts; each problem has a button that opens its row. **Save CSV** downloads it (every column, in the template's order, plus any extra columns it was loaded with), and **Use in Firewall rules** takes it to the guided task. In Firewall rules, a CSV with problems has a **Fix in the editor** button. The editor never decides whether a row is valid; the checks do. Templates and examples are offered when the tool runs from its source folder, as `setup.sh` installs it.
- **Inventory** reads the segments, zones, zones per segment, address groups and service groups of the chosen Orchestrator (the same read-only discovery as `edgeconnect-auto discovery`) and shows each as a searchable, paged table.

## Remaining release validation

Before production use, validate the exact target release for global policy options, non-default multi-segment appliance representation, multi-appliance convergence timing, new-zone propagation, paused/unreachable behavior, native ICMPV6 importer behavior, classifier writes and AppExpress collection writes. Never claim HTTP acceptance alone as convergence, and never treat this local test suite as integration testing.
