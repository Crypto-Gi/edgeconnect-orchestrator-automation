# Workflows

First-use procedure, every workflow with its template and commands, CSV-driven deletion and verbose output. Moved from the README.

## First-use procedure

### 1. Run the test suite

From a clone install (a `setup.sh` install can skip this step):

```bash
python -m unittest discover -v
```

### 2. Perform read-only discovery

```bash
edgeconnect-auto discovery \
  --output reports/discovery.json
```

Expected result:

- Exit code `0`
- No Orchestrator write
- Orchestrator release, Routing Segmentation state, segments, zones, the segment-zone map, address groups, service groups, and an inventory fingerprint (appliance reachability is read later, by each workflow's own discovery)

### 3. Copy, edit, and validate a firewall CSV

```bash
cp templates/edgeconnect/firewall_rules.csv rules.csv
```

Edit `rules.csv` with the intended segments, zones, addresses, dependencies, actions, logging, and explicit priorities where required. Then validate it locally:

```bash
edgeconnect-auto firewall validate \
  --csv rules.csv
```

Expected result for a valid file:

```text
status: valid
exit code: 0
```

### 4. Perform an authenticated dry-run

```bash
edgeconnect-auto firewall deploy \
  --csv rules.csv \
  --resolved-csv reports/rules-resolved.csv \
  --report reports/firewall-dry-run.json \
  --dry-run
```

Expected result for an eligible plan:

- Exit code `0`
- No Orchestrator write
- A RUN SUMMARY with the planned changes per segment pair and one line per CSV row (`WOULD CREATE`, `ALREADY PRESENT`, `BLOCKED` and so on); the complete baseline and candidate are in the report file and the report log, and `-v` prints them
- Eligible segment pairs and final rule priorities
- Warnings for paused or unreachable appliances
- A JSON dry-run report; a resolved CSV is also written when eligible rows exist

### 5. Review the complete preview

Check:

- Segment-pair eligibility
- Missing dependencies
- Existing policies
- Global and local priority collisions
- Generated priorities
- Unreachable or paused appliances
- Candidate payload
- Baseline fingerprint
- Expected verification and rollback

### 6. Deploy

```bash
edgeconnect-auto firewall deploy \
  --csv reports/rules-resolved.csv \
  --report reports/firewall-run.json
```

When prompted, type:

```text
APPLY
```

Use the generated resolved CSV for every future rerun when the original CSV omitted priorities. See [Understanding the resolved firewall CSV](RESOLVED_FIREWALL_CSV.md) for a beginner-friendly explanation, examples, rerun workflow, and troubleshooting.

## Common workflows

Unless a section states otherwise, a successful `--dry-run` exits `0`, performs no Orchestrator write, and ends with a RUN SUMMARY of the planned changes; the exact candidate is in the report log (and `--report` file) and `-v` prints it. A real write requires interactive `APPLY`; a later exact rerun should be a verified no-op. Exit `5` means the result is intentionally incomplete and requires review, even when eligible changes succeeded.

### Firewall rules

Template:

```text
templates/edgeconnect/firewall_rules.csv
```

Dry-run:

```bash
edgeconnect-auto firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_preview.json \
  --dry-run
```

Apply:

```bash
edgeconnect-auto firewall deploy \
  --csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_result.json
```

The tool evaluates each source/destination segment pair independently. Invalid pairs are excluded; valid pairs may proceed. Individual invalid rules are never skipped inside a submitted pair.

#### Match-all safety: `broad_match_ack`

A rule matches all traffic in its source/destination segment and zone-pair scope when every traffic match field is blank. `broad_match_ack` does not change that behavior; it is a local safety acknowledgment proving the empty criteria were intentional.

| Match fields | `broad_match_ack` | Result |
|---|---|---|
| All blank | `TRUE` | Accepted as an intentional match-all rule |
| All blank | `FALSE` or blank | Local validation fails; nothing is deployed |
| One or more criteria present | `TRUE`, `FALSE`, or blank | Accepted; the supplied criteria determine the match |

For example, an intentional final catch-all deny uses blank match fields and:

```csv
action,broad_match_ack
deny,TRUE
```

With blank match fields, `FALSE` never means “match nothing.” It blocks the CSV during local validation. If the rule reached Orchestrator, an empty API `match` object would still mean “match everything.” The acknowledgment is not sent to Orchestrator, does not appear as a stored GUI property, and does not bypass dependency, priority, drift, approval, or verification checks. Disabled match-all rules also require `TRUE` because they could later be enabled. See [CSV reference](CSV_REFERENCE.md#broad-match-acknowledgment) for the complete field list and examples.

#### ACL firewall references

Set `acl` to one exact centrally defined ACL name and leave every ordinary traffic-match field blank. ACL mode is exclusive: mixing an ACL with addresses, groups, applications, protocol, ports, or service groups fails local validation. The central ACL must be nonempty and selected in an Access Lists template.

An unassociated source template is reported, but every reachable target must already contain an exact matching ACL body; a missing or mismatched ACL blocks the segment pair. Unreachable/paused targets still warn and produce PARTIAL because their state cannot be proven. Live 9.7.1 testing showed that one missing ACL makes Orchestrator reject the complete appliance security-map update, not only the ACL-referencing rule. Exact global and reachable-appliance readback must preserve the nonempty ACL name and matching ACL body. The firewall CSV does not require `broad_match_ack=TRUE` based on the ACL's internal rules. See [ACL match mode](CSV_REFERENCE.md#acl-match-mode).

### Template-group ACL creation and merge

Use `templates/edgeconnect/template_acls.csv` with `template-acls deploy`. Existing groups and ACLs are merged by priority: matching priorities replace the complete rule, new priorities are added, and omitted priorities remain unchanged. Supported match criteria are application, application group, directional/either IP, address group, port, service group and domain, per-side segment (entered by name, resolved to its ID at runtime), and protocol, matching the firewall CSV's match fields. Group encodings copy what the Orchestrator GUI writes, verified against GUI-created rules on 9.7.1. Separate several groups with `|`, never with a comma. Phase one accepts only `MERGE`; `REPLACE` is rejected. A target group with the Security Policies template selected in replace mode is blocked (no rules) or warned (with rules), because associating it replaces the appliance firewall policy.

```bash
edgeconnect-auto template-acls deploy --csv template_acls.csv --report reports/template-acls.json --dry-run
edgeconnect-auto template-acls deploy --csv template_acls.csv --report reports/template-acls.json
```

A missing group requires typing its exact name and then `APPLY`. Existing groups additionally require explicit confirmation before selecting Access Lists or changing native template mode to merge. New groups are never associated with appliances automatically.

Strict deletion removes a complete ACL only when every live entry exactly matches the complete CSV definition. It preserves the template group, selection, associations, unrelated ACLs and unrelated templates. It blocks firewall, template, appliance route-map and unreachable-target references, requires the standard deletion code and abyss acknowledgment, removes the exact central ACL plus exact copies from associated appliances through documented passthrough, and verifies absence. This appliance step is required because native template merge does not remove an omitted ACL.

```bash
edgeconnect-auto template-acls delete --csv template_acls.csv --dry-run
edgeconnect-auto template-acls delete --csv template_acls.csv
```

See [Template-group ACL CSV](CSV_REFERENCE.md#template-group-acls).

### Missing zones

Firewall deployment detects missing zones. A missing base zone requires:

1. Individual `CREATE <zone>` confirmation
2. Final `APPLY` confirmation
3. Full zone-collection preservation and drift check
4. Zone readback verification
5. A complete firewall rerun

After the zones are created the command exits `2` with RESULT `ZONES_CREATED_RERUN` and writes no firewall rule; run the same firewall command again. A zone that already exists but is not mapped to the row's segment is not created again: the run stops with `BLOCKED_SEGMENT_MAPPING` (exit `2`), and the mapping must be fixed in Orchestrator. Zones are offered only when the CSV has no validation errors.

Zones can also be created directly:

```bash
edgeconnect-auto zones create \
  --name POS \
  --name RX \
  --report reports/zones.json \
  --dry-run
```

### Address groups

Template:

```text
templates/edgeconnect/address_groups.csv
```

```bash
edgeconnect-auto address-groups deploy \
  --csv address_groups.csv \
  --report reports/address-groups.json \
  --dry-run
```

The file uses Orchestrator’s native GUI CSV format. List cells are comma-separated and quoted. Repeated group names create multiple rules. Address members support documented IPv4 addresses, CIDR or dotted-decimal masks, short octet ranges, ranged octets with masks, and wildcard octets with optional masks. IPv6 is rejected locally because the tested Orchestrator 9.7.1 native address-group importer rejects it.

### Service groups

Template:

```text
templates/edgeconnect/service_groups.csv
```

```bash
edgeconnect-auto service-groups deploy \
  --csv service_groups.csv \
  --report reports/service-groups.json \
  --dry-run
```

Supported local validation includes TCP, UDP, ICMP, and ICMPv6. The native 9.7.1 importer rejected the tested ICMPv6 type/code payload; runtime failures are reported rather than treated as success.

### Application definitions

Template:

```text
templates/edgeconnect/application_definitions.csv
```

```bash
edgeconnect-auto app-definitions deploy \
  --csv application_definitions.csv \
  --report reports/application-definitions.json \
  --dry-run
```

Supported types:

- `IP_PROTOCOL`
- `TCP_PORT`
- `UDP_PORT`
- `DOMAIN`
- `COMPOUND`

Defaults:

- Enabled
- Confidence 100
- AppExpress Off

`AppExpressMode` is authoritative in the application-definition CSV. `MONITOR` ensures a Monitor entry exists, while `OFF` removes an existing AppExpress entry for that named application. Both definition and AppExpress changes are shown in one preview and applied after one approval. Rows whose classifier identity conflicts with an existing different definition are shown under `skipped_conflicts`; they and their AppExpress intent are excluded while independent definitions may proceed. Any skipped conflict makes the command return partial exit code `5` even when all eligible rows verify.

Compound definitions support directional/either port, IP/subnet, geo, domain, address map, DSCP, protocol, and interface selectors. Geo accepts ISO codes or country names, interface accepts label names or IDs, and address maps must exist; all are resolved against live inventory during planning. Compound numeric IDs are server ordering indices and are not treated as stable identities.

Every CSV row is validated completely, and each problem is reported with a rule ID, field, value, suggested fix, and blocked scope. See [CSV constraints and dependencies](CSV_CONSTRAINTS_AND_DEPENDENCIES.md) for the full rule catalogue.

### Application groups

Template:

```text
templates/edgeconnect/application_groups.csv
```

```bash
edgeconnect-auto app-groups deploy \
  --csv application_groups.csv \
  --report reports/application-groups.json \
  --dry-run
```

The workflow validates application membership, parent references, and cycles while preserving the complete existing collection. A group with missing applications, missing parents, conflicting existing semantics, a parent cycle, or invalid identity is listed under `skipped_conflicts`; groups that depend on a skipped parent are also skipped. Independent groups may proceed after `APPLY`, and any skips produce partial exit code `5`.

## CSV-driven deletion

Every configurable resource workflow supports `delete` with the same CSV used for deployment:

```bash
edgeconnect-auto firewall delete --csv firewall_rules.csv --report reports/firewall-delete.json --dry-run
edgeconnect-auto template-acls delete --csv template_acls.csv --report reports/template-acls-delete.json --dry-run
edgeconnect-auto address-groups delete --csv address_groups.csv --report reports/address-delete.json --dry-run
edgeconnect-auto service-groups delete --csv service_groups.csv --report reports/service-delete.json --dry-run
edgeconnect-auto app-groups delete --csv application_groups.csv --report reports/app-groups-delete.json --dry-run
edgeconnect-auto app-definitions delete --csv application_definitions.csv --report reports/app-definitions-delete.json --dry-run
```

Deletion has no implicit name-prefix restriction. A live resource must match the CSV semantics exactly; absent resources are no-ops, while mismatches, external references detected by the workflow, or baseline drift block deletion. Always begin with `--dry-run`. Without it, the CLI displays the complete deletion table, requires a fresh random code, then requires typing `I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION`. State is re-read after confirmation and absence is verified after deletion. Delete dependencies in this order when separate CSVs are involved: firewall rules, template ACLs, application groups, application definitions with their integrated AppExpress state, service groups, then address groups.

## Verbose output

```bash
edgeconnect-auto -v discovery
edgeconnect-auto -vv firewall deploy --csv rules.csv --dry-run
```

- Default: small results as JSON, a short change table before every `APPLY` prompt, and the [run summary](REPORTS_AND_TROUBLESHOOTING.md#run-summary-and-report-log) at the end. Large previews and plans are not printed; they are always saved in the report log.
- `-v`: also prints the full preview JSON, plus API method/path, status, and response size
- `-vv`: sanitized payload details, plus a Python traceback for unexpected runtime errors

`-v`, `--dotenv`, `--orchestrator`, `--allow-http`, and `--report-dir` are global options: place them **before** the workflow name. `edgeconnect-auto firewall validate --csv rules.csv -v` fails with `unrecognized arguments: -v`. Verbosity only affects Orchestrator API calls, so local-only `validate` output looks the same at every level.

Credentials and authorization headers are never logged.
