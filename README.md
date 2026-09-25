# EdgeConnect Automation

Safety-focused, CSV-driven automation for HPE Aruba Networking EdgeConnect Orchestrator.

Preview, validate, deploy, verify, and remove firewall policies and supporting objects without silently overwriting existing configuration. Every write is approval-gated, checked for drift, and verified through fresh readback.

EdgeConnect Orchestrator is the central management system; this CLI turns reviewed CSV intent into guarded Orchestrator API workflows.

**Current release:** `v1.1.1` / package version `1.1.1` — stricter CSV validation, merge-only template ACL automation, safer firewall ACL dependency checks, and compact valid/invalid example sets.

The tool implements:

- Central/global Routing Segmentation firewall policies
- Firewall dependency inventory and prechecks
- Missing-zone creation with explicit confirmation
- Native address-group and service-group CSV imports
- Application groups and parent relationships
- IP protocol, TCP port, UDP port, domain, and compound application definitions
- Application-definition-driven AppExpress OFF/MONITOR desired state
- Strict exact-match CSV deletion workflows
- Dry-run, drift checks, exact readback, appliance verification, audit correlation, and segment-pair rollback

## Contents

- [Safety model](#safety-model)
- [Supported scope](#supported-scope)
- [Repository layout](#repository-layout)
- [Installation](#new-machine-installation)
- [First-use procedure](#first-use-procedure)
- [Common workflows](#common-workflows)
- [CSV-driven deletion](#csv-driven-deletion)
- [Exit codes](#exit-codes)
- [CSV templates and examples](#csv-templates-and-examples)
- [Testing and development](#testing-and-development)
- [Troubleshooting](#troubleshooting)
- [Support](#support)
- [Documentation](#additional-documentation)
- [License](#license)

## Safety model

The operating sequence is:

```text
Inventory → Validate → Preview → Type APPLY → Deploy → Read back → Verify
```

Key safeguards:

- No writes during `--dry-run`
- Every normal write requires typing uppercase `APPLY`
- Non-interactive writes are refused
- No `--yes` bypass
- Baselines are fingerprinted and re-read before writes
- Deploy workflows preserve existing rules and objects
- Delete workflows remove only exact CSV-matched resources after three-stage confirmation
- Missing dependencies invalidate the affected segment pair
- Exact local/global priority collisions invalidate the segment pair
- Dropped or changed API fields fail normalized readback verification
- Failed segment-pair writes attempt baseline restoration and continue independent pairs
- Unreachable targets are reported as unverified and produce a nonzero PARTIAL result
- Secrets are redacted from reports and logs

Read [SECURITY.md](SECURITY.md) before using the tool.

## Supported scope

- The CLI accepts Orchestrator 9.3 or later
- ECOS 9.5 or later is the current design target
- Centrally managed Routing Segmentation Global Firewall Policies
- Python 3.9 or later

Complete contract testing used Orchestrator 9.7.1.42046 and one reachable ECOS 9.5.4.1 appliance. Other release combinations and multi-appliance topologies require release-specific lab validation before production use; this repository is not blanket certification for every supported release.

Not supported:

- Firewall templates
- Automatic Routing Segmentation enablement
- Appliance-local rule modification
- Updating semantically different existing rules or objects
- URL firewall matching
- AppExpress steering
- Automatic dependency deletion

## Repository layout

```text
edgeconnect-automation/
├── src/edgeconnect_automation/   Python package
├── tests/                        Unit, contract, safety, and generated CSV cases
├── templates/edgeconnect/        Clean starter CSV templates
├── examples/edgeconnect/         Valid and intentionally invalid CSV examples
├── docs/                         Operator, CSV, architecture, and design guides
├── pyproject.toml                Python packaging and CLI entry point
├── .env.example                  Safe configuration example
├── SECURITY.md                   Security requirements
├── CONTRIBUTING.md               Development workflow
└── CHANGELOG.md                  Release history
```

## New-machine installation

### Prerequisites

Install:

1. Git
2. Python 3.9 or later
3. Network connectivity to the Orchestrator HTTPS API
4. An Orchestrator API key
5. The private CA certificate bundle if the Orchestrator certificate is not trusted by the operating system

No third-party runtime Python packages are required.

### macOS or Linux

```bash
git clone https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation.git edgeconnect-automation
cd edgeconnect-automation

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools
python -m pip install -e .

cp .env.example .env
chmod 600 .env
```

Edit `.env`:

```dotenv
orchestrator_base_url=https://<ORCHESTRATOR_FQDN>
orchestrator_api_key=<ORCHESTRATOR_API_KEY>
# orchestrator_ca_bundle=/absolute/path/to/ca-bundle.pem
```

When `--dotenv` is omitted, the CLI loads only `./.env` from the current working directory. It never searches parent or home directories. Process environment variables override values from the file. Use `--dotenv /absolute/path/to/other.env` to select a different file.

### Windows PowerShell

```powershell
git clone https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation.git edgeconnect-automation
Set-Location edgeconnect-automation

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip setuptools
python -m pip install -e .

Copy-Item .env.example .env
```

Restrict access to `.env` using your organization’s Windows file-permission policy, then replace the placeholders.

### Confirm installation

```bash
edgeconnect-auto --help
edgeconnect-auto firewall deploy --help
python -m unittest discover -v
```

If editable installation is not desired, run directly from the repository:

```bash
PYTHONPATH=src python3 -m edgeconnect_automation --help
```

## What to copy to another machine

Preferred method: copy or clone the **entire standalone repository**.

Required:

```text
src/
templates/
pyproject.toml
README.md
docs/
```

Recommended for validation and maintenance:

```text
tests/
SECURITY.md
CONTRIBUTING.md
CHANGELOG.md
```

Never copy or commit:

```text
.env
API keys
credentials
reports/
customer exports
production readbacks
cookies or tokens
```

Create a new `.env` securely on each machine.

## First-use procedure

### 1. Run the test suite

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
- Orchestrator release, Routing Segmentation state, segments, zones, address groups, service groups, appliance reachability, and an inventory fingerprint

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
- Complete baseline and candidate preview
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

Use the generated resolved CSV for every future rerun when the original CSV omitted priorities. See [Understanding the resolved firewall CSV](docs/RESOLVED_FIREWALL_CSV.md) for a beginner-friendly explanation, examples, rerun workflow, and troubleshooting.

## Common workflows

Unless a section states otherwise, a successful `--dry-run` exits `0`, performs no Orchestrator write, and prints the exact candidate. A real write requires interactive `APPLY`; a later exact rerun should be a verified no-op. Exit `5` means the result is intentionally incomplete and requires review, even when eligible changes succeeded.

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

With blank match fields, `FALSE` never means “match nothing.” It blocks the CSV during local validation. If the rule reached Orchestrator, an empty API `match` object would still mean “match everything.” The acknowledgment is not sent to Orchestrator, does not appear as a stored GUI property, and does not bypass dependency, priority, drift, approval, or verification checks. Disabled match-all rules also require `TRUE` because they could later be enabled. See [CSV reference](docs/CSV_REFERENCE.md#broad-match-acknowledgment) for the complete field list and examples.

#### ACL firewall references

Set `acl` to one exact centrally defined ACL name and leave every ordinary traffic-match field blank. ACL mode is exclusive: mixing an ACL with addresses, groups, applications, protocol, ports, or service groups fails local validation. The central ACL must be nonempty and selected in an Access Lists template.

An unassociated source template is reported, but every reachable target must already contain an exact matching ACL body; a missing or mismatched ACL blocks the segment pair. Unreachable/paused targets still warn and produce PARTIAL because their state cannot be proven. Live 9.7.1 testing showed that one missing ACL makes Orchestrator reject the complete appliance security-map update, not only the ACL-referencing rule. Exact global and reachable-appliance readback must preserve the nonempty ACL name and matching ACL body. The firewall CSV does not require `broad_match_ack=TRUE` based on the ACL's internal rules. See [ACL match mode](docs/CSV_REFERENCE.md#acl-match-mode).

### Template-group ACL creation and merge

Use `templates/edgeconnect/template_acls.csv` with `template-acls deploy`. Existing groups and ACLs are merged by priority: matching priorities replace the complete rule, new priorities are added, and omitted priorities remain unchanged. Supported match criteria are application, application group, directional/either IP, directional/either port, directional/either domain, and protocol. Phase one accepts only `MERGE`; `REPLACE` is rejected.

```bash
edgeconnect-auto template-acls deploy --csv template_acls.csv --report reports/template-acls.json --dry-run
edgeconnect-auto template-acls deploy --csv template_acls.csv --report reports/template-acls.json
```

A missing group requires typing its exact name and then `APPLY`. Existing groups additionally require explicit confirmation before selecting Access Lists or changing native template mode to merge. New groups are never associated with appliances automatically. See [Template-group ACL CSV](docs/CSV_REFERENCE.md#template-group-acls).

### Missing zones

Firewall deployment detects missing zones. A missing base zone requires:

1. Individual `CREATE <zone>` confirmation
2. Final `APPLY` confirmation
3. Full zone-collection preservation and drift check
4. Zone readback verification
5. A complete firewall rerun

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

Every CSV row is validated completely, and each problem is reported with a rule ID, field, value, suggested fix, and blocked scope. See [CSV constraints and dependencies](docs/CSV_CONSTRAINTS_AND_DEPENDENCIES.md) for the full rule catalogue.

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
edgeconnect-auto address-groups delete --csv address_groups.csv --report reports/address-delete.json --dry-run
edgeconnect-auto service-groups delete --csv service_groups.csv --report reports/service-delete.json --dry-run
edgeconnect-auto app-groups delete --csv application_groups.csv --report reports/app-groups-delete.json --dry-run
edgeconnect-auto app-definitions delete --csv application_definitions.csv --report reports/app-definitions-delete.json --dry-run
```

Deletion has no implicit name-prefix restriction. A live resource must match the CSV semantics exactly; absent resources are no-ops, while mismatches, external references detected by the workflow, or baseline drift block deletion. Always begin with `--dry-run`. Without it, the CLI displays the complete deletion table, requires a fresh random code, then requires typing `I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION`. State is re-read after confirmation and absence is verified after deletion. Delete dependencies in this order when separate CSVs are involved: firewall rules, application groups, application definitions with their integrated AppExpress state, service groups, then address groups.

## Verbose output

```bash
edgeconnect-auto -v discovery
edgeconnect-auto -vv firewall deploy --csv rules.csv --dry-run
```

- Default: plans, validation results, changes, and verification summary
- `-v`: API method/path, status, and response size
- `-vv`: sanitized payload details

Credentials and authorization headers are never logged.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success, verified no-op, or successful dry-run |
| 1 | Runtime/API failure |
| 2 | Validation failure or no eligible segment pair |
| 3 | Approval refused or non-interactive write attempted |
| 4 | Baseline drift |
| 5 | PARTIAL or CRITICAL result |

Automation systems must treat code 5 as incomplete deployment requiring operator review.

## Reports

Reports are:

- Redacted
- Fingerprinted
- Written with restrictive permissions
- Excluded from Git by default

They may still contain sensitive network configuration. Store and transfer them only through approved systems.

## CSV templates and examples

Use the six concise deployment starters under:

```text
templates/edgeconnect/
```

For broader testing, `examples/edgeconnect/` contains exactly two CSVs per workflow: one valid file covering supported field families and important boundaries, and one intentionally mixed valid/invalid file. The mixed files must fail validation and must never be applied.

Both valid sets form the same dependency chain: address groups and service groups → application definitions → application groups → template ACLs → firewall rules. Copy valid files before editing. Replace zone names, the template-group name, interface label, and any Address Map names with values from your Orchestrator. Always start with `validate`, `plan`, or `--dry-run`.

Additional conflict, drift, merge, deletion, and release-regression cases remain generated inside the standard-library tests rather than being published as dozens of single-case CSV files.

## Testing and development

```bash
PYTHONPATH=src python3 -m unittest discover -v
PYTHONPATH=src python3 -m compileall -q src tests scripts
```

The standard-library tests generate invalid and edge-case CSVs in temporary directories. The default suite uses fake transports and makes no network calls.

Live contract testing requires:

- Isolated lab
- Exact payload preview
- Impact and rollback plan
- Explicit payload-specific approval
- Verified cleanup

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Updating on an existing machine

```bash
git status
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -v
```

Review `CHANGELOG.md` before using a new version.

## Troubleshooting

### Configuration is missing

Run from the repository directory containing `.env`, provide process environment variables, or select another file explicitly:

```bash
edgeconnect-auto discovery
edgeconnect-auto --dotenv /absolute/path/to/other.env discovery
```

### Certificate verification fails

Do not disable TLS verification. Add the approved CA chain:

```dotenv
orchestrator_ca_bundle=/absolute/path/to/ca-bundle.pem
```

### Routing Segmentation is disabled

Firewall deployment stops. This tool does not enable Routing Segmentation automatically because enabling it affects the complete fabric.

### Missing zone

Review the proposed full zone collection, confirm each zone, apply the separate zone change, and rerun firewall validation.

### Priority conflict

- Add explicit priorities to the CSV, or
- Resolve the existing conflict outside the tool

The tool never overwrites a conflicting rule.

### Unreachable appliances

The global policy may be saved, but verification remains incomplete. The command exits PARTIAL and identifies unverified targets.

### API returns success but drops a field

Normalized readback fails and the affected segment pair enters recovery. Unsupported fields are not silently accepted.

## Support

- Use [GitHub Issues](https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation/issues) for reproducible bugs, documentation problems, and feature requests.
- Include the command, sanitized output, Orchestrator release, and relevant non-secret CSV rows.
- Never post API keys, `.env`, authorization headers, customer configuration, production reports, or private topology.
- Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Additional documentation

- [Quick start](QUICKSTART.md)
- [Installation and migration](docs/INSTALLATION.md)
- [Operator guide](docs/OPERATOR_GUIDE.md)
- [CSV reference](docs/CSV_REFERENCE.md)
- [Understanding the resolved firewall CSV](docs/RESOLVED_FIREWALL_CSV.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Implementation requirements](docs/IMPLEMENTATION_REQUIREMENTS.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

Licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).
