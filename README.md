# EdgeConnect Automation

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue) ![License Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue) ![Tested on Orchestrator 9.7.1 and ECOS 9.5.4](https://img.shields.io/badge/tested-Orchestrator%209.7.1%20%7C%20ECOS%209.5.4-informational) ![Runtime dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)

**Deploy HPE Aruba EdgeConnect firewall policy and application definitions from a CSV, with a dry run first, a typed `APPLY`, and a readback of every change.**

Orchestrator's GUI has no bulk path for global firewall policies or application definitions. This CLI turns a reviewed spreadsheet into guarded Orchestrator API workflows, and refuses anything that would silently overwrite live configuration. Every write is approval-gated, checked for drift, and verified through fresh readback.

Current release: `v1.2.5` (see [CHANGELOG.md](CHANGELOG.md)). Tested scope is stated under [Supported scope](#supported-scope).

## What a run looks like

Every command ends with a RUN SUMMARY, even when nothing was written. This one is a blocked dry run: the tool found a priority conflict, wrote nothing, and said how to fix it.

```text
==============================================================================
RUN SUMMARY
==============================================================================
Workflow     : firewall deploy
Run          : run-bd501d73af8d  at 2026-09-30T14:54:37-05:00  (3.3s)
Versions     : tool 1.2.5, Orchestrator 9.7.1.42046
CSV          : rules.csv (73 data rows, sha256 005f008e35f2...)
RESULT       : BLOCKED
Changes made : no
Exit code    : 2 = blocked by validation or planning; nothing was written

What was planned or done
  - segment pair Default -> Default: BLOCKED by 1 issue(s); none of its 73 rows will be written

Rows (73): 1 BLOCKED, 72 NOT ATTEMPTED
  ROW  OUTCOME        ITEM                 SCOPE / REASON
  2    BLOCKED        1 (priority 20000)   Default -> Default | INSIDE -> OUTSIDE | [FW-24] ... priority 20000 conflicts ...
  3    NOT ATTEMPTED  2 (priority 20005)   Default -> Default | INSIDE -> OUTSIDE | segment pair blocked by row 2
  ...

Why it stopped or what failed
  - row 2 [FW-24] rule_key 1 priority 20000 conflicts with a different existing rule in zone pair INSIDE -> OUTSIDE (existing: allow disabled, match acl=EXAMPLE-ACL; this row: allow disabled, match dst_ip=192.0.2.0/24, either_port=443, protocol=tcp); fix: use a free priority such as 20001, or remove the existing rule first

Warnings (do not block)
  - target 3.NE (branch-03) is unreachable and will remain unverified

Appliances
  - 0.NE (hub-01): reachable
  - 3.NE (branch-03): unreachable
Report       : reports/firewall.jsonl
Report       : reports/firewall.log

Next step    : Fix every blocking issue listed above, then rerun the same command with --dry-run.
==============================================================================
```

## Why not click it in the GUI or script the API?

| Risk | What this tool does |
|---|---|
| A bad rule among hundreds is discovered after it is live | `validate` checks every row locally; one bad row blocks its whole segment pair and the report names the row, rule ID and fix |
| A script silently replaces an existing rule or object | Deploy workflows preserve what exists; a conflicting rule is never overwritten |
| Configuration changes between preview and write | Baselines are fingerprinted and re-read before the write; drift stops the run |
| The API returns success but drops a field | Normalized readback fails the pair and triggers baseline restoration |
| Orchestrator accepts a rule that the appliance refuses to compile | Appliance alarms are read after every write and the rejected row is reported as `FAILED` |
| A deletion matches more than you meant | Deletion is exact-match only, with a fresh random code and a typed acknowledgment |

## Quick start

```bash
git clone https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation.git edgeconnect-automation
cd edgeconnect-automation
python3 -m venv .venv && source .venv/bin/activate && python -m pip install -e .
cp .env.example .env && chmod 600 .env     # then set orchestrator_base_url and orchestrator_api_key

cp templates/edgeconnect/firewall_rules.csv rules.csv                            # starter; edit it first
edgeconnect-auto discovery                                                       # read-only
edgeconnect-auto firewall validate --csv templates/edgeconnect/firewall_rules.csv  # local, no network
edgeconnect-auto firewall deploy --csv rules.csv --dry-run                       # preview, no write
```

Edit `rules.csv` for your segments, zones and addresses, and dry-run it before anything is applied. Windows, several Orchestrators in one `.env`, private CA bundles and self-signed certificates are in [Setup and configuration](docs/SETUP_AND_CONFIGURATION.md). The step-by-step first run is in [Workflows](docs/WORKFLOWS.md#first-use-procedure).

## Use it with an AI agent

`skills/managing-edgeconnect-firewall-and-objects/` is an agent skill. With it, an agent such as Claude Code turns a plain-language request or the policy table you already have ("let the POS network reach the payment gateway on 443", a spreadsheet of 200 inter-segment flows, a list of SaaS domains to monitor) into firewall or application definition CSV rows from `templates/edgeconnect/`, runs `discovery`, `firewall validate` and `--dry-run` previews until they are clean, and shows you the preview. It never writes: it gives you the exact command, you run it in your own terminal and type `APPLY`, and it then reads the result with `report summarize`.

Install it from a clone of this repository, since the skill uses the clone's templates and docs:

```bash
npx skills add https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation
# or, for Claude Code only:
cp -R skills/managing-edgeconnect-firewall-and-objects ~/.claude/skills/
```

## What it manages

- Central/global Routing Segmentation firewall policies, including inter-segment
- Firewall dependency inventory and prechecks
- Missing-zone creation with explicit confirmation
- Address groups and service groups (native CSV imports)
- Application definitions (IP protocol, TCP/UDP port, domain, compound) and application groups, with AppExpress OFF/MONITOR desired state
- Template-group ACL entries
- Strict exact-match CSV deletion for all of the above

Per-workflow commands, templates and rules are in [Workflows](docs/WORKFLOWS.md).

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

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success, verified no-op, or successful dry-run |
| 1 | Runtime/API failure |
| 2 | Validation failure or no eligible segment pair |
| 3 | Approval refused or non-interactive write attempted |
| 4 | Baseline drift |
| 5 | PARTIAL or CRITICAL result, including a run that stopped (drift, validation, refusal) after it had started writing |

Automation systems must treat code 5 as incomplete deployment requiring operator review.

Row outcomes, report files and troubleshooting are in [Reports and troubleshooting](docs/REPORTS_AND_TROUBLESHOOTING.md).

## CSV templates and examples

Use the six concise deployment starters under:

```text
templates/edgeconnect/
```

For broader testing, `examples/edgeconnect/` contains two CSVs per workflow: one valid file covering supported field families and important boundaries, and one intentionally mixed valid/invalid file, plus the `test3` template ACL pair. The mixed files must never be applied; use them only with validation or `--dry-run`. Validation rejects every mixed file as a whole. `app-groups deploy` is the exception: it skips invalid groups and the groups that depend on them, can still create the valid groups in the file, and ends PARTIAL (exit 5).

Both valid sets form the same dependency chain: address groups and service groups → application definitions → application groups → template ACLs → firewall rules. Copy valid files before editing. Replace zone names, the template-group name, interface label, and any Address Map names with values from your Orchestrator. Always start with `validate`, `plan`, or `--dry-run`.

Additional conflict, drift, merge, deletion, and release-regression cases remain generated inside the standard-library tests rather than being published as dozens of single-case CSV files.

## Testing and development

```bash
PYTHONPATH=src python3 -m unittest discover -v
PYTHONPATH=src python3 -m compileall -q src tests scripts
```

The standard-library tests generate invalid and edge-case CSVs in temporary directories. The default suite uses fake transports and makes no network calls.

Live contract testing requires an isolated lab, an exact payload preview, an impact and rollback plan, explicit payload-specific approval, and verified cleanup. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Repository layout

```text
edgeconnect-automation/
├── src/edgeconnect_automation/   Python package
├── tests/                        Unit, contract, safety, and generated CSV cases
├── templates/edgeconnect/        Clean starter CSV templates
├── examples/edgeconnect/         Valid and intentionally invalid CSV examples
├── docs/                         Operator, CSV, architecture, and design guides
├── skills/                       Agent skill: plain-language requests to CSV rows and dry runs
├── pyproject.toml                Python packaging and CLI entry point
├── .env.example                  Safe configuration example
├── SECURITY.md                   Security requirements
├── CONTRIBUTING.md               Development workflow
└── CHANGELOG.md                  Release history
```

## Support

- Use [GitHub Issues](https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation/issues) for reproducible bugs, documentation problems, and feature requests.
- Include the command, sanitized output, Orchestrator release, and relevant non-secret CSV rows.
- Never post API keys, `.env`, authorization headers, customer configuration, production reports, or private topology.
- Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Documentation

- [Quick start](QUICKSTART.md)
- [Setup and configuration](docs/SETUP_AND_CONFIGURATION.md)
- [Workflows](docs/WORKFLOWS.md)
- [Reports and troubleshooting](docs/REPORTS_AND_TROUBLESHOOTING.md)
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

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
