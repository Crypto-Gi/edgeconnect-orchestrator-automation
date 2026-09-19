# EdgeConnect Automation

Safety-focused, CSV-driven automation for HPE Aruba Networking EdgeConnect Orchestrator.

The tool implements:

- Central/global Routing Segmentation firewall policies
- Firewall dependency inventory and prechecks
- Missing-zone creation with explicit confirmation
- Native address-group and service-group CSV imports
- Application groups and parent relationships
- IP protocol, TCP port, UDP port, domain, and compound application definitions
- AppExpress Monitor configuration
- Dry-run, drift checks, exact readback, appliance verification, audit correlation, and segment-pair rollback

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
- Existing rules and objects are preserved
- Missing dependencies invalidate the affected segment pair
- Exact local/global priority collisions invalidate the segment pair
- Dropped or changed API fields fail normalized readback verification
- Failed segment-pair writes attempt baseline restoration and continue independent pairs
- Unreachable targets are reported as unverified and produce a nonzero PARTIAL result
- Secrets are redacted from reports and logs

Read [SECURITY.md](SECURITY.md) before using the tool.

## Supported scope

- Orchestrator 9.3 or later, with runtime capability checks
- ECOS 9.5 or later as the current target
- Centrally managed Routing Segmentation Global Firewall Policies
- Python 3.9 or later

The isolated contract-test environment used Orchestrator 9.7.1.42046 and one reachable ECOS 9.5.4.1 appliance. This is not production certification for every release or topology.

Not supported in phase one:

- Firewall templates
- Automatic routing-segmentation enablement
- Appliance-local rule modification
- Existing-object updates/deletes
- URL firewall matching
- AppExpress steering
- Compound application deletion

## Repository layout

```text
edgeconnect-automation/
├── src/edgeconnect_automation/   Python package
├── tests/                        Unit, contract, and safety tests
├── templates/                    CSV templates
├── docs/                         Detailed operator and design guides
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
edgeconnect-auto --dotenv .env discovery \
  --output reports/discovery.json
```

Review:

- Orchestrator release
- Routing Segmentation state
- Segments and zones
- Address and service groups
- Appliance reachability

### 3. Validate a firewall CSV locally

```bash
edgeconnect-auto firewall validate \
  --csv templates/edgeconnect/firewall_rules.csv
```

### 4. Perform an authenticated dry-run

```bash
edgeconnect-auto --dotenv .env firewall deploy \
  --csv rules.csv \
  --resolved-csv reports/rules-resolved.csv \
  --report reports/firewall-dry-run.json \
  --dry-run
```

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
edgeconnect-auto --dotenv .env firewall deploy \
  --csv rules.csv \
  --resolved-csv reports/rules-resolved.csv \
  --report reports/firewall-run.json
```

When prompted, type:

```text
APPLY
```

Use the generated resolved CSV for every future rerun when the original CSV omitted priorities.

## Common workflows

### Firewall rules

Template:

```text
templates/edgeconnect/firewall_rules.csv
```

Dry-run:

```bash
edgeconnect-auto --dotenv .env firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_preview.json \
  --dry-run
```

Apply:

```bash
edgeconnect-auto --dotenv .env firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_result.json
```

The tool evaluates each source/destination segment pair independently. Invalid pairs are excluded; valid pairs may proceed. Individual invalid rules are never skipped inside a submitted pair.

### Missing zones

Firewall deployment detects missing zones. A missing base zone requires:

1. Individual `CREATE <zone>` confirmation
2. Final `APPLY` confirmation
3. Full zone-collection preservation and drift check
4. Zone readback verification
5. A complete firewall rerun

Zones can also be created directly:

```bash
edgeconnect-auto --dotenv .env zones create \
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
edgeconnect-auto --dotenv .env address-groups deploy \
  --csv address_groups.csv \
  --report reports/address-groups.json \
  --dry-run
```

The file uses Orchestrator’s native GUI CSV format. List cells are comma-separated and quoted. Repeated group names create multiple rules.

### Service groups

Template:

```text
templates/edgeconnect/service_groups.csv
```

```bash
edgeconnect-auto --dotenv .env service-groups deploy \
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
edgeconnect-auto --dotenv .env app-definitions deploy \
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

Compound definitions support directional/either port, IP/subnet, geo, domain, address map, DSCP, protocol, and interface selectors. Compound numeric IDs are server ordering indices and are not treated as stable identities.

### Application groups

Template:

```text
templates/edgeconnect/application_groups.csv
```

```bash
edgeconnect-auto --dotenv .env app-groups deploy \
  --csv application_groups.csv \
  --report reports/application-groups.json \
  --dry-run
```

The workflow validates application membership, parent references, and cycles while preserving the complete existing collection.

### AppExpress Monitor

Template:

```text
templates/edgeconnect/appexpress_monitor.csv
```

```bash
edgeconnect-auto --dotenv .env appexpress deploy \
  --csv appexpress_monitor.csv \
  --report reports/appexpress.json \
  --dry-run
```

AppExpress Monitor is separate from application-definition creation. Off means no AppExpress entry. Steering is not supported in phase one.

## Verbose output

```bash
edgeconnect-auto -v --dotenv .env discovery
edgeconnect-auto -vv --dotenv .env firewall deploy --csv rules.csv --dry-run
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

## Comprehensive lab test suite

A deterministic test suite with valid and intentionally invalid CSVs is available under:

```text
examples/comprehensive_lab/
```

It includes 25 address groups, 25 service groups, 50 application definitions, application groups, AppExpress Monitor inputs, 57 firewall rules, expected-failure documentation, a generator, and a prefix-guarded cleanup script.

See [examples/comprehensive_lab/README.md](examples/comprehensive_lab/README.md). Use it only in an isolated lab and always begin with dry-run.

## Testing and development

```bash
PYTHONPATH=src python3 -m unittest discover -v
PYTHONPATH=src python3 -m compileall -q src tests
```

The default tests use fake transports and make no network calls.

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

Pass the dotenv explicitly:

```bash
edgeconnect-auto --dotenv .env discovery
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

## Additional documentation

- [Quick start](QUICKSTART.md)
- [Installation and migration](docs/INSTALLATION.md)
- [Operator guide](docs/OPERATOR_GUIDE.md)
- [CSV reference](docs/CSV_REFERENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Implementation requirements](docs/IMPLEMENTATION_REQUIREMENTS.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

Licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).
