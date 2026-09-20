# Quick Start

## 1. Install

```bash
git clone https://github.com/Crypto-Gi/edgeconnect-orchestrator-automation.git
cd edgeconnect-orchestrator-automation
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools
python -m pip install -e .
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
```

## 2. Configure

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env`:

```dotenv
orchestrator_base_url=https://<ORCHESTRATOR_FQDN>
orchestrator_api_key=<ORCHESTRATOR_API_KEY>
# orchestrator_ca_bundle=/absolute/path/to/ca-bundle.pem
```

Never commit `.env`. Commands run from this directory load `./.env` automatically. Use `--dotenv /absolute/path/to/other.env` only when selecting a different file; no parent or home-directory search occurs.

## 3. Test

```bash
python -m unittest discover -v
edgeconnect-auto --help
```

## 4. Read-only discovery

```bash
edgeconnect-auto discovery \
  --output reports/discovery.json
```

## 5. Firewall dry-run

Copy and edit:

```text
templates/edgeconnect/firewall_rules.csv
```

Then run:

```bash
edgeconnect-auto firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_preview.json \
  --dry-run
```

Review all segment-pair errors, dependencies, priorities, targets, and the candidate payload. If the input contains blank priorities, retain the generated resolved CSV and use it as the input for deployment and future reruns. See [Understanding the resolved firewall CSV](docs/RESOLVED_FIREWALL_CSV.md).

## 6. Apply

```bash
edgeconnect-auto firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_result.json
```

Type uppercase `APPLY` only after reviewing the complete preview.

## Other workflows

```bash
edgeconnect-auto address-groups deploy --csv address_groups.csv --dry-run
edgeconnect-auto service-groups deploy --csv service_groups.csv --dry-run
edgeconnect-auto app-definitions deploy --csv application_definitions.csv --dry-run
edgeconnect-auto app-groups deploy --csv application_groups.csv --dry-run
edgeconnect-auto appexpress deploy --csv appexpress_monitor.csv --dry-run
```

Start every workflow with `--dry-run`. See [README.md](README.md) and [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) for full details.
