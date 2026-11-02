# Quick Start

## 1. Install

To install the toolkit in one step (macOS and Linux), run the setup script. It asks which repositories to install (this CLI, the `edgeconnect-preconfig` command, the edgeconnect-mcp server and its skills), which agents get the skills, the install folder (default: the folder you run it from) and where the skills go. It creates one shared `.env` in the install folder:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Crypto-Gi/edgeconnect-orchestrator-automation/main/setup.sh)
```

Or install this CLI only:

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

**After `setup.sh`:** edit `<install folder>/.env`. It already holds one Orchestrator under the nickname `lab`:

```dotenv
orch_1=lab
lab_base_url=https://<ORCHESTRATOR_FQDN_OR_IP>
lab_api_key=<API_KEY>
```

The `edgeconnect-auto` command that `setup.sh` installs always passes `--dotenv <install folder>/.env`, so it works from any folder. The same file also holds settings for `edgeconnect-preconfig` and the MCP server; this CLI ignores them.

**After a clone install:**

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

Never commit `.env`. Commands run from this directory load `./.env` automatically. Use `--dotenv /absolute/path/to/other.env` only when selecting a different file; no parent or home-directory search occurs. Several Orchestrators, private CAs and self-signed certificates are in [Setup and configuration](docs/SETUP_AND_CONFIGURATION.md).

## 3. Test

```bash
edgeconnect-auto --help
python -m unittest discover -v     # clone install only, from the clone folder
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

Review the RUN SUMMARY: segment-pair errors, dependencies, priorities and targets. The complete candidate payload is in `reports/firewall_preview.json` and in the report log, and `-v` (before the workflow name) prints it. A row with every traffic match field blank is match-all and must use `broad_match_ack=TRUE`; `FALSE` or blank rejects the row rather than making it match nothing. A populated `acl` is an exclusive match criterion: leave all ordinary match fields blank and review central source and appliance-distribution warnings. See the [CSV reference](docs/CSV_REFERENCE.md#broad-match-acknowledgment) and [ACL match mode](docs/CSV_REFERENCE.md#acl-match-mode).

If the input contains blank priorities, retain the generated resolved CSV and use it as the input for deployment and future reruns. See [Understanding the resolved firewall CSV](docs/RESOLVED_FIREWALL_CSV.md).

## 6. Apply

```bash
edgeconnect-auto firewall deploy \
  --csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_result.json
```

Type uppercase `APPLY` only after reviewing the complete preview.

## 7. Or use the web GUI

```bash
edgeconnect-auto gui
```

Run it from the folder that holds `.env`. It prints a sign-in link and opens your browser. Load a CSV, fix the problems it lists, plan, then approve by typing `APPLY` and the Orchestrator nickname. Writes stay off until `.env` has `<nickname>_gui_writes=on`, for example `lab_gui_writes=on`. On WSL it opens the Windows browser.

## Other workflows

```bash
edgeconnect-auto address-groups deploy --csv address_groups.csv --dry-run
edgeconnect-auto service-groups deploy --csv service_groups.csv --dry-run
edgeconnect-auto app-definitions deploy --csv application_definitions.csv --dry-run
edgeconnect-auto app-groups deploy --csv application_groups.csv --dry-run
```

Start every workflow with `--dry-run`. See [README.md](README.md) and [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) for full details.
