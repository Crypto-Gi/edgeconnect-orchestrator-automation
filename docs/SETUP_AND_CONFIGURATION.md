# Setup and configuration

Full installation, several Orchestrators in one `.env`, moving to another machine and updating. Moved from the README; the short version is in [QUICKSTART.md](../QUICKSTART.md).

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

### Several Orchestrators in one `.env`

To switch between Orchestrators without editing `.env` or your CSV files, list each one under a nickname. The nickname is what you type on the command line.

```dotenv
orch_1=prod
orch_2=test

prod_base_url=https://<PROD_ORCHESTRATOR_FQDN>
prod_api_key=<PROD_API_KEY>
test_base_url=https://<TEST_ORCHESTRATOR_FQDN>
test_api_key=<TEST_API_KEY>
# Optional per nickname: <nickname>_ca_bundle, <nickname>_api_key_header,
#   <nickname>_tls_sha256 (pin a self-signed certificate by its SHA-256 fingerprint)

# Optional: used when the command does not name one
orch_default=prod
```

- `orch_<number>=<nickname>` registers an Orchestrator. Add `orch_3`, `orch_4` and so on as needed. The numbers set the menu order.
- `<nickname>_base_url` and `<nickname>_api_key` hold that Orchestrator's settings.
- `orch_default` accepts a nickname (`prod`) or a slot (`orch_1`).
- Nicknames use letters, digits and `_`, and capitals don't matter. Don't use `default`, `orchestrator`, `edgeconnect` or `ec`.

The tool picks an Orchestrator in this order:

1. `--orchestrator <nickname>` on the command (overrides the default)
2. `orch_default`
3. The only one, if just one is listed
4. Otherwise, a numbered menu in an interactive terminal. A non-interactive run stops and lists the nicknames instead.

```bash
edgeconnect-auto firewall deploy --csv rules.csv --dry-run                       # uses orch_default
edgeconnect-auto --orchestrator test firewall deploy --csv rules.csv --dry-run   # overrides it
```

The chosen Orchestrator is printed above every `APPLY` and deletion prompt (`Target Orchestrator: test (<host>)`) and on the `Orchestrator :` line of the RUN SUMMARY and report log. Check it before you confirm. The single-Orchestrator `orchestrator_base_url` / `orchestrator_api_key` lines work as before. If you add `orch_<number>` lines next to them, the old lines become one more choice with the nickname `orchestrator` (`--orchestrator orchestrator`, or `orch_default=orchestrator`). They are never silently ignored.

Plan files (`plan --output`) and inventory files (`discovery --output`) record the Orchestrator they were made from. `apply --approved-plan` and `firewall deploy --inventory` refuse to use them on a different Orchestrator, before any approval prompt, and name only the Orchestrator the file belongs to:

```text
this plan is for Orchestrator test (https://<FQDN>); rerun with --orchestrator test to use it
```

A firewall plan built offline from `--inventory` inherits that inventory's Orchestrator. Files written by older versions have no record and are not checked. Deletion has no saved plan; its target is shown in the deletion table and before every confirmation.

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

## Updating on an existing machine

```bash
git status
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -v
```

Review `CHANGELOG.md` before using a new version.
