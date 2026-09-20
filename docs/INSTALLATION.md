# Installation and Migration Guide

## Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.9 |
| Git | Any maintained release |
| Orchestrator | 9.3+ with required capabilities |
| ECOS target | 9.5+ |
| Network | HTTPS access to Orchestrator |
| Credentials | API key with appropriate read/write permissions |

The runtime has no third-party Python dependencies.

## Install from Git

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

Windows PowerShell activation:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools
python -m pip install -e .
Copy-Item .env.example .env
```

## Configure

```dotenv
orchestrator_base_url=https://<ORCHESTRATOR_FQDN>
orchestrator_api_key=<API_KEY>
# orchestrator_ca_bundle=/absolute/path/to/private-ca.pem
```

The base URL may be the host URL or may end in `/gms/rest`; it must not contain credentials, a query string, or another path. Commands load `./.env` from the current working directory by default, never search parent directories, and accept `--dotenv <PATH>` as an explicit override. Process environment variables take precedence.

## Verify

```bash
edgeconnect-auto --help
python -m unittest discover -v
edgeconnect-auto discovery --output reports/discovery.json
```

Discovery is read-only.

## Move to a new machine

1. Clone/copy the repository.
2. Create a new virtual environment.
3. Install editable package.
4. Create a new `.env` through an approved secret-transfer method.
5. Copy an approved private CA bundle if required.
6. Run tests.
7. Run discovery.
8. Run the intended workflow with `--dry-run`.
9. Review the preview before allowing any write.

Do not move the old `.venv`; recreate it. Do not transfer `.env` by email, chat, or source control.

## Upgrade

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -v
```

Review the changelog and rerun dry-run against the target environment after every update.

## Uninstall

```bash
python -m pip uninstall edgeconnect-automation
```

Removing the local virtual environment and repository does not modify Orchestrator configuration.
