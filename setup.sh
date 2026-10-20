#!/usr/bin/env bash
# Install or update the EdgeConnect toolkits and their agent skills (macOS and Linux).
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Crypto-Gi/edgeconnect-orchestrator-automation/main/setup.sh)
#
# Clones (or updates) both repositories at main into ~/edgeconnect (or EDGECONNECT_HOME),
# builds one Python environment, creates one shared .env, adds the edgeconnect-auto and
# edgeconnect-preconfig commands to ~/.local/bin, and installs both skills with the
# `skills` CLI, which asks which agents to add them to. Run it again to update everything.
set -euo pipefail

ROOT="${EDGECONNECT_HOME:-$HOME/edgeconnect}"
BIN="$HOME/.local/bin"
MARK="# edgeconnect setup.sh"
REPOS="edgeconnect-orchestrator-automation edgeconnect-preconfig"
PRECONFIG_SCRIPTS="$ROOT/edgeconnect-preconfig/skills/building-edgeconnect-preconfig-templates/scripts"

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null || die "git is required"
PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys, venv; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
    PYTHON="$candidate"; break
  fi
done
[ -n "$PYTHON" ] || die "Python 3.9 or later with the venv module is required (on Debian/Ubuntu: apt install python3-venv)"

say "Repositories (main) in $ROOT"
mkdir -p "$ROOT"
for repo in $REPOS; do
  if [ -d "$ROOT/$repo/.git" ]; then
    if [ -n "$(git -C "$ROOT/$repo" status --porcelain --untracked-files=no)" ]; then
      echo "$repo: local changes, not updated (commit or discard them, then run again)"
    else
      git -C "$ROOT/$repo" checkout -q main || die "$repo: could not switch to main"
      git -C "$ROOT/$repo" pull -q --ff-only origin main || die "$repo: could not update main (diverged, or no access to GitHub)"
      echo "$repo: updated to $(git -C "$ROOT/$repo" rev-parse --short HEAD)"
    fi
  else
    git clone -q "https://github.com/Crypto-Gi/$repo.git" "$ROOT/$repo" || die "$repo: clone failed; check your network access to github.com and run again"
    echo "$repo: cloned at $(git -C "$ROOT/$repo" rev-parse --short HEAD)"
  fi
done

say "Python environment in $ROOT/.venv"
[ -x "$ROOT/.venv/bin/python" ] || "$PYTHON" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install -q --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -q -e "$ROOT/edgeconnect-orchestrator-automation" -r "$ROOT/edgeconnect-preconfig/requirements.txt"
echo "installed edgeconnect-auto $("$ROOT/.venv/bin/python" -c 'import edgeconnect_automation as e; print(e.__version__)'), Jinja2 and PyYAML"

say "Shared settings in $ROOT/.env"
if [ -e "$ROOT/.env" ]; then
  echo "kept the existing .env"
else
  (umask 077; cat > "$ROOT/.env" <<'EOF'
# Shared by edgeconnect-auto and the preconfig scripts. Never commit or share this file.
# One slot per Orchestrator; the nickname is what you pass to --orchestrator.
orch_1=lab
lab_base_url=https://<ORCHESTRATOR_FQDN_OR_IP>
lab_api_key=<API_KEY>

# More Orchestrators:
# orch_2=prod
# prod_base_url=https://<ORCHESTRATOR_FQDN_OR_IP>
# prod_api_key=<API_KEY>

# Optional per nickname: <nickname>_ca_bundle=/path/to/ca.pem (private CA),
#   <nickname>_api_key_header=X-Auth-Token,
#   <nickname>_tls_sha256=<fingerprint> (self-signed certificate)
# Preconfig: Orchestrators allowed for /validate, comma-separated nicknames.
# EC_VALIDATORS=lab
EOF
  )
  echo "created .env: replace the placeholders before the first run"
fi
chmod 600 "$ROOT/.env"

say "Commands in $BIN"
mkdir -p "$BIN"
install_command() {  # name; wrapper body on stdin. Never replaces a command this script did not write.
  local target="$BIN/$1" body
  body="$(cat)"
  if [ -e "$target" ] && ! grep -qF "$MARK" "$target"; then
    echo "$1: $target exists and was not written by this script; left unchanged"
    return
  fi
  printf '#!/bin/sh\n%s\n%s\n' "$MARK" "$body" > "$target"
  chmod 755 "$target"
  echo "$1 -> $target"
}
install_command edgeconnect-auto <<EOF
exec "$ROOT/.venv/bin/edgeconnect-auto" --dotenv "$ROOT/.env" "\$@"
EOF
install_command edgeconnect-preconfig <<EOF
# Usage: edgeconnect-preconfig STAGE [options], where STAGE is capture, compare, translate, render, check, upload, ...
case "\${1:-}" in
  ""|-h|--help|*[!a-z_]*)
    echo "usage: edgeconnect-preconfig STAGE [options]; stages:"
    ls "$PRECONFIG_SCRIPTS" | sed -n 's/[.]py\$//p' | grep -v '^common\$'
    exit 2 ;;
esac
script="$PRECONFIG_SCRIPTS/\$1.py"; shift
[ -f "\$script" ] || { echo "unknown stage; run: edgeconnect-preconfig --help" >&2; exit 2; }
EC_DOTENV="\${EC_DOTENV:-$ROOT/.env}" exec "$ROOT/.venv/bin/python" "\$script" "\$@"
EOF
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "$BIN is not on your PATH; add this line to your shell profile: export PATH=\"$BIN:\$PATH\"" ;;
esac

say "Agent skills"
if ! command -v npx >/dev/null; then
  echo "Node.js 18 or later is needed for the skills installer; after installing it, run:"
  for repo in $REPOS; do echo "  npx -y skills add \"$ROOT/$repo\" -g"; done
elif ! { : </dev/tty; } 2>/dev/null; then
  echo "no terminal to ask which agents; run these yourself:"
  for repo in $REPOS; do echo "  npx -y skills add \"$ROOT/$repo\" -g"; done
else
  for repo in $REPOS; do
    npx -y skills add "$ROOT/$repo" -g </dev/tty
  done
fi

say "Done"
echo "1. Fill in $ROOT/.env"
echo "2. Check: edgeconnect-auto --orchestrator <nickname> discovery"
echo "3. Restart your agent so it loads the skills"
