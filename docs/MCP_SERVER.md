# MCP server

`edgeconnect-mcp` exposes the whole EdgeConnect Orchestrator REST API to an MCP client through five tools. It runs locally over stdio, uses the same `.env` as `edgeconnect-auto`, and needs no extra Python packages.

| Tool | What it does |
|---|---|
| `list_orchestrators` | Configured nicknames, host, and whether writes are enabled. Never shows keys. |
| `find_operations` | Keyword search over the Orchestrator's own API spec (about 1,200 operations on 9.7 / 10.0). |
| `describe_operation` | Parameters and request-body schema for one operation. |
| `api_get` | Any documented GET. |
| `api_write` | Any documented POST, PUT, PATCH or DELETE, only on Orchestrators with writes enabled. |

## Safety model

- **Read-only by default.** `api_write` is refused unless `.env` has `<nickname>_mcp_writes=true` for that Orchestrator. Turn it on only for lab Orchestrators, or deliberately.
- **Raw passthroughs need a second opt-in.** `/appliance/rest` and `/broadcastCli` forward any request to an appliance's own API or CLI, so the spec cannot limit what they change. Writes through them also need `<nickname>_mcp_passthrough=true`.
- **Spec allowlist.** Every call must match a method and path in the API spec the Orchestrator itself serves (`/gms/rest/apiDocs`, the same one Support > REST APIs shows). Undocumented paths, `..`, encoded separators and anything that would leave `/gms/rest` are rejected.
- **Separate read and write tools.** `api_write` is marked destructive, so MCP clients ask before each call; reads can be auto-approved.
- **Secrets stay local.** API keys are only sent as the `X-Auth-Token` header. String values under keys such as `apiKey`, `password`, `token`, `presharedKey`, `authKey` and `privateKey`, and any PEM private key, come back as `<REDACTED:…>` tokens; flags and numbers (`passwordMinLen`, `csrfProtection`) stay readable. Write a token back unchanged and the server puts the real value in, so read-modify-write of BGP, OSPF, overlays or tunnels round-trips exactly. A token is only restored under a secret-looking key, on the Orchestrator it came from, during the same server run; anything else (a plain `<REDACTED>`, a token moved into a readable field, a token from another Orchestrator or an earlier run) is refused, so a secret can never be overwritten with a placeholder or copied somewhere readable.
- **High-risk blocklist.** Even with writes on, these are refused unless `<nickname>_mcp_allow_high_risk` names their category (comma-separated, or `all`): `auth` (users, roles, RBAC, TACACS/RADIUS, API keys, sessions), `certificates` (certs, SSL/TLS, ciphers, HTTPS), `licensing`, `backup_restore`, `upgrade`, `reboot` (reboot, shutdown, restart, factory reset), `orchestrator_ha`, `appliance_lifecycle` (delete, approve/deny/revoke, EdgeHA, hostname, passthrough DELETE), `cli` (broadcastCli, tcpdump, shell), `ip_allowlist`, `traffic_disruptive` (network memory erase, flow reset). Passthrough writes are also checked against their `url`. `edgeconnect-mcp --list-high-risk <nickname>` prints every write in that Orchestrator's spec that the list refuses.
- **Rate limits per Orchestrator.** Reads default to 10 per second and writes to 2 per second, each with a burst of twice that. Over the limit, calls wait rather than fail, so scripts slow down instead of breaking. Change with `<nickname>_mcp_read_rate` / `<nickname>_mcp_write_rate` (0 = no limit).
- **Audit log.** Every tool call is appended as one JSON line to `~/.edgeconnect-mcp/audit.jsonl` (file 0600, folder 0700): time, session and call id, tool, Orchestrator, method, path, redacted query, a SHA-256 of the write body, outcome, error, duration and response size. Bodies and secrets are never written. Set `mcp_audit_log=/other/path` or `mcp_audit_log=off`.
- **Untrusted results.** API results carry a note that their text is data, not instructions, and the server instructions say the same. Invisible and direction-changing characters (zero-width, bidi overrides, Unicode tag characters) are shown as `\uXXXX` JSON escapes, so hidden text is visible while the value still decodes exactly.
- **Strict TLS.** Certificates are verified. A self-signed lab Orchestrator is supported by pinning its certificate (`<nickname>_tls_sha256`), never by turning verification off.
- **No listener.** stdio only; nothing is exposed on the network. Every write is also logged to stderr (the MCP client's server log) with method, path and query.
- Large responses are truncated to `max_chars` (default 60,000) so one call cannot flood the conversation.

## Configure

Use the multi-Orchestrator `.env` layout from the README, then add per nickname as needed:

```dotenv
orch_4=lab
lab_base_url=https://192.0.2.10
lab_api_key=<API_KEY>
lab_mcp_writes=true
# Optional: allow writes through /appliance/rest and /broadcastCli.
# lab_mcp_passthrough=true
# Self-signed certificate: pin it.
lab_tls_sha256=<SHA-256 fingerprint>
# Optional: use a saved spec instead of downloading it on first use.
# lab_openapi=/absolute/path/apiDocs.json
# Optional: allow blocklisted categories of writes (or "all").
# lab_mcp_allow_high_risk=traffic_disruptive,backup_restore
# Optional: requests per second (0 = no limit). Defaults: 10 reads, 2 writes.
# lab_mcp_read_rate=10
# lab_mcp_write_rate=2

# Global: audit log location, or off.
# mcp_audit_log=~/.edgeconnect-mcp/audit.jsonl
```

Get a certificate fingerprint (check it on the Orchestrator console or another trusted path before pinning):

```bash
openssl s_client -connect 192.0.2.10:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

`orch_default` picks the Orchestrator used when a tool call names none.

## Connect a client

After `python -m pip install --upgrade pip` and `python -m pip install -e .` (macOS's built-in Python 3.9 ships a pip too old for editable installs):

Claude Code:

```bash
claude mcp add edgeconnect -- /absolute/path/.venv/bin/edgeconnect-mcp --dotenv /absolute/path/.env
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "edgeconnect": {
      "command": "/absolute/path/.venv/bin/edgeconnect-mcp",
      "args": ["--dotenv", "/absolute/path/.env"]
    }
  }
}
```

`EDGECONNECT_DOTENV` works instead of `--dotenv`. Without either, `./.env` in the working directory is used.

## Using it

Ask in plain language, for example "list appliances on seteam that are unreachable" or "show the overlay config on the lab". The assistant searches the spec, reads the operation, and calls it. Paths are relative to `/gms/rest`, e.g. `/appliance` or `/appliance/2.NE`.

## Orchestrator API notes from lab testing

Found while driving a 9.7.1 Orchestrator with five ECOS 9.6/9.7 appliances through this server:

- Operations whose spec accepts only `text/plain` (Zscaler countries/timezones) take a plain string `body`, which `api_write` sends raw; a JSON-accepting operation gets it JSON-encoded.
- Deployment, BGP, OSPF, VRRP, static routes and IP SLA have no Orchestrator write operation in the 9.7.1 spec. Read the appliance's own config with `GET /appliance/rest?nePk=<NE>&url=<path>` (`deployment`, `subnets3/configured`, `bgp/config/neighbor`, `ospf/config/system`, `vrrp`, `ipsla/config/managers`), change it and POST the whole object back. Strip state fields (VRRP `uptime`, `vmac`, ...) first. `subnets/configured` returns 410; use `subnets3/configured`.
- Overlay `PUT /gms/overlays/config` is refused with 400 unless `multiCrossConnect` and `tunnelUsagePolicy` only name labels in the primary or backup list. Readback is normalised by bonding-policy presets, so compare intent fields, not the whole body. `topologyType` 1 is mesh and 2 is hub-and-spoke.
- `GET /gms/overlays/config/regions` needs both `overlayId` and `regionId`, or neither.
- User-defined applications are read with `GET /applicationDefinition?...&resourceKey=userDefined`; without it the call returns 200 with `{"result":"Not found"}`.
- LAN subnets in a non-default segment are not advertised until that VRF is added with `add_local_lan` via `POST /subnets/setSubnetSharingOptions`.
- Zone names allow only letters, digits and `_`. Zones and segment security policies are whole-collection writes: read, add, write back.

The CSV workflows in `edgeconnect-auto` remain the safer route for bulk firewall and object changes: they add drift checks, readback and rollback that raw `api_write` calls do not.
