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
- **Spec allowlist.** Every call must match a method and path in the API spec the Orchestrator itself serves (`/gms/rest/apiDocs`, the same one Support > REST APIs shows). Undocumented paths, `..`, encoded separators and anything that would leave `/gms/rest` are rejected.
- **Separate read and write tools.** `api_write` is marked destructive, so MCP clients ask before each call; reads can be auto-approved.
- **Secrets stay local.** API keys are only sent as the `X-Auth-Token` header. Responses and errors pass through the same redaction as the CLI (`apiKey`, `password`, `token`, ...).
- **Strict TLS.** Certificates are verified. A self-signed lab Orchestrator is supported by pinning its certificate (`<nickname>_tls_sha256`), never by turning verification off.
- **No listener.** stdio only; nothing is exposed on the network. Every write is logged to stderr (the MCP client's server log) with method, path and query.
- Large responses are truncated to `max_chars` (default 60,000) so one call cannot flood the conversation.

## Configure

Use the multi-Orchestrator `.env` layout from the README, then add per nickname as needed:

```dotenv
orch_4=lab
lab_base_url=https://192.0.2.10
lab_api_key=<API_KEY>
lab_mcp_writes=true
# Self-signed certificate: pin it.
lab_tls_sha256=<SHA-256 fingerprint>
# Optional: use a saved spec instead of downloading it on first use.
# lab_openapi=/absolute/path/apiDocs.json
```

Get a certificate fingerprint (check it on the Orchestrator console or another trusted path before pinning):

```bash
openssl s_client -connect 192.0.2.10:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

`orch_default` picks the Orchestrator used when a tool call names none.

## Connect a client

After `python -m pip install -e .`:

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

The CSV workflows in `edgeconnect-auto` remain the safer route for bulk firewall and object changes: they add drift checks, readback and rollback that raw `api_write` calls do not.
