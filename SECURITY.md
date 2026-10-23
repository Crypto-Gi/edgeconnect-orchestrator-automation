# Security

## Secrets

- Never commit `.env`, API keys, passwords, cookies, CSRF tokens, or authorization headers.
- The CLI automatically reads only `./.env` from the current working directory; it never searches parents or the home directory. Verify your current directory before running a command. The `edgeconnect-auto` wrapper that `setup.sh` installs always passes `--dotenv <install folder>/.env` instead.
- Use an expiring least-privilege Orchestrator API key restricted by source IP where practical.
- Keep TLS certificate and hostname verification enabled. Use a private CA bundle when required, or pin one self-signed certificate with `<nickname>_tls_sha256` (`orchestrator_tls_sha256` for a single Orchestrator).
- The client refuses HTTP redirects so the API key is only ever sent to the configured base URL. If Orchestrator sits behind a redirecting front end, configure the address that answers directly.
- Treat CSV inputs, plans, reports, and readbacks as sensitive network configuration.

## Safe operation

- Begin with read-only discovery and `--dry-run`.
- Review the complete preview before typing `APPLY`.
- Treat empty firewall match criteria as match-all. `broad_match_ack=TRUE` only acknowledges that intent; `FALSE` rejects the row and never means match-nothing.
- Treat `acl` as an exclusive firewall match mode. Review its central definition and distribution warnings; missing or unreachable appliance copies can produce PARTIAL without blocking the global submission.
- The tool refuses non-interactive writes and has no `--yes` bypass.
- Never treat HTTP acceptance as appliance convergence; review verification results and exit codes.
- Do not use the tool against production until the exact Orchestrator and ECOS release combination has been validated in a lab.

## Reporting a vulnerability

Report security issues privately to the internal project owner. Do not open a public issue containing customer configuration, logs, credentials, topology, or API responses.

## License

This project is available under the Apache License 2.0. See `LICENSE` and `NOTICE`. The license does not authorize disclosure of customer data, credentials, proprietary configurations, or other material that is not part of this repository.
