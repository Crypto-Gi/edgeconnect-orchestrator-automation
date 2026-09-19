# Security

## Secrets

- Never commit `.env`, API keys, passwords, cookies, CSRF tokens, or authorization headers.
- Use an expiring least-privilege Orchestrator API key restricted by source IP where practical.
- Keep TLS certificate and hostname verification enabled. Use a private CA bundle when required.
- Treat CSV inputs, plans, reports, and readbacks as sensitive network configuration.

## Safe operation

- Begin with read-only discovery and `--dry-run`.
- Review the complete preview before typing `APPLY`.
- The tool refuses non-interactive writes and has no `--yes` bypass.
- Never treat HTTP acceptance as appliance convergence; review verification results and exit codes.
- Do not use the tool against production until the exact Orchestrator and ECOS release combination has been validated in a lab.

## Reporting a vulnerability

Report security issues privately to the internal project owner. Do not open a public issue containing customer configuration, logs, credentials, topology, or API responses.

## License

This project is available under the BSD 3-Clause License. See `LICENSE`. The license does not authorize disclosure of customer data, credentials, proprietary configurations, or other material that is not part of this repository.
