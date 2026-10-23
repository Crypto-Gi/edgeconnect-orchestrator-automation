# Reports and troubleshooting

The RUN SUMMARY, row outcomes, report files and logs, and troubleshooting. Moved from the README.

## Run summary and report log

Every workflow command ends with a **RUN SUMMARY**, whatever happened: success, no-op, dry run, blocked, refused, drift, partial, interrupted, or an unexpected error. Think of it as the receipt at the end of a transaction: it tells you what happened, why, and what to do next, even when nothing was written.

```text
==============================================================================
RUN SUMMARY
==============================================================================
Workflow     : firewall deploy
Run          : run-bd501d73af8d  at 2026-09-30T14:54:37-05:00  (3.3s)
Versions     : tool 1.2.11, Orchestrator 9.7.1.42046
Orchestrator : lab (https://<ORCHESTRATOR_FQDN>)
CSV          : rules.csv (73 data rows, sha256 005f008e35f2...)
RESULT       : BLOCKED
Changes made : no
Exit code    : 2 = blocked by validation or planning; nothing was written

What was planned or done
  - segment pair Default -> Default: BLOCKED by 1 issue(s); none of its 73 rows will be written

Rows (73): 1 BLOCKED, 72 NOT ATTEMPTED
  ROW  OUTCOME        ITEM                 SCOPE / REASON
  2    BLOCKED        1 (priority 20000)   Default -> Default | INSIDE -> OUTSIDE | [FW-24] ... priority 20000 conflicts ...
  3    NOT ATTEMPTED  2 (priority 20005)   Default -> Default | INSIDE -> OUTSIDE | segment pair blocked by row 2
  ...

Why it stopped or what failed
  - row 2 [FW-24] rule_key 1 priority 20000 conflicts with a different existing rule in zone pair INSIDE -> OUTSIDE (existing: allow disabled, match acl=EXAMPLE-ACL; this row: allow disabled, match dst_ip=192.0.2.0/24, either_port=443, protocol=tcp); fix: use a free priority such as 20001, or remove the existing rule first

Warnings (do not block)
  - target 3.NE (branch-03) is unreachable and will remain unverified

Appliances
  - 0.NE (hub-01): reachable
  - 3.NE (branch-03): unreachable
Report       : reports/firewall.jsonl
Report       : reports/firewall.log

Next step    : Fix every blocking issue listed above, then rerun the same command with --dry-run.
==============================================================================
```

The summary is printed to standard error, so it still appears when standard output is redirected. `report summarize` is the one command without its own summary: it prints the saved one.

| Line | Meaning |
|---|---|
| `Orchestrator` | The nickname and address the command used (only the address for the single-Orchestrator lines); not shown when Orchestrator was not contacted |
| `RESULT` | `SUCCESS`, `NO_OP`, `DRY_RUN`, `VALID`, `PLANNED`, `BLOCKED`, `INVALID`, `REFUSED`, `DRIFT`, `PARTIAL`, `ZONES_CREATED_RERUN`, `INTERRUPTED`, or `ERROR` |
| `Changes made` | `no`, `yes`, `possibly` (partial), or `unknown` (error or interruption after `APPLY`: check Orchestrator) |
| `What was planned or done` | Counts per segment pair, template group, or object type; per-pair and per-group results, including rollback state |
| `Rows` | One line per CSV row (or object): its outcome and why. Problem rows are listed first; the screen shows 25, the report log shows all |
| `Why it stopped or what failed` | Every blocking issue, with its rule code, row, and fix |
| `Appliances` | Reachability or verification per appliance, with hostname |
| `Run ref` | Firewall writes only; each segment pair's Orchestrator audit log comment is this reference followed by `-<segment map>`, for example `-0_0` |

### Row outcomes

| Outcome | Meaning |
|---|---|
| `WOULD CREATE`, `WOULD ADD`, `WOULD OVERWRITE`, `WOULD DELETE` | Planned only (dry run, refused, or blocked elsewhere) |
| `CREATED`, `ADDED`, `OVERWRITTEN`, `DELETED` | Written and verified |
| `CREATED, UNVERIFIED` (and similar) | Written, but not every appliance or readback could be verified |
| `ALREADY PRESENT`, `ALREADY ABSENT` | Nothing to do for this row |
| `BLOCKED`, `INVALID` | This row has an error; the reason is shown |
| `NOT ATTEMPTED` | This row is fine, but another row blocks its segment pair, template group, or the whole CSV |
| `SKIPPED` | Row isolated from an otherwise successful run (application definitions and groups) |
| `FAILED`, `NOT WRITTEN` | The write failed and was rolled back, drift stopped it, or an appliance refused to compile the rule (see below) |
| `NOT DELETED` | A deletion run stopped or skipped this row after drift or an error; the reason is shown. Firewall deletion continues with other segment pairs; object deletion stops at the first problem |
| `UNKNOWN` | The command stopped after it had started writing, and the result of this row is not known; check Orchestrator |

A firewall error in one row blocks every row of the same segment pair, and a CSV validation error blocks the whole file. `NOT ATTEMPTED` makes that visible: fix the `BLOCKED` or `INVALID` rows and the rest can proceed.

### Status fields in report files

Every `--report` file and every report-log record starts with the same fields and words, whatever the workflow: `status` (the `RESULT` values above), `exit_code`, `changes_written`, `timestamp`, `run_id`, `workflow`, `orchestrator` (the nickname, or `unnamed` for the single-Orchestrator lines) and `orchestrator_url` (for example `https://<ORCHESTRATOR_FQDN>`). Commands that never contact Orchestrator, such as `validate`, record `not contacted`. Scripts should read these. To list every run against one Orchestrator: `grep '"orchestrator": "prod"' reports/firewall.jsonl`. The workflow-specific results underneath are unchanged (for example firewall `result.status: SUCCESS` or template ACL `result.status: success`); a different older top-level status is kept as `detail_status`.

### Summarize a saved report

```bash
edgeconnect-auto report summarize reports/firewall-deploy.json
edgeconnect-auto report summarize reports/firewall.jsonl --last 3
edgeconnect-auto report summarize old-report.json --rows-csv rows.csv
```

This prints the RUN SUMMARY and the full row table from a saved `--report` file, a plan file, or the last runs of a `reports/<workflow>.jsonl` log. It also works on reports written by versions before this feature (the tool version then shows as unknown). `--rows-csv` exports the row table for Excel. It reads files only: it does not contact Orchestrator and does not add to the report log.

### Automatic report log

You do not need `--report` to keep a record. Every run is appended to a log for its workflow in `./reports/` (created if missing, and excluded from Git):

| File | Contents |
|---|---|
| `reports/<workflow>.log` | The human-readable run summary of every run, newest at the end |
| `reports/<workflow>.jsonl` | One JSON line per run: the summary (run ID, timestamp, versions, command, CSV checksum, status, issues) plus the complete preview and result |

`<workflow>` is the command family: `firewall`, `template-acls`, `address-groups`, `service-groups`, `app-groups`, `app-definitions`, `zones`, or `discovery`. The log files grow with every run; archive or delete old ones when no longer needed.

| Option | Effect |
|---|---|
| (none) | Log to `./reports/` in the current directory |
| `--report-dir D:\ec-reports`, or `EDGECONNECT_REPORT_DIR` set in the process environment (not in `.env`) | Log to another folder |
| `--report-dir ""` | Disable the automatic log for this run |
| `--report reports/x.json` (per command) | Additionally write that one run to an exact file, overwritten each time. It is always written, even on refusal or error, and includes the same `summary` block, so it never shows an older run's result. |

To send a run for troubleshooting, send the matching block from `reports/<workflow>.log`; add the `.jsonl` line when the full preview is needed.

## Reports

Reports and report logs are:

- Redacted
- Fingerprinted
- Written with restrictive permissions
- Excluded from Git by default

They may still contain sensitive network configuration. Store and transfer them only through approved systems.

## Troubleshooting

### Configuration is missing

`Orchestrator base URL and API key are required; provide them in ./.env, process environment variables, or --dotenv <path>` (exit 2). Run from the directory containing `.env`, provide process environment variables, or select another file explicitly. The `edgeconnect-auto` command that `setup.sh` installs always reads `<install folder>/.env`.

```bash
edgeconnect-auto discovery
edgeconnect-auto --dotenv /absolute/path/to/other.env discovery
```

### Several Orchestrators and no choice

`multiple Orchestrators are configured (lab, prod); choose one with --orchestrator NAME or set orch_default in .env` (exit 2). Outside a terminal the tool cannot show its menu. Put `--orchestrator <nickname>` before the workflow name, or set `orch_default`. `unknown Orchestrator 'x'` lists the nicknames that exist.

### `non-interactive writes are refused` or `non-interactive deletion is refused`

Exit 3, nothing written. A write or deletion needs a person at a terminal to type `APPLY` (and the deletion code); it refuses to run from a script, a pipe or an agent tool. Run the command without `--dry-run` in your own terminal.

### `this plan is for Orchestrator ...`

A plan or inventory file made on another Orchestrator. Rerun with the `--orchestrator` it names, or build a new plan against this one.

### `--inventory expects the offline inventory JSON used by the contract tests`

Exit 2, nothing written. `firewall plan --inventory` and `firewall deploy --inventory` take the contract-test inventory format (`segments {name: id}`, `zones {"segment|zone": id}`, `policies {"source|destination": policy}`, ...), not a `discovery --output` file. Drop `--inventory` to discover live.

### `approved plan fingerprint does not match`

The plan file was edited after `plan` wrote it (firewall: `approved firewall plan is invalid or changed`). Never edit a plan; change the CSV and run `plan` again.

### `Orchestrator 9.3 or later is required`

The tool refuses older releases before any write.

### `HTTP 3xx redirect refused`

Set the base URL to the address that answers directly; the API key is never sent to a redirected location.

### Certificate verification fails

Do not disable TLS verification. A failure shows as `transport failure: URLError`. Add the approved CA chain:

```dotenv
orchestrator_ca_bundle=/absolute/path/to/ca-bundle.pem
```

A CA bundle only helps when the certificate names the host in the base URL. For a self-signed certificate, such as a lab Orchestrator reached by IP address, pin that one certificate instead (colons are optional):

```dotenv
orchestrator_tls_sha256=<SHA-256 fingerprint>   # or <nickname>_tls_sha256
```

Read the fingerprint with `openssl s_client -connect <host>:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256` and compare it with the certificate shown in your browser before saving it.

### `error: string indices must be integers, not 'str'`

Versions before `1.1.2` crashed during firewall discovery when an Orchestrator returned user-defined port/protocol or compound application definitions in a shape other than a list of records per key. The crash happened before any write. Update to `1.1.2` or later (`pip show edgeconnect-automation` shows the installed version). Unrecognized entries are now skipped; a referenced application that still cannot be found is resolved through exact wildcard search or blocked with `DEP-01`.

To see the full Python traceback for an unexpected runtime error, add `-vv` before the workflow name (`edgeconnect-auto -vv firewall deploy --csv rules.csv --dry-run`), or call the handler directly with a read-only dry run:

```bash
python -c "from edgeconnect_automation.cli import build_parser; a=build_parser().parse_args(['firewall','deploy','--csv','rules.csv','--dry-run']); a.handler(a)"
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

### Appliance alarm "ACL rule has invalid syntax"

Orchestrator can store a firewall rule or ACL entry, copy it to every appliance, and log success, while the appliance policy engine refuses to compile it. The appliance then raises the service-affecting alarm "ACL rule has invalid syntax" with source `/policyEngine/acl/<priority>`, and the rule is not enforced. On 9.6.4 appliances this happens for single addresses without a prefix length (`10.1.1.1` instead of `10.1.1.1/32`) and for dotted masks (`/255.255.255.0` instead of `/24`); one such value in a list rejects the whole rule.

- The tool sends these values as `/32` (`/128` for IPv6) and prefix lengths, and warns (`FW-33`, `ACL-29`).
- After every firewall or template ACL write it reads the appliance alarms for the verified appliances (for up to 30 seconds) and reports each rejected row as `FAILED`, with the appliance and the reason. The run ends PARTIAL. Rules written by older versions are not rechecked.
- A rule already deployed without `/32` blocks a redeploy at the same priority with `FW-34`. Remove it with `firewall delete` and the CSV it was deployed from (the delete still matches it), then deploy the corrected CSV.

### API returns success but drops a field

Normalized readback fails and the affected segment pair enters recovery. Unsupported fields are not silently accepted.
