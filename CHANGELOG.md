# Changelog

## Unreleased (`gui` branch)

- GUI: the launch link works once. It gives the browser a separate session cookie, so a link read by another account on the computer is useless after you open it. Opening it again in the same browser just shows the GUI. To use another browser, restart the GUI.
- GUI Undo: groups with several rules are undone whole (they were refused before), and uploads of applications and application groups can now be undone. Undo is not offered when an upload also changed something a delete cannot restore: a template group it created, its Access Lists template or merge mode, or AppExpress entries that already existed (including one already on monitor for a new application).
- GUI: each problem in a CSV is listed once (some were listed twice), application-group problems show their row in the Row column, and a task whose command line is refused ends as failed instead of staying "running".
- The run summary (and `report summarize`, `--rows-csv` and the GUI) says CREATED after a real `app-definitions apply` or `app-groups apply`; it said WOULD CREATE, because their results were not recognised as results.
- Address-group and service-group plans count groups, as the result does, and add the row count when a group has several rules: `to create: 25 (27 rows)` where it said `to create: 27`.
- GUI Undo counts what it deletes as the delete preview does: "Deletes the address groups this upload created (25, from 27 CSV rows)" where it said "the 27 rows of address groups".
- GUI: a plan cancelled while it runs ends as cancelled (it ended as planned and could be applied), and the GUI deletes its temporary folder of uploaded CSVs and plans when it stops.
- Every command reads the Orchestrator's serial number for the plan's identity. If that read fails for any reason, the command now goes on and compares the address only; before, any error other than 403 or 404 (such as 400, 401, a 5xx or a timeout) stopped the command.

## 1.3.0rc1 — 2026-10-26 (pre-release, `gui` branch)

- `edgeconnect-auto gui` starts a local web GUI for bulk CSV uploads, on 127.0.0.1 only. It runs the same commands as the CLI, so the checks and results are the same; nothing in the existing commands changed. A CSV with problems is listed row by row with the fix for each. A write needs the same typed confirmations as the terminal plus the Orchestrator nickname, and is off for an Orchestrator until `.env` has `<nickname>_gui_writes=on`. The GUI shows every Orchestrator's status, the run log, the inventory, a guided upload for each object type, Remove by CSV, and "Undo this upload" for uploads made in the GUI. It runs on macOS, Linux and Windows through WSL.
- `edgeconnect-auto gui` accepts `--dotenv` when it names the `.env` of the folder it starts in, so the launcher `setup.sh` installs works from the install folder.
## 1.2.11 — 2026-10-23

- `orchestrator_tls_sha256` now pins the `orchestrator` choice (the single-Orchestrator lines) when `orch_<N>` lines also exist. Previously the pin was dropped as soon as any nickname was configured. It is still never used for a nickname, because a pin belongs to one host.
- `firewall plan --inventory` and `firewall deploy --inventory` stop with exit 2 and name the expected format when the file is not the contract-test inventory format, for example a `discovery --output` file. Previously this ended with a raw `TypeError` or `ValueError` and exit 1. The help now says what `--inventory` replaces: live discovery only. `deploy` still reads the Orchestrator release and, without `--dry-run`, writes and verifies live.
- `firewall plan --dry-run` is refused with exit 2: plan is always read-only, so the option had no effect except to label an exit-5 plan `DRY_RUN` in the RUN SUMMARY.
- `SECURITY.md` points vulnerability reports to GitHub private vulnerability reporting (the **Report a vulnerability** button under the Security tab).

## 1.2.10 — 2026-10-21

- The agent skills show the exact command for every operation the agent runs or proposes, in its own code block, ready to paste into a terminal, even when the agent runs it itself. Only the command lines are shown, not the files the agent prepared. This skill: every read-only `edgeconnect-auto` command, not only the write hand-off. The `AGENTS.md` that `setup.sh` writes says the same for all three tools (for an MCP call, the tool and request), and CSV edits are named file and cell first, then the command that uses them.

## 1.2.9 — 2026-10-21

- `setup.sh` (the same file is in edgeconnect-preconfig and edgeconnect-mcp) keeps an `AGENTS.md` it wrote up to date: when you have not edited it, including one written by an earlier release, it is replaced and the run says "updated (you had not edited it)". A file you have edited is still kept, with the new text in `AGENTS.md.new`. It remembers what it wrote in `.AGENTS.md.setup-sha256`.
- The last screen states the MCP server's state plainly: local (with its launcher), Docker (with the guide), not installed (and which answer installs it), or not part of this install.

## 1.2.8 — 2026-10-21

- `setup.sh` (the same file is in edgeconnect-preconfig and edgeconnect-mcp) asks which agents to use once, from a table of 20. That answer applies to every picked skill, including ones already installed, and to the MCP server. The MCP server is added through `add-mcp` (tool calls are not auto-approved), through `devin mcp add` for Devin, or as a printed config to paste. When you choose the install folder, each agent that keeps MCP servers only for the whole user account (Windsurf, Cline, Goose, Antigravity, Claude Desktop) is asked about separately (y/n); with `--yes` it is skipped and the last screen shows the command to add it. `setup.sh` prints each agent's MCP settings file. Before adding the server it asks to continue, since an existing `edgeconnect` entry is replaced; with `--yes` it adds the server only when `--mcp stdio` is given, so a re-run never replaces your own `edgeconnect` entry silently. A Devin entry that points at another install folder is reported with the commands to switch it. The last screen shows how to fill in `.env` for what you picked. `--agents` now takes numbers or names for both skills and the MCP server; `--mcp-agents` remains an alias and `--refresh-skills` is no longer needed.

## 1.2.7 — 2026-10-21

- `setup.sh` (the same file is in edgeconnect-preconfig and edgeconnect-mcp) can now install the MCP server. When you pick repository 3 it asks whether to run the server locally (stdio), and then which agents get it: Claude Code and Codex through their own `mcp add` commands, other apps by printing the config to paste. If you run the server in Docker over HTTPS, it points you to the MCP install guide instead. The local server runs from `<install folder>/bin/edgeconnect-mcp` with the shared `.env`, so each install folder keeps its own server. One question now decides where both the skills and the MCP server go: only the install folder, or your user account. An agent that already has an `edgeconnect` server keeps it, and setup.sh says which one it is. New options: `--mcp stdio|docker|no` and `--mcp-agents claude-code,codex,other`.
- The `AGENTS.md` that `setup.sh` writes ends with "Installed here", built from what the folder holds.

## 1.2.6 — 2026-10-21

- `setup.sh` (the same file is in edgeconnect-preconfig and edgeconnect-mcp) first shows a table of the three repositories, with what each one does and the skill it installs, and asks which to install: numbers separated by commas (`1,3`) or `all`, the default. Only what you pick is cloned and set up; picking only the MCP repository installs just its guide skill, with no Python environment or `.env`. `--repos 1,3` (or `all`) answers it without asking. The MCP server itself is still never installed.

## 1.2.5 — 2026-10-20

- A NUL byte anywhere in a CSV now rejects the whole file with `CSV-11` on every Python version. On Python 3.11 and later the csv module accepts NUL, so a firewall CSV with a NUL in one cell blocked only that segment pair (`CSV-10`) and the other pairs could still be deployed.
- New agent skill `skills/managing-edgeconnect-firewall-and-objects/`: an agent writes CSV rows from a plain-language request and runs only read-only commands; every write stays with a person typing `APPLY` in a terminal. Tested on a 9.7.1 lab Orchestrator.
- Redaction now also hides pre-shared keys, auth keys, private keys and passphrases, and no longer hides flags and numbers under secret-looking keys (`passwordMinLen`, `csrfProtection`). Found by a full read sweep of a 9.7.1 lab, where tunnel and template-group `presharedkey` values were returned in clear.
- New `<nickname>_tls_sha256` (and `orchestrator_tls_sha256`) pins a self-signed Orchestrator certificate by SHA-256 fingerprint instead of disabling verification.
- `--allow-http` now accepts only localhost, 127.x and ::1 base URLs.
- `firewall validate` now reports a duplicate `rule_key` (`FW-21`) even when one of the colliding rows also has another error. `firewall delete` no longer labels every "already absent" rule with the last segment pair, and a blocked segment pair whose rows all failed parsing no longer says "none of its 0 rows".
- Rule IDs: the plan-time duplicate-priority check is now `FW-35` (it shared `FW-21` with duplicate `rule_key`), and the plan-time duplicate-`rule_key` check is `FW-21` (it used `FW-20`, the priority range check).
- The MCP server briefly added here now lives in its own repository, [edgeconnect-mcp](https://github.com/Crypto-Gi/edgeconnect-mcp).
- New `setup.sh` (the same file is in edgeconnect-preconfig and edgeconnect-mcp) installs this CLI, the preconfig toolkit and both agent skills from `main` in one step, with one shared `.env`. It asks for the install folder, then whether the skills go only in that folder or in your user account; re-running it updates both repositories and keeps what is already installed. It also writes an `AGENTS.md` (which tool to use for which task) and a `CLAUDE.md` into the install folder, and runs on macOS's bash 3.2.
- Licensed under the Apache License 2.0 (previously BSD-3-Clause), with a `NOTICE`.
- The agent skill now says up front that the CLI is built for a person at a terminal: the agent prepares the CSVs and hands each write to the user as one block to paste. It uses an EdgeConnect MCP server only for reads and for tasks this CLI does not cover.
- Tests and docs use neutral Orchestrator nicknames.

## 1.2.4 — 2026-10-16

- A `--dry-run` that skips rows (application groups and definitions return exit 5 for skips) is now summarized as `DRY_RUN` with "changes made: no". It was reported as `PARTIAL` with "changes made: possibly", although a dry run never writes. Found in a lab dry run of `application_groups_mixed.csv`.
- Before `APPLY`, application-definition runs now list every AppExpress change: `AppExpress: remove 1 (Zoom), change 1 to monitor-only (Teams), add 1 (Webex)`. Since 1.2.3 the short change table had left these out, so a blank `AppExpressMode` (which means `OFF`) could remove a fully configured AppExpress entry, and `MONITOR` could turn off `appExpressEnabled`, without either being shown. The line appears only when AppExpress actually changes.
- A run that stops after it has started writing is now reported as PARTIAL (exit 5) with "changes made: possibly", never as drift, validation or refusal with "nothing was written". Firewall, address/service group and application-definition deletion record what was deleted, mark the rest `NOT DELETED` with the reason, and still write the report; firewall deletion continues with independent segment pairs, object deletion stops at the first problem. A failed read before a later firewall segment pair no longer discards the results of pairs already written. When no per-row result exists, rows are marked `UNKNOWN` instead of `NOT ATTEMPTED`.
- `firewall delete` now applies the `FW-30` check that deploy already had: a segment pair whose policy options are not `merge=false` / `templateApply=false` blocks the deletion before confirmation, and the deletion is written with those contract-tested options. Previously it posted whatever options the live policy carried. Firewall rollback also sends those options when the baseline had none.
- Each segment pair written in one run now gets its own Orchestrator audit comment, `<run ref>-<segment map>`, and audit correlation matches that exact comment. Previously every pair shared one comment, so a completed audit entry for one pair could mark a different pair, even one whose own save failed, as audit-verified. `firewall delete` comments also include the segment map.
- HTTP redirects from Orchestrator are refused with a clear error. Previously the client followed them and resent the API key to the new location, even another host or plain HTTP, and a redirected POST was silently turned into a GET that reported success.

## 1.2.3 — 2026-10-03

- Fixed firewall rules and template ACL entries that appliances refused to compile. Orchestrator stores and distributes rules with a single address and no prefix length (`10.1.1.1`) or with a dotted mask, and its audit log reports success, but 9.6.4 appliances raise the service-affecting alarm "ACL rule has invalid syntax" and do not enforce the rule. These values are now sent as `/32` (`/128`) and prefix lengths, with warnings `FW-33` / `ACL-29`. Proven with disabled probe rules on a lab appliance and matched against a production alarm export (185 of 185 rejected rules had such a value; none of 590 accepted rules did).
- After every firewall and template ACL write, appliance alarms are read for the verified appliances and each rejected row is reported as `FAILED` with the appliance and reason; the run ends PARTIAL instead of SUCCESS. Configuration readback alone cannot detect this.
- A deployed rule that differs only by the missing prefix now blocks with `FW-34` and a fix, and strict `firewall delete` / `template-acls delete` still match such rules so they can be removed with the original CSV.
- Example template ACL files no longer use single addresses without `/32` or dotted masks as valid entries.
- `firewall delete` now waits until every reachable appliance no longer holds the deleted rules and reports `DELETE UNVERIFIED` with the appliance otherwise; previously it reported SUCCESS from the central readback alone.
- Several Orchestrators can be configured in one `.env`: `orch_1=prod`, `orch_2=test`, then `prod_base_url` / `prod_api_key` and so on. Choose per command with the global `--orchestrator <nickname>`, set `orch_default`, or pick from a menu when neither is given. The target Orchestrator is shown before every write or deletion confirmation and in the RUN SUMMARY. Existing single-Orchestrator `.env` files work unchanged.
- Plan and inventory files now record the Orchestrator they were made from. `apply --approved-plan` and `firewall deploy --inventory` refuse to use them on a different Orchestrator, before approval, and the message names only the Orchestrator the file belongs to.
- Every command now ends with a RUN SUMMARY: result, whether changes were made, exit-code meaning, counts per segment pair or template group, every blocking issue with its rule code and fix, warnings, appliance states with hostnames, and the next step. It is shown for success, dry run, blocked, refused, drift, partial, interrupted, and unexpected errors.
- Every run is appended automatically to `reports/<workflow>.log` and `reports/<workflow>.jsonl` (timestamped, one record per run, one pair of files per workflow). `--report-dir` or `EDGECONNECT_REPORT_DIR` relocates the log; `--report-dir ""` disables it.
- `--report <file>` is now written on every outcome, including approval refusal and errors, and includes the summary, so a failed run can no longer leave an older run's report in place.
- Before `APPLY`, a short change table replaces the full JSON preview; the full preview is in the report log and printed with `-v`. Large previews are no longer printed at the end of a run without `-v`.
- The summary includes a per-row outcome table: one line per CSV row with `BLOCKED`, `INVALID`, `NOT ATTEMPTED` (held back by another row in the same segment pair, template group, or CSV), `WOULD CREATE`, `CREATED`, `ALREADY PRESENT`, `SKIPPED`, `FAILED` and so on, with the reason. Problem rows are listed first. Template ACL plan entries now record their CSV row.
- Every `--report` file and report-log record starts with the same top-level `status`, `exit_code`, `changes_written`, `timestamp`, `run_id`, `workflow`, `orchestrator` and `orchestrator_url`, using the same status words for every workflow.
- New `edgeconnect-auto report summarize <file> [--last N] [--rows-csv rows.csv]` prints the summary and row table of a saved report, plan file, or `.jsonl` log, including reports written by older versions, without contacting Orchestrator.
- Firewall planning messages now carry rule codes and fixes. A priority conflict (`FW-24`) names the zone pair, shows the existing rule and the CSV row side by side, and suggests the nearest free priority. New codes: `FW-31` unknown segment pair, `FW-32` missing zone.
- Fixed a safety-order bug found by the full example suite: `firewall deploy` no longer offers to create missing zones when the CSV already has validation errors. The invalid CSV is reported first and no zone write is offered.
- Added strict `template-acls delete`: a complete ACL must exactly match the CSV; firewall/template/appliance route-map references and unreachable associated targets block; three-stage confirmation is required; the template group, selection, associations and unrelated configuration are preserved; exact central and associated-appliance copies are removed and verified. Appliance passthrough cleanup is required because native merge omission leaves the old ACL on the appliance.
- Full live 9.7.1 creation/deletion/recreation testing covered 54 firewall rules, 70 template ACL entries, 11 application groups, 48 definitions plus six AppExpress rows, 29 service groups and 25 address groups. All restored collections and `0.NE` firewall/ACL readbacks matched their saved baseline fingerprints exactly; 288 audit actions had zero failures; every valid CSV reran as a no-op.
- Live testing also fixed final ACL verification losing its specific mismatch/leftover state, per-row summaries duplicating string row numbers, and incomplete counts/status text for appliance-only ACL cleanup, app-group previews and firewall deletion.

## 1.2.2 — 2026-09-29

- Consolidated the two example folders into `examples/edgeconnect`. The lab suite's valid and invalid rows are merged into the `*_valid.csv` and `*_mixed.csv` files (firewall rules use placeholder zones and are disabled).
- Every object the examples and starter templates create now has a `test-51-` name (`test-51-ag-*`, `test-51-sg-*`, `test-51-*` applications and application groups, ACLs `test-51-acl` and `test-51-matrix`, firewall keys `test-51-fw-*`), so test objects are easy to find and clean up.
- Added `template_acls_test3_valid.csv` (55 valid entries for template group `test3`) and `template_acls_test3_invalid.csv` (40 rows with one deliberate mistake each) for manual template ACL testing. The valid file was deployed to a lab appliance and verified.
- Fixed the merged application-definition example: two rows reused an existing protocol and TCP port identity and were skipped at plan time. A new test requires every valid example to plan with no conflicts.
- Fixed `ApplicationGroup=any` in template ACLs, which was treated as a missing group.
- Fixed a false `PARTIAL` after template ACL deploys: the appliance reachability check ran right after the write, saw a brief "unreachable" while the template was applying, and gave up. It now retries until the verification timeout.

## 1.2.1 — 2026-09-29

- Fixed a 1.2.0 regression: deletion reference checks, and any other workflow that reads every segment pair, failed with `security policy response for map X has an invalid shape` when a segment pair had no firewall policy. Orchestrator returns `"data": null` for such pairs; it is now read as an empty policy, while genuinely malformed responses are still rejected.

## 1.2.0 — 2026-09-29

### Template ACL parity


- Template ACL CSV now matches the firewall CSV's match fields. New columns: `SourceAddressGroup`, `DestinationAddressGroup`, `EitherAddressGroup`, `SourceServiceGroup`, `DestinationServiceGroup`, `EitherServiceGroup`, and per-side `SourceSegment`, `DestinationSegment`, `EitherSegment` (segment names resolved to `*_vrf` IDs at runtime). Generated entries reproduce GUI-created 9.7.1 rules key for key. The original 20-column header is still accepted.
- New checks: `ACL-24` (literal and group on the same side), dimension-wide `DIR-01` (Either versus Source/Destination across literals and groups), `ACL-26` (group-name grammar; comma lists rejected because the appliance silently drops the second group), `ACL-27` (single segment), `DEP-03` and `DEP-07` (groups and segments must exist, re-checked before write).
- `ACL-25` guard: a target template group with Security Policies selected in replace mode is blocked when that template has no rules and warned when it has rules. A lab incident showed that associating such a group wipes the appliance firewall policy.
- Address and service group deletion is now also blocked by template ACL references, including `|` group lists.
- ACL no-op and appliance verification normalize `*_vrf` values (integer centrally, string on the appliance) and `|` list spacing.

### Release hardening (from fuzz and operator testing)

- Safety: collision detection no longer fails open when an appliance reports `gms_marked` as missing, `null`, a string, or `0`, or when its software version cannot be parsed. Automatic priorities skip appliance-local rules. Application-group parent cycles through existing groups are detected.
- Payload correctness: `|` lists are trimmed before sending, and a reordered list is a no-op rather than a conflict. Non-ASCII digits and leading zeros are rejected in ports, protocols, IP octets and masks. The domain check is stricter. IPv6 zone IDs are rejected. `Application=any` is rejected in ACLs (`ACL-28`).
- Validation: `firewall validate` catches duplicate `rule_key` (`FW-21`). Invisible Unicode characters are rejected outside free text. Duplicates are case-insensitive and network-aware. Malformed CSV syntax reports `CSV-11` with a line number. The strict application-group parser used by delete now matches deploy validation. New address-group warning `AG-17` for exclusions outside every inclusion.
- Errors and reports: unexpected Orchestrator response shapes raise clear `ResponseFormatError` messages, and a malformed zone container is never treated as empty. `-vv` prints a traceback for runtime errors. A blocked deploy still writes its `--report` file (`status: BLOCKED`). The auto-priority error now says to set an explicit priority.
- Template ACL application dependencies also accept disabled user-defined applications that the wildcard search omits.

## 1.1.2 — 2026-09-29

- Fixed `string indices must be integers, not 'str'` during firewall discovery and application-definition planning when Orchestrator returns user-defined port/protocol, domain, or compound definitions in a shape other than the tested list-of-records layout. Non-record entries are skipped; missing referenced applications still fall back to exact wildcard search or block with `DEP-01`. The failure occurred before any write.
- Documented that `-v`, `--dotenv`, and `--allow-http` must precede the workflow name, and how to capture a full traceback with a read-only dry run.

## 1.1.1 — 2026-09-25

- Reject template ACL CSV rows that reuse the same `TemplateGroup + ACLName` with inconsistent `ACLUpdateMode` or `TemplateApplyMode` values.

## 1.1.0 — 2026-09-25

- Replaced the large generated comprehensive/pre-release corpus with a compact public example suite under `examples/edgeconnect`: one comprehensive valid CSV and one intentionally mixed valid/invalid CSV per workflow. The six clean starters remain under `templates/edgeconnect`; focused regression inputs remain generated in temporary test directories.
- Approved 9.7.1 live testing found and fixed three release blockers: simple either-domain compounds now require `DOMAIN` unless another compound criterion exists; reachable missing/mismatched firewall ACLs block before submission; deleting the final firewall rule removes its empty zone-pair container. ICMPV6 native service import remains a documented release-specific failure.
- Added complete CSV constraint validation based on vendor documentation and approved 9.7.1 API/importer probes. Every row now reports all problems with a rule ID, field, value, fix, and blocked scope. `firewall validate` returns structured issues and warnings.
- Firewall and template ACL IP fields accept documented policy formats: octet ranges, whole-octet wildcards, dotted masks, and IPv6. GUI-compatibility forms and host bits produce warnings.
- Added the `tcp/udp` protocol, firewall domain columns, and case-insensitive application references. `application=any` is now rejected, as is a nonzero `logging_level` when logging is disabled.
- Enforced ACL priority 1–65535, 64-character group names, nesting depth across existing groups, required inclusions, include/exclude overlap checks, ICMP type ranges, empty application groups, and the 50-application AppExpress limit.
- Compound definitions now send comma-separated lists. Geo, interface-label, DSCP, and address-map values are normalized and resolved against live inventory. Definitions deployed earlier with pipe lists, country names, or interface names will show as conflicts and are never overwritten.
- Deletion now blocks groups and applications that global firewall rules or central template ACLs still reference.
- Rejected malformed CSV structure: short rows, empty files, control characters, empty or duplicate list members, and wrong separators.
- Removed the standalone AppExpress CLI and CSV; `AppExpressMode` in application-definition CSV is now the single source of truth for OFF/MONITOR planning, deployment, verification, and deletion.
- Added exclusive firewall ACL references with central template resolution, ambiguity and drift checks, and exact global/effective/appliance verification. Live 9.7.1 pre-release testing later tightened safety: a missing or mismatched ACL on a reachable appliance now blocks the pair because Orchestrator rejects the complete security-map update; unreachable/paused targets remain warnings/PARTIAL.
- Added merge-only CSV management for template-group ACLs, including priority overwrite semantics, preservation, drift checks, typed creation/selection/mode confirmations, central and appliance verification, and no automatic association.
- Reworked the main README and operator/CSV guides for source-verified onboarding, expected outcomes, navigation, support guidance, and release limitations.
- Corrected linked operator and implementation documentation for strict deletion, compound deletion, and conflict-isolation behavior.
- Documented `broad_match_ack` across README, quick start, CSV reference, operator, security, requirements, and lab guides, including the critical distinction between match-all acknowledgment and match-nothing behavior.

## 1.0.0 — 2026-09-20

- Added missing-zone detection, explicit per-zone approval, full-collection preservation, readback verification, and firewall replanning.
- Integrated `AppExpressMode` desired state into application-definition planning, deployment, verification, and cleanup.
- Isolated conflicting application definitions and invalid or dependent application groups while returning explicit partial status.
- Added strict per-workflow CSV deletion for firewall rules, native groups, application groups, application definitions with AppExpress, and standalone AppExpress entries.
- Added complete deletion tables, generated confirmation codes, final responsibility acknowledgment, drift checks, dependency checks, and absence verification.
- Defaulted configuration loading to `./.env` in the current directory with process-environment precedence and an explicit `--dotenv` override.
- Aligned native address-group validation with documented IPv4 address, mask, range, and wildcard forms; IPv6 is rejected before native import on the tested 9.7.1 release.
- Normalized server-managed native group `type: null` while preserving exact semantic rule-body verification.
- Expanded deterministic comprehensive valid/invalid datasets and corrected the valid IP-protocol fixture for end-to-end lab deployment.
- Added a beginner-friendly resolved firewall CSV guide and a reusable project documentation skill.
- Expanded standard-library unit, contract, safety, cleanup, drift, and partial-result coverage to 96 tests.

## 0.1.0 — 2026-09-19

- Initial safety-focused EdgeConnect Orchestrator automation release.
- Added global firewall policy validation, planning, deployment, verification, and segment-pair rollback.
- Added native address/service-group bulk import workflows.
- Added application-group, application-definition, compound, and AppExpress Monitor workflows.
- Added CSV templates, operator documentation, redacted reports, dry-run, drift protection, and exact write confirmation.
- Added BSD 3-Clause licensing, a standalone quick start, and guarded comprehensive-lab cleanup tooling.
