# Changelog

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
