# Changelog

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
