# EdgeConnect Firewall API Automation — Latest Agreed Implementation Requirements

**Status:** Design baseline as of 2026-09-18. This document contains the current requirements only; superseded ideas such as skipping invalid rules, template-based firewall deployment, and checking only the E2E zoning toggle are intentionally excluded.

**Safety boundary:** This document does not authorize lab or production writes. Read-only discovery is separate from approval to create zones, application definitions, or firewall policies. Never include credentials, cookies, CSRF tokens, or API keys in logs, plans, reports, fixtures, or documentation.

## 1. Objective

Build production-quality, CSV-driven automation following:

```text
Understand → Inventory → Validate → Preview → Approve → Deploy → Verify
```

No firewall rules may be submitted until the complete CSV, all dependencies, existing policy state, and priority plan pass prechecks.

## 2. Supported Configuration Surface

- Centrally managed **Routing Segmentation (VRF) → Global Firewall Policies** only.
- Templates and appliance-local policy management are out of scope.
- Policy hierarchy:

```text
Source segment / destination segment pair
  └── Source zone / destination zone pair
        └── Priority-keyed firewall rules
```

- Rules within the same segment-pair/zone-pair scope are evaluated in ascending numeric priority. The first matching rule applies its action; otherwise evaluation continues.
- Target compatibility goal: Orchestrator 9.3.x and later, with per-release capability checks. ECOS target is 9.5 and later. Do not claim support solely from version numbers; required endpoints and fields must be discovered.
- Latest supplied API reference: `swagger_file_api_9.7.1.42046`. The earlier supplied export remains useful for compatibility differences. Both files report `info.version: 7.2.0`, so runtime release must be retrieved independently.

## 3. Routing Segmentation Prerequisite

Check:

```text
GET /vrf/config/enable
```

Expected response:

```json
{"enable": true}
```

If routing segmentation is disabled:

1. Stop global firewall deployment.
2. Do not fall back to templates.
3. In dry-run, report the prerequisite only; make no change.
4. A separate enable workflow may be offered using `POST /vrf/config/enable` only after displaying:
   - Exact target and current state
   - Explicit warning that connectivity can be lost
   - All-appliance impact
   - Validation and recovery plan
   - A fresh one-time confirmation code that the user must type exactly
5. Enabling segmentation is a separate approval and does not approve firewall deployment.

The 9.7.1 Swagger states that enabling routing segmentation also enables E2E zoning and triggers orchestration to all managed appliances. Disabling is not a guaranteed simple rollback because non-default segments must first be removed. Automation must never delete segments as rollback.

## 4. Required Firewall Prechecks

Prechecks are fail-closed per source/destination segment pair, which is the API write and rollback unit. Collect all detectable errors across the input in one report. Any invalid rule, missing dependency, priority conflict, incomplete inventory, or invalid zone pair makes that entire segment pair ineligible; no rules from that segment pair are written. Other fully valid segment pairs may proceed after preview and approval.

Validate:

- CSV schema, required values, encoding, duplicate headers and row shape
- Segment names/IDs and segment-pair scope
- Source and destination zones in the correct segment context
- Address/subnet syntax and address groups
- Protocols, ports, and service groups
- Applications and application groups
- Supported actions, logging, and enabled state
- Priority ordering and collisions
- Duplicate rules and duplicate CSV priorities
- Existing rules in every affected segment-pair/zone-pair
- Complete, successful inventories; unavailable inventory is fatal, not “object missing”
- Runtime capabilities for every requested field
- Routing segmentation enabled
- Target appliances, paused orchestration, reachability, and permissions

Missing non-zone dependencies are not created by the firewall workflow. Report them and stop. Application-definition creation is a separate approved workflow; after remediation, rerun all firewall prechecks.

## 5. Missing Zones and New Zone Pairs

### 5.1 Important distinction

A **zone object** and a **zone-pair policy container** are different:

- A missing zone is a dependency requiring a separate zone change.
- No separate zone-pair create endpoint is documented. If both zone objects exist and the pair has no policy yet, the pair is introduced by the approved global security-policy map submission.

### 5.2 Missing-zone workflow

If the CSV references missing zone objects:

1. Finish discovery and list every missing zone with its referenced segment(s) and affected CSV rows.
2. Stop before firewall policy writes.
3. Ask the user to confirm creation of each missing zone individually.
4. If any zone is declined, unanswered, invalid, conflicting, or cannot be created and verified, stop the entire workflow.
5. If all are approved, create zones as a separate change.
6. Verify the complete zone collection, assigned IDs, all-VRF/segment mappings, and relevant appliance state.
7. Rerun the entire firewall inventory, validation, priority planning, and preview from the beginning.
8. Obtain separate firewall deployment approval.

### 5.3 Safe zone API handling

Relevant APIs:

```text
GET  /zones
GET  /zones?allVRFZones=true
GET  /zones/nextId
GET  /zones/vrfZonesMap
GET  /zones/vrfSegmentZonesMap
POST /zones?deleteDependencies=false
```

`POST /zones` replaces the entire zone collection; any omitted zone is deleted. Therefore:

- Retrieve a fresh complete base-zone collection.
- Preserve every existing zone semantically unchanged.
- Add only individually approved missing zones.
- Allocate from `GET /zones/nextId`; do not set nextId separately unless lab contract testing proves it necessary.
- Use `deleteDependencies=false`.
- Re-read immediately before POST and abort if the inventory fingerprint changed. No conditional-write API is documented, so the race cannot be eliminated completely.
- Valid names contain only letters, numbers, and underscores; `Default` is reserved.
- Verify base zones and generated segment-specific IDs/mappings after the 204 response.

A 204 response means the zone configuration was accepted and appliances were placed in pending orchestration. It does not prove appliance convergence.

Zone changes can affect all managed appliances. Never use deletion or renaming as an automatic rollback. Any rollback requires a separately reviewed full-zone payload and dependency analysis.

## 6. Priority Rules

Priority scope is one source/destination segment pair plus one source/destination zone pair.

### Explicit CSV priority

- Use the specified priority only if it is valid and unoccupied in that exact scope.
- Check collisions with existing rules and all CSV rows.
- Any collision blocks the complete batch.
- Never overwrite or modify the existing rule.

### Missing CSV priority

Automatic allocation is allowed only when the existing zone pair:

- Is empty; or
- Contains solely the priority `65535` allow-all or deny-all catch-all.

The tool must inspect the actual 65535 match and action; priority alone does not prove it is a catch-all.

When automatic allocation is permitted:

1. Reserve explicit CSV priorities first.
2. Assign missing priorities in CSV order from 20000 upward, skipping explicit CSV reservations.
3. Keep generated ordinary rules below 65535.
4. Preserve the existing 65535 catch-all unchanged.
5. Show the final first-match order in preview.

If any other existing global rule is present and any incoming row lacks a priority, reject that zone pair and therefore its entire containing segment pair. Ask the user to add explicit priorities to the CSV or prepare a clean zone pair manually. Do not clean rules or search for gaps around existing non-default rules. For appliance-local rules, compare priority numbers only: an exact local/global priority collision invalidates the segment pair with an explicit explanation; different local priorities need no further semantic analysis.

After a successful automatic allocation, output a resolved CSV/plan containing the assigned priorities. A later rerun of the original priority-less CSV will encounter the now-populated pair and must stop rather than generate different identities.

Maximum supported priority from the agreed requirement is 65535. No lower bound was established for explicit priorities; validate it against runtime behavior before writes.

## 7. Phase-One Firewall Fields

Required capability families:

- Source and destination segments
- Source and destination zones
- IP/subnet criteria and address groups
- Protocol and source/destination ports
- Service groups
- Applications and application groups
- Actions: allow, deny, inspect
- Logging and logging level
- Enabled/disabled state
- Priority
- Description/comment

The global policy rule is represented under:

```text
data.map1.<sourceZoneId_destinationZoneId>.prio.<priority>
```

The supplied schema still loosely types `match`, `misc`, and `set`, but 9.7.1 lab readbacks confirm `set.action` values `allow`, `deny`, and `inspect`; `misc.rule` values `enable`/`disable`; `misc.logging` values `enable`/`disable`; and logging priority 0–7. Confirmed match keys are `application`, `app_group`, `src_ip`, `dst_ip`, `either_ip`, `protocol`, `src_port`, `dst_port`, `either_port`, `src_addrgrp_groups`, `dst_addrgrp_groups`, `either_addrgrp_groups`, `src_srvcgrp_groups`, `dst_srvcgrp_groups`, `either_srvcgrp_groups`, and `either_dns`. Requested but unverified fields must block validation rather than be ignored.

URL matching is phase two. An approved disabled-rule probe on Orchestrator 9.7.1 with reachable ECOS 9.5.4.1 submitted `match.url`; the server returned 204 but silently dropped the URL criterion and stored a rule with no match criteria. The rollback restored baseline. Phase-one validation must reject URL columns/values. Never send `match.url`, and always fail normalized candidate/readback comparison if any requested criterion disappears.

## 8. Phase-One CSV Intent

The template should contain network-engineer-friendly names rather than raw IDs. Internally resolve names to IDs after complete inventory.

Core columns:

```text
rule_key
rule_name
description
enabled
priority
source_segment
destination_segment
source_zone
destination_zone
source_address
source_address_group
destination_address
destination_address_group
application
application_group
protocol
source_port
destination_port
service_group
action
logging
logging_level
```

Rules:

- `rule_key` is a local stable identity; it is not a documented native rule UUID.
- Lab testing confirms literal address and address-group criteria can coexist in the same source or destination selector; preserve both when supplied and validated.
- Lab testing confirms literal port and service-group criteria can coexist in the same source or destination selector; preserve both when supplied and validated.
- Multi-value IP/port cells use `|`; port ranges use `-` (for example `10.1.1.1/32|10.1.1.2/32` and `1000-1002|1010`).
- Ports require compatible protocol semantics.
- A rule with no match conditions requires explicit acknowledgement because it is broad.
- Unsupported columns or combinations are errors.
- CSV values must never silently override existing remote state.

## 9. Dependency Inventories

Collect each inventory once per plan and track completeness:

- Runtime Orchestrator and ECOS versions
- Routing segments and configured segment maps
- Zones and segment-zone IDs
- Existing global policies in every affected scope
- Address groups
- Service groups
- Applications: built-in and user-defined
- Application groups
- Protocol references
- Target appliances, associations, reachability, and paused orchestration

Inventory statuses must distinguish `complete`, `partial`, `unavailable`, `permission_denied`, and `unsupported`. Anything other than complete for a required namespace blocks firewall deployment.

## 10. Global Policy Write Safety

Relevant APIs:

```text
GET  /vrf/config/securityPolicies?map=<sourceSegmentId>_<destinationSegmentId>
POST /vrf/config/securityPolicies?map=<sourceSegmentId>_<destinationSegmentId>&comment=<run-reference>
```

No dedicated global per-rule create/delete/reorder API is documented. The POST receives a policy map. Latest Swagger describes:

- `merge=false`: replacement in orchestration range
- `merge=true`: merge with existing policies
- `templateApply=true`: standard policy orchestration

The earlier supplied export contradicts the latest `templateApply` guidance. Before writes, lab evidence must confirm the exact target release behavior, including preservation of every existing rule and settings. Excluding templates does not make the POST append-only.

The implementation must:

- Read and fingerprint the current policy.
- Build a candidate preserving all existing entries exactly while adding approved rules only.
- Show a normalized before/after diff.
- Re-read immediately before POST and abort on drift.
- Never delete, alter, or reprioritize existing entries.
- Never submit after any failed precheck.
- Add a unique audit comment/run reference without secrets.

## 11. Verification After Every API Call

Validate expected status, media type, and response shape. Do not treat `False`, `None`, an error object, HTML, or empty unexpected content as valid inventory.

For global firewall deployment, separate three states:

```text
Request accepted → Orchestrator saved state verified → Appliance convergence verified
```

The 9.7.1 global policy POST documents `204 No Content` and says changes are queued. It does not return a deployment GUID or completion body.

Verification sequence:

1. Validate POST status.
2. GET the exact segment-map policy and verify:
   - Every new rule exists with expected match/action/misc/priority
   - All prior rules and settings remain unchanged
3. Determine expected target appliances and check paused/reachability states.
4. Use bounded, low-frequency fresh reads:
   ```text
   GET /securityMaps?nePk=<target>&cached=false
   ```
5. Compare effective policy after first validating how global segment policies are represented on appliances.
6. Query audit/action evidence using time, user, audit comment, and target.
7. Report each target as verified, pending, failed, unreachable, paused, or unknown.

Audit APIs:

```text
GET /action
GET /action/status?key=<guid>
GET /action/inProgress?user=<user>
```

`/action/status` is useful only when an operation provides a GUID. The global policy POST does not document one, and the confirmed lab save/apply entries used `guid: null`. Correlate the user-side `Segment Security Policy Changed` event by unique audit comment, time, segment map, and changed priority paths; correlate per-appliance `Apply Firewall Zone Policies` by time and `nepk`. Poll with a quiet/stability window because the appliance apply—and especially rollback audit—can appear after Orchestrator readback is already correct. A completed action with `completionStatus=true` proves that action succeeded, not that every appliance converged. Audit logs are supporting diagnostics, never the sole verification.

Cache/database sync and orchestration timing statistics are not appliance-policy completion indicators.

## 12. Missing Dependencies and Failure Handling

If any required dependency is missing, produce one complete report and mark every affected segment pair ineligible. Make zero changes for those segment pairs. Fully valid independent segment pairs may proceed. Missing approved zones may follow the separate workflow in Section 5; all other remediation is external or a separate approved automation workflow.

Error handling:

- 400: validation failure; report sanitized server error and stop
- 401: authentication failure; stop
- 403: permission failure; stop; never call object missing
- 404: distinguish missing resource from unreachable appliance
- 409/conflict or detected drift: discard plan and require re-plan
- 429: honor `Retry-After` for safe reads; bounded backoff
- Read timeout/5xx: bounded retry with jitter
- Write timeout/5xx: outcome unknown; perform readback before any retry
- Partial appliance convergence: no automatic destructive rollback; report precisely and require review

## 13. Phase-One Application Definitions

Supported initial types:

- IP protocol
- TCP port
- UDP port
- Domain name
- Compound

Defaults when omitted:

- Enabled (`disabled=false` where applicable)
- Confidence/priority = 100
- AppExpress = off

AppExpress choices are off and monitor only. Steering, transport policies, and monitor-and-steer are excluded.

Reference examples must use non-customer placeholder names. Example prefixes never grant permission to modify or delete existing definitions.

Existing identical objects are reusable/no-op. A missing application definition may be created only through its separate validated, previewed, and approved workflow. Conflicting existing identities block creation; never update or delete existing definitions.

Compound application definitions are phase one. The unified CSV includes directional/either protocol, port, IP/subnet, geo, domain, DSCP, address-map, and interface columns plus AppExpress OFF/MONITOR intent. For each criterion family, `Either` is mutually exclusive with source/destination fields. At least two meaningful attributes are required; simple single-port/domain/IP definitions must use their dedicated definition type. GUI and API tests showed sequential create IDs. Allocate `max(existing user IDs < 50000)+1`, use the same query/body ID, fingerprint/re-read immediately before POST, and abort on drift; document residual concurrency risk because POST is create-or-update. Treat unique name + semantic body as stable identity, never numeric ID: deleting a compound compacts/renumbers all remaining user records. Product automation is create-only and does not delete compounds. A compound domain selected or added in the GUI is stored directly in `src_dns`/`dst_dns`/`either_dns`; it is not required to exist as a separate DNS application definition and “Add new item” did not create one. Only explicit `DOMAIN` rows use the DNS-definition endpoint.

Additional phase-one create-only workflows:

- Address groups: use Orchestrator's native GUI bulk-import CSV unchanged: `Name,IncludedIPs,ExcludedIPs,IncludedGroups,Comment`; direct multipart/form-data `/ipObjects/addressGroup/bulkUpload` with file field `csvFile`, not the known-broken pyedgeconnect wrapper. List cells are comma-separated and CSV-quoted.
- Service groups: use Orchestrator's native GUI bulk-import CSV unchanged: `Name,Protocol,IncludedPorts,ExcludedPorts,IncludedGroups,ExcludedGroups,IcmpTypes,IcmpCodes,Comment`; direct multipart/form-data `/ipObjects/serviceGroup/bulkUpload` with `csvFile`. List cells are comma-separated and CSV-quoted. Protocols: TCP/UDP/ICMP/ICMPV6; native validation is all-or-nothing; same-name rows merge into multiple group rules; maximum nesting depth 2.
- Pre-parse native CSVs for syntax, references, cycles, existing identities and conflicts; submit only create-only eligible groups, then verify full object readback. Identical existing groups are no-ops; differing existing groups are conflicts. Contract testing confirmed address include/exclude/nesting/multi-rule and TCP/ICMP service features. The 9.7.1 native importer rejected ICMPv6 type/code despite Swagger validation; treat that as a release-specific runtime failure, never as successful creation.
- Application groups: application members plus parent-group relationships, with cycle/reference validation and full-collection preservation.
- Application definitions: one universal CSV with `definition_type` and conditional type-specific fields.
- AppExpress monitor: separate command after definitions exist; off requires no AppExpress entry. Preserve collection insertion order and append new entries. Orchestrator may reassign all numeric IDs from collection order, so verify existing/new name and semantic configuration while treating IDs as server-managed. If a monitor write fails, stop and report without deleting the valid application definition.

All object workflows are create-only: identical existing identity is a no-op; different existing content is a conflict. Runtime partial failures stop subsequent writes and are reported; no automatic deletion rollback.

Operational decisions:

- Appliance-local rules: compare priority numbers only. Exact local/global priority collision invalidates that segment pair and explains why; different priorities need no further analysis.
- Unreachable or paused targets: warn and continue; unresolved post-deployment targets produce a distinct nonzero PARTIAL result.
- Segment-pair runtime failure: restore that segment pair's exact saved baseline by removing only rules created by this run, verify restoration, and record the outcome. Continue other independent valid segment pairs even if restoration cannot be verified; mark the unresolved pair CRITICAL/PARTIAL. Never alter pre-existing rules during recovery.
- If logging is enabled and level omitted, default to level 2.
- Source and destination segment are required on every firewall CSV row.
- `rule_name` is local plan/report metadata only; API comment receives description.

## 14. Phase-Two Backlog

- Additional compound criteria or behaviors not validated in phase one
- Address-map creation and advanced attributes
- Firewall domain and geolocation matching
- Interface, DSCP, traffic behavior, and Fabric-or-Internet criteria
- URL, web category, web reputation, and bad-IP reputation
- Endpoint role, MAC, username, device, group, and user VLAN criteria
- AppExpress steering and associated transport/group configuration

Phase-one domain application definitions are different from phase-two firewall domain matching.

## 15. CLI and Approval Model

Proposed commands:

```text
edgeconnect-auto firewall validate --csv rules.csv
edgeconnect-auto firewall plan --csv rules.csv --dry-run
edgeconnect-auto zones plan-missing --from-firewall-plan <plan>
edgeconnect-auto zones apply --approved-plan <zone-plan>
edgeconnect-auto firewall apply --approved-plan <firewall-plan>
edgeconnect-auto firewall verify --run-id <id>
```

Approval boundaries:

- Dry-run performs reads and planning only.
- Normal write workflows validate and preview in one command, then require the operator to type `APPLY` exactly. Non-interactive execution refuses writes; no `--yes` bypass.
- Each missing zone is individually listed and confirmed before the aggregate zone change prompt. Zone approval is separate from firewall approval.
- Enabling routing segmentation is a separate high-risk approval with its own fresh code; normal `APPLY` is insufficient.
- Preview includes target identity, baseline fingerprints, sanitized exact payload, expected impact, validation, and recovery procedure.
- Any baseline drift invalidates approval and requires a new preview.
- Generated priorities increment by 10 from 20000. The tool writes a resolved CSV; future reruns must use that resolved CSV, not the original priority-less input.

## 16. Credentials and Logging

Use project/environment variable names such as:

```text
orchestrator_base_url
orchestrator_api_key
```

Never hard-code or display values. Prefer an expiring least-privilege API key, IP restrictions, and verified TLS/private CA bundle.

Logging:

- Default: stages, counts, validation failures, planned changes, verification status
- `-v`: endpoint/method, sanitized diffs, resolution decisions, response status and timing
- `-vv`: sanitized diagnostics without headers, cookies, credentials, or raw sensitive responses

Reports and rollback snapshots are sensitive configuration data and require restricted permissions.

## 17. Implementation Blockers Requiring Lab Evidence

Before enabling writes, confirm:

1. Global policy `merge`/`templateApply` behavior on supported releases other than the contract-tested 9.7.1 lab (`merge=false`, `templateApply=false` confirmed there)
2. New-zone propagation into segment-specific mappings and appliances
3. Multi-segment global policy representation in uncached appliance `securityMaps` (single-segment 9.7.1 shape and effective global/local rule merging are confirmed)
4. Audit correlation and convergence behavior with multiple reachable appliances or partial failure (single reachable-appliance save/apply/rollback is confirmed)
5. Application-definition AppExpress full-collection write and ID allocation for new monitored apps (off/monitor readback encodings are confirmed)
6. URL payload and availability on 9.7+
7. Behavior when orchestration is paused, appliance is unreachable, or only part of the fabric converges

These tests begin read-only. Any write, failure injection, segmentation enablement, zone creation, or policy submission requires a separately reviewed exact plan and explicit authorization.
