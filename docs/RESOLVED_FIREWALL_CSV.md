# Understanding the Resolved Firewall CSV

This guide explains `--resolved-csv` for someone using the firewall workflow for the first time.

## The short version

A resolved firewall CSV is a finalized, reusable copy of the firewall rules that were eligible during planning.

Use it when the input CSV leaves priorities blank. The automation assigns safe priorities, writes those exact values into the resolved CSV, and requires future reruns to use that file instead of the original priority-less CSV.

If every input rule already has an explicit priority, the resolved CSV is optional. It can still be useful as a normalized review artifact.

## A simple analogy

Imagine a draft appointment list:

```text
Alice — Monday — time not selected
Bob   — Monday — 10:00
```

The finalized list might be:

```text
Alice — Monday — 09:00
Bob   — Monday — 10:00
```

The original list records the request. The finalized list records the exact schedule that everyone must reuse.

A resolved firewall CSV serves the same purpose for rule priorities.

## The three files in a firewall run

| File | Role | Can it be reused as CSV input? |
|---|---|---:|
| Original CSV | Human-authored intent | Yes, unless it contained blank priorities that were allocated |
| Resolved CSV | Final eligible rows with concrete priorities and normalized values | Yes |
| JSON report | Preview, fingerprints, target states, execution and verification evidence | No |

The resolved CSV is not:

- A backup of the existing Orchestrator policy
- A rollback file
- An API response
- Proof that every appliance received the policy
- A second CSV merged with the original

## Why firewall priority matters

Within a zone pair, lower priorities are evaluated first:

```text
20000  allow DNS
20010  deny other traffic
65535  final deny-all
```

Changing a priority can change which rule matches first. An automatically assigned priority therefore becomes part of the rule's stable identity and must be retained.

## Before-and-after example

Original input:

```csv
rule_key,priority,source_zone,destination_zone,action
rule-001,,INSIDE,OUTSIDE,allow
rule-002,30010,INSIDE,OUTSIDE,deny
```

If automatic allocation is safe, the resolved output might contain:

```csv
rule_key,priority,source_zone,destination_zone,action
rule-001,20000,INSIDE,OUTSIDE,allow
rule-002,30010,INSIDE,OUTSIDE,deny
```

The important change is that `rule-001` now has a concrete priority.

The real resolved file contains every supported firewall column, normalized booleans such as `TRUE` and `FALSE`, and permissions restricted to the current user.

## What happens during planning

When you run:

```bash
edgeconnect-auto firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_preview.json \
  --dry-run
```

the workflow:

1. Reads the original CSV.
2. Discovers segments, zones, objects, policies and appliance state.
3. Validates dependencies and priority collisions.
4. Resolves blank priorities when safe.
5. Builds the final candidate for every eligible segment pair.
6. Writes eligible finalized rows to the resolved CSV.
7. Writes detailed preview evidence to the JSON report.
8. Performs no Orchestrator write because `--dry-run` is present.

Writing a resolved CSV is a local file operation. It can happen during dry-run.

## When automatic priority allocation is allowed

A blank priority can be allocated only when the target zone pair is:

- Empty, or
- Contains only a verified priority `65535` allow-all or deny-all catch-all

Allocation starts at `20000` and increments by `10`. Explicit CSV priorities are reserved first.

The tool does not silently search for gaps among ordinary existing rules. If a zone pair already contains non-default rules, add explicit priorities to the input CSV.

## When `--resolved-csv` is required

It is required when at least one eligible rule receives an automatically assigned priority.

Without it, the command stops with:

```text
--resolved-csv is required when priorities are automatically allocated
```

## When it is optional

It is optional when every rule already has an explicit priority.

For example, the canonical firewall template uses explicit priorities such as `41000`, `41010`, and `41020`.

This command is sufficient:

```bash
edgeconnect-auto firewall deploy \
  --csv templates/edgeconnect/firewall_rules.csv \
  --report reports/firewall-preview.json \
  --dry-run
```

Adding `--resolved-csv` is still allowed if you want a normalized review artifact.

## Eligible rows only

The resolved CSV contains rows from eligible segment pairs only.

If one segment pair is invalid but another is eligible, the file is a reduced artifact. The separate `firewall plan` command returns exit code `5`, and an applied reduced deployment reports partial status. The one-command `firewall deploy --dry-run` currently returns `0` when at least one pair is eligible, so always inspect pair eligibility and omitted rows rather than treating the exit code alone as proof that the artifact is complete.

If no segment pair is eligible, `resolved_rows` is empty and the command does not create or update the resolved CSV. A file left over at the same path from an older run may therefore be stale. Use a unique filename per run or verify its timestamp and contents.

## The correct rerun workflow

### First run with blank priorities

```bash
edgeconnect-auto firewall deploy \
  --csv firewall_rules.csv \
  --resolved-csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_preview.json \
  --dry-run
```

Review the generated priority values, pair eligibility and complete candidate.

### Approved deployment

Use the reviewed resolved CSV as input:

```bash
edgeconnect-auto firewall deploy \
  --csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_result.json
```

Type `APPLY` only after reviewing the exact preview.

### Later audit or no-op check

```bash
edgeconnect-auto firewall deploy \
  --csv reports/firewall_rules_resolved.csv \
  --report reports/firewall_noop.json \
  --dry-run
```

Exact existing rules should be reported as no-ops.

## Why not reuse the original priority-less CSV?

Suppose the first run assigns priority `20000`. After deployment, the zone pair is no longer empty. A later run of the original blank-priority CSV no longer has the same safe allocation conditions and must not invent a new identity.

The resolved CSV removes that ambiguity:

```text
rule-001 is priority 20000
```

The workflow can then compare the exact rule and recognize a no-op.

## Resolved CSV versus JSON report

Use the resolved CSV when you need:

- Reusable firewall input
- Concrete assigned priorities
- A normalized spreadsheet for review

Use the JSON report when you need:

- Baseline and candidate fingerprints
- Eligible and ineligible pair details
- Appliance reachability and verification
- Runtime result and recovery status
- A report fingerprint for evidence integrity

Keep both when priorities were generated.

## Understanding exit codes

| Exit | Meaning for this workflow |
|---:|---|
| `0` | Successful dry-run, verified success or no-op |
| `2` | No eligible segment pair or validation failure |
| `3` | Approval refused or non-interactive write attempted |
| `5` | Partial/critical result, including reduced eligible pairs or unreachable targets |

A resolved CSV does not turn exit code `5` into success. It records finalized eligible rows; target verification remains a separate requirement.

## Troubleshooting

### `--resolved-csv is required`

At least one eligible row has a blank priority. Add the option and review the generated file.

### `resolved_rows` is empty

No segment pair was eligible. Fix the reported dependencies, zones, collisions or validation errors first.

### The file was not updated

No resolved rows were available, so the writer did not run. Do not assume an older file at that path represents the current plan.

### Deployment is `PARTIAL` even though priorities resolved

Priority resolution and appliance verification are different stages. Unreachable or paused appliances can produce `PARTIAL` even when Orchestrator saved the policy and reachable appliances verified it.

### All priorities are already filled in

The option is optional. Keep it only if you want a normalized artifact.

## One rule to remember

> If the input contains blank priorities, generate, review and retain the resolved CSV. Use that resolved CSV for deployment and every future rerun.
