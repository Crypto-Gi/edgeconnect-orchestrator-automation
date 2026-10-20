---
name: managing-edgeconnect-firewall-and-objects
description: Use when generating HPE Aruba EdgeConnect Orchestrator global Routing Segmentation firewall policies (including inter-segment) or application definitions in bulk with the edgeconnect-auto CLI, or when creating, previewing or deleting zones, address groups, service groups, application groups, AppExpress Monitor entries or template-group ACLs with it, or writing, editing or fixing those CSV files from a plain-language request.
---

# Managing EdgeConnect Firewall Rules and Objects

## Overview

Turn the user's request into CSV rows, prove them with the `edgeconnect-auto` CLI, and hand the one write step to the user. The tool's main job is bulk: many global Routing Segmentation firewall policies across segment pairs, and many application definitions, neither of which the Orchestrator GUI can create in bulk. Everything else (zones, groups, application groups, template ACLs) exists so those rows have what they reference. The CLI owns validation, dependency and collision checks, priorities, preview, drift detection, readback, rollback and reports. The CSV is the only file you edit.

**You never write to the Orchestrator; the user does, by typing `APPLY` in their own terminal.** Your part:
1. **Turn the user's words into CSV rows.** Copy the matching file from `templates/edgeconnect/`, keep its header exactly, and generate the rows with a script from the user's list, table or spreadsheet (see Bulk Work). Show the user the result before running anything: every row when there are a few, a summary plus the risky rows when there are many. `references/request-to-csv.md` maps common requests to columns and shows how to edit a CSV without breaking its quoting.
2. **Run the read-only commands** below in order and stop at the first non-zero exit; show the user the message. Fix each blocking issue by editing the CSV as its `fix:` text says, then re-run. Never get past a check by blanking a field the user asked for, setting `broad_match_ack=TRUE`, or dropping a row, unless the user says yes to exactly that.
3. **Hand the write to the user** with the exact command to run in their own terminal, from the same folder. Afterwards read the result with `report summarize` and tell them what changed.

**Violating the letter of the rules is violating the spirit of the rules.** Read before writing or fixing a CSV:
- `docs/CSV_REFERENCE.md`: every column, accepted value, separator and the `blank` versus `any` rule.
- `docs/CSV_CONSTRAINTS_AND_DEPENDENCIES.md`: the full rule catalogue behind each message ID (`CSV-`, `FW-`, `ACL-`, `DIR-`, `DEP-`, `VAL-`) and the create and delete order (section 9).
- `docs/RESOLVED_FIREWALL_CSV.md`: why firewall reruns and deletes use the resolved CSV.
- `docs/OPERATOR_GUIDE.md`: what each workflow reads, writes, verifies and recovers.

`docs/`, `templates/` and `examples/` are folders of the tool's repository clone (Setup step 1).

## When to Use

- Generate many global Routing Segmentation firewall policies, within a segment or between segments, from a list, matrix or spreadsheet; or delete them
- Generate many application definitions (IP protocol, TCP or UDP port, domain, compound) with their AppExpress Monitor state; or delete them
- Create the zones, address groups, service groups and application groups those rows reference
- Merge entries into template-group ACLs, or delete a complete ACL
- Write, fix or explain one of these CSV files

**When NOT to use:** firewall templates, appliance-local rules, enabling Routing Segmentation, URL matching, AppExpress steering, or changing an existing object into something different (the tool reports a conflict instead of updating; see Common Mistakes). Preconfiguration YAML belongs to the `building-edgeconnect-preconfig-templates` skill.

## Setup

1. **Find the CLI and the clone.** Try `edgeconnect-auto --help`. Without it, run every command below as `<python> -m edgeconnect_automation ...`, where `<python>` is the interpreter it is installed in (often a project `.venv/bin/python`), or as `PYTHONPATH=<clone>/src python3 -m edgeconnect_automation ...`. The clone is the folder holding `src/edgeconnect_automation/`, two folders above this file when the skill sits in the repository. With none of these, ask the user before cloning or installing anything; `QUICKSTART.md` has the steps.
2. **Work in the user's folder that holds `.env`.** The CLI reads only `./.env` from the current folder, never a parent or home folder, unless given `--dotenv <path>`. Keep the CSVs there; run logs go to `./reports/`. Never commit CSVs, reports or `.env`, and never put an API key in a CSV or a command line.
3. **Name the Orchestrator.** When `.env` lists more than one, pass the global `--orchestrator <nickname>` before the workflow name (`edgeconnect-auto --orchestrator lab firewall ...`): without a terminal the CLI cannot show its menu and stops. Confirm the nickname with the user before the first command against it.
4. **Trust the certificate.** `transport failure: URLError` on the first call usually means the certificate is not trusted or does not match the host in `<nickname>_base_url`. For a private CA the user sets `<nickname>_ca_bundle=<pem path>`; for one self-signed certificate (common in labs) the user adds `<nickname>_tls_sha256=<SHA-256 fingerprint>` to `.env`, which the CLI checks on every connection. Give the user the line to add; never edit `.env`, the hosts file or a trust store yourself, and never relay or proxy the connection.

## Quick Reference

Every command you run is read-only: `discovery`, `firewall validate`, `--dry-run` and `report summarize` make no writes and need no terminal.

| Stage | Command you run | Purpose |
|---|---|---|
| **Inventory** | `edgeconnect-auto discovery --output reports/discovery.json` | Segmentation state, segments, zones, segment zone map, address and service groups |
| **Check offline** | `edgeconnect-auto firewall validate --csv <file>` | Firewall CSV only; every problem in every row with its rule ID and fix; no Orchestrator access |
| **Preview** | `edgeconnect-auto <workflow> deploy --csv <file> --report reports/<name>-preview.json --dry-run` | Live dependency, collision and conflict checks and the full preview; zero writes. Firewall: add `--resolved-csv reports/<name>-resolved.csv` |
| **Preview zones** | `edgeconnect-auto zones create --name <ZONE> [--name <ZONE> ...] --dry-run` | New zones only, mapped into every segment; never renames or deletes. Zone names use letters, digits and `_` only |
| **Preview deletion** | `edgeconnect-auto <workflow> delete --csv <file> --dry-run` | Exact-match deletion table and reference checks; zero writes |
| **Read a result** | `edgeconnect-auto report summarize reports/<workflow>.jsonl` | Summary and per-row table of the latest run (`--last N` for more); no Orchestrator access |

`<workflow>` is `firewall`, `template-acls`, `address-groups`, `service-groups`, `app-definitions` or `app-groups`. The user runs the same `deploy`, `delete` or `zones create` command **without `--dry-run`** in their own terminal; the CLI shows a short change table, re-reads the baseline, and asks them to type `APPLY` (a zone also `CREATE <zone>`, a new template group its exact name; deletion a generated code and a final sentence).

Exit codes: `0` success, verified no-op or clean preview; `1` runtime or API error; `2` validation failure; `3` approval refused or no terminal (nothing was written; a mistyped `APPLY` or code is safe, re-run the same command and finished rows show as already present or absent); `4` the live state changed since the preview (re-run the preview); `5` PARTIAL (rows skipped as conflicts or missing dependencies, unreachable appliances, or appliance-rejected rules: read the row table; a dry run can also exit `5`); `130` interrupted.

## Bulk Work

- **Generate, never retype.** Write a short Python script that reads the user's source (pasted table, CSV or spreadsheet export, list of hosts and ports, matrix of segments) and writes the CSV with the `csv` module. Keep the script beside the CSV so the batch can be regenerated after a fix. `references/request-to-csv.md` has generator examples.
- **Stable keys.** Derive each firewall `rule_key` from the row's own fields (`corp-to-dc-web-443`) so reruns and deletes match; keys must be unique (`FW-21`). Application definition names are their identity: one name, one meaning.
- **One pass finds every problem.** `firewall validate` reports every issue in every row at once; fix them all before the dry run.
- **Blast radius.** One bad firewall row blocks its whole segment pair: no rule in that pair is written, other pairs continue. A row with a blank segment blocks the whole file. Application definitions are independent per row: a conflict is skipped and the rest proceed (exit `5`).
- **Priorities.** Blank priorities are allocated per zone pair in CSV row order, from 20000 in steps of 10, so row order is rule order. That works only in an empty zone pair (`FW-23` otherwise); for a pair that already has rules, ask the user for a free priority range and fill it in. Always hand over the resolved CSV.
- **Show a summary.** For many rows, report counts per segment pair, zone pair and action, then list every row that is broad (`0.0.0.0/0`, `::/0`, no port, `broad_match_ack=TRUE`) or denies traffic, so the user reviews what matters.

## Workflow

1. **Pick the workflow and its file.** Firewall rules: `firewall_rules.csv`. Template ACL entries: `template_acls.csv`. Address groups: `address_groups.csv`. Service groups: `service_groups.csv`. Applications and AppExpress: `application_definitions.csv`. Application groups: `application_groups.csv`. Zones take `--name` arguments, no CSV.
2. **Order the steps.** Create address and service groups first, then application definitions, application groups, template ACLs, and firewall rules last; zones before the rules that use them. Delete in the reverse order. A row naming an object that does not exist yet is blocked (firewall: `DEP-` and exit `2`) or skipped (other workflows: exit `5`), so a request that needs a new group is two runs: the group (user applies), then the rule.
3. **Read the live names.** Run `discovery` and use the exact segment, zone and group names it returns. Never guess a name; ask the user when the request does not say which one.
4. **Write the rows** (your part 1). Fill only the columns the request needs: a blank match field means "not used", never "any".
5. **Check.** Firewall: `firewall validate` until it exits 0. Then `deploy --dry-run` (or `delete --dry-run`) for every workflow involved. Show each blocking issue with its rule ID and fix, edit, and re-run.
6. **Present the preview.** Summarise what would be created, what is already present (no-op), skipped or blocked rows with reasons, warnings such as `FW-33` (single address sent as `/32`), target appliances and any unreachable or paused ones. Ask whether to proceed.
7. **Hand over.** Give the exact command without `--dry-run`. For a firewall CSV with blank priorities, the command uses the resolved CSV (`--csv reports/<name>-resolved.csv`) so the priorities match what they previewed; that file is the source for every rerun and delete.
8. **Verify and report.** When the user says it ran, run `report summarize reports/<workflow>.jsonl` and report the status, rows created, no-ops, failures with appliance and reason, and the next step. Exit `4` means someone changed the Orchestrator in between: re-run the preview and show what moved.

## Common Mistakes

- **Wrong list separator.** `|` in firewall, template ACL and application definition CSVs; a comma inside a quoted cell in address group, service group and application group CSVs (`VAL-02` when a template ACL group cell has a comma).
- **`any`.** Only `application_group` (template ACL `ApplicationGroup`) accepts `any`. For all addresses use `0.0.0.0/0` or `::/0`; otherwise leave the cell blank.
- **Match-all by accident.** A firewall row with every match field and `acl` blank is rejected (`FW-04`) unless `broad_match_ack=TRUE`. Set it only when the user explicitly wants the rule to match everything in that zone pair.
- **Mixing directions.** In one family (addresses, address groups, ports, service groups, domains) use either the `either_` column or the source/destination columns, never both (`DIR-01`). `acl` excludes every other match column.
- **Changing an existing object.** A row identical to the live object is a no-op; a different body with the same identity (firewall priority, group name, application identity) is a conflict, not an update. To change one: delete it with a CSV holding its current exact row, the user applies, then deploy the new row.
- **Rerunning a firewall CSV with blank priorities.** Use the resolved CSV; firewall `delete` needs explicit priorities on every row. A blank priority is allocated only in an empty zone pair; in a pair that already has rules, ask the user for a free priority (`FW-23`).
- **`FW-30` on every firewall row.** The CLI writes rules only to a segment pair whose Security Policies options are `merge=false` and `templateApply=false`. That setting belongs to the user's Orchestrator design: report it and let the user decide; never change it yourself.
- **Domain already owned.** An application definition whose domain or port an existing definition already uses is skipped as a conflict. Find the owner in Orchestrator and ask the user; never edit the existing one.
- **Hand-editing a CSV with `sed` or by retyping it.** Quoted cells with commas break. Edit with Python's `csv` module (`references/request-to-csv.md`).
- **Leftovers after cleanup.** `template-acls deploy` creates a missing template group, but `template-acls delete` removes only the ACL and leaves the group. There is no zone delete command. Tell the user before creating either; they remove a group or zone in Orchestrator themselves.
- **Template ACL reach.** Saving a template group pushes its ACL to every appliance associated with that group; name those appliances to the user from the preview. Mind the `ACL-25` guard on groups whose Security Policies template is in replace mode.
- **Example files.** `examples/edgeconnect/*_mixed.csv` and `template_acls_test3_invalid.csv` are invalid by design; use them only with `validate` or `--dry-run`. Example objects are named `test-51-`; remove those rows from a copied template unless the user wants them.

## Red Flags

| Excuse | Reality |
|---|---|
| "I'll run `deploy` without `--dry-run`; it asks for `APPLY` anyway." | Never. The write and its approval belong to the user, in their own terminal. |
| "The prompt needs a terminal, so I'll wrap it in `script`, `expect` or a pty, or pipe `APPLY` in." | Never fake a terminal or type `APPLY`, a deletion code or the final sentence for the user. That removes the human approval the tool exists for. |
| "Calling the Orchestrator API (or an MCP `api_write`) directly is quicker." | Never write these objects any other way. The direct path skips dependency, collision, drift, readback, appliance-alarm and rollback checks. |
| "I'll fix the plan, report or resolved CSV JSON by hand." | Never edit an output. Change the input CSV and re-run. |
| "Validation fails, so I'll blank the field, drop the row, or acknowledge a broad match." | Only after the user says yes to that exact change; otherwise apply the `fix:` the message gives. |
| "One row was skipped, so I'll abort everything." | Independent rows still proceed (exit `5`); report which rows were skipped and why. |
| "A dry run only reads, so the Orchestrator does not matter." | Confirm the nickname; the user's `APPLY` writes to the `Target Orchestrator:` the CLI prints. |
