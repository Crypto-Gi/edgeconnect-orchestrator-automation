# GUI build plan

The automation GUI is built in the steps below, one pull request per step. Each step starts only after the previous one is merged.

## Decided (26 Oct)
- Audience: everyone, including customers. Automation only for now; one GUI for all three tools later.
- The browser only displays what Python decided (no validation in JavaScript).
- Apply and delete happen in the GUI with all safety gates. The GUI is for people, not primarily AI agents.
- Switching Orchestrator resets everything (CSVs, edits, plans, inventory, open task); asks first if there is unsaved work and offers a CSV download.
- Logs are shown as tables; paging and filtering are required.
- <nick>_gui_writes is OFF by default per Orchestrator.
- Do not build: API keys in the browser, a hosted multi-user server, an AI chat box, Orchestrator editing beyond the CLI's scope, any write path that skips the plan.
- API: the CLI code becomes a Python API plus a PRIVATE task API in the GUI server (no public REST).
- Platforms: macOS, Linux, Windows via WSL only.
- Style: the toolkit page's design tokens. Dark-first plus a light theme; Bricolage Grotesque, IBM Plex Sans and IBM Plex Mono bundled locally under the OFL; blue for data and primary actions, amber for gates, green ok, red bad; 14px rounded panels, pill buttons, sticky blurred top bar, stat tiles.
- Zero new Python dependencies (standard-library server).

## Step 0: CI
GitHub Actions running the existing tests on Python 3.9 and 3.13, on Linux and macOS.
Done when: green on main (the owner then makes it required for pull requests).

## Step 1: Golden outputs and run context
Record CLI output for representative commands from offline inventory fixtures as golden files (validate, plan and dry-run for each object type). Then replace the cli.py module globals (_TARGET, _TARGET_NAME, _TARGET_URL, _RUN, the gateway cache) with a run context object passed through.
Done when: tests pass, golden outputs are byte-identical, and two run contexts can coexist in one process.

## Step 2: Shared approval module (approval.py)
Terminal front end reproduces every current prompt exactly (APPLY, CREATE <zone>, template group name, Access Lists selection, merge mode, the DELETE-xxxxxxxx code, the acknowledgement sentence) and keeps the no-terminal refusal. GUI front end issues a single-use approval bound to the plan fingerprint, the Orchestrator identity and a 10-minute expiry.
Done when: existing gate tests pass unchanged, and new tests prove an approval can't be reused, expires, and is refused for a different plan or Orchestrator.

## Step 3: Python engine API (engine.py)
discover, validate, plan, apply, delete, verify, summarize. Each takes a run context and returns structured results: issues (row, column, rule ID, message), preview counts, per-object create/modify/delete with field-level diffs, per-row outcomes. The CLI becomes argument parsing plus printing these.
Done when: golden outputs unchanged and the structured results have their own tests.

## Step 4: Orchestrator identity and fleet status
Read identity (URL, release, and a stable ID if the API has one; investigate first). Check all profiles in parallel with a short timeout and classify green, amber or red with a plain reason. Plans record the identity; apply refuses on a mismatch. Add optional <nick>_gui_color, <nick>_gui_label and <nick>_gui_writes (default off) to .env.example.
Done when: fixture tests cover each status and the mismatch refusal, and a read-only check on the lab Orchestrators passes.

## Step 5: GUI server and task API
`edgeconnect-auto gui`: standard-library ThreadingHTTPServer on 127.0.0.1. Launch token that becomes an HttpOnly, SameSite=Strict cookie required on every API call and the progress stream. Exact Host allowlist (localhost, 127.0.0.1, [::1], with the port) against DNS rebinding (see Ollama CVE-2024-28224). Origin check on state-changing requests. No CORS. Static files served from the package. Task API: create, get, list, cancel before apply, server-sent-events progress. States: queued, running, planned, awaiting approval, applying, done, failed, rejected, expired. One change task per Orchestrator at a time; reads run in parallel. On WSL, open the Windows browser via wslview or explorer.exe and always print the URL.
Done when: security tests cover a rebinding Host, a missing cookie, a cross-origin POST and keys never appearing in responses; the page loads on macOS, Linux and WSL.

## Step 6: Design system and shell
Theme per the style above. Top bar with the Orchestrator switcher, colour and label. Fleet status panel. Intent-first home ("What do you want to do?" task cards: firewall rules, applications, application groups, address or service groups, template ACLs, missing zones, remove by CSV, see what changed). Command palette. Reset on switch.
Done when: usable with the keyboard only, WCAG AA contrast in both themes.

## Step 7: Inventory and logs tables
Inventory tabs with search and paging. Runs table from reports/*.jsonl (time, Orchestrator, workflow and action, status badge, changes_written, row outcome counts, duration, source, run_id) with sort, filter, paging, search and problems-only. Drill-down to the per-row table (row, item, scope, outcome, reason). CSV export. Add `source` (cli or gui) to the run log.
Done when: tables match `report summarize` for the same files, and 10,000 log rows stay responsive.

## Step 8: First guided task: firewall rules
Stepper: Load, Fix, Plan, Review, Approve, Apply, Done. Review shows deletes and warnings first, then counts, then changes by object type with field-level diffs. The approve dialog shows the Orchestrator's colour and label and requires typing its nickname. Live progress, then readback. Rejected and Expired final states. Approval record in the run log (OS user, time, plan fingerprint, Orchestrator, typed confirmation). gui_writes gate.
Done when: the same CSVs through the CLI and the GUI on the lab Orchestrator give identical results, and every gate is tested.

## Step 9: The other six tasks plus delete
Template ACLs, zones, address groups, service groups, application definitions, application groups on the same stepper. Danger-zone delete by CSV: warnings, an "I understand" tick box, then the deletion code and sentence.
Done when: each has a lab run compared with the CLI, and the delete gates are tested.

## Step 10: Grid editor
Paged grid with a per-row form, dropdowns from the live inventory, start from templates and examples, dependency warnings before planning, CSV save. Validation stays in Python.
Done when: a firewall CSV can be built with no typed names, and 5,000 rows stay responsive.

## Step 11: Revert
Store the pre-change state with each apply. A Revert action on the run page builds a new plan that goes through the same review and approval.
Done when: a lab apply followed by a revert returns the readback to the original state.

## Step 12: Polish and release
Accessibility pass, Playwright smoke test, README and QUICKSTART GUI sections, scrubbed demo GIF, WSL smoke test, remove the experimental label, version bump and release.
Done when: CI is green, a WSL test has passed, and the release is published.
