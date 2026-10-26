# GUI build plan

A local web GUI for `edgeconnect-auto`, built one step at a time. Each step is its own branch and pull request into `main`; the owner merges it, and the next step starts from the merged `main`. Steps 0 to 4 change no CLI behaviour: the existing tests and the golden outputs stay identical. The `gui` command is labelled experimental until step 12.

## Decided (owner, 2026-10-26)

- Audience: everyone, customers included. This GUI covers this repository only for now; one GUI for all three EdgeConnect tools may follow.
- The browser only displays what Python decided. There is no validation in JavaScript.
- Apply and delete happen in the GUI, behind every safety gate the CLI has. The GUI is for people, not primarily for AI agents.
- Switching Orchestrator resets everything (CSVs, edits, plans, inventory, the open task). If there is unsaved work it asks first and offers a CSV download.
- Logs are shown as tables, with paging and filtering.
- `<nickname>_gui_writes` is off by default for every Orchestrator.
- Not built: API keys in the browser, a hosted multi-user server, an AI chat box, Orchestrator editing beyond what the CLI does, any write path that skips the plan.
- API: the CLI code becomes a Python API, used by a private task API inside the GUI server. There is no public REST API.
- Platforms: macOS, Linux, and Windows through WSL only.
- Style: the design tokens of the EdgeConnect toolkit overview page. Dark first with a full light theme; Bricolage Grotesque, IBM Plex Sans and IBM Plex Mono bundled locally (OFL); blue for data and primary actions, amber for gates, green for OK, red for problems; 14px rounded panels, pill buttons, a sticky blurred top bar, stat tiles.
- No new Python dependencies: the server uses the standard library.

## Rules for every step

- One branch and pull request per step; the owner merges.
- Lab writes only on the lab Orchestrator approved for writes; reference Orchestrators are read with GET only. No lab, customer or site names in commits.

## Steps

**0. CI.** GitHub Actions runs the existing tests on Python 3.9 and 3.13, on Linux and macOS. Done: green on `main`, required for pull requests (the owner sets branch protection).

**1. Golden outputs and a run context.** Record the CLI output of representative commands from offline inventory fixtures as golden files (validate, plan, and dry run per object type). Then replace the `cli.py` module globals (`_TARGET`, `_TARGET_NAME`, `_TARGET_URL`, `_RUN`, the gateway cache) with a run context object that is passed through. Done: tests pass, golden outputs byte-identical, two contexts can coexist in one process.

**2. Shared approval module (`approval.py`).** The terminal front end reproduces every current prompt exactly (`APPLY`, `CREATE <zone>`, the template group name, the Access Lists selection, merge mode, the `DELETE-xxxxxxxx` code, the acknowledgement sentence) and keeps the refusal without a terminal. The GUI front end issues a single-use approval bound to the plan fingerprint, the Orchestrator identity and a 10-minute expiry. Done: existing gate tests unchanged; new tests prove no reuse, expiry, and refusal of a wrong plan or Orchestrator.

**3. Python engine API (`engine.py`).** discover, validate, plan, apply, delete, verify and summarize take a run context and return structured results: issues with row, column, rule ID and message; preview counts; per-object create, modify and delete with field-level differences; per-row outcomes. The CLI becomes argument parsing plus printing these. Done: golden outputs unchanged; structured results tested.

**4. Orchestrator identity and fleet status.** Read the identity (URL, release, and a stable ID if the API has one; investigate first). Check every profile in parallel with a short timeout and classify it green, amber or red with a plain reason. Plans record the identity, and apply refuses on a mismatch. Add optional `<nickname>_gui_color`, `<nickname>_gui_label` and `<nickname>_gui_writes` (default off) to `.env.example`. Done: fixture tests for each status and for the mismatch refusal; a read-only check on lab Orchestrators.

**5. GUI server and task API.** `edgeconnect-auto gui`: a standard-library `ThreadingHTTPServer` on 127.0.0.1. A launch token becomes an HttpOnly, SameSite=Strict cookie required on every API call and on the progress stream. An exact Host allowlist (localhost, 127.0.0.1, [::1], with the port) against DNS rebinding (compare CVE-2024-28224); an Origin check on state-changing requests; no CORS; static files served from the package. Task API: create, get, list, cancel before apply, and server-sent progress. States: queued, running, planned, awaiting approval, applying, done, failed, rejected, expired. One change task per Orchestrator at a time; reads run in parallel. On WSL, open the Windows browser through `wslview` or `explorer.exe`, and always print the URL. Done: security tests (rebinding Host, missing cookie, cross-origin POST, keys never in responses); loads on macOS, Linux and WSL.

**6. Design system and shell.** The theme above; a top bar with the Orchestrator switcher, its colour and label; a fleet status panel; an intent-first home ("What do you want to do?") with task cards: firewall rules, applications, application groups, address and service groups, template ACLs, missing zones, remove by CSV, see what changed; a command palette; reset on switch. Done: usable by keyboard alone; WCAG AA contrast in both themes.

**7. Inventory and log tables.** Inventory tabs with search and paging. A runs table from `reports/*.jsonl` (time, Orchestrator, workflow and action, status badge, changes written, row outcome counts, duration, source, run ID) with sort, filter, paging, search and a problems-only view; a per-row drill-down (row, item, scope, outcome, reason); CSV export. Add `source` (cli or gui) to the run log. Done: matches `report summarize` for the same files; 10,000 log rows stay responsive.

**8. First guided task: firewall rules.** A stepper: Load, Fix, Plan, Review, Approve, Apply, Done. The review shows deletes and warnings first, then counts, then changes by object type with field-level differences. The approve dialog shows the Orchestrator colour and label and requires typing the nickname. Live progress; readback; final states Rejected and Expired; an approval record in the log (OS user, time, plan fingerprint, Orchestrator, the typed confirmation); the `gui_writes` gate. Done: the same CSVs through CLI and GUI on the lab Orchestrator give identical results; every gate tested.

**9. The other six tasks and delete.** Template ACLs, zones, address groups, service groups, application definitions and application groups on the same stepper; a danger-zone delete by CSV (warnings, an "I understand" tick box, the deletion code and sentence). Done: each has a lab run compared with the CLI; delete gates tested.

**10. Grid editor.** A paged grid plus a per-row form, drop-downs filled from the live inventory, starting from the templates and examples, dependency warnings before planning, CSV save; validation stays in Python. Done: a firewall CSV built without typing a name; 5,000 rows stay responsive.

**11. Revert.** Store the state before each apply; Revert on the run page builds a new plan through the same review and approval. Done: a lab apply and revert return the readback to the original.

**12. Polish and release.** An accessibility pass, a Playwright smoke test, GUI sections in README and QUICKSTART, a scrubbed demo GIF, a WSL smoke test, removal of the experimental label, a version bump and a release. Done: CI green, the WSL test passed, the release published.
