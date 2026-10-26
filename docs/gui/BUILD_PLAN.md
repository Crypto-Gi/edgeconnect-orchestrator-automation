# GUI build plan

The automation GUI is built in the steps below, one pull request per step into the `gui` branch. Each step starts only after the previous one is merged there. main stays untouched until the owner decides to merge `gui` into it.

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
- Bulk only: the GUI uploads CSVs and never builds or edits individual rules. A CSV with problems is listed row by row and fixed in the file.

## Step 0: CI
GitHub Actions running the existing tests on Python 3.9 and 3.13, on Linux and macOS.
Done when: green on the `gui` branch.

## Step 1: Golden outputs and run context
Record CLI output for representative commands from offline inventory fixtures as golden files (validate, plan and dry-run for each object type). Then replace the cli.py module globals (_TARGET, _TARGET_NAME, _TARGET_URL, _RUN, the gateway cache) with a run context object passed through.
Done when: tests pass, golden outputs are byte-identical, and two run contexts can coexist in one process.

## Step 2: Shared approval module (approval.py)
Terminal front end reproduces every current prompt exactly (APPLY, CREATE <zone>, template group name, Access Lists selection, merge mode, the DELETE-xxxxxxxx code, the acknowledgement sentence) and keeps the no-terminal refusal. GUI front end issues a single-use approval bound to the plan fingerprint, the Orchestrator identity and a 10-minute expiry.
Done when: existing gate tests pass unchanged, and new tests prove an approval can't be reused, expires, and is refused for a different plan or Orchestrator.

## Step 3: Python engine API (engine.py)
discover, validate, plan, apply, delete, verify, summarize. Each takes a run context and returns structured results: issues (row, column, rule ID, message), preview counts, per-object create/modify/delete with field-level diffs, per-row outcomes. The CLI becomes argument parsing plus printing these.
Done when: golden outputs unchanged and the structured results have their own tests.
Built as: `engine.py` runs the CLI's own command code in-process with its own run context and builds the structured results from what the run produced, instead of moving that code out of `cli.py`. The GUI and the CLI still share one code path, and CLI output cannot drift. Writes take a single-use GUI approval in place of the terminal prompts.

## Step 4: Orchestrator identity and fleet status
Read identity (URL, release, and a stable ID if the API has one; investigate first). Check all profiles in parallel with a short timeout and classify green, amber or red with a plain reason. Plans record the identity; apply refuses on a mismatch. Add optional <nick>_gui_color, <nick>_gui_label and <nick>_gui_writes (default off) to .env.example.
Built as: the stable ID is the Orchestrator serial number (`serialNumber` from `GET /gmsserver/info`, documented by pyedgeconnect). Lab check 26 Oct: the cloud-hosted Orchestrators (9.6.4, 9.7.1, 10.0) all report the placeholder `00-00-00-00-00-00`, so a placeholder counts as no serial and those Orchestrators are known by their address; an on-premises serial is still unchecked. Plans record name, URL, release and serial; apply refuses a different serial at the same URL, and compares URL only when either side has no serial. `fleet.check_all()` gives one try of 5 s per read: green = connected and release 9.3+ (the reason says when there is no unique serial); amber = usable but slow (over 2 s) or busy (429); red = bad settings, no answer, certificate, DNS, refused, key refused, release too old or server error.
Done when: fixture tests cover each status and the mismatch refusal, and a read-only check on the lab Orchestrators passes.

## Step 5: GUI server and task API
`edgeconnect-auto gui`: standard-library ThreadingHTTPServer on 127.0.0.1. Launch token that becomes an HttpOnly, SameSite=Strict cookie required on every API call and the progress stream. Exact Host allowlist (localhost, 127.0.0.1, [::1], with the port) against DNS rebinding (see Ollama CVE-2024-28224). Origin check on state-changing requests. No CORS. Static files served from the package. Task API: create, get, list, cancel before apply, server-sent-events progress. States: queued, running, planned, awaiting approval, applying, done, failed, rejected, expired. One change task per Orchestrator at a time; reads run in parallel. On WSL, open the Windows browser via wslview or explorer.exe and always print the URL.
Done when: security tests cover a rebinding Host, a missing cookie, a cross-origin POST and keys never appearing in responses; the page loads on macOS, Linux and WSL.
Built as: `gui_server.py` (HTTP, security, static files) and `gui_tasks.py` (tasks over `engine.py`). Actions: discover, validate, plan (reads) and apply, delete (changes); CSVs come in the request body and each task works in its own private temporary folder. One more state than planned, `cancelled`. Also: POSTs must be `application/json`, the cookie name includes the port (cookies ignore ports), and the launch token stays valid while the server runs. Not yet: `gui --dotenv` (the GUI reads `./.env`), and GUI writes on the unnamed single-Orchestrator lines (writes need a nickname with `<nickname>_gui_writes=on`). The page is a placeholder until step 6.

## Step 6: Design system and shell
Theme per the style above. Top bar with the Orchestrator switcher, colour and label. Fleet status panel. Intent-first home ("What do you want to do?" task cards: firewall rules, applications, application groups, address or service groups, template ACLs, missing zones, remove by CSV, see what changed). Command palette. Reset on switch.
Done when: usable with the keyboard only, WCAG AA contrast in both themes.
Built as: plain HTML, CSS and JavaScript served by the GUI server (no build step, no CDN); fonts bundled as latin woff2 with their OFL licences. Light-theme blue, amber, green and red are darkened from the toolkit page's values, which were below 4.5:1 for text; `tests/test_gui_design.py` checks every text colour pair in both themes. Status is shown by shape and word (● green, ▲ amber, ■ red), never colour alone. The Orchestrator's `_gui_color` is a stripe and a swatch, never a text background. Command palette: Ctrl+K or Cmd+K. The task cards open a placeholder until each guided task is built. Keyboard walk-through checked in headless Chromium.

## Step 7: Inventory and logs tables
Inventory tabs with search and paging. Runs table from reports/*.jsonl (time, Orchestrator, workflow and action, status badge, changes_written, row outcome counts, duration, source, run_id) with sort, filter, paging, search and problems-only. Drill-down to the per-row table (row, item, scope, outcome, reason). CSV export. Add `source` (cli or gui) to the run log.
Done when: tables match `report summarize` for the same files, and 10,000 log rows stay responsive.
Built as: `gui_tables.py` builds every table on the server and sends one page at a time, so the browser never holds the whole log. Runs come from `reporting`'s own reader (the one `report summarize` uses), cached per log file until its size or time changes; a damaged line is counted and skipped. Records from versions without a run ID (which `report summarize` calls `file <name>`) get `<log>-line-<n>` so each can be opened. Problems only = a result other than SUCCESS, NO_OP, DRY_RUN, VALID or PLANNED, or any row BLOCKED, FAILED, SKIPPED, NOT WRITTEN, INVALID or UNVERIFIED. CSV exports follow the current search and filters; with none, the row CSV is byte-identical to `report summarize --rows-csv`. `source` is `cli` for the command line and `gui` for runs through `engine.py`, also as a top-level field of every report. Inventory is a discover task with five tabs: segments, zones, zones per segment, address groups, service groups (applications are not part of discovery). Measured: 10,000 logged runs load in about 0.6 s the first time and answer a search, filter or sort in about 15 ms after that (this container).

## Step 8: First guided task: firewall rules
Stepper: Load, Fix, Plan, Review, Approve, Apply, Done. Review shows deletes and warnings first, then counts, then changes by object type with field-level diffs. The approve dialog shows the Orchestrator's colour and label and requires typing its nickname. Live progress, then readback. Rejected and Expired final states. Approval record in the run log (OS user, time, plan fingerprint, Orchestrator, typed confirmation). gui_writes gate.
Done when: the same CSVs through the CLI and the GUI on the lab Orchestrator give identical results, and every gate is tested.
Built as: the stepper and its panels follow server tasks (validate, plan, apply); the browser only shows them. The Orchestrator nickname is checked in Python, before the terminal's gates, and a wrong one ends the task as `rejected`. Task views carry counts only; issues, changes (deletes first) and per-row outcomes come a page at a time from `/api/tasks/<id>/issues|changes|rows`, so a large plan never travels whole. The approval record is `summary.approval` (`by`, `time`, `plan_fingerprint` of the exact preview, `orchestrator`, `orchestrator_id`, `typed_orchestrator`, `typed`), written only for GUI approvals. "Live progress" is the task's states (building the preview, waiting for approval, writing, done); the firewall apply's own read-back gives the per-row outcomes. Offline, the same CSV through the CLI (plan, then apply with APPLY typed) and through the GUI writes the identical policy and the same row outcomes; the lab comparison is still to run.

## Step 9: The other six tasks plus delete
Template ACLs, zones, address groups, service groups, application definitions, application groups on the same stepper. Danger-zone delete by CSV: warnings, an "I understand" tick box, then the deletion code and sentence.
Done when: each has a lab run compared with the CLI, and the delete gates are tested.
Built as: one guided view for every object type (`#/do/<kind>`) and Remove by CSV (`#/remove`, steps Load, Preview, Confirm, Delete, Done) over the same server tasks; the step 8 firewall view became that view. Address and service groups are two tasks (the home had one card for both). Only firewall rules have an offline check, so the others check rows while planning. Missing zones takes names instead of a CSV. The "I understand" tick box is sent with the approval and checked in Python (`understood` must be `true` for a delete), after the nickname and before the typed gates. Offline, every object type's plan through the GUI is identical to the CLI's saved plan; the lab comparisons are still to run.

## Step 10: Grid editor (dropped)
Dropped by the owner on 26 Oct, after it was built and merged: the GUI uploads CSVs in bulk and does not edit rules. A loaded CSV is checked, every problem is listed with its row, column and fix, and the person corrects the file and loads it again. The editor was removed in the change that records this.

## Step 11: Revert
Store the pre-change state with each apply. A Revert action on the run page builds a new plan that goes through the same review and approval.
Done when: a lab apply followed by a revert returns the readback to the original state.
Built as: "Undo this upload" on the run page, for uploads made in the GUI (owner, 26 Oct). Every firewall and object upload only adds, so the pre-change state is "without what this upload created": when a GUI upload writes, Python keeps next to its run log entry (`revert/<run_id>.json`, mode 600) the delete CSV of exactly the rows whose outcome is CREATED or ADDED, cut from the CSV that was planned. Rows already present, blocked or failed are left out, and a firewall row left to automatic priority gets the priority it was created at. Undo starts an ordinary delete task with that CSV (`revert: <run_id>`, checked in Python against the run's object type and Orchestrator), so it has the same preview, tick box, typed code, sentence and nickname as Remove by CSV, and the delete commands still refuse anything that no longer matches exactly. Not offered for zones (the tool has no zone delete), for uploads that overwrote or removed existing entries, or for uploads made with the command line. No CLI code changed. Offline, a firewall upload followed by its undo leaves the policy identical to the one before the upload; the lab run is still to do.

## Step 12: Polish and release
Accessibility pass, Playwright smoke test, README and QUICKSTART GUI sections, scrubbed demo GIF, WSL smoke test, remove the experimental label, version bump and release.
Done when: CI is green, a WSL test has passed, and the release is published.
