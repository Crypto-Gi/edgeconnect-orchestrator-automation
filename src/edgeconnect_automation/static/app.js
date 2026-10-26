// EdgeConnect Automation GUI shell. The browser only shows what the Python server decided; it never validates or
// decides anything itself. Every value is written with textContent, never as HTML.
"use strict";

const TASKS = [
  { id: "firewall", title: "Firewall rules", text: "Add or change zone-based firewall rules between segments, from a CSV.", writes: true },
  { id: "applications", title: "Applications", text: "Define custom applications by address, port or domain, and AppExpress entries.", writes: true },
  { id: "app-groups", title: "Application groups", text: "Group applications so one firewall rule can match them all.", writes: true },
  { id: "groups", title: "Address or service groups", text: "Name sets of addresses or ports for firewall rules to use.", writes: true },
  { id: "template-acls", title: "Template ACLs", text: "Merge access lists into the Access Lists template of template groups.", writes: true },
  { id: "zones", title: "Missing zones", text: "Create the firewall zones a CSV needs that this Orchestrator does not have yet.", writes: true },
  { id: "remove", title: "Remove by CSV", text: "Delete exactly the objects listed in a CSV, after a typed confirmation.", writes: true },
  { id: "changes", title: "See what changed", text: "Look through earlier runs, their outcomes and every row they touched.", writes: false, href: "#/runs" },
  { id: "inventory", title: "Inventory", text: "Look through the segments, zones and groups this Orchestrator has now.", writes: false, href: "#/inventory" },
];
const SHAPE = { green: "●", amber: "▲", red: "■" };
const OPEN_STATES = new Set(["queued", "running", "awaiting_approval"]);

const state = { fleet: [], current: null, tasks: [], work: { csvs: {}, inventory: null } };
const $ = (id) => document.getElementById(id);

function store(key, value) {
  try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (_) { return null; }
  return null;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

async function api(path, options) {
  const response = await fetch(path, Object.assign({ credentials: "same-origin" }, options));
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || response.statusText);
  return body;
}

function post(path, body) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
}

function nameOf(orch) { return orch ? (orch.label || orch.name || orch.url) : ""; }
function current() { return state.fleet.find((orch) => orch.name === state.current) || null; }

/* theme */
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme;
}
function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  store("ec-theme", next);
}

/* fleet status and the switcher */
async function loadFleet() {
  const list = $("fleet");
  list.setAttribute("aria-busy", "true");
  $("fleet-refresh").disabled = true;
  try {
    state.fleet = (await api("/api/orchestrators")).orchestrators;
  } catch (error) {
    state.fleet = [];
    list.replaceChildren(el("li", { class: "s-red", text: "Could not check the Orchestrators: " + error.message }));
  }
  list.setAttribute("aria-busy", "false");
  $("fleet-refresh").disabled = false;
  if (!state.fleet.length) return renderHeader();
  const remembered = store("ec-orchestrator");
  if (!state.fleet.some((orch) => orch.name === state.current)) {
    const pick = state.fleet.find((orch) => orch.name === remembered) || state.fleet.find((orch) => orch.status === "green") || state.fleet[0];
    state.current = pick.name;
  }
  renderFleet();
  renderSwitcher();
  renderHeader();
  render();
}

function renderFleet() {
  const list = $("fleet");
  list.replaceChildren(...state.fleet.map((orch) => {
    const item = el("li", { class: "orch" },
      el("span", { class: "name", text: nameOf(orch) + (orch.name === state.current ? " (selected)" : "") }),
      el("span", { class: "status-word s-" + orch.status, text: SHAPE[orch.status] + " " + orch.status }),
      el("span", { class: "reason", text: orch.reason }),
      el("span", { class: "meta", text: [orch.url, orch.release && "release " + orch.release, "writes " + (orch.writes ? "on" : "off")].filter(Boolean).join(" · ") }));
    if (orch.color) item.style.setProperty("--c", orch.color);
    return item;
  }));
}

function renderSwitcher() {
  const select = $("orch");
  select.replaceChildren(...state.fleet.map((orch) => {
    const option = el("option", { value: orch.name, text: nameOf(orch) + " — " + orch.status });
    option.selected = orch.name === state.current;
    return option;
  }));
  select.disabled = state.fleet.length < 2;
}

function renderHeader() {
  const orch = current();
  const root = document.documentElement.style;
  if (orch && orch.color) root.setProperty("--orch-color", orch.color); else root.removeProperty("--orch-color");
  const status = $("orch-status");
  status.className = "status-word" + (orch ? " s-" + orch.status : "");
  status.textContent = orch ? SHAPE[orch.status] + " " + orch.status : "";
  status.title = orch ? orch.reason : "";
  const label = orch ? nameOf(orch) : "No Orchestrator configured";
  $("home-orch").textContent = label;
  $("task-orch").textContent = label;
  $("home-writes").textContent = !orch ? "Add an Orchestrator to .env, then check again."
    : orch.writes ? "Changes are allowed on " + nameOf(orch) + ". Every write still shows its preview and needs your typed confirmation."
    : "Read-only on " + nameOf(orch) + ": you can plan and preview, but writes are off. Set " + orch.name + "_gui_writes=on in .env to allow them.";
  document.title = (orch ? nameOf(orch) + " · " : "") + "EdgeConnect Automation";
}

/* switching Orchestrator resets everything; ask first when there is something to lose */
function openTasks(name) { return state.tasks.filter((task) => task.orchestrator === name && OPEN_STATES.has(task.state)); }

function requestSwitch(name) {
  if (name === state.current) return;
  const csvs = Object.keys(state.work.csvs).length;
  const open = openTasks(state.current).length;
  if (!csvs && !open) return switchTo(name);
  const parts = [];
  if (csvs) parts.push(csvs + " CSV" + (csvs > 1 ? "s" : "") + " with your edits");
  if (open) parts.push(open + " open task" + (open > 1 ? "s, which will be cancelled" : ", which will be cancelled"));
  $("switch-text").textContent = "Switching to " + nameOf(state.fleet.find((orch) => orch.name === name)) + " starts fresh. You would lose " + parts.join(" and ") + ". Plans and previews are never carried to another Orchestrator.";
  $("switch-download").hidden = !csvs;
  const dialog = $("switch-dialog");
  dialog.returnValue = "";
  dialog.onclose = () => {
    if (dialog.returnValue === "switch") switchTo(name);
    else $("orch").value = state.current;
  };
  dialog.showModal();
}

async function switchTo(name) {
  for (const task of openTasks(state.current)) {
    try { await post("/api/tasks/" + task.id + "/cancel"); } catch (_) { /* already finished */ }
  }
  state.current = name;
  state.work = { csvs: {}, inventory: null };
  store("ec-orchestrator", name);
  renderSwitcher();
  renderFleet();
  renderHeader();
  location.hash = "#/";
  render();
  $("main").focus();
}

function downloadCsvs() {
  for (const [file, text] of Object.entries(state.work.csvs)) {
    const link = el("a", { href: URL.createObjectURL(new Blob([text], { type: "text/csv" })), download: file });
    link.click();
    URL.revokeObjectURL(link.href);
  }
}

/* views */
function renderIntents() {
  const orch = current();
  $("intents").replaceChildren(...TASKS.map((task) => el("li", null,
    el("a", { class: "intent", href: task.href || "#/task/" + task.id },
      // Title first, so a screen reader names the link by its task; CSS shows the kind above it.
      el("h3", { text: task.title }),
      el("p", { text: task.text }),
      el("span", { class: "kind" + (task.writes ? " writes" : ""), text: task.writes ? (orch && orch.writes ? "changes Orchestrator" : "preview only here") : "read only" })))));
}

function show(view) {
  for (const id of ["view-home", "view-task", "view-runs", "view-run", "view-inventory"]) $(id).hidden = id !== view;
}

function render() {
  const hash = location.hash;
  if (hash === "#/runs") { show("view-runs"); return runsTable.load(); }
  const run = hash.match(/^#\/runs\/([\w-]+)$/);
  if (run) { show("view-run"); return loadRun(run[1]); }
  if (hash === "#/inventory") { show("view-inventory"); return renderInventory(); }
  const match = hash.match(/^#\/task\/([\w-]+)$/);
  const task = match && TASKS.find((item) => item.id === match[1] && !item.href);
  show(task ? "view-task" : "view-home");
  if (!task) return renderIntents();
  $("task-title").textContent = task.title;
  $("task-text").textContent = task.text;
  $("task-note").textContent = "This guided task is not built yet. Until it is, use the edgeconnect-auto command line for it.";
}

async function loadTasks() {
  try { state.tasks = (await api("/api/tasks")).tasks; } catch (_) { return; }
  const rows = state.tasks.map((task) => el("tr", null,
    el("td", { text: [task.action, task.kind].filter(Boolean).join(" ") }),
    el("td", { text: task.orchestrator || "(unnamed)" }),
    el("td", { text: task.state.replace("_", " ") }),
    el("td", { text: task.message })));
  $("tasks").replaceChildren(...(rows.length ? rows : [el("tr", null, el("td", { colspan: "4", class: "muted", text: "No tasks yet." }))]));
}

/* paged tables: the server searches, filters, sorts and pages; this only shows the page it sends */
const SHAPES = { ok: "●", bad: "■" };

function toneCell(text, tone) {
  return el("span", { class: "tone-" + tone, text: (SHAPES[tone] ? SHAPES[tone] + " " : "") + text });
}

function query(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== "" && value != null && value !== false) search.set(key, value === true ? "1" : value);
  return search.toString();
}

class PagedTable {
  // columns: [{ key, label, cell(row) -> node or text, mono }]; filters: [{ key, label }] drawn from the server's facets.
  constructor(options) {
    Object.assign(this, { filters: [], problems: "", exportName: "" }, options);
    this.params = Object.assign({ q: "", page: 1, size: 50, sort: "", order: "", problems: false }, ...this.filters.map((filter) => ({ [filter.key]: "" })));
    this.sequence = 0;
    this.timer = null;
    this.build();
  }

  build() {
    const id = this.id;
    this.search = el("input", { type: "search", id: id + "-q", placeholder: "Search", "aria-controls": id + "-grid", autocomplete: "off" });
    this.search.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.set({ q: this.search.value, page: 1 }), 250);
    });
    const toolbar = el("div", { class: "toolbar" }, el("label", { for: id + "-q", class: "sr-only", text: "Search " + this.label }), this.search);
    this.selects = {};
    for (const filter of this.filters) {
      const select = el("select", { id: id + "-" + filter.key, "aria-label": filter.label });
      select.addEventListener("change", () => this.set({ [filter.key]: select.value, page: 1 }));
      this.selects[filter.key] = select;
      toolbar.append(select);
    }
    if (this.problems) {
      const box = el("input", { type: "checkbox", id: id + "-problems" });
      box.addEventListener("change", () => this.set({ problems: box.checked, page: 1 }));
      toolbar.append(el("label", { class: "check", for: id + "-problems" }, box, this.problems));
    }
    const size = el("select", { id: id + "-size", "aria-label": "Rows per page" }, ...[25, 50, 100, 200].map((value) => el("option", { value: String(value), text: value + " per page" })));
    size.value = "50";
    size.addEventListener("change", () => this.set({ size: size.value, page: 1 }));
    toolbar.append(size);
    if (this.exportPath) {
      this.exportLink = el("a", { class: "btn", text: "Export CSV" });
      toolbar.append(this.exportLink);
    }
    this.head = el("tr");
    this.body = el("tbody");
    this.count = el("span", { class: "count", role: "status" });
    this.prev = el("button", { class: "btn", type: "button", text: "← Previous" });
    this.next = el("button", { class: "btn", type: "button", text: "Next →" });
    this.where = el("span", { class: "count" });
    this.prev.addEventListener("click", () => this.set({ page: this.params.page - 1 }));
    this.next.addEventListener("click", () => this.set({ page: this.params.page + 1 }));
    this.container.replaceChildren(toolbar,
      el("div", { class: "table-wrap" }, el("table", { id: id + "-grid" }, el("caption", { class: "sr-only", text: this.label }), el("thead", null, this.head), this.body)),
      el("div", { class: "pager" }, this.count, el("div", { class: "btns" }, this.prev, this.where, this.next)));
  }

  set(changes) {
    clearTimeout(this.timer);  // a search still being typed goes with this request, not after it
    Object.assign(this.params, { q: this.search.value }, changes);
    this.load();
  }

  reset() {
    Object.assign(this.params, { q: "", page: 1, problems: false }, ...this.filters.map((filter) => ({ [filter.key]: "" })));
    this.search.value = "";
    const box = $(this.id + "-problems");
    if (box) box.checked = false;
  }

  async load() {
    const path = this.path();
    if (!path) return;
    const sequence = ++this.sequence;
    this.container.setAttribute("aria-busy", "true");
    let data;
    try {
      data = await api(path + "?" + query(this.params));
    } catch (error) {
      if (sequence !== this.sequence) return;
      this.container.setAttribute("aria-busy", "false");
      this.body.replaceChildren(el("tr", null, el("td", { colspan: String(this.columns.length), class: "tone-bad", text: "Could not load: " + error.message })));
      return;
    }
    if (sequence !== this.sequence) return;  // a newer request is on its way; never show an older answer over it
    this.container.setAttribute("aria-busy", "false");
    this.show(this.table ? this.table(data) : data, data);
  }

  show(table, data) {
    Object.assign(this.params, { page: table.page, size: table.size, sort: table.sort, order: table.order });
    this.head.replaceChildren(...this.columns.map((column) => {
      const sorted = table.sort === column.key;
      const button = el("button", { type: "button", text: column.label + (sorted ? (table.order === "asc" ? " ↑" : " ↓") : "") });
      button.addEventListener("click", () => this.set({ sort: column.key, order: sorted && table.order === "asc" ? "desc" : "asc", page: 1 }));
      const th = el("th", { scope: "col" }, button);
      if (sorted) th.setAttribute("aria-sort", table.order === "asc" ? "ascending" : "descending");
      return th;
    }));
    for (const filter of this.filters) {
      const select = this.selects[filter.key];
      const values = (table.facets && table.facets[filter.key]) || [];
      select.replaceChildren(el("option", { value: "", text: filter.label }), ...values.map((value) => el("option", { value, text: value || "(blank)" })));
      select.value = this.params[filter.key] || "";
    }
    const rows = table.rows.map((row) => el("tr", null, ...this.columns.map((column) => {
      const value = column.cell ? column.cell(row) : row[column.key];
      return el("td", column.mono ? { class: "mono" } : null, value == null ? "" : value instanceof Node ? value : String(value));
    })));
    const empty = table.total ? "Nothing matches. Clear the search or filters." : (this.empty || "Nothing here yet.");
    this.body.replaceChildren(...(rows.length ? rows : [el("tr", null, el("td", { colspan: String(this.columns.length), class: "muted", text: empty }))]));
    const first = table.matching ? (table.page - 1) * table.size + 1 : 0;
    const last = Math.min(table.page * table.size, table.matching);
    this.count.textContent = "Showing " + first.toLocaleString() + "–" + last.toLocaleString() + " of " + table.matching.toLocaleString() + (table.matching !== table.total ? " matching (" + table.total.toLocaleString() + " in all)" : "");
    this.where.textContent = "Page " + table.page + " of " + table.pages;
    this.prev.disabled = table.page <= 1;
    this.next.disabled = table.page >= table.pages;
    if (this.exportLink) {
      const params = Object.assign({}, this.params, { page: "", size: "" });
      this.exportLink.href = this.exportPath() + "?" + query(params);
      this.exportLink.setAttribute("download", this.exportName());
    }
    if (this.after) this.after(data);
  }
}

const runsTable = new PagedTable({
  id: "runs",
  label: "runs",
  container: $("runs-table"),
  path: () => "/api/runs",
  exportPath: () => "/api/runs.csv",
  exportName: () => "runs.csv",
  problems: "Problems only",
  empty: "No runs logged yet.",
  filters: [{ key: "orchestrator", label: "All Orchestrators" }, { key: "workflow", label: "All workflows" }, { key: "status", label: "All results" }, { key: "source", label: "CLI and GUI" }],
  columns: [
    { key: "timestamp", label: "Time", mono: true, cell: (row) => String(row.timestamp).replace("T", " ") },
    { key: "orchestrator", label: "Orchestrator" },
    { key: "workflow", label: "Workflow" },
    { key: "status", label: "Result", cell: (row) => toneCell(row.status, row.tone) },
    { key: "changes_written", label: "Changes made" },
    { key: "row_outcomes", label: "Rows" },
    { key: "duration_seconds", label: "Seconds" },
    { key: "source", label: "From" },
    { key: "run_id", label: "Run", mono: true, cell: (row) => el("a", { href: "#/runs/" + row.run_id, text: row.run_id }) },
  ],
  after: (data) => {
    const parts = [data.folder ? "Every run logged in " + data.folder + ", newest first." : "Run logging is off (EDGECONNECT_REPORT_DIR is empty), so there are no runs to show."];
    if (data.unreadable) parts.push(data.unreadable + " log line" + (data.unreadable > 1 ? "s" : "") + " could not be read and " + (data.unreadable > 1 ? "are" : "is") + " left out.");
    $("runs-text").textContent = parts.join(" ");
  },
});

let runId = "";
const rowsTable = new PagedTable({
  id: "rows",
  label: "rows of this run",
  container: $("run-rows"),
  path: () => runId && "/api/runs/" + runId,
  exportPath: () => "/api/runs/" + runId + "/rows.csv",
  exportName: () => runId + "-rows.csv",
  problems: "Problems only",
  empty: "This run has no per-row table.",
  filters: [{ key: "outcome", label: "All outcomes" }],
  table: (data) => data.rows,
  columns: [
    { key: "row", label: "Row" },
    { key: "item", label: "Item" },
    { key: "scope", label: "Scope" },
    { key: "outcome", label: "Outcome", cell: (row) => toneCell(row.outcome, row.tone) },
    { key: "reason", label: "Reason" },
  ],
  after: (data) => renderRun(data.run),
});

function loadRun(id) {
  if (id !== runId) {
    runId = id;
    rowsTable.reset();
    $("run-title").textContent = "Loading…";
  }
  rowsTable.load();
}

function renderRun(run) {
  $("run-id").textContent = run.run_id;
  $("run-title").replaceChildren(run.workflow + " · ", toneCell(run.status, run.tone));
  $("run-next").textContent = run.next_step || "";
  const facts = [
    ["Time", String(run.timestamp).replace("T", " ")],
    ["Orchestrator", [run.orchestrator, run.orchestrator_url].filter(Boolean).join(" · ")],
    ["Release", run.orchestrator_release],
    ["From", run.source],
    ["Changes made", run.changes_written],
    ["Exit code", run.exit_code + " = " + run.exit_meaning],
    ["Seconds", run.duration_seconds],
    ["Rows", run.row_outcomes_text],
    ["CSV", run.csv && run.csv.path ? run.csv.path + " (" + run.csv.data_rows + " data rows)" : ""],
    ["Run ref", run.run_reference],
    ["Tool", run.tool_version],
    ["Command", run.command],
  ].filter(([, value]) => value !== "" && value != null);
  $("run-facts").replaceChildren(...facts.flatMap(([name, value]) => [el("dt", { text: name }), el("dd", name === "Command" ? { class: "mono", text: String(value) } : { text: String(value) })]));
  const notes = [["What was planned or done", run.counts], ["Why it stopped or what failed", run.blocking_issues], ["Warnings (do not block)", run.warnings], ["Appliances", run.targets]]
    .filter(([, items]) => items && items.length)
    .flatMap(([title, items]) => [el("p", { class: "notes-title", text: title }), el("ul", { class: "notes" }, ...items.map((item) => el("li", { text: item })))]);
  $("run-notes").replaceChildren(...(notes.length ? notes : [el("p", { class: "muted", text: "Nothing else was recorded for this run." })]));
}

/* inventory: a discover task on the chosen Orchestrator, then its tables one tab at a time */
const inventoryTable = new PagedTable({
  id: "inventory",
  label: "inventory",
  container: $("inventory-table"),
  path: () => state.work.inventory && state.work.inventory.state === "done" && "/api/tasks/" + state.work.inventory.id + "/inventory",
  table: (data) => data.table,
  columns: [],
  after: (data) => renderTabs(data),
});
inventoryTable.params.tab = "segments";

const INVENTORY_COLUMNS = {
  segments: [["id", "ID"], ["name", "Name"]],
  zones: [["id", "ID"], ["name", "Name"]],
  segment_zones: [["segment", "Segment"], ["zone", "Zone"], ["zone_id", "Zone ID"]],
  address_groups: [["name", "Name"], ["rules", "Rules"], ["included_ips", "Included IPs"], ["excluded_ips", "Excluded IPs"], ["included_groups", "Included groups"], ["comment", "Comment"]],
  service_groups: [["name", "Name"], ["rules", "Rules"], ["protocol", "Protocol"], ["included_ports", "Included ports"], ["excluded_ports", "Excluded ports"], ["included_groups", "Included groups"], ["comment", "Comment"]],
};

function inventoryColumns(tab) {
  inventoryTable.columns = INVENTORY_COLUMNS[tab].map(([key, label]) => ({ key, label }));
}
inventoryColumns("segments");

function renderTabs(data) {
  const tabs = $("inventory-tabs");
  const focused = tabs.contains(document.activeElement);
  tabs.replaceChildren(...data.tabs.map((tab) => {
    const button = el("button", { class: "btn", type: "button", role: "tab", id: "tab-" + tab.id, "aria-controls": "inventory-table", "aria-selected": String(tab.id === data.tab), tabindex: tab.id === data.tab ? "0" : "-1", text: tab.label + " (" + tab.count.toLocaleString() + ")" });
    button.addEventListener("click", () => chooseTab(tab.id));
    return button;
  }));
  $("inventory-table").setAttribute("aria-labelledby", "tab-" + data.tab);
  if (focused) $("tab-" + data.tab).focus();
}

function chooseTab(tab) {
  inventoryColumns(tab);
  inventoryTable.reset();
  inventoryTable.set({ tab, sort: "", order: "", page: 1 });
}

function renderInventory() {
  const orch = current();
  const task = state.work.inventory;
  $("inventory-orch").textContent = orch ? nameOf(orch) : "No Orchestrator configured";
  $("inventory-load").disabled = !orch || Boolean(task && OPEN_STATES.has(task.state));
  $("inventory-load").textContent = task && task.state === "done" ? "Read again" : "Read inventory";
  const ready = Boolean(task && task.state === "done");
  $("inventory-table").hidden = !ready;
  $("inventory-tabs").hidden = !ready;
  $("inventory-status").textContent = !task ? "Not read yet for this Orchestrator."
    : ready ? "Read " + new Date(task.finished * 1000).toLocaleTimeString() + "."
    : task.state === "failed" ? "Could not read the inventory: " + task.message
    : "Reading the inventory…";
  $("inventory-status").className = task && task.state === "failed" ? "tone-bad" : "muted";
  if (ready) inventoryTable.load();
}

async function readInventory() {
  const orchestrator = state.current;
  let task;
  try {
    task = await post("/api/tasks", { action: "discover", orchestrator });
  } catch (error) {
    state.work.inventory = { state: "failed", message: error.message };
    return renderInventory();
  }
  state.work.inventory = task;
  renderInventory();
  const events = new EventSource("/api/tasks/" + task.id + "/events");
  events.onmessage = (message) => {
    const view = JSON.parse(message.data).task;
    if (state.current !== orchestrator || !state.work.inventory || state.work.inventory.id !== view.id) return events.close();  // switched away: start fresh
    if (!OPEN_STATES.has(view.state)) {
      events.close();
      view.finished = Date.now() / 1000;
    }
    state.work.inventory = view;
    if (location.hash === "#/inventory") renderInventory();
    loadTasks();
  };
  events.onerror = () => events.close();
}

/* command palette: combobox and listbox, all by keyboard */
let paletteItems = [];
let paletteIndex = 0;

function commands() {
  const list = [{ label: "Go to all tasks", hint: "home", run: () => { location.hash = "#/"; } }];
  for (const task of TASKS) list.push({ label: task.title, hint: task.writes ? "task" : "read only", run: () => { location.hash = task.href || "#/task/" + task.id; } });
  for (const orch of state.fleet) if (orch.name !== state.current) list.push({ label: "Switch to " + nameOf(orch), hint: orch.status, run: () => requestSwitch(orch.name) });
  list.push({ label: "Check Orchestrators again", hint: "status", run: loadFleet });
  list.push({ label: "Switch light or dark theme", hint: "theme", run: toggleTheme });
  return list;
}

function renderPalette() {
  const query = $("palette-input").value.trim().toLowerCase();
  paletteItems = commands().filter((item) => item.label.toLowerCase().includes(query));
  paletteIndex = Math.min(paletteIndex, Math.max(paletteItems.length - 1, 0));
  $("palette-list").replaceChildren(...paletteItems.map((item, index) => {
    const option = el("li", { role: "option", id: "cmd-" + index, "aria-selected": String(index === paletteIndex) }, el("b", { text: item.label }), el("span", { text: item.hint }));
    option.addEventListener("click", () => runCommand(index));
    return option;
  }));
  const input = $("palette-input");
  if (paletteItems.length) input.setAttribute("aria-activedescendant", "cmd-" + paletteIndex); else input.removeAttribute("aria-activedescendant");
  const active = $("cmd-" + paletteIndex);
  if (active) active.scrollIntoView({ block: "nearest" });
}

function openPalette() {
  const dialog = $("palette");
  if (dialog.open) return;
  $("palette-input").value = "";
  paletteIndex = 0;
  renderPalette();
  dialog.showModal();
  $("palette-input").focus();
}

function runCommand(index) {
  const item = paletteItems[index];
  $("palette").close();
  if (item) item.run();
}

/* wiring */
applyTheme(store("ec-theme"));
$("theme").addEventListener("click", toggleTheme);
$("inventory-load").addEventListener("click", readInventory);
$("inventory-tabs").addEventListener("keydown", (event) => {
  const tabs = [...$("inventory-tabs").querySelectorAll("[role=tab]")];
  const index = tabs.indexOf(document.activeElement);
  if (index < 0) return;
  const next = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 }[event.key];
  if (next === undefined) return;
  event.preventDefault();
  const tab = tabs[(next + tabs.length) % tabs.length];
  tab.focus();
  chooseTab(tab.id.slice(4));
});
$("fleet-refresh").addEventListener("click", loadFleet);
$("orch").addEventListener("change", (event) => requestSwitch(event.target.value));
$("palette-open").addEventListener("click", openPalette);
$("palette-input").addEventListener("input", () => { paletteIndex = 0; renderPalette(); });
$("palette-input").addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    const step = event.key === "ArrowDown" ? 1 : -1;
    paletteIndex = (paletteIndex + step + paletteItems.length) % Math.max(paletteItems.length, 1);
    renderPalette();
  } else if (event.key === "Enter") {
    event.preventDefault();
    runCommand(paletteIndex);
  }
});
$("switch-confirm").addEventListener("click", () => $("switch-dialog").close("switch"));
$("switch-cancel").addEventListener("click", () => $("switch-dialog").close("stay"));
$("switch-download").addEventListener("click", downloadCsvs);
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openPalette();
  }
});
window.addEventListener("hashchange", () => { render(); $("main").focus(); });

render();
loadFleet();
loadTasks();
setInterval(loadTasks, 5000);
