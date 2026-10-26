// EdgeConnect Automation GUI shell. The browser only shows what the Python server decided; it never validates or
// decides anything itself. Every value is written with textContent, never as HTML.
"use strict";

const TASKS = [
  { id: "firewall", title: "Firewall rules", text: "Add or change zone-based firewall rules between segments, from a CSV.", writes: true, href: "#/firewall" },
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

const state = { fleet: [], current: null, tasks: [], work: { csvs: {}, inventory: null, firewall: {} } };
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
  state.work = { csvs: {}, inventory: null, firewall: {} };
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
  for (const id of ["view-home", "view-task", "view-firewall", "view-runs", "view-run", "view-inventory"]) $(id).hidden = id !== view;
}

function render() {
  const hash = location.hash;
  if (hash === "#/runs") { show("view-runs"); return runsTable.load(); }
  const run = hash.match(/^#\/runs\/([\w-]+)$/);
  if (run) { show("view-run"); return loadRun(run[1]); }
  if (hash === "#/inventory") { show("view-inventory"); return renderInventory(); }
  if (hash === "#/firewall") { show("view-firewall"); return renderFirewall(); }
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
    ["Approved by", run.approval ? run.approval.by + " at " + String(run.approval.time).replace("T", " ") + ", typing " + [run.approval.typed_orchestrator].concat(run.approval.typed || []).filter(Boolean).join(", ") : ""],
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

/* guided firewall task: Load, Fix, Plan, Review, Approve, Apply, Done. Each step is a server task; this only shows them. */
const STEPS = ["Load", "Fix", "Plan", "Review", "Approve", "Apply", "Done"];
const FINAL_STATES = new Set(["planned", "done", "failed", "rejected", "expired", "cancelled"]);

function follow(work, key, task, onChange) {
  work[key] = task;
  const events = new EventSource("/api/tasks/" + task.id + "/events");
  events.onmessage = (message) => {
    const view = JSON.parse(message.data).task;
    if (work[key] !== task && (!work[key] || work[key].id !== view.id)) return events.close();  // started again or switched away
    work[key] = view;
    if (FINAL_STATES.has(view.state)) events.close();
    onChange(view);
    loadTasks();
  };
  events.onerror = () => events.close();
}

async function startTask(work, key, body, onChange) {
  try {
    follow(work, key, await post("/api/tasks", Object.assign({ orchestrator: state.current }, body)), onChange);
  } catch (error) {
    work[key] = { state: "failed", message: error.message, result: null };
  }
  onChange();
}

function firewallStep(fw) {
  if (!fw.csv) return [0, false];
  const { validate, plan, apply } = fw;
  if (apply) {
    if (apply.state === "applying") return [5, false];
    if (FINAL_STATES.has(apply.state)) return [6, apply.state !== "done"];
    return [4, false];
  }
  if (plan) {
    if (plan.state === "planned") return [3, false];
    return [2, plan.state === "failed"];
  }
  return [1, Boolean(validate && validate.state === "failed")];
}

const issueColumns = [
  { key: "row", label: "Row" }, { key: "column", label: "Column" }, { key: "rule", label: "Rule", mono: true },
  { key: "value", label: "Value", mono: true }, { key: "message", label: "Problem" }, { key: "fix", label: "Fix" },
];
let fwIssueTask = "";
const fwIssues = new PagedTable({ id: "fw-issues", label: "problems in the CSV", container: $("fw-issues"), path: () => fwIssueTask && "/api/tasks/" + fwIssueTask + "/issues", filters: [{ key: "rule", label: "All rules" }, { key: "column", label: "All columns" }], columns: issueColumns, empty: "No problems." });

function diffCell(row) {
  if (!row.fields.length) return "";
  return el("ul", { class: "diff" }, ...row.fields.map((item) => el("li", null,
    el("span", { text: item.field + ": " }),
    item.before == null ? null : el("span", { class: "before", text: JSON.stringify(item.before) }),
    item.before == null || item.after == null ? null : " → ",
    item.after == null ? el("span", { class: "before", text: "(removed)" }) : el("span", { class: "after", text: JSON.stringify(item.after) }))));
}
let fwPlanTask = "";
const fwChanges = new PagedTable({
  id: "fw-changes", label: "changes", container: $("fw-changes"), path: () => fwPlanTask && "/api/tasks/" + fwPlanTask + "/changes",
  problems: "Deletes only", filters: [{ key: "action", label: "All actions" }, { key: "type", label: "All object types" }], empty: "Nothing to change.",
  columns: [
    { key: "action", label: "Action", cell: (row) => row.action === "delete" ? toneCell("delete", "bad") : row.action },
    { key: "type", label: "Type" }, { key: "scope", label: "Where" }, { key: "object", label: "Object", mono: true },
    { key: "fields", label: "Field changes", cell: diffCell },
  ],
});
let fwApplyTask = "";
const fwRows = new PagedTable({
  id: "fw-rows", label: "rows written", container: $("fw-rows"), path: () => fwApplyTask && "/api/tasks/" + fwApplyTask + "/rows",
  problems: "Problems only", filters: [{ key: "outcome", label: "All outcomes" }], empty: "No per-row outcomes for this run.",
  columns: [{ key: "row", label: "Row" }, { key: "item", label: "Item" }, { key: "scope", label: "Scope" }, { key: "outcome", label: "Outcome", cell: (row) => toneCell(row.outcome, row.tone) }, { key: "reason", label: "Reason" }],
});

function notes(list, items) {
  list.replaceChildren(...(items || []).map((item) => el("li", { text: item })));
}

function renderFirewall() {
  const fw = state.work.firewall;
  const orch = current();
  const [step, stopped] = firewallStep(fw);
  $("fw-orch").textContent = orch ? nameOf(orch) : "No Orchestrator configured";
  $("fw-steps").replaceChildren(...STEPS.map((name, index) => {
    const finished = index < step || (index === 6 && step === 6 && !stopped);
    const item = el("li", { class: finished ? "done" : index === step && stopped ? "stopped" : "", text: name });
    if (index === step) item.setAttribute("aria-current", "step");
    return item;
  }));
  for (const id of ["fw-load", "fw-fix", "fw-review", "fw-progress", "fw-done"]) $(id).hidden = true;
  $("fw-file-name").textContent = fw.file ? "Loaded " + fw.file : "";
  if (step === 0) { $("fw-load").hidden = false; return; }

  if (step === 1 || (step === 2 && stopped)) {
    const task = step === 1 ? fw.validate : fw.plan;
    const result = task && task.result;
    $("fw-fix").hidden = false;
    $("fw-plan").hidden = !(step === 1 && task && task.state === "done");
    $("fw-plan").textContent = "Plan on " + (orch ? nameOf(orch) : "this Orchestrator");
    $("fw-fix-title").textContent = step === 1 ? "Check " + fw.file : "Plan stopped";
    $("fw-fix-text").textContent = !task || !FINAL_STATES.has(task.state) ? "Checking every row…"
      : result && result.issues ? result.issues + " problem" + (result.issues > 1 ? "s" : "") + " to fix in the CSV. Correct them, then load it again." + (step === 2 ? " Nothing was written." : "")
      : task.state === "failed" ? task.message
      : "Every row is valid. Next, plan it against " + nameOf(orch) + ": that reads the Orchestrator and changes nothing.";
    notes($("fw-fix-warnings"), result ? result.warnings : []);
    $("fw-issues").hidden = !(result && result.issues);
    if (result && result.issues) {
      if (fwIssueTask !== task.id) { fwIssueTask = task.id; fwIssues.reset(); }
      fwIssues.load();
    }
    return;
  }
  if (step === 3) {
    const result = fw.plan.result;
    $("fw-review").hidden = false;
    $("fw-deletes").hidden = !result.deletes;
    $("fw-deletes").textContent = result.deletes ? result.deletes + " object" + (result.deletes > 1 ? "s" : "") + " will be deleted. They are listed first." : "";
    $("fw-warnings").replaceChildren(...(result.warnings.length ? [el("div", { class: "callout gate" }, el("p", { class: "notes-title", text: "Warnings (do not block)" }), el("ul", { class: "notes" }, ...result.warnings.map((item) => el("li", { text: item }))))] : []));
    notes($("fw-counts"), result.counts);
    if (fwPlanTask !== fw.plan.id) { fwPlanTask = fw.plan.id; fwChanges.reset(); }
    fwChanges.load();
    const canWrite = Boolean(orch && orch.writes && result.changes);
    $("fw-approve").hidden = !canWrite;
    $("fw-writes-off").hidden = canWrite;
    $("fw-writes-off").textContent = !result.changes ? "Nothing to change: Orchestrator already has every rule in this CSV."
      : "Writes are off for " + nameOf(orch) + ". Set " + orch.name + "_gui_writes=on in .env to approve changes here, or apply this plan with the command line.";
    return;
  }
  if (step === 2) {
    $("fw-progress").hidden = false;
    $("fw-progress-title").textContent = "Planning on " + nameOf(orch);
    $("fw-progress-text").textContent = fw.plan.state === "queued" ? "Waiting to start." : "Reading the segments, zones and current rules, then working out every change. Nothing is written.";
    $("fw-open-approval").hidden = true;
    $("fw-cancel").hidden = true;
    return;
  }
  if (step === 4 || step === 5) {
    const task = fw.apply;
    $("fw-progress").hidden = false;
    const awaiting = task.state === "awaiting_approval";
    $("fw-progress-title").textContent = step === 5 ? "Writing to " + nameOf(orch) : awaiting ? "Waiting for your approval" : "Building the exact preview";
    $("fw-progress-text").textContent = step === 5 ? "Writing, then reading back to confirm every appliance has it. Do not close this page."
      : awaiting ? "Nothing has been written. Type the confirmations to approve this exact preview." : task.state === "queued" ? "Waiting for another write on this Orchestrator to finish." : "Checking that Orchestrator still matches the plan.";
    $("fw-open-approval").hidden = !awaiting;
    $("fw-cancel").hidden = step === 5;
    if (awaiting && !task.prompted) { task.prompted = true; openApproval(); }
    return;
  }
  const task = fw.apply;
  const result = task.result || {};
  $("fw-done").hidden = false;
  $("fw-done-title").replaceChildren(task.state === "done" ? toneCell("Written and confirmed", "ok") : toneCell({ rejected: "Rejected", expired: "Expired", cancelled: "Cancelled", failed: "Stopped" }[task.state] || task.state, "bad"));
  $("fw-done-text").textContent = task.state === "done" ? "Every change was written to " + nameOf(orch) + " and read back from it." : task.message;
  notes($("fw-done-counts"), result.counts);
  $("fw-run-link").hidden = !result.run_id;
  $("fw-run-link").href = "#/runs/" + (result.run_id || "");
  $("fw-rows").hidden = !result.rows;
  if (result.rows) {
    if (fwApplyTask !== task.id) { fwApplyTask = task.id; fwRows.reset(); }
    fwRows.load();
  }
}

function rerenderFirewall() { if (location.hash === "#/firewall") renderFirewall(); }

function loadFirewallCsv(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result);
    state.work.firewall = { file: file.name, csv: text };
    state.work.csvs = { [file.name]: text };
    startTask(state.work.firewall, "validate", { action: "validate", csv_text: text }, rerenderFirewall);
  };
  reader.readAsText(file);
}

function restartFirewall() {
  state.work.firewall = {};
  state.work.csvs = {};
  $("fw-file").value = "";
  renderFirewall();
  $("fw-file").focus();
}

/* approval: the server checks every answer; the dialog only collects them */
let clock = null;
function openApproval() {
  const task = state.work.firewall.apply;
  const orch = current();
  if (!task || task.state !== "awaiting_approval" || !orch) return;
  const gates = task.result.approval.gates;
  $("approve-band").replaceChildren(el("span", { text: nameOf(orch) + " " }), el("span", { class: "mono", text: "(" + orch.name + ", " + orch.url + ")" }));
  $("approve-text").textContent = "You are approving exactly the changes you reviewed, on " + nameOf(orch) + ". The approval works once.";
  $("approve-gates").replaceChildren(...gates.map((gate, index) => el("label", { class: "gate", for: "gate-" + index },
    gate.notice ? el("pre", { text: gate.notice.trim() }) : null,
    el("span", { text: gate.prompt.replace(/:\s*$/, "") }),
    el("input", { type: "text", id: "gate-" + index, autocomplete: "off", spellcheck: "false", required: "" }))));
  $("approve-orch-label").textContent = "Type the Orchestrator nickname " + orch.name + " to confirm where this goes";
  $("approve-orch").value = "";
  const tick = () => {
    const left = Math.max(0, Math.round((task.deadline || 0) - Date.now() / 1000));
    $("approve-clock").textContent = "This approval expires in " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") + ".";
  };
  tick();
  clearInterval(clock);
  clock = setInterval(tick, 1000);
  $("approve-dialog").showModal();
  const first = $("approve-gates").querySelector("input");
  (first || $("approve-orch")).focus();
}

async function submitApproval(event) {
  event.preventDefault();
  const task = state.work.firewall.apply;
  const answers = [...$("approve-gates").querySelectorAll("input")].map((input) => input.value);
  const orchestrator = $("approve-orch").value;
  $("approve-dialog").close();
  try {
    await post("/api/tasks/" + task.id + "/approve", { answers, orchestrator });
  } catch (error) {
    $("fw-progress-text").textContent = "Could not send the approval: " + error.message;
  }
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
$("fw-file").addEventListener("change", (event) => { if (event.target.files[0]) loadFirewallCsv(event.target.files[0]); });
$("fw-reload").addEventListener("click", restartFirewall);
$("fw-restart").addEventListener("click", restartFirewall);
$("fw-again").addEventListener("click", restartFirewall);
$("fw-plan").addEventListener("click", () => startTask(state.work.firewall, "plan", { action: "plan", kind: "firewall", csv_text: state.work.firewall.csv }, rerenderFirewall));
$("fw-approve").addEventListener("click", () => startTask(state.work.firewall, "apply", { action: "apply", kind: "firewall", plan_task: state.work.firewall.plan.id }, rerenderFirewall));
$("fw-open-approval").addEventListener("click", openApproval);
$("fw-cancel").addEventListener("click", async () => {
  try { await post("/api/tasks/" + state.work.firewall.apply.id + "/cancel"); } catch (error) { $("fw-progress-text").textContent = error.message; }
});
$("approve-form").addEventListener("submit", submitApproval);
$("approve-later").addEventListener("click", () => $("approve-dialog").close());
$("approve-dialog").addEventListener("close", () => clearInterval(clock));
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
