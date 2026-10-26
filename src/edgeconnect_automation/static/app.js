// EdgeConnect Automation GUI shell. The browser only shows what the Python server decided; it never validates or
// decides anything itself. Every value is written with textContent, never as HTML.
"use strict";

const TASKS = [
  { id: "firewall", title: "Firewall rules", text: "Add or change zone-based firewall rules between segments, from a CSV.", writes: true, href: "#/do/firewall" },
  { id: "applications", title: "Applications", text: "Define custom applications by address, port or domain, and AppExpress entries.", writes: true, href: "#/do/app-definitions" },
  { id: "app-groups", title: "Application groups", text: "Group applications so one firewall rule can match them all.", writes: true, href: "#/do/app-groups" },
  { id: "address-groups", title: "Address groups", text: "Name sets of addresses for firewall rules to use.", writes: true, href: "#/do/address-groups" },
  { id: "service-groups", title: "Service groups", text: "Name sets of protocols and ports for firewall rules to use.", writes: true, href: "#/do/service-groups" },
  { id: "template-acls", title: "Template ACLs", text: "Merge access lists into the Access Lists template of template groups.", writes: true, href: "#/do/template-acls" },
  { id: "zones", title: "Missing zones", text: "Create the firewall zones your rules need that this Orchestrator does not have yet.", writes: true, href: "#/do/zones" },
  { id: "remove", title: "Remove by CSV", text: "Delete exactly the objects listed in a CSV, after three warnings and typed confirmations.", writes: true, href: "#/remove" },
  { id: "editor", title: "Build a firewall CSV", text: "Pick segments, zones, groups and applications from this Orchestrator instead of typing them.", writes: false, href: "#/edit/firewall" },
  { id: "changes", title: "See what changed", text: "Look through earlier runs, their outcomes and every row they touched.", writes: false, href: "#/runs" },
  { id: "inventory", title: "Inventory", text: "Look through the segments, zones and groups this Orchestrator has now.", writes: false, href: "#/inventory" },
];
const SHAPE = { green: "●", amber: "▲", red: "■" };
const OPEN_STATES = new Set(["queued", "running", "awaiting_approval"]);

const state = { fleet: [], current: null, tasks: [], work: { csvs: {}, inventory: null, flow: {} } };
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
  $("home-writes").textContent = !orch ? "Add an Orchestrator to .env, then check again."
    : orch.writes ? "Changes are allowed on " + nameOf(orch) + ". Every write still shows its preview and needs your typed confirmation."
    : "Read-only on " + nameOf(orch) + ": you can plan and preview, but writes are off. Set " + orch.name + "_gui_writes=on in .env to allow them.";
  document.title = (orch ? nameOf(orch) + " · " : "") + "EdgeConnect Automation";
}

/* switching Orchestrator resets everything; ask first when there is something to lose */
function openTasks(name) { return state.tasks.filter((task) => task.orchestrator === name && OPEN_STATES.has(task.state)); }

function requestSwitch(name) {
  if (name === state.current) return;
  const editing = Boolean(state.work.editor && state.work.editor.dirty);
  const csvs = Object.keys(state.work.csvs).length + (editing ? 1 : 0);
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
  state.work = { csvs: {}, inventory: null, flow: {} };
  store("ec-orchestrator", name);
  renderSwitcher();
  renderFleet();
  renderHeader();
  location.hash = "#/";
  render();
  $("main").focus();
}

function downloadCsvs() {
  if (state.work.editor && state.work.editor.dirty) saveEditorCsv();
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
    el("a", { class: "intent", href: task.href },
      // Title first, so a screen reader names the link by its task; CSS shows the kind above it.
      el("h3", { text: task.title }),
      el("p", { text: task.text }),
      el("span", { class: "kind" + (task.writes ? " writes" : ""), text: task.writes ? (orch && orch.writes ? "changes Orchestrator" : "preview only here") : "read only" })))));
}

function show(view) {
  for (const id of ["view-home", "view-flow", "view-editor", "view-runs", "view-run", "view-inventory"]) $(id).hidden = id !== view;
}

function render() {
  const hash = location.hash;
  if (hash === "#/runs") { show("view-runs"); return runsTable.load(); }
  const run = hash.match(/^#\/runs\/([\w-]+)$/);
  if (run) { show("view-run"); return loadRun(run[1]); }
  if (hash === "#/inventory") { show("view-inventory"); return renderInventory(); }
  if (hash === "#/edit/firewall") { show("view-editor"); return renderEditor(); }
  if (hash === "#/remove") { show("view-flow"); return openFlow("", true); }
  const kind = hash.match(/^#\/do\/([\w-]+)$/);
  if (kind && FLOWS[kind[1]]) { show("view-flow"); return openFlow(kind[1], false); }
  show("view-home");
  renderIntents();
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
    if (location.hash === "#/edit/firewall" && !OPEN_STATES.has(view.state)) renderEditor();
    loadTasks();
  };
  events.onerror = () => events.close();
}

/* guided tasks. A change: Load, Fix, Plan, Review, Approve, Apply, Done. Remove by CSV: Load, Preview, Confirm, Delete, Done.
   Each step is a server task; this only shows them. */
const FLOWS = {
  firewall: { title: "Firewall rules", things: "rules", file: "a firewall CSV", help: "One row per rule, with the same columns the command line uses.", validate: true },
  "app-definitions": { title: "Applications", things: "applications", file: "an applications CSV", help: "One row per application definition or AppExpress entry, with the same columns the command line uses." },
  "app-groups": { title: "Application groups", things: "application groups", file: "an application groups CSV", help: "One row per application group, with the same columns the command line uses." },
  "address-groups": { title: "Address groups", things: "address groups", file: "an address groups CSV", help: "One row per address group rule, with the same columns the command line uses." },
  "service-groups": { title: "Service groups", things: "service groups", file: "a service groups CSV", help: "One row per service group rule, with the same columns the command line uses." },
  "template-acls": { title: "Template ACLs", things: "access list entries", file: "a template ACLs CSV", help: "One row per access list entry, with the same columns the command line uses." },
  zones: { title: "Missing zones", things: "zones", names: true },
};
const REMOVABLE = ["firewall", "template-acls", "address-groups", "service-groups", "app-groups", "app-definitions"];
const STEPS = ["Load", "Fix", "Plan", "Review", "Approve", "Apply", "Done"];
const REMOVE_STEPS = ["Load", "Preview", "Confirm", "Delete", "Done"];
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

// [step index, stopped] for the stepper
function flowStep(flow) {
  const { validate, plan, apply } = flow;
  if (flow.remove) {
    if (!apply) return [0, false];
    const asked = Boolean(apply.result && apply.result.approval);
    if (!FINAL_STATES.has(apply.state) && !asked) return [1, false];
    if (!asked) return [1, true];  // blocked, or nothing in the CSV exists
    if (apply.state === "awaiting_approval") return [2, false];
    if (apply.state === "applying") return [3, false];
    return [4, apply.state !== "done"];
  }
  if (apply) {
    if (apply.state === "applying") return [5, false];
    if (FINAL_STATES.has(apply.state)) return [6, apply.state !== "done"];
    return [4, false];
  }
  if (plan) {
    if (plan.state === "planned") return [3, false];
    return [2, plan.state === "failed"];
  }
  if (!flow.csv) return [0, false];
  return [1, Boolean(validate && validate.state === "failed")];
}

const issueColumns = [
  { key: "row", label: "Row" }, { key: "column", label: "Column" }, { key: "rule", label: "Rule", mono: true },
  { key: "value", label: "Value", mono: true }, { key: "message", label: "Problem" }, { key: "fix", label: "Fix" },
];
let flowIssueTask = "";
const flowIssues = new PagedTable({ id: "flow-issues", label: "problems in the CSV", container: $("flow-issues"), path: () => flowIssueTask && "/api/tasks/" + flowIssueTask + "/issues", filters: [{ key: "rule", label: "All rules" }, { key: "column", label: "All columns" }], columns: issueColumns, empty: "No problems." });

function diffCell(row) {
  if (!row.fields.length) return "";
  return el("ul", { class: "diff" }, ...row.fields.map((item) => el("li", null,
    el("span", { text: item.field + ": " }),
    item.before == null ? null : el("span", { class: "before", text: JSON.stringify(item.before) }),
    item.before == null || item.after == null ? null : " → ",
    item.after == null ? el("span", { class: "before", text: "(removed)" }) : el("span", { class: "after", text: JSON.stringify(item.after) }))));
}
let flowPlanTask = "";
const flowChanges = new PagedTable({
  id: "flow-changes", label: "changes", container: $("flow-changes"), path: () => flowPlanTask && "/api/tasks/" + flowPlanTask + "/changes",
  problems: "Deletes only", filters: [{ key: "action", label: "All actions" }, { key: "type", label: "All object types" }], empty: "Nothing to change.",
  columns: [
    { key: "action", label: "Action", cell: (row) => row.action === "delete" ? toneCell("delete", "bad") : row.action },
    { key: "type", label: "Type" }, { key: "scope", label: "Where" }, { key: "object", label: "Object", mono: true },
    { key: "fields", label: "Field changes", cell: diffCell },
  ],
});
let flowApplyTask = "";
const flowRows = new PagedTable({
  id: "flow-rows", label: "rows written", container: $("flow-rows"), path: () => flowApplyTask && "/api/tasks/" + flowApplyTask + "/rows",
  problems: "Problems only", filters: [{ key: "outcome", label: "All outcomes" }], empty: "No per-row outcomes for this run.",
  columns: [{ key: "row", label: "Row" }, { key: "item", label: "Item" }, { key: "scope", label: "Scope" }, { key: "outcome", label: "Outcome", cell: (row) => toneCell(row.outcome, row.tone) }, { key: "reason", label: "Reason" }],
});

function notes(list, items) {
  list.replaceChildren(...(items || []).map((item) => el("li", { text: item })));
}

function plural(count, word) { return count + " " + word + (count === 1 ? "" : "s"); }

// The flow the address asks for; another kind, or switching between change and remove, starts fresh.
function openFlow(kind, remove) {
  const flow = state.work.flow;
  if (Boolean(flow.remove) !== remove || (!remove && flow.kind !== kind)) {
    state.work.flow = { kind: remove ? (flow.remove && flow.kind) || "firewall" : kind, remove };
    state.work.csvs = {};
  }
  renderFlow();
}

function renderFlow() {
  const flow = state.work.flow;
  const info = FLOWS[flow.kind];
  const orch = current();
  const where = orch ? nameOf(orch) : "this Orchestrator";
  const steps = flow.remove ? REMOVE_STEPS : STEPS;
  const last = steps.length - 1;
  const [step, stopped] = flowStep(flow);
  $("flow-orch").textContent = orch ? nameOf(orch) : "No Orchestrator configured";
  $("flow-title").textContent = flow.remove ? "Remove by CSV" : info.title;
  $("flow-steps").replaceChildren(...steps.map((name, index) => {
    const finished = index < step || (index === last && step === last && !stopped);
    const item = el("li", { class: finished ? "done" : index === step && stopped ? "stopped" : "", text: name });
    if (index === step) item.setAttribute("aria-current", "step");
    return item;
  }));
  for (const id of ["flow-load", "flow-fix", "flow-review", "flow-progress", "flow-done"]) $(id).hidden = true;

  if (step === 0) {
    $("flow-load").hidden = false;
    $("flow-remove-kind").hidden = !flow.remove;
    $("flow-names").hidden = !info.names || flow.remove;
    $("flow-csv").hidden = Boolean(info.names) && !flow.remove;
    $("flow-load-title").textContent = flow.remove ? "Load the CSV of what to delete" : info.names ? "Name the zones to create" : "Load " + info.file;
    $("flow-load-text").textContent = flow.remove ? "Pick the object type, then load a CSV with the same columns you would use to create them. Only the exact objects it names are deleted, after three warnings."
      : info.names ? "One zone name per line. Planning reads which zones " + where + " already has and changes nothing."
      : info.help + " Nothing is sent to Orchestrator until you approve the exact changes.";
    $("flow-file-name").textContent = flow.file ? "Loaded " + flow.file : "";
    $("flow-build").hidden = flow.kind !== "firewall" || flow.remove;
    return;
  }

  if (flow.remove && step === 1 && !stopped) {
    $("flow-progress").hidden = false;
    $("flow-progress-title").textContent = "Building the deletion table";
    $("flow-progress-text").textContent = flow.apply.state === "queued" ? "Waiting for another write on this Orchestrator to finish." : "Matching every row of " + flow.file + " to what " + where + " has now. Nothing is deleted.";
    $("flow-open-approval").hidden = true;
    $("flow-cancel").hidden = false;
    return;
  }

  if ((!flow.remove && (step === 1 || (step === 2 && stopped))) || (flow.remove && step === 1)) {
    const task = flow.remove ? flow.apply : step === 1 ? flow.validate : flow.plan;
    const result = task && task.result;
    const finished = !info.validate && step === 1 && !flow.remove ? true : task && FINAL_STATES.has(task.state);
    $("flow-fix").hidden = false;
    $("flow-plan").hidden = flow.remove || step !== 1 || !(info.validate ? task && task.state === "done" : true);
    $("flow-plan").textContent = "Plan on " + where;
    $("flow-fix-title").textContent = flow.remove ? "Nothing deleted" : step === 1 ? "Check " + flow.file : "Plan stopped";
    $("flow-fix-text").textContent = !finished ? "Checking every row…"
      : !flow.remove && !info.validate && step === 1 ? flow.file + " is checked while planning. Plan it on " + where + ": that reads the Orchestrator and changes nothing."
      : result && result.issues ? plural(result.issues, "problem") + " to fix in the CSV. Correct them, then load it again." + (step > 1 || flow.remove ? " Nothing was written." : "")
      : task.state === "failed" ? task.message
      : flow.remove ? "None of the " + info.things + " in " + flow.file + " exist on " + where + ", so there is nothing to delete."
      : "Every row is valid. Next, plan it against " + where + ": that reads the Orchestrator and changes nothing.";
    notes($("flow-fix-warnings"), result ? result.warnings : []);
    $("flow-issues").hidden = !(result && result.issues);
    $("flow-edit").hidden = !(flow.kind === "firewall" && !flow.remove && result && result.issues);
    if (result && result.issues) {
      if (flowIssueTask !== task.id) { flowIssueTask = task.id; flowIssues.reset(); }
      flowIssues.load();
    }
    return;
  }

  if ((!flow.remove && step === 3) || (flow.remove && step === 2)) {
    const task = flow.remove ? flow.apply : flow.plan;
    const result = task.result;
    $("flow-review").hidden = false;
    $("flow-review-title").textContent = flow.remove ? "Warning 1 of 3: everything below will be deleted" : "Review the changes";
    $("flow-deletes").hidden = !result.deletes;
    $("flow-deletes").textContent = !result.deletes ? ""
      : flow.remove ? plural(result.deletes, "object") + " will be deleted from " + where + ". Anything that uses " + (result.deletes === 1 ? "it" : "them") + " may stop working, and nothing is restored automatically."
      : plural(result.deletes, "object") + " will be deleted. They are listed first.";
    $("flow-warnings").replaceChildren(...(result.warnings.length ? [el("div", { class: "callout gate" }, el("p", { class: "notes-title", text: "Warnings (do not block)" }), el("ul", { class: "notes" }, ...result.warnings.map((item) => el("li", { text: item }))))] : []));
    notes($("flow-counts"), result.counts);
    if (flowPlanTask !== task.id) { flowPlanTask = task.id; flowChanges.reset(); $("flow-understood").checked = false; }
    flowChanges.load();
    $("flow-confirm").hidden = !flow.remove;
    $("flow-understood-text").textContent = "I understand that " + (result.deletes === 1 ? "this object" : "these " + plural(result.deletes, "object")) + " will be deleted from " + where + " and are not restored automatically.";
    $("flow-delete").disabled = !$("flow-understood").checked;
    const canWrite = Boolean(orch && orch.writes && result.changes);
    $("flow-approve").hidden = flow.remove || !canWrite;
    $("flow-writes-off").hidden = flow.remove || canWrite;
    $("flow-writes-off").textContent = !result.changes ? "Nothing to change: " + where + " already has every one of the " + info.things + " in this request."
      : "Writes are off for " + where + ". Set " + orch.name + "_gui_writes=on in .env to approve changes here, or apply this plan with the command line.";
    return;
  }

  if (!flow.remove && step === 2) {
    $("flow-progress").hidden = false;
    $("flow-progress-title").textContent = "Planning on " + where;
    $("flow-progress-text").textContent = flow.plan.state === "queued" ? "Waiting to start." : "Reading what " + where + " has now, then working out every change. Nothing is written.";
    $("flow-open-approval").hidden = true;
    $("flow-cancel").hidden = true;
    return;
  }

  if (step < last) {
    const writing = flow.apply.state === "applying";
    const awaiting = flow.apply.state === "awaiting_approval";
    $("flow-progress").hidden = false;
    $("flow-progress-title").textContent = writing ? (flow.remove ? "Deleting from " : "Writing to ") + where : awaiting ? "Waiting for your approval" : "Building the exact preview";
    $("flow-progress-text").textContent = writing ? (flow.remove ? "Deleting, then reading back to confirm they are gone." : "Writing, then reading back to confirm every appliance has it.") + " Do not close this page."
      : awaiting ? "Nothing has been written. Type the confirmations to approve this exact preview." : flow.apply.state === "queued" ? "Waiting for another write on this Orchestrator to finish." : "Checking that Orchestrator still matches the plan.";
    $("flow-open-approval").hidden = !awaiting;
    $("flow-cancel").hidden = writing;
    if (awaiting && !flow.apply.prompted) { flow.apply.prompted = true; openApproval(); }
    return;
  }

  const task = flow.apply;
  const result = task.result || {};
  $("flow-done").hidden = false;
  $("flow-done-title").replaceChildren(task.state === "done" ? toneCell(flow.remove ? "Deleted and confirmed" : "Written and confirmed", "ok") : toneCell({ rejected: "Rejected", expired: "Expired", cancelled: "Cancelled", failed: "Stopped" }[task.state] || task.state, "bad"));
  $("flow-done-text").textContent = task.state !== "done" ? task.message
    : flow.remove ? "Every object in the table was deleted from " + where + ", and reading back confirms it."
    : "Every change was written to " + where + " and read back from it.";
  notes($("flow-done-counts"), result.counts);
  $("flow-run-link").hidden = !result.run_id;
  $("flow-run-link").href = "#/runs/" + (result.run_id || "");
  $("flow-rows").hidden = !result.rows;
  if (result.rows) {
    if (flowApplyTask !== task.id) { flowApplyTask = task.id; flowRows.reset(); }
    flowRows.load();
  }
}

function rerenderFlow() { if (!$("view-flow").hidden) renderFlow(); }

function loadFlowCsv(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result);
    const flow = state.work.flow;
    if (flow.remove) flow.kind = $("flow-kind").value;
    Object.assign(flow, { file: file.name, csv: text });
    state.work.csvs = { [file.name]: text };
    if (flow.remove) startTask(flow, "apply", { action: "delete", kind: flow.kind, csv_text: text }, rerenderFlow);
    else if (FLOWS[flow.kind].validate) startTask(flow, "validate", { action: "validate", csv_text: text }, rerenderFlow);
    else renderFlow();
  };
  reader.readAsText(file);
}

function planZones(event) {
  event.preventDefault();
  const names = $("flow-zone-names").value.split(/[\n,]+/).map((name) => name.trim()).filter(Boolean);
  Object.assign(state.work.flow, { names, file: plural(names.length, "zone") });
  startTask(state.work.flow, "plan", { action: "plan", kind: "zones", names }, rerenderFlow);
}

function restartFlow() {
  const flow = state.work.flow;
  if (flow.apply && flow.apply.id && OPEN_STATES.has(flow.apply.state)) post("/api/tasks/" + flow.apply.id + "/cancel").catch(() => {});  // already finished
  state.work.flow = { kind: flow.kind, remove: flow.remove };
  state.work.csvs = {};
  $("flow-file").value = "";
  renderFlow();
  (FLOWS[flow.kind].names && !flow.remove ? $("flow-zone-names") : $("flow-file")).focus();
}

/* approval: the server checks every answer, and the tick box; the dialog only collects them */
let clock = null;
function openApproval() {
  const task = state.work.flow.apply;
  const orch = current();
  if (!task || task.state !== "awaiting_approval" || !orch) return;
  const remove = state.work.flow.remove;
  const gates = task.result.approval.gates;
  $("approve-band").replaceChildren(el("span", { text: nameOf(orch) + " " }), el("span", { class: "mono", text: "(" + orch.name + ", " + orch.url + ")" }));
  $("approve-title").textContent = remove ? "Approve this deletion" : "Approve this write";
  $("approve-text").textContent = "You are approving exactly the " + (remove ? "deletion table" : "changes") + " you reviewed, on " + nameOf(orch) + ". The approval works once.";
  $("approve-gates").replaceChildren(...gates.map((gate, index) => el("label", { class: "gate", for: "gate-" + index },
    gate.notice ? el("pre", { text: gate.notice.trim() }) : null,
    el("span", { text: gate.prompt.replace(/:\s*$/, "") }),
    el("input", { type: "text", id: "gate-" + index, autocomplete: "off", spellcheck: "false", required: "" }))));
  $("approve-orch-label").textContent = "Type the Orchestrator nickname " + orch.name + " to confirm where this goes";
  $("approve-orch").value = "";
  $("approve-submit").textContent = remove ? "Delete" : "Approve and write";
  $("approve-submit").className = "btn " + (remove ? "danger" : "primary");
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
  const flow = state.work.flow;
  const answers = [...$("approve-gates").querySelectorAll("input")].map((input) => input.value);
  const orchestrator = $("approve-orch").value;
  $("approve-dialog").close();
  try {
    await post("/api/tasks/" + flow.apply.id + "/approve", { answers, orchestrator, understood: Boolean(flow.remove && $("flow-understood").checked) });
  } catch (error) {
    $(flow.remove ? "flow-counts" : "flow-progress-text").textContent = "Could not send the approval: " + error.message;
  }
}

/* firewall CSV editor. Rows are edited here; the server parses and writes the CSV, offers the choices, and checks rows. */
const EDITOR_PAGE = 50;
let editorSpec = null;
let editorRowIndex = -1;

function editor() {
  if (!state.work.editor) state.work.editor = { rows: [], extra: [], name: "firewall-rules.csv", started: false, dirty: false, page: 1, q: "", check: null, options: null, optionsFor: "" };
  return state.work.editor;
}

async function loadEditorSpec() {
  if (!editorSpec) editorSpec = await api("/api/editor/firewall");
  return editorSpec;
}

// Choices for the name columns come from the inventory read of the current Orchestrator; read it if it is not read yet.
async function editorOptions() {
  const ed = editor();
  const inventory = state.work.inventory;
  if (!inventory) readInventory();  // after a failed read, Inventory has the button to read again
  if (inventory && inventory.state === "done" && ed.optionsFor !== inventory.id) {
    try {
      ed.options = await api("/api/editor/options?task=" + encodeURIComponent(inventory.id));
      ed.optionsFor = inventory.id;
    } catch (error) {
      ed.options = null;
    }
  }
}

async function renderEditor() {
  const ed = editor();
  const orch = current();
  const where = orch ? nameOf(orch) : "this Orchestrator";
  $("editor-orch").textContent = orch ? nameOf(orch) : "No Orchestrator configured";
  let spec;
  try {
    spec = await loadEditorSpec();
  } catch (error) {
    $("editor-start-text").textContent = "Could not load the editor: " + error.message;
    return;
  }
  await editorOptions();
  const inventory = state.work.inventory;
  $("editor-inventory").textContent = ed.options ? "Choices come from " + where + "'s inventory, read " + new Date(inventory.finished * 1000).toLocaleTimeString() + "."
    : inventory && inventory.state === "failed" ? "Could not read " + where + "'s inventory, so segment, zone and group choices are empty: " + inventory.message + " Read it again from Inventory."
    : "Reading " + where + "'s inventory for the segment, zone and group choices…";
  $("editor-start").hidden = ed.started;
  $("editor-grid-panel").hidden = !ed.started;
  $("editor-actions").hidden = !ed.started;
  const select = $("editor-source");
  if (!select.options.length) select.replaceChildren(...spec.sources.map((item) => el("option", { value: item.id, text: item.label })));
  $("editor-source-row").hidden = !spec.sources.length;
  if (!ed.started) return;
  $("editor-name").textContent = ed.name + (ed.dirty ? " (not saved)" : "");
  $("editor-check-orch").textContent = "Check against " + where;
  renderEditorGrid();
  renderEditorCheck();
}

function matchText(row) {
  const parts = [];
  for (const [label, keys] of [["from", ["source_address", "source_address_group"]], ["to", ["destination_address", "destination_address_group"]], ["either", ["either_address", "either_address_group"]],
    ["app", ["application", "application_group"]], ["", ["protocol"]], ["port", ["source_port", "destination_port", "either_port"]], ["service", ["source_service_group", "destination_service_group", "either_service_group"]], ["acl", ["acl"]]]) {
    const values = keys.map((key) => row[key]).filter(Boolean);
    if (values.length) parts.push((label ? label + " " : "") + values.join(", "));
  }
  return parts.join("; ") || "all traffic";
}

function editorMatches() {
  const ed = editor();
  const q = ed.q.trim().toLowerCase();
  const all = ed.rows.map((row, index) => index);
  if (!q) return all;
  return all.filter((index) => Object.values(ed.rows[index]).some((value) => String(value).toLowerCase().includes(q)));
}

function renderEditorGrid() {
  const ed = editor();
  const matches = editorMatches();
  const pages = Math.max(1, Math.ceil(matches.length / EDITOR_PAGE));
  ed.page = Math.min(Math.max(1, ed.page), pages);
  const shown = matches.slice((ed.page - 1) * EDITOR_PAGE, ed.page * EDITOR_PAGE);
  const button = (text, run, label) => {
    const node = el("button", { class: "btn small", type: "button", text, "aria-label": label });
    node.addEventListener("click", run);
    return node;
  };
  $("editor-rows").replaceChildren(...(shown.length ? shown.map((index) => {
    const row = ed.rows[index];
    const label = row.rule_key || "row " + (index + 2);
    return el("tr", null,
      el("td", { text: String(index + 2) }),
      el("td", { class: "mono", text: row.rule_key }),
      el("td", { text: row.priority }),
      el("td", { text: [row.source_segment, row.source_zone].filter(Boolean).join(" / ") }),
      el("td", { text: [row.destination_segment, row.destination_zone].filter(Boolean).join(" / ") }),
      el("td", { text: matchText(row) }),
      el("td", { text: row.action + (String(row.enabled).toUpperCase() === "FALSE" ? " (disabled)" : "") }),
      el("td", { class: "row-actions" },
        button("Edit", () => openRow(index), "Edit " + label),
        button("Copy", () => copyRow(index), "Copy " + label),
        button("Remove", () => removeRow(index), "Remove " + label)));
  }) : [el("tr", null, el("td", { colspan: "8", class: "muted", text: ed.rows.length ? "No rule matches the search." : "No rules yet. Add one." }))]));
  $("editor-count").textContent = matches.length === ed.rows.length ? plural(ed.rows.length, "rule") : matches.length + " of " + ed.rows.length + " rules match";
  $("editor-where").textContent = "Page " + ed.page + " of " + pages;
  $("editor-prev").disabled = ed.page <= 1;
  $("editor-next").disabled = ed.page >= pages;
}

function changed() {
  const ed = editor();
  ed.dirty = true;
  ed.check = null;
  $("editor-name").textContent = ed.name + " (not saved)";
}

function startEditor(rows, extra, name) {
  const ed = editor();
  Object.assign(ed, { rows, extra: extra || [], name: name || ed.name, started: true, dirty: false, page: 1, q: "", check: null });
  $("editor-q").value = "";
  renderEditor();
}

async function startFromSource() {
  try {
    const parsed = await api("/api/editor/firewall/source?id=" + encodeURIComponent($("editor-source").value));
    startEditor(parsed.rows, parsed.extra, "firewall-rules.csv");
  } catch (error) {
    $("editor-start-text").textContent = "Could not start from it: " + error.message;
  }
}

async function startFromText(text, name) {
  try {
    const parsed = await post("/api/editor/firewall/parse", { csv_text: text });
    startEditor(parsed.rows, parsed.extra, name);
  } catch (error) {
    $("editor-start-text").textContent = "Could not read " + name + ": " + error.message;
  }
}

function addRow() {
  const ed = editor();
  ed.rows.push(Object.assign({}, editorSpec.blank, { rule_key: "rule-" + (ed.rows.length + 1) }));
  changed();
  ed.q = "";
  $("editor-q").value = "";
  ed.page = Math.ceil(ed.rows.length / EDITOR_PAGE);
  renderEditorGrid();
  openRow(ed.rows.length - 1);
}

function copyRow(index) {
  const ed = editor();
  const copy = Object.assign({}, ed.rows[index], { rule_key: ed.rows[index].rule_key + "-copy", priority: "" });
  ed.rows.splice(index + 1, 0, copy);
  changed();
  renderEditorGrid();
  openRow(index + 1);
}

function removeRow(index) {
  editor().rows.splice(index, 1);
  changed();
  renderEditorGrid();
}

/* the per-row form: choices from the inventory; values not on this Orchestrator stay, marked */
function names(value) { return String(value || "").split("|").map((item) => item.trim()).filter(Boolean); }

function choiceOptions(values, current, multiple) {
  const chosen = multiple ? names(current) : [current || ""];
  const list = values.slice();
  for (const value of chosen) if (value && !list.includes(value)) list.push(value);
  return list.map((value) => {
    const option = el("option", { value, text: value === "" ? "(blank)" : value + (values.includes(value) ? "" : " (not on this Orchestrator)") });
    option.selected = chosen.includes(value);
    return option;
  });
}

function sourceValues(source, form) {
  const options = editor().options || { segments: [], zones: {}, all_zones: [], address_groups: [], service_groups: [] };
  if (source.startsWith("zones:")) {
    const segment = form.elements[source.slice(6)].value;
    return options.zones[segment] || options.all_zones;
  }
  return options[source] || [];
}

function fieldControl(field, value, form) {
  const id = "row-" + field.name;
  if (field.kind === "choice") return el("select", { id, name: field.name }, ...choiceOptions(field.choices, value, false));
  if (field.kind === "name") return el("select", { id, name: field.name, "data-source": field.source }, ...choiceOptions([""].concat(sourceValues(field.source, form)), value, false));
  if (field.kind === "names") return el("select", { id, name: field.name, multiple: "", size: "4" }, ...choiceOptions(sourceValues(field.source, form), value, true));
  if (field.kind === "search") return searchControl(field, value);
  return el("input", { type: "text", id, name: field.name, value: value || "", autocomplete: "off", spellcheck: "false" });
}

// Applications and application groups: Orchestrator has thousands, so they are found by search and picked, never typed.
function searchControl(field, value) {
  const hidden = el("input", { type: "hidden", name: field.name, value: value || "" });
  const chips = el("ul", { class: "chips", "aria-label": field.label + " chosen" });
  const drawChips = () => chips.replaceChildren(...names(hidden.value).map((name) => {
    const remove = el("button", { type: "button", class: "chip", "aria-label": "Remove " + name, text: name + " ×" });
    remove.addEventListener("click", () => { hidden.value = names(hidden.value).filter((item) => item !== name).join("|"); drawChips(); });
    return el("li", null, remove);
  }));
  drawChips();
  const box = el("input", { type: "search", id: "row-" + field.name, placeholder: "Search " + field.label.toLowerCase(), autocomplete: "off" });
  const results = el("ul", { class: "chips results", "aria-live": "polite" });
  const find = el("button", { type: "button", class: "btn small", text: "Find" });
  const run = async () => {
    results.replaceChildren(el("li", { class: "muted", text: "Searching…" }));
    try {
      const found = (await api("/api/editor/search?" + query({ orchestrator: state.current, kind: field.source, q: box.value }))).names;
      results.replaceChildren(...(found.length ? found.map((name) => {
        const add = el("button", { type: "button", class: "chip add", text: "+ " + name });
        add.addEventListener("click", () => { if (!names(hidden.value).includes(name)) hidden.value = names(hidden.value).concat(name).join("|"); drawChips(); });
        return el("li", null, add);
      }) : [el("li", { class: "muted", text: "Nothing found." })]));
    } catch (error) {
      results.replaceChildren(el("li", { class: "tone-bad", text: "Search failed: " + error.message }));
    }
  };
  find.addEventListener("click", run);
  box.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); run(); } });
  return el("div", { class: "search-field" }, hidden, chips, el("div", { class: "toolbar" }, box, find), results);
}

function openRow(index) {
  const ed = editor();
  const row = ed.rows[index];
  editorRowIndex = index;
  const form = $("row-form");
  form.replaceChildren();
  $("row-title").textContent = "Row " + (index + 2) + (row.rule_key ? ": " + row.rule_key : "");
  const groups = {};
  for (const field of editorSpec.fields) {
    if (!groups[field.group]) {
      groups[field.group] = el("fieldset", null, el("legend", { text: field.group }));
      form.append(groups[field.group]);
    }
    const control = fieldControl(field, row[field.name], form);
    groups[field.group].append(el("div", { class: "field" }, el("label", { for: "row-" + field.name, text: field.label }), control));
  }
  // zones follow the chosen segment
  for (const side of ["source", "destination"]) {
    form.elements[side + "_segment"].addEventListener("change", () => {
      const zone = form.elements[side + "_zone"];
      zone.replaceChildren(...choiceOptions([""].concat(sourceValues("zones:" + side + "_segment", form)), zone.value, false));
    });
  }
  form.append(el("div", { class: "actions" }, el("button", { class: "btn primary", type: "submit", text: "Keep these values" }), el("button", { class: "btn", type: "button", id: "row-cancel", text: "Cancel" })));
  $("row-cancel").addEventListener("click", () => $("row-dialog").close());
  $("row-dialog").showModal();
  form.elements[0].focus();
}

function saveRow(event) {
  event.preventDefault();
  const ed = editor();
  const form = $("row-form");
  const row = Object.assign({}, ed.rows[editorRowIndex]);
  for (const field of editorSpec.fields) {
    const control = form.elements[field.name];
    row[field.name] = control.multiple ? [...control.selectedOptions].map((option) => option.value).join("|") : control.value;
  }
  ed.rows[editorRowIndex] = row;
  $("row-dialog").close();
  changed();
  renderEditorGrid();
}

async function editorCsv() {
  const ed = editor();
  return (await post("/api/editor/firewall/csv", { rows: ed.rows, extra: ed.extra })).csv_text;
}

async function saveEditorCsv() {
  const ed = editor();
  try {
    const text = await editorCsv();
    const link = el("a", { href: URL.createObjectURL(new Blob([text], { type: "text/csv" })), download: ed.name });
    link.click();
    URL.revokeObjectURL(link.href);
    ed.dirty = false;
    $("editor-name").textContent = ed.name;
  } catch (error) {
    $("editor-check-text").textContent = "Could not save: " + error.message;
  }
}

/* checks: the offline row check, or a read-only plan against the Orchestrator for missing names and conflicts */
let editorIssueTask = "";
const editorIssues = new PagedTable({
  id: "editor-issues", label: "problems in the rules", container: $("editor-issues"), path: () => editorIssueTask && "/api/tasks/" + editorIssueTask + "/issues",
  filters: [{ key: "rule", label: "All rules" }, { key: "column", label: "All columns" }], empty: "No problems.",
  columns: [{ key: "row", label: "Row", cell: (row) => {
    const index = Number(row.row) - 2;
    if (!(index >= 0 && index < editor().rows.length)) return String(row.row || "");
    const open = el("button", { class: "btn small", type: "button", text: "Row " + row.row, "aria-label": "Edit row " + row.row });
    open.addEventListener("click", () => openRow(index));
    return open;
  } }].concat(issueColumns.slice(1)),
});

async function checkEditor(kind) {
  const ed = editor();
  let text;
  try {
    text = await editorCsv();
  } catch (error) {
    ed.check = { state: "failed", message: error.message, result: null };
    return renderEditorCheck();
  }
  const body = kind === "plan" ? { action: "plan", kind: "firewall", csv_text: text } : { action: "validate", csv_text: text };
  ed.check = { state: "queued", action: body.action, result: null };
  renderEditorCheck();
  const holder = {};
  await startTask(holder, "task", body, () => { ed.check = holder.task; if (location.hash === "#/edit/firewall") renderEditorCheck(); });
}

function renderEditorCheck() {
  const task = editor().check;
  const result = task && task.result;
  const where = nameOf(current()) || "this Orchestrator";
  $("editor-check-text").className = task && FINAL_STATES.has(task.state) && (task.state === "failed" || (result && result.issues)) ? "tone-bad" : "muted";
  $("editor-check-text").textContent = !task ? "Check the rules before you use them. Checking writes nothing."
    : !FINAL_STATES.has(task.state) ? (task.action === "plan" ? "Checking against " + where + "…" : "Checking every row…")
    : result && result.issues ? plural(result.issues, "problem") + " to fix. Use the row buttons to open each one."
    : task.state === "failed" ? task.message
    : task.action === "plan" ? "Every rule can be planned on " + where + ": every name exists there." + (result && result.warnings.length ? " Warnings: " + result.warnings.join("; ") : "")
    : "Every row is valid." + (result && result.warnings.length ? " Warnings: " + result.warnings.join("; ") : "") + " Check against " + where + " to find names it does not have.";
  $("editor-issues").hidden = !(result && result.issues);
  if (result && result.issues) {
    if (editorIssueTask !== task.id) { editorIssueTask = task.id; editorIssues.reset(); }
    editorIssues.load();
  }
}

async function useInFirewall() {
  const ed = editor();
  let text;
  try {
    text = await editorCsv();
  } catch (error) {
    $("editor-check-text").textContent = "Could not build the CSV: " + error.message;
    return;
  }
  state.work.flow = { kind: "firewall", remove: false, file: ed.name, csv: text };
  state.work.csvs = { [ed.name]: text };
  startTask(state.work.flow, "validate", { action: "validate", csv_text: text }, rerenderFlow);
  location.hash = "#/do/firewall";
}

function editFlowCsv() {
  const flow = state.work.flow;
  location.hash = "#/edit/firewall";
  startFromText(flow.csv, flow.file);
}

function restartEditor() {
  const ed = editor();
  if (ed.dirty && !confirm("Start over? Your edits to " + ed.name + " are not saved.")) return;
  Object.assign(ed, { rows: [], extra: [], started: false, dirty: false, check: null });
  renderEditor();
}

/* command palette: combobox and listbox, all by keyboard */
let paletteItems = [];
let paletteIndex = 0;

function commands() {
  const list = [{ label: "Go to all tasks", hint: "home", run: () => { location.hash = "#/"; } }];
  for (const task of TASKS) list.push({ label: task.title, hint: task.writes ? "task" : "read only", run: () => { location.hash = task.href; } });
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
$("flow-file").addEventListener("change", (event) => { if (event.target.files[0]) loadFlowCsv(event.target.files[0]); });
$("flow-reload").addEventListener("click", restartFlow);
$("flow-restart").addEventListener("click", restartFlow);
$("flow-again").addEventListener("click", restartFlow);
$("flow-plan").addEventListener("click", () => startTask(state.work.flow, "plan", { action: "plan", kind: state.work.flow.kind, csv_text: state.work.flow.csv }, rerenderFlow));
$("flow-approve").addEventListener("click", () => startTask(state.work.flow, "apply", { action: "apply", kind: state.work.flow.kind, plan_task: state.work.flow.plan.id }, rerenderFlow));
$("flow-names").addEventListener("submit", planZones);
$("flow-understood").addEventListener("change", () => { $("flow-delete").disabled = !$("flow-understood").checked; });
$("flow-delete").addEventListener("click", openApproval);
$("flow-edit").addEventListener("click", editFlowCsv);
$("editor-blank").addEventListener("click", () => startEditor([], [], "firewall-rules.csv"));
$("editor-from-source").addEventListener("click", startFromSource);
$("editor-file").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => startFromText(String(reader.result), file.name);
  reader.readAsText(file);
  event.target.value = "";
});
$("editor-q").addEventListener("input", () => { const ed = editor(); ed.q = $("editor-q").value; ed.page = 1; renderEditorGrid(); });
$("editor-add").addEventListener("click", addRow);
$("editor-prev").addEventListener("click", () => { editor().page -= 1; renderEditorGrid(); });
$("editor-next").addEventListener("click", () => { editor().page += 1; renderEditorGrid(); });
$("editor-check").addEventListener("click", () => checkEditor("validate"));
$("editor-check-orch").addEventListener("click", () => checkEditor("plan"));
$("editor-save").addEventListener("click", saveEditorCsv);
$("editor-use").addEventListener("click", useInFirewall);
$("editor-restart").addEventListener("click", restartEditor);
$("row-form").addEventListener("submit", saveRow);
$("flow-open-approval").addEventListener("click", openApproval);
$("flow-cancel").addEventListener("click", async () => {
  try { await post("/api/tasks/" + state.work.flow.apply.id + "/cancel"); } catch (error) { $("flow-progress-text").textContent = error.message; }
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
