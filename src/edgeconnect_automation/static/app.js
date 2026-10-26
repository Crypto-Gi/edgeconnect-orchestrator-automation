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
  { id: "changes", title: "See what changed", text: "Look through earlier runs, their outcomes and every row they touched.", writes: false },
];
const SHAPE = { green: "●", amber: "▲", red: "■" };
const OPEN_STATES = new Set(["queued", "running", "awaiting_approval"]);

const state = { fleet: [], current: null, tasks: [], work: { csvs: {} } };
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
  state.work = { csvs: {} };
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
    el("a", { class: "intent", href: "#/task/" + task.id },
      // Title first, so a screen reader names the link by its task; CSS shows the kind above it.
      el("h3", { text: task.title }),
      el("p", { text: task.text }),
      el("span", { class: "kind" + (task.writes ? " writes" : ""), text: task.writes ? (orch && orch.writes ? "changes Orchestrator" : "preview only here") : "read only" })))));
}

function render() {
  const match = location.hash.match(/^#\/task\/([\w-]+)$/);
  const task = match && TASKS.find((item) => item.id === match[1]);
  $("view-home").hidden = Boolean(task);
  $("view-task").hidden = !task;
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

/* command palette: combobox and listbox, all by keyboard */
let paletteItems = [];
let paletteIndex = 0;

function commands() {
  const list = [{ label: "Go to all tasks", hint: "home", run: () => { location.hash = "#/"; } }];
  for (const task of TASKS) list.push({ label: task.title, hint: "task", run: () => { location.hash = "#/task/" + task.id; } });
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
