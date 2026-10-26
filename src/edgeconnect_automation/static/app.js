// Placeholder page for GUI step 5: shows what the server decided; the real screens arrive in later steps.
"use strict";

function cell(row, text, className) {
  const td = row.insertCell();
  td.textContent = text;  // never innerHTML: every value comes from Orchestrator or a CSV
  if (className) td.className = className;
}

async function getJSON(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) throw new Error((await response.json()).error || response.statusText);
  return response.json();
}

async function showFleet() {
  const body = document.getElementById("fleet");
  try {
    const { orchestrators } = await getJSON("/api/orchestrators");
    body.replaceChildren();
    for (const item of orchestrators) {
      const row = body.insertRow();
      cell(row, item.label || item.name || item.url);
      cell(row, item.status, item.status);
      cell(row, item.release);
      cell(row, item.writes ? "on" : "off");
      cell(row, item.reason);
    }
  } catch (error) {
    body.replaceChildren();
    cell(body.insertRow(), error.message, "red");
  }
}

async function showTasks() {
  const body = document.getElementById("tasks");
  const { tasks } = await getJSON("/api/tasks");
  body.replaceChildren();
  for (const task of tasks) {
    const row = body.insertRow();
    cell(row, task.id);
    cell(row, [task.action, task.kind].filter(Boolean).join(" "));
    cell(row, task.orchestrator);
    cell(row, task.state);
    cell(row, task.message);
  }
}

showFleet();
showTasks();
setInterval(showTasks, 5000);
