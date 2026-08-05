"use strict";

const catalogsNode = document.getElementById("catalogs");
const catalogStatus = document.getElementById("catalog-status");
const catalogSelect = document.getElementById("catalog-id");
const form = document.getElementById("application-form");
const result = document.getElementById("application-result");

function appendText(parent, tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  parent.appendChild(node);
  return node;
}

async function loadCatalogs() {
  const response = await fetch("/api/developer/catalogs", { credentials: "same-origin" });
  if (!response.ok) throw new Error(`catalog request failed: ${response.status}`);
  const body = await response.json();
  for (const catalog of body.catalogs || []) {
    const card = document.createElement("article");
    card.className = "catalog";
    appendText(card, "h3", catalog.title || catalog.id);
    appendText(card, "p", catalog.description || "No description");
    const link = appendText(card, "a", "OpenAPI document");
    link.href = catalog.openapi_url;
    for (const operation of catalog.operations || []) {
      const row = document.createElement("div");
      row.className = "operation";
      appendText(row, "span", operation.method, "method");
      appendText(row, "span", `${operation.path}${operation.summary ? ` — ${operation.summary}` : ""}`);
      card.appendChild(row);
    }
    catalogsNode.appendChild(card);
    const option = document.createElement("option");
    option.value = catalog.id;
    option.textContent = catalog.title || catalog.id;
    catalogSelect.appendChild(option);
  }
  catalogStatus.textContent = `${(body.catalogs || []).length} 个 catalog`;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  result.textContent = "正在提交…";
  const requestedPlan = document.getElementById("requested-plan").value.trim();
  const payload = {
    catalog_id: catalogSelect.value,
    applicant_id: document.getElementById("applicant-id").value.trim(),
    display_name: document.getElementById("display-name").value.trim(),
  };
  if (requestedPlan) payload.requested_plan = requestedPlan;
  try {
    const response = await fetch("/api/developer/key-applications", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${document.getElementById("portal-token").value}`,
      },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    result.textContent = JSON.stringify(body, null, 2);
  } catch (error) {
    result.textContent = String(error);
  }
});

loadCatalogs().catch((error) => { catalogStatus.textContent = String(error); });
