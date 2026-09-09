// Drives /nostr-admin (see server.py's admin_page and the /nostr-admin/api/*
// routes). Loaded with script-src 'self' only (web/page.py's
// CONTENT_SECURITY_POLICY) - no inline script, same convention as the
// login/account pages.
(() => {
  "use strict";

  const gate = document.getElementById("gate");
  const gateTitle = document.getElementById("gate-title");
  const gateMessage = document.getElementById("gate-message");
  const app = document.getElementById("app");
  const whoami = document.getElementById("whoami");
  const banner = document.getElementById("banner");
  const tbody = document.getElementById("identities-body");
  const emptyMessage = document.getElementById("empty-message");
  const searchInput = document.getElementById("search");
  const showRevoked = document.getElementById("show-revoked");
  const addForm = document.getElementById("add-form");
  const addSubmit = document.getElementById("add-submit");
  const refreshButton = document.getElementById("refresh");

  let identities = [];

  function showBanner(message, kind) {
    banner.textContent = message;
    banner.className = kind;
    if (kind === "success") {
      window.setTimeout(() => {
        if (banner.textContent === message) {
          banner.className = "";
          banner.textContent = "";
        }
      }, 4000);
    }
  }

  async function api(path, options) {
    const response = await fetch(path, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options && options.headers) },
    });
    let body = null;
    try {
      body = await response.json();
    } catch (e) {
      body = null;
    }
    if (!response.ok) {
      const message = (body && body.error) || `request failed (HTTP ${response.status})`;
      throw new Error(message);
    }
    return body;
  }

  function formatTimestamp(seconds) {
    if (!seconds) return "never";
    return new Date(seconds * 1000).toLocaleString();
  }

  function truncatePubkey(npub) {
    if (!npub || npub.length <= 20) return npub || "";
    return `${npub.slice(0, 12)}…${npub.slice(-6)}`;
  }

  function matchesFilter(identity, needle) {
    if (!needle) return true;
    const haystack = [
      identity.username,
      identity.label || "",
      identity.npub,
      identity.pubkey,
      identity.signer_type,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(needle);
  }

  function renderRows() {
    const needle = searchInput.value.trim().toLowerCase();
    const includeRevoked = showRevoked.checked;

    const rows = identities.filter((identity) => {
      if (!includeRevoked && !identity.enabled) return false;
      return matchesFilter(identity, needle);
    });

    tbody.innerHTML = "";
    emptyMessage.style.display = rows.length === 0 ? "block" : "none";

    for (const identity of rows) {
      const tr = document.createElement("tr");

      const statusChip = identity.enabled
        ? '<span class="chip">active</span>'
        : '<span class="chip revoked">revoked</span>';

      tr.innerHTML = `
        <td>${escapeHtml(identity.username)}</td>
        <td class="pubkey" title="${escapeHtml(identity.pubkey)}">${escapeHtml(truncatePubkey(identity.npub))}</td>
        <td>${escapeHtml(identity.signer_type)}</td>
        <td class="label-cell">${escapeHtml(identity.label || "")}</td>
        <td>${statusChip}</td>
        <td>${escapeHtml(formatTimestamp(identity.created_at))}</td>
        <td>${escapeHtml(formatTimestamp(identity.last_used))}</td>
        <td class="row-actions"></td>
      `;

      const actions = tr.querySelector(".row-actions");

      if (identity.enabled) {
        const renameButton = document.createElement("button");
        renameButton.type = "button";
        renameButton.className = "secondary";
        renameButton.textContent = "Rename";
        renameButton.addEventListener("click", () => renameIdentity(identity));
        actions.appendChild(renameButton);

        const revokeButton = document.createElement("button");
        revokeButton.type = "button";
        revokeButton.className = "danger";
        revokeButton.textContent = "Revoke";
        revokeButton.addEventListener("click", () => revokeIdentity(identity));
        actions.appendChild(revokeButton);
      }

      tbody.appendChild(tr);
    }
  }

  function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }

  async function loadIdentities() {
    try {
      const body = await api("/nostr-admin/api/identities", { method: "GET" });
      identities = body.identities;
      renderRows();
    } catch (e) {
      showBanner(`Could not load identities: ${e.message}`, "error");
    }
  }

  async function renameIdentity(identity) {
    const label = window.prompt(`New label for ${identity.username}'s identity:`, identity.label || "");
    if (label === null) return;
    if (!label.trim()) {
      showBanner("Label cannot be empty", "error");
      return;
    }
    try {
      await api(`/nostr-admin/api/identities/${identity.id}/rename`, {
        method: "POST",
        body: JSON.stringify({ username: identity.username, label: label.trim() }),
      });
      showBanner(`Renamed ${identity.username}'s identity`, "success");
      await loadIdentities();
    } catch (e) {
      showBanner(`Could not rename identity: ${e.message}`, "error");
    }
  }

  async function revokeIdentity(identity) {
    if (!window.confirm(`Revoke this identity for ${identity.username}? It can be re-linked later.`)) {
      return;
    }
    try {
      await api(`/nostr-admin/api/identities/${identity.id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ username: identity.username }),
      });
      showBanner(`Revoked ${identity.username}'s identity`, "success");
      await loadIdentities();
    } catch (e) {
      showBanner(`Could not revoke identity: ${e.message}`, "error");
    }
  }

  addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    addSubmit.disabled = true;
    try {
      const formData = new FormData(addForm);
      const label = (formData.get("label") || "").toString().trim();
      await api("/nostr-admin/api/identities", {
        method: "POST",
        body: JSON.stringify({
          username: (formData.get("username") || "").toString().trim(),
          pubkey: (formData.get("pubkey") || "").toString().trim(),
          signer_type: formData.get("signer_type"),
          label: label || null,
          replace: formData.get("replace") === "on",
        }),
      });
      showBanner("Identity linked", "success");
      addForm.reset();
      await loadIdentities();
    } catch (e) {
      showBanner(`Could not link identity: ${e.message}`, "error");
    } finally {
      addSubmit.disabled = false;
    }
  });

  searchInput.addEventListener("input", renderRows);
  showRevoked.addEventListener("change", renderRows);
  refreshButton.addEventListener("click", loadIdentities);

  async function init() {
    gate.classList.remove("hidden");
    let session;
    try {
      session = await api("/nostr-admin/api/session", { method: "GET" });
    } catch (e) {
      gateTitle.textContent = "Could not check access";
      gateMessage.textContent = e.message;
      return;
    }

    if (!session.authenticated) {
      gateTitle.textContent = "Sign in required";
      gateMessage.textContent = "Log in to YunoHost as an administrator, then reload this page.";
      return;
    }
    if (!session.is_admin) {
      gateTitle.textContent = "Admin access required";
      gateMessage.textContent = `Signed in as ${session.username}, which is not in the "admins" group.`;
      return;
    }

    gate.classList.add("hidden");
    app.classList.remove("hidden");
    whoami.textContent = `Signed in as ${session.username}`;
    await loadIdentities();
  }

  init();
})();
