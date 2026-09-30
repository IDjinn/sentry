// Sentry dashboard — dependency-free polling UI over the JSON API.
"use strict";

const EVENTS_POLL_MS = 2000;
const PANELS_POLL_MS = 5000;
let levelFilter = "";
let currentRole = null;

const $ = (id) => document.getElementById(id);

async function fetchJson(url, opts) {
  const resp = await fetch(url, opts);
  if (!resp.ok) {
    if (resp.status === 401) {
      showLogin();
      throw new Error("authentication required");
    }
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.error || resp.status);
  }
  return resp.json();
}

function setConn(ok) {
  const dot = $("conn");
  dot.className = "dot " + (ok ? "dot-on" : "dot-off");
}

function showLogin() {
  $("login-overlay").classList.remove("hidden");
}

function hideLogin() {
  $("login-overlay").classList.add("hidden");
  $("login-error").classList.add("hidden");
}

function applyIdentity(me) {
  if (me && me.authenticated) {
    currentRole = me.role;
    const label = $("identity");
    label.textContent = me.username + " · " + me.role;
    label.classList.remove("hidden");
    $("logout-btn").classList.remove("hidden");
    hideLogin();
  } else {
    currentRole = null;
    $("identity").classList.add("hidden");
    $("logout-btn").classList.add("hidden");
  }
  // Viewers can't mutate: hide the manual block form.
  $("block-form").style.display = currentRole === "admin" || currentRole === null ? "" : "none";
}

async function bootAuth() {
  try {
    const me = await fetchJson("/api/me");
    applyIdentity(me);
    if (!me.authenticated) showLogin();
  } catch (e) {
    showLogin();
  }
}

async function doLogin(ev) {
  ev.preventDefault();
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const token = $("login-token").value.trim();
  const payload = token ? { token } : { username, password };
  try {
    const resp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(body.error || "login failed");
    applyIdentity({ authenticated: true, username: body.username, role: body.role });
    $("login-password").value = "";
    $("login-token").value = "";
    refreshAll();
  } catch (e) {
    const err = $("login-error");
    err.textContent = e.message;
    err.classList.remove("hidden");
  }
}

async function doLogout() {
  try {
    await fetch("/api/logout", { method: "POST" });
  } catch (e) { /* ignore */ }
  applyIdentity(null);
  showLogin();
}

function text(parent, tag, value, className) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = value;
  parent.appendChild(el);
  return el;
}

function protocolSummary(evt) {
  const proto = evt.protocol || {};
  if (proto.kind === "http") {
    return {
      method: (proto.method || "???").toUpperCase(),
      target: proto.path + (proto.query ? "?" + proto.query : ""),
      status: proto.status != null ? proto.status : "–",
      signals: signalNames(evt),
    };
  }
  if (proto.kind === "syslog") {
    return {
      method: "sys",
      target: proto.message || "",
      status: proto.severity != null ? "sev" + proto.severity : "–",
      signals: signalNames(evt),
    };
  }
  return {
    method: "–",
    target: proto.kind || "(non-http)",
    status: "–",
    signals: signalNames(evt),
  };
}

function signalNames(evt) {
  const signals = Array.isArray(evt.signals) ? evt.signals : [];
  return signals.map((s) => (typeof s === "string" ? s : s.kind)).join(",");
}

async function refreshEvents() {
  const params = new URLSearchParams({ limit: "50" });
  if (levelFilter) params.set("level", levelFilter);
  try {
    const data = await fetchJson("/api/events?" + params);
    setConn(true);
    const tbody = $("events-body");
    tbody.textContent = "";
    $("events-empty").style.display = data.events.length ? "none" : "block";
    for (const evt of data.events) {
      const p = protocolSummary(evt);
      const tr = document.createElement("tr");
      text(tr, "td", (evt.timestamp || "").replace("T", " ").slice(0, 19));
      text(tr, "td", evt.client_ip || "–");
      text(tr, "td", p.method);
      text(tr, "td", p.target);
      text(tr, "td", String(p.status));
      text(tr, "td", evt.risk_level || "info", "level-" + (evt.risk_level || "info"));
      text(tr, "td", evt.verdict || "allow", "verdict-" + (evt.verdict || "allow"));
      text(tr, "td", p.signals);
      tbody.appendChild(tr);
    }
  } catch (e) {
    setConn(false);
  }
}

async function refreshStats() {
  try {
    const data = await fetchJson("/api/stats");
    setConn(true);
    const total = (data.by_level || []).reduce((acc, x) => acc + x.count, 0);
    const acted = (data.by_verdict || [])
      .filter((x) => x.name !== "allow")
      .reduce((acc, x) => acc + x.count, 0);
    $("stat-events").textContent = total;
    $("stat-blocked").textContent = acted;
    $("stat-top-ip").textContent = data.top_ips?.[0]?.name ?? "–";
    $("stat-top-path").textContent = data.top_paths?.[0]?.name ?? "–";
  } catch (e) {
    setConn(false);
  }
}

function actionButton(label, url, after) {
  const btn = document.createElement("button");
  btn.textContent = label;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await fetchJson(url, { method: "POST" });
    } catch (e) {
      alert(e.message);
      btn.disabled = false;
      return;
    }
    after();
  });
  return btn;
}

async function refreshIncidents() {
  try {
    const data = await fetchJson("/api/incidents");
    const ul = $("incidents");
    ul.textContent = "";
    $("incidents-empty").style.display = data.incidents.length ? "none" : "block";
    for (const inc of data.incidents) {
      const li = document.createElement("li");
      const meta = document.createElement("div");
      meta.className = "meta";
      const acked = inc.acknowledged_at ? " · acked" : "";
      text(meta, "div", (inc.risk_level || "?") + " · " + (inc.action || "?") + acked,
        "level-" + (inc.risk_level || "info"));
      text(meta, "small",
        (inc.client_ip ? inc.client_ip + " · " : "") +
        (inc.created_at || "").replace("T", " ").slice(0, 16) +
        (inc.notes ? " · " + inc.notes : ""));
      li.appendChild(meta);
      const btns = document.createElement("div");
      if (!inc.acknowledged_at) {
        btns.appendChild(actionButton("ack", "/api/incidents/" + inc.id + "/ack", refreshIncidents));
        btns.appendChild(document.createTextNode(" "));
      }
      btns.appendChild(actionButton("resolve", "/api/incidents/" + inc.id + "/resolve", refreshIncidents));
      li.appendChild(btns);
      ul.appendChild(li);
    }
  } catch (e) {
    /* keep last render */
  }
}

async function refreshBlocked() {
  try {
    const data = await fetchJson("/api/ips/blocked");
    const ul = $("blocked");
    ul.textContent = "";
    $("blocked-empty").style.display = data.blocked.length ? "none" : "block";
    for (const row of data.blocked) {
      const li = document.createElement("li");
      const meta = document.createElement("div");
      meta.className = "meta";
      text(meta, "div", row.ip);
      text(meta, "small", "strikes " + (row.strikes ?? "–") + " · violations " + (row.total_violations ?? "–"));
      li.appendChild(meta);
      const btns = document.createElement("div");
      btns.appendChild(actionButton("unblock", "/api/ips/" + row.ip + "/unblock", refreshBlocked));
      btns.appendChild(document.createTextNode(" "));
      btns.appendChild(actionButton("forgive", "/api/ips/" + row.ip + "/forgive", refreshBlocked));
      li.appendChild(btns);
      ul.appendChild(li);
    }
  } catch (e) {
    /* keep last render */
  }
}

$("level-filter").addEventListener("change", (ev) => {
  levelFilter = ev.target.value;
  refreshEvents();
});

$("login-form").addEventListener("submit", doLogin);
$("logout-btn").addEventListener("click", doLogout);

$("block-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const ip = $("block-ip").value.trim();
  if (!ip) return;
  try {
    await fetchJson("/api/ips/" + encodeURIComponent(ip) + "/block", { method: "POST" });
    $("block-ip").value = "";
    refreshBlocked();
  } catch (e) {
    alert(e.message);
  }
});

function refreshAll() {
  refreshEvents();
  refreshStats();
  refreshIncidents();
  refreshBlocked();
}

refreshAll();
setInterval(refreshEvents, EVENTS_POLL_MS);
setInterval(refreshStats, PANELS_POLL_MS);
setInterval(refreshIncidents, PANELS_POLL_MS);
setInterval(refreshBlocked, PANELS_POLL_MS);
bootAuth();
