// Warden dashboard — polls backend REST endpoints, renders timeline + caps + creds.
// Spec: PRD §8, §13.

const API_BASE = (() => {
  // If served from the same origin as the backend, use relative URLs.
  // Otherwise (file:// or different port), hit localhost:3000.
  if (location.protocol === "http:" || location.protocol === "https:") {
    if (location.port === "3000") return "";
  }
  return "http://localhost:3000";
})();

const POLL_MS = 1000;
const RETRY_MS = 3000;
const EVENTS_LIMIT = 100;

const state = {
  lastEventId: 0,
  events: [],           // newest first for rendering
  openEventIds: new Set(),
  caps: [],
  creds: [],
  connected: false,
  eventsTimer: null,
  capsTimer: null,
  credsTimer: null,
  ttlTimer: null,
};

// --- DOM refs ---
const $conn = document.getElementById("conn");
const $connLabel = document.getElementById("conn-label");
const $events = document.getElementById("events");
const $eventsEmpty = document.getElementById("events-empty");
const $caps = document.getElementById("caps");
const $capsEmpty = document.getElementById("caps-empty");
const $creds = document.getElementById("creds");
const $credsEmpty = document.getElementById("creds-empty");

// --- Connection indicator ---
function setConnected(up) {
  if (state.connected === up) return;
  state.connected = up;
  $conn.classList.toggle("conn-up", up);
  $conn.classList.toggle("conn-down", !up);
  $connLabel.textContent = up ? "Connected" : "Disconnected";
}

// --- Helpers ---
function fmtTime(ts) {
  // ts is unix millis per PRD §6 events.ts
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function fmtTimeSecs(ts) {
  // credentials.created_at is unix seconds per PRD §6
  return fmtTime(ts * 1000);
}

function fmtCountdown(seconds) {
  if (seconds <= 0) return "expired";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${String(s).padStart(2, "0")}`;
}

function colorClassFor(ev) {
  const t = ev.event_type;
  const outcome = ev.outcome;
  if (t === "sanitizer_redacted") return "ev-yellow";
  if (t === "capability_denied" || t === "tool_blocked" || t === "leak_detected") return "ev-red";
  if (t === "tool_called") return outcome === "error" ? "ev-red" : "ev-green";
  // run_started, run_ended, capability_granted, revoked, and anything else ok
  return "ev-green";
}

function safeParseJson(s) {
  if (s == null) return null;
  if (typeof s !== "string") return s;
  try { return JSON.parse(s); } catch { return s; }
}

function shortDetail(ev) {
  const parts = [];
  if (ev.tool) parts.push(ev.tool);
  if (ev.detail) parts.push(ev.detail);
  if (!parts.length && ev.args_redacted) {
    const args = safeParseJson(ev.args_redacted);
    if (args && typeof args === "object") {
      const keys = Object.keys(args).slice(0, 3).join(", ");
      parts.push(`{${keys}}`);
    }
  }
  return parts.join("  ·  ");
}

// --- Fetch helpers with connection tracking ---
async function getJSON(path) {
  const resp = await fetch(`${API_BASE}${path}`, { method: "GET" });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return await resp.json();
}

async function postJSON(path) {
  const resp = await fetch(`${API_BASE}${path}`, { method: "POST" });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return await resp.json();
}

// --- Events polling ---
async function pollEvents() {
  try {
    const data = await getJSON(`/api/events?since=${state.lastEventId}&limit=${EVENTS_LIMIT}`);
    setConnected(true);
    if (data && Array.isArray(data.events) && data.events.length) {
      for (const ev of data.events) {
        state.events.unshift(ev);
      }
      if (typeof data.latest_id === "number") {
        state.lastEventId = Math.max(state.lastEventId, data.latest_id);
      } else {
        for (const ev of data.events) {
          if (ev.id > state.lastEventId) state.lastEventId = ev.id;
        }
      }
      // keep list bounded
      if (state.events.length > 500) state.events.length = 500;
      renderEvents();
    }
    scheduleEvents(POLL_MS);
  } catch (e) {
    setConnected(false);
    scheduleEvents(RETRY_MS);
  }
}

async function pollCaps() {
  try {
    const data = await getJSON(`/api/active_capabilities`);
    setConnected(true);
    state.caps = (data && Array.isArray(data.capabilities)) ? data.capabilities : [];
    renderCaps();
    scheduleCaps(POLL_MS);
  } catch (e) {
    setConnected(false);
    scheduleCaps(RETRY_MS);
  }
}

async function pollCreds() {
  try {
    const data = await getJSON(`/api/credentials`);
    setConnected(true);
    state.creds = (data && Array.isArray(data.credentials)) ? data.credentials : [];
    renderCreds();
    // Creds change rarely; poll less often.
    scheduleCreds(5000);
  } catch (e) {
    setConnected(false);
    scheduleCreds(RETRY_MS);
  }
}

function scheduleEvents(ms) {
  clearTimeout(state.eventsTimer);
  state.eventsTimer = setTimeout(pollEvents, ms);
}
function scheduleCaps(ms) {
  clearTimeout(state.capsTimer);
  state.capsTimer = setTimeout(pollCaps, ms);
}
function scheduleCreds(ms) {
  clearTimeout(state.credsTimer);
  state.credsTimer = setTimeout(pollCreds, ms);
}

// --- Rendering ---
function renderEvents() {
  if (!state.events.length) {
    $eventsEmpty.style.display = "";
    $events.innerHTML = "";
    return;
  }
  $eventsEmpty.style.display = "none";
  const frag = document.createDocumentFragment();
  for (const ev of state.events) {
    const li = document.createElement("li");
    li.className = colorClassFor(ev);
    if (state.openEventIds.has(ev.id)) li.classList.add("open");
    li.dataset.id = String(ev.id);

    const row = document.createElement("div");
    row.className = "row";

    const ts = document.createElement("span");
    ts.className = "ts";
    ts.textContent = fmtTime(ev.ts);

    const etype = document.createElement("span");
    etype.className = "etype";
    etype.textContent = ev.event_type;

    const detail = document.createElement("span");
    detail.className = "detail";
    detail.textContent = shortDetail(ev);

    const outcome = document.createElement("span");
    outcome.className = "outcome";
    outcome.textContent = ev.outcome || "";

    row.appendChild(ts);
    row.appendChild(etype);
    row.appendChild(detail);
    row.appendChild(outcome);

    const exp = document.createElement("div");
    exp.className = "exp";
    const full = {
      id: ev.id,
      ts: ev.ts,
      run_id: ev.run_id,
      capability_id: ev.capability_id,
      event_type: ev.event_type,
      tool: ev.tool,
      args_redacted: safeParseJson(ev.args_redacted),
      outcome: ev.outcome,
      detail: ev.detail,
      duration_ms: ev.duration_ms,
    };
    exp.textContent = JSON.stringify(full, null, 2);

    li.appendChild(row);
    li.appendChild(exp);

    li.addEventListener("click", () => {
      if (state.openEventIds.has(ev.id)) {
        state.openEventIds.delete(ev.id);
        li.classList.remove("open");
      } else {
        state.openEventIds.add(ev.id);
        li.classList.add("open");
      }
    });

    frag.appendChild(li);
  }
  $events.replaceChildren(frag);
}

function renderCaps() {
  if (!state.caps.length) {
    $capsEmpty.style.display = "";
    $caps.innerHTML = "";
    return;
  }
  $capsEmpty.style.display = "none";
  const now = Math.floor(Date.now() / 1000);
  const frag = document.createDocumentFragment();
  for (const c of state.caps) {
    const li = document.createElement("li");
    li.dataset.id = c.id;

    const idEl = document.createElement("span");
    idEl.className = "cap-id";
    idEl.textContent = c.id;

    const typeEl = document.createElement("span");
    typeEl.className = "cap-type";
    typeEl.textContent = c.cap_type;

    const scopeEl = document.createElement("span");
    scopeEl.className = "cap-scope";
    const scope = safeParseJson(c.scope);
    scopeEl.textContent = scopeSummary(c.cap_type, scope);

    const ttlEl = document.createElement("span");
    ttlEl.className = "cap-ttl";
    const remaining = typeof c.seconds_remaining === "number"
      ? c.seconds_remaining
      : (c.expires_at - now);
    ttlEl.dataset.expires = String(c.expires_at);
    ttlEl.textContent = `expires ${fmtCountdown(remaining)}`;
    if (remaining <= 60) ttlEl.classList.add("expiring");

    const btn = document.createElement("button");
    btn.className = "revoke-btn";
    btn.textContent = "Revoke";
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      btn.disabled = true;
      try {
        await postJSON(`/api/revoke/${encodeURIComponent(c.id)}`);
        // optimistic: drop it locally; next poll will confirm
        state.caps = state.caps.filter((x) => x.id !== c.id);
        renderCaps();
      } catch (err) {
        btn.disabled = false;
      }
    });

    li.appendChild(idEl);
    li.appendChild(typeEl);
    li.appendChild(scopeEl);
    li.appendChild(ttlEl);
    li.appendChild(btn);
    frag.appendChild(li);
  }
  $caps.replaceChildren(frag);
}

function scopeSummary(capType, scope) {
  if (!scope || typeof scope !== "object") return String(scope ?? "");
  if (capType === "github") {
    const perms = Array.isArray(scope.permissions) ? scope.permissions.join(",") : "";
    return `repo=${scope.repo || "?"}  perms=[${perms}]`;
  }
  if (capType === "groq") {
    const models = Array.isArray(scope.models) ? scope.models.join(",") : "";
    const mt = scope.max_tokens_per_call != null ? ` max_tokens=${scope.max_tokens_per_call}` : "";
    return `models=[${models}]${mt}`;
  }
  try { return JSON.stringify(scope); } catch { return String(scope); }
}

function renderCreds() {
  if (!state.creds.length) {
    $credsEmpty.style.display = "";
    $creds.innerHTML = "";
    return;
  }
  $credsEmpty.style.display = "none";
  const frag = document.createDocumentFragment();
  for (const c of state.creds) {
    const li = document.createElement("li");
    const idEl = document.createElement("span");
    idEl.className = "cred-id";
    idEl.textContent = c.id;
    const typeEl = document.createElement("span");
    typeEl.className = "cred-type";
    typeEl.textContent = c.type;
    const tsEl = document.createElement("span");
    tsEl.className = "cred-ts";
    tsEl.textContent = `registered ${fmtTimeSecs(c.created_at)}`;
    li.appendChild(idEl);
    li.appendChild(typeEl);
    li.appendChild(tsEl);
    frag.appendChild(li);
  }
  $creds.replaceChildren(frag);
}

// Update countdown timers once per second without refetching.
function tickTTLs() {
  const now = Math.floor(Date.now() / 1000);
  const nodes = $caps.querySelectorAll(".cap-ttl");
  nodes.forEach((n) => {
    const expires = Number(n.dataset.expires || 0);
    const remaining = expires - now;
    n.textContent = `expires ${fmtCountdown(remaining)}`;
    if (remaining <= 60) n.classList.add("expiring");
    else n.classList.remove("expiring");
  });
}

// --- Boot ---
function start() {
  setConnected(false);
  pollEvents();
  pollCaps();
  pollCreds();
  state.ttlTimer = setInterval(tickTTLs, 1000);
}

start();
