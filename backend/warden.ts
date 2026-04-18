import express, { Request, Response } from "express";
import cors from "cors";
import Database from "better-sqlite3";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");

dotenv.config({ path: resolve(REPO_ROOT, ".env") });

const PORT = Number(process.env.WARDEN_PORT ?? 3000);
const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? "";
const GROQ_API_KEY = process.env.GROQ_API_KEY ?? "";

// ─────────────────────────────────────────────────────────────
// DB init
// ─────────────────────────────────────────────────────────────

const db = new Database(resolve(REPO_ROOT, "warden.db"));
const schema = readFileSync(resolve(REPO_ROOT, "schema.sql"), "utf8");
db.exec(schema);

db.exec(`
  CREATE TABLE IF NOT EXISTS dynamic_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    params TEXT NOT NULL,
    implementation_hint TEXT,
    created_at INTEGER NOT NULL,
    approved_by TEXT NOT NULL,
    confidence REAL NOT NULL
  );
`);

// Register root credentials from .env if not already present
const nowSec = () => Math.floor(Date.now() / 1000);

function registerCredentialIfMissing(id: string, type: string, value: string) {
  const v = value.trim();
  if (!v) return;
  const existing = db.prepare("SELECT id FROM credentials WHERE id = ?").get(id);
  if (existing) {
    db.prepare("UPDATE credentials SET value = ? WHERE id = ?").run(v, id);
  } else {
    db.prepare(
      "INSERT INTO credentials (id, type, value, scope_ceiling, created_at) VALUES (?, ?, ?, ?, ?)"
    ).run(id, type, v, null, nowSec());
  }
}

registerCredentialIfMissing("gh_prod", "github", GITHUB_TOKEN);
registerCredentialIfMissing("groq_prod", "groq", GROQ_API_KEY);

// In-memory cache of credential values, used by sanitizer / leak detector / honesty assertion.
let credentialValues: Set<string> = new Set();
let credentialTypes: Map<string, string> = new Map();
function reloadCredentialCache() {
  const rows = db.prepare("SELECT value, type FROM credentials").all() as { value: string; type: string }[];
  const trimmed = rows.map((r) => ({ value: r.value.trim(), type: r.type })).filter((r) => r.value.length > 0);
  credentialValues = new Set(trimmed.map((r) => r.value));
  credentialTypes = new Map(trimmed.map((r) => [r.value, r.type]));
}
reloadCredentialCache();

/** Re-read `.env` from disk and refresh DB + leak/sanitizer cache before brokered calls.
 * Avoids false negatives when the agent reads a fresh token from disk but the Node process
 * still had an older credential loaded at startup. */
function syncCredentialsFromEnv() {
  dotenv.config({ path: resolve(REPO_ROOT, ".env"), override: true });
  const gh = (process.env.GITHUB_TOKEN ?? "").trim();
  const gq = (process.env.GROQ_API_KEY ?? "").trim();
  if (gh) registerCredentialIfMissing("gh_prod", "github", gh);
  if (gq) registerCredentialIfMissing("groq_prod", "groq", gq);
  reloadCredentialCache();
}

// ─────────────────────────────────────────────────────────────
// Security pipeline: sanitizer, leak detector, honesty assertion
// ─────────────────────────────────────────────────────────────

const REDACTED = "[REDACTED by Warden]";

function sanitize(obj: any): { sanitized: any; redactions: number } {
  let redactions = 0;
  const secrets = [...credentialValues];

  const walk = (node: any): any => {
    if (typeof node === "string") {
      let out = node;
      for (const secret of secrets) {
        if (secret && out.includes(secret)) {
          out = out.split(secret).join(REDACTED);
          redactions++;
        }
      }
      return out;
    }
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      const copy: Record<string, any> = {};
      for (const k of Object.keys(node)) copy[k] = walk(node[k]);
      return copy;
    }
    return node;
  };

  return { sanitized: walk(obj), redactions };
}

function detectLeak(args: any): { leaked: boolean; fields: string[] } {
  const fields: string[] = [];
  const secrets = [...credentialValues];

  const walk = (node: any, path: string) => {
    if (typeof node === "string") {
      for (const secret of secrets) {
        if (secret && node.includes(secret)) {
          const credType = credentialTypes.get(secret) ?? "unknown";
          console.log(`[detectLeak] field="${path}" preview="${node.slice(0, 20).replace(/\n/g, "\\n")}" type=${credType}`);
          fields.push(path);
          return;
        }
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${path}[${i}]`));
      return;
    }
    if (node && typeof node === "object") {
      for (const k of Object.keys(node)) walk(node[k], path ? `${path}.${k}` : k);
    }
  };

  walk(args, "");
  return { leaked: fields.length > 0, fields };
}

function assertNoRawCredentials(event: Record<string, any>): void {
  const serialized = JSON.stringify(event);
  for (const secret of credentialValues) {
    if (secret && serialized.includes(secret)) {
      const msg = `HONESTY_VIOLATION: event contains raw credential value`;
      console.error(msg, { event_type: event.event_type, tool: event.tool });
      process.exit(1);
    }
  }
}

// ─────────────────────────────────────────────────────────────
// Event emission
// ─────────────────────────────────────────────────────────────

type EventRow = {
  ts: number;
  run_id: string | null;
  capability_id: string | null;
  event_type: string;
  tool: string | null;
  args_redacted: string | null;
  outcome: "ok" | "blocked" | "error";
  detail: string | null;
  duration_ms: number | null;
};

function emitEvent(e: Partial<EventRow> & Pick<EventRow, "event_type" | "outcome">): number {
  const row: EventRow = {
    ts: Date.now(),
    run_id: e.run_id ?? null,
    capability_id: e.capability_id ?? null,
    event_type: e.event_type,
    tool: e.tool ?? null,
    args_redacted: e.args_redacted ?? null,
    outcome: e.outcome,
    detail: e.detail ?? null,
    duration_ms: e.duration_ms ?? null,
  };

  assertNoRawCredentials(row);

  const info = db
    .prepare(
      `INSERT INTO events (ts, run_id, capability_id, event_type, tool, args_redacted, outcome, detail, duration_ms)
       VALUES (@ts, @run_id, @capability_id, @event_type, @tool, @args_redacted, @outcome, @detail, @duration_ms)`
    )
    .run(row);
  return info.lastInsertRowid as number;
}

// ─────────────────────────────────────────────────────────────
// Handle utilities
// ─────────────────────────────────────────────────────────────

function generateHandle(): string {
  return "cap_" + randomBytes(6).toString("hex");
}

type CapabilityRow = {
  id: string;
  run_id: string;
  cap_type: string;
  credential_id: string;
  scope: string;
  justification: string | null;
  granted_at: number;
  expires_at: number;
  revoked_at: number | null;
  revocation_reason: string | null;
};

function getCapability(handle: string): CapabilityRow | undefined {
  return db.prepare("SELECT * FROM capabilities WHERE id = ?").get(handle) as
    | CapabilityRow
    | undefined;
}

// ─────────────────────────────────────────────────────────────
// JSON-RPC error helper
// ─────────────────────────────────────────────────────────────

class RpcError extends Error {
  code: number;
  data?: any;
  constructor(code: number, message: string, data?: any) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: any;
  result?: any;
  error?: { code: number; message: string; data?: any };
};

// ─────────────────────────────────────────────────────────────
// MCP tool implementations
// ─────────────────────────────────────────────────────────────

const GITHUB_PERMS_ALLOWED = new Set(["read", "write"]);
const GROQ_MODELS_ALLOWED = new Set([
  "llama-3.3-70b-versatile",
  "llama-3.1-8b-instant",
  "mixtral-8x7b-32768",
]);
const MAX_TTL = 3600;
const DEFAULT_TTL_GITHUB = 300;
const DEFAULT_TTL_GROQ = 300;
const MAX_GROQ_TOKENS = 4096;

// ——— warden.start_run ———
function startRun(params: any) {
  const task = String(params?.task ?? "").trim();
  if (!task) throw new RpcError(-32602, "task is required");

  const run_id = randomUUID();
  const agent_identity = randomUUID();
  db.prepare(
    "INSERT INTO runs (id, task, agent_identity, started_at, status) VALUES (?, ?, ?, ?, 'active')"
  ).run(run_id, task, agent_identity, nowSec());

  emitEvent({
    run_id,
    event_type: "run_started",
    outcome: "ok",
    detail: `task=${task}`,
  });

  return { run_id, agent_identity };
}

// ——— warden.end_run ———
function endRun(params: any, reason: "run_ended" | "timeout" = "run_ended") {
  const run_id = String(params?.run_id ?? "");
  if (!run_id) throw new RpcError(-32602, "run_id is required");

  const run = db.prepare("SELECT * FROM runs WHERE id = ?").get(run_id) as any;
  if (!run) throw new RpcError(-32602, "run not found");

  const status = reason === "timeout" ? "timeout" : "ended";
  db.prepare("UPDATE runs SET ended_at = ?, status = ? WHERE id = ? AND status = 'active'").run(
    nowSec(),
    status,
    run_id
  );

  const caps = db
    .prepare(
      "SELECT id FROM capabilities WHERE run_id = ? AND revoked_at IS NULL"
    )
    .all(run_id) as { id: string }[];

  const revokeTs = nowSec();
  const updateStmt = db.prepare(
    "UPDATE capabilities SET revoked_at = ?, revocation_reason = ? WHERE id = ?"
  );
  for (const c of caps) {
    updateStmt.run(revokeTs, reason, c.id);
    emitEvent({
      run_id,
      capability_id: c.id,
      event_type: "revoked",
      outcome: "ok",
      detail: `reason=${reason}`,
    });
  }

  emitEvent({
    run_id,
    event_type: "run_ended",
    outcome: "ok",
    detail: `revoked=${caps.length} status=${status}`,
  });

  return { revoked: caps.length };
}

// ——— capability request helpers ———
function validateActiveRun(run_id: string): void {
  const run = db.prepare("SELECT status FROM runs WHERE id = ?").get(run_id) as
    | { status: string }
    | undefined;
  if (!run) {
    throw new RpcError(-32001, "Invalid run", {
      code: "INVALID_RUN",
      message: "run_id does not exist",
      suggestion: "Call warden.start_run first",
    });
  }
  if (run.status !== "active") {
    throw new RpcError(-32001, "Run is not active", {
      code: "RUN_NOT_ACTIVE",
      message: `Run status is '${run.status}'`,
      suggestion: "Start a new run",
    });
  }
}

function requestGithubAccess(params: any) {
  const run_id = String(params?.run_id ?? "");
  const scope = params?.scope ?? {};
  const justification = String(params?.justification ?? "");
  const ttl = Math.min(Number(params?.ttl_seconds ?? DEFAULT_TTL_GITHUB), MAX_TTL);

  validateActiveRun(run_id);

  const repo = String(scope.repo ?? "").trim();
  const permissions: string[] = Array.isArray(scope.permissions) ? scope.permissions : [];

  if (!repo) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: "missing repo",
    });
    throw new RpcError(-32001, "Scope denied", {
      code: "SCOPE_EXCEEDS_CEILING",
      message: "scope.repo is required",
      suggestion: "Pass scope.repo as 'owner/repo'",
    });
  }
  for (const p of permissions) {
    if (!GITHUB_PERMS_ALLOWED.has(p)) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `disallowed permission: ${p}`,
      });
      throw new RpcError(-32001, "Scope denied", {
        code: "SCOPE_EXCEEDS_CEILING",
        message: `permission '${p}' not allowed`,
        suggestion: "Use 'read' and/or 'write'",
      });
    }
  }

  const handle = generateHandle();
  const granted_scope = { repo, permissions };
  const granted_at = nowSec();
  const expires_at = granted_at + ttl;

  db.prepare(
    `INSERT INTO capabilities
       (id, run_id, cap_type, credential_id, scope, justification, granted_at, expires_at)
     VALUES (?, ?, 'github', 'gh_prod', ?, ?, ?, ?)`
  ).run(handle, run_id, JSON.stringify(granted_scope), justification, granted_at, expires_at);

  emitEvent({
    run_id,
    capability_id: handle,
    event_type: "capability_granted",
    outcome: "ok",
    detail: `github repo=${repo} perms=${permissions.join(",")} ttl=${ttl}`,
  });

  return { handle, granted_scope, expires_at };
}

function requestGroqAccess(params: any) {
  const run_id = String(params?.run_id ?? "");
  const scope = params?.scope ?? {};
  const justification = String(params?.justification ?? "");
  const ttl = Math.min(Number(params?.ttl_seconds ?? DEFAULT_TTL_GROQ), MAX_TTL);

  validateActiveRun(run_id);

  const models: string[] = Array.isArray(scope.models) ? scope.models : [];
  const max_tokens_per_call = Math.min(
    Number(scope.max_tokens_per_call ?? 1024),
    MAX_GROQ_TOKENS
  );

  if (models.length === 0) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: "empty models list",
    });
    throw new RpcError(-32001, "Scope denied", {
      code: "SCOPE_EXCEEDS_CEILING",
      message: "scope.models must be non-empty",
      suggestion: "Specify at least one model",
    });
  }
  for (const m of models) {
    if (!GROQ_MODELS_ALLOWED.has(m)) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `disallowed model: ${m}`,
      });
      throw new RpcError(-32001, "Scope denied", {
        code: "SCOPE_EXCEEDS_CEILING",
        message: `model '${m}' not allowed`,
        suggestion: `Allowed: ${[...GROQ_MODELS_ALLOWED].join(", ")}`,
      });
    }
  }

  const handle = generateHandle();
  const granted_scope = { models, max_tokens_per_call };
  const granted_at = nowSec();
  const expires_at = granted_at + ttl;

  db.prepare(
    `INSERT INTO capabilities
       (id, run_id, cap_type, credential_id, scope, justification, granted_at, expires_at)
     VALUES (?, ?, 'groq', 'groq_prod', ?, ?, ?, ?)`
  ).run(handle, run_id, JSON.stringify(granted_scope), justification, granted_at, expires_at);

  emitEvent({
    run_id,
    capability_id: handle,
    event_type: "capability_granted",
    outcome: "ok",
    detail: `groq models=${models.join(",")} max_tokens=${max_tokens_per_call} ttl=${ttl}`,
  });

  return { handle, granted_scope, expires_at };
}

// ——— brokered operation pipeline ———

type PipelineCtx = {
  handle: string;
  capability: CapabilityRow;
  scope: any;
  credentialValue: string;
  argsRedacted: Record<string, any>;
};

function openPipeline(
  handle: string,
  expectCapType: "github" | "groq",
  tool: string,
  rawArgs: Record<string, any>
): PipelineCtx {
  // 1. RESOLVE HANDLE
  const cap = getCapability(handle);
  if (!cap) {
    emitEvent({
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: "handle not found",
      args_redacted: JSON.stringify({ ...rawArgs, handle }),
    });
    throw new RpcError(-32001, "Invalid handle", { code: "HANDLE_NOT_FOUND" });
  }
  if (cap.cap_type !== expectCapType) {
    emitEvent({
      run_id: cap.run_id,
      capability_id: cap.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: `handle is ${cap.cap_type}, tool expects ${expectCapType}`,
      args_redacted: JSON.stringify({ ...rawArgs, handle }),
    });
    throw new RpcError(-32001, "Wrong handle type", { code: "WRONG_CAP_TYPE" });
  }
  if (cap.revoked_at) {
    emitEvent({
      run_id: cap.run_id,
      capability_id: cap.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: `revoked: ${cap.revocation_reason}`,
      args_redacted: JSON.stringify({ ...rawArgs, handle }),
    });
    throw new RpcError(-32001, "Handle revoked", { code: "HANDLE_REVOKED" });
  }
  if (cap.expires_at < nowSec()) {
    db.prepare(
      "UPDATE capabilities SET revoked_at = ?, revocation_reason = 'expired' WHERE id = ?"
    ).run(nowSec(), cap.id);
    emitEvent({
      run_id: cap.run_id,
      capability_id: cap.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: "expired",
      args_redacted: JSON.stringify({ ...rawArgs, handle }),
    });
    throw new RpcError(-32001, "Handle expired", { code: "HANDLE_EXPIRED" });
  }

  // 2. LEAK DETECTOR (inbound)
  syncCredentialsFromEnv();
  const leak = detectLeak(rawArgs);
  if (leak.leaked) {
    const argsRedacted = sanitize(rawArgs).sanitized;
    emitEvent({
      run_id: cap.run_id,
      capability_id: cap.id,
      event_type: "leak_detected",
      outcome: "blocked",
      tool,
      detail: `fields=${leak.fields.join(",")}`,
      args_redacted: JSON.stringify(argsRedacted),
    });
    throw new RpcError(-32002, "Tool call args contained a raw credential value. Call blocked.", {
      code: "LEAK_DETECTED",
      fields: leak.fields,
    });
  }

  // Load credential value and parse scope
  const credRow = db
    .prepare("SELECT value FROM credentials WHERE id = ?")
    .get(cap.credential_id) as { value: string } | undefined;
  if (!credRow) {
    throw new RpcError(-32603, "Backing credential missing");
  }

  const scope = JSON.parse(cap.scope);
  const argsRedacted = sanitize(rawArgs).sanitized;

  return { handle, capability: cap, scope, credentialValue: credRow.value, argsRedacted };
}

function finalizeOk(
  ctx: PipelineCtx,
  tool: string,
  responseObj: any,
  durationMs: number
): any {
  const { sanitized, redactions } = sanitize(responseObj);
  if (redactions > 0) {
    emitEvent({
      run_id: ctx.capability.run_id,
      capability_id: ctx.capability.id,
      event_type: "sanitizer_redacted",
      outcome: "ok",
      tool,
      detail: `redactions=${redactions}`,
    });
  }
  emitEvent({
    run_id: ctx.capability.run_id,
    capability_id: ctx.capability.id,
    event_type: "tool_called",
    outcome: "ok",
    tool,
    args_redacted: JSON.stringify(ctx.argsRedacted),
    duration_ms: durationMs,
  });
  return sanitized;
}

function finalizeError(
  ctx: PipelineCtx,
  tool: string,
  err: any,
  durationMs: number
): never {
  emitEvent({
    run_id: ctx.capability.run_id,
    capability_id: ctx.capability.id,
    event_type: "tool_called",
    outcome: "error",
    tool,
    args_redacted: JSON.stringify(ctx.argsRedacted),
    detail: String(err?.message ?? err),
    duration_ms: durationMs,
  });
  throw err instanceof RpcError ? err : new RpcError(-32603, String(err?.message ?? err));
}

// ——— github.list_issues ———
async function githubListIssues(params: any) {
  const tool = "warden.github.list_issues";
  const handle = String(params?.handle ?? "");
  const repo = String(params?.repo ?? "");
  const state = String(params?.state ?? "open");

  const ctx = openPipeline(handle, "github", tool, { handle, repo, state });

  if (ctx.scope.repo !== repo) {
    emitEvent({
      run_id: ctx.capability.run_id,
      capability_id: ctx.capability.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: `repo ${repo} not in scope (${ctx.scope.repo})`,
    });
    throw new RpcError(-32001, "Repo out of scope", { code: "SCOPE_MISMATCH" });
  }

  const t0 = Date.now();
  try {
    const url = `https://api.github.com/repos/${repo}/issues?state=${encodeURIComponent(state)}`;
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${ctx.credentialValue}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "Warden/0.1",
      },
    });
    const body = await resp.json();
    if (!resp.ok) {
      return finalizeError(
        ctx,
        tool,
        new RpcError(-32603, `GitHub API ${resp.status}: ${JSON.stringify(body)}`),
        Date.now() - t0
      );
    }
    const issues = Array.isArray(body) ? body : [];
    return finalizeOk(ctx, tool, { issues }, Date.now() - t0);
  } catch (err) {
    return finalizeError(ctx, tool, err, Date.now() - t0);
  }
}

// ——— github.create_comment ———
async function githubCreateComment(params: any) {
  const tool = "warden.github.create_comment";
  const handle = String(params?.handle ?? "");
  const repo = String(params?.repo ?? "");
  const issue_number = Number(params?.issue_number ?? 0);
  const body = String(params?.body ?? "");

  const ctx = openPipeline(handle, "github", tool, { handle, repo, issue_number, body });

  if (ctx.scope.repo !== repo) {
    emitEvent({
      run_id: ctx.capability.run_id,
      capability_id: ctx.capability.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: `repo ${repo} not in scope (${ctx.scope.repo})`,
    });
    throw new RpcError(-32001, "Repo out of scope", { code: "SCOPE_MISMATCH" });
  }
  const perms: string[] = ctx.scope.permissions ?? [];
  if (!perms.includes("write")) {
    emitEvent({
      run_id: ctx.capability.run_id,
      capability_id: ctx.capability.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: "missing write permission",
    });
    throw new RpcError(-32001, "Write permission required", { code: "SCOPE_MISMATCH" });
  }

  const t0 = Date.now();
  try {
    const url = `https://api.github.com/repos/${repo}/issues/${issue_number}/comments`;
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ctx.credentialValue}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "Warden/0.1",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body }),
    });
    const respBody = await resp.json();
    if (!resp.ok) {
      return finalizeError(
        ctx,
        tool,
        new RpcError(-32603, `GitHub API ${resp.status}: ${JSON.stringify(respBody)}`),
        Date.now() - t0
      );
    }
    return finalizeOk(ctx, tool, respBody, Date.now() - t0);
  } catch (err) {
    return finalizeError(ctx, tool, err, Date.now() - t0);
  }
}

// ——— groq.chat_completion ———
async function groqChatCompletion(params: any) {
  const tool = "warden.groq.chat_completion";
  const handle = String(params?.handle ?? "");
  const messages = Array.isArray(params?.messages) ? params.messages : [];
  const model = String(params?.model ?? "llama-3.3-70b-versatile");
  const max_tokens = params?.max_tokens != null ? Number(params.max_tokens) : undefined;

  const ctx = openPipeline(handle, "groq", tool, { handle, messages, model, max_tokens });

  const allowedModels: string[] = ctx.scope.models ?? [];
  if (!allowedModels.includes(model)) {
    emitEvent({
      run_id: ctx.capability.run_id,
      capability_id: ctx.capability.id,
      event_type: "tool_blocked",
      outcome: "blocked",
      tool,
      detail: `model ${model} not in scope (${allowedModels.join(",")})`,
    });
    throw new RpcError(-32001, "Model out of scope", { code: "SCOPE_MISMATCH" });
  }
  const capMax = Number(ctx.scope.max_tokens_per_call ?? 1024);
  const effectiveMax = max_tokens != null ? Math.min(max_tokens, capMax) : capMax;

  const t0 = Date.now();
  try {
    const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ctx.credentialValue}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model, messages, max_tokens: effectiveMax }),
    });
    const body: any = await resp.json();
    if (!resp.ok) {
      return finalizeError(
        ctx,
        tool,
        new RpcError(-32603, `Groq API ${resp.status}: ${JSON.stringify(body)}`),
        Date.now() - t0
      );
    }
    const content = body?.choices?.[0]?.message?.content ?? "";
    const tokens_used = body?.usage?.total_tokens ?? 0;
    return finalizeOk(ctx, tool, { content, tokens_used }, Date.now() - t0);
  } catch (err) {
    return finalizeError(ctx, tool, err, Date.now() - t0);
  }
}

// ─────────────────────────────────────────────────────────────
// JSON-RPC dispatcher
// ─────────────────────────────────────────────────────────────

const METHODS: Record<string, (params: any) => any | Promise<any>> = {
  "warden.start_run": startRun,
  "warden.end_run": (p) => endRun(p, "run_ended"),
  "warden.request_github_access": requestGithubAccess,
  "warden.request_groq_access": requestGroqAccess,
  "warden.github.list_issues": githubListIssues,
  "warden.github.create_comment": githubCreateComment,
  "warden.groq.chat_completion": groqChatCompletion,
};

/** Cursor/MCP may use underscore tool ids (warden_github_list_issues); map to canonical dotted names. */
const MCP_TOOL_ALIASES: Record<string, string> = {
  warden_start_run: "warden.start_run",
  warden_end_run: "warden.end_run",
  warden_request_github_access: "warden.request_github_access",
  warden_request_groq_access: "warden.request_groq_access",
  warden_github_list_issues: "warden.github.list_issues",
  warden_github_create_comment: "warden.github.create_comment",
  warden_groq_chat_completion: "warden.groq.chat_completion",
};

function resolveToolName(name: string): string {
  return MCP_TOOL_ALIASES[name] ?? name;
}

const TOOL_DEFS = [
  {
    name: "warden.start_run",
    description: "Start a security-scoped Warden run.",
    inputSchema: {
      type: "object",
      properties: {
        task: { type: "string", description: "Task description for this run." },
      },
      required: ["task"],
      additionalProperties: false,
    },
  },
  {
    name: "warden.end_run",
    description: "End a run and revoke all active handles.",
    inputSchema: {
      type: "object",
      properties: {
        run_id: { type: "string" },
      },
      required: ["run_id"],
      additionalProperties: false,
    },
  },
  {
    name: "warden.request_github_access",
    description: "Request time-boxed GitHub credential access for a repo.",
    inputSchema: {
      type: "object",
      properties: {
        run_id: { type: "string" },
        scope: {
          type: "object",
          properties: {
            repo: { type: "string" },
            permissions: { type: "array", items: { type: "string" } },
          },
          required: ["repo", "permissions"],
          additionalProperties: false,
        },
        justification: { type: "string" },
        ttl_seconds: { type: "number" },
      },
      required: ["run_id", "scope", "justification"],
      additionalProperties: false,
    },
  },
  {
    name: "warden.request_groq_access",
    description: "Request time-boxed Groq model access.",
    inputSchema: {
      type: "object",
      properties: {
        run_id: { type: "string" },
        scope: {
          type: "object",
          properties: {
            models: { type: "array", items: { type: "string" } },
            max_tokens_per_call: { type: "number" },
          },
          required: ["models"],
          additionalProperties: false,
        },
        justification: { type: "string" },
        ttl_seconds: { type: "number" },
      },
      required: ["run_id", "scope", "justification"],
      additionalProperties: false,
    },
  },
  {
    name: "warden.github.list_issues",
    description: "List issues for a repo under a granted handle.",
    inputSchema: {
      type: "object",
      properties: {
        handle: { type: "string" },
        repo: { type: "string" },
        state: { type: "string" },
      },
      required: ["handle", "repo"],
      additionalProperties: false,
    },
  },
  {
    name: "warden.github.create_comment",
    description: "Create an issue comment under a write-capable handle.",
    inputSchema: {
      type: "object",
      properties: {
        handle: { type: "string" },
        repo: { type: "string" },
        issue_number: { type: "number" },
        body: { type: "string" },
      },
      required: ["handle", "repo", "issue_number", "body"],
      additionalProperties: false,
    },
  },
  {
    name: "warden.groq.chat_completion",
    description: "Create a Groq chat completion under a granted handle.",
    inputSchema: {
      type: "object",
      properties: {
        handle: { type: "string" },
        messages: { type: "array", items: { type: "object" } },
        model: { type: "string" },
        max_tokens: { type: "number" },
      },
      required: ["handle", "messages"],
      additionalProperties: false,
    },
  },
];

// ─────────────────────────────────────────────────────────────
// Dynamic tool registry
// ─────────────────────────────────────────────────────────────

const dynamicToolDefs: Array<{
  name: string;
  description: string;
  params: string[];
  implementation_hint: string;
}> = [];

function registerMcpTool(toolDef: {
  name: string;
  description: string;
  params: string[];
  implementation_hint: string;
}): void {
  // Store for future McpServer instances
  dynamicToolDefs.push(toolDef);

  // Add to METHODS so runTool() and tools/call dispatch can find it
  METHODS[toolDef.name] = async (args: any) => {
    emitEvent({
      run_id: args.run_id || null,
      capability_id: null,
      event_type: "tool_called",
      tool: toolDef.name,
      args_redacted: JSON.stringify(args),
      outcome: "ok",
      detail: `dynamic tool executed: ${toolDef.implementation_hint}`,
      duration_ms: 0,
    });
    return {
      tool: toolDef.name,
      args: args,
      implementation_hint: toolDef.implementation_hint,
      message: `Dynamic tool ${toolDef.name} executed successfully`,
    };
  };

  // Add to TOOL_DEFS so the legacy tools/list response includes it
  (TOOL_DEFS as any[]).push({
    name: toolDef.name,
    description: toolDef.description,
    inputSchema: {
      type: "object",
      properties: Object.fromEntries(
        toolDef.params.map((p) => [p, { type: "string", description: p }])
      ),
      additionalProperties: false,
    },
  });

  console.log(`Registered dynamic tool: ${toolDef.name}`);
}

function loadDynamicTools(): void {
  const tools = db.prepare("SELECT * FROM dynamic_tools").all() as any[];
  for (const tool of tools) {
    registerMcpTool({
      name: tool.name,
      description: tool.description,
      params: JSON.parse(tool.params),
      implementation_hint: tool.implementation_hint,
    });
  }
  console.log(`Loaded ${tools.length} dynamic tools from DB`);
}

async function dispatchLegacyRpc(body: any): Promise<JsonRpcResponse> {
  const id = body?.id ?? null;
  const method = body?.method;
  const params = body?.params ?? {};

  if (!method || typeof method !== "string") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
  }
  const handler = METHODS[method];
  if (!handler) {
    return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
  try {
    const result = await handler(params);
    return { jsonrpc: "2.0", id, result };
  } catch (err: any) {
    if (err instanceof RpcError) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: err.code, message: err.message, data: err.data },
      };
    }
    console.error("Unhandled error in", method, err);
    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32603, message: String(err?.message ?? err) },
    };
  }
}

async function dispatchRpc(body: any): Promise<JsonRpcResponse> {
  const id = body?.id ?? null;
  const method = body?.method;
  const params = body?.params ?? {};

  if (!method || typeof method !== "string") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
  }

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "warden-local", version: "0.1.0" },
        capabilities: { tools: {} },
      },
    };
  }

  if (method === "notifications/initialized") {
    return { jsonrpc: "2.0", id, result: {} };
  }

  if (method === "tools/list") {
    return { jsonrpc: "2.0", id, result: { tools: TOOL_DEFS } };
  }

  if (method === "tools/call") {
    const name = resolveToolName(String(params?.name ?? ""));
    const args = params?.arguments ?? {};
    const handler = METHODS[name];
    if (!handler) {
      return { jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown tool: ${name}` } };
    }
    try {
      const result = await handler(args);
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify(result),
            },
          ],
          structuredContent: result,
        },
      };
    } catch (err: any) {
      if (err instanceof RpcError) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: err.code, message: err.message, data: err.data },
        };
      }
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: String(err?.message ?? err) },
      };
    }
  }

  return dispatchLegacyRpc(body);
}

// ─────────────────────────────────────────────────────────────
// Express app: MCP + dashboard API
// ─────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// Legacy JSON-RPC compatibility route for Python demo agent + attack harness.
// Real MCP clients should use /mcp (Streamable HTTP transport, wired below).
app.post("/rpc", async (req: Request, res: Response) => {
  const resp = await dispatchRpc(req.body);
  res.json(resp);
});

// ─────────────────────────────────────────────────────────────
// MCP server — real protocol via StreamableHTTPServerTransport
// Routes every tools/call through the same underlying handlers the
// legacy /rpc dispatcher uses, so the security pipeline is shared.
// ─────────────────────────────────────────────────────────────

function registerDynamicToolsOnServer(srv: McpServer): void {
  for (const def of dynamicToolDefs) {
    const schema: Record<string, z.ZodTypeAny> = {};
    for (const param of def.params) {
      schema[param] = z.string().describe(param);
    }
    srv.registerTool(
      def.name,
      { description: def.description, inputSchema: schema },
      async (args) => runTool(def.name, args)
    );
  }
}

function buildMcpServer(): McpServer {
  const srv = new McpServer(
    { name: "warden", version: "0.1.0" },
    {
      capabilities: { tools: {} },
      instructions:
        "Warden brokers credentials for external services. Agents never hold raw tokens — " +
        "they hold opaque handles minted per run. Start every session with warden.start_run, " +
        "request access via warden.request_* tools to get a handle, call warden.<service>.<op> " +
        "using the handle, and call warden.end_run when done to auto-revoke all handles.",
    }
  );
  registerWardenTools(srv);
  registerDynamicToolsOnServer(srv);
  return srv;
}

// Map tool-name → underlying function. Handlers are defined already; we route to them.
const toolImpl: Record<string, (params: any) => any | Promise<any>> = METHODS;

function wrapOk(result: any) {
  return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
}
function wrapErr(err: any) {
  const text =
    err instanceof RpcError
      ? JSON.stringify({
          error: true,
          code: err.data?.code ?? err.code,
          message: err.message,
          data: err.data,
        })
      : JSON.stringify({ error: true, code: -32603, message: String(err?.message ?? err) });
  return { content: [{ type: "text" as const, text }], isError: true };
}

async function runTool(name: string, args: Record<string, unknown>) {
  const impl = toolImpl[name];
  if (!impl) return wrapErr(new RpcError(-32601, `Method not found: ${name}`));
  try {
    const result = await impl(args);
    return wrapOk(result);
  } catch (err) {
    return wrapErr(err);
  }
}

// Zod shapes for each tool. Match the existing params shapes the underlying fns accept.
const startRunShape = { task: z.string().describe("Human-readable description of what this run will do.") };

const endRunShape = { run_id: z.string().describe("The run_id returned by warden.start_run.") };

const githubAccessShape = {
  run_id: z.string(),
  scope: z.object({
    repo: z.string().describe("GitHub repository as 'owner/repo'."),
    permissions: z.array(z.enum(["read", "write"])),
  }),
  justification: z.string().describe("Reason the agent needs this access (logged in audit trail)."),
  ttl_seconds: z.number().int().positive().max(3600).optional(),
};

const groqAccessShape = {
  run_id: z.string(),
  scope: z.object({
    models: z.array(z.string()),
    max_tokens_per_call: z.number().int().positive().max(4096).optional(),
  }),
  justification: z.string(),
  ttl_seconds: z.number().int().positive().max(3600).optional(),
};

const listIssuesShape = {
  handle: z.string().describe("Capability handle (cap_*) from warden.request_github_access."),
  repo: z.string(),
  state: z.enum(["open", "closed", "all"]).optional(),
};

const createCommentShape = {
  handle: z.string(),
  repo: z.string(),
  issue_number: z.number().int().positive(),
  body: z.string().describe("Comment body. Must not contain any raw credential values — Warden blocks with LEAK_DETECTED."),
};

const chatCompletionShape = {
  handle: z.string(),
  messages: z.array(
    z.object({
      role: z.enum(["system", "user", "assistant"]),
      content: z.string(),
    })
  ),
  model: z.string().optional(),
  max_tokens: z.number().int().positive().optional(),
};

function registerWardenTools(srv: McpServer): void {
  srv.registerTool(
    "warden.start_run",
    {
      description:
        "Begin a new Warden run. Call this first in every session. Returns a run_id that tags all subsequent capability requests and events. The run must be ended with warden.end_run (or it will auto-expire after 1 hour).",
      inputSchema: startRunShape,
    },
    async (args) => runTool("warden.start_run", args)
  );

  srv.registerTool(
    "warden.end_run",
    {
      description:
        "End a Warden run. Auto-revokes all capabilities minted during the run. After this call, every handle from this run becomes unusable.",
      inputSchema: endRunShape,
    },
    async (args) => runTool("warden.end_run", args)
  );

  srv.registerTool(
    "warden.request_github_access",
    {
      description:
        "Request a scoped, time-limited GitHub capability for the current run. Returns an opaque handle (cap_*) — NOT a GitHub token. Use the handle with warden.github.list_issues and warden.github.create_comment.",
      inputSchema: githubAccessShape,
    },
    async (args) => runTool("warden.request_github_access", args)
  );

  srv.registerTool(
    "warden.request_groq_access",
    {
      description:
        "Request a scoped, time-limited Groq (OpenAI-compatible LLM) capability for the current run. Returns an opaque handle (cap_*) — NOT the Groq API key. Use with warden.groq.chat_completion.",
      inputSchema: groqAccessShape,
    },
    async (args) => runTool("warden.request_groq_access", args)
  );

  srv.registerTool(
    "warden.github.list_issues",
    {
      description:
        "List issues on a GitHub repository. Warden makes the call on your behalf using the credential behind the handle — you never see the raw token. Repo must match the scope granted to the handle.",
      inputSchema: listIssuesShape,
    },
    async (args) => runTool("warden.github.list_issues", args)
  );

  srv.registerTool(
    "warden.github.create_comment",
    {
      description:
        "Post a comment on a GitHub issue through Warden. IMPORTANT: do NOT include any raw API tokens or secrets in the body — Warden's leak detector will block the call with LEAK_DETECTED if it sees a known credential value. Write permission required on the handle.",
      inputSchema: createCommentShape,
    },
    async (args) => runTool("warden.github.create_comment", args)
  );

  srv.registerTool(
    "warden.groq.chat_completion",
    {
      description:
        "Call Groq chat completions (OpenAI-compatible) through Warden. IMPORTANT: do NOT include any raw credentials in the messages — Warden blocks the call with LEAK_DETECTED before any request leaves the process. Model must be in the handle's granted scope.",
      inputSchema: chatCompletionShape,
    },
    async (args) => runTool("warden.groq.chat_completion", args)
  );
}

// Stateless Streamable HTTP: each request gets a fresh server+transport pair
// (SDK requirement when sessionIdGenerator is undefined).
async function handleMcp(req: Request, res: Response) {
  const server = buildMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    transport.close().catch(() => {});
    server.close().catch(() => {});
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("MCP handleRequest error:", err);
    if (!res.headersSent) res.status(500).json({ error: "mcp_transport_error" });
  }
}

app.post("/mcp", handleMcp);
app.get("/mcp", handleMcp);
app.delete("/mcp", handleMcp);

// Dashboard endpoints
app.get("/api/events", (req: Request, res: Response) => {
  const since = Number(req.query.since ?? 0);
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  const rows = db
    .prepare("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?")
    .all(since, limit) as any[];
  // Always return the DB's actual max id so clients can detect reset
  // (since<max would indicate the DB was reseeded below the client's watermark).
  const maxRow = db.prepare("SELECT MAX(id) AS m FROM events").get() as { m: number | null };
  const latest_id = maxRow.m ?? 0;
  res.json({ events: rows, latest_id });
});

app.get("/api/active_capabilities", (_req: Request, res: Response) => {
  const now = nowSec();
  const rows = db
    .prepare(
      `SELECT id, run_id, cap_type, scope, granted_at, expires_at
         FROM capabilities
         WHERE revoked_at IS NULL AND expires_at > ?
         ORDER BY granted_at DESC`
    )
    .all(now) as any[];
  const capabilities = rows.map((r) => ({
    ...r,
    seconds_remaining: Math.max(0, r.expires_at - now),
  }));
  res.json({ capabilities });
});

app.get("/api/runs", (req: Request, res: Response) => {
  const limit = Math.min(Number(req.query.limit ?? 20), 200);
  const rows = db
    .prepare("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?")
    .all(limit);
  res.json({ runs: rows });
});

app.get("/api/credentials", (_req: Request, res: Response) => {
  const rows = db
    .prepare("SELECT id, type, created_at FROM credentials ORDER BY created_at ASC")
    .all();
  res.json({ credentials: rows });
});

app.post("/api/revoke/:cap_id", (req: Request, res: Response) => {
  const cap_id = req.params.cap_id;
  const cap = getCapability(cap_id);
  if (!cap) {
    return res.status(404).json({ status: "not_found" });
  }
  if (cap.revoked_at) {
    return res.json({ cap_id, revoked_at: cap.revoked_at, status: "already_revoked" });
  }
  const ts = nowSec();
  db.prepare(
    "UPDATE capabilities SET revoked_at = ?, revocation_reason = 'manual' WHERE id = ?"
  ).run(ts, cap_id);
  emitEvent({
    run_id: cap.run_id,
    capability_id: cap_id,
    event_type: "revoked",
    outcome: "ok",
    detail: "reason=manual",
  });
  res.json({ cap_id, revoked_at: ts, status: "ok" });
});

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", port: PORT });
});

app.post("/api/tools/register", express.json(), (req: Request, res: Response) => {
  const { name, description, params, implementation_hint, approved_by, confidence } = req.body;

  if (!name || !description || !params) {
    return res.status(400).json({ error: "name, description, and params are required" });
  }

  if (!name.startsWith("warden.")) {
    return res.status(400).json({ error: "tool name must start with warden." });
  }

  const existing = db.prepare("SELECT id FROM dynamic_tools WHERE name = ?").get(name);
  if (existing) {
    return res.status(409).json({ error: "tool already registered", name });
  }

  db.prepare(`
    INSERT INTO dynamic_tools (name, description, params, implementation_hint, created_at, approved_by, confidence)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    description,
    JSON.stringify(params),
    implementation_hint || "",
    Math.floor(Date.now() / 1000),
    approved_by || "tool_forge",
    confidence || 1.0
  );

  registerMcpTool({
    name,
    description,
    params,
    implementation_hint: implementation_hint || "",
  });

  emitEvent({
    run_id: null,
    capability_id: null,
    event_type: "tool_called",
    tool: "warden.forge.register",
    args_redacted: JSON.stringify({ name, description, params }),
    outcome: "ok",
    detail: `dynamic tool registered approved_by=${approved_by} confidence=${confidence}`,
    duration_ms: 0,
  });

  res.json({
    status: "registered",
    name,
    message: `Tool ${name} is now live and callable via MCP`,
  });
});

app.get("/api/tools/dynamic", (_req: Request, res: Response) => {
  const tools = db.prepare("SELECT * FROM dynamic_tools ORDER BY created_at DESC").all();
  res.json({ tools });
});

// ─────────────────────────────────────────────────────────────
// Timeout sweep — auto-end runs older than 1 hour
// ─────────────────────────────────────────────────────────────

function sweepTimeouts() {
  const cutoff = nowSec() - 3600;
  const stale = db
    .prepare("SELECT id FROM runs WHERE status = 'active' AND started_at < ?")
    .all(cutoff) as { id: string }[];
  for (const r of stale) {
    try {
      endRun({ run_id: r.id }, "timeout");
    } catch (err) {
      console.error("sweep error", err);
    }
  }
}
setInterval(sweepTimeouts, 30_000);

// ─────────────────────────────────────────────────────────────
// Startup
// ─────────────────────────────────────────────────────────────

loadDynamicTools();

app.listen(PORT, () => {
  console.log(`Warden listening on http://localhost:${PORT}`);
  console.log(`  MCP endpoint: POST /mcp`);
  console.log(`  Dashboard API: GET /api/events /api/active_capabilities /api/runs /api/credentials`);
  console.log(`  Credentials registered: ${credentialValues.size}`);
});
