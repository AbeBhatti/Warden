import express, { Request, Response } from "express";
import cors from "cors";
import Database from "better-sqlite3";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

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

// Register root credentials from .env if not already present
const nowSec = () => Math.floor(Date.now() / 1000);

function registerCredentialIfMissing(id: string, type: string, value: string) {
  if (!value) return;
  const existing = db.prepare("SELECT id FROM credentials WHERE id = ?").get(id);
  if (existing) {
    db.prepare("UPDATE credentials SET value = ? WHERE id = ?").run(value, id);
  } else {
    db.prepare(
      "INSERT INTO credentials (id, type, value, scope_ceiling, created_at) VALUES (?, ?, ?, ?, ?)"
    ).run(id, type, value, null, nowSec());
  }
}

registerCredentialIfMissing("gh_prod", "github", GITHUB_TOKEN);
registerCredentialIfMissing("groq_prod", "groq", GROQ_API_KEY);

// In-memory cache of credential values, used by sanitizer / leak detector / honesty assertion.
let credentialValues: Set<string> = new Set();
function reloadCredentialCache() {
  const rows = db.prepare("SELECT value FROM credentials").all() as { value: string }[];
  credentialValues = new Set(rows.map((r) => r.value).filter((v) => v && v.length > 0));
}
reloadCredentialCache();

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
      throw new Error(msg);
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
    return finalizeOk(ctx, tool, body, Date.now() - t0);
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

async function dispatchRpc(body: any): Promise<any> {
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

// ─────────────────────────────────────────────────────────────
// Express app: MCP + dashboard API
// ─────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.post("/mcp", async (req: Request, res: Response) => {
  const resp = await dispatchRpc(req.body);
  res.json(resp);
});

// Dashboard endpoints
app.get("/api/events", (req: Request, res: Response) => {
  const since = Number(req.query.since ?? 0);
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  const rows = db
    .prepare("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?")
    .all(since, limit) as any[];
  const latest_id = rows.length ? rows[rows.length - 1].id : since;
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

app.listen(PORT, () => {
  console.log(`Warden listening on http://localhost:${PORT}`);
  console.log(`  MCP endpoint: POST /mcp`);
  console.log(`  Dashboard API: GET /api/events /api/active_capabilities /api/runs /api/credentials`);
  console.log(`  Credentials registered: ${credentialValues.size}`);
});
