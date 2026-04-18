import express, { Request, Response } from "express";
import cors from "cors";
import Database from "better-sqlite3";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { z } from "zod";
import * as yaml from "js-yaml";
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

// Idempotent migrations for pre-existing DBs that predate the hash-chain columns.
// schema.sql already declares these on fresh clones — this brings old DBs up to parity.
{
  const eventsCols = db.prepare("PRAGMA table_info(events)").all() as { name: string }[];
  const colNames = new Set(eventsCols.map((c) => c.name));
  if (!colNames.has("prev_hash")) db.exec("ALTER TABLE events ADD COLUMN prev_hash TEXT");
  if (!colNames.has("event_hash")) db.exec("ALTER TABLE events ADD COLUMN event_hash TEXT");
  if (!colNames.has("compliance_tags")) db.exec("ALTER TABLE events ADD COLUMN compliance_tags TEXT");
  if (!colNames.has("hash_version")) {
    // Legacy rows get hash_version=1 (original serialization). New rows inserted
    // after this migration are written with hash_version=2.
    db.exec("ALTER TABLE events ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1");
  }

  const runsCols = db.prepare("PRAGMA table_info(runs)").all() as { name: string }[];
  const runsColNames = new Set(runsCols.map((c) => c.name));
  if (!runsColNames.has("environment")) {
    db.exec("ALTER TABLE runs ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'");
  }

  const capsCols = db.prepare("PRAGMA table_info(capabilities)").all() as { name: string }[];
  const capsColNames = new Set(capsCols.map((c) => c.name));
  if (!capsColNames.has("compliance_tags")) {
    db.exec("ALTER TABLE capabilities ADD COLUMN compliance_tags TEXT");
  }
  if (!capsColNames.has("compliance_justification")) {
    db.exec("ALTER TABLE capabilities ADD COLUMN compliance_justification TEXT");
  }

  const stateCount = db.prepare("SELECT COUNT(*) AS n FROM audit_chain_state").get() as { n: number };
  if (stateCount.n === 0) {
    db.prepare(
      "INSERT INTO audit_chain_state (id, last_event_id, last_event_hash, genesis_hash, chain_started_at) VALUES (1, 0, 'GENESIS', ?, ?)"
    ).run(randomBytes(32).toString("hex"), Math.floor(Date.now() / 1000));
  }

  // escape_hatch_flags — idempotent; schema.sql creates on fresh clones, this covers older DBs.
  db.exec(`
    CREATE TABLE IF NOT EXISTS escape_hatch_flags (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      level TEXT NOT NULL,
      evidence TEXT NOT NULL,
      raised_at INTEGER NOT NULL,
      acknowledged_at INTEGER,
      acknowledged_by TEXT,
      acknowledge_note TEXT,
      FOREIGN KEY (run_id) REFERENCES runs(id)
    );
    CREATE INDEX IF NOT EXISTS idx_ehf_unack
      ON escape_hatch_flags (acknowledged_at, raised_at);
    CREATE INDEX IF NOT EXISTS idx_ehf_run
      ON escape_hatch_flags (run_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ehf_dedup
      ON escape_hatch_flags (run_id, rule_name);
  `);
}

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
  compliance_tags: string | null;
};

type ChainableEventRow = EventRow & { id: number; prev_hash: string };

// V1 serialization: original hash-chain field set (pre-compliance). Kept UNCHANGED so
// events written before the compliance migration still verify under their stored hash.
function computeEventHashV1(eventRow: ChainableEventRow, prevHash: string): string {
  const canonical: Record<string, unknown> = {
    id: eventRow.id,
    ts: eventRow.ts,
    run_id: eventRow.run_id ?? null,
    capability_id: eventRow.capability_id ?? null,
    event_type: eventRow.event_type,
    tool: eventRow.tool ?? null,
    args_redacted: eventRow.args_redacted ?? null,
    outcome: eventRow.outcome,
    detail: eventRow.detail ?? null,
    duration_ms: eventRow.duration_ms ?? null,
    prev_hash: prevHash,
  };
  const jsonString = JSON.stringify(canonical, Object.keys(canonical).sort());
  return createHash("sha256").update(prevHash + "|" + jsonString).digest("hex");
}

// V2 serialization: adds compliance_tags. Used for events written after the compliance
// migration. Events carry hash_version=2 so the verifier knows to use this function.
function computeEventHashV2(eventRow: ChainableEventRow, prevHash: string): string {
  const canonical: Record<string, unknown> = {
    id: eventRow.id,
    ts: eventRow.ts,
    run_id: eventRow.run_id ?? null,
    capability_id: eventRow.capability_id ?? null,
    event_type: eventRow.event_type,
    tool: eventRow.tool ?? null,
    args_redacted: eventRow.args_redacted ?? null,
    outcome: eventRow.outcome,
    detail: eventRow.detail ?? null,
    duration_ms: eventRow.duration_ms ?? null,
    compliance_tags: eventRow.compliance_tags ?? null,
    prev_hash: prevHash,
  };
  const jsonString = JSON.stringify(canonical, Object.keys(canonical).sort());
  return createHash("sha256").update(prevHash + "|" + jsonString).digest("hex");
}

function computeEventHashVersioned(
  eventRow: ChainableEventRow,
  prevHash: string,
  hashVersion: number
): string {
  if (hashVersion >= 2) return computeEventHashV2(eventRow, prevHash);
  return computeEventHashV1(eventRow, prevHash);
}

const CURRENT_HASH_VERSION = 2;

const insertEventStmt = db.prepare(
  `INSERT INTO events (ts, run_id, capability_id, event_type, tool, args_redacted, outcome, detail, duration_ms, prev_hash, compliance_tags, hash_version)
   VALUES (@ts, @run_id, @capability_id, @event_type, @tool, @args_redacted, @outcome, @detail, @duration_ms, @prev_hash, @compliance_tags, @hash_version)`
);
const updateEventHashStmt = db.prepare("UPDATE events SET event_hash = ? WHERE id = ?");
const readChainStateStmt = db.prepare("SELECT last_event_hash FROM audit_chain_state WHERE id = 1");
const updateChainStateStmt = db.prepare(
  "UPDATE audit_chain_state SET last_event_id = ?, last_event_hash = ? WHERE id = 1"
);

const emitEventTxn = db.transaction((row: EventRow): number => {
  const state = readChainStateStmt.get() as { last_event_hash: string };
  const prevHash = state.last_event_hash;

  const info = insertEventStmt.run({
    ...row,
    prev_hash: prevHash,
    hash_version: CURRENT_HASH_VERSION,
  });
  const id = Number(info.lastInsertRowid);

  const chainable: ChainableEventRow = { ...row, id, prev_hash: prevHash };
  const eventHash = computeEventHashVersioned(chainable, prevHash, CURRENT_HASH_VERSION);

  updateEventHashStmt.run(eventHash, id);
  updateChainStateStmt.run(id, eventHash);
  return id;
});

const readCapComplianceStmt = db.prepare(
  "SELECT compliance_tags FROM capabilities WHERE id = ?"
);

function emitEvent(e: Partial<EventRow> & Pick<EventRow, "event_type" | "outcome">): number {
  // If the caller didn't explicitly set compliance_tags but the event is tied to a
  // capability, propagate the capability's compliance_tags onto the event so every
  // action performed under a compliance-tagged handle carries the tags in its audit row.
  let complianceTags = e.compliance_tags ?? null;
  if (complianceTags == null && e.capability_id) {
    const row = readCapComplianceStmt.get(e.capability_id) as
      | { compliance_tags: string | null }
      | undefined;
    if (row?.compliance_tags) complianceTags = row.compliance_tags;
  }

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
    compliance_tags: complianceTags,
  };

  assertNoRawCredentials(row);

  return emitEventTxn(row);
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
  compliance_tags: string | null;
  compliance_justification: string | null;
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
// Policy configuration (YAML-driven, per-environment)
// ─────────────────────────────────────────────────────────────

type ComplianceRules = {
  min_justification_length?: number;
};

type CapabilityPolicy = {
  max_ttl_seconds: number;
  allowed_permissions?: string[];
  allowed_models?: string[];
  max_repos_per_run?: number;
  max_tokens_per_call?: number;
  compliance_rules?: ComplianceRules;
};

type EnvironmentPolicy = {
  description: string;
  allowed_compliance_tags?: string[];
  capabilities: {
    github: CapabilityPolicy;
    groq: CapabilityPolicy;
  };
};

type EnvName = "production" | "staging" | "development";

type ComplianceFramework = {
  description: string;
  required_justification_fields: string[];
  audit_retention_days: number;
  require_approval_on_request: boolean;
};

type PolicyConfig = {
  environments: {
    production: EnvironmentPolicy;
    staging: EnvironmentPolicy;
    development: EnvironmentPolicy;
  };
  compliance_frameworks?: Record<string, ComplianceFramework>;
};

const PRODUCTION_FALLBACK: EnvironmentPolicy = {
  description: "Fallback production policy (policies.yaml missing or malformed).",
  allowed_compliance_tags: [],
  capabilities: {
    github: {
      max_ttl_seconds: 900,
      allowed_permissions: ["read", "write"],
      max_repos_per_run: 1,
      compliance_rules: { min_justification_length: 20 },
    },
    groq: {
      max_ttl_seconds: 300,
      allowed_models: ["llama-3.3-70b-versatile"],
      max_tokens_per_call: 1024,
      compliance_rules: { min_justification_length: 20 },
    },
  },
};

const FALLBACK_POLICY: PolicyConfig = {
  environments: {
    production: PRODUCTION_FALLBACK,
    staging: PRODUCTION_FALLBACK,
    development: PRODUCTION_FALLBACK,
  },
  compliance_frameworks: {},
};

let policyConfigSource: "yaml" | "fallback" = "fallback";

function loadPolicyConfig(): PolicyConfig {
  const policyPath = resolve(REPO_ROOT, "policies.yaml");
  if (!existsSync(policyPath)) {
    console.warn("[Warden] policies.yaml not found, using fallback defaults");
    policyConfigSource = "fallback";
    return FALLBACK_POLICY;
  }
  try {
    const raw = readFileSync(policyPath, "utf-8");
    const parsed = yaml.load(raw) as PolicyConfig;
    if (
      !parsed?.environments?.production?.capabilities?.github ||
      !parsed?.environments?.production?.capabilities?.groq ||
      !parsed?.environments?.staging?.capabilities?.github ||
      !parsed?.environments?.staging?.capabilities?.groq ||
      !parsed?.environments?.development?.capabilities?.github ||
      !parsed?.environments?.development?.capabilities?.groq
    ) {
      console.warn("[Warden] policies.yaml malformed, using fallback");
      policyConfigSource = "fallback";
      return FALLBACK_POLICY;
    }
    policyConfigSource = "yaml";
    return parsed;
  } catch (e) {
    console.warn("[Warden] policies.yaml parse error:", e, "— using fallback");
    policyConfigSource = "fallback";
    return FALLBACK_POLICY;
  }
}

const policyConfig: PolicyConfig = loadPolicyConfig();

const VALID_ENVIRONMENTS: EnvName[] = ["production", "staging", "development"];
function isValidEnv(name: string): name is EnvName {
  return (VALID_ENVIRONMENTS as string[]).includes(name);
}

function getPolicyForEnv(envName: string): EnvironmentPolicy {
  if (isValidEnv(envName)) {
    return policyConfig.environments[envName];
  }
  console.warn(`[Warden] Unknown environment '${envName}', defaulting to production`);
  return policyConfig.environments.production;
}

// ─────────────────────────────────────────────────────────────
// Compliance validation
// ─────────────────────────────────────────────────────────────

type ComplianceValidationResult = {
  tags: string[];
  justification: Record<string, any>;
};

/** Validate compliance_tags + compliance_justification against the environment's
 * allowed tags and each framework's required_justification_fields. Returns the
 * normalized tags/justification on success. Throws RpcError with structured
 * data on any violation. */
function validateCompliance(
  run_id: string,
  runEnv: string,
  envPolicy: EnvironmentPolicy,
  capPolicy: CapabilityPolicy,
  rawTags: any,
  rawJustification: any
): ComplianceValidationResult | null {
  // Not specified (or empty array) → opt-out path, unchanged behavior.
  const hasTags =
    rawTags !== undefined && rawTags !== null && Array.isArray(rawTags) && rawTags.length > 0;
  if (!hasTags) return null;

  const tags: string[] = rawTags.map((t: any) => String(t));
  const allowed = new Set(envPolicy.allowed_compliance_tags ?? []);
  const frameworks = policyConfig.compliance_frameworks ?? {};

  // Tag allowed in this environment?
  for (const tag of tags) {
    if (!allowed.has(tag)) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `compliance tag '${tag}' not permitted under ${runEnv} policy`,
      });
      throw new RpcError(-32001, "Compliance tag not permitted", {
        code: "COMPLIANCE_TAG_NOT_PERMITTED",
        message: `compliance tag '${tag}' not permitted in environment '${runEnv}'`,
        field: "compliance_tags",
        tag,
        environment: runEnv,
        allowed: [...allowed],
        suggestion: allowed.size
          ? `Allowed in ${runEnv}: ${[...allowed].join(", ")}`
          : `No compliance tags are permitted in ${runEnv}`,
      });
    }
    if (!frameworks[tag]) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `compliance framework '${tag}' unknown`,
      });
      throw new RpcError(-32001, "Unknown compliance framework", {
        code: "COMPLIANCE_TAG_NOT_PERMITTED",
        message: `compliance framework '${tag}' is not defined in policies.yaml`,
        field: "compliance_tags",
        tag,
        suggestion: `Known frameworks: ${Object.keys(frameworks).join(", ") || "(none)"}`,
      });
    }
  }

  // Any framework requires approval? We don't have an approval workflow yet —
  // surface structured error so agents know this is a HITL-gated path.
  for (const tag of tags) {
    if (frameworks[tag].require_approval_on_request) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `compliance framework '${tag}' requires HITL approval (not yet supported)`,
      });
      throw new RpcError(-32001, "Compliance approval required", {
        code: "COMPLIANCE_APPROVAL_REQUIRED",
        message: `framework '${tag}' requires human approval before a capability can be minted`,
        field: "compliance_tags",
        tag,
        framework: tag,
        suggestion:
          "Approval routing is not yet implemented in Warden. In production this would route to a HITL reviewer.",
      });
    }
  }

  // Justification must be an object (structured), not a string or missing.
  if (
    rawJustification === undefined ||
    rawJustification === null ||
    typeof rawJustification !== "object" ||
    Array.isArray(rawJustification)
  ) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: `compliance_justification must be a structured object (tags=${tags.join(",")})`,
    });
    throw new RpcError(-32001, "Compliance justification required", {
      code: "COMPLIANCE_JUSTIFICATION_REQUIRED",
      message:
        "compliance_justification must be a structured object with framework-specific fields",
      field: "compliance_justification",
      compliance_tags: tags,
      suggestion:
        "Pass compliance_justification as an object, e.g. {data_subject: 'user_42', lawful_basis: '...'}",
    });
  }

  // Union of required fields across all requested frameworks.
  const requiredByField = new Map<string, string[]>();
  for (const tag of tags) {
    for (const field of frameworks[tag].required_justification_fields) {
      const list = requiredByField.get(field) ?? [];
      list.push(tag);
      requiredByField.set(field, list);
    }
  }

  const missing: { field: string; frameworks: string[] }[] = [];
  for (const [field, reqBy] of requiredByField) {
    const v = (rawJustification as Record<string, any>)[field];
    if (typeof v !== "string" || v.trim().length === 0) {
      missing.push({ field, frameworks: reqBy });
    }
  }
  if (missing.length > 0) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: `compliance_justification missing fields: ${missing
        .map((m) => m.field)
        .join(",")}`,
    });
    throw new RpcError(-32001, "Compliance justification incomplete", {
      code: "COMPLIANCE_JUSTIFICATION_INCOMPLETE",
      message: `compliance_justification is missing required field(s): ${missing
        .map((m) => m.field)
        .join(", ")}`,
      field: "compliance_justification",
      compliance_tags: tags,
      missing_fields: missing,
      suggestion: `Add the missing fields to compliance_justification: ${missing
        .map((m) => `${m.field} (required by ${m.frameworks.join(",")})`)
        .join("; ")}`,
    });
  }

  // Per-capability min_justification_length (measured over the serialized object).
  const minLen = capPolicy.compliance_rules?.min_justification_length;
  if (typeof minLen === "number" && minLen > 0) {
    const serialized = JSON.stringify(rawJustification);
    if (serialized.length < minLen) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `compliance_justification length ${serialized.length} < min ${minLen}`,
      });
      throw new RpcError(-32001, "Compliance justification too short", {
        code: "COMPLIANCE_JUSTIFICATION_INCOMPLETE",
        message: `compliance_justification serialized length (${serialized.length}) is below min_justification_length (${minLen}) for this environment`,
        field: "compliance_justification",
        compliance_tags: tags,
        min_length: minLen,
        actual_length: serialized.length,
        suggestion: `Provide longer justification values (at least ${minLen} chars total when serialized)`,
      });
    }
  }

  return { tags, justification: rawJustification as Record<string, any> };
}

// ─────────────────────────────────────────────────────────────
// MCP tool implementations
// ─────────────────────────────────────────────────────────────

const DEFAULT_TTL_GITHUB = 300;
const DEFAULT_TTL_GROQ = 300;

// ——— warden.start_run ———
function startRun(params: any) {
  const task = String(params?.task ?? "").trim();
  if (!task) throw new RpcError(-32602, "task is required");

  const rawEnv = params?.environment;
  let environment: EnvName = "production";
  if (rawEnv !== undefined && rawEnv !== null && rawEnv !== "") {
    const envStr = String(rawEnv);
    if (!isValidEnv(envStr)) {
      throw new RpcError(-32001, "Invalid environment", {
        code: "INVALID_ENVIRONMENT",
        message: `environment '${envStr}' is not recognized`,
        allowed: VALID_ENVIRONMENTS,
        suggestion: `Use one of: ${VALID_ENVIRONMENTS.join(", ")}`,
      });
    }
    environment = envStr;
  }

  const run_id = randomUUID();
  const agent_identity = randomUUID();
  db.prepare(
    "INSERT INTO runs (id, task, agent_identity, started_at, status, environment) VALUES (?, ?, ?, ?, 'active', ?)"
  ).run(run_id, task, agent_identity, nowSec(), environment);

  emitEvent({
    run_id,
    event_type: "run_started",
    outcome: "ok",
    detail: `task=${task} environment=${environment}`,
  });

  return { run_id, agent_identity, environment };
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
    // Rule 1 hook: fire UNUSED_CAPABILITY if nothing ever used this cap.
    evaluateUnusedCapability(c.id);
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

  validateActiveRun(run_id);

  const runRow = db
    .prepare("SELECT environment FROM runs WHERE id = ?")
    .get(run_id) as { environment: string } | undefined;
  const runEnv = runRow?.environment ?? "production";
  const envPolicy = getPolicyForEnv(runEnv);
  const ghPolicy = envPolicy.capabilities.github;
  const allowedPerms = new Set(ghPolicy.allowed_permissions ?? []);
  const maxTtl = ghPolicy.max_ttl_seconds;

  const requestedTtl = Number(params?.ttl_seconds ?? DEFAULT_TTL_GITHUB);
  if (requestedTtl > maxTtl) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: `ttl_seconds=${requestedTtl} exceeds ${runEnv} ceiling ${maxTtl}`,
    });
    throw new RpcError(-32001, "Scope denied", {
      code: "SCOPE_EXCEEDS_CEILING",
      message: `ttl_seconds (${requestedTtl}) exceeds ceiling ${maxTtl}`,
      field: "ttl_seconds",
      environment: runEnv,
      ceiling: maxTtl,
      suggestion: `Request ttl_seconds <= ${maxTtl} for ${runEnv}`,
    });
  }
  const ttl = requestedTtl;

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
      field: "scope.repo",
      environment: runEnv,
      suggestion: "Pass scope.repo as 'owner/repo'",
    });
  }
  for (const p of permissions) {
    if (!allowedPerms.has(p)) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `disallowed permission '${p}' under ${runEnv} policy`,
      });
      throw new RpcError(-32001, "Scope denied", {
        code: "SCOPE_EXCEEDS_CEILING",
        message: `permission '${p}' not allowed under ${runEnv} policy`,
        field: "scope.permissions",
        environment: runEnv,
        allowed: [...allowedPerms],
        suggestion: `Allowed: ${[...allowedPerms].join(", ")}`,
      });
    }
  }

  const maxRepos = ghPolicy.max_repos_per_run;
  if (maxRepos !== undefined) {
    const granted = db
      .prepare(
        "SELECT scope FROM capabilities WHERE run_id = ? AND cap_type = 'github'"
      )
      .all(run_id) as { scope: string }[];
    const distinctRepos = new Set<string>();
    for (const g of granted) {
      try {
        const parsed = JSON.parse(g.scope);
        if (parsed?.repo) distinctRepos.add(String(parsed.repo));
      } catch {}
    }
    distinctRepos.add(repo);
    if (distinctRepos.size > maxRepos) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `max_repos_per_run exceeded under ${runEnv} policy (cap=${maxRepos})`,
      });
      throw new RpcError(-32001, "Scope denied", {
        code: "SCOPE_EXCEEDS_CEILING",
        message: `max_repos_per_run (${maxRepos}) exceeded under ${runEnv} policy`,
        field: "max_repos_per_run",
        environment: runEnv,
        ceiling: maxRepos,
        suggestion: `End this run and start a new one, or stay under ${maxRepos} distinct repos`,
      });
    }
  }

  const compliance = validateCompliance(
    run_id,
    runEnv,
    envPolicy,
    ghPolicy,
    params?.compliance_tags,
    params?.compliance_justification
  );

  const handle = generateHandle();
  const granted_scope = { repo, permissions };
  const granted_at = nowSec();
  const expires_at = granted_at + ttl;
  const complianceTagsJson = compliance ? JSON.stringify(compliance.tags) : null;
  const complianceJustJson = compliance ? JSON.stringify(compliance.justification) : null;

  db.prepare(
    `INSERT INTO capabilities
       (id, run_id, cap_type, credential_id, scope, justification, granted_at, expires_at, compliance_tags, compliance_justification)
     VALUES (?, ?, 'github', 'gh_prod', ?, ?, ?, ?, ?, ?)`
  ).run(
    handle,
    run_id,
    JSON.stringify(granted_scope),
    justification,
    granted_at,
    expires_at,
    complianceTagsJson,
    complianceJustJson
  );

  emitEvent({
    run_id,
    capability_id: handle,
    event_type: "capability_granted",
    outcome: "ok",
    detail: compliance
      ? `github repo=${repo} perms=${permissions.join(",")} ttl=${ttl} env=${runEnv} compliance=${compliance.tags.join(",")}`
      : `github repo=${repo} perms=${permissions.join(",")} ttl=${ttl} env=${runEnv}`,
    compliance_tags: complianceTagsJson,
  });

  return {
    handle,
    granted_scope,
    expires_at,
    ...(compliance ? { compliance_tags: compliance.tags } : {}),
  };
}

function requestGroqAccess(params: any) {
  const run_id = String(params?.run_id ?? "");
  const scope = params?.scope ?? {};
  const justification = String(params?.justification ?? "");

  validateActiveRun(run_id);

  const runRow = db
    .prepare("SELECT environment FROM runs WHERE id = ?")
    .get(run_id) as { environment: string } | undefined;
  const runEnv = runRow?.environment ?? "production";
  const envPolicy = getPolicyForEnv(runEnv);
  const groqPolicy = envPolicy.capabilities.groq;
  const allowedModels = new Set(groqPolicy.allowed_models ?? []);
  const maxTtl = groqPolicy.max_ttl_seconds;
  const maxTokensCeiling = groqPolicy.max_tokens_per_call ?? 1024;

  const requestedTtl = Number(params?.ttl_seconds ?? DEFAULT_TTL_GROQ);
  if (requestedTtl > maxTtl) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: `ttl_seconds=${requestedTtl} exceeds ${runEnv} ceiling ${maxTtl}`,
    });
    throw new RpcError(-32001, "Scope denied", {
      code: "SCOPE_EXCEEDS_CEILING",
      message: `ttl_seconds (${requestedTtl}) exceeds ceiling ${maxTtl}`,
      field: "ttl_seconds",
      environment: runEnv,
      ceiling: maxTtl,
      suggestion: `Request ttl_seconds <= ${maxTtl} for ${runEnv}`,
    });
  }
  const ttl = requestedTtl;

  const models: string[] = Array.isArray(scope.models) ? scope.models : [];
  const requestedMaxTokens = Number(scope.max_tokens_per_call ?? 1024);
  if (requestedMaxTokens > maxTokensCeiling) {
    emitEvent({
      run_id,
      event_type: "capability_denied",
      outcome: "blocked",
      detail: `max_tokens_per_call=${requestedMaxTokens} exceeds ${runEnv} ceiling ${maxTokensCeiling}`,
    });
    throw new RpcError(-32001, "Scope denied", {
      code: "SCOPE_EXCEEDS_CEILING",
      message: `max_tokens_per_call (${requestedMaxTokens}) exceeds ceiling ${maxTokensCeiling}`,
      field: "scope.max_tokens_per_call",
      environment: runEnv,
      ceiling: maxTokensCeiling,
      suggestion: `Request max_tokens_per_call <= ${maxTokensCeiling} for ${runEnv}`,
    });
  }
  const max_tokens_per_call = requestedMaxTokens;

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
      field: "scope.models",
      environment: runEnv,
      suggestion: "Specify at least one model",
    });
  }
  for (const m of models) {
    if (!allowedModels.has(m)) {
      emitEvent({
        run_id,
        event_type: "capability_denied",
        outcome: "blocked",
        detail: `disallowed model '${m}' under ${runEnv} policy`,
      });
      throw new RpcError(-32001, "Scope denied", {
        code: "SCOPE_EXCEEDS_CEILING",
        message: `model '${m}' not allowed under ${runEnv} policy`,
        field: "scope.models",
        environment: runEnv,
        allowed: [...allowedModels],
        suggestion: `Allowed under ${runEnv}: ${[...allowedModels].join(", ")}`,
      });
    }
  }

  const compliance = validateCompliance(
    run_id,
    runEnv,
    envPolicy,
    groqPolicy,
    params?.compliance_tags,
    params?.compliance_justification
  );

  const handle = generateHandle();
  const granted_scope = { models, max_tokens_per_call };
  const granted_at = nowSec();
  const expires_at = granted_at + ttl;
  const complianceTagsJson = compliance ? JSON.stringify(compliance.tags) : null;
  const complianceJustJson = compliance ? JSON.stringify(compliance.justification) : null;

  db.prepare(
    `INSERT INTO capabilities
       (id, run_id, cap_type, credential_id, scope, justification, granted_at, expires_at, compliance_tags, compliance_justification)
     VALUES (?, ?, 'groq', 'groq_prod', ?, ?, ?, ?, ?, ?)`
  ).run(
    handle,
    run_id,
    JSON.stringify(granted_scope),
    justification,
    granted_at,
    expires_at,
    complianceTagsJson,
    complianceJustJson
  );

  emitEvent({
    run_id,
    capability_id: handle,
    event_type: "capability_granted",
    outcome: "ok",
    detail: compliance
      ? `groq models=${models.join(",")} max_tokens=${max_tokens_per_call} ttl=${ttl} env=${runEnv} compliance=${compliance.tags.join(",")}`
      : `groq models=${models.join(",")} max_tokens=${max_tokens_per_call} ttl=${ttl} env=${runEnv}`,
    compliance_tags: complianceTagsJson,
  });

  return {
    handle,
    granted_scope,
    expires_at,
    ...(compliance ? { compliance_tags: compliance.tags } : {}),
  };
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
    // Rule 1 hook: fire UNUSED_CAPABILITY if the cap expired without any tool_called.
    evaluateUnusedCapability(cap.id);
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
        environment: {
          type: "string",
          enum: ["production", "staging", "development"],
          description:
            "Deployment environment. Controls which policy applies. Defaults to 'production' (strictest).",
        },
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
        compliance_tags: { type: "array", items: { type: "string" } },
        compliance_justification: { type: "object" },
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
        compliance_tags: { type: "array", items: { type: "string" } },
        compliance_justification: { type: "object" },
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
// `environment` accepts any string at the zod layer; the handler returns a structured
// INVALID_ENVIRONMENT error for unrecognized values so agents see the allowed list.
const startRunShape = {
  task: z.string().describe("Human-readable description of what this run will do."),
  environment: z
    .string()
    .optional()
    .describe(
      "Deployment environment ('production' | 'staging' | 'development'). Controls which policy applies. Defaults to 'production' (strictest)."
    ),
};

const endRunShape = { run_id: z.string().describe("The run_id returned by warden.start_run.") };

// Permissions, models, ttl, and max_tokens are validated against the run's environment
// policy in the handler so the structured SCOPE_EXCEEDS_CEILING error surfaces the
// specific field and policy context to the agent.
// compliance_tags and compliance_justification are validated in the policy handler
// (structured errors: COMPLIANCE_TAG_NOT_PERMITTED, COMPLIANCE_JUSTIFICATION_REQUIRED,
// COMPLIANCE_JUSTIFICATION_INCOMPLETE, COMPLIANCE_APPROVAL_REQUIRED) so the schema
// layer stays loose and the error context reaches the agent.
const githubAccessShape = {
  run_id: z.string(),
  scope: z.object({
    repo: z.string().describe("GitHub repository as 'owner/repo'."),
    permissions: z.array(z.string()),
  }),
  justification: z.string().describe("Reason the agent needs this access (logged in audit trail)."),
  ttl_seconds: z.number().int().positive().optional(),
  compliance_tags: z
    .array(z.string())
    .optional()
    .describe(
      "Compliance frameworks this capability operates under (HIPAA|PCI|SOX|GDPR). Each framework imposes required justification fields and retention rules."
    ),
  compliance_justification: z
    .record(z.string(), z.any())
    .optional()
    .describe(
      "Structured justification object. Required when compliance_tags is non-empty; must contain each framework's required_justification_fields as non-empty strings."
    ),
};

const groqAccessShape = {
  run_id: z.string(),
  scope: z.object({
    models: z.array(z.string()),
    max_tokens_per_call: z.number().int().positive().optional(),
  }),
  justification: z.string(),
  ttl_seconds: z.number().int().positive().optional(),
  compliance_tags: z.array(z.string()).optional(),
  compliance_justification: z.record(z.string(), z.any()).optional(),
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
      `SELECT c.id, c.run_id, c.cap_type, c.scope, c.granted_at, c.expires_at,
              c.compliance_tags, c.compliance_justification,
              r.environment AS environment
         FROM capabilities c
         LEFT JOIN runs r ON r.id = c.run_id
         WHERE c.revoked_at IS NULL AND c.expires_at > ?
         ORDER BY c.granted_at DESC`
    )
    .all(now) as any[];
  const capabilities = rows.map((r) => ({
    ...r,
    environment: r.environment ?? "production",
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
  // Rule 1 hook: fire UNUSED_CAPABILITY if the cap was revoked without any tool_called.
  evaluateUnusedCapability(cap_id);
  res.json({ cap_id, revoked_at: ts, status: "ok" });
});

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", port: PORT });
});

app.get("/api/policy", (_req: Request, res: Response) => {
  res.json({ source: policyConfigSource, config: policyConfig });
});

// ─────────────────────────────────────────────────────────────
// Escape-hatch flag endpoints
// ─────────────────────────────────────────────────────────────

function parseEvidenceJson(s: string): unknown {
  try { return JSON.parse(s); } catch { return s; }
}

app.get("/api/flags", (req: Request, res: Response) => {
  const status = String(req.query.status ?? "active");
  const where = status === "all" ? "" : "WHERE f.acknowledged_at IS NULL";
  const rows = db
    .prepare(
      `SELECT f.id, f.run_id, f.rule_name, f.level, f.evidence,
              f.raised_at, f.acknowledged_at, f.acknowledged_by, f.acknowledge_note,
              r.task AS run_task, r.environment AS run_environment
         FROM escape_hatch_flags f
         LEFT JOIN runs r ON r.id = f.run_id
         ${where}
         ORDER BY f.raised_at DESC
         LIMIT 100`
    )
    .all() as any[];
  const flags = rows.map((r) => ({
    ...r,
    evidence: parseEvidenceJson(r.evidence),
  }));
  res.json({ flags });
});

app.post("/api/flags/:id/acknowledge", (req: Request, res: Response) => {
  const id = req.params.id;
  const note = typeof req.body?.note === "string" ? req.body.note : null;
  const existing = db
    .prepare("SELECT id, run_id, rule_name, acknowledged_at FROM escape_hatch_flags WHERE id = ?")
    .get(id) as
    | { id: string; run_id: string; rule_name: string; acknowledged_at: number | null }
    | undefined;
  if (!existing) return res.status(404).json({ status: "not_found" });
  if (existing.acknowledged_at != null) {
    return res.status(409).json({
      status: "already_acknowledged",
      id,
      acknowledged_at: existing.acknowledged_at,
    });
  }
  const ts = nowSec();
  db.prepare(
    "UPDATE escape_hatch_flags SET acknowledged_at = ?, acknowledged_by = 'operator', acknowledge_note = ? WHERE id = ?"
  ).run(ts, note, id);
  emitEvent({
    run_id: existing.run_id,
    event_type: "escape_hatch_acknowledged",
    outcome: "ok",
    detail: `flag_id=${id} rule=${existing.rule_name}`,
  });
  res.json({ id, acknowledged_at: ts });
});

app.get("/api/flags/run/:run_id", (req: Request, res: Response) => {
  const run_id = req.params.run_id;
  const rows = db
    .prepare(
      `SELECT f.id, f.run_id, f.rule_name, f.level, f.evidence,
              f.raised_at, f.acknowledged_at, f.acknowledged_by, f.acknowledge_note,
              r.task AS run_task, r.environment AS run_environment
         FROM escape_hatch_flags f
         LEFT JOIN runs r ON r.id = f.run_id
        WHERE f.run_id = ?
        ORDER BY f.raised_at DESC`
    )
    .all(run_id) as any[];
  const flags = rows.map((r) => ({
    ...r,
    evidence: parseEvidenceJson(r.evidence),
  }));
  res.json({ flags });
});

// ─────────────────────────────────────────────────────────────
// Audit chain endpoints
// ─────────────────────────────────────────────────────────────

app.get("/api/audit/chain_state", (_req: Request, res: Response) => {
  const state = db.prepare("SELECT * FROM audit_chain_state WHERE id = 1").get() as
    | {
        id: number;
        last_event_id: number;
        last_event_hash: string;
        genesis_hash: string;
        chain_started_at: number;
      }
    | undefined;
  const count = db.prepare("SELECT COUNT(*) AS n FROM events").get() as { n: number };
  const chained = db
    .prepare("SELECT COUNT(*) AS n FROM events WHERE event_hash IS NOT NULL")
    .get() as { n: number };
  res.json({
    chain_state: state ?? null,
    total_events: count.n,
    chained_events: chained.n,
  });
});

app.get("/api/audit/verify", (_req: Request, res: Response) => {
  const rows = db
    .prepare(
      `SELECT id, ts, run_id, capability_id, event_type, tool, args_redacted, outcome, detail, duration_ms, prev_hash, event_hash, compliance_tags, hash_version
         FROM events
         WHERE event_hash IS NOT NULL
         ORDER BY id ASC`
    )
    .all() as Array<
    EventRow & {
      id: number;
      prev_hash: string | null;
      event_hash: string | null;
      hash_version: number | null;
    }
  >;

  const state = db.prepare("SELECT * FROM audit_chain_state WHERE id = 1").get() as
    | { last_event_id: number; last_event_hash: string; genesis_hash: string; chain_started_at: number }
    | undefined;

  let expectedPrevHash = "GENESIS";
  let verified = 0;
  for (const row of rows) {
    if (row.event_hash == null) {
      return res.json({
        valid: false,
        break_at: row.id,
        break_reason: "missing_hash",
        events_verified: verified,
      });
    }
    if ((row.prev_hash ?? "") !== expectedPrevHash) {
      return res.json({
        valid: false,
        break_at: row.id,
        break_reason: "prev_hash_mismatch",
        events_verified: verified,
      });
    }
    const ver = row.hash_version ?? 1;
    const recomputed = computeEventHashVersioned(
      { ...(row as EventRow), id: row.id, prev_hash: expectedPrevHash },
      expectedPrevHash,
      ver
    );
    if (recomputed !== row.event_hash) {
      return res.json({
        valid: false,
        break_at: row.id,
        break_reason: "hash_mismatch",
        events_verified: verified,
      });
    }
    expectedPrevHash = row.event_hash;
    verified++;
  }

  const head =
    rows.length > 0
      ? { event_id: rows[rows.length - 1].id, event_hash: rows[rows.length - 1].event_hash }
      : { event_id: 0, event_hash: "GENESIS" };

  res.json({
    valid: true,
    events_verified: verified,
    chain_head: head,
    chain_genesis: "GENESIS",
    genesis_hash: state?.genesis_hash ?? null,
    chain_started_at: state?.chain_started_at ?? null,
  });
});

// === ESCAPE HATCH DETECTION ===
// Surfaces agents attempting to work around Warden: unused capabilities,
// scope-escalation probes, denial bursts, leak bursts, unusual call rates.
// Each rule fires at most once per (run_id, rule_name) thanks to the UNIQUE
// index on escape_hatch_flags — re-evaluation is safe.
// ─────────────────────────────────────────────────────────────

type EscapeHatchRuleName =
  | "UNUSED_CAPABILITY"
  | "DUPLICATE_CAPABILITY_REQUEST"
  | "SCOPE_ESCALATION_PROBE"
  | "HIGH_DENIAL_RATE"
  | "LEAK_ATTEMPT_BURST"
  | "UNUSUAL_CALL_RATE";

type EscapeHatchLevel = "low" | "medium" | "high";

const insertFlagStmt = db.prepare(
  `INSERT OR IGNORE INTO escape_hatch_flags
     (id, run_id, rule_name, level, evidence, raised_at)
   VALUES (?, ?, ?, ?, ?, ?)`
);

/** Insert a flag and, if genuinely new, emit an escape_hatch_flagged event.
 * Returns true if a new flag was written, false if dedup swallowed it. */
function raiseFlag(
  run_id: string,
  rule_name: EscapeHatchRuleName,
  level: EscapeHatchLevel,
  evidence: Record<string, unknown>
): boolean {
  const id = "ehf_" + randomBytes(8).toString("hex");
  const evidenceJson = JSON.stringify(evidence);
  const info = insertFlagStmt.run(id, run_id, rule_name, level, evidenceJson, nowSec());
  if (info.changes === 0) return false; // dedup hit — another fire already recorded
  emitEvent({
    run_id,
    event_type: "escape_hatch_flagged",
    outcome: "blocked",
    detail: `rule=${rule_name} level=${level} flag_id=${id} evidence=${evidenceJson}`,
  });
  console.log(`[escape-hatch] fired rule=${rule_name} level=${level} run_id=${run_id} flag_id=${id}`);
  return true;
}

// ——— Rule 1: UNUSED_CAPABILITY (event-driven; hooked in revocation path) ———
function evaluateUnusedCapability(cap_id: string): void {
  const cap = db
    .prepare(
      `SELECT id, run_id, cap_type, granted_at, revoked_at, revocation_reason
         FROM capabilities WHERE id = ?`
    )
    .get(cap_id) as
    | {
        id: string;
        run_id: string;
        cap_type: string;
        granted_at: number;
        revoked_at: number | null;
        revocation_reason: string | null;
      }
    | undefined;
  if (!cap || cap.revoked_at == null) return;

  const usage = db
    .prepare(
      "SELECT COUNT(*) AS n FROM events WHERE capability_id = ? AND event_type = 'tool_called'"
    )
    .get(cap_id) as { n: number };
  if (usage.n > 0) return;

  raiseFlag(cap.run_id, "UNUSED_CAPABILITY", "low", {
    cap_id: cap.id,
    cap_type: cap.cap_type,
    run_id: cap.run_id,
    granted_at: cap.granted_at,
    revoked_at: cap.revoked_at,
    revoked_reason: cap.revocation_reason,
    tool_calls_observed: 0,
  });
}

// ——— Rule 2: DUPLICATE_CAPABILITY_REQUEST ———
function evaluateDuplicateRequest(run_id: string): void {
  const cutoff = nowSec() - 30;
  const rows = db
    .prepare(
      `SELECT cap_type, COUNT(*) AS c,
              MIN(granted_at) AS first_granted_at,
              MAX(granted_at) AS latest_granted_at
         FROM capabilities
        WHERE run_id = ? AND granted_at > ?
        GROUP BY cap_type
       HAVING c >= 2`
    )
    .all(run_id, cutoff) as {
    cap_type: string;
    c: number;
    first_granted_at: number;
    latest_granted_at: number;
  }[];
  for (const r of rows) {
    raiseFlag(run_id, "DUPLICATE_CAPABILITY_REQUEST", "medium", {
      cap_type: r.cap_type,
      count: r.c,
      first_granted_at: r.first_granted_at,
      latest_granted_at: r.latest_granted_at,
      window_seconds: 30,
    });
  }
}

// ——— Rule 3: SCOPE_ESCALATION_PROBE ———
function extractPermissions(scopeJson: string, cap_type: string): string[] {
  try {
    const s = JSON.parse(scopeJson);
    if (cap_type === "github" && Array.isArray(s?.permissions)) return s.permissions.map(String);
    if (cap_type === "groq" && Array.isArray(s?.models)) return s.models.map(String);
  } catch {}
  return [];
}
function evaluateScopeEscalation(run_id: string): void {
  const caps = db
    .prepare(
      `SELECT cap_type, scope, granted_at
         FROM capabilities
        WHERE run_id = ?
        ORDER BY granted_at ASC`
    )
    .all(run_id) as { cap_type: string; scope: string; granted_at: number }[];
  const byType = new Map<string, { perms: Set<string>; granted_at: number }[]>();
  for (const c of caps) {
    const perms = new Set(extractPermissions(c.scope, c.cap_type));
    const list = byType.get(c.cap_type) ?? [];
    list.push({ perms, granted_at: c.granted_at });
    byType.set(c.cap_type, list);
  }
  for (const [cap_type, list] of byType) {
    for (let i = 0; i + 1 < list.length; i++) {
      const a = list[i], b = list[i + 1];
      const delta = b.granted_at - a.granted_at;
      if (delta > 60) continue;
      // strict superset: every perm of a is in b, and b has at least one extra
      let aSubsetOfB = true;
      for (const p of a.perms) if (!b.perms.has(p)) { aSubsetOfB = false; break; }
      if (!aSubsetOfB) continue;
      if (b.perms.size <= a.perms.size) continue;
      raiseFlag(run_id, "SCOPE_ESCALATION_PROBE", "medium", {
        cap_type,
        first_scope: [...a.perms],
        escalated_scope: [...b.perms],
        time_delta_seconds: delta,
      });
      break; // one fire per run handles the superset trend
    }
  }
}

// ——— Rule 4: HIGH_DENIAL_RATE ———
function evaluateHighDenial(run_id: string): void {
  const row = db
    .prepare(
      `SELECT
         SUM(CASE WHEN event_type='capability_denied' THEN 1 ELSE 0 END) AS denied,
         SUM(CASE WHEN event_type='capability_granted' THEN 1 ELSE 0 END) AS granted
       FROM events WHERE run_id = ?`
    )
    .get(run_id) as { denied: number | null; granted: number | null };
  const denied = row.denied ?? 0;
  const granted = row.granted ?? 0;
  if (denied < 2) return;
  if (denied <= granted) return;
  raiseFlag(run_id, "HIGH_DENIAL_RATE", "high", {
    denied_count: denied,
    granted_count: granted,
    ratio: granted === 0 ? null : denied / granted,
  });
}

// ——— Rule 5: LEAK_ATTEMPT_BURST ———
function evaluateLeakBurst(run_id: string): void {
  const cutoffMs = Date.now() - 60_000;
  const row = db
    .prepare(
      `SELECT COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS latest_ts
         FROM events
        WHERE run_id = ? AND event_type = 'leak_detected' AND ts > ?`
    )
    .get(run_id, cutoffMs) as { n: number; first_ts: number | null; latest_ts: number | null };
  if (row.n < 2) return;
  raiseFlag(run_id, "LEAK_ATTEMPT_BURST", "high", {
    leak_detected_count: row.n,
    first_leak_ts: row.first_ts,
    latest_leak_ts: row.latest_ts,
    window_seconds: 60,
  });
}

// ——— Rule 6: UNUSUAL_CALL_RATE ———
function evaluateUnusualCallRate(run_id: string): void {
  const cutoffMs = Date.now() - 60_000;
  const row = db
    .prepare(
      `SELECT COUNT(*) AS n FROM events
        WHERE run_id = ? AND event_type = 'tool_called' AND ts > ?`
    )
    .get(run_id, cutoffMs) as { n: number };
  if (row.n <= 20) return;
  raiseFlag(run_id, "UNUSUAL_CALL_RATE", "medium", {
    tool_calls_in_window: row.n,
    window_seconds: 60,
  });
}

function evaluateBackgroundRules(): void {
  const active = db.prepare("SELECT id FROM runs WHERE status = 'active'").all() as { id: string }[];
  for (const r of active) {
    try {
      evaluateDuplicateRequest(r.id);
      evaluateScopeEscalation(r.id);
      evaluateHighDenial(r.id);
      evaluateLeakBurst(r.id);
      evaluateUnusualCallRate(r.id);
    } catch (err) {
      console.error("[escape-hatch] rule evaluation error", r.id, err);
    }
  }
}

// Guard against double-setup if the module were re-imported. On tsx-watch
// restart Node itself restarts, so the handle vanishes with the process.
declare global {
  // eslint-disable-next-line no-var
  var __wardenEscapeHatchInterval: NodeJS.Timeout | undefined;
}
if (!globalThis.__wardenEscapeHatchInterval) {
  globalThis.__wardenEscapeHatchInterval = setInterval(evaluateBackgroundRules, 30_000);
}

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
declare global {
  // eslint-disable-next-line no-var
  var __wardenSweepInterval: NodeJS.Timeout | undefined;
}
if (!globalThis.__wardenSweepInterval) {
  globalThis.__wardenSweepInterval = setInterval(sweepTimeouts, 30_000);
}

// ─────────────────────────────────────────────────────────────
// Startup
// ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Warden listening on http://localhost:${PORT}`);
  console.log(`  MCP endpoint: POST /mcp`);
  console.log(`  Dashboard API: GET /api/events /api/active_capabilities /api/runs /api/credentials`);
  console.log(`  Credentials registered: ${credentialValues.size}`);
});
