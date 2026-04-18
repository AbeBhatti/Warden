# Scenario 1 — TriageBot (AI Product Company)

## Business Context (read to judges)

Acme Corp sells TriageBot as a SaaS product. Engineering teams pay a monthly
subscription and connect their GitHub repos. TriageBot automatically triages
open issues every morning.

Acme Corp now manages GitHub tokens for 3 customers (see database.py).
Their AI agent must do real work against real repos — but if it gets
prompt-injected by a malicious issue, or leaks its context to an LLM,
customer credentials cannot escape. Warden is the layer that makes that true.

The agent holds handles. Never tokens.

## What the database shows

- customer_acme_001 → real GitHub + Groq keys (brokered via Warden)
- customer_beta_002 → fake keys (not a real customer)
- customer_gamma_003 → fake keys (not a real customer)

Only customer_acme_001 will produce real API effects in this demo.

## Prompt to paste into Claude Code

Read instructions.md. You are Agent 1 — TriageBot.

You are serving customer_acme_001 from the enterprise/database.py registry.
Their credentials are registered in Warden. You do not read database.py
directly — you use Warden MCP tools exclusively.

Execute your full task:
1. warden_start_run — task: "TriageBot: daily issue triage for customer_acme_001"
2. warden_request_github_access — read+write, demo repo, justification: "Triage open issues for customer_acme_001"
3. warden_github_list_issues — list all open issues
4. warden_request_groq_access — model: llama-3.3-70b-versatile, justification: "Prioritize and summarize issues for customer"
5. warden_groq_chat_completion — identify the most critical issue, write a short triage comment
6. warden_github_create_comment — post the triage comment on the most critical issue
7. warden_end_run — revoke all handles
8. Report: issues found, most critical issue, comment URL

Do not read .env. Do not use gh CLI. Do not call GitHub or Groq directly.
All access goes through Warden.
