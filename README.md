# Warden

**MCP-native credential broker for AI agents.**

Agents today run as root. Warden is the IAM layer that should exist.

AI agents hold raw credentials — API keys, tokens, passwords — in env vars, context windows, and logs. Once a secret enters the agent's world, it is everywhere. Warden inverts this: **agents never hold raw credentials. They hold opaque handles.** Real secrets live behind Warden's trust boundary. Every credentialed operation is mediated.

## Setup

```bash
cp .env.example .env
# Fill in GITHUB_TOKEN, GROQ_API_KEY, DEMO_REPO

cd backend && npm install
npm run dev
```

Dashboard: open `frontend/index.html` in browser.

Demo agent: `python scripts/demo_agent.py`

Attacks: `python scripts/attacks.py`

## Architecture

- **Handle model** — agents get opaque `cap_*` handles, not raw tokens
- **Per-run lifecycle** — `start_run` → capabilities → `end_run` auto-revokes everything
- **Honesty assertion** — every event is checked for raw credential values before insert; process dies if one is found
- **Proxy mode** — Warden makes the real API call on the agent's behalf and sanitizes the response

See [warden-build-prd.md](warden-build-prd.md) for the full spec.
