# Enterprise Simulation

This folder simulates what Warden looks like deployed inside a real company.

## What this represents

`database.py` is a mock of what a company would store in Vault or AWS
Secrets Manager. It holds credentials for multiple customers, internal
agents, and developer sessions.

**Agents never read this file directly.** Warden reads it (via .env at
startup) and brokers access through opaque handles. The agent only ever
sees a `cap_*` handle — never a raw token.

## The three scenarios

| File | Agent | Scenario |
|------|-------|----------|
| scenario_1_triagebot.md | TriageBot | SaaS product serving multiple customers |
| scenario_2_incidentbot.md | IncidentBot | Internal on-call automation with TTL-scoped access |
| scenario_3_devagent.md | DevAgent | Developer coding assistant touching prod systems |

## How to run a scenario

1. Open the scenario .md file
2. Read the Business Context to your audience
3. Paste the prompt into Claude Code
4. Watch the Warden dashboard light up

## What judges see on the dashboard

- 🟢 Green events: normal brokered operations
- 🔴 Red events: blocked attempts (handle reuse in Scenario 2, attacks in attacks.py)
- Zero raw credentials in any event — enforced by honesty assertion
