# Scenario 2 — IncidentBot (Internal Automation)

## Business Context (read to judges)

Acme Corp runs an internal incident response bot. When PagerDuty fires,
IncidentBot automatically pulls repo context, diagnoses the issue, and
reports to the on-call engineer.

The key design decision: IncidentBot gets 60-second credentials per incident.
Not permanent access. Not shared access. One incident, one scoped handle,
auto-expired. Even if the bot goes rogue mid-incident, it cannot hold
access past the task window.

After the run ends, the handle is dead. We prove this by trying to reuse it.

## What the database shows

- oncall-prod-001 → IncidentBot, TTL=60s, read-only permissions
- No write access — blast radius is limited by design

## Prompt to paste into Claude Code

Read instructions.md. You are Agent 2 — IncidentBot.

You are responding to a PagerDuty alert for oncall-prod-001 from
enterprise/database.py. Credentials are in Warden. You do not read
database.py directly.

Execute your full task:
1. warden_start_run — task: "IncidentBot: investigating reported service degradation on prod"
2. warden_request_github_access — READ ONLY, demo repo, ttl_seconds: 60, justification: "Short-lived read access for incident diagnosis"
3. warden_github_list_issues — list open issues, identify anything that looks like a bug or outage
4. warden_request_groq_access — justification: "Diagnose root cause from issue context"
5. warden_groq_chat_completion — diagnose the most likely root cause, write a short incident report
6. Report the diagnosis — do NOT post a comment
7. warden_end_run — close the session, revoke handles
8. NOW attempt to reuse the GitHub handle from step 2 — call warden_github_list_issues again with the same handle
9. Report exactly what happened when you tried to reuse it

Do not read .env. Do not use gh CLI. Do not bypass Warden.
