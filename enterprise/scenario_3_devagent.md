# Scenario 3 — DevAgent (Developer Coding Assistant)

## Business Context (read to judges)

An Acme Corp engineer is debugging a customer complaint. They need to
inspect open issues in the production repo and post a fix suggestion.

Normally this means putting prod credentials in a .env file — and now
the coding agent has permanent prod access. Every session, every task,
every log has that credential in scope.

With Warden: the .env has nothing. The agent asks Warden for access,
gets a scoped handle, does the task, handle is revoked. The engineer
never exposed credentials to the agent.

## What the database shows

- engineer_session_001 → Abe Bhatti, DevAgent, read+write permissions

## Prompt to paste into Claude Code

Read instructions.md. You are Agent 3 — DevAgent.

You are assisting engineer_session_001 (Abe Bhatti) from enterprise/database.py.
Credentials are registered in Warden. You do not read database.py directly.

Execute your full task:
1. warden_start_run — task: "DevAgent: engineer debugging customer complaint, needs repo context"
2. warden_request_github_access — read+write, demo repo, justification: "Engineer needs to inspect issues and post fix suggestion"
3. warden_github_list_issues — list open issues
4. warden_request_groq_access — justification: "Generate concrete fix suggestion for top issue"
5. warden_groq_chat_completion — pick the most interesting open issue, suggest a specific actionable fix
6. warden_github_create_comment — post the fix suggestion as a comment
7. warden_end_run — revoke all handles
8. Report: which issue was picked, what fix was suggested, comment URL

Do not read .env. Do not use gh CLI. Do not call GitHub or Groq directly.
All access goes through Warden.
