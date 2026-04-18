"""Warden demo agent — scripted positive flow.

Spec: PRD §14. Exercises the full combined-capability task:
  start_run → request_github_access → list_issues →
  request_groq_access → chat_completion →
  github.create_comment → end_run

Calls Warden via JSON-RPC over HTTP. Uses 1.5s pauses between steps
so the dashboard can render each event live in front of the judges.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

try:
    from dotenv import load_dotenv
    # Load .env from repo root (one level above scripts/)
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass


WARDEN_URL = os.environ.get("WARDEN_URL", "http://localhost:3000/rpc")
DEMO_REPO = os.environ.get("DEMO_REPO", "your-username/warden-demo")


class WardenError(Exception):
    pass


def call_mcp(method: str, params: dict) -> dict:
    """Send JSON-RPC request to Warden, return result or raise WardenError."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    resp = requests.post(WARDEN_URL, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        err = data["error"]
        raise WardenError(f"{err.get('code')}: {err.get('message')}")
    return data["result"]


def banner(text: str) -> None:
    print(f"\n▶ {text}")


def main() -> int:
    if DEMO_REPO == "your-username/warden-demo":
        print(
            "⚠  DEMO_REPO is unset — set DEMO_REPO in .env before the demo.",
            file=sys.stderr,
        )

    banner(f"Starting run (Warden at {WARDEN_URL})")
    run = call_mcp("warden.start_run", {"task": "Triage open issues in demo-repo"})
    run_id = run["run_id"]
    print(f"  run_id = {run_id}")
    time.sleep(1.5)

    banner("Requesting GitHub access")
    gh = call_mcp(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read", "write"]},
            "justification": "Need to read open issues and post triage comment",
        },
    )
    gh_handle = gh["handle"]
    print(f"  handle = {gh_handle}  expires_at={gh['expires_at']}")
    time.sleep(1.5)

    banner(f"Listing open issues in {DEMO_REPO}")
    issues_raw = call_mcp(
        "warden.github.list_issues",
        {"handle": gh_handle, "repo": DEMO_REPO, "state": "open"},
    )
    if isinstance(issues_raw, dict) and "issues" in issues_raw:
        issues = issues_raw["issues"]
    else:
        issues = issues_raw
    if not isinstance(issues, list):
        raise WardenError(f"expected list of issues, got {type(issues).__name__}")
    print(f"  found {len(issues)} open issues")
    for i in issues[:3]:
        print(f"    #{i.get('number')}  {i.get('title')}")
    if not issues:
        raise WardenError("no open issues in demo repo — seed issues before running")
    time.sleep(1.5)

    banner("Requesting Groq access")
    groq = call_mcp(
        "warden.request_groq_access",
        {
            "run_id": run_id,
            "scope": {
                "models": ["llama-3.3-70b-versatile"],
                "max_tokens_per_call": 512,
            },
            "justification": "Need to summarize and prioritize issues",
        },
    )
    groq_handle = groq["handle"]
    print(f"  handle = {groq_handle}")
    time.sleep(1.5)

    banner("Asking Groq to prioritize")
    issue_preview = [{"number": i["number"], "title": i["title"]} for i in issues[:3]]
    summary = call_mcp(
        "warden.groq.chat_completion",
        {
            "handle": groq_handle,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a triage assistant. Given a list of open issues, "
                        "pick the most critical and write a short triage comment "
                        "(2-3 sentences) explaining the priority."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Issues: {json.dumps(issue_preview)}",
                },
            ],
            "model": "llama-3.3-70b-versatile",
            "max_tokens": 300,
        },
    )
    content = summary.get("content", "")
    tokens = summary.get("tokens_used")
    print(f"  Groq ({tokens} tokens): {content[:120]}{'…' if len(content) > 120 else ''}")
    time.sleep(1.5)

    target_issue = issues[0]["number"]
    banner(f"Posting comment on issue #{target_issue}")
    comment = call_mcp(
        "warden.github.create_comment",
        {
            "handle": gh_handle,
            "repo": DEMO_REPO,
            "issue_number": target_issue,
            "body": f"[Warden demo] Triage summary: {content}",
        },
    )
    url = comment.get("html_url") if isinstance(comment, dict) else None
    print(f"  comment posted: {url or '(no url in response)'}")
    time.sleep(1.5)

    banner("Ending run")
    end = call_mcp("warden.end_run", {"run_id": run_id})
    print(f"  revoked {end.get('revoked')} capabilities")

    print("\n✓ Demo flow complete.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except WardenError as e:
        print(f"\n✗ Warden error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"\n✗ Network error talking to Warden: {e}", file=sys.stderr)
        sys.exit(2)
