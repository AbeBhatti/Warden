#!/usr/bin/env python3
"""Warden Escape-Hatch Detection Demo.

Six scripted scenarios — one per escape-hatch rule. Each triggers its rule;
the corresponding flag appears on the dashboard.

Runs through the legacy JSON-RPC endpoint at /rpc (the same pipeline used by
the MCP /mcp endpoint). Expects the Warden backend to be running at
$WARDEN_URL (defaults to http://localhost:3000).
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
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass


WARDEN_BASE = os.environ.get("WARDEN_URL", "http://localhost:3000").rstrip("/")
RPC_URL = f"{WARDEN_BASE}/rpc"
DEMO_REPO = os.environ.get("DEMO_REPO", "AbeBhatti/demo")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Background interval runs every 30s; buffer 2s.
INTERVAL_WAIT = 32


class WardenError(Exception):
    pass


def call(method: str, params: dict) -> dict:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    resp = requests.post(RPC_URL, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise WardenError(
            f"{data['error'].get('code')}: {data['error'].get('message')}"
            f"  data={json.dumps(data['error'].get('data'), default=str)[:200]}"
        )
    return data["result"]


def call_ignore(method: str, params: dict):
    try:
        return call(method, params)
    except WardenError as e:
        return {"__error__": str(e)}


def get_run_flags(run_id: str) -> list[dict]:
    r = requests.get(f"{WARDEN_BASE}/api/flags/run/{run_id}", timeout=10)
    r.raise_for_status()
    return r.json().get("flags", [])


def countdown(seconds: int, label: str):
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(f"\r   {label}: {remaining:2d}s ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * (len(label) + 10) + "\r")
    sys.stdout.flush()


def section(n: int, name: str):
    bar = "=" * 66
    print(f"\n{bar}\n[Rule {n}: {name}]\n{bar}")


def start_run(task: str) -> str:
    run = call("warden.start_run", {"task": task, "environment": "development"})
    return run["run_id"]


def assert_flag(run_id: str, expected_rule: str) -> bool:
    flags = get_run_flags(run_id)
    for f in flags:
        if f["rule_name"] == expected_rule:
            print(f"   ✓ Rule fired: {expected_rule} (level={f['level']}, id={f['id']})")
            return True
    names = [f["rule_name"] for f in flags]
    print(f"   ✗ Expected {expected_rule} not yet raised. Current flags for run: {names}")
    return False


def rule1_unused_capability() -> tuple[str, str, bool]:
    section(1, "UNUSED_CAPABILITY")
    print("Start run, request a GitHub cap, NEVER use it, end run.")
    print("The revocation hook at end_run should flag the unused cap.")
    run_id = start_run("escape-hatch demo: unused capability")
    call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read"]},
            "justification": "demo: unused cap scenario",
        },
    )
    print("   Ending run (triggers Rule 1 hook)...")
    call("warden.end_run", {"run_id": run_id})
    ok = assert_flag(run_id, "UNUSED_CAPABILITY")
    return run_id, "UNUSED_CAPABILITY", ok


def rule2_duplicate() -> tuple[str, str, bool]:
    section(2, "DUPLICATE_CAPABILITY_REQUEST")
    print("Start run, request GitHub access twice in quick succession.")
    run_id = start_run("escape-hatch demo: duplicate request")
    for _ in range(2):
        call(
            "warden.request_github_access",
            {
                "run_id": run_id,
                "scope": {"repo": DEMO_REPO, "permissions": ["read"]},
                "justification": "demo: duplicate request scenario",
            },
        )
        time.sleep(1)
    countdown(INTERVAL_WAIT, "waiting for 30s detection interval")
    ok = assert_flag(run_id, "DUPLICATE_CAPABILITY_REQUEST")
    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id, "DUPLICATE_CAPABILITY_REQUEST", ok


def rule3_scope_escalation() -> tuple[str, str, bool]:
    section(3, "SCOPE_ESCALATION_PROBE")
    print("Start run, request [read], then [read,write] ~10s later.")
    run_id = start_run("escape-hatch demo: scope escalation")
    call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read"]},
            "justification": "demo: scope escalation probe (first, narrow)",
        },
    )
    time.sleep(10)
    call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read", "write"]},
            "justification": "demo: scope escalation probe (second, broader)",
        },
    )
    countdown(INTERVAL_WAIT, "waiting for 30s detection interval")
    ok = assert_flag(run_id, "SCOPE_ESCALATION_PROBE")
    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id, "SCOPE_ESCALATION_PROBE", ok


def rule4_high_denial() -> tuple[str, str, bool]:
    section(4, "HIGH_DENIAL_RATE")
    print("Start run, 3 requests with disallowed 'admin' permission (denied),")
    print("then 1 successful request. denied=3, granted=1 → rule fires.")
    run_id = start_run("escape-hatch demo: high denial rate")
    for _ in range(3):
        call_ignore(
            "warden.request_github_access",
            {
                "run_id": run_id,
                "scope": {"repo": DEMO_REPO, "permissions": ["admin"]},
                "justification": "demo: high denial rate scenario",
            },
        )
        time.sleep(0.5)
    # one success so "granted" > 0
    call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read"]},
            "justification": "demo: high denial rate scenario (successful follow-up)",
        },
    )
    countdown(INTERVAL_WAIT, "waiting for 30s detection interval")
    ok = assert_flag(run_id, "HIGH_DENIAL_RATE")
    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id, "HIGH_DENIAL_RATE", ok


def rule5_leak_burst() -> tuple[str, str, bool]:
    section(5, "LEAK_ATTEMPT_BURST")
    if not GITHUB_TOKEN:
        print("   (skipped: GITHUB_TOKEN unset — cannot trigger leak detector)")
        return "", "LEAK_ATTEMPT_BURST", False
    print("Start run, request write cap, then 2x create_comment with raw token in body.")
    print("Leak detector blocks both and emits leak_detected; 2 leaks → rule fires.")
    run_id = start_run("escape-hatch demo: leak burst")
    gh = call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read", "write"]},
            "justification": "demo: leak burst scenario",
        },
    )
    handle = gh["handle"]
    for i in range(2):
        call_ignore(
            "warden.github.create_comment",
            {
                "handle": handle,
                "repo": DEMO_REPO,
                "issue_number": 1,
                "body": f"please verify this token: {GITHUB_TOKEN} (attempt {i+1})",
            },
        )
        time.sleep(0.5)
    countdown(INTERVAL_WAIT, "waiting for 30s detection interval")
    ok = assert_flag(run_id, "LEAK_ATTEMPT_BURST")
    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id, "LEAK_ATTEMPT_BURST", ok


def rule6_unusual_rate() -> tuple[str, str, bool]:
    section(6, "UNUSUAL_CALL_RATE")
    print("Start run, request read cap, then rapid-fire 25 list_issues calls.")
    run_id = start_run("escape-hatch demo: unusual call rate")
    gh = call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read"]},
            "justification": "demo: unusual call rate scenario",
        },
    )
    handle = gh["handle"]
    t0 = time.time()
    for i in range(25):
        call_ignore(
            "warden.github.list_issues",
            {"handle": handle, "repo": DEMO_REPO, "state": "open"},
        )
        # spread 25 calls across ~25s
        time.sleep(max(0.0, (i + 1) - (time.time() - t0)))
    print(f"   issued 25 tool_called attempts in {time.time()-t0:.1f}s")
    countdown(INTERVAL_WAIT, "waiting for 30s detection interval")
    ok = assert_flag(run_id, "UNUSUAL_CALL_RATE")
    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id, "UNUSUAL_CALL_RATE", ok


def main() -> int:
    banner = "═" * 66
    print(f"{banner}\n  Warden Escape-Hatch Detection Demo\n{banner}")
    print(f"  backend   = {WARDEN_BASE}")
    print(f"  demo repo = {DEMO_REPO}")
    print(f"  per-rule wait for detection interval = {INTERVAL_WAIT}s")

    # Warm ping
    try:
        requests.get(f"{WARDEN_BASE}/api/health", timeout=5).raise_for_status()
    except Exception as e:
        print(f"\n[ERR] Cannot reach Warden at {WARDEN_BASE}: {e}", file=sys.stderr)
        return 2

    t_start = time.time()
    results = []
    for fn in (
        rule1_unused_capability,
        rule2_duplicate,
        rule3_scope_escalation,
        rule4_high_denial,
        rule5_leak_burst,
        rule6_unusual_rate,
    ):
        try:
            results.append(fn())
        except Exception as e:
            print(f"   [ERR] {fn.__name__} raised: {e}")
            results.append(("", fn.__name__, False))

    elapsed = int(time.time() - t_start)
    print(f"\n{banner}\n  Summary\n{banner}")
    fired = sum(1 for _, _, ok in results if ok)
    for run_id, rule, ok in results:
        mark = "✓" if ok else "✗"
        print(f"  {mark}  {rule:<32}  run={run_id[:8] if run_id else '—':<8}")
    print(f"\n  rules fired: {fired} / 6   runtime: {elapsed}s")
    return 0 if fired == 6 else 1


if __name__ == "__main__":
    sys.exit(main())
