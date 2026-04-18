#!/usr/bin/env python3
"""Warden GDPR DSAR Demo.

Simulates activity for three different data subjects (plus noise from
runs without any subject association). Then fires a DSAR for user_42 and
asserts the returned report contains only that subject's records.
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
DSAR_URL = f"{WARDEN_BASE}/api/dsar/subject"
DEMO_REPO = os.environ.get("DEMO_REPO", "AbeBhatti/demo")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")


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
        )
    return data["result"]


def call_ignore(method: str, params: dict):
    try:
        return call(method, params)
    except WardenError as e:
        return {"__error__": str(e)}


def simulate_gdpr_subject(subject_id: str, lawful_basis: str, tool_calls: int) -> str:
    """Run a GDPR-tagged session for the given subject."""
    print(f"  [subject={subject_id}] starting run, requesting GitHub (GDPR) access, "
          f"making {tool_calls} tool call(s)")
    run = call(
        "warden.start_run",
        {"task": f"process data for {subject_id}", "environment": "development"},
    )
    run_id = run["run_id"]

    gh = call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read", "write"]},
            "justification": f"GDPR-compliant access for subject {subject_id}",
            "compliance_tags": ["GDPR"],
            "compliance_justification": {
                "data_subject": subject_id,
                "lawful_basis": lawful_basis,
            },
        },
    )
    handle = gh["handle"]

    # Issue tool_calls. Alternate list_issues / create_comment (benign).
    for i in range(tool_calls):
        if i % 2 == 0:
            call_ignore(
                "warden.github.list_issues",
                {"handle": handle, "repo": DEMO_REPO, "state": "open"},
            )
        else:
            call_ignore(
                "warden.github.create_comment",
                {
                    "handle": handle,
                    "repo": DEMO_REPO,
                    "issue_number": 1,
                    "body": f"DSAR demo comment for {subject_id}",
                },
            )
        time.sleep(0.2)

    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id


def simulate_noise_run() -> str:
    """Run with no compliance framework / no data_subject (noise)."""
    run = call(
        "warden.start_run",
        {"task": "noise: unrelated GitHub list", "environment": "development"},
    )
    run_id = run["run_id"]
    gh = call(
        "warden.request_github_access",
        {
            "run_id": run_id,
            "scope": {"repo": DEMO_REPO, "permissions": ["read"]},
            "justification": "noise run — no compliance framework",
        },
    )
    handle = gh["handle"]
    call_ignore(
        "warden.github.list_issues",
        {"handle": handle, "repo": DEMO_REPO, "state": "open"},
    )
    call_ignore("warden.end_run", {"run_id": run_id})
    return run_id


def dsar(subject_id: str) -> dict:
    resp = requests.post(
        DSAR_URL,
        json={"subject_id": subject_id, "format": "markdown"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    banner = "═" * 66
    print(f"{banner}\n  Warden GDPR DSAR Demo\n{banner}")
    print(f"  backend   = {WARDEN_BASE}")
    print(f"  demo repo = {DEMO_REPO}")

    try:
        requests.get(f"{WARDEN_BASE}/api/health", timeout=5).raise_for_status()
    except Exception as e:
        print(f"\n[ERR] Cannot reach Warden at {WARDEN_BASE}: {e}", file=sys.stderr)
        return 2

    # ── simulate activity ────────────────────────────────────────
    print("\nSimulating multi-subject activity...")
    run_42 = simulate_gdpr_subject("user_42", "consent", tool_calls=2)
    run_108 = simulate_gdpr_subject("user_108", "legitimate_interest", tool_calls=3)
    run_99 = simulate_gdpr_subject("user_99", "contract_performance", tool_calls=1)
    noise_runs = [simulate_noise_run() for _ in range(2)]
    print(f"  runs: user_42={run_42[:8]} user_108={run_108[:8]} "
          f"user_99={run_99[:8]} noise={[r[:8] for r in noise_runs]}")

    print("\nData generated. Querying DSAR for user_42...")

    # ── DSAR for user_42 ─────────────────────────────────────────
    res = dsar("user_42")
    md = res.get("markdown", "")
    meta = res.get("metadata", {})
    caps_found = meta.get("capabilities_found", -1)
    events_found = meta.get("events_found", -1)
    flags_found = meta.get("flags_found", -1)
    chain_status = meta.get("chain_status", "")

    print("\n── DSAR metadata ────────────────────────────────────")
    print(f"  request_id         = {res.get('request_id')}")
    print(f"  subject_id         = {res.get('subject_id')}")
    print(f"  capabilities_found = {caps_found}")
    print(f"  events_found       = {events_found}")
    print(f"  flags_found        = {flags_found}")
    print(f"  chain_status       = {chain_status}")

    print("\n── DSAR markdown ────────────────────────────────────")
    print(md)

    # ── assertions ───────────────────────────────────────────────
    print("── assertions ───────────────────────────────────────")
    results: list[tuple[str, bool, str]] = []

    # At least the one cap this demo just granted for user_42 must be found.
    # (DB state from prior runs may have older user_42 caps too — DSAR
    # correctly surfaces ALL of them, which is what GDPR Article 15 demands.)
    results.append((
        "capabilities_found >= 1",
        caps_found >= 1,
        f"got {caps_found}",
    ))

    # events_found should include at least the 2 tool_called events for user_42
    # plus capability_granted (and possibly end-run-related). user_108 had 3
    # tool_calls, user_99 had 1; a leak in propagation would show user_108/
    # user_99 content in the markdown — asserted below.
    results.append((
        "events_found > 0",
        events_found > 0,
        f"got {events_found}",
    ))

    results.append((
        "chain_status == 'valid'",
        chain_status == "valid",
        f"got {chain_status!r}",
    ))

    results.append((
        "markdown contains 'user_42'",
        "user_42" in md,
        "user_42 absent from markdown",
    ))

    for other in ("user_108", "user_99"):
        results.append((
            f"markdown does NOT contain {other!r}",
            other not in md,
            f"{other} leaked into markdown",
        ))

    if GITHUB_TOKEN:
        results.append((
            "markdown does NOT contain raw GITHUB_TOKEN",
            GITHUB_TOKEN not in md,
            "raw GITHUB_TOKEN leaked into markdown",
        ))
    if GROQ_API_KEY:
        results.append((
            "markdown does NOT contain raw GROQ_API_KEY",
            GROQ_API_KEY not in md,
            "raw GROQ_API_KEY leaked into markdown",
        ))

    # Empty-subject DSAR
    empty = dsar("user_nonexistent")
    empty_meta = empty.get("metadata", {})
    results.append((
        "nonexistent subject: capabilities_found == 0",
        empty_meta.get("capabilities_found") == 0,
        f"got {empty_meta.get('capabilities_found')}",
    ))
    results.append((
        "nonexistent subject: events_found == 0",
        empty_meta.get("events_found") == 0,
        f"got {empty_meta.get('events_found')}",
    ))
    results.append((
        "nonexistent subject: markdown mentions 'no activity'",
        "no activity" in (empty.get("markdown", "").lower()),
        "'no activity' not found in empty DSAR markdown",
    ))

    passed = 0
    for name, ok, note in results:
        mark = "✓" if ok else "✗"
        print(f"  {mark}  {name}" + ("" if ok else f"  — {note}"))
        if ok:
            passed += 1

    print(f"\n  {passed} / {len(results)} assertions passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
