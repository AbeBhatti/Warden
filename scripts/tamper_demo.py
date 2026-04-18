#!/usr/bin/env python3
"""Warden audit-chain tamper-detection demo.

Verifies the chain, tampers with a recent non-critical event directly in
SQLite, re-verifies (chain must be detected broken), restores the original
value, and re-verifies (chain must be valid again).
"""
import os
import subprocess
import sys
import urllib.error
import urllib.request
import json

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "warden.db")
API_BASE = os.environ.get("WARDEN_API", "http://localhost:3000")


def banner(msg):
    print(f"\n{'=' * 60}\n{msg}\n{'=' * 60}")


def sqlite(query, *params):
    cmd = ["sqlite3", DB_PATH]
    if params:
        safe = query
        for p in params:
            safe = safe.replace("?", "'" + str(p).replace("'", "''") + "'", 1)
        cmd.append(safe)
    else:
        cmd.append(query)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"sqlite3 failed: {r.stderr.strip()}")
    return r.stdout.strip()


def http_get_json(path):
    req = urllib.request.Request(f"{API_BASE}{path}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def verify():
    return http_get_json("/api/audit/verify")


def main():
    banner("╔═══ Warden Audit Chain Tamper Detection ═══╗")

    # 1. Confirm chain is valid before we start.
    try:
        v = verify()
    except urllib.error.URLError as e:
        print(f"[ERR] Cannot reach backend at {API_BASE}: {e}")
        sys.exit(2)
    if not v.get("valid"):
        print(f"[ERR] Chain is ALREADY invalid — refusing to tamper further.")
        print(f"      break_at={v.get('break_at')} reason={v.get('break_reason')}")
        sys.exit(2)
    print(f"[✓] Chain currently valid. {v['events_verified']} events verified.")

    # 2. Pick a recent run_started event with a non-null event_hash.
    rows = sqlite(
        "SELECT id, detail FROM events "
        "WHERE event_type='run_started' AND event_hash IS NOT NULL "
        "ORDER BY id DESC LIMIT 5"
    )
    if not rows:
        print("[ERR] No chained run_started events to tamper with. "
              "Start a run first with the MCP server or demo agent.")
        sys.exit(2)

    candidates = []
    for line in rows.splitlines():
        if "|" in line:
            eid, detail = line.split("|", 1)
            candidates.append((int(eid), detail))

    # Prefer not the very latest — but if only one exists, use it.
    target_id, original_detail = candidates[1] if len(candidates) > 1 else candidates[0]

    print(f"[!] Tampering with event #{target_id}: "
          f"changing detail to 'TAMPERED BY DEMO SCRIPT'...")
    sqlite("UPDATE events SET detail='TAMPERED BY DEMO SCRIPT' WHERE id=?", target_id)

    # 3. Re-verify — must now be invalid.
    print("[?] Re-verifying chain...")
    v = verify()
    if v.get("valid"):
        print("[ERR] Chain reported valid after tampering — this is a bug.")
        # Restore anyway before exiting.
        sqlite("UPDATE events SET detail=? WHERE id=?", original_detail, target_id)
        sys.exit(3)
    print(f"[✓] Tamper detected! Break at event #{v['break_at']}, "
          f"reason: {v['break_reason']}")

    # 4. Restore original value.
    print("[~] Restoring original event value...")
    sqlite("UPDATE events SET detail=? WHERE id=?", original_detail, target_id)

    v = verify()
    if not v.get("valid"):
        print(f"[ERR] Chain still invalid after restore — "
              f"break_at={v.get('break_at')} reason={v.get('break_reason')}")
        sys.exit(4)
    print(f"[✓] Chain restored and valid. {v['events_verified']} events verified.")

    banner("╚═══ Demo complete ═══╝")


if __name__ == "__main__":
    main()
