#!/usr/bin/env bash
# Warden verification smoke test.
# Usage: assumes backend running on localhost:3000, .env loaded with
# GITHUB_TOKEN and GROQ_API_KEY, warden.db present.
# Exits 0 on success, non-zero with a failure message on first failure.

set -e
set -o pipefail

# Load tokens to grep for
if [ ! -f .env ]; then
  echo "FAIL: .env missing"; exit 1
fi
# shellcheck disable=SC1091
source .env

PASS() { echo "  ✓ $1"; }
FAIL() { echo "  ✗ $1"; exit 1; }

echo ""
echo "Warden verification smoke test"
echo "------------------------------"

# 1. Backend health
echo ""
echo "[1/6] Backend health..."
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health || echo "000")
if [ "$HEALTH" = "200" ]; then PASS "Backend responds 200"; else FAIL "Health check returned $HEALTH"; fi

# 2. tools/list returns 7 tools
echo ""
echo "[2/6] MCP tools/list..."
TOOLS_COUNT=$(curl -s http://localhost:3000/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | grep -o '"name":"warden\.[^"]*"' | sort -u | wc -l | tr -d ' ')
if [ "$TOOLS_COUNT" = "7" ]; then PASS "tools/list returns 7 warden tools"; else FAIL "tools/list returned $TOOLS_COUNT tools (expected 7)"; fi

# 3. /rpc dispatcher works
echo ""
echo "[3/6] Legacy /rpc dispatcher..."
RPC_RESULT=$(curl -s http://localhost:3000/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"warden.start_run","params":{"task":"verify-smoke-test"}}')
if echo "$RPC_RESULT" | grep -q '"run_id"'; then PASS "/rpc start_run returned a run_id"; else FAIL "/rpc start_run failed: $RPC_RESULT"; fi

RUN_ID=$(echo "$RPC_RESULT" | grep -o '"run_id":"[^"]*"' | head -1 | cut -d'"' -f4)
END_RESULT=$(curl -s http://localhost:3000/rpc -X POST \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"warden.end_run\",\"params\":{\"run_id\":\"$RUN_ID\"}}")
if echo "$END_RESULT" | grep -q '"revoked"'; then PASS "/rpc end_run closed the run"; else FAIL "/rpc end_run failed: $END_RESULT"; fi

# 4. Zero raw tokens in events table
echo ""
echo "[4/6] Honesty check: no raw tokens in events..."
if [ -z "$GITHUB_TOKEN" ] || [ -z "$GROQ_API_KEY" ]; then
  FAIL ".env missing GITHUB_TOKEN or GROQ_API_KEY"
fi

if sqlite3 warden.db "SELECT * FROM events" | grep -qF "$GITHUB_TOKEN"; then
  FAIL "GITHUB_TOKEN found in events table — honesty violation"
fi
PASS "GITHUB_TOKEN not in events"

if sqlite3 warden.db "SELECT * FROM events" | grep -qF "$GROQ_API_KEY"; then
  FAIL "GROQ_API_KEY found in events table — honesty violation"
fi
PASS "GROQ_API_KEY not in events"

# 5. Credentials endpoint does not leak values
echo ""
echo "[5/6] /api/credentials does not leak values..."
CREDS=$(curl -s http://localhost:3000/api/credentials)
if echo "$CREDS" | grep -qF "$GITHUB_TOKEN"; then FAIL "/api/credentials leaked GITHUB_TOKEN"; fi
if echo "$CREDS" | grep -qF "$GROQ_API_KEY"; then FAIL "/api/credentials leaked GROQ_API_KEY"; fi
if echo "$CREDS" | grep -q '"value"'; then FAIL "/api/credentials exposes a value field"; fi
PASS "/api/credentials exposes only metadata"

# 6. Schema integrity
echo ""
echo "[6/6] Schema integrity..."
TABLES=$(sqlite3 warden.db ".tables" | tr -s ' ' '\n' | sort | tr '\n' ' ')
for T in capabilities credentials events policies runs; do
  if ! echo "$TABLES" | grep -qw "$T"; then FAIL "Missing table: $T"; fi
done
PASS "All 5 tables present"

echo ""
echo "✓ All checks passed"
exit 0
