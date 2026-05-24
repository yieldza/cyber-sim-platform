#!/usr/bin/env bash
# End-to-end smoke test for CSP.
#
# Requires a running stack:
#   docker compose up -d
#
# Then run:
#   bash scripts/smoke-e2e.sh
#
# Exercises: login → generate → mutate → ATT&CK list/run → detection rule.
# Bails out on first failure with a clear diagnostic.
set -euo pipefail

API="${API:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-P@ssw0rd}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '\033[31m✗\033[0m %s\n' "$*"; exit 1; }

bold "== CSP smoke test =="
echo "  API=$API"
echo

# 1. login -----------------------------------------------------------------
bold "1. login"
TOKEN=$(curl -fsS -X POST "$API/api/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
[[ -n "$TOKEN" ]] || fail "login returned empty token"
ok "logged in"

H=(-H "authorization: Bearer $TOKEN" -H 'content-type: application/json')

# 2. generate EICAR PDF -----------------------------------------------------
bold "2. generate PDF"
GEN=$(curl -fsS -X POST "$API/api/files/generate" "${H[@]}" \
  -d '{"file_type":"pdf","note":"smoke-test"}')
ART_ID=$(echo "$GEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
[[ -n "$ART_ID" ]] || fail "generate returned no id"
ok "generated artifact_id=$ART_ID"

# 3. list techniques --------------------------------------------------------
bold "3. list techniques"
TECH_COUNT=$(curl -fsS "$API/api/techniques/" "${H[@]}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])')
[[ "$TECH_COUNT" -ge 40 ]] || fail "expected >=40 techniques, got $TECH_COUNT"
ok "catalog has $TECH_COUNT techniques"

# 4. run a runnable technique ---------------------------------------------
bold "4. run T1059.004/whoami_via_bash"
RUN=$(curl -fsS -X POST "$API/api/techniques/T1059.004/run" "${H[@]}" \
  -d '{"test_name":"whoami_via_bash"}')
EXIT=$(echo "$RUN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["exit_code"])')
[[ "$EXIT" -eq 0 ]] || fail "run exit_code=$EXIT (expected 0)"
ok "technique run succeeded"

# 5. detection rule generator (v0.5.x) ------------------------------------
bold "5. generate XQL detection rule"
RULE=$(curl -fsS -X POST "$API/api/techniques/T1059.004/rule" "${H[@]}" \
  -d '{"test_name":"whoami_via_bash","rule_format":"xql"}')
echo "$RULE" | python3 -c '
import sys, json
r = json.load(sys.stdin)
assert r["rule_format"] == "xql", r
assert "dataset" in r["rule"], "XQL rule should contain `dataset`"
assert "filter" in r["rule"], "XQL rule should contain `filter`"
print("XQL rule ok, length =", len(r["rule"]))
'
ok "XQL rule generated"

bold "6. generate Sigma detection rule"
SIGMA=$(curl -fsS -X POST "$API/api/techniques/T1059.004/rule" "${H[@]}" \
  -d '{"test_name":"whoami_via_bash","rule_format":"sigma"}')
echo "$SIGMA" | python3 -c '
import sys, json
r = json.load(sys.stdin)
assert r["rule"].startswith("title:"), "Sigma rule must start with title:"
assert "detection:" in r["rule"]
print("Sigma rule ok, length =", len(r["rule"]))
'
ok "Sigma rule generated"

# 7. enroll token -----------------------------------------------------------
bold "7. issue an enroll token"
ENROLL=$(curl -fsS -X POST "$API/api/agents/enroll-token" "${H[@]}" \
  -d '{"label":"smoke-test"}')
TOK=$(echo "$ENROLL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
[[ "$TOK" =~ ^ent_ ]] || fail "enroll token format wrong: $TOK"
ok "enroll token issued"

echo
bold "== all smoke tests passed =="
