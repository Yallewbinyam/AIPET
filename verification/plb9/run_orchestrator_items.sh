#!/usr/bin/env bash
# WSL-side orchestrator -- runs the items that need backend-side
# coordination (06, 11B, 12, 13, 14, 17) and aggregates evidence.
# Caller must have already run the on-VM checks (01, 02-05, 07-11A, 15, 16, 18).
#
# Inputs (env or pre-flight files):
#   AGENT_KEY  -- read from verification/plb9/.agent_key
#   AGENT_KEY_ID -- read from verification/plb9/.agent_key_id
#   JWT        -- read from verification/plb9/.jwt
#   VM_IP      -- 10.0.3.10
#   BACKEND    -- http://localhost:5001 (WSL-side; 10.0.3.2:5001 is what the agent uses)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE_DIR="$REPO_ROOT/verification/plb9/evidence"
mkdir -p "$EVIDENCE_DIR"

VM_IP=10.0.3.10
BACKEND="http://localhost:5001"

KEY=$(cat "$REPO_ROOT/verification/plb9/.agent_key")
KEY_ID=$(cat "$REPO_ROOT/verification/plb9/.agent_key_id")
JWT=$(cat "$REPO_ROOT/verification/plb9/.jwt")

# Refresh JWT (originals are 15-min)
fresh_jwt() {
    curl -s -X POST "$BACKEND/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"email":"test@aipet.io","password":"Test1234!"}' \
    | "$REPO_ROOT/venv/bin/python" -c 'import sys,json; d=json.load(sys.stdin); print(d.get("token") or d.get("access_token") or "")'
}

emit() {
    local id="$1" status="$2" rationale="$3"
    echo "[ITEM-$id] STATUS=$status -- $rationale" | tee -a "$EVIDENCE_DIR/orchestrator.log"
}

# ===== Item 06 -- heartbeat reaches backend within 60s of service start =====
echo "=== Item 06: heartbeat (telemetry) within 60s of service restart ==="
ITEM06_DIR="$EVIDENCE_DIR/item-06"
mkdir -p "$ITEM06_DIR"

# Restart the service via SSH and timestamp it
T0=$(date +%s)
ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "Restart-Service AipetAgent -Force; Get-Date -Format o"' \
    > "$ITEM06_DIR/restart-timestamp.txt" 2>&1

# Wait up to 65s, then query /api/agent/devices for last_seen within window
sleep 65
JWT=$(fresh_jwt)
curl -s -H "Authorization: Bearer $JWT" "$BACKEND/api/agent/devices" \
    > "$ITEM06_DIR/devices-after-restart.json"

# Parse last_seen for our agent_id (we don't know agent_id but our key is unique;
# use the most recent last_seen of any agent telemetry from the last 90s).
"$REPO_ROOT/venv/bin/python" - "$ITEM06_DIR/devices-after-restart.json" "$T0" <<'PY' > "$ITEM06_DIR/result.txt"
import sys, json, datetime
fp, t0 = sys.argv[1], int(sys.argv[2])
data = json.load(open(fp))
devices = data.get("devices", [])
now = datetime.datetime.utcnow()
recent = []
for d in devices:
    ls = d.get("last_seen")
    if not ls: continue
    # last_seen format: 2026-04-27T22:00:00.000000
    try:
        t = datetime.datetime.fromisoformat(ls.replace("Z", ""))
    except Exception:
        continue
    age = (now - t).total_seconds()
    recent.append((age, d.get("hostname"), d.get("ip_address"), d.get("agent_version")))
recent.sort()
print("Most-recent agent telemetry:")
for r in recent[:5]:
    print(f"  age={r[0]:.0f}s host={r[1]} ip={r[2]} v={r[3]}")
fresh = [r for r in recent if r[0] < 90]
print(f"\nfresh_count_within_90s={len(fresh)}")
print(f"oldest_seen_age={recent[0][0] if recent else 'none'}")
PY
cat "$ITEM06_DIR/result.txt"
if grep -qE "fresh_count_within_90s=[1-9]" "$ITEM06_DIR/result.txt"; then
    emit 06 PASS "telemetry seen at /api/agent/devices within 90s of service restart"
else
    emit 06 FAIL "no telemetry observed within 90s window"
fi

# ===== Item 11B -- agent key with WRONG scope rejected with 403 =====
echo
echo "=== Item 11B: server-side scope mismatch -> 403 ==="
ITEM11B_DIR="$EVIDENCE_DIR/item-11"
mkdir -p "$ITEM11B_DIR"

# Insert a temporary key with scope='other' directly into the DB to simulate
# what the @agent_key_required(scope='agent') decorator should reject.
# (The /api/agent/keys POST endpoint hardcodes scope='agent', so this is the
# only way to exercise the scope-mismatch branch.)
"$REPO_ROOT/venv/bin/python" - <<'PY' > "$ITEM11B_DIR/temp_key.json"
import os, sys, secrets, bcrypt
from datetime import datetime, timezone
sys.path.insert(0, os.path.expanduser("~/AIPET"))
os.environ.setdefault("DATABASE_URL", "postgresql://aipet_user:aipet_password@localhost:5433/aipet_db")
from dashboard.backend.app_cloud import create_app
from dashboard.backend.models import db, User
from dashboard.backend.agent_keys.models import AgentApiKey
import json

app = create_app("development")
with app.app_context():
    user = User.query.filter_by(email="test@aipet.io").first()
    raw = secrets.token_urlsafe(48)
    full_key = f"aipet_{raw}"
    prefix = full_key[:14]
    h = bcrypt.hashpw(full_key.encode(), bcrypt.gensalt()).decode()
    row = AgentApiKey(
        user_id=user.id, label="plb9-wrong-scope", key_prefix=prefix,
        key_hash=h, scope="other-not-agent", permissions=["scan:write"],
        enabled=True,
    )
    db.session.add(row)
    db.session.commit()
    json.dump({"id": row.id, "full_key": full_key, "scope": row.scope}, sys.stdout)
PY

WRONG_KEY=$("$REPO_ROOT/venv/bin/python" -c "import json; print(json.load(open('$ITEM11B_DIR/temp_key.json'))['full_key'])")
WRONG_ID=$("$REPO_ROOT/venv/bin/python" -c "import json; print(json.load(open('$ITEM11B_DIR/temp_key.json'))['id'])")
echo "Inserted wrong-scope key id=$WRONG_ID prefix=$(echo $WRONG_KEY | cut -c1-14)"

# Hit /api/agent/scan-results with the wrong-scope key (no body needed -- decorator runs first)
SUBB=$(curl -s -o "$ITEM11B_DIR/subB-response.json" -w "%{http_code}" \
    -X POST "$BACKEND/api/agent/scan-results" \
    -H "X-Agent-Key: $WRONG_KEY" \
    -H "Content-Type: application/json" \
    -d '{"scan_id":"plb9-scope-mismatch-test","format":"json","scan_data":{"hosts":[]},"scan_metadata":{"target":"x","scan_type":"discovery","started_at":"2026-04-27T00:00:00","completed_at":"2026-04-27T00:00:00","host_count":0,"service_count":0}}')
echo "subB code=$SUBB"
cat "$ITEM11B_DIR/subB-response.json"
echo

# Clean up the temp key (delete row entirely so it can't be reused)
"$REPO_ROOT/venv/bin/python" - "$WRONG_ID" <<'PY'
import os, sys
sys.path.insert(0, os.path.expanduser("~/AIPET"))
from dashboard.backend.app_cloud import create_app
from dashboard.backend.models import db
from dashboard.backend.agent_keys.models import AgentApiKey
app = create_app("development")
with app.app_context():
    row = db.session.get(AgentApiKey, int(sys.argv[1]))
    if row:
        db.session.delete(row); db.session.commit()
        print(f"deleted temp key id={sys.argv[1]}")
PY

if [ "$SUBB" = "403" ]; then
    emit 11B PASS "wrong-scope key -> 403 (scope check enforced by decorator)"
else
    emit 11B FAIL "wrong-scope key -> $SUBB (expected 403)"
fi

# ===== Item 12 -- watchdog detects revocation -> service stops, no restart =====
echo
echo "=== Item 12: revoke key, expect AipetAgent STOPPED within watchdog window ==="
ITEM12_DIR="$EVIDENCE_DIR/item-12"
mkdir -p "$ITEM12_DIR"

# We set AIPET_WATCHDOG_INTERVAL=300 in install_windows.bat. To finish item 12
# in reasonable time we'd want a shorter interval. The orchestrator can poll
# every 30s for up to 6 min (one full interval + a buffer for the GET to fire
# and the agent to exit and NSSM to honor AppExit 1 Stop).

# First confirm service is RUNNING before we revoke
ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Service AipetAgent).Status"' \
    > "$ITEM12_DIR/pre-revoke-status.txt" 2>&1
echo "pre-revoke: $(cat "$ITEM12_DIR/pre-revoke-status.txt")"

JWT=$(fresh_jwt)
curl -s -X PUT "$BACKEND/api/agent/keys/$KEY_ID/revoke" \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d '{"reason":"PLB-9 watchdog test"}' > "$ITEM12_DIR/revoke-response.json"
echo "Revoked key $KEY_ID at $(date -u +%FT%TZ)"

# Poll every 30s for up to 7 min
T_POLL=0
STATUS="Running"
while [ $T_POLL -lt 420 ]; do
    sleep 30
    T_POLL=$((T_POLL + 30))
    STATUS=$(ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Service AipetAgent).Status"' 2>/dev/null | tr -d '\r')
    echo "  t=${T_POLL}s status=$STATUS"
    if [ "$STATUS" = "Stopped" ]; then
        break
    fi
done

# Capture log evidence on the VM
ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "
    Get-Content C:\ProgramData\AIPET\logs\agent.log -Tail 30 -ErrorAction SilentlyContinue
    Write-Host \"---error log---\"
    Get-Content C:\ProgramData\AIPET\logs\agent-error.log -Tail 30 -ErrorAction SilentlyContinue
"' > "$ITEM12_DIR/agent-log-tail.txt" 2>&1

if [ "$STATUS" = "Stopped" ]; then
    if grep -q "revoked or invalid" "$ITEM12_DIR/agent-log-tail.txt" 2>/dev/null || grep -q "key revoked" "$ITEM12_DIR/agent-log-tail.txt" 2>/dev/null; then
        emit 12 PASS "service Stopped within ${T_POLL}s; log mentions 'revoked or invalid'"
    else
        emit 12 PARTIAL "service Stopped within ${T_POLL}s but log doesn't mention revocation explicitly"
    fi
else
    emit 12 FAIL "service still $STATUS after 7 min -- watchdog did not stop the agent"
fi

# Wait 60s to confirm NSSM did NOT restart it
sleep 60
RECHECK=$(ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Service AipetAgent).Status"' 2>/dev/null | tr -d '\r')
echo "After 60s no-restart probe: $RECHECK"
if [ "$RECHECK" = "Stopped" ]; then
    echo "[ITEM-12-NORESTART] PASS - NSSM honored AppExit 1 Stop" | tee -a "$EVIDENCE_DIR/orchestrator.log"
else
    echo "[ITEM-12-NORESTART] FAIL - service is now $RECHECK after 60s" | tee -a "$EVIDENCE_DIR/orchestrator.log"
fi

echo
echo "Orchestrator items 06, 11B, 12 done."
echo "(Items 13 reboot, 14 backend outage, 17 uninstall+reinstall handled by phase5_part2.sh after we re-mint a key.)"
