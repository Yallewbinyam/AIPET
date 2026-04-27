#!/usr/bin/env bash
# Items 13 (reboot), 14 (backend outage resilience), 17 (uninstall+reinstall).
# Pre-condition: items 01..12 completed; key from item 12 is REVOKED so we
# need to mint a fresh key before items 13/14 (the agent needs a working key).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE_DIR="$REPO_ROOT/verification/plb9/evidence"
VM_IP=10.0.3.10
BACKEND="http://localhost:5001"

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

# Mint a fresh key (item 12 revoked the previous one)
JWT=$(fresh_jwt)
RESP=$(curl -s -X POST "$BACKEND/api/agent/keys" \
    -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
    -d '{"label":"plb9-verify-pt2"}')
NEW_KEY=$(echo "$RESP" | "$REPO_ROOT/venv/bin/python" -c 'import sys,json; print(json.load(sys.stdin).get("full_key",""))')
NEW_ID=$(echo "$RESP" | "$REPO_ROOT/venv/bin/python" -c 'import sys,json; print(json.load(sys.stdin).get("id",""))')
echo "New key id=$NEW_ID prefix=$(echo $NEW_KEY | cut -c1-14)"

# Update NSSM env var on VM and restart service so the watchdog comes back up
ssh aipet@$VM_IP "powershell -NoProfile -Command \"& 'C:\\Program Files\\AIPET\\nssm.exe' set AipetAgent AppEnvironmentExtra 'AIPET_API=http://10.0.3.2:5001' 'AIPET_AGENT_KEY=$NEW_KEY' 'AIPET_AGENT_LABEL=plb9-windows-verify' 'AIPET_SCAN_TARGET=auto' 'AIPET_SCAN_INTERVAL_HOURS=24' 'AIPET_INTERVAL=60' 'AIPET_WATCHDOG_INTERVAL=300' 'AIPET_LOG_LEVEL=INFO'; Start-Service AipetAgent; (Get-Service AipetAgent).Status\""

# ===== Item 13 -- reboot survival =====
echo
echo "=== Item 13: reboot survival ==="
ITEM13_DIR="$EVIDENCE_DIR/item-13"
mkdir -p "$ITEM13_DIR"

T_BEFORE=$(date -u +%FT%TZ)
echo "$T_BEFORE" > "$ITEM13_DIR/reboot-time.txt"
ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "shutdown /r /t 0 /f"' 2>&1 | tee -a "$ITEM13_DIR/shutdown.log"

# Poll SSH up to 6 min
echo "Waiting for VM to come back..."
T_DOWN=0
while [ $T_DOWN -lt 360 ]; do
    sleep 15
    T_DOWN=$((T_DOWN + 15))
    if ssh -o BatchMode=yes -o ConnectTimeout=5 aipet@$VM_IP 'whoami' >/dev/null 2>&1; then
        echo "  VM back at t=${T_DOWN}s"
        break
    fi
    echo "  ... still down at t=${T_DOWN}s"
done

if [ $T_DOWN -ge 360 ]; then
    emit 13 FAIL "VM did not come back within 6 min"
else
    # Wait up to 2 min for service to auto-start
    T_WAIT=0
    STATUS="Stopped"
    while [ $T_WAIT -lt 120 ]; do
        sleep 15
        T_WAIT=$((T_WAIT + 15))
        STATUS=$(ssh -o BatchMode=yes aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Service AipetAgent).Status"' 2>/dev/null | tr -d '\r')
        echo "  service status @${T_WAIT}s: $STATUS"
        if [ "$STATUS" = "Running" ]; then break; fi
    done
    ssh aipet@$VM_IP 'powershell -NoProfile -Command "
        Get-Service AipetAgent | Format-List Name, Status, StartType
        Get-WinEvent -FilterHashtable @{LogName=\"System\"; ID=6005,7036; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match \"Aipet\" -or $_.Id -eq 6005 } | Select-Object TimeCreated, Id, Message | Format-List
    "' > "$ITEM13_DIR/post-boot-state.txt" 2>&1

    if [ "$STATUS" = "Running" ]; then
        emit 13 PASS "VM back in ${T_DOWN}s; AipetAgent Running ${T_WAIT}s after boot"
    else
        emit 13 FAIL "service did not auto-start within 2 min of boot (status=$STATUS)"
    fi
fi

# ===== Item 14 -- backend outage resilience =====
echo
echo "=== Item 14: backend outage resilience ==="
ITEM14_DIR="$EVIDENCE_DIR/item-14"
mkdir -p "$ITEM14_DIR"

# Identify gunicorn master PID
GUNICORN_PID=$(cat "$REPO_ROOT/pids/gunicorn.pid" 2>/dev/null || echo "")
if [ -z "$GUNICORN_PID" ]; then
    GUNICORN_PID=$(pgrep -f 'gunicorn.*app_cloud' | head -1)
fi
echo "gunicorn master PID=$GUNICORN_PID"

# Snapshot agent log size before
SIZE_BEFORE=$(ssh aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Item C:\ProgramData\AIPET\logs\agent.log -ErrorAction SilentlyContinue).Length"' 2>/dev/null | tr -d '\r')
echo "log size before outage: $SIZE_BEFORE"

# Stop backend (TERM the master, gunicorn graceful-shutdowns workers)
T0=$(date -u +%FT%TZ)
echo "$T0 -- stopping gunicorn" >> "$ITEM14_DIR/timeline.txt"
kill -TERM "$GUNICORN_PID" 2>&1 || true
sleep 3
# Confirm port closed
ss -tlnp 2>/dev/null | grep ":5001" | head -3 > "$ITEM14_DIR/port-during-outage.txt"

# Wait 60s to see retries
echo "  outage sustained 60s..."
sleep 60

# Restart backend
echo "$(date -u +%FT%TZ) -- restarting gunicorn" >> "$ITEM14_DIR/timeline.txt"
cd "$REPO_ROOT" && nohup ./start_cloud.sh > "$ITEM14_DIR/restart-stdout.log" 2>&1 &
sleep 10

# Wait until backend responds
T_W=0
while [ $T_W -lt 60 ]; do
    if curl -s -o /dev/null --max-time 3 http://localhost:5001/api/ping; then
        echo "  backend up @t=${T_W}s after restart"
        break
    fi
    sleep 5
    T_W=$((T_W + 5))
done

# Pull agent log tail to see retry behaviour
sleep 30
ssh aipet@$VM_IP "powershell -NoProfile -Command \"Get-Content C:\\ProgramData\\AIPET\\logs\\agent.log -Tail 50\"" > "$ITEM14_DIR/agent-log-during-outage.txt" 2>&1
ssh aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Service AipetAgent).Status"' > "$ITEM14_DIR/service-status-after.txt" 2>&1

RETRY_COUNT=$(grep -cE 'Send failed|RequestException|warning|connection|refused|timed' "$ITEM14_DIR/agent-log-during-outage.txt" || echo 0)
SVC_STATUS=$(cat "$ITEM14_DIR/service-status-after.txt" | tr -d '\r')

if [ "$SVC_STATUS" = "Running" ] && [ "$RETRY_COUNT" -ge 3 ]; then
    emit 14 PARTIAL "agent stayed Running, observed $RETRY_COUNT retry/error log lines (flat retry, no exponential backoff -- documented as known)"
elif [ "$SVC_STATUS" = "Running" ]; then
    emit 14 PARTIAL "agent stayed Running but only $RETRY_COUNT retry events visible in log"
else
    emit 14 FAIL "agent service is $SVC_STATUS after outage"
fi

# ===== Item 17 -- uninstall + reinstall =====
echo
echo "=== Item 17: uninstall + reinstall ==="
ITEM17_DIR="$EVIDENCE_DIR/item-17"
mkdir -p "$ITEM17_DIR"

# Uninstall (skip the YES prompt by piping it)
ssh aipet@$VM_IP 'cmd /c "echo YES | \"C:\\Program Files\\AIPET\\uninstall_windows.bat\""' > "$ITEM17_DIR/uninstall.log" 2>&1

# Verify cleanup
ssh aipet@$VM_IP 'powershell -NoProfile -Command "
    @{
        service = (sc.exe query AipetAgent 2>&1) -join \"`n\"
        install_dir = (Test-Path \"C:\Program Files\AIPET\")
        data_dir = (Test-Path C:\ProgramData\AIPET)
        reg = (Test-Path \"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent\")
    } | ConvertTo-Json
"' > "$ITEM17_DIR/post-uninstall-state.json" 2>&1

UNINST_OK=$(grep -E '"install_dir":\s*false' "$ITEM17_DIR/post-uninstall-state.json" >/dev/null && \
            grep -E '"data_dir":\s*false' "$ITEM17_DIR/post-uninstall-state.json" >/dev/null && \
            grep -E '"reg":\s*false' "$ITEM17_DIR/post-uninstall-state.json" >/dev/null && echo yes || echo no)

# Reinstall: re-extract bundle (was deleted) then run installer
if [ "$UNINST_OK" = "yes" ]; then
    JWT=$(fresh_jwt)
    REINST_KEY_RESP=$(curl -s -X POST "$BACKEND/api/agent/keys" \
        -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
        -d '{"label":"plb9-reinstall-test"}')
    REINST_KEY=$(echo "$REINST_KEY_RESP" | "$REPO_ROOT/venv/bin/python" -c 'import sys,json; print(json.load(sys.stdin).get("full_key",""))')

    ssh aipet@$VM_IP "powershell -NoProfile -Command \"Remove-Item -Recurse -Force C:\\AIPET\\verify\\bundle -ErrorAction SilentlyContinue; Expand-Archive -Path C:\\AIPET\\verify\\aipet-agent-windows-1.0.0_all.zip -DestinationPath C:\\AIPET\\verify\\bundle -Force\"" 2>&1 | tail -3
    ssh aipet@$VM_IP "cmd /c \"C:\\AIPET\\verify\\run_install_proper.cmd $REINST_KEY plb9-reinstall auto\"" > "$ITEM17_DIR/reinstall.log" 2>&1
    REINST_STATUS=$(ssh aipet@$VM_IP 'powershell -NoProfile -Command "(Get-Service AipetAgent -ErrorAction SilentlyContinue).Status"' 2>/dev/null | tr -d '\r')
    if [ "$REINST_STATUS" = "Running" ]; then
        emit 17 PASS "uninstall removed all artefacts; reinstall succeeded; service Running"
    else
        emit 17 PARTIAL "uninstall clean but reinstall service status=$REINST_STATUS"
    fi
else
    emit 17 FAIL "uninstall left artefacts -- see post-uninstall-state.json"
fi
