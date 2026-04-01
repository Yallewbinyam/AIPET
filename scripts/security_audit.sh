#!/bin/bash
# =============================================================
# AIPET Cloud — Security Audit Script
# Runs all security checks in one command.
# Usage: bash scripts/security_audit.sh
# =============================================================

BASE_URL="http://localhost:5001"
PASS=0
FAIL=0

# Colours
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No colour

echo ""
echo "============================================================"
echo "  AIPET Cloud — Security Audit"
echo "  $(date)"
echo "============================================================"
echo ""

# ── Helper functions ──────────────────────────────────────────

pass() { echo -e "${GREEN}  [PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}  [FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}  [INFO]${NC} $1"; }

# ── Check Flask is running ────────────────────────────────────

echo "── Server Status ─────────────────────────────────────────"
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/api/health)
if [ "$HEALTH" = "200" ]; then
    pass "Flask server is running"
else
    fail "Flask server is not running (HTTP $HEALTH)"
    echo "Start Flask first: python dashboard/backend/app_cloud.py"
    exit 1
fi

# ── Security Headers ──────────────────────────────────────────

echo ""
echo "── Security Headers ──────────────────────────────────────"

HEADERS=$(curl -sI $BASE_URL/api/health)

check_header() {
    if echo "$HEADERS" | grep -qi "$1"; then
        pass "$1 header present"
    else
        fail "$1 header missing"
    fi
}

check_header "X-Frame-Options"
check_header "X-Content-Type-Options"
check_header "X-XSS-Protection"
check_header "Content-Security-Policy"
check_header "Referrer-Policy"
check_header "Permissions-Policy"

# Check server header is hidden
if echo "$HEADERS" | grep -qi "Server: AIPET"; then
    pass "Server header masked as AIPET"
else
    fail "Server header exposes software version"
fi

# ── Authentication Security ───────────────────────────────────

echo ""
echo "── Authentication Security ───────────────────────────────"

# Test brute force protection
info "Testing brute force protection (5 attempts)..."
for i in {1..5}; do
    curl -s -X POST $BASE_URL/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email": "audit_test@aipet.io", "password": "wrongpass"}' \
        > /dev/null
done

LOCKOUT=$(curl -s -X POST $BASE_URL/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "audit_test@aipet.io", "password": "wrongpass"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('locked' if '429' in str(d) or 'locked' in str(d).lower() else 'open')" 2>/dev/null)

if [ "$LOCKOUT" = "locked" ]; then
    pass "Brute force protection working"
else
    fail "Brute force protection not working"
fi

# Test unauthenticated access is blocked
UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/api/summary)
if [ "$UNAUTH" = "401" ] || [ "$UNAUTH" = "422" ]; then
    pass "Protected endpoints require authentication"
else
    fail "Protected endpoint accessible without authentication (HTTP $UNAUTH)"
fi

# ── Input Validation ──────────────────────────────────────────

echo ""
echo "── Input Validation ──────────────────────────────────────"

# Get a valid token
TOKEN=$(curl -s -X POST $BASE_URL/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "test@aipet.io", "password": "Test1234!"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    # Test invalid mode rejection
    INVALID=$(curl -s -X POST $BASE_URL/api/scan/start \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"mode": "invalid"}' \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print('rejected' if 'error' in d else 'accepted')" 2>/dev/null)

    if [ "$INVALID" = "rejected" ]; then
        pass "Invalid scan mode rejected"
    else
        fail "Invalid scan mode accepted"
    fi

    # Test sensitive data not exposed
    SENSITIVE=$(curl -s $BASE_URL/api/auth/me \
        -H "Authorization: Bearer $TOKEN" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print('exposed' if 'password' in str(d) or 'stripe_customer_id' in str(d) else 'safe')" 2>/dev/null)

    if [ "$SENSITIVE" = "safe" ]; then
        pass "No sensitive data exposed in user endpoint"
    else
        fail "Sensitive data exposed in user endpoint"
    fi
else
    fail "Could not get auth token for testing"
fi

# ── Dependency Audit ──────────────────────────────────────────

echo ""
echo "── Dependency Audit ──────────────────────────────────────"

VULNS=$(pip-audit --format=json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    count = len(data.get('vulnerabilities', []))
    print(count)
except:
    print('error')
")

if [ "$VULNS" = "0" ]; then
    pass "No Python dependency vulnerabilities"
elif [ "$VULNS" = "error" ]; then
    info "pip-audit not available — run: pip install pip-audit"
else
    fail "$VULNS Python dependency vulnerabilities found — run: pip-audit"
fi

# ── Summary ───────────────────────────────────────────────────

echo ""
echo "============================================================"
echo -e "  Results: ${GREEN}$PASS passed${NC} | ${RED}$FAIL failed${NC}"
echo "============================================================"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  All security checks passed!${NC}"
else
    echo -e "${RED}  $FAIL check(s) failed — review and fix before deployment${NC}"
fi
echo ""