#!/usr/bin/env bash
# AIPET X Agent — single-command installer
# Usage in production:  curl -sSL https://aipet.io/install | sudo bash
# For local testing:    sudo AIPET_DEB_URL=file:///path/to/aipet-agent_1.0.0_all.deb \
#                            AIPET_API_URL=http://localhost:5001 \
#                            bash install.sh
#
# Designed for non-technical IT staff. Asks 3 questions max.
# Self-tests the install. Plain-English errors only — no Python tracebacks.
set -e
set -o pipefail

DEB_URL="${AIPET_DEB_URL:-https://aipet.io/dl/aipet-agent_latest.deb}"
API_URL="${AIPET_API_URL:-https://api.aipet.io}"

# Colours, gracefully disabled when stdout is not a TTY
if [ -t 1 ]; then
    GREEN=$(printf '\033[0;32m'); YELLOW=$(printf '\033[1;33m'); RED=$(printf '\033[0;31m')
    BLUE=$(printf '\033[0;34m');  NC=$(printf '\033[0m')
else
    GREEN=""; YELLOW=""; RED=""; BLUE=""; NC=""
fi

print_step()    { printf "%s[*]%s %s\n" "$BLUE"   "$NC" "$1"; }
print_success() { printf "%s[✓]%s %s\n" "$GREEN"  "$NC" "$1"; }
print_warning() { printf "%s[!]%s %s\n" "$YELLOW" "$NC" "$1"; }
print_error()   { printf "%s[✗]%s %s\n" "$RED"    "$NC" "$1" >&2; }

print_header() {
    cat <<HDR

${BLUE}════════════════════════════════════════════════════${NC}
${BLUE}  AIPET X Agent — Installation${NC}
${BLUE}════════════════════════════════════════════════════${NC}

This will install the AIPET X security agent on this machine.
It will scan your local network for IoT devices and report
findings to your AIPET X dashboard.

  Required: sudo access, internet connection
  Time:     about 2 minutes

HDR
}

# ── 1. Sanity checks ─────────────────────────────────────
check_prerequisites() {
    print_step "Checking prerequisites..."

    if [ "$(id -u)" -ne 0 ]; then
        print_error "Please run with sudo:  curl -sSL https://aipet.io/install | sudo bash"
        exit 1
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        print_error "This installer supports Debian/Ubuntu only."
        print_error "Detected: $(uname -a)"
        print_error "For other systems see: https://docs.aipet.io/agent/install"
        exit 1
    fi

    # Try to reach the API host. Skip ping for file:// dev installs because
    # there's nothing remote to ping anyway.
    if [[ "$DEB_URL" != file://* ]]; then
        local host
        host=$(printf '%s' "$API_URL" | sed -E 's|^https?://||; s|/.*||')
        if ! getent hosts "$host" >/dev/null 2>&1; then
            print_error "Cannot resolve $host. Check your internet connection."
            exit 1
        fi
    fi

    print_success "Prerequisites OK"
}

# ── 2. Ask 3 questions ────────────────────────────────────
ask_questions() {
    echo ""
    echo "${BLUE}━━━ Configuration ━━━${NC}"
    echo ""
    echo "I need 3 things to set up your agent:"
    echo ""

    # Q1 — API key
    echo "1. Your AIPET X agent API key"
    echo "   (Get one from: https://app.aipet.io/settings/agents)"
    echo "   Format: aipet_<random>"
    echo ""
    while :; do
        printf "   API Key: "
        read -r AGENT_KEY
        if printf '%s' "$AGENT_KEY" | grep -Eq '^aipet_[A-Za-z0-9_-]{20,}$'; then
            break
        fi
        print_warning "That doesn't look like a valid AIPET key. It must start with 'aipet_'. Try again."
    done
    echo ""

    # Q2 — label
    echo "2. A label for this agent (e.g. 'Server Room A')"
    echo ""
    DEFAULT_LABEL="$(hostname)"
    printf "   Label [%s]: " "$DEFAULT_LABEL"
    read -r AGENT_LABEL
    AGENT_LABEL="${AGENT_LABEL:-$DEFAULT_LABEL}"
    echo ""

    # Q3 — scan target
    echo "3. What network should this agent scan?"
    echo "   Examples: 192.168.1.0/24, 10.0.0.0/16, auto (detect local subnet)"
    echo ""
    printf "   Network [auto]: "
    read -r SCAN_TARGET
    SCAN_TARGET="${SCAN_TARGET:-auto}"

    if [ "$SCAN_TARGET" = "auto" ]; then
        SCAN_TARGET=$(ip -o -f inet addr show 2>/dev/null | awk '/scope global/ {print $4; exit}')
        if [ -z "$SCAN_TARGET" ]; then
            print_error "Could not auto-detect a local subnet. Re-run and enter a CIDR (e.g. 192.168.1.0/24)."
            exit 1
        fi
        print_success "Auto-detected: $SCAN_TARGET"
    elif ! printf '%s' "$SCAN_TARGET" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
        print_error "That doesn't look like a CIDR or IP. Examples: 192.168.1.0/24, 10.0.0.5"
        exit 1
    fi
    echo ""
}

# ── 3. Install package ────────────────────────────────────
install_deb() {
    print_step "Downloading installer package..."
    local tmp_deb="/tmp/aipet-agent.deb"

    if [[ "$DEB_URL" == file://* ]]; then
        local src="${DEB_URL#file://}"
        if [ ! -f "$src" ]; then
            print_error "Local .deb not found at $src"
            exit 1
        fi
        cp "$src" "$tmp_deb"
    else
        if ! wget -q -O "$tmp_deb" "$DEB_URL"; then
            print_error "Could not download installer from $DEB_URL"
            print_error "Check your internet connection or try again."
            exit 1
        fi
    fi

    print_step "Installing AIPET agent package (this may take 30–60 seconds)..."
    # apt-get pulls dependencies; dpkg -i alone can leave them missing.
    if ! apt-get install -y "$tmp_deb" >/tmp/aipet-install.log 2>&1; then
        print_error "Package installation failed. Last 20 lines of the log:"
        tail -20 /tmp/aipet-install.log >&2
        print_error "Full log: /tmp/aipet-install.log"
        exit 1
    fi

    rm -f "$tmp_deb"
    print_success "Package installed"
}

# ── 4. Configure agent ────────────────────────────────────
configure_agent() {
    print_step "Writing configuration..."
    local conf=/etc/aipet-agent/agent.conf
    umask 077
    cat > "$conf" <<EOF
# AIPET X Agent Configuration
# Generated by installer on $(date -u +%Y-%m-%dT%H:%M:%SZ)
AIPET_API=$API_URL
AIPET_AGENT_KEY=$AGENT_KEY
AIPET_AGENT_LABEL=$AGENT_LABEL
AIPET_SCAN_TARGET=$SCAN_TARGET
AIPET_SCAN_INTERVAL_HOURS=24
AIPET_INTERVAL=60
AIPET_WATCHDOG_INTERVAL=300
AIPET_LOG_LEVEL=INFO
EOF
    chmod 640 "$conf"
    chown root:aipet-agent "$conf"
    print_success "Configuration saved (key hidden — file: $conf, mode 640)"
}

# ── 5. Start service ──────────────────────────────────────
start_service() {
    print_step "Starting agent service..."
    systemctl daemon-reload
    systemctl enable aipet-agent.service >/dev/null 2>&1
    systemctl restart aipet-agent.service
    sleep 3

    if systemctl is-active --quiet aipet-agent.service; then
        print_success "Service started and enabled (will start on boot)"
    else
        print_error "Service failed to start. Recent logs:"
        journalctl -u aipet-agent -n 20 --no-pager 2>/dev/null || true
        exit 1
    fi
}

# ── 6. Self-test ──────────────────────────────────────────
self_test() {
    echo ""
    echo "${BLUE}━━━ Self-Test ━━━${NC}"
    echo ""

    print_step "Verifying connection to AIPET cloud ($API_URL)..."
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -H "X-Agent-Key: $AGENT_KEY" \
        "$API_URL/api/agent/keys/me" 2>/dev/null || echo "000")
    case "$code" in
        200)  print_success "Connected — agent key is valid" ;;
        401)  print_error  "Agent key is invalid or revoked. Generate a new one in the dashboard."; exit 1 ;;
        000)  print_error  "Could not reach $API_URL — check your network."; exit 1 ;;
        *)    print_error  "Unexpected response from cloud (HTTP $code)."; exit 1 ;;
    esac

    print_step "Submitting test scan..."
    if [ -f /var/log/aipet-agent/agent.log ] && [ -s /var/log/aipet-agent/agent.log ]; then
        print_success "Agent is logging activity"
    else
        print_warning "Agent log empty yet — give it a minute, then check /var/log/aipet-agent/agent.log"
    fi

    print_step "Verifying agent registered with cloud..."
    sleep 3
    if curl -sSf --max-time 10 \
        -H "X-Agent-Key: $AGENT_KEY" \
        "$API_URL/api/agent/keys/me" 2>/dev/null | grep -q '"enabled": *true'; then
        print_success "Agent registered and key valid"
    else
        print_warning "Could not verify registration — check the dashboard."
    fi
}

# ── 7. Final message ──────────────────────────────────────
print_done() {
    cat <<DONE

${GREEN}════════════════════════════════════════════════════${NC}
${GREEN}  ✓ AIPET X Agent installed successfully${NC}
${GREEN}════════════════════════════════════════════════════${NC}

What happens now:
  • Agent will scan ${SCAN_TARGET} every 24 hours
  • Results appear in your AIPET X dashboard
  • Service runs automatically on boot

Useful commands:
  Status:     sudo systemctl status aipet-agent
  Logs:       sudo journalctl -u aipet-agent -f
  Restart:    sudo systemctl restart aipet-agent
  Re-run setup: sudo aipet-agent setup
  Uninstall:  sudo apt-get remove --purge aipet-agent

Documentation: https://docs.aipet.io/agent

DONE
}

# ── Main flow ─────────────────────────────────────────────
print_header
check_prerequisites
ask_questions
install_deb
configure_agent
start_service
self_test
print_done
