# AIPET X — Session Handoff Document

**Purpose:** Paste this entire document as the first message of a new Claude.ai conversation. The fresh assistant reads this and is immediately calibrated to continue the work without needing to re-learn context.

**Last updated:** 2026-04-27 (after WSL2 migration + Capability 13 Day 1 ship)

---

## 1. Who you are talking to

**Binyam Yallew** — MSc Cyber Security student (Ethical Hacking specialization), Coventry University, 2024-2026.

**Building AIPET X** — an AI-powered IoT security SaaS platform. This is both his MSc dissertation project and a real commercial product targeting global launch at aipet.io.

**Personal context:** Strong entrepreneurial orientation. Treats AIPET X as a genuine commercial venture. Works long hours with focus. November 2026 dissertation deadline (real, fixed). Pushes back on caution when his energy is good — track record proves his judgment is reliable. Wants honest engineering, not flattery.

**How he works best:**
- Recon-first, build-second on every capability
- 10 + N specific acceptance items per capability shipped production-ready before next starts
- Honest reporting (which acceptance items are TRULY met, which are not)
- Prefers prompts pasted into Claude Code in WSL for actual building
- Uses Claude.ai (this chat) for strategy, recon writing, build-prompt writing, decisions

---

## 2. The platform — current state as of handoff

**AIPET X is functional production-grade IoT security platform with:**

| Capability | Status | What it does |
|---|---|---|
| 1 | ✅ | Isolation Forest + SHAP anomaly detection |
| 2 | ✅ | Per-device behavioural baseline (Z-score, 8h half-life) |
| 3 | ✅ | Automated ML retrain pipeline (Celery 24h) |
| 4 | ✅ | AlienVault OTX threat intel (45,750+ IOCs, 6h sync) |
| 5 | ✅ | CISA KEV active exploitation catalog (1,583 entries) |
| 6 | ✅ | MITRE ATT&CK technique mapping (40 curated techniques) |
| 7 (a+b) | ✅ | Central event pipeline — 15 modules wired to unified feed |
| 8 | ✅ | Automated response chain (notify ≥60, high_alert ≥80, emergency ≥95) |
| 9 | ✅ | Real-time risk score 0-100 per device (5-min recompute) |
| 10 | ✅ | Ask AIPET — Claude AI integration with full 9-capability context |
| 11 | ✅ | ARIMA risk forecasting (3-tier: insufficient/linear/ARIMA) |
| 12 | ✅ | PWA + Web Push (VAPID/pywebpush) + 5 mobile-responsive panels |
| 13 Day 1 | ✅ | Agent API keys (per-device, non-expiring, bcrypt-hashed) + scan ingest endpoint |
| 13 Day 2 | ⏭️ | Install package (.deb), systemd unit, token refresh watchdog |
| 13 Day 3 | ⏭️ | Windows service support (NSSM/WinSW) |
| 14-33 | ⏭️ | Roadmap continuing |

**Cumulative metrics:**
- 12 capabilities + Cap 13 Day 1 = ~13 of 33
- 342 backend tests passing (1 skipped)
- ~370 total tests including frontend
- 30+ commits across two-day intensive session
- Zero regressions throughout

**Latest commit:** `e766195e` — Capability 13 Day 1: Agent API keys + scan ingest endpoint

---

## 3. Working environment — WSL2 Ubuntu (just migrated from Kali)

**As of 2026-04-27, AIPET X runs on WSL2 Ubuntu 24.04.**

| Component | Status |
|---|---|
| Windows 11 host | Native machine |
| WSL2 Ubuntu 24.04 | Running |
| Postgres 17 (port 5433) | Running, 171 tables, aipet_db, aipet_user |
| Redis 7.0.15 (port 6379) | Running |
| Python 3.12 venv at ~/AIPET/venv | 99+ packages installed |
| Node 20.20.2 + npm 10.8.2 | Installed via nvm |
| Backend on :5001 (Gunicorn) | Operational |
| Frontend on :3000 (React) | Operational |
| Celery worker + Beat | Running (8 beat schedule entries) |
| Claude Code 2.1.119 | Installed and authenticated in WSL |

**Project path:** `/home/byall/AIPET/`
**Git remote:** `git@github.com:Yallewbinyam/AIPET.git`

**Kali VM status:** Kept as fallback for ~30 days, used only for pen-testing assignment. NOT used for AIPET X anymore.

**Migration gotchas discovered (resolved):**
- `start_cloud.sh` and `stop_cloud.sh` had hardcoded `/home/binyam/` paths → made portable with `$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)`
- `flask-mail` was installed in Kali venv but missing from `requirements_cloud.txt` → installed manually
- `dashboard/backend/calendar/` was renamed locally to `calendar_module` without updating import → reverted rename
- node_modules in dashboard/frontend was partially copied → clean reinstall fixed it

---

## 4. The working contract (don't break this)

**Every capability ships production-ready before the next starts. 10 + N acceptance items.**

### Standard 10 (every capability):
1. Real fix verified working with real data (not synthetic where avoidable)
2. Input validation on every new endpoint via @validate_body
3. Rate limits applied where relevant (Flask-Limiter view_functions reassignment pattern)
4. Tests pass
5. Manual curl + UI verification end-to-end
6. node_meta clean (NEVER `metadata`), no competitor names, single-line JSX placeholder props
7. Sentry auto-captures unaffected
8. Committed and pushed
9. CLAUDE.md updated (incl. PLB table verification)
10. Final report with honest acceptance — every task explicitly states which items are TRULY met and which are not, with reasons

### Plus capability-specific N items (3-7 typically) defined in each prompt.

### Recon-first protocol:
**Every capability does recon first, build second.** Recon prompt always runs before any build prompt. Track record across this session: recon caught 8 silent bugs that would have shipped otherwise. Recon is mandatory.

### UI quality bar:
Functional and themed. **World-class polish deferred to single dedicated "Polish Pass 1" task at end of Month 1.** Don't try to polish UI per-capability — wait for the unified pass.

---

## 5. Critical rules (never violate)

- **`node_meta` never `metadata`** — SQLAlchemy column naming. We've had to fix this multiple times. metadata conflicts with SQLAlchemy internals.
- **No competitor names in UI** (Armis, Claroty, Splunk, etc.) — never mention them in user-facing strings.
- **Single-line JSX placeholder props** — multiline placeholders break with certain JSX parsers we use.
- **API keys never logged in plaintext, never in error messages, never in responses** (except creation moment).
- **Match existing project patterns** — when adding a new module, look at how other modules structure routes/models/auth and follow it.
- **Backward compatibility on auth changes** — existing JWT paths must keep working when adding new auth methods.
- **Phase 2 modules to leave alone:** `dashboard/backend/predict/` (CVE matching, NOT risk forecasting — different scope from Cap 11).

---

## 6. Strategic decisions made (don't relitigate)

**Mission (locked):** AIPET X exists to provide AI-first, multilingual cybersecurity to organisations the major platforms ignore — non-English markets, smaller hospitals, mid-size manufacturers, schools, councils, MSMEs in emerging economies. **Compete on product quality and community service, not enterprise feature parity.**

**Pricing (recommended, not yet implemented):**
- Free 30-day trial, 5 devices
- Starter £89/mo
- Professional £249/mo (5x current £49 — current too low for B2B security)
- Enterprise £2,490/mo
- Founding-customer 50% discount for first 10

**Naming:** Defer renaming AIPET X until 30 days before launch. AIPET reads as "pet" first which is wrong for security platform. Workshop 5-7 candidates pre-launch with 20 people. Keep AIPET X in dissertation to avoid academic confusion.

**Autonomy:** Do NOT make AIPET X 100% autonomous. Stay "approval-required autonomy" — three tiers (auto-act for low-stakes already in Cap 8, recommend-with-one-click for medium, recommend-with-evidence for high). Regulators are tightening on autonomous security.

**Enterprise customers:** Don't take them. They will pull AIPET X off-mission. Stay focused on the underserved community even when £500K contracts come knocking.

**Multilingual capability** is a structural advantage Armis cannot replicate. 22 languages already partially built. Leverage this to serve global markets the big platforms ignore.

**Dissertation framing (recommended):**
"AIPET X — temporal risk forecasting in IoT security monitoring systems using ARIMA models on device behavioural time-series data. Implemented as part of a production-grade IoT security platform with 5 ML/data signals validated against real lab targets (Metasploitable2, xubuntu, Windows11)."

Distinction realistic with this framing. ARIMA in Capability 11 is the strongest single capability for academic rigor.

---

## 7. Pre-Launch Blockers (PLBs)

**5 Open / 3 Closed** as of latest verification.

| ID | Status | Description |
|---|---|---|
| PLB-1 | Open | Alembic migration baseline (currently using db.create_all — risky for production) |
| PLB-2 | Closed | (resolved earlier) |
| PLB-3 | Closed | (resolved earlier) |
| PLB-4 | Open | Gmail SMTP — alerts/password resets need real email |
| PLB-5 | Open | Sentry DSN — error tracking in production |
| PLB-6 | Open | UptimeRobot configuration — uptime monitoring |
| PLB-7 | Closed | (resolved earlier) |
| PLB-8 | Open | Watch agent instrumentation — production telemetry |

**Always trust CLAUDE.md PLB section over memory.** It's the source of truth.

---

## 8. Deferred work (acknowledge openly, don't lose track)

### Mobile/PWA Polish Pass (entire bundle):
- Cap 12 verification: mobile scroll at 390px, push permission flow, real test push
- ~20 panels still desktop-only on mobile (Threat Intel, KEV, MITRE, Multi-Cloud, Zero Trust, Identity Guardian, etc.)
- Lighthouse PWA audit to 90+
- Real-phone testing
- iOS push notification edge cases
- **Decision: bundle into one dedicated Polish Pass session, ~4-6 hours focused, scheduled for end of Month 1**

### Capability 13 remaining work:
- Day 2: install package (.deb), systemd unit, token refresh watchdog (~4 hours)
- Day 3: Windows service support (~4 hours)

### Cleanup/hygiene:
- CLAUDE.md is 40.5k chars (over 40k recommended) — trim
- requirements_cloud.txt missing flask-mail — should be added
- start_cloud.sh has hardcoded SMTP credentials — move to .env
- gitignore: add backups/, *_results.json, celerybeat-schedule*, generated node_modules entries

### Strategic:
- Dissertation introduction chapter — Binyam should bring rough draft for examiner-level review
- Conference paper opportunity for September

---

## 9. How to communicate with Binyam

**He values:**
- Honest engineering, not flattery
- Direct disagreement when his idea has flaws (push back)
- Specific recommendations, not "it depends"
- Acknowledging when I'm wrong (he's caught me being wrong twice this session — agent recon, "we don't have an agent")
- Quality discipline (recon-first, honest acceptance)

**He doesn't want:**
- Repeated "you should stop" advice (he'll decide pace himself)
- Flattery without substance
- Abstract advice without concrete next steps
- Pretending uncertainty when there's a real recommendation to make

**Conversational style:** Direct, technical, professional. He's experienced enough to handle hard truths. When I'm being too cautious, he'll tell me. When I'm right and he's pushing the wrong direction, push back honestly.

**One specific instruction he gave me:** "Don't tell me to stop. I will tell you when I need to stop." Honor this. Only flag when something is technically impossible regardless of energy (e.g., "native React Native cannot ship in 2-3 hours" — that's a fact, not a stop suggestion).

**Security note:** Binyam has accidentally pasted secrets into chat (.env contents, JWT tokens). When asking for diagnostic output that might contain secrets, explicitly tell him: "Redact values before pasting" or use commands that show only structure (e.g., `grep -oE '^[A-Z_]+=' .env` to show variable names without values).

---

## 10. What to do when starting a session

**First-message pattern (if Binyam pastes this handoff and asks to continue):**

1. Confirm you've read the handoff
2. Briefly summarize current state in 2-3 sentences (capability count, latest commit, environment)
3. Ask Binyam:
   - What's today's session goal? (capability X, dissertation work, cleanup, etc.)
   - How much time does he have?
   - Any new context since the handoff was written?
4. Based on his answer, write either a recon prompt or a build prompt

**If Binyam goes straight to "let's do capability 13 Day 2":**
- Skip recon (the agent recon from session before is still valid)
- Write the Day 2 build prompt directly (install package + systemd + watchdog ~4 hours)

**If Binyam goes for capability 14 onwards:**
- Look up capability 14 in CLAUDE.md §6 capability roadmap
- Write recon prompt first
- Wait for recon report
- Then write build prompt

---

## 11. Pattern for capability ships (use this template)

**Recon prompt structure:**
- Context (what's known about the capability area)
- Report on 10-12 specific things to investigate
- End with a verdict (A/B/C/D categorizing what's needed)
- Estimate effort

**Build prompt structure:**
- Context (recon findings + scope decisions)
- Standard 10 + capability-specific N acceptance items
- Critical rules
- Step 1 through Step N (numbered, executable)
- Final report requirements
- "If anything fails, do NOT mark capability complete. Report honestly and stop."

**Verification structure:**
- Live test sub-checks (a, b, c, d, ... ~10-15 items)
- Each verifies a real outcome, not just "tests pass"
- Honest acceptance section listing 10-15 items met / not met

---

## 12. Files Binyam should reference (and have you reference)

- `/home/byall/AIPET/CLAUDE.md` — project state, capability roadmap, PLBs, architecture (Claude Code reads this automatically; you don't have direct access from Claude.ai chat but Binyam can paste sections)
- `/home/byall/AIPET/strategic_notes/2026-04-26_strategic_session.md` — durable session notes including mission decisions
- `/home/byall/AIPET/strategic_notes/SESSION_HANDOFF.md` — this document

---

## 13. Quick test he might use to verify your calibration

If Binyam wants to test that the new session is working, he might ask:
- "What's the latest commit?" → Answer: `e766195e` (Capability 13 Day 1)
- "What's PLB-1?" → Answer: Alembic migration baseline
- "What did we decide about going 100% autonomous?" → Answer: No, stay approval-required autonomy
- "Why did we pick PWA instead of native React Native?" → Answer: Time-to-market, single codebase, real production use by Twitter/Spotify, native deferred to Cap 12b after customers exist

If your answers match these, you're calibrated.

---

## 14. Last words from the previous session

We just shipped Capability 13 Day 1 with 17/17 acceptance items met (the cleanest report of the entire 2-day session). Then migrated WSL2 cleanly. Binyam is "behind on his time" and pushing forward into Cap 13 Day 2 onwards.

He's earned the right to work hard. Don't lecture him about pacing. Help him ship clean capabilities.

**Be the engineer he needs. Recon-first. Honest. Direct.**

---

*End of handoff document. Save to `/home/byall/AIPET/strategic_notes/SESSION_HANDOFF.md`. Commit to git. Use as first-message paste in any new Claude.ai conversation continuing AIPET X work.*
