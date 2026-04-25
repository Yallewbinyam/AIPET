# AIPET X — Strategic Session Notes
**Date:** 2026-04-26
**Session focus:** Architecture at full capability, pricing, naming, dissertation framing

This file captures strategic decisions and reasoning from a long planning conversation. It exists because chat memory drifts across sessions. This file does not.

## 1. Architecture at Capability 32 — The 4-Layer Model

When all 32 capabilities are complete, AIPET X operates as four distinct layers:

### Layer 1 — Collection (capabilities 13, 15, 16, 21)
Where data enters the platform.
- Customer agents push telemetry from their networks (HTTPS upload to api.aipet.io)
- Customer-deployed appliances run scans inside their networks
- Cloud-side scanners hit public attack surfaces
- Firmware analysis (binwalk) processes uploaded firmware
- Shodan integration adds external exposure context
- Dark web monitoring pulls breach data
- Network topology builder constructs visual maps from raw scan data

### Layer 2 — Intelligence (capabilities 1, 2, 3, 4, 5, 6, 11, 25)
Where data becomes signal.
- Isolation Forest detects distribution-level anomalies
- Per-device baselines detect behavioural deviations
- Threat intelligence (AlienVault OTX) cross-references known-bad indicators
- KEV cross-references against actively-exploited vulnerabilities
- MITRE ATT&CK maps everything to a shared taxonomy
- Predictive risk forecasts probability of breach
- ML benchmarking validates models stay calibrated
- Automated 24-hour retraining keeps everything current

### Layer 3 — Reasoning & Response (capabilities 7, 8, 9, 17, 18, 19, 20)
Where signal becomes action.
- Central event pipeline ingests everything from Layer 2
- Module correlation finds patterns across signals
- Unified risk score aggregates all signals into one number per device
- Automated response playbooks (isolate, snapshot, rotate)
- Digital twin simulator tests "what if" scenarios safely
- Zero trust engine continuously scores device trust
- File integrity monitoring catches changes to critical files

### Layer 4 — Communication (capabilities 10, 12, 22, 23, 24, 26-32)
Where action becomes human-readable.
- Claude AI ("Ask AIPET") — natural language queries about the customer's environment
- AI-written weekly briefings
- Mobile app for alerts on the go
- 22+ languages
- Executive war room (full-screen mission control)
- Evidence chain (capabilities 26-32) — the most differentiated part of the platform

### Production Event Flow Example (the 5:47am MRI exfiltration case)

A real production scenario demonstrating all 4 layers in sequence:

1. **5:47am Tuesday**: Agent in Sarah's NHS trust network observes the MRI machine sending 80GB to an unusual IP.
2. **5:47:03am**: Agent uploads to api.aipet.io. Lands in real_scan_results and agent_telemetry.
3. **5:47:05am**: Layer 2 fires. All 5 verdict signals run in parallel via Celery:
   - Isolation Forest flags the device (anomaly)
   - Behavioural baseline flags it (12σ deviation from normal)
   - Threat intel checks the destination IP — it's in OTX as a known exfiltration server
   - KEV checks open CVEs — patched
   - MITRE maps to T1041 (Exfiltration Over C2 Channel) + T1567 (Exfiltration Over Web Service)
4. **5:47:08am**: Layer 3 correlates. Five-out-of-five signals = critical confidence. Unified risk score for this device jumps from 23 to 95. Playbook engine triggers: isolate device, snapshot disk, rotate associated credentials.
5. **5:47:12am**: Layer 4 fires. Claude API drafts an incident summary. Sarah's mobile app pings. Email goes to the IT team. Jira ticket opens with evidence (network capture screenshot, video of the dashboard at the moment of detection, signed PDF report with chain of custody).
6. **5:48am**: A draft NIS2 breach notification letter sits in Sarah's pending-review queue (capability 32) — she edits and sends within the legal 72-hour window.

End-to-end pipeline: ~25 seconds.

### What's Genuinely Differentiated vs Standard

**Differentiated:**
1. The evidence chain (capabilities 26-32) — most platforms send alerts; few automate full evidence-to-regulatory-notification pipelines.
2. Claude AI integration depth — most platforms bolt on chat-with-data as marketing; here it's integrated into the reasoning layer.
3. The 5-verdict architecture — unusually transparent; most platforms output a single confidence score, AIPET X shows independent signals with attribution.

**Standard / table-stakes:**
- Underlying tech (Isolation Forest, MITRE, OTX, KEV) is industry-standard.
- The assembly is what's distinct, not the components.

## 2. Pricing Strategy

### Current Pricing Problems
- Free £0 / 5 scans
- Professional £49/mo unlimited
- Enterprise £499/mo unlimited + API

**Diagnosis:** Too low for B2B security. Target customers (NHS trusts, universities, mid-size manufacturers) pay £49/mo from petty cash and don't take the platform seriously. Cheap signals "not serious" in B2B security.

### Recommended Pricing (defer to launch decision)

| Tier | Price | Purpose |
|---|---|---|
| Free | £0 / 30 days / 5 devices | Trial, not free-forever |
| Starter (new) | £89/mo | Captures small businesses unwilling to pay £249 |
| Professional | £249/mo or £1,990/yr | 5x current; still cheap vs Armis (£30k+) |
| Enterprise | £2,490/mo or £24,900/yr | 5x current; still 10x cheaper than competitors |

### The Math
- £49 × 50 customers Year 1 = £29,400/year
- £249 × 30 customers Year 1 = £89,640/year (lower volume but real businesses, lower churn)
- Plus 1 Enterprise at £2,490 = £119,520/year
- Same effort, 4x revenue, longer retention.

### Decision
Don't change pricing today. Build with £249/£2,490 in mind. Make every feature feel like it belongs at that price. Launch at recommended pricing. Offer founding-customer 50% discount for first 10 paying customers (locks them in cheap, creates social proof).

## 3. Naming Strategy — Defer to Launch

### Current Name Assessment (AIPET X)

**Works:**
- Memorable
- Domain (aipet.io) is short and owned
- "X" connotes enterprise/extended

**Doesn't work:**
- "PET" reads as "pet" first, AI/security second — risks misreading as pet-care startup
- Pen Testing is one of 32 capabilities; the name no longer matches the platform's scope
- "X" requires explanation
- Hard to pronounce in sales conversations

### What Good Security Platform Names Share
1-3 syllables. Easy to say. Easy to spell. Doesn't try to describe the product. Examples: Wiz, Snyk, Drata, Vanta, Tessian, Lacework.

### Naming Approach Categories
1. **Abstract / coined** (highest credibility, hardest to find) — like Wiz, Snyk, Vanta
2. **Real words with connotations** — Sentinel, Vigil, Watchtower (many already taken)
3. **Greek/Latin roots** — Argus, Cerberus, Aegis (security industry saturated with these)
4. **Concept-words** — Threadly, Signalcraft, Verdis, Scopely
5. **Compound names** — ThreatLens, RiskGrid, SignalPath

### Decision
**Defer renaming to 30 days before launch.**

Reasons:
- Renaming mid-development creates confusion in dissertation, GitHub history, and supervisor conversations
- A bad name is worse than an OK name — give time to find a great one
- The right name often emerges from spending time with potential customers

**For dissertation: keep AIPET X.** Switching mid-MSc creates academic confusion. The new name becomes the brand at launch; AIPET X becomes the codename.

**Practical action:**
1. Reserve 5-7 candidate domains now (£10-20 each). Don't commit to one.
2. A month before launch, run a name workshop with 20 people: which name makes them think of what?
3. Pick the cleanest associations.

## 4. Dissertation Framing

### Recommended Position
Frame this as a **systems contribution**, not narrow ML.

> "I built a working production-grade IoT security platform integrating multiple ML/data signals with explainability and validated it against [Metasploitable2 + xubuntu + Windows11] in a controlled lab. This thesis presents the architecture, the design decisions, the empirical results, and the implications for defending IoT-rich enterprises like NHS trusts."

### Why This Framing Wins Distinction
Most MSc cybersecurity dissertations cover one ML technique narrowly applied. AIPET X has 6+ capabilities working together in a real system with real lab validation. Few MSc students do systems work. **Distinction is realistic with this framing.**

### Strong Intro Chapter Structure
1. The problem (IoT security is broken; here's why)
2. The gap (existing platforms cost £30k+; existing research doesn't address NHS-scale needs)
3. The contribution (this is what was built and what's novel)
4. The roadmap (what each chapter covers)

### Conference Paper Opportunity
Supervisor mentioned September. A 6-8 page conference paper can be extracted from the same material — likely focused on the multi-verdict ML architecture or the explainability+evidence pipeline.

### Next Step
When ready, bring the introduction chapter for honest examiner-level review. Even rough draft. The introduction is where dissertations win or lose marks.

## 5. Future Decision Calendar

These reminders matter more than memory:

| When | What |
|---|---|
| At Capability 12 completion | Review dissertation introduction chapter with Claude |
| 60 days before launch | Pricing review and finalisation |
| 30 days before launch | Rename workshop with 5-7 candidate names |
| Launch week | PLB-4 Gmail SMTP credentials, PLB-5 Sentry DSN |
| Launch day | PLB-6 UptimeRobot configuration |
| Month 2 capability work | PLB-8 Watch agent instrumentation (TCP flags, directional bytes, per-protocol counts, remove 10-destination cap) |
| Dedicated focused day before launch | PLB-1 Alembic migration baseline |

## 6. Working Contract (established this session)

Every task ships production-ready before the next task starts. The 10-point standard:

1. Real fix verified working with real data (not synthetic where avoidable)
2. Input validation on every new endpoint via @validate_body
3. Rate limits applied where relevant (Flask-Limiter view_functions reassignment pattern)
4. Tests pass
5. Manual curl + UI verification end-to-end
6. node_meta clean (never `metadata`), no competitor names, single-line JSX placeholder props
7. Sentry auto-captures unaffected
8. Committed and pushed
9. CLAUDE.md updated (incl. PLB table verification)
10. Final report with honest acceptance — every task explicitly states which items are TRULY met and which are not, with reasons

Plus: every capability does **recon first**, **build second**. Recon prevents fake work and surface-level builds.

UI quality bar: functional and themed. World-class polish is deferred to a single dedicated "Polish Pass 1" task at the end of Month 1.
