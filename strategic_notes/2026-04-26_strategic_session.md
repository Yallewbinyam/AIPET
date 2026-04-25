# Strategic Session Notes — 2026-04-26

These notes were written the day Capabilities 1–6 shipped (Isolation Forest + SHAP,
Behavioural Baseline, Automated ML Pipeline, AlienVault OTX, CISA KEV, MITRE ATT&CK).
The platform now returns five independent verdicts on every detection.

Read this before any strategic discussion about launch, pricing, naming, or dissertation.

---

## Architecture at Capability 32

### The 4-Layer Model

When all 32 capabilities are complete, AIPET X will operate as a four-layer security intelligence platform. Understanding this structure is essential for positioning, dissertation framing, and investor conversations.

**Layer 1 — Collection**
Raw data ingestion from the physical environment. This includes Nmap host/service/OS scanning, NVD CVE matching, live CVE feed sync (hourly), firmware extraction via binwalk (Capability 13), Shodan internet-exposure checks (Capability 16), and the Python device agent streaming CPU/mem/disk/process/network telemetry every 30 seconds. Nothing is synthesised at this layer — it is observed reality about what is running on the network.

**Layer 2 — Intelligence**
The five-verdict analysis engine that processes Collection layer data and produces structured findings. As of Capability 6, this layer is complete at its core:
- Isolation Forest anomaly detection with SHAP explainability (Capability 1)
- Per-device behavioural baseline with Z-score deviation (Capability 2)
- AlienVault OTX threat intelligence cross-reference: 45,750 cached IOCs (Capability 4)
- CISA KEV actively-exploited CVE cross-reference: 1,583 entries (Capability 5)
- MITRE ATT&CK live technique mapping from all four prior signals (Capability 6)

When Capabilities 7–12 ship, this layer also includes: CISA KEV exploit validation already done; MITRE ATT&CK already done; a central event pipeline that feeds every module's findings into a unified brain (Capability 7); automated response chains (Capability 8); a unified real-time risk score (Capability 9); Claude API-powered natural language Q&A about the specific environment (Capability 10); a 90-day breach probability forecast (Capability 11); and AI-written weekly security briefings (Capability 12).

**Layer 3 — Reasoning**
The autonomous response and decision layer. Playbooks that isolate hosts, snapshot state, rotate credentials (Capability 17). Digital twin attack simulation (Capability 18). Zero trust continuous trust scoring (Capability 19). File integrity monitoring (Capability 20). This layer is what makes AIPET X autonomous rather than just observational — it acts, not just alerts.

**Layer 4 — Communication**
Board-ready output. Executive one-page summaries (Capability 29). Board presentation mode with auto-generated PowerPoint (Capability 31). Claude API-generated NIS2/GDPR breach notification letters (Capability 32). PDF reports with digital signatures and timestamps (Capability 28). This layer translates everything in Layers 1–3 into the language of boardrooms, regulators, and insurers.

### How a Production Event Flows Through the Architecture

**The 5:47am MRI exfiltration scenario** (a realistic IoT healthcare incident):

1. **Collection layer** — The device agent on a hospital's MRI controller reports an anomalous outbound byte rate spike at 5:47am. This is raw telemetry. Simultaneously, the NVD sync has flagged two new CVEs against the MRI vendor's firmware from last week's release.

2. **Intelligence layer** processes the telemetry:
   - Isolation Forest scores this device at 0.82 anomaly score (high). SHAP breakdown: byte_rate is the top contributor (SHAP 1.4), outbound_ratio second (SHAP 0.9), night_activity third (SHAP 0.6).
   - Behavioural baseline shows the MRI controller has never transferred more than 2MB outbound between midnight and 6am. Current observation: 847MB. Z-score: 12.3σ.
   - OTX cross-reference: no IOC match (expected — this is likely an internal exfil, not C2 to a known bad IP).
   - CISA KEV: one of the two new CVEs is KEV-listed (CVE-2026-XXXX, CWE-77, command injection). High confidence, ransomware-associated.
   - MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel) from byte_rate, T1190 (Exploit Public-Facing Application) from KEV hit, T1059 (Command and Scripting Interpreter) from CWE-77.

3. **Reasoning layer** (when Capabilities 17–20 ship) would automatically: isolate the MRI controller from the network at the switch level, snapshot the running state, open a high-severity incident, and queue the response playbook for an on-call engineer.

4. **Communication layer** generates: a 60-second executive summary with breach probability update, a detailed forensic timeline, and a draft NIS2 notification letter (72-hour reporting window, applicable since this is healthcare IoT data).

**The point of this scenario** is to demonstrate that AIPET X does not produce a log entry — it produces a complete evidence chain from raw observation to boardroom-ready action, automatically, in seconds. No SIEM/SOAR stack of 15 vendor tools produces this with this degree of transparency (five independent verdicts, each with source attribution and confidence level).

### What Is Genuinely Differentiated

These things are hard to replicate quickly and represent real moat:

**1. Five-verdict evidence chain on a single detection.** Isolation Forest + Behavioural Baseline + OTX + KEV + MITRE ATT&CK, all running on every predict_real call, all source-attributed and confidence-labelled. No other IoT security platform surfaces this density of context per alert. Most show one verdict (ML score) or two (ML + CVE). Five with full transparency is a differentiated UX.

**2. Claude API integration depth (Capabilities 10, 12, 29, 32).** When these ship, every piece of intelligence in the platform feeds a Claude context window that answers specific questions about the user's specific environment — not generic security advice. "Which of our 47 devices is most likely to be the entry point for the attack pattern we saw last week?" That is not a query you can run against any existing product.

**3. IoT/OT coverage at enterprise depth.** Most IoT security tools are either consumer-grade (scan a home network) or industrial OT tools with huge licence fees and professional services requirements. AIPET X covers the middle — enterprise IoT + OT + cloud in a single platform at SaaS price points.

**4. Dissertation-validated real lab data.** The Metasploitable2 + xubuntu + Windows 11 lab validates the ML pipeline against real devices with known-vulnerable profiles. Published academic validation of a commercial platform is unusual and creates credibility that pure-commercial tools cannot easily claim.

**5. Regulatory output that is ready to file.** A Claude-generated NIS2/GDPR breach notification letter (Capability 32) that an organisation can review and submit — not a template they fill in manually — changes the operational response experience materially. Legal review time is the bottleneck in breach response. Cutting it has direct cost value.

### What Is Standard Table-Stakes

These things are necessary but not differentiating — every serious security platform has them:

- JWT authentication, Google OAuth, Stripe payments
- PDF report export
- Rate limiting and input validation
- Celery task queue with scheduled jobs
- Nmap integration (every IoT scanner does this)
- NVD CVE matching (standard)
- Basic SIEM event storage and dashboards

The architecture at Capability 32 is differentiating. The scaffolding that holds it together is not.

---

## Pricing Strategy

### The Current Problem

The initial pricing is too low for the B2B security market:
- Free: 5 scans
- Professional: £149/month
- Enterprise: £499/month

The problem is not just revenue — it is positioning. Enterprise security buyers do not trust cheap tools. A £149/month Professional plan signals a product aimed at small-business IT managers, not the ISO 27001 lead or Head of Security who is the actual buyer. The price communicates category.

Comparable SaaS security products:
- Wiz (cloud CSPM): £8,000–£40,000/year at the low end
- Snyk (developer security): £90/month per developer, enterprise £1,000s/year
- Vanta (compliance automation): £5,000–£25,000/year
- Darktrace (AI threat detection): £30,000+/year

AIPET X is not directly comparable to any of these — it is IoT/OT focused, which is a distinct buyer. But the pricing tier positioning is informative.

### The Recommendation

| Tier | Price | Positioning | Included |
|---|---|---|---|
| Free Trial | £0 for 30 days | Everything in Professional | Removes commitment friction; no credit card required |
| Starter | £89/month | SMB with IoT (dentist with IP cameras, small manufacturing) | 50 scans/month, 3 users, basic reports, no Claude integration |
| Professional | £249/month | Mid-market security teams, IoT-heavy SMEs | Unlimited scans, 10 users, all capabilities including Claude Q&A, full PDF reports |
| Enterprise | £2,490/month | Enterprise security teams, compliance-driven buyers | Unlimited everything, multi-tenant, API access, dedicated SLA, white-glove onboarding |

### The Math

Current ARR potential (at 100 paying customers):
- 60 Professional (£149) + 40 Enterprise (£499) = £8,940 + £19,960 = £28,900/month = £346,800 ARR

Revised ARR potential (at 100 paying customers):
- 20 Starter (£89) + 50 Professional (£249) + 30 Enterprise (£2,490) = £1,780 + £12,450 + £74,700 = £88,930/month = **£1,067,160 ARR**

Same number of customers. Same support overhead. 3× the ARR, concentrated in Enterprise (where the stickiness is highest). The 30-day free trial removes the friction that justifies the higher price.

### Retention Argument

Higher prices correlate with lower churn in B2B security:
1. The buyer spent more budget, so there is more internal accountability for results.
2. The platform gets more deeply integrated into workflows (compliance reporting, incident response).
3. Security buyers do not switch tools casually — switching costs are high (reconfiguring scanning targets, retraining staff, re-establishing baselines).

A £2,490/month Enterprise customer is likely to stay 18–36 months. A £499/month Enterprise customer who signed up to "try it" may cancel at month 4.

### The Decision

**Defer pricing changes to launch week** — do not update Stripe configuration or marketing pages yet. Build the platform with the revised pricing in mind (the Enterprise feature set is already correct; the Starter tier would be a minor restriction of the current Free tier). The pricing review happens at 60 days before launch.

---

## Naming Strategy

### What Works About AIPET X

- "AI" signals the core differentiator immediately
- "PET" is memorable — petname, not acronym
- The IoT/connected device focus is implied
- "X" signals a platform version / premium tier

### What Does Not Work

- "PET" (for a security product sold to enterprise) can read as cute or consumer-grade
- The full expansion "AI Platform for Enterprise Threat detection" is awkward — most buyers will not know what it stands for
- No 3–4 letter abbreviation that works as a spoken word (unlike "Wiz", "Snyk", "Vanta")
- Hard to trademark internationally without conflict risk

### What Good Security Product Names Share

Looking at the successful modern security SaaS names:

| Name | Syllables | Type | Why It Works |
|---|---|---|---|
| Wiz | 1 | Real word (clever/wizard) | Memorable, confident, abstract-enough |
| Snyk | 1 | Coined | Distinct, easy to say once learned |
| Vanta | 2 | Coined (ultra-black) | Premium feel, abstract, sounds authoritative |
| Lacework | 2 | Compound real word | Implies network + coverage |
| Orca | 2 | Animal metaphor | Cloud security → apex predator framing |
| Rubrik | 2 | Near-word (rubric) | Academic/structured, data protection |
| Cyera | 3 | Coined | Feminine, modern, distinguishable |

Pattern: 1–3 syllables. Either a real word with metaphorical resonance (apex predator, clever, protective) or a coined word that is phonetically clean and trademarkable. No acronyms. No "AI" in the name (every tool says AI now — it adds nothing).

### The Approach

1. **Do not rename before launch.** Renaming mid-development creates confusion in documentation, CLAUDE.md, test fixtures, and any academic work. The risk is not worth it at this stage.

2. **Run a candidate workshop at 30 days before launch.** Generate 20–30 candidates using these constraints: 1–3 syllables, conable trademark, no existing security product with the same name, works as a .io or .security domain. Narrow to 5–7 for stakeholder review. Decision in one sitting.

3. **Candidate directions to explore:**
   - Predator/guardian animal metaphors (Lynx, Kestrel, Corvo, Nyx)
   - Coined security-adjacent words (Sentryx, Arcana, Verixa)
   - Abstract threat/visibility metaphors (Umbra, Solace, Vantage)
   - Short portmanteaus of the core value prop (Threatn, Signar, Veridex)

4. **In all academic/dissertation contexts: use AIPET X.** The dissertation cites the platform by its development name. Renaming creates a discrepancy between submitted chapters and the live product — the examiner will notice and it creates unnecessary questions. The dissertation is about the system architecture, not the brand.

---

## Dissertation Framing

### The Core Positioning Problem

A PhD dissertation on an AI/security platform faces a framing choice: narrow ML contribution or systems contribution. The narrow ML framing is safer academically (easier to bound, easier to evaluate) but undersells the actual work. The systems framing is riskier but more accurate and more impressive.

**The narrow ML framing** would present: "We evaluated Isolation Forest anomaly detection on IoT network telemetry, and found that SHAP explainability increases operator trust in ML security systems." This is defensible but small. The academic contribution is incremental.

**The systems framing** presents: "We designed, implemented, and validated a full-stack autonomous security platform for IoT/OT environments, integrating five independent intelligence sources (ML anomaly detection, behavioural baselines, open-source threat intelligence, actively-exploited CVE databases, and MITRE ATT&CK technique mapping) into a production-grade system validated against real heterogeneous hardware." This is a genuine systems contribution.

### The Strongest Angle

The combination of factors that makes this academically novel:

1. **Production-grade, not prototype.** Most academic security systems are evaluated against synthetic datasets or PCAP files. AIPET X is evaluated against live hardware: a deliberate vulnerability lab (Metasploitable2 with 23 open ports, 14 CVEs), a normal-profile device (xubuntu, 0 open ports), and a mixed-profile device (Windows 11, 1 port, 5 CVEs). The ML pipeline produces correct anomaly classifications on real data — anomaly=True for Metasploitable2, anomaly=False for xubuntu — which is the actual validation claim.

2. **Five-verdict transparency as a research contribution.** The idea that every detection event should surface five independent, source-attributed, confidence-labelled verdicts (with SHAP explanations, Z-score deviations, and MITRE ATT&CK mapping) and that this transparency reduces alert fatigue and increases operator trust — this is a testable research claim. If Capability 25 (ML benchmarking and evaluation) produces a formal comparison of operator response time / false positive rate between this system and rule-based baselines, that is a publishable result.

3. **Claude API depth in security reasoning.** Capability 10 (Ask AIPET — answers about your specific environment) and Capability 12 (weekly briefings) represent a distinct contribution: the use of a frontier language model as a reasoning layer over a structured security knowledge graph, with citation of real scan data as context. This is novel in the IoT security domain.

### Conference Paper Opportunity

By September 2026, if Capabilities 1–12 are complete, there is a plausible submission to:
- **ACM CCS** (Computer and Communications Security, deadline typically June for November conference)
- **USENIX Security** (deadline typically February for August conference — so September 2026 would be the following year's cycle)
- **IEEE S&P (Oakland)** (deadline typically December)
- **NDSS** (deadline typically August for February conference)

A more realistic target for September 2026 given timeline:
- **RAID** (Research in Attacks, Intrusions and Defenses) — a respected B-tier venue, practical focus, good fit for a systems paper
- **AsiaCCS** — international venue, accepts work with strong implementation validation
- A **workshop paper** at CCS or USENIX as a first submission

The paper angle: "Five-Verdict Transparent Anomaly Detection for IoT/OT Environments: A Production-Grade Systems Architecture and Evaluation." Results section: Metasploitable2 / xubuntu / Windows 11 real-device validation; Capability 25 ML benchmarking; operator trust study if time permits.

### Next Step

**Bring the dissertation introduction chapter for examiner-level review.** The introduction needs to: stake the systems contribution claim clearly, situate it in the existing IoT security landscape (Darktrace, Claroty, Armis, Nozomi — and why none of them do what AIPET X does), and articulate the research questions in testable terms. This is the document that examiner credibility lives or dies on. A single focused review session on that chapter is the highest-value academic work right now.

---

## Future Decision Calendar

These are the committed dates and triggers for the decisions deferred today. Future Claude Code sessions should check this calendar against current progress.

### At Capability 12 Completion (target: end of Month 1)

**Action: Dissertation introduction chapter review.**
When all 12 Month 1 Intelligence Core capabilities are complete, the platform has enough depth to make the research claims in the introduction credible. At that point, draft the introduction and bring it for examiner-level critique. The questions to answer: Is the systems contribution claim defensible? Are the research questions appropriately scoped? Is the related work section sufficiently broad?

### At Capability 25 Completion (Month 5 target)

**Action: ML benchmarking results and paper submission decision.**
Capability 25 is ML benchmarking and evaluation — comparing the five-verdict system against rule-based baselines. This is the empirical core of any conference paper. When this ships, decide whether to pursue a workshop paper submission (likely NDSS 2027 or RAID 2026) or integrate results into the dissertation as the evaluation chapter.

### 60 Days Before Launch (date TBD based on deployment timeline)

**Action: Pricing review and finalisation.**
Revisit the pricing model proposed in these notes. By this point, there should be a clearer picture of: who is actually using the beta (if any beta users exist), what the competitive landscape looks like (any new entrants in IoT security SaaS), and what the cost structure of the platform actually is (DigitalOcean hosting + Claude API costs at scale). Confirm, adjust, or reject the £89/£249/£2,490 tiers. Update Stripe configuration. Update the pricing page.

The specific questions to answer at this review:
- Is the Enterprise price in the right range given actual customer conversations?
- Does the Starter tier (£89) cannibalise Professional in a way that hurts growth, or does it genuinely expand the addressable market?
- Is the 30-day free trial the right onboarding pattern, or would a freemium model (limited scans forever) perform better for acquisition?

### 30 Days Before Launch

**Action: Name workshop.**
Convene a focused session (1–2 hours) to review the naming situation. By this point the product is functionally complete and the category positioning is clear from any early customer conversations. Generate 20–30 candidates using the constraints in the Naming Strategy section above. Narrow to 5–7. Decision in one sitting. Begin domain registration and trademark search immediately after.

If the decision is to keep AIPET X: update branding assets accordingly and move on. Renaming is not required — this is a decision point, not a commitment.

### Launch Week

**PLB-4: Gmail SMTP.**
Create a Gmail App Password (Google Account → Security → 2-Step Verification → App Passwords) and add to production .env as MAIL_USERNAME and MAIL_PASSWORD. This enables password reset emails and scan completion notifications. Without this, the Flask-Mail integration silently fails and users cannot reset passwords. Estimated time: 10 minutes once the App Password is created.

**PLB-5: Sentry DSN.**
Create a Sentry account at sentry.io. Create a project for AIPET X (Python / Flask). Copy the DSN and add to production .env as SENTRY_DSN. This enables automatic error capture and alerting for production exceptions. Without this, errors are logged locally but not alerted. Estimated time: 15 minutes.

### Launch Day

**PLB-6: UptimeRobot.**
Once aipet.io is live and DNS is propagated, create an UptimeRobot monitor pointing at `https://aipet.io/api/ping` with a 5-minute check interval. The `/api/ping` endpoint is already implemented and returns `{"status": "ok", "timestamp": ...}`. Set alerts to the operational email. Without this, there is no external uptime monitoring — downtime goes undetected until a user reports it. Estimated time: 5 minutes.

---

## What I Will Not Forget

These items are tracked here so they survive session boundaries and are not lost to chat context expiry. Future Claude Code sessions must read this section before any strategic conversation.

**1. The pricing is a decision deferred, not a decision made.**
The current Stripe configuration (Free 5 scans / Professional £149 / Enterprise £499) is a placeholder. The strategic recommendation — Starter £89 / Professional £249 / Enterprise £2,490 / Free Trial 30 days — is recorded here but not yet implemented. This will be revisited at 60 days before launch, with actual customer signal. Do not present the current pricing as final.

**2. The name AIPET X is kept for now but is under review.**
The platform will be called AIPET X for all development, documentation, dissertation, and academic purposes. A rename workshop happens 30 days before launch. The outcome is uncertain. The naming candidates section above documents the direction. Do not assume AIPET X is the final commercial name.

**3. The T1071 hardcoding bug was fixed in Capability 6 (commit 72a2eaf7).**
10 historical ba_anomalies rows remain labelled T1071 (backward-compat policy). All new behavioral deviations from commit 72a2eaf7 onwards are correctly mapped via from_behavioral_deviations(). If anyone queries old data and sees T1071 in ba_anomalies, this is expected and documented.

**4. The dissertation introduction chapter is the single highest-priority academic task.**
Not writing more code. Not adding more capabilities. The introduction chapter is the document that sets up everything else and is the examiner's first impression. It needs examiner-level review. Bring it when Capability 12 is complete.

**5. The 5-verdict predict_real response is the core product claim.**
Every sales conversation, every pitch deck, every conference paper abstract should lead with this: five independent, source-attributed, confidence-labelled verdicts on every detection. Isolation Forest + Behavioural Baseline + OTX + KEV + MITRE ATT&CK. No other IoT security platform does this at this depth with this transparency. This is the thing.

**6. PLB-1 (Alembic migrations) is the only pre-launch blocker that requires a dedicated day.**
All other PLBs (4, 5, 6, 8) are either configuration tasks (10 minutes each) or Month 2+ development work. PLB-1 requires a full database backup, creating a baseline migration from the existing schema, and testing the migration path. This must happen before production deployment and before any beta users have data in the system that could be corrupted. Schedule it at the start of the production deployment day — not as an afterthought.

**7. The lab environment is the proof, not just a test fixture.**
The VirtualBox Host-Only network with Metasploitable2 (10.0.3.11), xubuntu (10.0.3.9), and Windows 11 (10.0.3.10) is the primary evidence base for the dissertation's evaluation claims. Keep these VMs. Maintain their current configuration. If the host machine changes, migrate the VMs before deleting anything. The ML pipeline's correct classification of Metasploitable2 as anomaly and xubuntu as normal is the key empirical result.

**8. The Claude API integration is not just a feature — it is a research contribution.**
When Capability 10 (Ask AIPET) ships, document it carefully: what is in the context window, how scan data is cited, how the system avoids hallucinating facts about the user's environment. This is the most academically novel part of the system and should be written up with the same rigour as the ML evaluation.

---

*Written: 2026-04-26. AIPET X at Capabilities 1–6 complete, 26 remaining. Commit: 72a2eaf7.*
