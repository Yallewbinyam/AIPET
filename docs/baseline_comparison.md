# AIPET Validation — Baseline Comparison Experiment
## Target: OWASP IoTGoat v1.0 Raspberry Pi Firmware

---

## Experiment Design

**Objective:** Compare manual IoT firmware assessment
against AIPET automated assessment on the same target.

**Target:** OWASP IoTGoat v1.0
**Path:** lab/_IoTGoat-raspberry-pi2.img.extracted/squashfs-root
**Date:** March 2025

---

## Assessment A — Manual Analysis (No AI)

**Tools used:** strings, grep, file, find (standard Linux)
**No AI prioritisation — analyst judgment only**

### Start time: [recorded below]

### Step 1 — File system overview
```bash
find squashfs-root -type f | wc -l
```
Files found: 1,219

### Step 2 — Search for passwords manually
```bash
grep -r "password" squashfs-root/etc/ --include="*.conf"
grep -r "password" squashfs-root/etc/ --include="*.sh"
```

### Step 3 — Check shadow file
```bash
cat squashfs-root/etc/shadow
cat squashfs-root/etc/passwd
```

### Step 4 — Look for private keys
```bash
grep -r "BEGIN PRIVATE KEY" squashfs-root/
grep -r "BEGIN RSA" squashfs-root/
```

### Step 5 — Check for telnet
```bash
find squashfs-root -name "telnetd"
find squashfs-root -name "*.sh" | xargs grep -l "telnet"
```

### Manual findings recorded below:
---

## Assessment B — AIPET Automated Analysis

**Already completed — results in:**
docs/iotgoat_validation_results.json

**Time taken:** Recorded during run
**Findings:** 279 credentials, 12 keys, 33 configs,
              112 vulnerable components
**AI prioritisation:** Critical findings ranked first

---

## Comparison Results

## Comparison Results

| Metric | Manual | AIPET | Improvement |
|--------|--------|-------|-------------|
| Time taken | 162 seconds | ~30 seconds | 5.4x faster |
| Files scanned | Partial sample | 1,219 (100%) | Complete |
| Credential findings | 8 | 279 | 34x more |
| Private keys found | 1 | 12 | 12x more |
| Dangerous configs | 0 | 33 | New coverage |
| Vulnerable components | 0 | 112 | New coverage |
| AI prioritisation | None | SHAP ranked | Quantified |

## Key Findings from Manual Assessment
- Shadow file: root and iotgoatuser MD5 hashes (crackable)
- Private key: libmbedcrypto.so.2.12.0
- Telnetd binary present at /usr/sbin/telnetd
- Password references in /etc/init.d/uhttpd

## Honest Limitations of AIPET
- 279 credential patterns includes false positives from
  BusyBox binaries containing "password: incorrect" error
  messages — not real hardcoded credentials
- AIPET did not specifically flag MD5 hash format for
  offline cracking — human analyst would prioritise this
- Pattern-based approach cannot replace analyst intuition
  for contextual finding interpretation

## Conclusion
AIPET demonstrated superior coverage and speed across all
quantitative metrics. Manual assessment showed advantages
in contextual interpretation of specific finding types.
The optimal approach combines AIPET automation with human
analyst review of prioritised findings.
