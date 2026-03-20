# AIPET Literature Notes
## Document 1: OWASP IoT Top 10 (2018)
**Source:** https://owasp.org/www-project-internet-of-things/
**Read Date:** March 2025
**Relevance:** Defines the 10 primary IoT attack categories 
— framework anchor for all AIPET modules

---

## How AIPET Covers the OWASP IoT Top 10

| # | Vulnerability | AIPET Module | How We Test It |
|---|--------------|-------------|----------------|
| I1 | Weak/Hardcoded Passwords | Module 2 (MQTT) + Module 4 (HTTP) | Brute force + default credential testing |
| I2 | Insecure Network Services | Module 1 (Recon) | Port scan + service enumeration |
| I3 | Insecure Ecosystem Interfaces | Module 4 (HTTP) | API fuzzing + session testing |
| I4 | Lack of Secure Update Mechanism | Module 5 (Firmware) | Firmware extraction + integrity check |
| I5 | Insecure/Outdated Components | Module 6 (AI Engine) | CVE matching against device profile |
| I6 | Insufficient Privacy Protection | Module 2+3 (MQTT/CoAP) | Unencrypted traffic interception |
| I7 | Insecure Data Transfer | Module 2+3 (MQTT/CoAP) | Protocol attack + eavesdropping |
| I8 | Lack of Device Management | Module 1 (Recon) | Exposed management interfaces |
| I9 | Insecure Default Settings | Module 4 (HTTP) + Module 2 | Default credential + config testing |
| I10 | Lack of Physical Hardening | Module 5 (Firmware) | Debug port detection + firmware dump |

---

## Key Takeaways for AIPET
- AIPET covers 9 out of 10 OWASP IoT categories directly
- I10 (Physical Hardening) is partially covered via firmware 
  analysis — full hardware testing is post-MSc scope
- The AI engine (Module 6) adds intelligence across ALL 
  categories by predicting which vulnerabilities are most 
  likely given the device profile

---

## Notes
- Write your own observations here as you read
- Any questions that come up — note them here
