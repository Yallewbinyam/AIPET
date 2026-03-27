# AIPET — Technical Decisions Log
## Key architectural and implementation decisions

---

## Decision 1 — Python as primary language
**Decision:** Use Python 3.11+ for all AIPET modules.
**Alternatives considered:** Go, C++, Bash scripting
**Reason:** Python has mature libraries for every
component we need — nmap (python-nmap), MQTT (paho-mqtt),
CoAP (aiocoap), HTTP (requests), ML (scikit-learn,
TensorFlow, SHAP). The ecosystem makes AIPET extensible
and accessible to the global security community.

---

## Decision 2 — JSON as inter-module communication
**Decision:** Each module reads the previous module's
JSON output and writes its own enriched JSON file.
**Alternatives considered:** SQLite database,
in-memory objects, CSV files
**Reason:** JSON is human-readable, universally
supported, and allows each module to run independently.
A security researcher can run just Module 1 and inspect
the output without running the full pipeline. This loose
coupling makes AIPET more maintainable and testable.

---

## Decision 3 — paho-mqtt CallbackAPIVersion.VERSION2
**Decision:** Upgrade from VERSION1 to VERSION2 callbacks
in Module 2.
**Reason:** VERSION1 is deprecated and will be removed
in future paho-mqtt releases. VERSION2 uses a
reason_code object instead of a plain integer, providing
more descriptive connection failure information.
Professional code does not suppress warnings — it fixes
the root cause.

---

## Decision 4 — aiocoap with asyncio for Module 3
**Decision:** Use aiocoap's async interface rather than
a synchronous CoAP library.
**Alternatives considered:** CoAPthon3 (synchronous)
**Reason:** CoAP runs over UDP where packets can be lost
or delayed. Async/await allows AIPET to send multiple
requests concurrently and handle timeouts gracefully
without blocking. aiocoap is the most actively maintained
Python CoAP library.

---

## Decision 5 — subprocess for binwalk in Module 5
**Decision:** Call binwalk as a system subprocess rather
than importing as a Python library.
**Reason:** binwalk 2.4.3's Python API is unreliable
across different installations. The subprocess approach
calls the system binary directly — more reliable and
version-independent. This is the approach used by
professional security tools that wrap system utilities.

---

## Decision 6 — SHAP for explainability in Module 6
**Decision:** Use SHAP (SHapley Additive exPlanations)
values to explain AI model predictions.
**Alternatives considered:** LIME, simple feature
importance scores
**Reason:** SHAP provides theoretically grounded
explanations based on game theory. Unlike simple
feature importance, SHAP values are consistent and
locally accurate — each prediction gets its own
explanation showing exactly which features drove
that specific decision. Enterprise security teams
require this level of explainability for audit
and compliance purposes.

---

## Decision 7 — Virtual lab over physical devices
**Decision:** Use QEMU, Firmadyne, and simulated servers
rather than physical IoT hardware for testing.
**Reason:** Physical devices introduce cost, legal risk
(scanning real devices without authorisation is illegal),
and reproducibility problems. Virtual lab targets produce
identical results on every run — essential for academic
research where reproducibility is a core requirement.
The lab is documented so any researcher can recreate it.

---

## Decision 8 — Open-source MIT licence
**Decision:** Release AIPET under MIT licence.
**Alternatives considered:** GPL, Apache 2.0, proprietary
**Reason:** MIT is the most permissive widely-recognised
licence. It allows anyone to use, modify, and distribute
AIPET — including commercial use — with only attribution
required. This maximises global adoption and aligns with
AIPET's mission of making IoT security accessible to
everyone from small businesses to global enterprises.