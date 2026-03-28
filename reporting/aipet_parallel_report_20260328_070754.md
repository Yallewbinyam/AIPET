# AIPET Parallel Scan Report

**Generated:** 2026-03-28 07:07:54
**Networks Scanned:** 2
**Devices Discovered:** 2
**Overall Risk:** CRITICAL

## Networks Scanned

- localhost
- 127.0.0.1

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH     | 3     |
| MEDIUM   | 0   |
| LOW      | 0      |
| **TOTAL**| **8**|

## All Findings (Sorted by Severity)

### [CRITICAL] Connection Test
**Module:** MQTT | **Target:** localhost

BROKER ACCEPTS ANONYMOUS CONNECTIONS — No authentication required

---

### [CRITICAL] Authentication Bypass
**Module:** MQTT | **Target:** localhost

Authentication bypass successful — 17 valid credential set(s) found

---

### [CRITICAL] Sensitive Data Harvest
**Module:** MQTT | **Target:** localhost

4 sensitive data pattern(s) found in MQTT traffic

---

### [CRITICAL] Connection Test
**Module:** MQTT | **Target:** 127.0.0.1

BROKER ACCEPTS ANONYMOUS CONNECTIONS — No authentication required

---

### [CRITICAL] Authentication Bypass
**Module:** MQTT | **Target:** 127.0.0.1

Authentication bypass successful — 17 valid credential set(s) found

---

### [HIGH] Message Injection
**Module:** MQTT | **Target:** localhost

Message injection successful — 4 message(s) injected without authorisation

---

### [HIGH] Topic Enumeration
**Module:** MQTT | **Target:** 127.0.0.1

Discovered 4 topic(s), captured 4 message(s)

---

### [HIGH] Message Injection
**Module:** MQTT | **Target:** 127.0.0.1

Message injection successful — 4 message(s) injected without authorisation

---

### [INFO] Topic Enumeration
**Module:** MQTT | **Target:** localhost

No messages captured in window

---

### [INFO] Retained Message Scanner
**Module:** MQTT | **Target:** localhost

No retained messages found

---

### [INFO] Sensitive Data Harvest
**Module:** MQTT | **Target:** 127.0.0.1

No sensitive patterns detected

---

### [INFO] Retained Message Scanner
**Module:** MQTT | **Target:** 127.0.0.1

No retained messages found

---

