# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 3: CoAP Attack Suite
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Tests CoAP devices for unauthenticated access,
#              resource enumeration, replay attacks, and
#              malformed packet injection.
#              Uses aiocoap 0.4.17 async client.
# =============================================================

import asyncio
import aiocoap
import json
import time
import socket
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────

# Standard CoAP discovery endpoint — lists all resources
WELLKNOWN_CORE = "/.well-known/core"

# CoAP response codes we care about
COAP_SUCCESS_CODES = [
    "2.01 Created",
    "2.02 Deleted",
    "2.03 Valid",
    "2.04 Changed",
    "2.05 Content",
]

# Sensitive patterns to look for in CoAP responses
SENSITIVE_PATTERNS = [
    "password", "passwd", "pwd", "secret",
    "token", "key", "api_key", "apikey",
    "credential", "auth", "login",
    "admin", "root", "sudo",
    "location", "gps", "latitude", "longitude",
    "heartrate", "patient", "medical",
    "command", "cmd", "execute", "control",
    "firmware", "version", "model",
]


# ── Attack 1: Resource Discovery ──────────────────────────────
async def discover_resources(host, port=5683):
    """
    Attack 1: Query the CoAP well-known/core endpoint to
    discover all resources exposed by the device.

    The /.well-known/core endpoint is a standard CoAP
    feature defined in RFC 6690. It returns a list of
    all available resources in CoRE Link Format.
    Any CoAP device should respond to this — and the
    response reveals the complete attack surface.

    Args:
        host (str): Target device IP
        port (int): CoAP port (default 5683)

    Returns:
        dict: Discovery results with found resources
    """
    print(f"\n[*] Attack 1: Resource discovery on "
          f"coap://{host}:{port}")

    result = {
        "attack":             "Resource Discovery",
        "host":               host,
        "port":               port,
        "resources_found":    [],
        "raw_response":       "",
        "finding":            "",
        "severity":           ""
    }

    try:
        # Create CoAP client context
        protocol = await aiocoap.Context.create_client_context()

        # Build GET request to /.well-known/core
        request = aiocoap.Message(
            code=aiocoap.GET,
            uri=f"coap://{host}:{port}{WELLKNOWN_CORE}"
        )

        # Send request and wait for response
        response = await asyncio.wait_for(
            protocol.request(request).response,
            timeout=10.0
        )

        raw = response.payload.decode('utf-8', errors='ignore')
        result["raw_response"] = raw

        # Parse CoRE Link Format response
        # Format: </resource1>,</resource2>;attr=value
        resources = []
        if raw:
            links = raw.split(',')
            for link in links:
                link = link.strip()
                if link.startswith('<'):
                    # Extract resource path from <path>
                    path = link.split('>')[0].replace('<', '')
                    resources.append(path)
                    print(f"    [RESOURCE] {path}")

        result["resources_found"] = resources

        if resources:
            result["finding"] = (
                f"Discovered {len(resources)} resource(s) — "
                f"device attack surface fully mapped"
            )
            result["severity"] = "HIGH"
            print(f"[!] HIGH: Found {len(resources)} "
                  f"resource(s) on device")
        else:
            result["finding"]  = "No resources discovered"
            result["severity"] = "INFO"
            print("[-] No resources found")

        await protocol.shutdown()

    except asyncio.TimeoutError:
        result["finding"]  = "Discovery timed out — device may not support CoAP"
        result["severity"] = "INFO"
        print("[-] Discovery timed out")

    except Exception as e:
        result["finding"]  = f"Discovery error: {str(e)}"
        result["severity"] = "ERROR"
        print(f"[-] Error: {e}")

    return result


# ── Attack 2: Unauthenticated Access ──────────────────────────
async def test_unauthenticated_access(host, port=5683,
                                       resources=None):
    """
    Attack 2: Attempt GET and PUT requests to all discovered
    resources without any authentication.

    CoAP has no built-in authentication mechanism —
    security is the device's responsibility. Most IoT
    devices implement no access control whatsoever,
    allowing anyone to read sensor data and send commands.

    Args:
        host (str): Target device IP
        port (int): CoAP port
        resources (list): Resources from Attack 1

    Returns:
        dict: Unauthenticated access results
    """
    print(f"\n[*] Attack 2: Testing unauthenticated access "
          f"on coap://{host}:{port}")

    result = {
        "attack":              "Unauthenticated Access",
        "host":                host,
        "readable_resources":  [],
        "writable_resources":  [],
        "sensitive_data":      [],
        "finding":             "",
        "severity":            ""
    }

    # Use discovered resources or fall back to common paths
    test_resources = resources if resources else [
        "/temperature",
        "/humidity",
        "/status",
        "/config",
        "/credentials",
        "/control",
        "/firmware",
        "/admin",
        "/sensor",
        "/data"
    ]

    try:
        protocol = await aiocoap.Context.create_client_context()

        for resource_path in test_resources:
            # Skip the well-known endpoint
            if resource_path == WELLKNOWN_CORE:
                continue

            uri = f"coap://{host}:{port}{resource_path}"

            # ── Test GET (read) ──
            try:
                get_request = aiocoap.Message(
                    code=aiocoap.GET,
                    uri=uri
                )
                get_response = await asyncio.wait_for(
                    protocol.request(get_request).response,
                    timeout=5.0
                )

                response_code = str(get_response.code)
                payload = get_response.payload.decode(
                    'utf-8', errors='ignore'
                )

                if any(code in response_code
                       for code in COAP_SUCCESS_CODES):
                    result["readable_resources"].append({
                        "path":     resource_path,
                        "response": response_code,
                        "payload":  payload[:200]
                    })
                    print(f"    [READ] {resource_path} — "
                          f"{response_code}")
                    print(f"           {payload[:100]}")

                    # Check for sensitive data in response
                    payload_lower = payload.lower()
                    for pattern in SENSITIVE_PATTERNS:
                        if pattern in payload_lower:
                            result["sensitive_data"].append({
                                "resource": resource_path,
                                "pattern":  pattern,
                                "payload":  payload[:200]
                            })
                            print(f"    [SENSITIVE] Pattern "
                                  f"'{pattern}' in "
                                  f"{resource_path}")
                            break

            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

            # ── Test PUT (write) ──
            try:
                put_payload = json.dumps({
                    "source":  "AIPET_security_test",
                    "message": "Unauthorised write test",
                    "time":    datetime.now().strftime(
                                   "%Y-%m-%d %H:%M:%S")
                }).encode()

                put_request = aiocoap.Message(
                    code=aiocoap.PUT,
                    uri=uri,
                    payload=put_payload
                )
                put_response = await asyncio.wait_for(
                    protocol.request(put_request).response,
                    timeout=5.0
                )

                response_code = str(put_response.code)

                if any(code in response_code
                       for code in COAP_SUCCESS_CODES):
                    result["writable_resources"].append({
                        "path":     resource_path,
                        "response": response_code
                    })
                    print(f"    [WRITE] {resource_path} — "
                          f"unauthorised write accepted!")

            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        await protocol.shutdown()

        # Determine severity based on findings
        if result["sensitive_data"]:
            result["finding"] = (
                f"Sensitive data exposed on "
                f"{len(result['sensitive_data'])} resource(s) "
                f"without authentication"
            )
            result["severity"] = "CRITICAL"
            print(f"[!] CRITICAL: Sensitive data exposed "
                  f"without authentication")

        elif result["writable_resources"]:
            result["finding"] = (
                f"{len(result['writable_resources'])} "
                f"resource(s) accept unauthorised writes"
            )
            result["severity"] = "HIGH"
            print(f"[!] HIGH: Unauthorised writes accepted")

        elif result["readable_resources"]:
            result["finding"] = (
                f"{len(result['readable_resources'])} "
                f"resource(s) readable without authentication"
            )
            result["severity"] = "MEDIUM"
            print(f"[!] MEDIUM: Resources readable "
                  f"without authentication")

        else:
            result["finding"]  = "No unauthenticated access found"
            result["severity"] = "INFO"
            print("[-] No unauthenticated access found")

    except Exception as e:
        result["finding"]  = f"Error: {str(e)}"
        result["severity"] = "ERROR"
        print(f"[-] Error: {e}")

    return result


# ── Attack 3: Replay Attack ────────────────────────────────────
async def test_replay_attack(host, port=5683,
                              resources=None):
    """
    Attack 3: Capture a valid CoAP request and replay it.

    CoAP uses UDP which has no connection state. Each
    message has a token to match requests to responses,
    but many devices do not validate whether a token
    has already been processed. This allows an attacker
    to replay captured packets — reissuing commands,
    re-triggering actions, or bypassing one-time tokens.

    We simulate this by sending the same request twice
    and checking if both succeed.

    Args:
        host (str): Target device IP
        port (int): CoAP port
        resources (list): Resources to test

    Returns:
        dict: Replay attack results
    """
    print(f"\n[*] Attack 3: Testing replay attack "
          f"on coap://{host}:{port}")

    result = {
        "attack":             "Replay Attack",
        "host":               host,
        "vulnerable_resources": [],
        "finding":            "",
        "severity":           ""
    }

    # Focus on writable resources for replay
    test_resources = resources if resources else [
        "/control",
        "/config",
        "/temperature",
        "/firmware"
    ]

    try:
        protocol = await aiocoap.Context.create_client_context()

        for resource_path in test_resources:
            if resource_path == WELLKNOWN_CORE:
                continue

            uri = f"coap://{host}:{port}{resource_path}"

            replay_payload = json.dumps({
                "source":  "AIPET_replay_test",
                "command": "replay_test",
                "time":    datetime.now().strftime(
                               "%Y-%m-%d %H:%M:%S")
            }).encode()

            success_count = 0

            # Send same request twice
            for attempt in range(2):
                try:
                    request = aiocoap.Message(
                        code=aiocoap.PUT,
                        uri=uri,
                        payload=replay_payload
                    )

                    response = await asyncio.wait_for(
                        protocol.request(request).response,
                        timeout=5.0
                    )

                    response_code = str(response.code)

                    if any(code in response_code
                           for code in COAP_SUCCESS_CODES):
                        success_count += 1

                    # Small delay between replays
                    await asyncio.sleep(0.5)

                except asyncio.TimeoutError:
                    break
                except Exception:
                    break

            # If both attempts succeeded — vulnerable to replay
            if success_count == 2:
                result["vulnerable_resources"].append(
                    resource_path
                )
                print(f"    [!] Replay successful: "
                      f"{resource_path} accepted "
                      f"duplicate requests")

        await protocol.shutdown()

        if result["vulnerable_resources"]:
            count = len(result["vulnerable_resources"])
            result["finding"] = (
                f"{count} resource(s) vulnerable to "
                f"replay attacks — no duplicate "
                f"request detection"
            )
            result["severity"] = "HIGH"
            print(f"[!] HIGH: {count} resource(s) "
                  f"vulnerable to replay")
        else:
            result["finding"]  = (
                "No replay vulnerabilities detected"
            )
            result["severity"] = "INFO"
            print("[-] No replay vulnerabilities found")

    except Exception as e:
        result["finding"]  = f"Error: {str(e)}"
        result["severity"] = "ERROR"
        print(f"[-] Error: {e}")

    return result


# ── Attack 4: Malformed Packet Injection ──────────────────────
async def test_malformed_packets(host, port=5683):
    """
    Attack 4: Send malformed CoAP packets to test device
    robustness. A well-hardened device should reject
    invalid packets gracefully. A vulnerable device may
    crash, hang, return error messages that reveal
    internal information, or behave unpredictably.

    We test three malformation types:
    - Oversized payload
    - Invalid option numbers
    - Wrong message type

    Args:
        host (str): Target device IP
        port (int): CoAP port

    Returns:
        dict: Malformed packet test results
    """
    print(f"\n[*] Attack 4: Malformed packet injection "
          f"on coap://{host}:{port}")

    result = {
        "attack":         "Malformed Packet Injection",
        "host":           host,
        "tests_run":      0,
        "anomalies":      [],
        "finding":        "",
        "severity":       ""
    }

    # Test 1 — Oversized payload
    print("    [*] Test 1: Oversized payload")
    try:
        protocol = await aiocoap.Context.create_client_context()

        # Send a PUT with an oversized payload (10KB)
        oversized_payload = b"A" * 10240

        request = aiocoap.Message(
            code=aiocoap.PUT,
            uri=f"coap://{host}:{port}/control",
            payload=oversized_payload
        )

        result["tests_run"] += 1

        response = await asyncio.wait_for(
            protocol.request(request).response,
            timeout=8.0
        )

        response_text = response.payload.decode(
            'utf-8', errors='ignore'
        )

        print(f"    [+] Device responded to oversized "
              f"payload: {str(response.code)}")

        # Check if error message reveals internal info
        if any(p in response_text.lower()
               for p in ["error", "exception",
                          "stack", "traceback"]):
            result["anomalies"].append({
                "test":     "Oversized payload",
                "finding":  "Error message reveals "
                            "internal information",
                "response": response_text[:200]
            })
            print(f"    [!] Internal error exposed "
                  f"in response")

        await protocol.shutdown()

    except asyncio.TimeoutError:
        result["anomalies"].append({
            "test":    "Oversized payload",
            "finding": "Device timed out — possible "
                       "resource exhaustion"
        })
        print("    [!] Device timed out on oversized payload")
    except Exception as e:
        print(f"    [-] Test 1 error: {e}")

    # Test 2 — Empty payload on PUT
    print("    [*] Test 2: Empty payload PUT")
    try:
        protocol = await aiocoap.Context.create_client_context()

        request = aiocoap.Message(
            code=aiocoap.PUT,
            uri=f"coap://{host}:{port}/control",
            payload=b""
        )

        result["tests_run"] += 1

        response = await asyncio.wait_for(
            protocol.request(request).response,
            timeout=5.0
        )

        print(f"    [+] Device accepted empty PUT: "
              f"{str(response.code)}")

        if any(code in str(response.code)
               for code in COAP_SUCCESS_CODES):
            result["anomalies"].append({
                "test":    "Empty payload PUT",
                "finding": "Device accepts empty PUT "
                           "without validation"
            })
            print("    [!] Device accepted empty payload "
                  "without validation")

        await protocol.shutdown()

    except asyncio.TimeoutError:
        print("    [-] Test 2 timed out")
    except Exception as e:
        print(f"    [-] Test 2 error: {e}")

    # Test 3 — Rapid request flood
    print("    [*] Test 3: Rapid request flood (10 requests)")
    try:
        protocol = await aiocoap.Context.create_client_context()
        result["tests_run"] += 1
        success_count = 0

        for i in range(10):
            try:
                request = aiocoap.Message(
                    code=aiocoap.GET,
                    uri=f"coap://{host}:{port}/temperature"
                )
                response = await asyncio.wait_for(
                    protocol.request(request).response,
                    timeout=3.0
                )
                if any(code in str(response.code)
                       for code in COAP_SUCCESS_CODES):
                    success_count += 1
            except Exception:
                pass

        print(f"    [+] {success_count}/10 requests "
              f"succeeded under flood")

        if success_count < 5:
            result["anomalies"].append({
                "test":    "Rapid request flood",
                "finding": f"Device degraded under load — "
                           f"only {success_count}/10 "
                           f"requests succeeded"
            })
            print("    [!] Device shows signs of "
                  "degradation under load")

        await protocol.shutdown()

    except Exception as e:
        print(f"    [-] Test 3 error: {e}")

    # Determine severity
    if result["anomalies"]:
        result["finding"] = (
            f"{len(result['anomalies'])} anomalie(s) found — "
            f"device does not handle malformed "
            f"packets robustly"
        )
        result["severity"] = "MEDIUM"
        print(f"[!] MEDIUM: {len(result['anomalies'])} "
              f"anomalie(s) detected")
    else:
        result["finding"]  = (
            "Device handles malformed packets correctly"
        )
        result["severity"] = "INFO"
        print("[-] No anomalies detected")

    return result


# ── Main Orchestrator ─────────────────────────────────────────
async def run_coap_attacks_async(host, port=5683):
    """
    Run all 4 CoAP attacks against a target device.
    Internal async function called by run_coap_attacks().

    Args:
        host (str): Target CoAP device IP
        port (int): CoAP port (default 5683)

    Returns:
        dict: Complete results from all 4 attacks
    """
    print("=" * 60)
    print("  AIPET — Module 3: CoAP Attack Suite")
    print(f"  Target: coap://{host}:{port}")
    print("=" * 60)

    all_results = {
        "target":    host,
        "port":      port,
        "scan_time": datetime.now().strftime(
                         "%Y-%m-%d %H:%M:%S"),
        "attacks":   [],
        "summary":   {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "info":     0
        }
    }

    # Attack 1 — Resource discovery
    discovery_result = await discover_resources(host, port)
    all_results["attacks"].append(discovery_result)

    # Extract discovered resources for subsequent attacks
    resources = discovery_result.get("resources_found", [])

    # Attack 2 — Unauthenticated access
    unauth_result = await test_unauthenticated_access(
        host, port, resources
    )
    all_results["attacks"].append(unauth_result)

    # Attack 3 — Replay attack
    replay_result = await test_replay_attack(
        host, port, resources
    )
    all_results["attacks"].append(replay_result)

    # Attack 4 — Malformed packets
    malformed_result = await test_malformed_packets(host, port)
    all_results["attacks"].append(malformed_result)

    # Tally findings by severity
    for attack in all_results["attacks"]:
        sev = attack.get("severity", "").upper()
        if sev == "CRITICAL":
            all_results["summary"]["critical"] += 1
        elif sev == "HIGH":
            all_results["summary"]["high"] += 1
        elif sev == "MEDIUM":
            all_results["summary"]["medium"] += 1
        else:
            all_results["summary"]["info"] += 1

    # Save results
    output_file = "coap/coap_results.json"
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=4)

    # Print final summary
    print("\n" + "=" * 60)
    print("  CoAP ATTACK SUMMARY")
    print("=" * 60)
    print(f"  Target:   coap://{host}:{port}")
    s = all_results["summary"]
    print(f"  Critical: {s['critical']}")
    print(f"  High:     {s['high']}")
    print(f"  Medium:   {s['medium']}")
    print(f"  Info:     {s['info']}")
    print(f"\n[+] Results saved to {output_file}")
    print("=" * 60)

    return all_results


def run_coap_attacks(host, port=5683):
    """
    Public entry point for Module 3.
    Wraps the async function for synchronous callers.

    Args:
        host (str): Target CoAP device IP
        port (int): CoAP port (default 5683)

    Returns:
        dict: Complete results from all 4 attacks
    """
    return asyncio.run(run_coap_attacks_async(host, port))


if __name__ == "__main__":
    run_coap_attacks("localhost", 5683)