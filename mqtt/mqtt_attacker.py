# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 2: MQTT Attack Suite
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Tests MQTT brokers for authentication bypass,
#              topic enumeration, message injection, and
#              sensitive data exposure.
#              Uses paho-mqtt CallbackAPIVersion.VERSION2
# =============================================================

import paho.mqtt.client as mqtt
import json
import time
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────
LISTEN_TIMEOUT = 5

DEFAULT_CREDENTIALS = [
    ("",        ""),
    ("admin",   "admin"),
    ("admin",   "password"),
    ("admin",   "1234"),
    ("admin",   ""),
    ("root",    "root"),
    ("root",    "password"),
    ("root",    ""),
    ("mqtt",    "mqtt"),
    ("mqtt",    "password"),
    ("guest",   "guest"),
    ("user",    "user"),
    ("test",    "test"),
    ("pi",      "raspberry"),
    ("ubnt",    "ubnt"),
    ("admin",   "admin123"),
    ("support", "support"),
]

SENSITIVE_PATTERNS = [
    "password", "passwd", "pwd", "secret",
    "token", "key", "api_key", "apikey",
    "credential", "auth", "login",
    "ssn", "credit", "card",
    "location", "gps", "latitude", "longitude",
    "heartrate", "heart_rate", "bloodpressure",
    "temperature", "patient", "medical",
    "command", "cmd", "execute", "control",
    "admin", "root", "sudo",
]

# Global message store — shared across callback threads
captured_messages = []


# ── Attack 1: Connection Test ──────────────────────────────────
def test_connection(host, port=1883):
    """
    Test if MQTT broker accepts anonymous connections.

    Args:
        host (str): Target broker IP
        port (int): MQTT port (default 1883)

    Returns:
        dict: Connection test results
    """
    print(f"\n[*] Attack 1: Testing connection to {host}:{port}")

    result = {
        "attack":        "Connection Test",
        "host":          host,
        "port":          port,
        "connected":     False,
        "auth_required": False,
        "finding":       "",
        "severity":      ""
    }

    connect_result = {"code": None, "failed": False}

    def on_connect(client, userdata, flags,
                   reason_code, properties):
        """
        VERSION2 callback — reason_code is an object.
        reason_code.is_failure = True if connection failed.
        reason_code.value = numeric code for the reason.
        """
        if reason_code.is_failure:
            connect_result["failed"] = True
            connect_result["code"]   = reason_code.value
        else:
            connect_result["code"]   = 0

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="AIPET_recon",
        protocol=mqtt.MQTTv311
    )
    client.on_connect = on_connect

    try:
        client.connect(host, port, keepalive=10)
        client.loop_start()

        # Wait up to 5 seconds for connection result
        timeout = 5.0
        while connect_result["code"] is None and timeout > 0:
            time.sleep(0.5)
            timeout -= 0.5

        client.loop_stop()
        client.disconnect()

        if connect_result["code"] == 0:
            result["connected"]     = True
            result["auth_required"] = False
            result["finding"]       = (
                "BROKER ACCEPTS ANONYMOUS CONNECTIONS — "
                "No authentication required"
            )
            result["severity"] = "CRITICAL"
            print("[!] CRITICAL: Broker accepts anonymous "
                  "connections — no authentication required")

        elif connect_result.get("failed"):
            result["connected"]     = False
            result["auth_required"] = True
            result["finding"]       = (
                "Broker requires authentication — "
                "attempting credential attacks"
            )
            result["severity"] = "INFO"
            print("[+] Broker requires authentication")

        else:
            result["finding"]  = (
                f"Connection failed — "
                f"code {connect_result['code']}"
            )
            result["severity"] = "INFO"
            print(f"[-] Connection failed "
                  f"(code {connect_result['code']})")

    except Exception as e:
        result["finding"]  = f"Connection error: {str(e)}"
        result["severity"] = "ERROR"
        print(f"[-] Connection error: {e}")

    return result


# ── Attack 2: Topic Enumeration ────────────────────────────────
def enumerate_topics(host, port=1883,
                     username="", password="",
                     listen_time=LISTEN_TIMEOUT):
    """
    Subscribe to wildcard '#' and capture all messages
    flowing through the broker.

    Args:
        host (str): Target broker IP
        port (int): MQTT port
        username (str): Username if auth required
        password (str): Password if auth required
        listen_time (int): Seconds to listen

    Returns:
        dict: Enumeration results with captured topics
    """
    print(f"\n[*] Attack 2: Enumerating topics on {host}:{port}")
    print(f"    Listening for {listen_time} seconds...")

    result = {
        "attack":        "Topic Enumeration",
        "host":          host,
        "topics_found":  [],
        "message_count": 0,
        "finding":       "",
        "severity":      ""
    }

    discovered_topics = []
    message_count     = [0]

    def on_connect(client, userdata, flags,
                   reason_code, properties):
        if not reason_code.is_failure:
            # Subscribe to ALL topics using wildcard
            client.subscribe("#")
            print("    [+] Subscribed to all topics (#)")

    def on_message(client, userdata, msg):
        topic   = msg.topic
        payload = msg.payload.decode('utf-8', errors='ignore')
        message_count[0] += 1

        if topic not in discovered_topics:
            discovered_topics.append(topic)
            print(f"    [TOPIC] {topic}")

        # Check for sensitive patterns
        payload_lower = payload.lower()
        for pattern in SENSITIVE_PATTERNS:
            if pattern in payload_lower:
                print(f"    [SENSITIVE] Topic: {topic} "
                      f"contains pattern: '{pattern}'")
                break

        captured_messages.append({
            "topic":     topic,
            "payload":   payload,
            "timestamp": datetime.now().strftime(
                             "%Y-%m-%d %H:%M:%S")
        })

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="AIPET_enum",
        protocol=mqtt.MQTTv311
    )
    client.on_connect = on_connect
    client.on_message = on_message

    if username:
        client.username_pw_set(username, password)

    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        time.sleep(listen_time)
        client.loop_stop()
        client.disconnect()

        result["topics_found"]  = discovered_topics
        result["message_count"] = message_count[0]

        if discovered_topics:
            result["finding"] = (
                f"Discovered {len(discovered_topics)} topic(s), "
                f"captured {message_count[0]} message(s)"
            )
            result["severity"] = "HIGH"
            print(f"[!] Found {len(discovered_topics)} topic(s), "
                  f"{message_count[0]} message(s) captured")
        else:
            result["finding"]  = "No messages captured in window"
            result["severity"] = "INFO"
            print("[-] No messages captured")

    except Exception as e:
        result["finding"]  = f"Error: {str(e)}"
        result["severity"] = "ERROR"
        print(f"[-] Error: {e}")

    return result


# ── Attack 3: Authentication Bypass ───────────────────────────
def test_auth_bypass(host, port=1883):
    """
    Attempt authentication bypass using common default
    credentials found on IoT MQTT brokers.

    Args:
        host (str): Target broker IP
        port (int): MQTT port

    Returns:
        dict: Auth bypass results
    """
    print(f"\n[*] Attack 3: Testing authentication bypass "
          f"on {host}:{port}")

    result = {
        "attack":            "Authentication Bypass",
        "host":              host,
        "credentials_tried": 0,
        "bypass_found":      False,
        "valid_credentials": [],
        "finding":           "",
        "severity":          ""
    }

    for username, password in DEFAULT_CREDENTIALS:
        result["credentials_tried"] += 1

        display_user = username if username else "(empty)"
        display_pass = password if password else "(empty)"
        print(f"    [*] Trying: {display_user} / {display_pass}")

        connect_code = [None]

        def on_connect(client, userdata, flags,
                       reason_code, properties):
            if reason_code.is_failure:
                connect_code[0] = reason_code.value
            else:
                connect_code[0] = 0

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"AIPET_auth_{result['credentials_tried']}",
            protocol=mqtt.MQTTv311
        )
        client.on_connect = on_connect

        if username:
            client.username_pw_set(username, password)

        try:
            client.connect(host, port, keepalive=5)
            client.loop_start()

            timeout = 3.0
            while connect_code[0] is None and timeout > 0:
                time.sleep(0.3)
                timeout -= 0.3

            client.loop_stop()
            client.disconnect()

            if connect_code[0] == 0:
                print(f"    [!] VALID: {display_user} / "
                      f"{display_pass}")
                result["bypass_found"] = True
                result["valid_credentials"].append({
                    "username": username,
                    "password": password
                })

        except Exception:
            pass

        time.sleep(0.2)

    if result["bypass_found"]:
        count = len(result["valid_credentials"])
        result["finding"] = (
            f"Authentication bypass successful — "
            f"{count} valid credential set(s) found"
        )
        result["severity"] = "CRITICAL"
        print(f"[!] CRITICAL: Found {count} valid "
              f"credential set(s)")
    else:
        result["finding"]  = (
            f"No default credentials worked from "
            f"{result['credentials_tried']} attempts"
        )
        result["severity"] = "INFO"
        print("[-] No default credentials worked")

    return result


# ── Attack 4: Message Injection ────────────────────────────────
def inject_message(host, port=1883,
                   username="", password="",
                   topics=None):
    """
    Publish unauthorised messages to discovered topics
    to test if the broker validates message sources.

    Args:
        host (str): Target broker IP
        port (int): MQTT port
        username (str): Valid username if found
        password (str): Valid password if found
        topics (list): Topics from enumeration

    Returns:
        dict: Injection test results
    """
    print(f"\n[*] Attack 4: Testing message injection "
          f"on {host}:{port}")

    result = {
        "attack":                "Message Injection",
        "host":                  host,
        "injections_attempted":  0,
        "injections_successful": 0,
        "finding":               "",
        "severity":              ""
    }

    test_topics = topics if topics else [
        "test/aipet",
        "home/control",
        "device/command",
        "sensor/data"
    ]

    connect_code = [None]

    def on_connect(client, userdata, flags,
                   reason_code, properties):
        if reason_code.is_failure:
            connect_code[0] = reason_code.value
        else:
            connect_code[0] = 0

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="AIPET_inject",
        protocol=mqtt.MQTTv311
    )
    client.on_connect = on_connect

    if username:
        client.username_pw_set(username, password)

    try:
        client.connect(host, port, keepalive=10)
        client.loop_start()

        timeout = 5.0
        while connect_code[0] is None and timeout > 0:
            time.sleep(0.5)
            timeout -= 0.5

        if connect_code[0] == 0:
            for topic in test_topics[:5]:
                test_payload = json.dumps({
                    "source":    "AIPET_security_test",
                    "message":   "AIPET unauthorised injection test",
                    "timestamp": datetime.now().strftime(
                                     "%Y-%m-%d %H:%M:%S"),
                    "warning":   "Broker does not validate "
                                 "message sources"
                })

                info = client.publish(topic, test_payload)
                result["injections_attempted"] += 1

                if info.rc == 0:
                    result["injections_successful"] += 1
                    print(f"    [!] Injected to: {topic}")

        client.loop_stop()
        client.disconnect()

    except Exception as e:
        result["finding"]  = f"Error: {str(e)}"
        result["severity"] = "ERROR"
        return result

    if result["injections_successful"] > 0:
        result["finding"] = (
            f"Message injection successful — "
            f"{result['injections_successful']} message(s) "
            f"injected without authorisation"
        )
        result["severity"] = "HIGH"
        print(f"[!] HIGH: {result['injections_successful']} "
              f"message(s) injected successfully")
    else:
        result["finding"]  = "Message injection blocked"
        result["severity"] = "INFO"
        print("[-] Message injection blocked")

    return result


# ── Attack 5: Sensitive Data Harvester ────────────────────────
def harvest_sensitive_data(host, port=1883,
                           username="", password="",
                           listen_time=LISTEN_TIMEOUT):
    """
    Monitor all MQTT topics for sensitive data patterns —
    credentials, personal data, commands, location data.

    Args:
        host (str): Target broker IP
        port (int): MQTT port
        username (str): Valid username if found
        password (str): Valid password if found
        listen_time (int): Seconds to monitor

    Returns:
        dict: Sensitive data findings
    """
    print(f"\n[*] Attack 5: Harvesting sensitive data "
          f"from {host}:{port}")
    print(f"    Monitoring for {listen_time} seconds...")

    result = {
        "attack":          "Sensitive Data Harvest",
        "host":            host,
        "sensitive_found": [],
        "finding":         "",
        "severity":        ""
    }

    def on_connect(client, userdata, flags,
                   reason_code, properties):
        if not reason_code.is_failure:
            client.subscribe("#")

    def on_message(client, userdata, msg):
        topic         = msg.topic
        payload       = msg.payload.decode('utf-8', errors='ignore')
        payload_lower = payload.lower()

        for pattern in SENSITIVE_PATTERNS:
            if pattern in payload_lower:
                finding = {
                    "topic":     topic,
                    "pattern":   pattern,
                    "payload":   payload[:200],
                    "timestamp": datetime.now().strftime(
                                     "%Y-%m-%d %H:%M:%S")
                }
                result["sensitive_found"].append(finding)
                print(f"    [SENSITIVE] Pattern '{pattern}' "
                      f"found in topic: {topic}")
                break

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="AIPET_harvest",
        protocol=mqtt.MQTTv311
    )
    client.on_connect = on_connect
    client.on_message = on_message

    if username:
        client.username_pw_set(username, password)

    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        time.sleep(listen_time)
        client.loop_stop()
        client.disconnect()

    except Exception as e:
        result["finding"]  = f"Error: {str(e)}"
        result["severity"] = "ERROR"
        return result

    if result["sensitive_found"]:
        count = len(result["sensitive_found"])
        result["finding"] = (
            f"{count} sensitive data pattern(s) found "
            f"in MQTT traffic"
        )
        result["severity"] = "CRITICAL"
        print(f"[!] CRITICAL: {count} sensitive pattern(s) found")
    else:
        result["finding"]  = "No sensitive patterns detected"
        result["severity"] = "INFO"
        print("[-] No sensitive patterns detected")

    return result


# ── Main Orchestrator ─────────────────────────────────────────

def scan_retained_messages(host, port=1883,
                           username=None, password=None):
    """
    Attack 6: Scan for MQTT retained messages.

    Retained messages are stored by the broker permanently
    and delivered immediately to any new subscriber.
    Devices may have published sensitive data in the past
    that is still stored on the broker — even if no device
    is currently active.

    This attack subscribes to all topics with the retained
    flag and collects any stored messages immediately.

    Args:
        host (str): MQTT broker hostname or IP
        port (int): MQTT broker port
        username (str): Optional username
        password (str): Optional password

    Returns:
        dict: Retained message scan results
    """
    print(f"\n[*] Attack 6: Scanning for retained messages "
          f"on {host}:{port}")

    result = {
        "attack":            "Retained Message Scanner",
        "target":            f"{host}:{port}",
        "retained_messages": [],
        "sensitive_found":   False,
        "finding":           "",
        "severity":          ""
    }

    retained_messages = []
    connected = [False]
    scan_complete = [False]

    def on_connect(client, userdata, flags,
                   reason_code, properties):
        if not reason_code.is_failure:
            connected[0] = True
            # Subscribe to all topics — retained messages
            # are delivered immediately on subscription
            client.subscribe("#", qos=0)
            print("    [+] Subscribed — collecting "
                  "retained messages...")
        else:
            print(f"    [-] Connection failed: {reason_code}")

    def on_message(client, userdata, message):
        # Check if this is a retained message
        if message.retain:
            payload = ""
            try:
                payload = message.payload.decode(
                    'utf-8', errors='ignore'
                )
            except Exception:
                payload = str(message.payload[:100])

            retained_messages.append({
                "topic":   message.topic,
                "payload": payload[:200],
                "qos":     message.qos,
                "retain":  True
            })

            # Check for sensitive patterns
            sensitive_hit = any(
                keyword in payload.lower()
                for keyword in SENSITIVE_PATTERNS
            )

            if sensitive_hit:
                result["sensitive_found"] = True
                print(f"    [!] RETAINED+SENSITIVE: "
                      f"{message.topic}")
                print(f"        Payload: {payload[:80]}")
            else:
                print(f"    [+] Retained: {message.topic} "
                      f"({len(payload)} bytes)")

    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2
        )
        client.on_connect = on_connect
        client.on_message = on_message

        if username:
            client.username_pw_set(username, password)

        client.connect(host, port, keepalive=10)
        client.loop_start()

        # Wait for connection
        timeout = 5
        start = time.time()
        while not connected[0] and                 time.time() - start < timeout:
            time.sleep(0.1)

        if connected[0]:
            # Wait to collect retained messages
            # They arrive immediately after subscription
            time.sleep(3)

        client.loop_stop()
        client.disconnect()

    except Exception as e:
        result["finding"]  = f"Scan error: {str(e)}"
        result["severity"] = "ERROR"
        return result

    # Store results
    result["retained_messages"] = retained_messages
    count = len(retained_messages)

    if count > 0:
        if result["sensitive_found"]:
            result["finding"] = (
                f"Found {count} retained message(s) — "
                f"sensitive data present in stored messages"
            )
            result["severity"] = "CRITICAL"
            print(f"[!] CRITICAL: {count} retained "
                  f"message(s) with sensitive data")
        else:
            result["finding"] = (
                f"Found {count} retained message(s) — "
                f"historical data stored on broker"
            )
            result["severity"] = "HIGH"
            print(f"[!] HIGH: {count} retained message(s) found")
    else:
        result["finding"]  = "No retained messages found"
        result["severity"] = "INFO"
        print("[-] No retained messages found")

    return result

def run_mqtt_attacks(host, port=1883):
    """
    Run all 5 MQTT attacks against a target broker.
    This is the main entry point for Module 2.

    Attack order:
        1. Connection test
        3. Auth bypass (before enumeration — need credentials)
        2. Topic enumeration
        4. Message injection
        5. Sensitive data harvest

    Args:
        host (str): Target MQTT broker IP
        port (int): MQTT port (default 1883)

    Returns:
        dict: Complete results from all 5 attacks
    """
    print("=" * 60)
    print("  AIPET — Module 2: MQTT Attack Suite")
    print(f"  Target: {host}:{port}")
    print("=" * 60)

    all_results = {
        "target":    host,
        "port":      port,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacks":   [],
        "summary":   {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "info":     0
        }
    }

    # Attack 1 — Connection test
    conn_result = test_connection(host, port)
    all_results["attacks"].append(conn_result)

    # Stop if we cannot connect at all
    if not conn_result["connected"]:
        print("\n[-] Cannot connect to broker. Stopping.")
        return all_results

    # Attack 3 — Auth bypass first so we have credentials
    #             for subsequent attacks
    auth_result = test_auth_bypass(host, port)
    all_results["attacks"].append(auth_result)

    # Use first valid credentials found (empty = anonymous)
    username = ""
    password = ""
    if auth_result["bypass_found"]:
        creds    = auth_result["valid_credentials"][0]
        username = creds["username"]
        password = creds["password"]

    # Attack 2 — Topic enumeration with credentials
    enum_result = enumerate_topics(
        host, port, username, password
    )
    all_results["attacks"].append(enum_result)

    # Use discovered topics for injection
    topics = enum_result.get("topics_found", [])

    # Attack 4 — Message injection
    inject_result = inject_message(
        host, port, username, password, topics
    )
    all_results["attacks"].append(inject_result)

    # Attack 5 — Sensitive data harvest
    harvest_result = harvest_sensitive_data(
        host, port, username, password
    )
    all_results["attacks"].append(harvest_result)
    # Attack 6 — Retained message scanner
    retained_result = scan_retained_messages(
        host, port, username, password
    )
    all_results["attacks"].append(retained_result)

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

    # Save results to JSON
    output_file = "mqtt/mqtt_results.json"
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=4)

    # Print final summary
    print("\n" + "=" * 60)
    print("  MQTT ATTACK SUMMARY")
    print("=" * 60)
    print(f"  Target:   {host}:{port}")
    s = all_results["summary"]
    print(f"  Critical: {s['critical']}")
    print(f"  High:     {s['high']}")
    print(f"  Medium:   {s['medium']}")
    print(f"  Info:     {s['info']}")
    print(f"\n[+] Results saved to {output_file}")
    print("=" * 60)

    return all_results


if __name__ == "__main__":
    run_mqtt_attacks("localhost", 1883)