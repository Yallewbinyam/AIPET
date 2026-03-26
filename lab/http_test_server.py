# =============================================================
# AIPET — Virtual IoT Lab
# HTTP Test Server — Simulates a vulnerable IoT web interface
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Deliberately vulnerable HTTP server simulating
#              a real IoT device web interface.
#              Includes admin panel, API, and config pages.
# WARNING: For isolated lab use only
# =============================================================

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

# ── Simulated device data ─────────────────────────────────────
DEVICE_CONFIG = {
    "device_id":      "SmartSensor-X100",
    "firmware":       "1.2.3",
    "admin_user":     "admin",
    "admin_password": "admin123",
    "api_key":        "SECRET_API_KEY_12345",
    "wifi_ssid":      "HomeNetwork",
    "wifi_password":  "wifipass123",
    "mqtt_broker":    "192.168.1.100",
    "mqtt_port":      "1883",
}

SENSOR_DATA = {
    "temperature": "22.5",
    "humidity":    "65",
    "pressure":    "1013",
    "location":    "server_room",
    "status":      "active",
}

# Valid session tokens (simulated)
VALID_SESSIONS = set()


class IoTWebHandler(BaseHTTPRequestHandler):
    """
    Handles all HTTP requests to the vulnerable IoT web server.
    Implements common IoT web interface patterns including
    admin panels, REST APIs, and configuration pages.
    """

    def log_message(self, format, *args):
        """Override to show clean request logs."""
        print(f"    [REQUEST] {self.command} "
              f"{self.path} — {args[1]}")

    def send_json(self, data, status=200):
        """Helper to send JSON responses."""
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=200):
        """Helper to send HTML responses."""
        body = html.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def get_post_data(self):
        """Read POST body data."""
        length = int(
            self.headers.get('Content-Length', 0)
        )
        return self.rfile.read(length).decode()

    def do_GET(self):
        """Handle all GET requests."""
        path = self.path.split('?')[0]

        # Home page
        if path == '/' or path == '/index.html':
            self.send_html("""
<html><body>
<h1>SmartSensor-X100 Web Interface</h1>
<p>Firmware: 1.2.3 | Model: SmartSensor-X100</p>
<a href='/admin'>Admin Panel</a> |
<a href='/status'>Device Status</a> |
<a href='/config'>Configuration</a>
</body></html>""")

        # Admin panel — no authentication required
        elif path == '/admin':
            self.send_html(f"""
<html><body>
<h1>Admin Panel</h1>
<p>Welcome admin — full device control</p>
<p>Device ID: {DEVICE_CONFIG['device_id']}</p>
<p>Firmware: {DEVICE_CONFIG['firmware']}</p>
<form method='POST' action='/admin/login'>
Username: <input name='username' value='admin'><br>
Password: <input name='password' type='password'><br>
<input type='submit' value='Login'>
</form>
</body></html>""")

        # Status page — exposes sensitive data
        elif path == '/status':
            self.send_json({
                "device":      DEVICE_CONFIG['device_id'],
                "firmware":    DEVICE_CONFIG['firmware'],
                "temperature": SENSOR_DATA['temperature'],
                "humidity":    SENSOR_DATA['humidity'],
                "location":    SENSOR_DATA['location'],
                "mqtt_broker": DEVICE_CONFIG['mqtt_broker'],
                "api_key":     DEVICE_CONFIG['api_key'],
            })

        # Config page — exposes ALL credentials
        elif path == '/config':
            self.send_json(DEVICE_CONFIG)

        # Backup file — common IoT misconfiguration
        elif path == '/config.bak':
            self.send_json(DEVICE_CONFIG)

        # Firmware info
        elif path == '/firmware':
            self.send_json({
                "version":      DEVICE_CONFIG['firmware'],
                "model":        DEVICE_CONFIG['device_id'],
                "update_url":   "http://update.vulntech.com",
                "last_updated": "2021-03-15"
            })

        # API endpoint — no auth
        elif path == '/api/v1/sensors':
            self.send_json(SENSOR_DATA)

        # API credentials endpoint
        elif path == '/api/v1/config':
            self.send_json(DEVICE_CONFIG)

        # Hidden diagnostic page
        elif path == '/diag':
            self.send_json({
                "cpu":      "45%",
                "memory":   "62%",
                "uptime":   "15 days",
                "password": DEVICE_CONFIG['admin_password'],
                "api_key":  DEVICE_CONFIG['api_key'],
            })

        # Setup page
        elif path == '/setup':
            self.send_html("""
<html><body>
<h1>Device Setup</h1>
<p>Initial configuration page — no auth required</p>
</body></html>""")

        # Management interface
        elif path == '/management':
            self.send_json({
                "status":   "management interface active",
                "password": DEVICE_CONFIG['admin_password']
            })

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle all POST requests."""
        path = self.path
        data = self.get_post_data()

        # Admin login — accepts default credentials
        if path == '/admin/login':
            params = urllib.parse.parse_qs(data)
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]

            if (username == DEVICE_CONFIG['admin_user'] and
                    password == DEVICE_CONFIG['admin_password']):
                self.send_json({
                    "status":  "success",
                    "message": "Login successful",
                    "token":   "SESSION_TOKEN_12345",
                    "role":    "admin"
                })
            else:
                self.send_json({
                    "status":  "error",
                    "message": "Invalid credentials"
                }, status=401)

        # API control endpoint — no auth
        elif path == '/api/v1/control':
            self.send_json({
                "status":  "command accepted",
                "payload": data
            })

        else:
            self.send_response(404)
            self.end_headers()


def run_server(port=8080):
    """Start the vulnerable IoT HTTP test server."""
    server = HTTPServer(('localhost', port), IoTWebHandler)

    print("=" * 60)
    print("  AIPET — Vulnerable IoT HTTP Test Server")
    print(f"  Listening on http://localhost:{port}")
    print("=" * 60)
    print("  Endpoints available:")
    print(f"  http://localhost:{port}/")
    print(f"  http://localhost:{port}/admin")
    print(f"  http://localhost:{port}/status")
    print(f"  http://localhost:{port}/config")
    print(f"  http://localhost:{port}/config.bak")
    print(f"  http://localhost:{port}/firmware")
    print(f"  http://localhost:{port}/api/v1/sensors")
    print(f"  http://localhost:{port}/api/v1/config")
    print(f"  http://localhost:{port}/diag")
    print(f"  http://localhost:{port}/setup")
    print(f"  http://localhost:{port}/management")
    print("=" * 60)
    print("  WARNING: Deliberately vulnerable — lab use only")
    print("=" * 60)

    server.serve_forever()


if __name__ == "__main__":
    run_server(8080)