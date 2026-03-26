# =============================================================
# AIPET — Virtual IoT Lab
# CoAP Test Server — Simulates a vulnerable IoT device
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Deliberately vulnerable CoAP server for
#              testing AIPET Module 3 attacks.
#              Simulates a real IoT sensor device.
# WARNING: For isolated lab use only — never expose
#          this server on a real network
# =============================================================

import asyncio
import aiocoap
import aiocoap.resource as resource
import logging

# Enable logging so we can see incoming requests
logging.basicConfig(level=logging.INFO)


# ── Resource 1: Temperature Sensor ───────────────────────────
class TemperatureResource(resource.Resource):
    """
    Simulates an IoT temperature sensor.
    Deliberately has no authentication — any client
    can read the temperature value.
    """

    def __init__(self):
        super().__init__()
        self.temperature = "22.5"

    async def render_get(self, request):
        """Respond to GET requests with temperature value."""
        payload = (
            f"temperature={self.temperature}C,"
            f"unit=celsius,"
            f"location=server_room"
        ).encode()
        return aiocoap.Message(payload=payload)

    async def render_put(self, request):
        """
        Accept PUT requests to change temperature threshold.
        No authentication — deliberately vulnerable.
        """
        new_value = request.payload.decode()
        self.temperature = new_value
        return aiocoap.Message(
            code=aiocoap.CHANGED,
            payload=f"Temperature updated to {new_value}".encode()
        )


# ── Resource 2: Device Credentials ───────────────────────────
class CredentialsResource(resource.Resource):
    """
    Simulates a poorly designed IoT device that exposes
    its configuration including credentials over CoAP.
    This is a common real-world misconfiguration.
    """

    async def render_get(self, request):
        """Return device configuration — including credentials."""
        payload = (
            "device_id=IoT_SENSOR_001,"
            "admin_user=admin,"
            "admin_password=admin123,"
            "api_key=SECRET_API_KEY_12345,"
            "firmware=v1.2.3"
        ).encode()
        return aiocoap.Message(payload=payload)


# ── Resource 3: Device Control ────────────────────────────────
class ControlResource(resource.Resource):
    """
    Simulates device control endpoint.
    Accepts commands without authentication.
    """

    def __init__(self):
        super().__init__()
        self.status = "active"

    async def render_get(self, request):
        payload = f"status={self.status}".encode()
        return aiocoap.Message(payload=payload)

    async def render_put(self, request):
        """Accept control commands without authentication."""
        command = request.payload.decode()
        self.status = command
        return aiocoap.Message(
            code=aiocoap.CHANGED,
            payload=f"Command executed: {command}".encode()
        )


# ── Resource 4: Firmware Info ─────────────────────────────────
class FirmwareResource(resource.Resource):
    """
    Exposes firmware version and update URL.
    Real devices often expose this — attackers use it
    to find known CVEs for the firmware version.
    """

    async def render_get(self, request):
        payload = (
            "firmware_version=1.2.3,"
            "model=SmartSensor-X100,"
            "manufacturer=VulnTech,"
            "update_url=http://update.vulntech.com/firmware"
        ).encode()
        return aiocoap.Message(payload=payload)


# ── Server Setup ──────────────────────────────────────────────
async def main():
    """
    Start the vulnerable CoAP test server on port 5683.
    Registers all resources at their CoAP paths.
    """
    # Build the resource tree
    root = resource.Site()

    # Standard CoAP discovery endpoint
    # /.well-known/core lists all available resources
    root.add_resource(
        ['.well-known', 'core'],
        resource.WKCResource(
            root.get_resources_as_linkheader
        )
    )

    # Add our vulnerable resources
    root.add_resource(['temperature'],  TemperatureResource())
    root.add_resource(['credentials'],  CredentialsResource())
    root.add_resource(['control'],      ControlResource())
    root.add_resource(['firmware'],     FirmwareResource())

    print("=" * 60)
    print("  AIPET — Vulnerable CoAP Test Server")
    print("  Listening on coap://localhost:5683")
    print("=" * 60)
    print("  Resources available:")
    print("  coap://localhost:5683/temperature")
    print("  coap://localhost:5683/credentials")
    print("  coap://localhost:5683/control")
    print("  coap://localhost:5683/firmware")
    print("  coap://localhost:5683/.well-known/core")
    print("=" * 60)
    print("  WARNING: Deliberately vulnerable — lab use only")
    print("=" * 60)

    # Start the server
    await aiocoap.Context.create_server_context(
        root,
        bind=('localhost', 5683)
    )

    # Run forever
    await asyncio.get_event_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
    