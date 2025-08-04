#!/usr/bin/env python3
"""
FLARE LSMA Synchronization Module
==================================
- Handles validated alert messages from P4-SFFP + AFAC
- Synchronizes urgent alerts across multiple controllers
- Uses secure TLS channels for routine and urgent pathways
- For Java controllers (Beacon, ODL, Floodlight), use compatible gRPC server.
"""

import asyncio
import ssl
import json
import logging
import datetime

import jsonschema

# Load JSON schema to validate alerts
with open('runtime/flare_alert.json') as f:
    ALERT_SCHEMA = json.load(f)

# Secure channel configuration (matches controller_config.yaml)
ROUTINE_HOST = '127.0.0.100'
ROUTINE_PORT = 6000
ROUTINE_CERT = 'certs/routine_cert.pem'
ROUTINE_KEY = 'certs/routine_key.pem'

URGENT_HOST = '127.0.0.100'
URGENT_PORT = 6001
URGENT_CERT = 'certs/urgent_cert.pem'
URGENT_KEY = 'certs/urgent_key.pem'

logging.basicConfig(level=logging.INFO)


async def send_over_secure_channel(host, port, cert, key, alert_data):
    """Send alert JSON over TLS to remote coordination engine or controller."""
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.load_cert_chain(certfile=cert, keyfile=key)

    reader, writer = await asyncio.open_connection(
        host, port, ssl=ssl_ctx
    )

    writer.write(json.dumps(alert_data).encode('utf-8'))
    await writer.drain()

    logging.info(f"Alert sent to {host}:{port}: {alert_data['alert_id']}")

    writer.close()
    await writer.wait_closed()


async def handle_alert(alert_data):
    """Validate, tag, and dispatch an alert to appropriate pathway."""
    # Validate with JSON Schema
    jsonschema.validate(alert_data, ALERT_SCHEMA)
    logging.info(f"✅ Validated alert: {alert_data['alert_id']}")

    # Example logic: high risk if confidence > 0.9 + frag or RST
    high_risk = alert_data['classifier_confidence'] > 0.9 or alert_data['flags']['FRAG'] or alert_data['flags']['RST']

    if high_risk:
        logging.info(f"🚨 Urgent alert: {alert_data['alert_id']}")
        await send_over_secure_channel(URGENT_HOST, URGENT_PORT, URGENT_CERT, URGENT_KEY, alert_data)
    else:
        logging.info(f"ℹ️ Routine alert: {alert_data['alert_id']}")
        await send_over_secure_channel(ROUTINE_HOST, ROUTINE_PORT, ROUTINE_CERT, ROUTINE_KEY, alert_data)


async def main():
    """Example usage: fake incoming alert loop for test."""
    while True:
        fake_alert = {
            "alert_id": "test-" + datetime.datetime.utcnow().isoformat(),
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.101",
            "destination_ip": "10.0.0.5",
            "protocol": "TCP",
            "flags": {
                "RST": True,
                "FIN": False,
                "SYN": False,
                "FRAG": False
            },
            "classifier_confidence": 0.95,
            "recommended_action": "RATE_LIMIT"
        }

        await handle_alert(fake_alert)
        await asyncio.sleep(10)  # Simulate incoming alerts every 10 sec


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopped LSMA sync module.")
