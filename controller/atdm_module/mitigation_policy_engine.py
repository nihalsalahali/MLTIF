#!/usr/bin/env python3
"""
FLARE MLDFM Mitigation Policy Engine
======================================
- Loads thresholds & policies from mldfm_policy.yaml
- Receives classified alerts (flare_alert.json)
- Decides mitigation actions
- Calls relevant action modules (rate limit, drop frag, flush state)
"""

import yaml
import logging
import time

from actions import rate_limit, drop_frag, flush_state

logging.basicConfig(level=logging.INFO)

POLICY_FILE = "configs/mldfm_policy.yaml"


def load_policy():
    with open(POLICY_FILE) as f:
        return yaml.safe_load(f)


def handle_alert(alert, policy):
    """
    Decide mitigation based on alert and loaded policy.
    """
    flags = alert['flags']
    action_taken = []

    if flags['RST']:
        logging.info("🚨 RST flag detected")
        for p in policy['policies']:
            if p['action'] == "RATE_LIMIT_FLAG" and p['flag'] == "RST":
                rate_limit.apply(p['flag'], p['rate'])
                action_taken.append(f"Rate limit RST @ {p['rate']}")

    if flags['FRAG']:
        logging.info("🚨 Fragment detected")
        for p in policy['policies']:
            if p['action'] == "DROP_FRAGMENT":
                drop_frag.apply(p['type'])
                action_taken.append(f"Dropped frag: {p['type']}")

    if alert['recommended_action'] == "STATE_FLUSH":
        logging.info("🚨 Triggering state flush")
        flush_state.apply(alert['destination_ip'])
        action_taken.append("State flushed for destination")

    if not action_taken:
        logging.info("ℹ️ No mitigation required")

    return action_taken


def main():
    policy = load_policy()

    logging.info("✅ Loaded MLDFM policy config")

    # Example loop: simulate receiving alerts
    fake_alert = {
        "alert_id": "test-123",
        "flags": {"RST": True, "FIN": False, "SYN": False, "FRAG": True},
        "recommended_action": "STATE_FLUSH",
        "destination_ip": "10.0.0.5"
    }

    while True:
        results = handle_alert(fake_alert, policy)
        logging.info(f"Actions taken: {results}")
        time.sleep(30)


if __name__ == "__main__":
    main()
