#!/usr/bin/env python3
"""
FLARE AFAC Online Classifier
===============================
- Loads trained ensemble + scaler
- Reads flag counts from P4 registers
- Predicts malicious patterns in real-time
- Generates alert JSON (matches flare_alert.json)
- Pushes alert to LSMA sync API
"""

import time
import grpc
import json
import requests
import uuid
import datetime

import joblib
import numpy as np

from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper

# Paths
P4INFO_FILE_PATH = "configs/p4info.txt"
MODEL_DIR = "afac/models/"
LSMA_SYNC_URL = "https://127.0.0.1:6000/alert"  # Example routine link

# Switch gRPC endpoint
SWITCH_ADDRESS = '127.0.0.1:50051'
DEVICE_ID = 0

# Load trained models
scaler = joblib.load(f"{MODEL_DIR}scaler.joblib")
ensemble = joblib.load(f"{MODEL_DIR}ensemble.joblib")


def get_flag_features(p4info_helper, sw):
    """
    Reads register values from P4 SFFP to build feature vector.
    Example: [RST_count, FIN_count, FRAG_count]
    """
    features = []
    for reg in ["MyIngress.rst_count", "MyIngress.fin_count", "MyIngress.frag_count"]:
        total = 0
        for response in sw.ReadRegisters(p4info_helper.get_register_id(reg)):
            for entity in response.entities:
                entry = entity.register_entry
                val = int(entry.data.bitstring, 2)
                total += val
        features.append(total)
    return np.array(features).reshape(1, -1)


def create_alert_json(features, prediction, confidence):
    """
    Creates valid flare_alert.json payload.
    """
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source_ip": "0.0.0.0",  # Replace with real source IP if available
        "destination_ip": "0.0.0.0",
        "protocol": "TCP",
        "flags": {
            "RST": bool(features[0][0] > 0),
            "FIN": bool(features[0][1] > 0),
            "SYN": False,
            "FRAG": bool(features[0][2] > 0)
        },
        "classifier_confidence": float(confidence),
        "recommended_action": "RATE_LIMIT" if prediction == 1 else "NO_ACTION"
    }


def main():
    p4info_helper = P4InfoHelper(P4INFO_FILE_PATH)

    try:
        sw = p4info_helper.connect(
            name='flare_afac_switch',
            address=SWITCH_ADDRESS,
            device_id=DEVICE_ID,
            proto_dump_file='logs/grpc_afac_dump.txt'
        )

        while True:
            features = get_flag_features(p4info_helper, sw)
            scaled = scaler.transform(features)
            prediction = ensemble.predict(scaled)[0]
            confidence = max(ensemble.predict_proba(scaled)[0])

            print(f"Features: {features} | Prediction: {prediction} | Confidence: {confidence:.4f}")

            if confidence > 0.85 and prediction == 1:
                alert = create_alert_json(features, prediction, confidence)

                # Send alert to LSMA sync
                try:
                    res = requests.post(LSMA_SYNC_URL, json=alert, verify=False)
                    print(f"🚨 Alert sent! Response: {res.status_code}")
                except Exception as e:
                    print(f"❌ Failed to send alert: {e}")

            time.sleep(5)

    except KeyboardInterrupt:
        print("Stopping AFAC online classifier...")
    except grpc.RpcError as e:
        print(f"gRPC error: {e}")

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    main()
