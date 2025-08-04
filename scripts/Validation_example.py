import jsonschema
import json

with open('runtime/flare_alert.json') as f:
    schema = json.load(f)

alert = {
  "alert_id": "e7b3f13e-1234-45ab-b123-1234567890ab",
  "timestamp": "2025-07-05T12:34:56Z",
  "source_ip": "192.168.1.10",
  "destination_ip": "10.0.0.5",
  "protocol": "TCP",
  "flags": {"RST": true, "FIN": false, "SYN": false, "FRAG": true},
  "classifier_confidence": 0.92,
  "recommended_action": "DROP_FRAGMENT"
}

jsonschema.validate(alert, schema)
print("✅ Alert is valid!")
