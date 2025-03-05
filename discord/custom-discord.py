#!/usr/bin/env python3

import sys
import requests
import json

"""
ossec.conf configuration structure
 <integration>
     <name>custom-discord</name>
     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>
"""

# Read arguments - See https://wazuh.com/blog/how-to-integrate-external-software-using-integrator/
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# Read JSON data from the alert file.
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# Extract alert level from the alert.
alert_level = alert_json["rule"]["level"]

# Determine which agent caused the alert.
if "agentless" in alert_json:
    agent_ = "agentless"
else:
    agent_ = alert_json["agent"]["name"]

# Colors from https://gist.github.com/thomasbnt/b6f455e2c7d743b796917fa3c205f812
# Aligned with Wazuh UI color coding.
if alert_level < 7:
    # Green
    color = "5763719"
elif 7 <= alert_level <= 11:
    # Blue
    color = "3447003"
elif 12 <= alert_level <= 14:
    # Yellow
    color = "16705372"
else:
    # Red
    color = "15548997"

fields = [
    {
        "name": "Agent",
        "value": agent_,
        "inline": True
    }, {
        "name": "Level",
        "value": alert_level,
        "inline": True
    }
]

# combine message details
payload = json.dumps({
    "content": "",
    "embeds": [
        {
            "title": f"Wazuh Alert - Rule {alert_json['rule']['id']}",
            "color": color,
            "description": alert_json["rule"]["description"],
            "fields": fields
        }
    ]
})

# send message to discord
r = requests.post(hook_url, data=payload, headers={"content-type": "application/json"})
sys.exit(0)
