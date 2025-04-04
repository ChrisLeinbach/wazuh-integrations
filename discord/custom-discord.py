#!/usr/bin/env python3

import sys
import requests
import json
import rule_handlers
import logging

"""
ossec.conf configuration structure
 <integration>
     <name>custom-discord</name>
     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>
"""

LOG_LEVEL = logging.DEBUG
LOG_FILE = '/var/ossec/logs/custom-discord.log'
LOG_HIDE_WEBHOOK_URL = False

logging.basicConfig(level=LOG_LEVEL, filename=LOG_FILE, filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')

IGNORED_ALERT_IDS = ['23504', '23505']

# Read arguments - See https://wazuh.com/blog/how-to-integrate-external-software-using-integrator/
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

logging.debug(f'Custom-Discord Initialized. '
              f'Alert file: {alert_file}, '
              f'User: {user}, '
              f'Hook URL: {"HIDDEN" if LOG_HIDE_WEBHOOK_URL else hook_url}')

logging.debug(f'Loaded Handlers: {[cls.__name__ for cls in rule_handlers.get_all_handlers()]}')

# Read JSON data from the alert file.
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# Extract alert level and ID from the alert.
alert_id = alert_json['rule']['id']
alert_level = alert_json["rule"]["level"]

logging.info(f'Loading Alert ID {alert_id} with level {alert_level}.')

if alert_id in IGNORED_ALERT_IDS:
    logging.info(f'Alert ID {alert_id} is explicitly ignored.')
    sys.exit(0)

# Determine which agent caused the alert.
if "agentless" in alert_json:
    agent = "agentless"
else:
    agent = f'Name: {alert_json["agent"]["name"]}\nID: {alert_json["agent"]["id"]}\nIP: {alert_json["agent"]["ip"]}'

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
        "value": agent,
        "inline": True
    }, {
        "name": "Level",
        "value": alert_level,
        "inline": True
    }
]

# Load the rule handlers. Iterate over the handlers and check if the alert ID matches on any of them.
# If there is a match, generate the fields and description(s) for that handler.
matched_handlers = [handler_class(alert_json) for handler_class in rule_handlers.get_all_handlers() if alert_id in handler_class.alert_ids]
logging.debug(f'Matched Handlers: {matched_handlers}')
descriptions = []
for handler in matched_handlers:
    if handler.enabled:
        fields.extend(handler.generate_fields())
        description = handler.generate_description()
        if description:
            descriptions.append(description)
    else:
        logging.debug(f'Handler {handler} disabled.')

# Check if the handlers set a description entry. If not, use the rule description. If it is set,
# add the rule description to the end then join them with newlines.
if not descriptions:
    description = f"{alert_json['rule']['description']}"
else:
    description = "\n".join(descriptions)

# Build data to send to Discord.
payload = json.dumps({
    "content": "",
    "embeds": [
        {
            "title": f"Wazuh Alert - Rule {alert_json['rule']['id']}",
            "color": color,
            "description": description,
            "fields": fields
        }
    ]
})

logging.info(f'Sending webhook for alert {alert_id}.')
r = requests.post(hook_url, data=payload, headers={"content-type": "application/json"})

if r.ok:
    logging.info(f'Webhook sent successfully for alert {alert_id}.')
    sys.exit(0)
else:
    logging.info(f'Failed to send webhook for alert {alert_id}. Status Code {r.status_code}.')
    logging.debug(f"Response from Discord: {r.text}")
    logging.debug(f"Attempted Payload: {json.dumps(payload)}")
    sys.exit(1)
