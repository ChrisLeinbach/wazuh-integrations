# Wazuh Integrations

This repository holds a custom Wazuh integration for Discord that allows you to forward Wazuh alerts via Webhook.

## Installation

```
git clone https://github.com/ChrisLeinbach/wazuh-integrations.git
cp -r wazuh-integrations/discord/* /var/ossec/integrations/
chmod -R 750 /var/ossec/integrations/*
chown -R root:wazuh /var/ossec/integrations/*
systemctl restart wazuh-manager
```

## Handler Development

Each of the handlers is a subclass of the BaseHandler class in rule_handlers/base_handler.py. The BaseHandler defines
two functions which must be overridden by the subclasses. These two functions are generate_fields() and 
generate_description(). They provide the embed fields and body text for the Discord message respectively.

It's recommended to use a log level of debug when building handlers to make it easier to see what's going on. The
logger will generate its logs in /var/ossec/logs/custom-discord.log. 
/var/ossec/logs/ossec.log and /var/ossec/logs/integrations.log are also good places to monitor. Exceptions can cause
logs to appear in either of those files.

Additionally, the easiest way to see what the script will receive for a given alert in Wazuh is to use the Discover 
feed and open the expanded documents as JSON. This helps avoid things like unexpected type errors.


