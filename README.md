# Wazuh Integrations

This repository holds a custom Wazuh integration for Discord that allows you to forward Wazuh alerts via Webhook.

## Installation

To install the code integration itself, use the following commands:

```
git clone https://github.com/ChrisLeinbach/wazuh-integrations.git
cp -r wazuh-integrations/discord/* /var/ossec/integrations/
chmod -R 750 /var/ossec/integrations/*
chown -R root:wazuh /var/ossec/integrations/*
systemctl restart wazuh-manager
```

The integration then needs Discord and Wazuh setup to use it. It's best to follow Maik Ro's blog post on this:

[How to connect wazuh and discord: a Step-By-Step Guide. By Maik Ro.](https://maikroservice.com/how-to-connect-wazuh-and-discord-a-step-by-step-guide)

There is some addition customization that can be done using these integrations. See the following section for
additional configuration options and an example config block.

## Additional Configuration Options

Additional customization is done via the options field of the config XML block. This field supports standard JSON.

Available JSON Fields:
* ignored_alert_ids: A list of alert IDs as strings to ignore. Ex.  ```"ignored_alert_ids": ["23504", "23505"]```

### Example Config
```
  <integration>
    <name>custom-discord</name>
    <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXXXXX</hook_url>
    <level>8</level>
    <alert_format>json</alert_format>
    <options>{"ignored_alert_ids": ["23504", "23505"]}</options>
  </integration
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


