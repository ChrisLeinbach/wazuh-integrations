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


