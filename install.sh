#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cp -r "$SCRIPT_DIR"/discord/* /var/ossec/integrations/
chown -R root:wazuh /var/ossec/integrations/
chmod -R 750 /var/ossec/integrations/
systemctl restart wazuh-manager