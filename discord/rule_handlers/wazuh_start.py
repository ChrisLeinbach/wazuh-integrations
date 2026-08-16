from typing import List, Union
from rule_handlers.base_handler import BaseHandler
from custom_discord_config import CustomDiscordConfig


class WazuhStartHandler(BaseHandler):

    """
    WazuhStartHandler handles alert ID 502 which is the Wazuh manager starting. This handler provides an easy to test,
    minimum viable product handler that is triggered by restarting manager with systemd.
    """

    rule_ids = ['502']
    enabled = True

    def __init__(self, alert_data: dict, shared_config: CustomDiscordConfig):
        super().__init__(alert_data, shared_config)

    def generate_fields(self) -> List[dict]:
        fired_field = self.create_new_field("Trigger Count", self.alert_data["rule"]["firedtimes"])
        return [fired_field]

    def generate_description(self) -> Union[str, None]:
        return f"The Wazuh Manager has started on agent {self.alert_data['agent']['name']}."
