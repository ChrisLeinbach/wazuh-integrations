from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class WazuhStartHandler(BaseHandler):

    """
    WazuhStartHandler handles alert ID 502 which is the Wazuh manager starting. This handler provides an easy to test,
    minimum viable product handler that is triggered by restarting manager with systemd.
    """

    alert_ids = ['502']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        fired_field = self._create_new_field("Trigger Count", self.alert_data["rule"]["firedtimes"])
        return [fired_field]

    def generate_description(self) -> Union[str, None]:
        return f"The Wazuh Manager has started on agent {self.alert_data['agent']['name']}."
