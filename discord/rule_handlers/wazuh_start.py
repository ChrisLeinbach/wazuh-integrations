from typing import List, Union
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class WazuhStartHandler(BaseHandler):

    alert_ids = ['502']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        fired_field = deepcopy(self.base_field)
        fired_field["name"] = "Trigger Count"
        fired_field["value"] = self.alert_data["rule"]["firedtimes"]

        return [fired_field]

    def generate_description(self) -> Union[str, None]:
        return f"The Wazuh Manager has started on agent {self.alert_data['agent']['name']}."
