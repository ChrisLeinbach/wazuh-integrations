from typing import List, Union
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class IntegrityHandler(BaseHandler):

    """
    IntegrityHandler handles alert ID 550 which is the Wazuh notifying of changes to monitored files that may
    impact that file's integrity.
    """

    alert_ids = ['550']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        file_field = deepcopy(self.base_field)
        file_field["name"] = "Path"
        file_field["value"] = self.alert_data["syscheck"]["path"]

        event_field = deepcopy(self.base_field)
        event_field["name"] = "Event Type"
        event_field["value"] = self.alert_data["syscheck"]["event"].capitalize()

        attr_field = deepcopy(self.base_field)
        attr_field["name"] = "Changed Attributes"
        attr_field["value"] = ", ".join(self.alert_data["syscheck"]["changed_attributes"])

        return [file_field, event_field, attr_field]

    def generate_description(self) -> Union[str, None]:
        return self.alert_data['full_log']
