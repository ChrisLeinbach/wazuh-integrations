from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class IntegrityHandler(BaseHandler):

    """
    IntegrityHandler handles alert ID 550 which is the Wazuh notifying of changes to monitored files that may
    impact that file's integrity.
    """

    rule_ids = ['550']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        file_field = self._create_new_field("Path", self.alert_data["syscheck"]["path"])
        event_field = self._create_new_field("Event Type", self.alert_data["syscheck"]["event"].capitalize())
        attr_field = self._create_new_field("Changed Attributes", ", ".join(self.alert_data["syscheck"]["changed_attributes"]))
        return [file_field, event_field, attr_field]

    def generate_description(self) -> Union[str, None]:
        return self.alert_data['full_log']
