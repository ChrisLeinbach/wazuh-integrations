from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class RootCheckHandler(BaseHandler):

    """
    RootCheckHandler handles alert ID 510 which is the Wazuh attempting to identify root kits.
    """

    alert_ids = ['510']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        log_field = self._create_new_field("Report", self.alert_data["full_log"])
        return [log_field]

    def generate_description(self) -> Union[str, None]:
        return None
