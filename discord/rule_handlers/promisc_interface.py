import re
from typing import List, Union
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class PromiscInterfaceHandler(BaseHandler):

    """
    PromiscInterfaceHandler handles alerts where an interface has entered promiscuous mode.
    """

    alert_ids = ['5104']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:

        interface_field = deepcopy(self.base_field)
        interface_field["name"] = "Interface"
        interface_field["value"] = self.extract_device_name(self.alert_data['full_log'])

        return [interface_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None

    @staticmethod
    def extract_device_name(log_string: str) -> str:
        """ Retrieves the device name from the full_log string. """
        device_pattern = r"device ([a-zA-Z0-9\-\_]+)"
        re_matches = re.search(device_pattern, log_string)
        if re_matches:
            return re_matches.group(1)
        else:
            return "Unknown"