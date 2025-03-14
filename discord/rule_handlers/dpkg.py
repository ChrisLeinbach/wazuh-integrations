from typing import List, Union
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class DpkgHandler(BaseHandler):

    """
    DpkgHandler handles alerts ID 2902 and 2904 which is the Wazuh notifying of changes via DPKG.
    """

    alert_ids = ['2902', '2904']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        package_field = deepcopy(self.base_field)
        package_field["name"] = "Package"
        package_field["value"] = self.alert_data["data"]["package"]

        arch_field = deepcopy(self.base_field)
        arch_field["name"] = "Architecture"
        arch_field["value"] = self.alert_data["data"]["arch"]

        version_field = deepcopy(self.base_field)
        version_field["name"] = "Architecture"
        version_field["value"] = self.alert_data["data"]["version"]

        return [package_field, arch_field, version_field]

    def generate_description(self) -> Union[str, None]:
        return None
