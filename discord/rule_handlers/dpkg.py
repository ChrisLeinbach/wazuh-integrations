from typing import List, Union
from rule_handlers.base_handler import BaseHandler
from custom_discord_config import CustomDiscordConfig


class DpkgHandler(BaseHandler):

    """
    DpkgHandler handles alerts ID 2902 and 2904 which is the Wazuh notifying of changes via DPKG.
    """

    rule_ids = ['2902', '2904']
    enabled = True

    def __init__(self, alert_data: dict, shared_config: CustomDiscordConfig):
        super().__init__(alert_data, shared_config)

    def generate_fields(self) -> List[dict]:
        package_field = self.create_new_field("Package", self.alert_data["data"]["package"])
        arch_field = self.create_new_field("Architecture", self.alert_data["data"]["arch"])
        version_field = self.create_new_field("Version", self.alert_data["data"]["version"])
        return [package_field, arch_field, version_field]

    def generate_description(self) -> Union[str, None]:
        return None
