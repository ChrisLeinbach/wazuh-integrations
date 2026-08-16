from typing import List, Union
from rule_handlers.base_handler import BaseHandler
from custom_discord_config import CustomDiscordConfig


class VulnDetectCVEHandler(BaseHandler):

    """
    VulnDetectCVEHandler handles alerts where a new CVE is detected by Wazuh.
    """

    rule_ids = ['23504', '23505', '23506']
    enabled = True

    def __init__(self, alert_data: dict, shared_config: CustomDiscordConfig):
        super().__init__(alert_data, shared_config)

    def generate_fields(self) -> List[dict]:
        cve_field = self.create_new_field("CVE", self.alert_data["data"]["vulnerability"]["cve"])
        package_field = self.create_new_field("Package", self.alert_data['data']['vulnerability']['package']['name'])
        score_field = self.create_new_field("Score", self.alert_data["data"]["vulnerability"]["score"]["base"])
        status_field = self.create_new_field("Status", self.alert_data["data"]["vulnerability"]["status"])
        rationale_field = self.create_new_field("Rationale", self.alert_data["data"]["vulnerability"]["rationale"])
        reference_field = self.create_new_field("Reference", self._format_references(self.alert_data["data"]["vulnerability"]["reference"]))
        return [cve_field, package_field, score_field, status_field, rationale_field, reference_field]

    def generate_description(self) -> Union[str, None]:
        return (f"{self.alert_data['data']['vulnerability']['cve']} "
                f"with severity {self.alert_data['data']['vulnerability']['severity']} "
                f"impacts package {self.alert_data['data']['vulnerability']['package']['name']}.")

    def _format_references(self, references: str) -> str:
        """ Reformats the references entry into a bulleted list. """
        if ',' in references:
            return self.format_field_list(references.split(', '))
        else:
            return '- ' + references
