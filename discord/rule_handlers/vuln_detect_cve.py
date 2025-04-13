from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class VulnDetectCVEHandler(BaseHandler):

    """
    VulnDetectCVEHandler handles alerts where a new CVE is detected by Wazuh.
    """

    alert_ids = ['23504', '23505', '23506']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        cve_field = self._create_new_field("CVE", self.alert_data["data"]["vulnerability"]["cve"])
        package_field = self._create_new_field("Package", self.alert_data['data']['vulnerability']['package']['name'])
        score_field = self._create_new_field("Score", self.alert_data["data"]["vulnerability"]["score"]["base"])
        status_field = self._create_new_field("Status", self.alert_data["data"]["vulnerability"]["status"])
        rationale_field = self._create_new_field("Rationale", self.alert_data["data"]["vulnerability"]["rationale"])
        reference_field = self._create_new_field("Reference", self._format_references(self.alert_data["data"]["vulnerability"]["reference"]))
        return [cve_field, package_field, score_field, status_field, rationale_field, reference_field]

    def generate_description(self) -> Union[str, None]:
        return (f"{self.alert_data['data']['vulnerability']['cve']} "
                f"with severity {self.alert_data['data']['vulnerability']['severity']} "
                f"impacts package {self.alert_data['data']['vulnerability']['package']['name']}.")

    @staticmethod
    def _format_references(references: str) -> str:
        """ Reformats the references entry into a bulleted list. """
        if ',' in references:
            if len(references.split(', ')) < 3:
                return '- ' + '\n- '.join(references.split(', ')[:2]) + '\n- References truncated to 3.'
            else:
                return '- ' + '\n- '.join(references.split(', '))
        else:
            return '- ' + references