from typing import List, Union
from copy import deepcopy
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
        cve_field = deepcopy(self.base_field)
        cve_field["name"] = "CVE"
        cve_field["value"] = self.alert_data["data"]["vulnerability"]["cve"]

        package_field = deepcopy(self.base_field)
        package_field["name"] = "Package"
        package_field["value"] = self.alert_data['data']['vulnerability']['package']['name']

        score_field = deepcopy(self.base_field)
        score_field["name"] = "Score"
        score_field["value"] = self.alert_data["data"]["vulnerability"]["score"]["base"]

        status_field = deepcopy(self.base_field)
        status_field["name"] = "Status"
        status_field["value"] = self.alert_data["data"]["vulnerability"]["status"]

        rationale_field = deepcopy(self.base_field)
        rationale_field["name"] = "Rationale"
        rationale_field["value"] = self.alert_data["data"]["vulnerability"]["rationale"]

        reference_field = deepcopy(self.base_field)
        reference_field["name"] = "Reference"
        references = self._format_references(self.alert_data["data"]["vulnerability"]["reference"])
        reference_field["value"] = references

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