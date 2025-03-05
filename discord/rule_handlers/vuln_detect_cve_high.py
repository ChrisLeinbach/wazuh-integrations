from typing import List
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class VulnDetectCVEHandler(BaseHandler):

    id = [23504, 23505]

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        cve_field = deepcopy(self.base_field)
        cve_field["name"] = "CVE"
        cve_field["value"] = self.alert_data["data"]["vulnerability"]["cve"]

        score_field = deepcopy(self.base_field)
        score_field["name"] = "Score"
        score_field["value"] = self.alert_data["data"]["vulnerability"]["score"]["base"]

        rationale_field = deepcopy(self.base_field)
        rationale_field["name"] = "Rationale"
        rationale_field["value"] = self.alert_data["data"]["vulnerability"]["rationale"]

        reference_field = deepcopy(self.base_field)
        reference_field["name"] = "Reference"
        reference_field["value"] = self.alert_data["data"]["vulnerability"]["reference"]

        return [cve_field, score_field, rationale_field, reference_field]
