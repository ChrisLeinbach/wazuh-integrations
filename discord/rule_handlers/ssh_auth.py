from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class SSHAuthHandler(BaseHandler):

    """
    SSHAuthHandler handles alerts related to fail access via SSH.
    Currently tested against 5710 and 5718.
    """

    rule_ids = ['5710', '5718']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        user_field = self._create_new_field("User", self.alert_data['data']['dstuser'])
        ip_field = self._create_new_field("Source IP", self.alert_data['data']['srcip'])
        origin_field = self._create_new_field("Origin", self.make_geo_string(self.alert_data))
        return [user_field, ip_field, origin_field]

    def generate_description(self) -> Union[str, None]:
        return None
