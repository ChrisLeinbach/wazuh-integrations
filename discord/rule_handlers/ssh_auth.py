import re
from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class SSHAuthHandler(BaseHandler):

    """
    SSHAuthHandler handles alerts related to fail access via SSH.
    Currently tested against 5710, 5718, and 5758.
    """

    rule_ids = ['5710', '5718', '5758']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        if 'data' in self.alert_data.keys():
            user = self.alert_data['data'].get('dstuser') or self.alert_data['data'].get('srcuser')
            src_ip = self.alert_data['data']['srcip']
        else:
            # Sometimes Wazuh doesn't extract this info, it appears this happens when 
            # the invalid user is just a space or some other kind of null string.
            event_data = self.alert_data['full_log']
            match = re.search(r"(?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)", event_data)
            user = match.group(1)
            src_ip = match.group(2)

        user_field = self.create_new_field("User", user)
        ip_field = self.create_new_field("Source IP", src_ip)
        origin_field = self.create_new_field("Origin", self.make_geo_string())
        return [user_field, ip_field, origin_field]

    def generate_description(self) -> Union[str, None]:
        return None
