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

        user = None
        src_ip = None

        # Attempt to use data Wazuh already extracted.
        if 'data' in self.alert_data.keys():
            user = self.alert_data['data'].get('dstuser') or self.alert_data['data'].get('srcuser')
            src_ip = self.alert_data['data'].get('srcip') or self.alert_data['data'].get('dstip')

        # Use regex as fallback for either field.
        if not user or not src_ip:
            pattern = re.compile(r"""(?:Invalid|Failed|User)\s+user?\s*(?:(\S+)\s+)?from\s+([0-9a-fA-F:.]+)""", re.IGNORECASE | re.VERBOSE)
            event_data = self.alert_data['full_log']
            match = pattern.search(event_data)
            user = match.group(1) if not user else user
            src_ip = match.group(2) if not src_ip else src_ip

        user_field = self.create_new_field("User", user)
        ip_field = self.create_new_field("Source IP", src_ip)
        origin_field = self.create_new_field("Origin", self.make_geo_string())
        return [user_field, ip_field, origin_field]

    def generate_description(self) -> Union[str, None]:
        return None
