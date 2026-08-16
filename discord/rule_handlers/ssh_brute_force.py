import re
from typing import List, Union
from rule_handlers.base_handler import BaseHandler
from custom_discord_config import CustomDiscordConfig


class SSHBruteForceHandler(BaseHandler):

    """
    SSHBruteForceHandler handles alert ID 5712 and 5719 which is Wazuh notifying about a brute force attempt via SSH.
    """

    rule_ids = ['5712', '5719']
    enabled = True

    def __init__(self, alert_data: dict, shared_config: CustomDiscordConfig):
        super().__init__(alert_data, shared_config)

    def generate_fields(self) -> List[dict]:
        events = self.alert_data['previous_output'].split('\n')

        ips = set()
        users = set()
        for event in events:
            user_ip_matches = re.compile(r"user\s+(\S+).*?\b([0-9a-fA-F:.]+)\b", re.IGNORECASE).search(event)
            user, ip = user_ip_matches.groups()
            ips.add(ip)
            users.add(user)

        user_field = self.create_new_field("Users", ', '.join(sorted(users)))
        address_field = self.create_new_field("Sources", ', '.join(sorted(ips)))
        attempts_field = self.create_new_field("Attempts", len(events))
        origin_field = self.create_new_field("Origin", self.make_geo_string())

        return [user_field, address_field, attempts_field, origin_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None