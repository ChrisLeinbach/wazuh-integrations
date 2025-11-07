import re
from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class SSHBruteForceHandler(BaseHandler):

    """
    SSHBruteForceHandler handles alert ID 5712 which is Wazuh notifying about a brute force attempt via SSH.
    """

    rule_ids = ['5712']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        event_data = self.alert_data['previous_output']

        pattern = re.compile(
            r"(?:Invalid user|invalid user)\s+(\S+)\s+(?:from\s+)?([0-9a-fA-F:.]+)",
            re.IGNORECASE
        )
        matches = pattern.findall(event_data)

        users = set()
        addresses = set()
        for user, address in matches:
            users.add(user)
            addresses.add(address)

        user_field = self._create_new_field("Users", ', '.join(sorted(users)))
        address_field = self._create_new_field("Sources", ', '.join(sorted(addresses)))
        attempts_field = self._create_new_field("Attempts", len(matches))
        country_field = self._create_new_field("Origin", self.alert_data["GeoLocation"]["country_name"])

        return [user_field, address_field, attempts_field, country_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None