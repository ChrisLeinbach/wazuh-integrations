import re
from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class SSHAuthAttemptsHandler(BaseHandler):

    """
    SSHAuthAttemptsHandler handles alert ID 5758 which is Wazuh notifying about a user having exceeded the 
    maximum number of SSH attempts.
    """

    rule_ids = ['5758']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        event_data = self.alert_data['full_log']
        match = re.search(r"(?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)", event_data)

        user_field = self._create_new_field("User", match.group(1))
        address_field = self._create_new_field("Source", match.group(2))

        return [user_field, address_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None