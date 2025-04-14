from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class PAMHandler(BaseHandler):

    """
    PAMHandler handles alerts events from PAM, the Linux authentication manager.
    """

    rule_ids = ['5501', '5502']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        fields = []

        if 'srcuser' in self.alert_data['data'].keys():
            fields.append(self._create_new_field("Source User", self.alert_data['data']["srcuser"]))
        if 'uid' in self.alert_data['data'].keys():
            fields.append(self._create_new_field("UID", self.alert_data['data']["uid"]))
        if 'dstuser' in self.alert_data['data'].keys():
            fields.append(self._create_new_field("Destination User", self.alert_data['data']["dstuser"]))

        return fields

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None
