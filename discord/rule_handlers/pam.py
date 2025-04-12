from typing import List, Union
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class PAMHandler(BaseHandler):

    """
    PAMHandler handles alerts events from PAM, the Linux authentication manager.
    """

    alert_ids = ['5501', '5502']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        fields = []

        if 'srcuser' in self.alert_data['data'].keys():
            src_user_field = deepcopy(self.base_field)
            src_user_field["name"] = "Source User"
            src_user_field["value"] = self.alert_data['data']["srcuser"]
            fields.append(src_user_field)

        if 'uid' in self.alert_data['data'].keys():
            uid_field = deepcopy(self.base_field)
            uid_field["name"] = "UID"
            uid_field["value"] = self.alert_data['data']["uid"]
            fields.append(uid_field)

        if 'dstuser' in self.alert_data['data'].keys():
            dst_user_field = deepcopy(self.base_field)
            dst_user_field["name"] = "Destination User"
            dst_user_field["value"] = self.alert_data['data']["dstuser"]
            fields.append(dst_user_field)

        return fields

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None
