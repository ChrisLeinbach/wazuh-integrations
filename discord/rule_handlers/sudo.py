from typing import List, Union
from copy import deepcopy
from rule_handlers.base_handler import BaseHandler


class SudoHandler(BaseHandler):

    """
    SudoHandler handles alerts events from the use of the sudo command.
    """

    alert_ids = ['5402']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        src_user_field = deepcopy(self.base_field)
        src_user_field["name"] = "Source User"
        src_user_field["value"] = self.alert_data['data']["srcuser"]

        dst_user_field = deepcopy(self.base_field)
        dst_user_field["name"] = "Destination User"
        dst_user_field["value"] = self.alert_data['data']["dstuser"]

        cmd_field = deepcopy(self.base_field)
        cmd_field["name"] = "Command"
        cmd_field["value"] = self.alert_data['data']["command"]

        pwd_field = deepcopy(self.base_field)
        pwd_field["name"] = "Working Directory"
        pwd_field["value"] = self.alert_data['data']["pwd"]

        tty_field = deepcopy(self.base_field)
        tty_field["name"] = "Terminal"
        tty_field["value"] = self.alert_data['data']["tty"]

        return [src_user_field, dst_user_field, cmd_field, pwd_field, tty_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None
