from typing import List, Union
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
        src_user_field = self._create_new_field("Source User", self.alert_data['data']["srcuser"])
        dst_user_field = self._create_new_field("Destination User", self.alert_data['data']["dstuser"])
        cmd_field = self._create_new_field("Command", self.alert_data['data']["command"])
        pwd_field = self._create_new_field("Working Directory", self.alert_data['data']["pwd"])
        tty_field = self._create_new_field("Terminal", self.alert_data['data']["tty"])
        return [src_user_field, dst_user_field, cmd_field, pwd_field, tty_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None
