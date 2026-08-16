from typing import List, Union
from rule_handlers.base_handler import BaseHandler
from custom_discord_config import CustomDiscordConfig


class SudoHandler(BaseHandler):

    """
    SudoHandler handles alerts events from the use of the sudo command.
    """

    rule_ids = ['5402']
    enabled = True

    def __init__(self, alert_data: dict, shared_config: CustomDiscordConfig):
        super().__init__(alert_data, shared_config)

    def generate_fields(self) -> List[dict]:
        src_user_field = self.create_new_field("Source User", self.alert_data['data']["srcuser"])
        dst_user_field = self.create_new_field("Destination User", self.alert_data['data']["dstuser"])
        cmd_field = self.create_new_field("Command", self.alert_data['data']["command"])
        pwd_field = self.create_new_field("Working Directory", self.alert_data['data']["pwd"])
        tty_field = self.create_new_field("Terminal", self.alert_data['data']["tty"])
        return [src_user_field, dst_user_field, cmd_field, pwd_field, tty_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None
