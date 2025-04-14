from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class NetstatPortHandler(BaseHandler):

    """
    NetstatPortHandler handles alerts where Wazuh has detected that the listening ports listed by Netstat have changed.
    """

    rule_ids = ['533']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        return []

    def generate_description(self) -> Union[str, None]:
        new_lines, removed_lines = self._find_line_deltas(self.alert_data['previous_log'], self.alert_data['full_log'])
        new_string = f"\nOpened Port(s):\n" + self._format_port_list(new_lines)
        old_string = f"\nClosed Port(s):\n" + self._format_port_list(removed_lines)
        return f"{new_string}\n{old_string}"

    @staticmethod
    def _format_port_list(port_list: list[str]) -> str:
        """ Converts a list of ports into a better formatted string. If the list is empty, converts it to None (str)."""
        if port_list:
            return "\n".join(port_list)
        else:
            return 'None'

    @staticmethod
    def _find_line_deltas(before, after):
        """ Finds the new lines and removed lines between a given set of before and after strings. """
        before_lines = before.splitlines()
        after_lines = after.splitlines()

        new_lines = [line for line in after_lines if line not in before_lines]
        removed_lines = [line for line in before_lines if line not in after_lines]

        return new_lines, removed_lines
