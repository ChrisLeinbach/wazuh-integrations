from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class NetstatPortHandler(BaseHandler):

    """
    NetstatPortHandler handles alerts where Wazuh has detected that the listening ports listed by Netstat have changed.
    """

    alert_ids = ['533']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        return []

    def generate_description(self) -> Union[str, None]:
        new_lines, removed_lines = self._find_line_deltas(self.alert_data['previous_log'], self.alert_data['full_log'])
        new_string = f"\nNew Listening Port(s):\n" + "\n".join(new_lines)
        old_string = f"\nOld Listening Port(s):\n" + "\n".join(removed_lines)
        return f"{new_string}\n{old_string}"

    @staticmethod
    def _find_line_deltas(before, after):
        """ Finds the new lines and removed lines between a given set of before and after strings. """
        before_lines = before.splitlines()
        after_lines = after.splitlines()

        new_lines = [line for line in after_lines if line not in before_lines]
        removed_lines = [line for line in before_lines if line not in after_lines]

        return new_lines, removed_lines
