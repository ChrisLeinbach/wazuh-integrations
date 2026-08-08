from typing import List, Union
from rule_handlers.base_handler import BaseHandler

import re

class WebErrorCodeHandler(BaseHandler):

    """
    WebErrorCodeHandler handles alerts events from webservers returning error codes.
    """

    rule_ids = ['31151']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        source_ip = self.create_new_field("Source IP", self.alert_data['data']['srcip'])
        status_code = self.create_new_field("Status Code", self.alert_data['data']['id'])

        request_str = f"{self.alert_data['data']['protocol']} - {self.alert_data['data']['url']}"
        request_field = self.create_new_field("Request", request_str)

        previous_field = self.create_new_field("Previous Requests", self._process_previous_output(self.alert_data['previous_output']))

        return [source_ip, status_code, request_field, previous_field]

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None

    def _process_previous_output(self, previous_output: str) -> str:
        """ Processes the previous output into a list and then converts that to a discord ready bulleted list string. """
        previous_lines = previous_output.splitlines()

        log_pattern = re.compile(
            r'(?P<ip>\S+) '
            r'(?P<ident>\S+) '
            r'(?P<user>\S+) '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) '
            r'(?P<path>\S+) '
            r'(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) '
            r'(?P<size>\S+) '
            r'"(?P<referer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
        )

        previous_requests = []
        for previous_line in previous_lines:
            match = log_pattern.match(previous_line)
            if match:
                fields = match.groupdict()
                previous_requests.append(f"{fields['method']} - {fields['path']}")

        return self._format_previous_list(previous_requests)


    @staticmethod
    def _format_previous_list(previous_list: List[str]) -> str:
        """ Reformats the references entry into a bulleted list. """
        if len(previous_list) > 3:
            return '- ' + '\n- '.join(previous_list[:3]) + '\n- Previous requests truncated to 3.'
        else:
            return '- ' + '\n- '.join(previous_list)
