from typing import List, Union
from rule_handlers.base_handler import BaseHandler


class SuricataEve(BaseHandler):

    """
    SuricataEve handles alerts generated by agents parsing Suricata's eve.json file.
    """

    alert_ids = ['86601']
    enabled = True

    def __init__(self, alert_data: dict):
        super().__init__(alert_data)

    def generate_fields(self) -> List[dict]:
        sig_field = self._create_new_field("Signature", self.alert_data["data"]["alert"]["signature_id"])
        action_field = self._create_new_field("Action", self.alert_data["data"]["alert"]["action"].capitalize())
        severity_field = self._create_new_field("Severity", self.alert_data["data"]["alert"]["severity"])
        conversation_field = self._create_new_field("Conversation", self.create_conversation_string())
        alert_data = [sig_field, action_field, severity_field, conversation_field]

        if "http" in self.alert_data["data"].keys():
            hostname = self.alert_data["data"]["http"]["hostname"]
            url = self.alert_data["data"]["http"]["url"]
            alert_data.append(self._create_new_field("HTTP Address", f"{hostname}{url}"))

        if 'tls' in self.alert_data["data"].keys():
            tls_sni = self.alert_data["data"]["tls"]["sni"]
            alert_data.append(self._create_new_field("TLS SNI", f"{tls_sni}"))

        # Need to get the 0th index of the query list. Wazuh makes this a list for some reason. Not sure it would make
        # sense to have more than one entry in the list.
        if 'dns' in self.alert_data["data"].keys():
            dns_query = self.alert_data["data"]["dns"]["query"][0]["rrname"]
            alert_data.append(self._create_new_field("DNS Query", f"{dns_query}"))

        return alert_data

    def generate_description(self) -> Union[str, None]:
        """ Default description is acceptably specific. """
        return None

    def create_conversation_string(self):
        protocol = self.alert_data["data"]["proto"]
        source_ip = self.alert_data["data"]["flow"]["src_ip"]
        source_port = self.alert_data["data"]["flow"]["src_port"]
        dest_ip = self.alert_data["data"]["flow"]["dest_ip"]
        dest_port = self.alert_data["data"]["flow"]["dest_port"]
        return f"{protocol} {source_ip}:{source_port} -> {dest_ip}:{dest_port}"
