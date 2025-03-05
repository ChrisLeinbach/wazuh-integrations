from typing import List


class BaseHandler:

    # Subclasses should overload this list of IDs with a list of rule IDs they can handle.
    id = [0]

    base_field = {
        "name": "ReplaceMe - Name",
        "value": "ReplaceMe - Value",
        "inline": True
    }

    def __init__(self, alert_data: dict):
        self.alert_data = alert_data

    def generate_fields(self) -> List[dict]:
        raise NotImplementedError("Subclasses must implement this method.")
