from typing import List, Union


class BaseHandler:

    # Subclasses should overload this list of IDs with a list of rule IDs they can handle. IDs are strings.
    alert_ids = ['0']

    base_field = {
        "name": "ReplaceMe - Name",
        "value": "ReplaceMe - Value",
        "inline": True
    }

    def __init__(self, alert_data: dict):
        self.alert_data = alert_data

    def generate_fields(self) -> List[dict]:
        """ Returns a list of dictionary field elements for discord. These should follow the form of base_field. """
        raise NotImplementedError("Subclasses must implement this method.")

    def generate_description(self) -> Union[str, None]:
        """ Returns a string for the description. If no description is provided, it will return None. """
        raise NotImplementedError("Subclasses must implement this method.")
