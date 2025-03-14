from typing import List, Union


class BaseHandler:

    """
    BaseHandler is the base class for all handlers. Handlers should extend it and override the several things:
    - alert_ids: Should be a list of string alert IDs that the handler can parse.
    - enabled: A boolean indicating if the handler should be enabled.
    - generate_fields(): A function that generates fields for the Discord embed.
    - generate_description(): A function that generates description for the Discord content.

    Multiple handlers can match the same alert ID, and they will all run. The description and fields
    are joined together in the outer code.

    The outer code also contains a configured logger so logging calls can be made via
    logging.info, critical, debug, etc. within handlers. The level output and output file are controlled in the
    outer code.
    """

    # Subclasses should overload this list of IDs with a list of rule IDs they can handle. IDs are strings.
    alert_ids = ['0']

    # Subclasses should overload this to allow them to be turned on/off as needed.
    enabled = True

    base_field = {
        "name": "ReplaceMe - Name",
        "value": "ReplaceMe - Value",
        "inline": True
    }

    def __init__(self, alert_data: dict):
        self.alert_data = alert_data

    def __repr__(self):
        return self.__class__.__name__

    def __str__(self):
        return self.__class__.__name__

    def generate_fields(self) -> List[dict]:
        """ Returns a list of dictionary field elements for discord. These should follow the form of base_field. """
        raise NotImplementedError("Subclasses must implement this method.")

    def generate_description(self) -> Union[str, None]:
        """ Returns a string for the description. If no description is provided, it will return None. """
        raise NotImplementedError("Subclasses must implement this method.")
