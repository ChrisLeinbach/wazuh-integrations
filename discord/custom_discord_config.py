class CustomDiscordConfig:

    def __init__(self, config_data: dict):
        self.ignored_rule_ids = config_data.get('ignored_rule_ids', [])
        self.field_list_length_limit = config_data.get('field_list_length_limit', 3)
