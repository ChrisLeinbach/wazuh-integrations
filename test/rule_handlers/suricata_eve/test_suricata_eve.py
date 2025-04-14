import json
import pytest
import pathlib
from discord.rule_handlers.suricata_eve import SuricataEve

test_handler = SuricataEve

test_fields_result = [
    {'name': 'Signature', 'value': '2047122', 'inline': True},
    {'name': 'Action', 'value': 'Allowed', 'inline': True},
    {'name': 'Severity', 'value': '3', 'inline': True},
    {'name': 'Conversation', 'value': 'UDP 192.168.99.99:42706 -> 192.168.1.1:53', 'inline': True},
    {'name': 'DNS Query', 'value': 'region2.v2.argotunnel.com', 'inline': True}
]

@pytest.fixture
def handler_object(request):
    test_path = pathlib.Path(request.node.fspath.strpath).with_name('test_data.json')
    with open(test_path, 'r') as test_file_handle:
        test_data = json.load(test_file_handle)
    return test_handler(test_data)

def test_generate_fields(handler_object):
    assert handler_object.generate_fields() == test_fields_result

def test_generate_description(handler_object):
    assert handler_object.generate_description() is None
