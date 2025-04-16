import json
import pytest
import pathlib
import importlib
import inspect

def discover_handlers():
    handler_map = {}

    module_path = "discord.rule_handlers"
    handler_path =  pathlib.Path(__file__).parents[2] / "discord" / "rule_handlers"

    for handler_file in handler_path.glob("*.py"):
        # Skip __init__.py, private files, and the base class.
        if handler_file.name.startswith("_") or handler_file.name == "base_handler.py":
            continue

        # Import the handler file.
        module_name = handler_file.stem
        full_module_path = f"{module_path}.{module_name}"
        module = importlib.import_module(full_module_path)

        # Get the handler's class and add it to the map if it has available test data.
        for name, obj in inspect.getmembers(module, inspect.isclass):
            module_test_root = pathlib.Path(__file__).parent / module_name
            if module_test_root.exists():
                handler_map[module_name] = obj
    return handler_map

HANDLER_MAP = discover_handlers()

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

@pytest.fixture(params=HANDLER_MAP.keys())
def handler_case(request):
    case_name = request.param
    base_path = pathlib.Path(__file__).parent / case_name

    handler_class = HANDLER_MAP[case_name]
    input_data = load_json(base_path / "input.json")
    expected_fields = load_json(base_path / "expected_fields.json")
    expected_description = load_json(base_path / "expected_description.json")

    return {
        "handler": handler_class(input_data),
        "expected_fields": expected_fields,
        "expected_description": expected_description
    }

def test_generate_fields(handler_case):
    assert handler_case["handler"].generate_fields() == handler_case["expected_fields"]

def test_generate_description(handler_case):
    assert handler_case["handler"].generate_description() == handler_case["expected_description"]
