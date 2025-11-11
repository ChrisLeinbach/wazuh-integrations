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

def load_test_cases(handler_name):
    """ Load lists of input/expected values and return a zipped list of test cases. """
    base_path = pathlib.Path(__file__).parent / handler_name

    inputs = load_json(base_path / "input.json")
    fields = load_json(base_path / "expected_fields.json")
    descs = load_json(base_path / "expected_description.json")

    # Safety check, should have matching number of input, field, and description inputs.
    if not (len(inputs) == len(fields) == len(descs)):
        raise ValueError(
            f"Test data length mismatch in '{handler_name}': "
            f"inputs={len(inputs)}, fields={len(fields)}, descs={len(descs)}"
        )

    return list(zip(inputs, fields, descs))

def pytest_generate_tests(metafunc):
    """ Dynamically parametrize based on handler test data. """
    if "handler_case" in metafunc.fixturenames:
        all_cases = []
        for handler_name, handler_class in HANDLER_MAP.items():
            for idx, (input_data, expected_fields, expected_description) in enumerate(load_test_cases(handler_name)):
                case_data = {
                    "handler_name": handler_name,
                    "handler_class": handler_class,
                    "input_data": input_data,
                    "expected_fields": expected_fields,
                    "expected_description": expected_description,
                }
                all_cases.append(
                    pytest.param(
                        case_data,
                        id=f"{handler_name}[case{idx}]"
                    )
                )

        metafunc.parametrize("handler_case", all_cases, indirect=True)

@pytest.fixture
def handler_case(request):
    """ Build a handler instance for each case. """
    case = request.param
    handler = case["handler_class"](case["input_data"])
    return {
        "handler": handler,
        "input_data": case["input_data"],
        "expected_fields": case["expected_fields"],
        "expected_description": case["expected_description"],
    }

def test_generate_fields(handler_case):
    assert handler_case["handler"].generate_fields() == handler_case["expected_fields"]

def test_generate_description(handler_case):
    assert handler_case["handler"].generate_description() == handler_case["expected_description"]
