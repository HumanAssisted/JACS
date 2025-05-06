import pytest
import jacs  #
import os
import pathlib
from datetime import datetime
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"
current_dir = pathlib.Path(__file__).parent.absolute()
fixtures_path = current_dir / "fixtures"
os.chdir(fixtures_path)
jacs.load("./jacs.config.json")


def test_module_import():
    """Check if the module imports correctly."""
    assert jacs is not None
    assert hasattr(jacs, "sign_request")
    assert hasattr(jacs, "verify_response")


def test_basic_types():
    """Test basic types."""
    request_data = 4
    helper_request_data(request_data)


def test_binary_data():
    """Test binary data."""
    request_data = b"hello"
    helper_request_data(request_data)

# def test_datetime():
#     """Test datetime."""
#     request_data = datetime.now()
#     helper_request_data(request_data)

def test_sign_request_response_basic():
    """Test signing a simple dictionary."""
    request_data = {"message": "hello", "value": 123}
    helper_request_data(request_data)


def helper_request_data(request_data):
    
    try:
        signed_request_data = jacs.sign_request(request_data)
        assert isinstance(signed_request_data, str)
        print(f"Signed Request: type {type(signed_request_data)} {signed_request_data}")
    except Exception as e:
        # Debug info
        print(f"Detailed error: {str(e)}")
        import traceback
        traceback.print_exc()
        pytest.fail(f"Test failed with error: {e}")
 
    try:
        payload = jacs.verify_response(signed_request_data)
        assert payload == request_data
        print(f"Verified Payload: type {type(payload)} {payload}")  

    except Exception as e:
        # This might fail if the global agent isn't loaded.
        print(f"Detailed error: {str(e)}")
        import traceback
        traceback.print_exc()
        pytest.fail(f"Test failed with error: {e}")


# Add more tests for edge cases, different data types, errors,
# and especially for load_agent_config if that's the entry point.

# Example test if conversion functions were directly exposed (requires modifying Rust)
# def test_direct_conversions():
#     test_dict = {"a": 1, "b": "str", "c": [True, None], "d": {"nested": 3.14}}
#     # Assume jacspy._py_to_value and jacspy._value_to_py exist
#     value_json_str = jacspy._py_to_value(test_dict) # Returns JSON string representation of Value
#     value = json.loads(value_json_str)
#     assert value == test_dict # Check JSON matches original dict
#
#     py_obj_back = jacspy._value_to_py(value) # Pass dict back, get PyObject
#     assert py_obj_back == test_dict


def test_conversion_with_sign_request():
    """Test the conversion functionality through sign_request and verify_response."""
    # This test demonstrates type conversion using the public API functions
    try:
        jacs.load("./jacs.config.json")

        # Test basic types
        basic_types = {
            "null_value": None,
            "bool_true": True,
            "bool_false": False,
            "int_positive": 123,
            "int_negative": -456,
            "float_value": 3.14,
            "string_value": "hello",
            "empty_string": "",
        }

        # Test nested structures
        nested_data = {
            "list_empty": [],
            "list_simple": [1, "two", True],
            "list_nested": [[1, 2], []],
            "dict_empty": {},
            "dict_simple": {"a": 1, "b": "bee", "c": None},
            "dict_nested": {
                "nested": {"a": 1, "b": "bee", "c": None},
                "list": [1, "two", True],
            },
        }

        # Combine all test data
        test_data = {}
        test_data.update(basic_types)
        test_data.update(nested_data)

        # Sign the test data, which will convert Python objects to Rust values
        signed_data = jacs.sign_request(test_data)

        # Verify the response, which will convert Rust values back to Python objects
        retrieved_data = jacs.verify_response(signed_data)

        # Verify that the data went through the conversion pipeline correctly
        assert retrieved_data == test_data

        # Check specific values to ensure type fidelity
        assert retrieved_data["null_value"] is None
        assert retrieved_data["bool_true"] is True
        assert retrieved_data["bool_false"] is False
        assert retrieved_data["int_positive"] == 123
        assert retrieved_data["int_negative"] == -456
        assert abs(retrieved_data["float_value"] - 3.14) < 1e-6
        assert retrieved_data["string_value"] == "hello"
        assert retrieved_data["empty_string"] == ""

        # Check nested structures
        assert retrieved_data["list_empty"] == []
        assert retrieved_data["list_simple"] == [1, "two", True]
        assert retrieved_data["list_nested"] == [[1, 2], []]
        assert retrieved_data["dict_empty"] == {}
        assert retrieved_data["dict_simple"] == {"a": 1, "b": "bee", "c": None}
        assert retrieved_data["dict_nested"]["nested"] == {
            "a": 1,
            "b": "bee",
            "c": None,
        }
        assert retrieved_data["dict_nested"]["list"] == [1, "two", True]

        print("All conversions successful!")

    except Exception as e:
        print(f"Detailed error: {str(e)}")
        import traceback
        traceback.print_exc()
        pytest.fail(f"Test failed with error: {e}")
