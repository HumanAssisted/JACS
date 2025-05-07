# use request to send a response to the server

import requests
import jacs
import os
from pathlib import Path
import json

# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.client.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))

BASE_URL = "http://localhost:8000"

def test_post_endpoint():
    # Prepare test data
    test_data = {
        "message": "Hello from client",
        "data": {
            "number": 42,
            "list": [1, 2, 3],
            "nested": {"key": "value"}
        }
    }
    
    # Sign the request data
    signed_request = jacs.sign_request(test_data)
    
    # Send POST request with signed data
    response = requests.post(
        f"{BASE_URL}/api/data",
        data=signed_request,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"\nPOST Test:")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        # Verify the response
        response_text = response.text
        verified_response = jacs.verify_response(response_text)
        print("Verified Response:", json.dumps(verified_response, indent=2))
    else:
        print("Error Response:", response.text)

def test_get_endpoint():
    # Send GET request
    response = requests.get(f"{BASE_URL}/api/manual-sign")
    
    print(f"\nGET Test:")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        # Verify the response
        response_text = response.text
        verified_response = jacs.verify_response(response_text)
        print("Verified Response:", json.dumps(verified_response, indent=2))
    else:
        print("Error Response:", response.text)

def test_invalid_signature():
    # Test with invalid data
    invalid_data = "This is not a valid JACS signature"
    
    print(f"\nInvalid Signature Test:")
    response = requests.post(
        f"{BASE_URL}/api/data",
        data=invalid_data,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"Status Code: {response.status_code}")
    print("Response:", response.text)

if __name__ == "__main__":
    print("Starting JACS HTTP Client Tests...")
    print("Make sure the server is running on http://localhost:8000")
    
    try:
        # Run all tests
        test_post_endpoint()
        test_get_endpoint()
        test_invalid_signature()
        
    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to the server. Make sure it's running on http://localhost:8000")
    except Exception as e:
        print(f"\nError during tests: {str(e)}")