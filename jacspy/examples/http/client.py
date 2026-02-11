"""Client that sends requests to a JACS-signed FastAPI server.

Verifies server responses using JACS.

    pip install jacs requests

    # Start the server first: python server.py
    python client.py
"""

import json
import requests
from jacs.client import JacsClient

BASE_URL = "http://localhost:8000"

# Create a client to verify responses
client = JacsClient.quickstart()


def test_post():
    """Send data, verify the signed response."""
    data = {"message": "Hello from client", "value": 42}

    response = requests.post(f"{BASE_URL}/api/data", json=data)
    print(f"POST /api/data -> {response.status_code}")

    if response.status_code == 200:
        result = client.verify(response.text)
        print(f"  Verified: {result.valid}")
        print(f"  Signer: {result.signer_id[:16]}...")


def test_get():
    """Get status, verify the signed response."""
    response = requests.get(f"{BASE_URL}/api/status")
    print(f"\nGET /api/status -> {response.status_code}")

    if response.status_code == 200:
        result = client.verify(response.text)
        print(f"  Verified: {result.valid}")
        print(f"  Payload: {json.loads(response.text).get('jacsDocument', {})}")


if __name__ == "__main__":
    print("JACS HTTP Client — verifying signed server responses\n")
    try:
        test_post()
        test_get()
    except requests.exceptions.ConnectionError:
        print("Error: Server not running. Start it with: python server.py")
