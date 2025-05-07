"""
FastMCP Authenticated Echo Demo
"""

import asyncio
import json
import uuid
import base64
import hmac
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional

from fastmcp import FastMCP, Client

# Security helpers
SECRET_KEY = b"very-secret-key-for-demo"

def generate_signature(data: Dict) -> str:
    """Generate a signature for data"""
    data_json = json.dumps(data, sort_keys=True)
    signature = hmac.new(SECRET_KEY, data_json.encode(), hashlib.sha256).digest()
    return base64.b64encode(signature).decode()

def verify_signature(data: Dict, signature: str) -> bool:
    """Verify a signature for data"""
    expected = generate_signature(data)
    return hmac.compare_digest(expected, signature)

# Simple demo that embeds auth directly in payload
async def run_auth_demo():
    # Create server
    server = FastMCP("AuthEchoServer")
    
    @server.tool(name="echos", description="Echos with authentication")
    async def echos(msg: str, auth: Dict = None) -> str:
        """Echo with authentication"""
        # Log to file instead of printing
        with open("server_logs.txt", "a") as log:
            log.write("\n=== SERVER RECEIVED REQUEST ===\n")
            log.write(f"Message: {msg}\n")
            log.write(f"Auth: {auth}\n")
            
            # Validate request
            auth_valid = False
            if auth and "data" in auth and "signature" in auth:
                # Verify signature
                auth_valid = verify_signature(auth["data"], auth["signature"])
                log.write(f"Auth valid: {auth_valid}\n")
            else:
                log.write("Missing auth data or signature\n")
            
            # Create response with embedded auth
            response_data = {
                "text": f"Echo: {msg}",
                "timestamp": datetime.now().isoformat(),
                "auth_valid": auth_valid
            }
            
            # Sign the response
            response_signature = generate_signature(response_data)
            
            # Embed auth in response as JSON
            response_json = json.dumps({
                "result": response_data,
                "auth": {
                    "data": {
                        "server_id": "s1",
                        "res_id": f"res-{uuid.uuid4()}",
                        "timestamp": datetime.now().isoformat()
                    },
                    "signature": response_signature
                }
            })
            
            log.write(f"Sending response: {response_json}\n")
            log.write("=== END SERVER PROCESSING ===\n")
            log.flush()
            
            # Try returning just a simple string instead of JSON
            return f"Echo via SSESSS: {str(response_json)} s"
    
    # Start server
    import uvicorn
    from uvicorn.config import Config
    from uvicorn.server import Server
    
    app = server.sse_app()
    config = Config(app=app, host="0.0.0.0", port=8000, log_level="warning")
    uvicorn_server = Server(config=config)
    server_task = asyncio.create_task(uvicorn_server.serve())
    
    await asyncio.sleep(1)
    print("Server started")
    
    try:
        # Client code
        async with Client("http://localhost:8000/sse") as client:
            print("\n=== CLIENT SENDING REQUEST ===")
            
            # Prepare auth data
            auth_data = {
                "client_id": "c1",
                "req_id": f"req-{uuid.uuid4()}",
                "timestamp": datetime.now().isoformat()
            }
            
            # Sign the auth data
            auth_signature = generate_signature(auth_data)
            
            # Prepare parameters with embedded auth
            params = {
                "msg": "Hello secure world",
                "auth": {
                    "data": auth_data,
                    "signature": auth_signature
                }
            }
            
            print(f"Request params: {params}")
            
            # Call the tool
            result = await client.call_tool("echos", params)
            print("\n=== CLIENT RECEIVED RESPONSE ===")
            print(f"Raw result: {result}")
            
            # Parse the response
            if isinstance(result, list) and len(result) > 0:
                # Response is a TextContent object
                content_object = result[0]
                if hasattr(content_object, 'text'):
                    content = content_object.text
                    
                    # Extract the JSON part from the string
                    try:
                        # Find the start and end of the JSON object
                        json_start = content.find('{')
                        json_end = content.rfind('}') + 1
                        
                        if json_start != -1 and json_end != -1:
                            json_string = content[json_start:json_end]
                            
                            # Parse the extracted JSON string
                            response_json = json.loads(json_string)
                            print(f"Parsed JSON response: {response_json}")
                            
                            # Verify the response authentication
                            if "result" in response_json and "auth" in response_json:
                                response_data = response_json["result"]
                                auth = response_json["auth"]
                                
                                if "data" in auth and "signature" in auth:
                                    # Verify signature
                                    is_valid = verify_signature(auth["data"], auth["signature"])
                                    print(f"Response signature valid: {is_valid}")
                                    print(f"Response data: {response_data}")
                                    print(f"Auth data: {auth['data']}")
                                else:
                                    print("Missing auth data or signature in response")
                            else:
                                print("Invalid response format")
                        else:
                            print("Could not find JSON object in response string")
                    except json.JSONDecodeError:
                        print(f"Failed to parse extracted JSON: {json_string}")
                    except Exception as e:
                        print(f"Error processing response content: {e}")
                else:
                    print("TextContent object does not have 'text' attribute")
            else:
                print("Unexpected response format")
    finally:
        # Shutdown server
        uvicorn_server.should_exit = True
        await server_task
        print("Server stopped")

if __name__ == "__main__":
    asyncio.run(run_auth_demo())