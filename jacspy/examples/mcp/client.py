# use request to send a response to the server

import asyncio
import os
from pathlib import Path
import jacs
from fastmcp import Client

# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.client.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))

# class JACSClientMiddleware:
#     """Base client middleware class"""
#     def __init__(self, next_middleware=None):
#         self.next = next_middleware
    
#     async def process_request(self, method, params):
#         """Process outgoing request before sending"""
#         if self.next:
#             return await self.next.process_request(method, params)
#         return params
    
#     async def process_response(self, method, result):
#         """Process incoming response after receiving"""
#         if self.next:
#             return await self.next.process_response(method, result)
#         return result

# class JACSAuthClientMiddleware(JACSClientMiddleware):
#     """Authentication middleware for client"""
#     async def process_request(self, method, params):
#         # Store original params for later use
#         print(f"Client sending request to {method}: {params}")
        
#         # Sign the request using JACS but preserve original parameters structure
#         signed_result = jacs.sign_request(params or {})
        
#         # If signed_result is a string, convert to dict
#         if isinstance(signed_result, str):
#             import json
#             try:
#                 signed_params = json.loads(signed_result)
#             except json.JSONDecodeError:
#                 signed_params = {"metadata": signed_result}
#         else:
#             signed_params = signed_result
            
#         # Add the original params as a sub-field
#         if '_original_params' not in signed_params:
#             signed_params['_original_params'] = params
            
#         return await super().process_request(method, signed_params)
    
#     async def process_response(self, method, result):
#         print(f"Client received raw response from {method}: {result}")
#         try:
#             # Handle different result types
#             content = None
#             if hasattr(result, 'text'):  # TextContent object
#                 content = result.text
#             elif isinstance(result, list) and len(result) > 0 and hasattr(result[0], 'text'):
#                 content = result[0].text
#             else:
#                 content = result
                
#             # Verify the response
#             verified_result = jacs.verify_response(content)
#             print(f"Client verified response: {verified_result}")
            
#             return await super().process_response(method, verified_result)
#         except Exception as e:
#             print(f"Failed to verify response: {e}")
#             return result

# class JACSAuthClient:
#     """Client wrapper that applies middleware to MCP Client"""
#     def __init__(self, url, middleware=None, **client_kwargs):
#         self.url = url
#         self.middleware = middleware
#         self.client_kwargs = client_kwargs
#         self.client = None
    
#     async def __aenter__(self):
#         self.client = await Client(self.url, **self.client_kwargs).__aenter__()
#         return self
    
#     async def __aexit__(self, exc_type, exc_val, exc_tb):
#         if self.client:
#             await self.client.__aexit__(exc_type, exc_val, exc_tb)
    
#     async def call_tool(self, tool_name, params=None, **kwargs):
#         """Call a tool with middleware processing"""
#         # Process request through middleware chain
#         if self.middleware:
#             params = await self.middleware.process_request(tool_name, params)
        
#         # Make the actual call
#         result = await self.client.call_tool(tool_name, params, **kwargs)
        
#         # Process response through middleware chain
#         if self.middleware:
#             result = await self.middleware.process_response(tool_name, result)
        
#         return result

async def main():
    # Server URL - assuming it's running locally on the default port
    server_url = "http://localhost:8000/sse"
    
    print(f"Connecting to server at {server_url}")
    
    try:
        # Create client with auth middleware
        auth_middleware = JACSAuthClientMiddleware()
        
        async with JACSAuthClient(server_url, middleware=auth_middleware) as client:
            print("Connected! Calling echo_tool...")
            
            # Test with simple string
            result = await client.call_tool("echo_tool", {"text": "Hello from authenticated client!"})
            print(f"\nFinal result: {result}")
            
            # You can add more test cases here
            
    except Exception as e:
        print(f"Error during client operation: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
 