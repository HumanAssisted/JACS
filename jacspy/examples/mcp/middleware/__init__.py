import jacs





def JACSMCPClient(url, **kwargs):
    """Creates a FastMCP client with JACS authentication interceptors"""
    
    # Create original client with standard transport
    transport = SSETransport(url)
    
    # Custom connect function that injects our interceptors
    @contextlib.asynccontextmanager
    async def patched_connect_session(**session_kwargs):
        async with sse_client(transport.url, headers=transport.headers) as transport_streams:
            original_read_stream, original_write_stream = transport_streams
            
            # Create intercepting write stream
            original_send = original_write_stream.send
            async def intercepted_send(message, **send_kwargs):
                print(f"→ Original outgoing message: {message.root}")
                # Sign the message here
                if isinstance(message.root, dict):
                    message.root = jacs.sign_request(message.root)
                print(f"→ Signed outgoing message: {message.root}")
                return await original_send(message, **send_kwargs)
            
            # Replace the send method
            original_write_stream.send = intercepted_send
            
            # Create intercepting read stream
            original_receive = original_read_stream.receive
            async def intercepted_receive(**receive_kwargs):
                message = await original_receive(**receive_kwargs)
                print(f"← Original incoming message: {message.root}")
                # Verify the message here
                if isinstance(message.root, dict):
                    message.root = jacs.verify_response(message.root)
                print(f"← Verified incoming message: {message.root}")
                return message
            
            # Replace the receive method
            original_read_stream.receive = intercepted_receive
            
            # Create session with the intercepted streams
            async with ClientSession(
                original_read_stream, original_write_stream, **session_kwargs
            ) as session:
                await session.initialize()
                yield session
    
    # Replace the transport's connect_session with our patched version
    transport.connect_session = patched_connect_session
    
    # Create client with patched transport
    return Client(transport, **kwargs)



def JACSMCPServer(mcp_server):
    """Creates a FastMCP server with JACS authentication interceptors"""
    
    # Keep a reference to the original sse_app method
    original_sse_app = mcp_server.sse_app
    
    # Create a patched version that adds our middleware
    def patched_sse_app():
        app = original_sse_app()
        
        # Add custom middleware to intercept raw requests/responses
        @app.middleware("http")
        async def jacs_authentication_middleware(request, call_next):
            # For incoming requests (can parse JSON body here)
            if request.url.path.endswith("/messages/"):
                # This is a JSON-RPC request
                body = await request.body()
                if body:
                    try:
                        data = json.loads(body)
                        # Verify the request
                        verified_data = jacs.verify_request(data)
                        # Replace the request body
                        request._body = json.dumps(verified_data).encode()
                    except Exception as e:
                        print(f"Error verifying request: {e}")
            
            # Process the request
            response = await call_next(request)
            
            # For outgoing responses
            if "application/json" in response.headers.get("content-type", ""):
                # This is a JSON-RPC response
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk
                
                try:
                    data = json.loads(body.decode())
                    # Sign the response
                    signed_data = jacs.sign_response(data)
                    # Create a new response
                    return Response(
                        content=json.dumps(signed_data).encode(),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type
                    )
                except Exception as e:
                    print(f"Error signing response: {e}")
            
            return response
        
        return app
    
    # Replace the sse_app method
    mcp_server.sse_app = patched_sse_app
    
    return mcp_server











# class JACSMCPMiddleware:
#     """Base middleware class that can be extended"""
#     def __init__(self, next_middleware=None):
#         self.next = next_middleware
    
#     async def process_request(self, method, params):
#         """Process incoming request before reaching the handler"""
#         if self.next:
#             return await self.next.process_request(method, params)
#         return params
    
#     async def process_response(self, method, result):
#         """Process outgoing response after handler execution"""
#         if self.next:
#             return await self.next.process_response(method, result)
#         return result

# class JACSMCPProxy:
#     """Server-side proxy that applies middleware to FastMCP"""
#     def __init__(self, mcp_instance, middleware=None):
#         self.mcp = mcp_instance
#         self.middleware = middleware
    
#     def tool(self, *args, **kwargs):
#         """Wrap the tool decorator to apply middleware"""
#         mcp_decorator = self.mcp.tool(*args, **kwargs)
        
#         def wrapper(func):
#             @functools.wraps(func)
#             async def middleware_wrapper(*args, **kwargs):
#                 # Extract method name from func
#                 method = func.__name__
                
#                 # Process request through middleware chain
#                 if self.middleware:
#                     kwargs = await self.middleware.process_request(method, kwargs)
                
#                 # Call original function
#                 result = await func(*args, **kwargs)
                
#                 # Process response through middleware chain
#                 if self.middleware:
#                     result = await self.middleware.process_response(method, result)
                
#                 return result
            
#             # Apply the original decorator
#             return mcp_decorator(middleware_wrapper)
        
#         return wrapper
    
#     # Similar wrappers for resource, prompt, etc.
    
#     # Delegate other methods to the underlying mcp instance
#     def __getattr__(self, name):
#         return getattr(self.mcp, name)
# # Create your middleware
# class JACSAuthMiddleware(JACSMCPMiddleware):
#     async def process_request(self, method, params):
#         print(f"Server received request: {params}")
        
#         # Extract the original parameters if they exist
#         original_params = params.get('_original_params', params)
        
#         try:
#             # Verify the request signature
#             jacs.verify_request(params)
#             print("Server verified request signature")
#         except Exception as e:
#             print(f"Failed to verify request signature: {e}")
#             # Continue with request processing even if verification fails
            
#         # Continue with the middleware chain using the original parameters
#         return await super().process_request(method, original_params)
    
#     async def process_response(self, method, result):
#         print(f"Server processing response: {result}")
        
#         # Process through the middleware chain first
#         processed_result = await super().process_response(method, result)
        
#         # Sign the response
#         try:
#             signed_result = jacs.sign_response(processed_result)
#             print(f"Server signed response")
#             return signed_result
#         except Exception as e:
#             print(f"Failed to sign response: {e}")
#             return processed_result
