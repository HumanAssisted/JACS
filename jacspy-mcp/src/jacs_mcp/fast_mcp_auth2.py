import json
import logging
import contextlib
import uuid
from fastmcp import FastMCP, Client, Context
from fastmcp.client.transports import ClientTransport, infer_transport
from starlette.middleware.base import BaseHTTPMiddleware
import asyncio
import sys
from starlette.applications import Starlette
from starlette.routing import Mount
from typing import Dict, Any, Optional
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("auth_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("auth")

# -- Server implementation --
class JACSFastMCP(FastMCP):
    def __init__(self, name, validate_request_fn=None, sign_response_fn=None, **kwargs):
        super().__init__(name, **kwargs)
        self._validate_request = validate_request_fn or default_validate_request
        self._sign_response = sign_response_fn or default_sign_response
        
        # Create a file logger
        self.log_file = open("server_debug.log", "w")
        self.log_file.write("=== SERVER STARTED ===\n")
        self.log_file.write(f"Registered tools: {getattr(self, '_tool_manager', None)}\n")
        self.log_file.flush()
        
    # Custom middleware for SSE app
    def sse_app(self):
        app = super().sse_app()
        
        # Log what routes and middleware are available
        with open("server_debug.log", "a") as f:
            f.write("\n=== APP INSPECTION ===\n")
            f.write(f"Routes: {app.routes}\n")
            if hasattr(app, "middleware"):
                f.write(f"Middleware: {app.middleware}\n")
            f.flush()
        
        # Create middleware for response signing
        class ResponseSigningMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, jacs_server):
                super().__init__(app)
                self.jacs_server = jacs_server
                logger.info("Initializing ResponseSigningMiddleware")
                
            async def dispatch(self, request, call_next):
                # Check for metadata in request
                if request.method == "POST":
                    try:
                        # Get request body
                        body = await request.body()
                        body_text = body.decode('utf-8')
                        logger.info(f"REQUEST RECEIVED: {request.url.path}")
                        
                        # Try to parse JSON
                        try:
                            data = json.loads(body_text)
                            
                            # Check for tool call
                            if isinstance(data, dict) and data.get("method") == "tools/call" and "params" in data:
                                params = data["params"]
                                
                                # Extract metadata if present
                                if "arguments" in params and "metadata" in params["arguments"]:
                                    metadata = params["arguments"]["metadata"]
                                    logger.info(f"REQUEST METADATA: {metadata}")
                                    
                                    # Validate metadata
                                    try:
                                        self.jacs_server._validate_request(metadata)
                                        logger.info("REQUEST METADATA VALIDATED")
                                    except Exception as e:
                                        logger.error(f"METADATA VALIDATION ERROR: {e}")
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse request body as JSON: {body_text[:100]}")
                        
                        # Important: Put the body back
                        request._body = body
                    except Exception as e:
                        logger.error(f"Error processing request: {e}")
                
                # Continue with the middleware chain
                response = await call_next(request)
                
                # Handle SSE responses (they use body_iterator)
                if hasattr(response, "body_iterator"):
                    original_iterator = response.body_iterator
                    
                    async def modified_iterator():
                        # Buffer for collecting SSE events
                        buffer = ""
                        
                        async for chunk in original_iterator:
                            # Convert chunk to text
                            if isinstance(chunk, bytes):
                                chunk_text = chunk.decode('utf-8')
                            else:
                                chunk_text = str(chunk)
                            
                            # Add to buffer
                            buffer += chunk_text
                            
                            # Process complete SSE events (format: "data: {...}\n\n")
                            while "\n\n" in buffer:
                                event, buffer = buffer.split("\n\n", 1)
                                
                                # Only process data events
                                if event.startswith("data:"):
                                    try:
                                        # Extract JSON data
                                        data_part = event[5:].strip()
                                        data = json.loads(data_part)
                                        
                                        # Only process JSON-RPC responses
                                        if isinstance(data, dict) and data.get("jsonrpc") == "2.0":
                                            # Sign the response
                                            result = data.get("result")
                                            metadata = self.jacs_server._sign_response(result)
                                            logger.info(f"SIGNING RESPONSE: {result}")
                                            logger.info(f"RESPONSE METADATA: {metadata}")
                                            
                                            # Add metadata to the response
                                            data["metadata"] = metadata
                                            
                                            # Replace the event data
                                            event = f"data: {json.dumps(data)}"
                                            logger.info("RESPONSE SIGNED")
                                    except json.JSONDecodeError:
                                        logger.warning(f"Failed to parse SSE data as JSON: {data_part[:100]}")
                                    except Exception as e:
                                        logger.error(f"Error signing response: {e}")
                                
                                # Yield the event (modified or original)
                                yield (event + "\n\n").encode()
                            
                        # Yield any remaining buffer
                        if buffer:
                            yield buffer.encode()
                    
                    # Replace the original iterator with our modified version
                    response.body_iterator = modified_iterator()
                
                return response
        
        # Apply our custom middleware
        app.add_middleware(ResponseSigningMiddleware, jacs_server=self)
        
        # Create a simple wrapper to log all ASGI events
        async def logging_asgi(scope, receive, send):
            with open("server_debug.log", "a") as f:
                f.write(f"\n=== ASGI REQUEST ===\n")
                f.write(f"Type: {scope.get('type')}\n")
                f.write(f"Path: {scope.get('path')}\n")
                f.write(f"Method: {scope.get('method')}\n")
                f.flush()
            
            # Pass to the original app
            await app(scope, receive, send)
        
        # Return the original app
        return app
    
    # Modify tool decorator to add metadata validation
    def tool(self, name=None, description=None, **kwargs):
        """Decorator to register a tool with metadata validation"""
        
        def decorator(func):
            import inspect
            import functools
            
            # Log the tool registration
            with open("server_debug.log", "a") as f:
                f.write(f"\n=== REGISTERING TOOL ===\n")
                f.write(f"Name: {name or func.__name__}\n")
                f.write(f"Description: {description}\n")
                f.write(f"Function: {func}\n")
                f.write(f"Signature: {inspect.signature(func)}\n")
                f.flush()
            
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                # Log tool execution
                with open("server_debug.log", "a") as f:
                    f.write(f"\n=== TOOL EXECUTION ===\n")
                    f.write(f"Tool: {name or func.__name__}\n")
                    f.write(f"Args: {args}\n")
                    f.write(f"Kwargs: {kwargs}\n")
                    f.flush()
                
                # Extract metadata from Context if available
                if 'ctx' in kwargs and kwargs['ctx'] is not None:
                    ctx = kwargs['ctx']
                    if hasattr(ctx, 'metadata') and ctx.metadata:
                        with open("server_debug.log", "a") as f:
                            f.write(f"Context metadata: {ctx.metadata}\n")
                            f.flush()
                        self._validate_request(ctx.metadata)
                
                # Call the original function
                try:
                    result = await func(*args, **kwargs)
                    with open("server_debug.log", "a") as f:
                        f.write(f"Tool result: {result}\n")
                        f.flush()
                    return result
                except Exception as e:
                    with open("server_debug.log", "a") as f:
                        f.write(f"Tool error: {e}\n")
                        import traceback
                        f.write(traceback.format_exc())
                        f.flush()
                    raise
            
            # Register with FastMCP - don't use super() here
            return FastMCP.tool(self, name=name, description=description, **kwargs)(wrapper)
        
        return decorator

# -- Client implementation --
class AuthInjectTransport(ClientTransport):
    def __init__(self, base_transport, sign_request_fn, validate_response_fn):
        self.base = base_transport
        self.sign_request_fn = sign_request_fn
        self.validate_response_fn = validate_response_fn
    
    @contextlib.asynccontextmanager
    async def connect_session(self, **kwargs):
        async with self.base.connect_session(**kwargs) as session:
            # Save original methods
            original_send = session._write_stream.send
            
            # Patch send method to inject metadata
            async def patched_send(message, **skw):
                if hasattr(message, "root") and hasattr(message.root, "method"):
                    method_name = message.root.method
                    
                    # Check for tool call method
                    if method_name == "tools/call" and hasattr(message.root, "params"):
                        params = message.root.params
                        
                        # Sign the request by adding metadata
                        logger.info(f"CLIENT SIGNING REQUEST: {params}")
                        metadata = self.sign_request_fn(params)
                        logger.info(f"CLIENT REQUEST METADATA: {metadata}")
                        
                        # Add metadata to arguments
                        if "arguments" not in params:
                            params["arguments"] = {}
                        
                        params["arguments"]["metadata"] = metadata
                        logger.info("CLIENT ADDED METADATA TO REQUEST")
                
                # Send the modified message
                await original_send(message, **skw)
            
            # Replace the send method
            session._write_stream.send = patched_send
            
            # To handle response validation, we need to intercept the raw message stream
            original_handler = getattr(session, '_message_handler', None)
            
            # Create a wrapper for the message handler
            async def message_handler_with_validation(message):
                # Check for metadata in the message
                if isinstance(message, dict) and "metadata" in message:
                    logger.info(f"CLIENT RECEIVED RESPONSE WITH METADATA: {message['metadata']}")
                    
                    try:
                        # Validate the metadata
                        self.validate_response_fn(message["metadata"])
                        logger.info("CLIENT VERIFIED RESPONSE METADATA")
                    except Exception as e:
                        logger.error(f"CLIENT METADATA VALIDATION ERROR: {str(e)}")
                
                # Call the original handler if it exists
                if original_handler:
                    return await original_handler(message)
                return message
            
            # Set the message handler
            session._message_handler = message_handler_with_validation
            
            try:
                yield session
            finally:
                # Restore original methods
                session._write_stream.send = original_send
                session._message_handler = original_handler

class AuthClient:
    def __init__(
        self,
        url,
        sign_request_fn=None,
        validate_response_fn=None,
        **client_kwargs
    ):
        self.url = url
        self.sign_request = sign_request_fn or default_sign_request
        self.validate_response = validate_response_fn or default_validate_response
        self._client = Client(url, **client_kwargs)
        logger.info("AuthClient created")
    
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    
    async def __aexit__(self, *exc):
        await self._client.__aexit__(*exc)
    
    async def call_tool(self, tool_name, params=None, **kwargs):
        logger.info(f"CALLING TOOL: {tool_name} with {params}")
        
        # Prepare parameters with metadata
        if params is None:
            params = {}
        
        # Sign the request
        metadata = self.sign_request(params)
        logger.info(f"REQUEST METADATA: {metadata}")
        
        # Make a copy of params and add metadata
        params_with_metadata = dict(params)
        params_with_metadata["metadata"] = metadata
        
        # Call the tool
        try:
            result = await self._client.call_tool(tool_name, params_with_metadata, **kwargs)
            logger.info(f"RECEIVED RESULT: {result}")
            
            # Try to extract and validate metadata from raw JSON responses 
            # (this works if MCP hasn't converted to TextContent yet)
            if isinstance(result, dict) and "metadata" in result:
                try:
                    self.validate_response(result["metadata"])
                    logger.info(f"RESPONSE METADATA VALIDATED: {result['metadata']}")
                except Exception as e:
                    logger.error(f"RESPONSE VALIDATION ERROR: {e}")
            
            return result
        except Exception as e:
            logger.error(f"ERROR CALLING TOOL: {e}")
            raise

# -- Default functions --
def default_sign_request(params):
    """Default function to sign requests"""
    return {"client_id": f"c1", "req_id": f"req-{uuid.uuid4()}"}

def default_validate_response(metadata):
    """Default function to validate response metadata"""
    if not metadata.get("server_id"):
        raise ValueError("Missing server_id in response metadata")

def default_validate_request(metadata):
    """Default function to validate request metadata"""
    if not metadata.get("client_id"):
        raise ValueError("Missing client_id in request metadata")

def default_sign_response(result):
    """Default function to sign responses"""
    return {"server_id": "s1", "res_id": f"res-{uuid.uuid4()}"}

# -- Demo implementation --
async def run_auth_demo():
    # Create server with auth
    server = JACSFastMCP("AuthServer")
    
    # Register echo tool that returns structured response
    @server.tool(name="secure_echo", description="Echo with metadata")
    async def secure_echo(msg: str, metadata: dict = None, ctx: Context = None):
        logger.info(f"SECURE_ECHO CALLED: {msg}, metadata={metadata}")
        
        # Validate request metadata (redundant but explicit)
        if metadata:
            server._validate_request(metadata)
            logger.info("REQUEST METADATA VALIDATED IN TOOL")
        
        # Create a response
        response = {
            "text": f"Secure echo: {msg}",
            "timestamp": str(datetime.datetime.now())
        }
        
        # Return structured data
        return response
    
    # Start server
    app = server.sse_app()
    
    # Add proper imports for Uvicorn
    import uvicorn
    from uvicorn.config import Config
    from uvicorn.server import Server
    
    config = Config(app=app, host="0.0.0.0", port=8000, log_level="info")
    uvicorn_server = Server(config=config)
    server_task = asyncio.create_task(uvicorn_server.serve())
    
    await asyncio.sleep(1)
    
    try:
        # Client with auth
        async with AuthClient("http://localhost:8000/sse") as client:
            result = await client.call_tool("secure_echo", {"msg": "Hello secure world"})
            print(f"RESULT: {result}")
    finally:
        uvicorn_server.should_exit = True
        await server_task

if __name__ == "__main__":
    # Add datetime import
    import datetime
    asyncio.run(run_auth_demo())