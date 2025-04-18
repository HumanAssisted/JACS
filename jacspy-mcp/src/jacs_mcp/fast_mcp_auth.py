import contextlib
from typing import Any, Callable, Dict, Optional, Coroutine, Awaitable, Union
from fastmcp.client.transports import PythonStdioTransport, SSETransport, FastMCPTransport, ClientTransport, infer_transport
import uuid
import json
import traceback
import functools
import inspect

# For FastAPI Middleware (add necessary imports if not present)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse, StreamingResponse

# Ensure JSONRPCMessage is imported if needed for type hinting
from mcp.types import JSONRPCMessage
from fastmcp import FastMCP, Client, Context


# --- Deprecated Example Function ---
def get_metadata() -> Dict[str, str]:
    """DEPRECATED example function."""
    return {"client_id": "deprecated", "request_id": "deprecated"}

# --- Deprecated AuthTransport Class ---
class AuthTransport:
    """DEPRECATED by AuthClient/JACSFastMCP approach."""
    # ... (implementation omitted for brevity) ...
    pass


# --- User-defined function types and Defaults ---
SyncMetadataCallback = Callable[[Dict[str, Any]], None]
MessageHandlerFnT = Callable[[Dict[str, Any]], Coroutine[Any, Any, Optional[Dict[str, Any]]]]

def default_sign_request(params: dict) -> dict:
    print("AUTH: Signing Client Request")
    return {"client_id": "c1", "req_id": f"creq-{uuid.uuid4()}"}

def default_validate_response(metadata: dict):
    print(f"AUTH: Validating Server Response Metadata: {metadata}")

def default_validate_request(metadata: dict):
    print(f"AUTH: Validating Client Request Metadata: {metadata}")

def default_sign_response(result: Any) -> dict:
    print("AUTH: Signing Server Response")
    return {"server_id": "s1", "res_id": f"sres-{uuid.uuid4()}"}


# --- Client-Side Injection Transport (AuthInjectTransport) ---
class AuthInjectTransport(ClientTransport):
    """CLIENT-SIDE INJECTOR: Wraps a transport to inject metadata into outgoing requests' params."""
    # ... (implementation from previous working version) ...
    def __init__(
        self,
        base_transport: Any,
        sign_request_fn: Callable[[dict], dict], # Expects the user's signing function
    ):
        self.base = base_transport
        self.sign_request_fn = sign_request_fn

    @contextlib.asynccontextmanager
    async def connect_session(self, **kwargs):
        async with self.base.connect_session(**kwargs) as session:
            try:
                original_stream_send = session._write_stream.send
            except AttributeError:
                 raise RuntimeError("Could not find session._write_stream.send to patch.") from None

            async def stream_send_with_meta(message: JSONRPCMessage, **send_kwargs):
                if hasattr(message, 'root') and isinstance(message.root, dict) and message.root.get("method"):
                    request_params = message.root.get("params", {})
                    metadata_to_inject = self.sign_request_fn(request_params or {})
                    current_params = message.root.get("params")
                    if isinstance(current_params, dict):
                         current_params["metadata"] = metadata_to_inject
                         message.root["params"] = current_params
                    elif current_params is None:
                         message.root["params"] = {"metadata": metadata_to_inject}
                    else:
                        print(f"Warning: Cannot inject metadata into non-dict params: {current_params}")
                await original_stream_send(message, **send_kwargs)

            session._write_stream.send = stream_send_with_meta
            try: yield session
            finally: session._write_stream.send = original_stream_send

    def __repr__(self) -> str: return f"<AuthInjectTransport wrapping {self.base!r}>"


# --- Client-Side Reading Handler Factory (create_metadata_reading_handler) ---
def create_metadata_reading_handler(
    validate_response_fn: SyncMetadataCallback,
    original_handler: Optional[MessageHandlerFnT] = None,
) -> MessageHandlerFnT:
    """CLIENT-SIDE READER: Creates handler to extract metadata and call validator."""
    # ... (implementation from previous working version) ...
    async def handle_message_with_metadata(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        processed_message: Optional[Dict[str, Any]] = message
        if isinstance(message, dict) and "metadata" in message:
            try:
                validate_response_fn(message["metadata"])
            except Exception as e:
                 print(f"Client Auth Error: Response validation failed: {e}")
        if original_handler and processed_message is not None:
            processed_message = await original_handler(processed_message)
        return processed_message
    return handle_message_with_metadata


# --- Client Wrapper (AuthClient - Revised call_tool Logic) ---
class AuthClient:
    """Client wrapper providing transparent request signing and response validation."""
    # ... (implementation from previous working version, including __init__ and call_tool) ...
    def __init__(
        self,
        transport: Any,
        sign_request_fn: Callable[[dict], dict] = default_sign_request,
        validate_response_fn: SyncMetadataCallback = default_validate_response,
        **client_kwargs
    ):
        base_transport = infer_transport(transport)
        auth_transport = AuthInjectTransport(base_transport, sign_request_fn)
        # The message handler will validate metadata but its return value isn't directly used by call_tool's logic below
        auth_handler = create_metadata_reading_handler(validate_response_fn)
        self._client = Client(auth_transport, message_handler=auth_handler, **client_kwargs)

    async def __aenter__(self): await self._client.__aenter__(); return self
    async def __aexit__(self, exc_type, exc_val, exc_tb): await self._client.__aexit__(exc_type, exc_val, exc_tb)

    async def call_tool(self, tool_name: str, params: dict | None = None, **kwargs):
        # AuthInjectTransport signs the request.
        # auth_handler (message_handler) attempts to validate the response metadata in the background.
        raw_response = await self._client.call_tool(tool_name, params, **kwargs)
        print(f"DEBUG: AuthClient received raw_response: {raw_response!r} (type: {type(raw_response)})")

        # --- New Logic based on observed behavior ---
        if isinstance(raw_response, list):
            if len(raw_response) > 0:
                # Assume the first item in the list is the actual result content
                print(f"DEBUG: Assuming first item of list is the result: {raw_response[0]!r}")
                # We might need to check if raw_response[0] represents an error later if possible
                return raw_response[0]
            else:
                # Handle empty list case - perhaps signifies no result?
                print("WARN: Received empty list from client.call_tool, returning None.")
                return None
        elif raw_response is not None:
             # If it's not a list and not None, assume it's the result content directly
             print(f"DEBUG: Assuming non-list response is the result: {raw_response!r}")
             # Need to consider if this could be an error object
             return raw_response
        else:
            # Handle None case
            print("WARN: Received None from client.call_tool, returning None.")
            return None

        # Note: This simplification means we are not explicitly checking for JSON-RPC level errors
        # returned within the raw_response structure itself (like we did before with hasattr error).
        # We rely on fastmcp.Client or the transport to raise exceptions for communication errors,
        # and the message_handler for metadata validation errors. Errors reported by the *server*
        # via the JSON-RPC 'error' field might not be caught and raised as exceptions here.


# --- Server Response Signing Middleware (MetadataInjectingMiddleware) ---
class MetadataInjectingMiddleware(BaseHTTPMiddleware):
    """SERVER-SIDE RESPONSE SIGNER (FastAPI): Injects metadata into outgoing JSON-RPC responses."""
    def __init__(
        self,
        app,
        # Default meta_fn directly to default_sign_response from this module
        meta_fn: Callable[[Any], dict] = default_sign_response,
    ):
        super().__init__(app)
        # Store the signing function (will be default_sign_response unless overridden)
        self.sign_response_fn = meta_fn # Keep storing it

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[StarletteResponse]]
    ) -> StarletteResponse:
        response = await call_next(request)
        if isinstance(response, StreamingResponse):
            response.body_iterator = self._modify_stream(response.body_iterator)
        elif response.headers.get("content-type") == "application/json":
            response_body = b""
            async for chunk in response.body_iterator: response_body += chunk
            try:
                data = json.loads(response_body.decode("utf-8"))
                if isinstance(data, dict) and data.get("jsonrpc") == "2.0" and ("result" in data or "error" in data):
                     # Call the stored signing function
                     metadata_to_inject = self.sign_response_fn(data.get("result")) # Pass result to signer
                     data.setdefault("metadata", {}).update(metadata_to_inject)
                     modified_body = json.dumps(data).encode("utf-8")
                     response = StarletteResponse(content=modified_body, status_code=response.status_code, headers=dict(response.headers), media_type="application/json")
                     response.headers["content-length"] = str(len(modified_body))
                else: response = StarletteResponse( content=response_body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type)
            except Exception: print("Error modifying JSON response in middleware"); traceback.print_exc(); response = StarletteResponse( content=response_body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type)
        return response

    async def _modify_stream(self, original_iterator):
        buffer = ""
        async for chunk in original_iterator:
            try:
                buffer += chunk.decode("utf-8")
                while "\n\n" in buffer:
                    event_str, buffer = buffer.split("\n\n", 1)
                    if event_str.startswith("data:"):
                        try:
                            data_part = event_str[len("data:"):].strip()
                            data = json.loads(data_part)
                            if isinstance(data, dict) and data.get("jsonrpc") == "2.0" and ("result" in data or "error" in data):
                                 metadata_to_inject = self.sign_response_fn(data.get("result"))
                                 data.setdefault("metadata", {}).update(metadata_to_inject)
                                 modified_event = f"data: {json.dumps(data)}\n\n"
                                 yield modified_event.encode("utf-8")
                                 continue
                        except json.JSONDecodeError: pass
                    yield (event_str + "\n\n").encode("utf-8")
            except Exception: print("Error modifying stream in middleware"); traceback.print_exc();
            if buffer: yield buffer.encode('utf-8'); buffer = ""
            else: yield chunk
        if buffer:
            try: yield buffer.encode("utf-8")
            except Exception: print("Error yielding final buffer content in middleware"); traceback.print_exc()


# --- Server Wrapper (JACSFastMCP - Composition Approach - Fixed Run Logic) ---
class JACSFastMCP:
    """Wrapper using composition to apply auth patterns (auto response signing middleware)."""
    def __init__(
        self,
        name: str,
        # REMOVED sign_response_fn parameter
        # validate_request_fn is not used here yet
        **kwargs
    ):
        print(f"DEBUG: Initializing JACSFastMCP '{name}'")
        self._internal_mcp = FastMCP(name, **kwargs)
        # No need to store _sign_response_fn if we always use the middleware default

    def tool(self, *args, **kwargs):
        return self._internal_mcp.tool(*args, **kwargs)

    def sse_app(self) -> Any:
        print("DEBUG: JACSFastMCP generating SSE app")
        app = self._internal_mcp.sse_app()
        app.add_middleware(MetadataInjectingMiddleware)
        return app

    def ws_app(self) -> Any: # Assuming ws_app exists
        print("DEBUG: JACSFastMCP generating WS app")
        app = self._internal_mcp.ws_app()
        app.add_middleware(MetadataInjectingMiddleware)
        return app

    # --- MODIFIED Run Method ---
    def run(self, transport: Optional[str] = None, **kwargs):
        """
        Runs the server. Handles Stdio directly, requires manual uvicorn setup
        for SSE/WS using the .sse_app() or .ws_app() methods.
        """
        # Determine effective transport - Default to 'stdio' if None
        if transport is None:
            effective_transport = 'stdio'
            print("DEBUG: JACSFastMCP run: No transport specified, defaulting to 'stdio'")
        else:
            effective_transport = transport
            print(f"DEBUG: JACSFastMCP run: Explicit transport specified: '{effective_transport}'")

        # --- Branch based on effective transport ---
        if effective_transport == 'stdio':
            print(f"DEBUG: JACSFastMCP running Stdio transport for '{self._internal_mcp.name}' (Auth handled by decorator/manual return)")
            # Delegate Stdio run to the internal FastMCP instance
            # The @validate_tool_request decorator handles request validation.
            # The tool function MUST manually handle response signing for Stdio.
            self._internal_mcp.run(transport='stdio', **kwargs)

        elif effective_transport in ['sse', 'ws']:
            # Guide user to use uvicorn for ASGI transports
            print(f"ERROR: For {effective_transport.upper()} transport, get app via .{effective_transport}_app() and run with uvicorn.")
            print(f"Example: uvicorn your_server_module:{effective_transport}_app --host localhost --port 8000")
            raise NotImplementedError(f"Direct run for {effective_transport.upper()} not supported. Use .{effective_transport}_app() with uvicorn.")

        else:
            # Attempt to run any other specified transports directly via internal FastMCP
            # Behavior for these other transports regarding auth is undefined here.
            print(f"DEBUG: JACSFastMCP attempting to run '{effective_transport}' via internal FastMCP (Auth behavior unknown)")
            self._internal_mcp.run(transport=effective_transport, **kwargs)

    @property
    def settings(self): return self._internal_mcp.settings
    @property
    def name(self): return self._internal_mcp.name


# --- NEW: Tool Request Validation Decorator ---
def validate_tool_request(validator_func: SyncMetadataCallback = default_validate_request):
    """
    Decorator for FastMCP tool functions to automatically validate incoming request metadata.

    It extracts 'metadata' from kwargs, calls the validator, and then calls
    the original tool function with only its explicitly defined arguments.
    """
    def decorator(tool_func):
        @functools.wraps(tool_func)
        async def wrapper(*args, **kwargs):
            print(f"DEBUG: @validate_tool_request wrapping {tool_func.__name__}, received kwargs: {list(kwargs.keys())}")

            metadata = kwargs.get('metadata')

            # Call the validator function
            try:
                validator_func(metadata) # Use the provided or default validator
            except Exception as e:
                print(f"Server Auth Error (@validate_tool_request): Request validation failed: {e}")
                # Re-raise to signal error to FastMCP/FastAPI
                raise ValueError(f"Client metadata validation failed: {e}") from e

            # Prepare args for the original function, filtering out metadata
            original_params = inspect.signature(tool_func).parameters
            call_kwargs = {k: v for k, v in kwargs.items() if k in original_params and k != 'metadata'}

            # Ensure all positional args expected by the original function are present
            # This handles 'self' or 'cls' if it's a method, and context, etc.
            # We assume FastMCP passes positional args correctly first.
            call_args = args[:len(original_params) - len(call_kwargs)] # Basic positional arg handling

            print(f"DEBUG: Calling original tool {tool_func.__name__} with args: {call_args}, kwargs: {call_kwargs}")
            return await tool_func(*call_args, **call_kwargs)

        return wrapper
    return decorator


# --- REMOVED AuthFastMCPServer (Inheritance version) ---
