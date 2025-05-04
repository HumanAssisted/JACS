import contextlib
from typing import Any, Callable, Dict, Optional, Coroutine, Awaitable
from fastmcp.client.transports import ClientTransport, infer_transport
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

import jacs

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
    print("AUTH: Signing Client Request", params)
    return {"client_id": "c1", "req_id": f"creq-{uuid.uuid4()}"}

def default_validate_response(metadata: dict):
    print(f"AUTH: Validating Server Response Metadata: {metadata}")

def default_validate_request(metadata: dict):
    print(f"AUTH: Validating Client Request Metadata: {metadata}")

def default_sign_response(result: Any) -> dict:
    print("AUTH: Signing Server Response", result)
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


# --- Server Wrapper (JACSFastMCP - Composition with Auto-Validation Decorators) ---
class JACSFastMCP:
    """
    Wrapper using composition to apply auth patterns:
      - Auto request validation via @mcp.tool / @mcp.resource decorators.
      - Auto response signing middleware for SSE/WS.
    """
    def __init__(
        self,
        name: str,
        # Reinstate validator function reference
        validate_request_fn: SyncMetadataCallback = default_validate_request,
        **kwargs
    ):
        print(f"DEBUG: Initializing JACSFastMCP '{name}' with validator: {validate_request_fn.__name__}")
        self._internal_mcp = FastMCP(name, **kwargs)
        self._validate_request_fn = validate_request_fn # Store validator

    # --- Internal Helper to Wrap Functions for Validation ---
    def _wrap_for_validation(self, func):
        """Wraps a tool/resource function to validate request metadata."""
        # Check if the function is already wrapped (simple check)
        if hasattr(func, '_jacs_validated'):
            return func

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            print(f"DEBUG: JACS Validation Wrapper executing for {func.__name__}")
            metadata = kwargs.get('metadata')
            try:
                self._validate_request_fn(metadata)
            except Exception as e:
                print(f"Server Auth Error (Wrapper): Request validation failed: {e}")
                raise ValueError(f"Client metadata validation failed: {e}") from e

            original_params = inspect.signature(func).parameters
            call_kwargs = {k: v for k, v in kwargs.items() if k in original_params and k != 'metadata'}
            # Basic positional arg handling (adjust if needed for complex cases)
            num_positional_expected = sum(1 for p in original_params.values() if p.kind in [p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD])
            num_positional_to_pass = min(len(args), num_positional_expected)

            call_args = args[:num_positional_to_pass]

            # print(f"DEBUG: Calling original {func.__name__} with args: {call_args}, kwargs: {call_kwargs}")
            return await func(*call_args, **call_kwargs)

        wrapper._jacs_validated = True # Mark as wrapped
        return wrapper

    # --- Modified Tool Decorator Factory (Accepts & Filters 'strict') ---
    def tool(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        strict: bool = False, # Explicitly accept 'strict'
        **kwargs # Accept any other potential kwargs
    ):
        """
        Registers a tool, automatically wrapping it for request validation.
        Accepts 'strict' param but does not pass it to underlying FastMCP.tool.
        """
        print(f"DEBUG: JACSFastMCP.tool called with name={name}, strict={strict}, kwargs={kwargs}")
        # **kwargs might contain other valid arguments for the underlying tool decorator later
        # We explicitly filter out 'strict' before passing kwargs down.

        # Log a warning if strict=True is used, as it has no effect currently
        if strict:
            print("WARN: 'strict=True' provided to JACSFastMCP.tool, but the underlying FastMCP does not support it. Parameter ignored.")

        def decorator(func):
            wrapped_func = self._wrap_for_validation(func)
            # Register the wrapped function, passing name, description, and **kwargs (excluding strict)
            # The underlying call only receives arguments it expects.
            self._internal_mcp.tool(name=name, description=description, **kwargs)(wrapped_func)
            return func
        return decorator

    # --- Modified Resource Decorator Factory (Apply similar logic if needed) ---
    def resource(
        self,
        uri_template: str,
        description: Optional[str] = None,
        strict: bool = False, # Example: Add strict here too if desired
        **kwargs
    ):
        """
        Registers a resource provider, automatically wrapping it for request validation.
        Accepts 'strict' param but does not pass it down.
        """
        if strict:
             print("WARN: 'strict=True' provided to JACSFastMCP.resource, parameter ignored.")

        def decorator(func):
            wrapped_func = self._wrap_for_validation(func)
            self._internal_mcp.resource(uri_template=uri_template, description=description, **kwargs)(wrapped_func)
            return func
        return decorator

    # --- Delegated List Method (Assuming it's not a decorator for functions needing validation) ---
    def list(self, *args, **kwargs):
        """Delegates the list call to the internal FastMCP instance."""
        # Check if _internal_mcp.list exists and is callable
        if hasattr(self._internal_mcp, 'list') and callable(self._internal_mcp.list):
            return self._internal_mcp.list(*args, **kwargs)
        else:
            # Handle case where FastMCP might not have a 'list' method
            raise NotImplementedError("The underlying FastMCP object does not have a 'list' method.")


    # --- ASGI App Methods (Apply response signing middleware) ---
    def sse_app(self) -> Any:
        print("DEBUG: JACSFastMCP generating SSE app with response signing middleware")
        app = self._internal_mcp.sse_app()
        # Middleware uses default_sign_response by default
        app.add_middleware(MetadataInjectingMiddleware)
        return app

    def ws_app(self) -> Any:
        print("DEBUG: JACSFastMCP generating WS app with response signing middleware")
        app = self._internal_mcp.ws_app()
        app.add_middleware(MetadataInjectingMiddleware)
        return app

    # --- Run Method (Unchanged from previous version) ---
    def run(self, transport: Optional[str] = None, **kwargs):
        # ... (logic to default to stdio, delegate stdio run, error for sse/ws) ...
        if transport is None:
            effective_transport = 'stdio'
            print("DEBUG: JACSFastMCP run: No transport specified, defaulting to 'stdio'")
        else:
            effective_transport = transport
            print(f"DEBUG: JACSFastMCP run: Explicit transport specified: '{effective_transport}'")

        if effective_transport == 'stdio':
            print(f"DEBUG: JACSFastMCP running Stdio transport for '{self._internal_mcp.name}' (Auth handled by decorator/manual return)")
            self._internal_mcp.run(transport='stdio', **kwargs)
        elif effective_transport in ['sse', 'ws']:
            print(f"ERROR: For {effective_transport.upper()} transport, get app via .{effective_transport}_app() and run with uvicorn.")
            raise NotImplementedError(f"Direct run for {effective_transport.upper()} not supported. Use .{effective_transport}_app() with uvicorn.")
        else:
            print(f"DEBUG: JACSFastMCP attempting to run '{effective_transport}' via internal FastMCP (Auth behavior unknown)")
            self._internal_mcp.run(transport=effective_transport, **kwargs)


    # --- Delegated Properties ---
    @property
    def settings(self): return self._internal_mcp.settings
    @property
    def name(self): return self._internal_mcp.name
