import contextlib
from typing import Any, Callable, Dict, Optional, Coroutine, Awaitable
from fastmcp.client.transports import PythonStdioTransport, SSETransport, FastMCPTransport
import uuid

# For FastAPI Middleware (add necessary imports if not present)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
import json


def get_metadata() -> Dict[str, str]:
    # Compute or refresh per‑request tokens, trace IDs, etc.
    return {
        "client_id": "trusted-client",
        "request_id": "req-" + str(uuid.uuid4()),
    }

class AuthTransport:
    """
    Wraps any supported transport to inject `metadata` into the JSON body.
    """

    def __init__(self, base_transport: Any, meta_fn: Callable[[], Dict[str, str]]):
        self.base = base_transport
        self.meta_fn = meta_fn

    @contextlib.asynccontextmanager
    async def connect_session(self, **kwargs):
        # Delegate to the underlying transport
        async with self.base.connect_session(**kwargs) as session:
            orig_send = session.send

            async def send_with_meta(message: dict, **send_kwargs):
                # JSON-RPC 2.0 envelope: always a dict
                message.setdefault("metadata", {}).update(self.meta_fn())
                return await orig_send(message, **send_kwargs)

            session.send = send_with_meta
            yield session


# --- Client-Side Metadata Injection ---

def get_client_metadata() -> Dict[str, str]:
    # Compute or refresh per‑request tokens, trace IDs, etc.
    return {
        "client_id": "trusted-client",
        "client_request_id": "req-" + str(uuid.uuid4()),
    }


class AuthInjectTransport:
    """
    CLIENT-SIDE INJECTOR: Wraps a transport to inject metadata into outgoing requests.
    """

    def __init__(
        self,
        base_transport: Any,
        meta_fn: Callable[[], Dict[str, str]] = get_client_metadata,
    ):
        self.base = base_transport
        self.meta_fn = meta_fn

    @contextlib.asynccontextmanager
    async def connect_session(self, **kwargs):
        # Delegate to the underlying transport
        async with self.base.connect_session(**kwargs) as session:
            orig_send = session.send

            async def send_with_meta(message: dict, **send_kwargs):
                # JSON-RPC 2.0 envelope: always a dict
                if isinstance(message, dict): # Ensure it's a dict before modifying
                    message.setdefault("metadata", {}).update(self.meta_fn())
                return await orig_send(message, **send_kwargs)

            session.send = send_with_meta
            yield session

    def __repr__(self) -> str:
        return f"<AuthInjectTransport wrapping {self.base!r}>"


# --- Client-Side Metadata Reading ---

# Define the type for the callback function users will provide
MetadataCallback = Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]
# Define the type for the MCP message handler function
MessageHandlerFnT = Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]


def create_metadata_reading_handler(
    on_metadata_received: MetadataCallback,
    original_handler: Optional[MessageHandlerFnT] = None,
) -> MessageHandlerFnT:
    """
    CLIENT-SIDE READER: Creates a message handler that extracts server metadata
    before calling the original handler (if any).

    Args:
        on_metadata_received: An async function to call with extracted metadata.
        original_handler: The original message handler to call after processing metadata.
    """

    async def handle_message_with_metadata(message: Dict[str, Any]):
        if isinstance(message, dict) and "metadata" in message:
            await on_metadata_received(message["metadata"])
            # Optionally remove metadata after processing if desired
            # del message["metadata"]

        # Call the original handler if one was provided
        if original_handler:
            await original_handler(message)
        # If no original handler, we might just log or do nothing further
        # else:
        #     print(f"Client received message: {message}")


    return handle_message_with_metadata


# --- Server-Side Metadata Injection (FastAPI Middleware Example) ---

def get_server_metadata() -> Dict[str, str]:
    """Generates metadata to be injected by the server."""
    return {
        "server_id": "main-server-process",
        "server_response_id": "res-" + str(uuid.uuid4()),
    }


class MetadataInjectingMiddleware(BaseHTTPMiddleware):
    """
    SERVER-SIDE INJECTOR (FastAPI): Middleware to inject metadata into outgoing
    JSON-RPC 2.0 responses.
    """
    def __init__(
        self,
        app,
        meta_fn: Callable[[], Dict[str, str]] = get_server_metadata,
    ):
        super().__init__(app)
        self.meta_fn = meta_fn

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)

        # Intercept streaming responses (like SSE)
        if isinstance(response, StreamingResponse):
            # We need to wrap the async iterator to modify chunks
            original_iterator = response.body_iterator
            response.body_iterator = self._modify_stream(original_iterator)
        # Intercept regular JSON responses (might happen for initial handshake etc.)
        elif response.headers.get("content-type") == "application/json":
             # Read the original body
            response_body = b""
            async for chunk in response.body_iterator:
                 response_body += chunk
             # Decode, modify, re-encode
            try:
                data = json.loads(response_body.decode("utf-8"))
                if isinstance(data, dict) and data.get("jsonrpc") == "2.0":
                    data.setdefault("metadata", {}).update(self.meta_fn())
                    modified_body = json.dumps(data).encode("utf-8")
                    # Create a new response with modified body and original headers/status
                    response = Response(
                        content=modified_body,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type="application/json",
                    )
                    # Update content-length if present
                    response.headers["content-length"] = str(len(modified_body))
            except json.JSONDecodeError:
                 # If not valid JSON, pass through unmodified
                 response = Response(
                     content=response_body,
                     status_code=response.status_code,
                     headers=dict(response.headers),
                     media_type=response.media_type,
                 )


        return response

    async def _modify_stream(self, original_iterator):
        """Wraps the streaming response iterator to inject metadata."""
        buffer = ""
        async for chunk in original_iterator:
            buffer += chunk.decode("utf-8")
            # Process line by line for SSE (often ends with \n\n)
            while "\n\n" in buffer:
                event_str, buffer = buffer.split("\n\n", 1)
                # Check if it's a data line and looks like JSON RPC
                if event_str.startswith("data:"):
                    try:
                        data_part = event_str[len("data:"):].strip()
                        data = json.loads(data_part)
                        if isinstance(data, dict) and data.get("jsonrpc") == "2.0":
                             data.setdefault("metadata", {}).update(self.meta_fn())
                             modified_event = f"data: {json.dumps(data)}\n\n"
                             yield modified_event.encode("utf-8")
                             continue # Skip original yield for this modified event
                    except json.JSONDecodeError:
                        pass # Not JSON, pass through original
                # Yield original chunk if not modified
                yield (event_str + "\n\n").encode("utf-8")
        # Yield any remaining buffer content
        if buffer:
            yield buffer.encode("utf-8")
