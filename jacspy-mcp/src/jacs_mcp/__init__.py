# # monkey patch fastmcp to add metadata to the JSON-RPC 2.0 envelope

# # --- Monkey patch fastmcp/mcp to add metadata ---
# import uuid
# import logging
# from typing import Dict, Callable, Any

# # Attempt to import the core session class and message types
# # This relies on the library structure remaining consistent.
# try:
#     from mcp.shared.session import BaseSession
#     from mcp.types import (
#         JSONRPCRequest,
#         JSONRPCNotification,
#         JSONRPCResponse,
#         JSONRPCError,
#         JSONRPCMessage,
#         ErrorData
#     )
#     # Import specific request/notification types if needed for context,
#     # though BaseSession methods often work generically.
#     # from mcp.types import ClientRequest, ServerNotification # etc.
#     _mcp_import_successful = True
# except ImportError as e:
#     logging.error(f"MCP Import Error: Could not import mcp.shared.session.BaseSession or mcp.types. Patching aborted. Error: {e}")
#     _mcp_import_successful = False


# # --- Metadata Generation ---
# # Define functions users can potentially override later
# def get_client_metadata_for_patch() -> Dict[str, str]:
#     """Default metadata generator for client-originated messages."""
#     return {
#         "client_id": "patched-client",
#         "client_request_id": "req-patch-" + str(uuid.uuid4()),
#         "patch_source": "client",
#     }

# def get_server_metadata_for_patch() -> Dict[str, str]:
#     """Default metadata generator for server-originated messages."""
#     return {
#         "server_id": "patched-server",
#         "server_response_id": "res-patch-" + str(uuid.uuid4()),
#         "patch_source": "server",
#     }

# # --- Patching Logic ---
# _mcp_patched = False

# def apply_mcp_patch():
#     global _mcp_patched
#     if _mcp_patched or not _mcp_import_successful:
#         return # Don't patch multiple times or if import failed

#     logging.info("Applying MCP BaseSession monkey patch for metadata injection...")

#     # --- Store original methods ---
#     original_send_request = BaseSession.send_request
#     original_send_notification = BaseSession.send_notification
#     original_send_response = BaseSession._send_response # Note: protected member access

#     # --- Patch send_request (Client -> Server) ---
#     async def patched_send_request(self: BaseSession, request: Any, result_type: type) -> Any:
#         # This method constructs the JSONRPCRequest internally
#         # We need to call the original but intercept the message *before* write
#         # Let's modify the *construction* part conceptually, though the original
#         # method handles request_id and response stream setup.
#         # A simpler approach is to patch the final _write_stream.send call,
#         # but that's harder to intercept cleanly from here.
#         # Alternative: Re-implement parts of send_request carefully.

#         # Re-implementation attempt (needs careful testing):
#         request_id = self._request_id # Access internal state
#         self._request_id = request_id + 1

#         response_stream, response_stream_reader = anyio.create_memory_object_stream[
#             JSONRPCResponse | JSONRPCError
#         ](1)
#         self._response_streams[request_id] = response_stream

#         self._exit_stack.push_async_callback(lambda: response_stream.aclose())
#         self._exit_stack.push_async_callback(lambda: response_stream_reader.aclose())

#         # *** Create the message and inject metadata ***
#         jsonrpc_request = JSONRPCRequest(
#             jsonrpc="2.0",
#             id=request_id,
#             **request.model_dump(by_alias=True, mode="json", exclude_none=True),
#         )
#         # Inject client metadata
#         metadata = get_client_metadata_for_patch()
#         jsonrpc_request.metadata = metadata
#         # *** End Injection ***

#         await self._write_stream.send(JSONRPCMessage(root=jsonrpc_request)) # Use root=

#         # Call the rest of the original logic for waiting (or copy it)
#         # This part is complex, involves timeouts etc. Copying is risky.
#         # Calling original_send_request might be better if we can modify the message *before* it's sent.
#         # Let's revert to trying to patch the final send step if possible,
#         # or accept that this re-implementation is complex.

#         # -- Simpler patch: Modify the object *after* construction in original --
#         # -- THIS IS HARD TO DO WITHOUT REWRITING _write_stream or message flow --

#         # -- Let's stick to patching the methods that call _write_stream.send --
#         # -- focusing on _send_response and send_notification first as they are simpler --
#         # -- send_request patch is very complex due to response handling --
#         # -- For now, let's skip patching send_request via monkey patch --
#         logging.warning("Monkey patching BaseSession.send_request is complex and skipped.")
#         # Instead, call the original directly for requests
#         return await original_send_request(self, request, result_type)


#     # --- Patch send_notification (Can be Client -> Server or Server -> Client) ---
#     async def patched_send_notification(self: BaseSession, notification: Any) -> None:
#         jsonrpc_notification = JSONRPCNotification(
#             jsonrpc="2.0",
#             **notification.model_dump(by_alias=True, mode="json", exclude_none=True),
#         )

#         # *** Inject Metadata - Need context! ***
#         # How to know if client or server is sending? We don't easily here.
#         # Assume Client for now, or make get_metadata context-aware.
#         # For this example, let's assume client sends notifications primarily.
#         # A better approach might involve checking type(self) if Client/ServerSession exist.
#         metadata = get_client_metadata_for_patch() # Defaulting to client meta
#         jsonrpc_notification.metadata = metadata
#         # *** End Injection ***

#         await self._write_stream.send(JSONRPCMessage(root=jsonrpc_notification)) # Use root=


#     # --- Patch _send_response (Server -> Client) ---
#     async def patched_send_response(self: BaseSession, request_id: Any, response: Any | ErrorData) -> None:
#         message_to_send = None
#         if isinstance(response, ErrorData):
#             jsonrpc_error = JSONRPCError(jsonrpc="2.0", id=request_id, error=response)
#             # Inject server metadata
#             metadata = get_server_metadata_for_patch()
#             jsonrpc_error.metadata = metadata
#             message_to_send = JSONRPCMessage(root=jsonrpc_error) # Use root=
#         else:
#             jsonrpc_response = JSONRPCResponse(
#                 jsonrpc="2.0",
#                 id=request_id,
#                 result=response.model_dump(
#                     by_alias=True, mode="json", exclude_none=True
#                 ),
#             )
#             # Inject server metadata
#             metadata = get_server_metadata_for_patch()
#             jsonrpc_response.metadata = metadata
#             message_to_send = JSONRPCMessage(root=jsonrpc_response) # Use root=

#         if message_to_send:
#             await self._write_stream.send(message_to_send)

#     # --- Apply the patches ---
#     # BaseSession.send_request = patched_send_request # Skipping due to complexity
#     BaseSession.send_notification = patched_send_notification
#     BaseSession._send_response = patched_send_response # Patching protected member

#     _mcp_patched = True
#     logging.info("MCP BaseSession monkey patch applied.")

# # --- Automatically apply the patch when this module is imported ---
# apply_mcp_patch()

# # --- Optional: Expose configuration functions ---
# def set_client_metadata_provider(func: Callable[[], Dict[str, str]]):
#     """Allows overriding the default client metadata function."""
#     global get_client_metadata_for_patch
#     get_client_metadata_for_patch = func
#     logging.info(f"MCP patch client metadata provider set to: {func.__name__}")

# def set_server_metadata_provider(func: Callable[[], Dict[str, str]]):
#     """Allows overriding the default server metadata function."""
#     global get_server_metadata_for_patch
#     get_server_metadata_for_patch = func
#     logging.info(f"MCP patch server metadata provider set to: {func.__name__}")

# # You can still import things from your own module if needed
# # from .fast_mcp_auth import AuthInjectTransport # etc.