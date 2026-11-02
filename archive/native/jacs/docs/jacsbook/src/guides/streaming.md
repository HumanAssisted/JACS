# Signing Streaming Output

A signature authenticates the bytes it covers. Data displayed before its final
signature arrives is provisional; do not treat it as verified output.

## Complete-response signing

For bounded text output, accumulate chunks and sign after successful completion.
This application-level example accepts an async iterator of strings:

```python
from jacs.client import JacsClient

async def signed_completion(chunks, client: JacsClient, max_bytes=1_000_000):
    parts = []
    size = 0
    async for chunk in chunks:
        size += len(chunk.encode("utf-8"))
        if size > max_bytes:
            raise ValueError("response exceeds signing buffer limit")
        parts.append(chunk)
    return client.sign_message({"response": "".join(parts)})
```

The caller decides how to display provisional chunks, handle cancellation and
deliver the final signed document. Enforce a size limit appropriate to the host;
LLM responses and tool streams are not guaranteed to fit in memory.

## Framework boundaries

- LangChain and LangGraph adapters sign completed tool results. They do not
  authenticate every token in the model's output stream.
- The Vercel AI adapter can attach provenance after stream completion; see its
  [adapter guide](../nodejs/vercel-ai.md) for the current chunk contract.
- HTTP JSON-signing middleware is not a generic SSE or chunked-response signing
  protocol. For signed events, sign complete event payloads and verify them
  before consumption.

For per-event signing, also authenticate stream identity, ordering and completion
under your application protocol. Independently valid events do not by themselves
prove that none were removed, reordered or replayed. See
[signed responses and events](../advanced/security.md#signed-response-and-event-contract)
for the existing response envelope and replay-store requirements.

## Large files

Use the file-signing API for file provenance, but measure memory and I/O costs
for your backend and embedding mode. This guide does not promise constant-memory
hashing or automatic streaming of multi-gigabyte attachments. Chunking large
artifacts needs an explicit manifest and completeness policy understood by both
producer and verifier.

See [Python adapters](../python/adapters.md) and
[Node adapters](../nodejs/langchain.md).
