# Streaming Signing

JACS uses a **buffer-then-sign** pattern for streaming outputs. Token streams from LLMs are accumulated in memory and signed once the stream completes. This is the correct approach for LLM outputs because:

1. **LLM responses are small.** A typical response is under 100KB of text. Buffering this costs nothing.
2. **Signatures cover the complete output.** A partial signature over incomplete text is useless for verification.
3. **Framework adapters handle this automatically.** If you use a JACS adapter, streaming signing just works.

## How It Works by Framework

### Vercel AI SDK (`streamText`)

The `wrapStream` middleware accumulates `text-delta` chunks via a `TransformStream`. When the stream flushes, it signs the complete text and emits a `provider-metadata` chunk containing the provenance record.

```typescript
import { withProvenance } from '@hai.ai/jacs/vercel-ai';
import { streamText } from 'ai';

const model = withProvenance(openai('gpt-4o'), { client });
const result = await streamText({ model, prompt: 'Explain trust.' });

for await (const chunk of result.textStream) {
  process.stdout.write(chunk); // stream to user in real time
}
// provenance is available after stream completes
```

### LangChain / LangGraph

LangChain tools execute synchronously (or await async results) before returning to the model. JACS signs each tool result individually via `wrap_tool_call` or `signed_tool`. No special streaming handling is needed because the signing happens at the tool output boundary, not the token stream.

```python
from jacs.adapters.langchain import jacs_signing_middleware

agent = create_agent(
    model="openai:gpt-4o",
    tools=tools,
    middleware=[jacs_signing_middleware(client=jacs_client)],
)
# Tool results are auto-signed before the model sees them
```

### Express / Koa / FastAPI

HTTP middleware signs the response body before it is sent. For streaming HTTP responses (SSE, chunked encoding), sign the complete message content before streaming, or sign each event individually.

```python
# FastAPI: middleware signs JSON responses automatically
from jacs.adapters.fastapi import JacsMiddleware
app.add_middleware(JacsMiddleware)
```

### Raw LLM APIs (No Framework Adapter)

If you're calling an LLM API directly without a framework adapter, accumulate the response yourself and sign it when complete:

```python
import jacs.simple as jacs

jacs.quickstart()

# Accumulate streamed response
chunks = []
async for chunk in llm_stream("What is trust?"):
    chunks.append(chunk)
    print(chunk, end="")  # stream to user

# Sign the complete response
complete_text = "".join(chunks)
signed = jacs.sign_message({"response": complete_text, "model": "gpt-4o"})
```

```javascript
const jacs = require('@hai.ai/jacs/simple');
await jacs.quickstart();

const chunks = [];
for await (const chunk of llmStream('What is trust?')) {
  chunks.push(chunk);
  process.stdout.write(chunk);
}

const signed = await jacs.signMessage({
  response: chunks.join(''),
  model: 'gpt-4o',
});
```

## When NOT to Buffer

The buffer-then-sign pattern assumes the full content fits in memory. This is always true for LLM text responses. If you need to sign very large data (multi-GB files, video streams), use `sign_file` instead, which hashes the file on disk without loading it into memory.

## See Also

- [Vercel AI SDK Adapter](../nodejs/vercel-ai.md)
- [LangChain Adapters](../python/adapters.md)
- [Framework Adapters (Node.js)](../nodejs/langchain.md)
