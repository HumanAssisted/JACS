# Vercel AI SDK

**Sign it. Prove it.** -- for every AI model output.

The JACS Vercel AI SDK adapter adds cryptographic provenance to AI-generated text and tool results using the `LanguageModelV3Middleware` pattern. Works with `generateText`, `streamText`, and any model provider (OpenAI, Anthropic, etc.).

## 5-Minute Quickstart

### 1. Install

```bash
npm install @hai.ai/jacs ai @ai-sdk/openai
```

### 2. Create a JACS client

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart();
```

### 3. Sign every model output

```typescript
import { withProvenance } from '@hai.ai/jacs/vercel-ai';
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

const model = withProvenance(openai('gpt-4'), { client });
const { text, providerMetadata } = await generateText({ model, prompt: 'Hello!' });

console.log(providerMetadata?.jacs?.text?.documentId); // JACS document ID
```

---

## Quick Start

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { withProvenance } from '@hai.ai/jacs/vercel-ai';
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

const client = await JacsClient.quickstart();
const model = withProvenance(openai('gpt-4'), { client });

const { text, providerMetadata } = await generateText({
  model,
  prompt: 'Summarize the quarterly report.',
});

console.log(text);
console.log(providerMetadata?.jacs?.text?.documentId); // JACS document ID
console.log(providerMetadata?.jacs?.text?.signed);      // true
```

Every model output is signed by your JACS agent. The provenance record is attached to `providerMetadata.jacs`.

## Installation

```bash
npm install @hai.ai/jacs ai @ai-sdk/openai  # or any provider
```

The `ai` package is a peer dependency.

## Two Ways to Use

### `withProvenance` (convenience)

Wraps a model with the JACS middleware in one call:

```typescript
import { withProvenance } from '@hai.ai/jacs/vercel-ai';

const model = withProvenance(openai('gpt-4'), { client });
```

### `jacsProvenance` (composable)

Returns a `LanguageModelV3Middleware` you can compose with other middleware:

```typescript
import { jacsProvenance } from '@hai.ai/jacs/vercel-ai';
import { wrapLanguageModel } from 'ai';

const provenance = jacsProvenance({ client });

const model = wrapLanguageModel({
  model: openai('gpt-4'),
  middleware: provenance,
});
```

## Options

```typescript
interface ProvenanceOptions {
  client: JacsClient;                  // Required: initialized JacsClient
  signText?: boolean;                  // Sign generated text (default: true)
  signToolResults?: boolean;           // Sign tool call results (default: true)
  strict?: boolean;                    // Throw on signing failure (default: false)
  metadata?: Record<string, unknown>;  // Extra metadata in provenance records
}
```

## Streaming

Streaming works automatically. Text chunks are accumulated and signed when the stream completes:

```typescript
import { streamText } from 'ai';

const result = streamText({
  model: withProvenance(openai('gpt-4'), { client }),
  prompt: 'Write a haiku.',
});

for await (const chunk of result.textStream) {
  process.stdout.write(chunk);
}

// Provenance is available after stream completes
const metadata = await result.providerMetadata;
console.log(metadata?.jacs?.text?.signed); // true
```

## Tool Call Signing

When `signToolResults` is true (default), tool results in the prompt are signed:

```typescript
import { generateText, tool } from 'ai';
import { z } from 'zod';

const { text, providerMetadata } = await generateText({
  model: withProvenance(openai('gpt-4'), { client }),
  tools: {
    getWeather: tool({
      parameters: z.object({ city: z.string() }),
      execute: async ({ city }) => `Weather in ${city}: sunny, 72F`,
    }),
  },
  prompt: 'What is the weather in Paris?',
});

// Both text output and tool results are signed
console.log(providerMetadata?.jacs?.text?.signed);
console.log(providerMetadata?.jacs?.toolResults?.signed);
```

## Provenance Record

Each signed output produces a `ProvenanceRecord`:

```typescript
interface ProvenanceRecord {
  signed: boolean;       // Whether signing succeeded
  documentId: string;    // JACS document ID
  agentId: string;       // Signing agent's ID
  timestamp: string;     // ISO 8601 timestamp
  error?: string;        // Error message if signing failed
  metadata?: Record<string, unknown>;
}
```

Access records from `providerMetadata.jacs`:

```typescript
const { providerMetadata } = await generateText({ model, prompt: '...' });

const textProvenance = providerMetadata?.jacs?.text;
const toolProvenance = providerMetadata?.jacs?.toolResults;
```

## Strict Mode

By default, signing failures are logged but do not throw. Enable `strict` to throw on failure:

```typescript
const model = withProvenance(openai('gpt-4'), {
  client,
  strict: true,  // Throws if signing fails
});
```

## Next Steps

- [Express Middleware](express.md) - Sign HTTP API responses
- [MCP Integration](mcp.md) - Secure MCP transport
- [API Reference](api.md) - Complete API documentation
