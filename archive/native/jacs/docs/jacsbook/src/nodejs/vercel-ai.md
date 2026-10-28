# Vercel AI SDK

{{#include ../_snippets/node-registry-status.md}}

**Sign it. Prove it.** -- for every AI model output.

The JACS Vercel AI SDK adapter adds cryptographic provenance to AI-generated text and tool results using the `LanguageModelV3Middleware` pattern. Use the nonstreaming `generateText` path with a compatible V3 provider.
The current streaming path has an SDK shape limitation described below.

## 5-Minute Quickstart

### 1. Install

```bash
npm install @hai.ai/jacs ai @ai-sdk/openai
```

### 2. Create a JACS client

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});
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

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});
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
  strict?: boolean;                    // Enforce signing; override unsigned-output opt-ins
  maxBufferedStreamBytes?: number;     // Default 1 MiB; maximum 16 MiB
  metadata?: Record<string, unknown>;  // Extra metadata in provenance records
}
```

## Streaming limitation

Use `generateText` for this guide. The current stream adapter reads
`text-delta` chunks from a `textDelta` property and throws if it is absent.
The repository tests supply that mocked shape; they do not qualify actual
provider streams. The package declares broad optional `ai >=4` and
`@ai-sdk/provider >=1` peer ranges rather than a tested pinned V3 provider.
Do not assume a provider emitting a different delta shape is supported.

When compatible chunks are supplied, the adapter buffers the whole stream,
signs it, and only then releases chunks. The default bound is 1 MiB;
`maxBufferedStreamBytes` can raise it to at most 16 MiB. Overflow or signing
failure withholds output. Explicit unsigned/post-hoc options weaken that
boundary and are not a remedy for an incompatible SDK shape.

## Tool Call Signing

When `signToolResults` is true (default), tool results in the prompt are signed:

```typescript
import { generateText, tool, stepCountIs } from 'ai';
import { z } from 'zod';

const { text, providerMetadata } = await generateText({
  model: withProvenance(openai('gpt-4'), { client }),
  tools: {
    getWeather: tool({
      inputSchema: z.object({ city: z.string() }),
      execute: async ({ city }) => `Weather in ${city}: sunny, 72F`,
    }),
  },
  prompt: 'What is the weather in Paris?',
  stopWhen: stepCountIs(2),
});

// Tool results are signed when fed back into a subsequent model step
console.log(providerMetadata?.jacs?.text?.signed);
console.log(providerMetadata?.jacs?.toolResults?.signed);
```

## Provenance Record

Each signed output produces a `ProvenanceRecord`:

```typescript
interface SignedProvenanceRecord {
  signed: true;
  documentId: string;    // JACS document ID
  agentId: string;       // Signing agent's ID
  timestamp: string;     // ISO 8601 timestamp
  signedDocument: string; // Full portable signed JACS document
  metadata?: Record<string, unknown>;
}
```

`ProvenanceRecord` is a union of that signed shape and an unsigned failure
shape (`signed: false`, empty IDs/timestamp, and `error`). Unsigned records are
only returned through explicit compatibility options. Verify `signedDocument`
and compare its signed output and metadata; the other fields alone are not proof.

Access records from `providerMetadata.jacs`:

```typescript
const { providerMetadata } = await generateText({ model, prompt: '...' });

const textProvenance = providerMetadata?.jacs?.text;
const toolProvenance = providerMetadata?.jacs?.toolResults;
```

## Strict Mode

Signing fails closed by default: a failed signature withholds the output.
`strict: true` also overrides explicit unsigned-output compatibility opt-ins.
Do not enable unsigned or post-hoc streaming options when signed output is required:

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
