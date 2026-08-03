# Tork Governance JavaScript SDK

This package (`tork-governance`) is the on-device engine — PII detection, redaction and local receipts, computed entirely on-device with no network calls by default. Supplying an optional `apiKey` additionally turns on best-effort, metadata-only reporting to `https://tork.network/api/v1/attestations` (see [Optional: Anchored Attestations](#optional-anchored-attestations) below); the governance decision itself is never delayed or changed by this. For cloud governance with dashboard receipts and audit logs, use `@torknetwork/sdk` (`TorkClient`) instead.

On-device AI governance with PII detection, redaction, and cryptographic receipts for Node.js and browser environments.

[![npm version](https://badge.fury.io/js/tork-governance.svg)](https://badge.fury.io/js/tork-governance)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install tork-governance
# or
yarn add tork-governance
```

## Quick Start

```typescript
import { Tork } from 'tork-governance';

const tork = new Tork();

// Govern text - detects and redacts PII
const result = tork.govern('My SSN is 123-45-6789');

console.log(result.action);  // 'redact'
console.log(result.output);  // 'My SSN is [SSN_REDACTED]'
console.log(result.pii.types);  // ['ssn']
console.log(result.receipt.receiptId);  // 'rcpt_...'
```

## Regional PII Detection (v1.1)

Activate country-specific and industry-specific PII patterns with the optional `region` and `industry` parameters:

```typescript
import { Tork } from 'tork-governance';
const tork = new Tork();

// UAE regional detection — Emirates ID, +971 phone, PO Box
const result = tork.govern(
  'Emirates ID: 784-1234-1234567-1',
  { region: ['ae'] }
);

// Multi-region + industry
const result2 = tork.govern(
  'Aadhaar: 1234 5678 9012, ICD-10: J45.20',
  { region: ['in'], industry: 'healthcare' }
);

// Available regions: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR
// Available industries: healthcare, finance, legal
```

## Optional: Anchored Attestations

PII detection, redaction, and the returned governance decision are **always** computed entirely on-device, regardless of whether an `apiKey` is supplied. Supplying one additionally turns on best-effort, metadata-only reporting of each decision to `https://tork.network/api/v1/attestations`:

```typescript
const tork = new Tork({ apiKey: process.env.TORK_API_KEY });
const result = tork.govern('My SSN is 123-45-6789');

// The confirmed network outcome, if you need it before proceeding:
await result.report.wait();
console.log(result.report.succeeded, result.report.receiptId, result.report.reason);
```

What this does and doesn't do:

- **Never blocks `govern()`.** The local decision (`action`/`output`/`pii`/`receipt`) is final before any network call is made, and reporting runs on a detached promise — `govern()` always returns immediately regardless of endpoint latency.
- **Never throws.** A failed or slow report is reflected in `result.report` (`attempted`/`succeeded`/`receiptId`/`reason`), never as an exception. Call `result.report.wait(timeoutMs?)` if you need the confirmed outcome before proceeding — most callers don't.
- **Sends metadata only, never content.** The request body carries only: the action taken, PII type labels and counts, a risk/score classification, policy labels, and a salted fingerprint. It never sends input text, output text, redacted content, or PII values — those never leave the device.
- **Records a client attestation, not a Tork-verified decision.** The resulting row is recorded as a self-reported, internally-consistent claim (`attested_by: 'client'`) that Tork did not itself execute or independently verify.

Supplying `apiKey` logs a one-time (per process) warning describing exactly what is sent. Omit it to keep this SDK fully local with zero network calls.

## Supported Frameworks (24 Adapters)

### AI SDKs & Frameworks
- **OpenAI** - Chat completions, completions, embeddings with streaming
- **Anthropic** - Claude messages API with content block governance
- **LangChain.js** - Callback handlers and runnable governance
- **Vercel AI** - Streaming middleware for useChat/useCompletion
- **Mastra** - Agent, tool wrapper, and workflow governance
- **Microsoft Agent Framework** - Agent chat and tool call governance

### Web Frameworks
- **Express** - Middleware for request/response governance
- **Fastify** - Plugin-based governance
- **Koa** - Middleware integration
- **Hono** - Lightweight middleware
- **Next.js** - API route and middleware support
- **NestJS** - Guards, interceptors, and pipes
- **Hapi** - Plugin with request lifecycle governance
- **Remix** - Loader and action governance wrappers
- **SvelteKit** - Load functions, form actions, and hooks
- **Nuxt** - Server routes and H3 event handlers
- **Astro** - Middleware and API route governance
- **Elysia** - Plugin with beforeHandle/afterHandle hooks
- **Deno Fresh** - Handler middleware and Fresh plugin
- **Bun.serve** - Fetch handler and router governance

### APIs & Protocols
- **tRPC** - Middleware, transformers, and resolver governance
- **GraphQL Yoga** - Plugin, context, and resolver governance
- **Socket.io** - Event and emit middleware
- **WebSocket** - ws server and handler governance

## Framework Examples

### Express Middleware

```typescript
import express from 'express';
import { torkExpressMiddleware } from 'tork-governance';

const app = express();
app.use(torkExpressMiddleware({ skipPaths: ['/health'] }));
```

### LangChain.js Integration

```typescript
import { TorkCallbackHandler } from 'tork-governance';

const model = new ChatOpenAI({ callbacks: [new TorkCallbackHandler()] });
```

### OpenAI SDK Integration

```typescript
import OpenAI from 'openai';
import { TorkOpenAIClient } from 'tork-governance';

const openai = new OpenAI();
const torkClient = new TorkOpenAIClient(openai);

// Governed chat completion with automatic PII redaction
const response = await torkClient.governChatCompletion({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'My email is john@example.com' }],
});
// Input message is automatically redacted before sending to OpenAI
```

### Anthropic SDK Integration

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { TorkAnthropicClient } from 'tork-governance';

const anthropic = new Anthropic();
const torkClient = new TorkAnthropicClient(anthropic);

// Governed message with automatic PII redaction
const response = await torkClient.governMessage({
  model: 'claude-3-opus-20240229',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'My SSN is 123-45-6789' }],
});
```

## Features

- **PII Detection**: SSN, credit cards, emails, phones, addresses, IP addresses, and more
- **Automatic Redaction**: Replace sensitive data with type-specific placeholders
- **Cryptographic Receipts**: SHA256 hashes for audit trails
- **24 Framework Adapters**: OpenAI, Anthropic, LangChain.js, Vercel AI, Mastra, Microsoft Agent Framework, Express, Fastify, Koa, Hono, Next.js, NestJS, Hapi, Remix, SvelteKit, Nuxt, Astro, Elysia, Deno Fresh, Bun.serve, tRPC, GraphQL Yoga, Socket.io, WebSocket
- **Streaming Support**: Governed streaming for OpenAI, Anthropic, and Vercel AI
- **TypeScript Support**: Full type definitions included

## API

### `Tork` Class

```typescript
const tork = new Tork({
  policyVersion: '1.0.0',
  defaultAction: 'redact',  // 'allow' | 'deny' | 'redact' | 'escalate'
  customPatterns: {},
  apiKey: undefined,  // optional — see "Optional: Anchored Attestations" above
});

// Apply governance
const result = tork.govern(text);

// Get statistics
const stats = tork.getStats();

// Reset statistics
tork.resetStats();
```

### `detectPII` Function

```typescript
import { detectPII } from 'tork-governance';

const result = detectPII('Contact: john@example.com');
// {
//   hasPII: true,
//   types: ['email'],
//   count: 1,
//   matches: [...],
//   redactedText: 'Contact: [EMAIL_REDACTED]'
// }
```

### Utility Functions

```typescript
import { hashText, generateReceiptId } from 'tork-governance';

hashText('test');  // 'sha256:9f86d08...'
generateReceiptId();  // 'rcpt_a1b2c3...'
```

## Supported PII Types

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| Address | 123 Main Street | [ADDRESS_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | 01/15/1990 | [DOB_REDACTED] |
| Passport | AB1234567 | [PASSPORT_REDACTED] |
| Driver's License | D1234567 | [DL_REDACTED] |
| Bank Account | 12345678901234 | [ACCOUNT_REDACTED] |

## License

MIT
