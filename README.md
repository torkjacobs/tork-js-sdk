# Tork Governance JavaScript SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Node.js and browser environments.

[![npm version](https://badge.fury.io/js/@tork-governance%2Fsdk.svg)](https://badge.fury.io/js/@tork-governance%2Fsdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @tork-governance/sdk
# or
yarn add @tork-governance/sdk
```

## Quick Start

```typescript
import { Tork } from '@tork-governance/sdk';

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
import { Tork } from '@tork-governance/sdk';
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

## Supported Frameworks (22 Adapters)

### AI SDKs & Frameworks
- **OpenAI** - Chat completions, completions, embeddings with streaming
- **Anthropic** - Claude messages API with content block governance
- **LangChain.js** - Callback handlers and runnable governance
- **Vercel AI** - Streaming middleware for useChat/useCompletion

### Web Frameworks
- **Express** - Middleware for request/response governance
- **Fastify** - Plugin-based governance
- **Koa** - Middleware integration
- **Hono** - Lightweight middleware
- **Hapi** - Plugin-based governance
- **Next.js** - API route and middleware support
- **NestJS** - Guards, interceptors, and pipes
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
import { torkExpressMiddleware } from '@tork-governance/sdk/middleware/express';

const app = express();
app.use(torkExpressMiddleware({ skipPaths: ['/health'] }));
```

### Hapi Plugin

```typescript
import Hapi from '@hapi/hapi';
import { torkHapiPlugin } from '@tork-governance/sdk/middleware/hapi';

const server = Hapi.server({ port: 3000 });
await server.register({ plugin: torkHapiPlugin, options: { skipPaths: ['/health'] } });
```

### LangChain.js Integration

```typescript
import { TorkCallbackHandler } from '@tork-governance/sdk/middleware/langchain';

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
- **22 Framework Adapters**: OpenAI, Anthropic, LangChain.js, Vercel AI, Express, Fastify, Koa, Hono, Hapi, Next.js, NestJS, Remix, SvelteKit, Nuxt, Astro, Elysia, Deno Fresh, Bun.serve, tRPC, GraphQL Yoga, Socket.io, WebSocket
- **Streaming Support**: Governed streaming for OpenAI, Anthropic, and Vercel AI
- **TypeScript Support**: Full type definitions included

## API

### `Tork` Class

```typescript
const tork = new Tork({
  policyVersion: '1.0.0',
  defaultAction: 'redact',  // 'allow' | 'deny' | 'redact' | 'escalate'
  customPatterns: {}
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
