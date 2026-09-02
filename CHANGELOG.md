# Changelog

All notable changes to the Tork Governance JavaScript SDK will be documented in this file.

## [0.12.0] - 2026-09-02

### Added
- **`scanToolResult()`** — scan a tool result (MCP server response, or any external
  system's output) for PII and prompt injection **before** it is appended to model
  context. On-device and synchronous: zero network calls, payload never leaves the
  machine. Available as a standalone function and as `Tork#scanToolResult`, which
  additionally produces a receipt.
- **PII detection reuses the existing on-device detector** (`detectPII`) — no second
  scanner. It moved to `src/pii.ts` so the scanner can import it without a cycle;
  `detectPII`, `PII_PATTERNS` and the PII types are still exported from the package
  entry, unchanged.
- **Prompt-injection heuristics** (`tork-injection-heuristics-v1`) — a conservative
  pattern set covering instruction override, role reassignment, and exfiltration
  URLs. The SDK had none before. Every injection finding is typed
  `heuristic:<name>` so a pattern match can never be read as a verified
  determination.
- **`receipt.tool_result_scan`** — records the scan as a client-attested, edge-captured
  control: `attested_by: 'client'`, `capture_mode: 'edge'`, counts by kind and type,
  tool name, server URI, blocked flag, and SDK version. Counts only — never the
  payload, a matched value, or a location path.
- `options.blockOnInjection` — when the heuristics fire, block the result: `sanitized`
  becomes `null` and `reason` explains the block.

### Notes
- Tool-result scanning is a **client-side, client-attested** control. Gateway-side
  enforcement is a separate, later control.
- The `tool_result_scan` block is local to the receipt. `POST /api/v1/attestations`
  validates a fixed field set with no column for it, so it is deliberately not
  transmitted; the attestation carries only the decision, PII type labels and count
  the endpoint already accepts.

## [0.10.0] - 2026-03-11

### Added
#### Mastra Adapter
- **TorkMastraAgent** — Governed agent wrapper for Mastra
- **TorkMastraToolWrapper** — Tool governance wrapper
- **governMastraWorkflow** — Workflow step middleware
- **mastraGoverned** — Decorator for agent.generate() calls
- Full support for streaming and async patterns

#### Microsoft Agent Framework Adapter
- **TorkMicrosoftAgent** — Governed agent wrapper
- **TorkMicrosoftToolWrapper** — Tool governance wrapper
- **governAgentChat** — Multi-agent chat governance
- **microsoftAgentGoverned** — Decorator for agent invocations
- Full support for A2A, MCP, and AG-UI patterns

## [0.9.2] - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)

## [0.7.0] - 2026-02-03

### Added
- **tRPC adapter** (`trpc.ts`) - Type-safe API governance with middleware and transformers
- **Socket.io adapter** (`socketio.ts`) - Real-time WebSocket governance for Socket.io servers
- **GraphQL Yoga adapter** (`graphql-yoga.ts`) - GraphQL server governance with plugin and resolver support
- **ws WebSocket adapter** (`ws.ts`) - Native WebSocket governance for ws library

### Changed
- Enhanced Hono adapter with improved type definitions

## [0.6.0] - 2026-02-03

### Added
- **Deno Fresh adapter** (`fresh.ts`) - Middleware and handler governance for Deno Fresh
- **Bun.serve adapter** (`bun.ts`) - Native Bun server governance with router support

## [0.5.0] - 2026-02-03

### Added
- **Astro adapter** (`astro.ts`) - Middleware and API route governance for Astro
- **Elysia adapter** (`elysia.ts`) - Plugin-based governance for Elysia (Bun framework)

## [0.4.0] - 2026-02-03

### Added
- **Remix adapter** (`remix.ts`) - Loader and action governance for Remix applications
- **SvelteKit adapter** (`sveltekit.ts`) - Load function and form action governance
- **Nuxt adapter** (`nuxt.ts`) - H3 event handler and Nuxt plugin governance

## [0.3.0] - 2026-02-01

### Added
- NestJS adapter with module, guard, and interceptor support
- LangChain.js adapter with chain and callback governance
- Vercel AI SDK adapter

## [0.2.0] - 2026-01-15

### Added
- Hapi adapter with plugin-based governance
- Next.js adapter with middleware and route handler support

## [0.1.0] - 2026-01-01

### Added
- Initial release
- Core governance engine with PII detection
- Express middleware adapter
- Fastify plugin adapter
- Koa middleware adapter
- Hono middleware adapter
- Cryptographic receipt generation
