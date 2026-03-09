# Changelog

All notable changes to the Tork Governance JavaScript SDK will be documented in this file.

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
