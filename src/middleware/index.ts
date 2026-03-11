/**
 * Tork Governance Framework Middleware
 *
 * Export all middleware adapters for popular JavaScript frameworks
 */

// Express
export { torkExpressMiddleware } from './express';
export type { TorkExpressOptions } from './express';

// Fastify
export { torkFastifyPlugin } from './fastify';
export type { TorkFastifyOptions } from './fastify';

// Koa
export { torkKoaMiddleware } from './koa';
export type { TorkKoaOptions } from './koa';

// Hono
export { torkHonoMiddleware, torkHonoHandler } from './hono';
export type { TorkHonoOptions, HonoContext } from './hono';

// Next.js
export { withTork, torkRouteHandler } from './nextjs';
export type { TorkNextOptions, NextApiRequestWithTork } from './nextjs';

// Vercel AI
export { torkVercelAIMiddleware, withTorkVercelAI, createGovernedChat } from './vercel-ai';
export type { GovernResult, VercelAIMessage, TorkVercelAIOptions } from './vercel-ai';

// NestJS
export { TorkNestJSModule, TorkNestJSGuard, TorkNestJSInterceptor, TorkGoverned, createTorkPipe } from './nestjs';
export type { TorkNestJSOptions } from './nestjs';

// LangChain
export {
  TorkCallbackHandler,
  withTorkGovernance,
  createGovernedTool,
  torkGovernanceRunnable,
  TorkLangChain,
  TorkLangChainAgent,
  TorkChatModel,
  createGovernedRunnable,
  governChain
} from './langchain';
export type { TorkLangChainOptions } from './langchain';

// Hapi
export { torkHapiPlugin } from './hapi';
export type { TorkHapiOptions } from './hapi';

// OpenAI
export { TorkOpenAIClient, governChatCompletion, governCompletion, governEmbedding, openaiGoverned } from './openai';
export type { TorkOpenAIOptions, OpenAIGovernanceResult, ChatMessage, ChatCompletionParams, CompletionParams, EmbeddingParams } from './openai';

// Anthropic
export { TorkAnthropicClient, governMessage, anthropicGoverned } from './anthropic';
export type { TorkAnthropicOptions, AnthropicGovernanceResult, AnthropicMessage, ContentBlock, MessageParams } from './anthropic';

// Remix
export { torkLoader, torkAction, createTorkRemixMiddleware } from './remix';
export type { TorkRemixOptions, RemixLoaderArgs, RemixActionArgs } from './remix';

// SvelteKit
export { torkLoad, torkFormAction, createTorkSvelteKitHandle, torkActions } from './sveltekit';
export type { TorkSvelteKitOptions, SvelteKitLoadEvent, SvelteKitRequestEvent } from './sveltekit';

// Nuxt
export { defineTorkEventHandler, createTorkNuxtMiddleware, torkApiRoute, useTorkGovernance, createTorkNuxtPlugin } from './nuxt';
export type { TorkNuxtOptions, H3Event } from './nuxt';

// Astro
export { torkAstroMiddleware, torkApiRoute as torkAstroApiRoute, createTorkAstroHandlers } from './astro';
export type { TorkAstroOptions, AstroAPIContext } from './astro';

// Elysia (Bun)
export { torkElysiaPlugin, torkElysiaDerive, torkHandler as torkElysiaHandler } from './elysia';
export type { TorkElysiaOptions, ElysiaContext } from './elysia';

// Deno Fresh
export { torkFreshMiddleware, torkFreshHandler, torkFreshPlugin, governRenderData } from './fresh';
export type { TorkFreshOptions, FreshContext, FreshHandler, FreshHandlers } from './fresh';

// Bun.serve
export { torkBunHandler, createTorkBunServer, createTorkBunRouter } from './bun';
export type { TorkBunOptions, BunServer } from './bun';

// tRPC
export { torkTrpcMiddleware, torkResolver, torkInputTransformer, torkOutputTransformer, torkTrpcTransformer, createTorkProcedure } from './trpc';
export type { TorkTrpcOptions, TrpcMiddlewareContext } from './trpc';

// Socket.io
export { torkSocketMiddleware, torkSocketHandler, torkEmit, createTorkSocketHandlers } from './socketio';
export type { TorkSocketOptions, SocketMiddlewareSocket } from './socketio';

// GraphQL Yoga
export { torkYogaPlugin, torkYogaContext, torkResolver as torkGraphQLResolver, torkFieldResolvers, torkEnvelopPlugin } from './graphql-yoga';
export type { TorkYogaOptions, YogaPluginContext } from './graphql-yoga';

// ws (WebSocket)
export { torkWsServer, torkWsHandler, torkWsSend, torkWsBroadcast } from './ws';
export type { TorkWsOptions, WsSocket, WsServer } from './ws';

// Mastra
export { TorkMastraAgent, TorkMastraToolWrapper, governMastraWorkflow, mastraGoverned } from './mastra';
export type { TorkMastraOptions, MastraGovernanceResult } from './mastra';

// Microsoft Agent Framework
export { TorkMicrosoftAgent, TorkMicrosoftToolWrapper, governAgentChat, microsoftAgentGoverned } from './microsoft-agents';
export type { TorkMicrosoftAgentOptions, MicrosoftAgentGovernanceResult, AgentMessage } from './microsoft-agents';
