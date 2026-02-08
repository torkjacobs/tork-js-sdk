/**
 * Tests for Deno Fresh middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import { torkFreshMiddleware, torkFreshHandler, torkFreshPlugin, governRenderData } from '../src/middleware/fresh';

function createFreshCtx(overrides: Partial<any> = {}): any {
  return {
    params: {},
    state: {},
    render: async (data?: any) => new Response(JSON.stringify(data || {})),
    renderNotFound: async () => new Response('Not Found', { status: 404 }),
    next: async () => new Response('OK'),
    ...overrides,
  };
}

describe('torkFreshHandler', () => {
  it('governs JSON response output', async () => {
    const tork = new Tork();
    const handler = torkFreshHandler(tork, async () => {
      return new Response(
        JSON.stringify({ message: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    const response = await handler(
      new Request('http://localhost/test'),
      createFreshCtx(),
    );

    const data = await response.json();
    expect(data.message).toContain('[SSN_REDACTED]');
    expect(data.message).not.toContain('123-45-6789');
  });

  it('governs URL search params', async () => {
    const tork = new Tork();
    const ctx = createFreshCtx();

    const handler = torkFreshHandler(tork, async (req, ctx) => {
      return new Response('OK');
    });

    await handler(
      new Request('http://localhost/test?q=SSN+123-45-6789'),
      ctx,
    );

    expect(ctx.state._tork_receipts).toBeDefined();
    expect(ctx.state._tork_receipts.length).toBeGreaterThan(0);
  });

  it('passes through clean data', async () => {
    const tork = new Tork();
    const handler = torkFreshHandler(tork, async () => {
      return new Response(
        JSON.stringify({ message: 'Hello world' }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    const response = await handler(
      new Request('http://localhost/test'),
      createFreshCtx(),
    );

    const data = await response.json();
    expect(data.message).toBe('Hello world');
  });

  it('skips governance when governOutput is false', async () => {
    const tork = new Tork();
    const handler = torkFreshHandler(tork, async () => {
      return new Response(
        JSON.stringify({ message: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      );
    }, { governOutput: false });

    const response = await handler(
      new Request('http://localhost/test'),
      createFreshCtx(),
    );

    const data = await response.json();
    expect(data.message).toBe('SSN: 123-45-6789');
  });
});

describe('torkFreshMiddleware', () => {
  it('wraps multiple HTTP method handlers', () => {
    const tork = new Tork();
    const handlers = torkFreshMiddleware(tork, {
      GET: async () => new Response('OK'),
      POST: async () => new Response('OK'),
    });

    expect(typeof handlers.GET).toBe('function');
    expect(typeof handlers.POST).toBe('function');
  });
});

describe('torkFreshPlugin', () => {
  it('creates plugin with name and middlewares', () => {
    const tork = new Tork();
    const plugin = torkFreshPlugin(tork);

    expect(plugin.name).toBe('tork-governance');
    expect(plugin.middlewares.length).toBeGreaterThan(0);
  });
});

describe('governRenderData', () => {
  it('governs object data for rendering', () => {
    const tork = new Tork();
    const result = governRenderData(tork, {
      title: 'Hello',
      email: 'admin@secret.com',
    });

    expect(result.title).toBe('Hello');
    expect(result.email).toContain('[EMAIL_REDACTED]');
  });
});
