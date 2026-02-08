/**
 * Tests for Astro middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import { torkAstroMiddleware, torkApiRoute, createTorkAstroHandlers } from '../src/middleware/astro';

function createAstroContext(overrides: Partial<any> = {}): any {
  return {
    request: new Request('http://localhost/test'),
    params: {},
    url: new URL('http://localhost/test'),
    locals: {},
    cookies: {},
    redirect: (path: string, status?: number) => new Response(null, { status: status || 302 }),
    ...overrides,
  };
}

describe('torkAstroMiddleware', () => {
  it('governs JSON response output', async () => {
    const tork = new Tork();
    const middleware = torkAstroMiddleware(tork);

    const response = await middleware(
      createAstroContext(),
      async () => new Response(
        JSON.stringify({ message: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      ),
    );

    const data = await response.json();
    expect(data.message).toContain('[SSN_REDACTED]');
    expect(data.message).not.toContain('123-45-6789');
  });

  it('governs query parameters', async () => {
    const tork = new Tork();
    const middleware = torkAstroMiddleware(tork);

    const ctx = createAstroContext({
      url: new URL('http://localhost/test?q=SSN+123-45-6789'),
    });

    await middleware(ctx, async () => new Response('OK'));

    expect(ctx.locals._tork_receipts).toBeDefined();
    expect(ctx.locals._tork_receipts.length).toBeGreaterThan(0);
  });

  it('passes through clean responses', async () => {
    const tork = new Tork();
    const middleware = torkAstroMiddleware(tork);

    const response = await middleware(
      createAstroContext(),
      async () => new Response(
        JSON.stringify({ message: 'Hello world' }),
        { headers: { 'content-type': 'application/json' } },
      ),
    );

    const data = await response.json();
    expect(data.message).toBe('Hello world');
  });

  it('skips output governance when disabled', async () => {
    const tork = new Tork();
    const middleware = torkAstroMiddleware(tork, { governOutput: false });

    const response = await middleware(
      createAstroContext(),
      async () => new Response(
        JSON.stringify({ message: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      ),
    );

    const data = await response.json();
    expect(data.message).toBe('SSN: 123-45-6789');
  });
});

describe('torkApiRoute', () => {
  it('governs API route output', async () => {
    const tork = new Tork();
    const handler = torkApiRoute(tork, async () => {
      return new Response(
        JSON.stringify({ email: 'admin@secret.com' }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    const response = await handler(createAstroContext());
    const data = await (response as Response).json();
    expect(data.email).toContain('[EMAIL_REDACTED]');
  });

  it('provides receipts to handler', async () => {
    const tork = new Tork();
    let receipts: any[] = [];

    const handler = torkApiRoute(tork, async (ctx) => {
      receipts = ctx._tork_receipts || [];
      return new Response('OK');
    });

    await handler(createAstroContext({
      url: new URL('http://localhost/test?ssn=123-45-6789'),
    }));

    expect(receipts.length).toBeGreaterThan(0);
  });
});

describe('createTorkAstroHandlers', () => {
  it('creates all HTTP method handlers', () => {
    const tork = new Tork();
    const handlers = createTorkAstroHandlers(tork);

    expect(typeof handlers.GET).toBe('function');
    expect(typeof handlers.POST).toBe('function');
    expect(typeof handlers.PUT).toBe('function');
    expect(typeof handlers.PATCH).toBe('function');
    expect(typeof handlers.DELETE).toBe('function');
  });
});
