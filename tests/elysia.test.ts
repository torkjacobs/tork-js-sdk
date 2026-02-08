/**
 * Tests for Elysia middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import { torkElysiaPlugin, torkElysiaDerive, torkHandler } from '../src/middleware/elysia';

function createElysiaContext(overrides: Partial<any> = {}): any {
  return {
    request: new Request('http://localhost/test'),
    path: '/test',
    query: {},
    params: {},
    body: null,
    headers: {},
    store: {},
    set: { headers: {} },
    ...overrides,
  };
}

describe('torkElysiaPlugin', () => {
  it('governs query params in beforeHandle', () => {
    const tork = new Tork();
    const plugin = torkElysiaPlugin(tork);

    const ctx = createElysiaContext({
      query: { q: 'SSN: 123-45-6789' },
    });

    plugin.beforeHandle(ctx);

    expect(ctx.store._tork_receipts).toBeDefined();
    expect(ctx.store._tork_receipts.length).toBeGreaterThan(0);
  });

  it('governs body in beforeHandle', () => {
    const tork = new Tork();
    const plugin = torkElysiaPlugin(tork);

    const ctx = createElysiaContext({
      body: { message: 'SSN: 123-45-6789' },
    });

    plugin.beforeHandle(ctx);
    expect(ctx.store._tork_receipts.length).toBeGreaterThan(0);
  });

  it('governs object response in afterHandle', () => {
    const tork = new Tork();
    const plugin = torkElysiaPlugin(tork);

    const ctx = createElysiaContext();
    plugin.beforeHandle(ctx);

    const result = plugin.afterHandle(ctx, { message: 'SSN: 123-45-6789' });
    expect(result.message).toContain('[SSN_REDACTED]');
  });

  it('governs string response in afterHandle', () => {
    const tork = new Tork();
    const plugin = torkElysiaPlugin(tork);

    const ctx = createElysiaContext();
    plugin.beforeHandle(ctx);

    const result = plugin.afterHandle(ctx, 'Email: admin@secret.com');
    expect(result).toContain('[EMAIL_REDACTED]');
  });

  it('skips output governance when disabled', () => {
    const tork = new Tork();
    const plugin = torkElysiaPlugin(tork, { governOutput: false });

    const ctx = createElysiaContext();
    plugin.beforeHandle(ctx);

    const result = plugin.afterHandle(ctx, { message: 'SSN: 123-45-6789' });
    expect(result.message).toBe('SSN: 123-45-6789');
  });
});

describe('torkElysiaDerive', () => {
  it('provides govern and governObject helpers', () => {
    const tork = new Tork();
    const derive = torkElysiaDerive(tork);

    const ctx = createElysiaContext();
    const derived = derive(ctx);

    expect(typeof derived.govern).toBe('function');
    expect(typeof derived.governObject).toBe('function');
    expect(derived.tork).toBe(tork);
  });

  it('governs query params', () => {
    const tork = new Tork();
    const derive = torkElysiaDerive(tork);

    const ctx = createElysiaContext({
      query: { ssn: '123-45-6789' },
    });

    const derived = derive(ctx);
    expect(derived.torkReceipts.length).toBeGreaterThan(0);
  });
});

describe('torkHandler', () => {
  it('governs handler input and output', async () => {
    const tork = new Tork();
    const handler = torkHandler(tork, async () => {
      return { email: 'admin@secret.com' };
    });

    const result = await handler(createElysiaContext());
    expect((result as any).email).toContain('[EMAIL_REDACTED]');
  });

  it('governs body input', async () => {
    const tork = new Tork();
    let receivedBody: any;

    const handler = torkHandler(tork, async (ctx) => {
      receivedBody = ctx.body;
      return { ok: true };
    });

    await handler(createElysiaContext({
      body: { text: 'SSN: 123-45-6789' },
    }));

    expect(receivedBody.text).toContain('[SSN_REDACTED]');
  });
});
