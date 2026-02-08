/**
 * Tests for Nuxt middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import {
  defineTorkEventHandler,
  createTorkNuxtMiddleware,
  useTorkGovernance,
  createTorkNuxtPlugin,
} from '../src/middleware/nuxt';

function createH3Event(overrides: Partial<any> = {}): any {
  return {
    node: { req: { body: null }, res: {} },
    path: '/api/test',
    method: 'GET',
    headers: new Headers(),
    context: {},
    ...overrides,
  };
}

describe('defineTorkEventHandler', () => {
  it('governs output data with PII', async () => {
    const tork = new Tork();
    const handler = defineTorkEventHandler(tork, async () => {
      return { message: 'SSN: 123-45-6789' };
    });

    const result = await handler(createH3Event()) as any;
    expect(result.message).toContain('[SSN_REDACTED]');
    expect(result.message).not.toContain('123-45-6789');
  });

  it('governs request body input', async () => {
    const tork = new Tork();
    let receipts: any[] = [];

    const handler = defineTorkEventHandler(tork, async (event) => {
      receipts = event._tork_receipts || [];
      return { ok: true };
    });

    await handler(createH3Event({
      node: { req: { body: { text: 'SSN: 123-45-6789' } }, res: {} },
    }));

    expect(receipts.length).toBeGreaterThan(0);
  });

  it('passes through clean data', async () => {
    const tork = new Tork();
    const handler = defineTorkEventHandler(tork, async () => {
      return { message: 'Hello world' };
    });

    const result = await handler(createH3Event()) as any;
    expect(result.message).toBe('Hello world');
  });

  it('skips governance when governOutput is false', async () => {
    const tork = new Tork();
    const handler = defineTorkEventHandler(tork, async () => {
      return { message: 'SSN: 123-45-6789' };
    }, { governOutput: false });

    const result = await handler(createH3Event()) as any;
    expect(result.message).toBe('SSN: 123-45-6789');
  });

  it('stores receipts in event context', async () => {
    const tork = new Tork();
    const event = createH3Event();

    await defineTorkEventHandler(tork, async () => {
      return { ok: true };
    })(event);

    expect(event.context._tork_receipts).toBeDefined();
  });
});

describe('createTorkNuxtMiddleware', () => {
  it('governs next() output', async () => {
    const tork = new Tork();
    const middleware = createTorkNuxtMiddleware(tork);
    const event = createH3Event();

    const result = await middleware(event, async () => ({
      data: 'Email: admin@secret.com',
    }));

    expect(result.data).toContain('[EMAIL_REDACTED]');
  });

  it('stores receipts in context', async () => {
    const tork = new Tork();
    const middleware = createTorkNuxtMiddleware(tork);
    const event = createH3Event();

    await middleware(event, async () => ({ ok: true }));

    expect(event.context._tork_receipts).toBeDefined();
  });
});

describe('useTorkGovernance', () => {
  it('governs string values', () => {
    const tork = new Tork();
    const { govern } = useTorkGovernance(tork);

    const result = govern('SSN: 123-45-6789');
    expect(result.output).toContain('[SSN_REDACTED]');
  });

  it('governs objects recursively', () => {
    const tork = new Tork();
    const { governObject } = useTorkGovernance(tork);

    const result = governObject({ email: 'admin@secret.com', count: 5 });
    expect(result.email).toContain('[EMAIL_REDACTED]');
    expect(result.count).toBe(5);
  });
});

describe('createTorkNuxtPlugin', () => {
  it('creates plugin with name and setup', () => {
    const tork = new Tork();
    const plugin = createTorkNuxtPlugin(tork);

    expect(plugin.name).toBe('tork-governance');
    expect(typeof plugin.setup).toBe('function');
  });
});
