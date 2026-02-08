/**
 * Tests for SvelteKit middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import { torkLoad, torkFormAction, createTorkSvelteKitHandle, torkActions } from '../src/middleware/sveltekit';

function createLoadEvent(overrides: Partial<any> = {}): any {
  return {
    params: {},
    url: new URL('http://localhost/test'),
    request: new Request('http://localhost/test'),
    fetch: globalThis.fetch,
    locals: {},
    route: { id: '/test' },
    ...overrides,
  };
}

describe('torkLoad', () => {
  it('governs output data with PII', async () => {
    const tork = new Tork();
    const load = torkLoad(tork, async () => {
      return { message: 'SSN: 123-45-6789' };
    });

    const result = await load(createLoadEvent()) as any;
    expect(result.message).toContain('[SSN_REDACTED]');
    expect(result.message).not.toContain('123-45-6789');
  });

  it('passes through clean data', async () => {
    const tork = new Tork();
    const load = torkLoad(tork, async () => {
      return { message: 'Hello world' };
    });

    const result = await load(createLoadEvent()) as any;
    expect(result.message).toBe('Hello world');
  });

  it('governs URL search params', async () => {
    const tork = new Tork();
    let receipts: any[] = [];

    const load = torkLoad(tork, async (event) => {
      receipts = event._tork_receipts || [];
      return { ok: true };
    });

    await load(createLoadEvent({
      url: new URL('http://localhost/test?q=SSN+123-45-6789'),
    }));

    expect(receipts.length).toBeGreaterThan(0);
  });

  it('skips governance when governOutput is false', async () => {
    const tork = new Tork();
    const load = torkLoad(tork, async () => {
      return { message: 'SSN: 123-45-6789' };
    }, { governOutput: false });

    const result = await load(createLoadEvent()) as any;
    expect(result.message).toBe('SSN: 123-45-6789');
  });
});

describe('torkFormAction', () => {
  it('governs form data input', async () => {
    const tork = new Tork();
    let receipts: any[] = [];

    const formData = new FormData();
    formData.append('name', 'SSN: 123-45-6789');

    const action = torkFormAction(tork, async (event) => {
      receipts = event._tork_receipts || [];
      return { success: true };
    });

    await action(createLoadEvent({
      request: new Request('http://localhost/test', {
        method: 'POST',
        body: formData,
      }),
    }));

    expect(receipts.length).toBeGreaterThan(0);
  });

  it('governs action output', async () => {
    const tork = new Tork();
    const action = torkFormAction(tork, async () => {
      return { email: 'admin@secret.com' };
    });

    const result = await action(createLoadEvent()) as any;
    expect(result.email).toContain('[EMAIL_REDACTED]');
  });
});

describe('createTorkSvelteKitHandle', () => {
  it('governs JSON response body', async () => {
    const tork = new Tork();
    const handle = createTorkSvelteKitHandle(tork);

    const event = createLoadEvent({
      request: new Request('http://localhost/test'),
    });

    const response = await handle({
      event,
      resolve: async () => new Response(
        JSON.stringify({ data: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      ),
    });

    const data = await response.json();
    expect(data.data).toContain('[SSN_REDACTED]');
  });

  it('stores receipts in locals', async () => {
    const tork = new Tork();
    const handle = createTorkSvelteKitHandle(tork);

    const event = createLoadEvent({
      request: new Request('http://localhost/test', {
        headers: { 'content-type': 'application/json' },
        method: 'POST',
        body: JSON.stringify({ text: 'SSN: 123-45-6789' }),
      }),
    });

    await handle({
      event,
      resolve: async () => new Response('OK'),
    });

    expect(event.locals._tork_receipts).toBeDefined();
  });
});

describe('torkActions', () => {
  it('wraps multiple actions', () => {
    const tork = new Tork();
    const actions = torkActions(tork, {
      default: async () => ({ ok: true }),
      delete: async () => ({ ok: true }),
    });

    expect(typeof actions.default).toBe('function');
    expect(typeof actions.delete).toBe('function');
  });
});
