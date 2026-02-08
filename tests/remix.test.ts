/**
 * Tests for Remix middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import { torkLoader, torkAction, createTorkRemixMiddleware } from '../src/middleware/remix';

function createRequest(url: string, init?: RequestInit) {
  return new Request(url, init);
}

describe('torkLoader', () => {
  it('governs output JSON response', async () => {
    const tork = new Tork();
    const loader = torkLoader(tork, async () => {
      return new Response(JSON.stringify({ message: 'SSN: 123-45-6789' }), {
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await loader({
      request: createRequest('http://localhost/test'),
      params: {},
    });

    const data = await (response as Response).json();
    expect(data.message).toContain('[SSN_REDACTED]');
    expect(data.message).not.toContain('123-45-6789');
  });

  it('governs URL search params', async () => {
    const tork = new Tork();
    let receivedReceipts: any[] = [];

    const loader = torkLoader(tork, async (args) => {
      receivedReceipts = args._tork_receipts || [];
      return new Response('OK');
    });

    await loader({
      request: createRequest('http://localhost/test?q=SSN+123-45-6789'),
      params: {},
    });

    expect(receivedReceipts.length).toBeGreaterThan(0);
  });

  it('passes through clean data unchanged', async () => {
    const tork = new Tork();
    const loader = torkLoader(tork, async () => {
      return new Response(JSON.stringify({ message: 'Hello world' }), {
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await loader({
      request: createRequest('http://localhost/test'),
      params: {},
    });

    const data = await (response as Response).json();
    expect(data.message).toBe('Hello world');
  });

  it('skips governance when governOutput is false', async () => {
    const tork = new Tork();
    const loader = torkLoader(tork, async () => {
      return new Response(JSON.stringify({ message: 'SSN: 123-45-6789' }), {
        headers: { 'content-type': 'application/json' },
      });
    }, { governOutput: false });

    const response = await loader({
      request: createRequest('http://localhost/test'),
      params: {},
    });

    const data = await (response as Response).json();
    expect(data.message).toBe('SSN: 123-45-6789');
  });
});

describe('torkAction', () => {
  it('governs JSON body input', async () => {
    const tork = new Tork();
    let receipts: any[] = [];

    const action = torkAction(tork, async (args) => {
      receipts = args._tork_receipts || [];
      return new Response('OK');
    });

    await action({
      request: createRequest('http://localhost/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'SSN: 123-45-6789' }),
      }),
      params: {},
    });

    expect(receipts.length).toBeGreaterThan(0);
  });

  it('governs action output', async () => {
    const tork = new Tork();
    const action = torkAction(tork, async () => {
      return new Response(JSON.stringify({ result: 'Email: admin@secret.com' }), {
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await action({
      request: createRequest('http://localhost/test', { method: 'POST' }),
      params: {},
    });

    const data = await (response as Response).json();
    expect(data.result).toContain('[EMAIL_REDACTED]');
  });

  it('skips input governance when disabled', async () => {
    const tork = new Tork();
    let receipts: any[] = [];

    const action = torkAction(tork, async (args) => {
      receipts = args._tork_receipts || [];
      return new Response('OK');
    }, { governInput: false });

    await action({
      request: createRequest('http://localhost/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'SSN: 123-45-6789' }),
      }),
      params: {},
    });

    expect(receipts).toHaveLength(0);
  });
});

describe('createTorkRemixMiddleware', () => {
  it('creates loader and action wrappers', () => {
    const tork = new Tork();
    const middleware = createTorkRemixMiddleware(tork);

    expect(typeof middleware.loader).toBe('function');
    expect(typeof middleware.action).toBe('function');
  });
});
