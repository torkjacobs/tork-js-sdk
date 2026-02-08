/**
 * Tests for Bun.serve middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import { torkBunHandler, createTorkBunServer, createTorkBunRouter } from '../src/middleware/bun';

describe('torkBunHandler', () => {
  it('governs JSON response output', async () => {
    const tork = new Tork();
    const handler = torkBunHandler(tork, async () => {
      return new Response(
        JSON.stringify({ message: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    const response = await handler(new Request('http://localhost/test'));
    const data = await response.json();
    expect(data.message).toContain('[SSN_REDACTED]');
    expect(data.message).not.toContain('123-45-6789');
  });

  it('governs text response output', async () => {
    const tork = new Tork();
    const handler = torkBunHandler(tork, async () => {
      return new Response('Email: admin@secret.com', {
        headers: { 'content-type': 'text/plain' },
      });
    });

    const response = await handler(new Request('http://localhost/test'));
    const text = await response.text();
    expect(text).toContain('[EMAIL_REDACTED]');
  });

  it('governs URL search params input', async () => {
    const tork = new Tork();
    let handlerCalled = false;

    const handler = torkBunHandler(tork, async () => {
      handlerCalled = true;
      return new Response('OK');
    });

    await handler(new Request('http://localhost/test?q=SSN+123-45-6789'));
    expect(handlerCalled).toBe(true);
  });

  it('passes through clean data', async () => {
    const tork = new Tork();
    const handler = torkBunHandler(tork, async () => {
      return new Response(
        JSON.stringify({ message: 'Hello world' }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    const response = await handler(new Request('http://localhost/test'));
    const data = await response.json();
    expect(data.message).toBe('Hello world');
  });

  it('skips governance when governOutput is false', async () => {
    const tork = new Tork();
    const handler = torkBunHandler(tork, async () => {
      return new Response(
        JSON.stringify({ message: 'SSN: 123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      );
    }, { governOutput: false });

    const response = await handler(new Request('http://localhost/test'));
    const data = await response.json();
    expect(data.message).toBe('SSN: 123-45-6789');
  });

  it('skips input governance when disabled', async () => {
    const tork = new Tork();
    const handler = torkBunHandler(tork, async () => {
      return new Response('OK');
    }, { governInput: false });

    // Should not throw even with PII in query
    const response = await handler(new Request('http://localhost/test?ssn=123-45-6789'));
    expect(response.status).toBe(200);
  });
});

describe('createTorkBunServer', () => {
  it('wraps fetch handler in config', () => {
    const tork = new Tork();
    const config = createTorkBunServer(tork, {
      fetch: async () => new Response('OK'),
      port: 3000,
    });

    expect(typeof config.fetch).toBe('function');
    expect(config.port).toBe(3000);
  });
});

describe('createTorkBunRouter', () => {
  it('creates router with HTTP method helpers', () => {
    const tork = new Tork();
    const router = createTorkBunRouter(tork);

    expect(typeof router.get).toBe('function');
    expect(typeof router.post).toBe('function');
    expect(typeof router.put).toBe('function');
    expect(typeof router.patch).toBe('function');
    expect(typeof router.delete).toBe('function');
    expect(typeof router.fetch).toBe('function');
  });

  it('governs route responses', async () => {
    const tork = new Tork();
    const router = createTorkBunRouter(tork);

    router.get('/api/data', async () => {
      return new Response(
        JSON.stringify({ ssn: '123-45-6789' }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    const response = await router.fetch(new Request('http://localhost/api/data'));
    const data = await response.json();
    expect(data.ssn).toContain('[SSN_REDACTED]');
  });
});
