/**
 * Tests for tRPC middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import {
  torkTrpcMiddleware,
  torkResolver,
  torkInputTransformer,
  torkOutputTransformer,
  torkTrpcTransformer,
} from '../src/middleware/trpc';

describe('torkTrpcMiddleware', () => {
  it('governs string input', async () => {
    const tork = new Tork();
    const middleware = torkTrpcMiddleware(tork);

    const opts: any = {
      ctx: {},
      input: 'SSN: 123-45-6789',
      rawInput: 'SSN: 123-45-6789',
      path: 'test',
      type: 'query',
      next: vi.fn().mockResolvedValue({ data: 'OK' }),
    };

    await middleware(opts);

    expect(opts.input).toContain('[SSN_REDACTED]');
    expect(opts.input).not.toContain('123-45-6789');
  });

  it('governs object input', async () => {
    const tork = new Tork();
    const middleware = torkTrpcMiddleware(tork);

    const opts: any = {
      ctx: {},
      input: { message: 'SSN: 123-45-6789' },
      rawInput: {},
      path: 'test',
      type: 'mutation',
      next: vi.fn().mockResolvedValue({ data: 'OK' }),
    };

    await middleware(opts);

    expect(opts.input.message).toContain('[SSN_REDACTED]');
  });

  it('governs output data', async () => {
    const tork = new Tork();
    const middleware = torkTrpcMiddleware(tork);

    const result = { data: 'Email: admin@secret.com' };
    const opts: any = {
      ctx: {},
      input: 'hello',
      rawInput: 'hello',
      path: 'test',
      type: 'query',
      next: vi.fn().mockResolvedValue(result),
    };

    const output = await middleware(opts);

    expect(output.data).toContain('[EMAIL_REDACTED]');
  });

  it('adds tork to context', async () => {
    const tork = new Tork();
    const middleware = torkTrpcMiddleware(tork);

    let receivedCtx: any;
    const opts: any = {
      ctx: {},
      input: 'hello',
      rawInput: 'hello',
      path: 'test',
      type: 'query',
      next: vi.fn().mockImplementation(({ ctx }) => {
        receivedCtx = ctx;
        return { data: 'OK' };
      }),
    };

    await middleware(opts);

    expect(receivedCtx.tork).toBe(tork);
    expect(receivedCtx.torkReceipts).toBeDefined();
  });

  it('skips input governance when disabled', async () => {
    const tork = new Tork();
    const middleware = torkTrpcMiddleware(tork, { governInput: false });

    const opts: any = {
      ctx: {},
      input: 'SSN: 123-45-6789',
      rawInput: '',
      path: 'test',
      type: 'query',
      next: vi.fn().mockResolvedValue({ data: 'OK' }),
    };

    await middleware(opts);

    expect(opts.input).toBe('SSN: 123-45-6789');
  });

  it('skips output governance when disabled', async () => {
    const tork = new Tork();
    const middleware = torkTrpcMiddleware(tork, { governOutput: false });

    const opts: any = {
      ctx: {},
      input: 'hello',
      rawInput: '',
      path: 'test',
      type: 'query',
      next: vi.fn().mockResolvedValue({ data: 'SSN: 123-45-6789' }),
    };

    const result = await middleware(opts);

    expect(result.data).toBe('SSN: 123-45-6789');
  });
});

describe('torkResolver', () => {
  it('governs resolver input and output', async () => {
    const tork = new Tork();
    const resolver = torkResolver(
      tork,
      async ({ input }) => `Received: ${input}`,
    );

    const result = await resolver({
      input: 'SSN: 123-45-6789',
      ctx: {},
    });

    // Input should be governed, and output contains the governed input
    expect(result).not.toContain('123-45-6789');
  });

  it('provides tork in context', async () => {
    const tork = new Tork();
    let receivedCtx: any;

    const resolver = torkResolver(tork, async ({ ctx }) => {
      receivedCtx = ctx;
      return 'OK';
    });

    await resolver({ input: 'hello', ctx: {} });

    expect(receivedCtx.tork).toBe(tork);
  });
});

describe('torkInputTransformer', () => {
  it('governs input on deserialize', () => {
    const tork = new Tork();
    const transformer = torkInputTransformer(tork);

    const result = transformer.deserialize('SSN: 123-45-6789');
    expect(result).toContain('[SSN_REDACTED]');
  });

  it('passes through on serialize', () => {
    const tork = new Tork();
    const transformer = torkInputTransformer(tork);

    const result = transformer.serialize('test');
    expect(result).toBe('test');
  });
});

describe('torkOutputTransformer', () => {
  it('governs output on serialize', () => {
    const tork = new Tork();
    const transformer = torkOutputTransformer(tork);

    const result = transformer.serialize('Email: admin@secret.com');
    expect(result).toContain('[EMAIL_REDACTED]');
  });
});

describe('torkTrpcTransformer', () => {
  it('creates combined input/output transformer', () => {
    const tork = new Tork();
    const transformer = torkTrpcTransformer(tork);

    expect(transformer.input).toBeDefined();
    expect(transformer.output).toBeDefined();
    expect(typeof transformer.input.serialize).toBe('function');
    expect(typeof transformer.output.serialize).toBe('function');
  });
});
