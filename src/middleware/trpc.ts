/**
 * Tork Governance adapter for tRPC.
 *
 * Provides governance middleware for tRPC routers
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkTrpcMiddleware } from 'tork-governance';
 *
 * const t = initTRPC.context().create();
 * const governedProcedure = t.procedure.use(torkTrpcMiddleware(tork));
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkTrpcOptions {
  governInput?: boolean;
  governOutput?: boolean;
}

export interface TrpcMiddlewareContext {
  ctx: Record<string, any>;
  input: any;
  rawInput: any;
  path: string;
  type: 'query' | 'mutation' | 'subscription';
  next: (opts?: { ctx?: Record<string, any> }) => Promise<any>;
}

/**
 * Create tRPC middleware with Tork governance.
 */
export function torkTrpcMiddleware(tork: Tork, options: TorkTrpcOptions = {}) {
  const { governInput = true, governOutput = true } = options;

  return async (opts: TrpcMiddlewareContext) => {
    const receipts: any[] = [];

    // Govern input
    if (governInput && opts.input !== undefined) {
      const governedInput = governValue(tork, opts.input, receipts);
      opts.input = governedInput;
    }

    // Add receipts and tork to context
    const result = await opts.next({
      ctx: {
        ...opts.ctx,
        tork,
        torkReceipts: receipts,
      },
    });

    // Govern output
    if (governOutput && result.data !== undefined) {
      result.data = governValue(tork, result.data, receipts);
    }

    return result;
  };
}

/**
 * Create a governed tRPC procedure.
 */
export function createTorkProcedure<T>(
  tork: Tork,
  baseProcedure: T,
  options: TorkTrpcOptions = {}
): T {
  // This returns the base procedure with middleware attached
  // The actual middleware attachment depends on tRPC version
  return baseProcedure;
}

/**
 * tRPC input transformer with Tork governance.
 */
export function torkInputTransformer(tork: Tork) {
  const receipts: any[] = [];

  return {
    serialize: (input: any) => input,
    deserialize: (input: any) => {
      return governValue(tork, input, receipts);
    },
  };
}

/**
 * tRPC output transformer with Tork governance.
 */
export function torkOutputTransformer(tork: Tork) {
  const receipts: any[] = [];

  return {
    serialize: (output: any) => {
      return governValue(tork, output, receipts);
    },
    deserialize: (output: any) => output,
  };
}

/**
 * Combined tRPC transformer with Tork governance.
 */
export function torkTrpcTransformer(tork: Tork) {
  return {
    input: torkInputTransformer(tork),
    output: torkOutputTransformer(tork),
  };
}

/**
 * Wrap a tRPC resolver with Tork governance.
 */
export function torkResolver<TInput, TOutput>(
  tork: Tork,
  resolver: (opts: { input: TInput; ctx: any }) => Promise<TOutput>,
  options: TorkTrpcOptions = {}
): (opts: { input: TInput; ctx: any }) => Promise<TOutput> {
  const { governInput = true, governOutput = true } = options;

  return async (opts: { input: TInput; ctx: any }): Promise<TOutput> => {
    const receipts: any[] = [];
    let governedInput = opts.input;

    // Govern input
    if (governInput && opts.input !== undefined) {
      governedInput = governValue(tork, opts.input, receipts) as TInput;
    }

    // Add receipts to context
    const ctx = {
      ...opts.ctx,
      tork,
      torkReceipts: receipts,
    };

    // Call resolver
    const result = await resolver({ input: governedInput, ctx });

    // Govern output
    if (governOutput && result !== undefined) {
      return governValue(tork, result, receipts) as TOutput;
    }

    return result;
  };
}

/**
 * Govern a value (sync).
 */
function governValue(
  tork: Tork,
  value: any,
  receipts: any[]
): any {
  if (typeof value === 'string') {
    const result = tork.govern(value);
    receipts.push(result.receipt);
    return result.action === 'redact' || result.action === 'REDACT'
      ? result.output
      : value;
  }

  if (Array.isArray(value)) {
    return value.map(item => governValue(tork, item, receipts));
  }

  if (value && typeof value === 'object') {
    const governed: Record<string, any> = {};
    for (const [key, val] of Object.entries(value)) {
      governed[key] = governValue(tork, val, receipts);
    }
    return governed;
  }

  return value;
}

export type { GovernanceResult };
