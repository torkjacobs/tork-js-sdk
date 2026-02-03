/**
 * Tork Governance adapter for Elysia (Bun web framework).
 *
 * Provides governance for Elysia routes and plugins
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkElysiaPlugin } from 'tork-governance';
 *
 * const app = new Elysia()
 *   .use(torkElysiaPlugin(tork))
 *   .get('/', () => 'Hello World');
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkElysiaOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governBody?: boolean;
}

export interface ElysiaContext {
  request: Request;
  path: string;
  query: Record<string, string | undefined>;
  params: Record<string, string>;
  body: any;
  headers: Record<string, string | undefined>;
  store: Record<string, any>;
  set: {
    headers: Record<string, string>;
    status?: number;
    redirect?: string;
  };
}

/**
 * Create Elysia plugin with Tork governance.
 */
export function torkElysiaPlugin(tork: Tork, options: TorkElysiaOptions = {}) {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return {
    name: 'tork-governance',

    beforeHandle(context: ElysiaContext) {
      const receipts: any[] = [];

      // Govern query parameters
      if (governInput && context.query) {
        for (const [key, value] of Object.entries(context.query)) {
          if (typeof value === 'string') {
            const result = tork.govern(value);
            receipts.push(result.receipt);
          }
        }
      }

      // Govern request body
      if (governInput && governBody && context.body) {
        if (typeof context.body === 'object') {
          governObject(tork, context.body, receipts);
        } else if (typeof context.body === 'string') {
          const result = tork.govern(context.body);
          receipts.push(result.receipt);
        }
      }

      // Store receipts
      context.store._tork_receipts = receipts;
    },

    afterHandle(context: ElysiaContext, response: any) {
      if (!governOutput) return response;

      const receipts = context.store._tork_receipts || [];

      // Govern response if object/string
      if (typeof response === 'object' && response !== null) {
        return governObject(tork, response, receipts);
      } else if (typeof response === 'string') {
        const result = tork.govern(response);
        receipts.push(result.receipt);
        return result.action === 'redact' || result.action === 'REDACT'
          ? result.output
          : response;
      }

      return response;
    },
  };
}

/**
 * Create Tork middleware function for Elysia derive.
 */
export function torkElysiaDerive(tork: Tork, options: TorkElysiaOptions = {}) {
  const { governInput = true } = options;

  return (context: ElysiaContext) => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput && context.query) {
      const governedQuery: Record<string, string | undefined> = {};
      for (const [key, value] of Object.entries(context.query)) {
        if (typeof value === 'string') {
          const result = tork.govern(value);
          receipts.push(result.receipt);
          governedQuery[key] = result.action === 'redact' || result.action === 'REDACT'
            ? result.output
            : value;
        } else {
          governedQuery[key] = value;
        }
      }
      context.query = governedQuery;
    }

    return {
      tork,
      torkReceipts: receipts,
      govern: (value: string) => tork.govern(value),
      governObject: <T extends object>(obj: T) => {
        const localReceipts: any[] = [];
        const governed = governObject(tork, obj, localReceipts);
        receipts.push(...localReceipts);
        return governed as T;
      },
    };
  };
}

/**
 * Wrap an Elysia handler with Tork governance.
 */
export function torkHandler<T>(
  tork: Tork,
  handler: (context: ElysiaContext & { _tork_receipts?: any[] }) => T | Promise<T>,
  options: TorkElysiaOptions = {}
): (context: ElysiaContext) => Promise<T> {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (context: ElysiaContext): Promise<T> => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput && context.query) {
      for (const [key, value] of Object.entries(context.query)) {
        if (typeof value === 'string') {
          const result = tork.govern(value);
          receipts.push(result.receipt);
        }
      }
    }

    // Govern body
    if (governInput && governBody && context.body) {
      if (typeof context.body === 'object') {
        context.body = governObject(tork, context.body, receipts);
      } else if (typeof context.body === 'string') {
        const result = tork.govern(context.body);
        receipts.push(result.receipt);
        context.body = result.action === 'redact' || result.action === 'REDACT'
          ? result.output
          : context.body;
      }
    }

    // Call handler
    const result = await handler({ ...context, _tork_receipts: receipts });

    // Govern output
    if (governOutput) {
      if (typeof result === 'object' && result !== null) {
        return governObject(tork, result, receipts) as T;
      } else if (typeof result === 'string') {
        const govResult = tork.govern(result);
        receipts.push(govResult.receipt);
        return (govResult.action === 'redact' || govResult.action === 'REDACT'
          ? govResult.output
          : result) as T;
      }
    }

    return result;
  };
}

/**
 * Recursively govern object values.
 */
function governObject(
  tork: Tork,
  obj: any,
  receipts: any[]
): any {
  if (typeof obj === 'string') {
    const result = tork.govern(obj);
    receipts.push(result.receipt);
    return result.action === 'redact' || result.action === 'REDACT'
      ? result.output
      : obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => governObject(tork, item, receipts));
  }

  if (obj && typeof obj === 'object') {
    const governed: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      governed[key] = governObject(tork, value, receipts);
    }
    return governed;
  }

  return obj;
}

export type { GovernanceResult };
