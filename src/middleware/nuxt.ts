/**
 * Tork Governance adapter for Nuxt.
 *
 * Provides governance for Nuxt server routes and middleware
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { defineTorkEventHandler } from 'tork-governance';
 *
 * export default defineTorkEventHandler(tork, async (event) => {
 *   return { data: "sensitive info" };
 * });
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkNuxtOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governBody?: boolean;
}

export interface H3Event {
  node: {
    req: any;
    res: any;
  };
  path: string;
  method: string;
  headers: Headers;
  context: Record<string, any>;
}

/**
 * Define a Nuxt event handler with Tork governance.
 */
export function defineTorkEventHandler<T>(
  tork: Tork,
  handler: (event: H3Event & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkNuxtOptions = {}
): (event: H3Event) => Promise<T> {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (event: H3Event): Promise<T> => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput) {
      try {
        const url = new URL(event.path, 'http://localhost');
        for (const [key, value] of url.searchParams.entries()) {
          const result = tork.govern(value);
          receipts.push(result.receipt);
        }
      } catch {
        // URL parsing failed
      }
    }

    // Govern request body
    if (governInput && governBody && event.node.req.body) {
      try {
        const body = event.node.req.body;
        if (typeof body === 'object') {
          governObject(tork, body, receipts);
        } else if (typeof body === 'string') {
          const result = tork.govern(body);
          receipts.push(result.receipt);
        }
      } catch {
        // Body parsing failed
      }
    }

    // Store receipts in context
    event.context._tork_receipts = receipts;

    // Call original handler
    const result = await handler({ ...event, _tork_receipts: receipts });

    // Govern output
    if (governOutput && result && typeof result === 'object') {
      return governObject(tork, result, receipts) as T;
    }

    return result;
  };
}

/**
 * Create Nuxt server middleware with Tork governance.
 */
export function createTorkNuxtMiddleware(tork: Tork, options: TorkNuxtOptions = {}) {
  const { governInput = true, governOutput = true } = options;

  return async (event: H3Event, next: () => Promise<any>): Promise<any> => {
    const receipts: any[] = [];

    // Govern incoming request
    if (governInput) {
      // Query params
      try {
        const url = new URL(event.path, 'http://localhost');
        for (const [key, value] of url.searchParams.entries()) {
          const result = tork.govern(value);
          receipts.push(result.receipt);
        }
      } catch {
        // URL parsing failed
      }
    }

    // Store receipts
    event.context._tork_receipts = receipts;

    // Continue to next handler
    const result = await next();

    // Govern response
    if (governOutput && result && typeof result === 'object') {
      return governObject(tork, result, receipts);
    }

    return result;
  };
}

/**
 * Wrap a Nuxt API route with Tork governance.
 */
export function torkApiRoute<T>(
  tork: Tork,
  handler: (event: H3Event & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkNuxtOptions = {}
): (event: H3Event) => Promise<T> {
  return defineTorkEventHandler(tork, handler, options);
}

/**
 * Create governed composable for Nuxt.
 */
export function useTorkGovernance(tork: Tork) {
  return {
    /**
     * Govern a string value.
     */
    govern: (value: string): GovernanceResult => {
      return tork.govern(value);
    },

    /**
     * Govern an object recursively.
     */
    governObject: <T extends object>(obj: T): T => {
      const receipts: any[] = [];
      return governObject(tork, obj, receipts) as T;
    },

    /**
     * Wrap an async function with governance.
     */
    withGovernance: <T>(fn: () => Promise<T>): (() => Promise<T>) => {
      return async () => {
        const result = await fn();
        if (result && typeof result === 'object') {
          const receipts: any[] = [];
          return governObject(tork, result, receipts) as T;
        }
        return result;
      };
    },
  };
}

/**
 * Nuxt plugin factory for Tork governance.
 */
export function createTorkNuxtPlugin(tork: Tork) {
  return {
    name: 'tork-governance',
    setup() {
      return {
        provide: {
          tork,
          torkGovernance: useTorkGovernance(tork),
        },
      };
    },
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
