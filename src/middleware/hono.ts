/**
 * Tork Governance adapter for Hono.
 *
 * Provides governance middleware for Hono applications
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { Hono } from 'hono';
 * import { torkHonoMiddleware } from 'tork-governance';
 *
 * const app = new Hono();
 * app.use('*', torkHonoMiddleware(tork));
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkHonoOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governBody?: boolean;
}

export interface HonoContext {
  req: {
    url: string;
    method: string;
    header: (name: string) => string | undefined;
    query: (name: string) => string | undefined;
    queries: (name: string) => string[] | undefined;
    json: () => Promise<any>;
    text: () => Promise<string>;
    formData: () => Promise<FormData>;
    raw: Request;
  };
  res: Response | undefined;
  json: (data: any, status?: number) => Response;
  text: (text: string, status?: number) => Response;
  body: (data: any, status?: number) => Response;
  set: (name: string, value: any) => void;
  get: (name: string) => any;
  var: Record<string, any>;
}

type HonoNext = () => Promise<void>;

/**
 * Create Hono middleware with Tork governance.
 */
export function torkHonoMiddleware(tork: Tork, options: TorkHonoOptions = {}) {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (c: HonoContext, next: HonoNext) => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput) {
      const url = new URL(c.req.url);
      for (const [key, value] of url.searchParams.entries()) {
        const result = tork.govern(value);
        receipts.push(result.receipt);
      }
    }

    // Govern request body
    if (governInput && governBody) {
      const contentType = c.req.header('content-type') || '';

      if (contentType.includes('application/json')) {
        try {
          const body = await c.req.raw.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed
        }
      } else if (contentType.includes('application/x-www-form-urlencoded') ||
                 contentType.includes('multipart/form-data')) {
        try {
          const formData = await c.req.raw.clone().formData();
          for (const [key, value] of formData.entries()) {
            if (typeof value === 'string') {
              const result = tork.govern(value);
              receipts.push(result.receipt);
            }
          }
        } catch {
          // Form data parsing failed
        }
      }
    }

    // Store receipts and tork instance
    c.set('torkReceipts', receipts);
    c.set('tork', tork);

    // Call next middleware
    await next();

    // Govern JSON response
    if (governOutput && c.res) {
      const contentType = c.res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const data = await c.res.clone().json();
          const governedData = governObject(tork, data, receipts);

          c.res = new Response(JSON.stringify(governedData), {
            status: c.res.status,
            statusText: c.res.statusText,
            headers: c.res.headers,
          });
        } catch {
          // Not JSON
        }
      }
    }
  };
}

/**
 * Wrap a Hono handler with Tork governance.
 */
export function torkHonoHandler<T>(
  tork: Tork,
  handler: (c: HonoContext) => T | Promise<T>,
  options: TorkHonoOptions = {}
): (c: HonoContext) => Promise<T> {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (c: HonoContext): Promise<T> => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput) {
      const url = new URL(c.req.url);
      for (const [key, value] of url.searchParams.entries()) {
        const result = tork.govern(value);
        receipts.push(result.receipt);
      }
    }

    // Govern body
    if (governInput && governBody) {
      const contentType = c.req.header('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const body = await c.req.raw.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed
        }
      }
    }

    // Store receipts
    c.set('torkReceipts', receipts);

    // Call handler
    const result = await handler(c);

    // Govern output if Response with JSON
    if (governOutput && result instanceof Response) {
      const contentType = result.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const data = await result.clone().json();
          const governedData = governObject(tork, data, receipts);

          return new Response(JSON.stringify(governedData), {
            status: result.status,
            statusText: result.statusText,
            headers: result.headers,
          }) as T;
        } catch {
          // Not JSON
        }
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
    return result.action === 'redact'
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
