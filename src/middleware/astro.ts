/**
 * Tork Governance adapter for Astro.
 *
 * Provides governance for Astro API routes and middleware
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkAstroMiddleware } from 'tork-governance';
 *
 * export const onRequest = torkAstroMiddleware(tork);
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkAstroOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governBody?: boolean;
}

export interface AstroAPIContext {
  request: Request;
  params: Record<string, string | undefined>;
  url: URL;
  locals: Record<string, any>;
  cookies: any;
  redirect: (path: string, status?: number) => Response;
}

/**
 * Create Astro middleware with Tork governance.
 */
export function torkAstroMiddleware(tork: Tork, options: TorkAstroOptions = {}) {
  const { governInput = true, governOutput = true } = options;

  return async (context: AstroAPIContext, next: () => Promise<Response>): Promise<Response> => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput) {
      for (const [key, value] of context.url.searchParams.entries()) {
        const result = tork.govern(value);
        receipts.push(result.receipt);
      }
    }

    // Govern request body if JSON
    if (governInput) {
      const contentType = context.request.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const body = await context.request.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed
        }
      }
    }

    // Store receipts in locals
    context.locals._tork_receipts = receipts;

    // Call next handler
    const response = await next();

    // Govern JSON response
    if (governOutput) {
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const data = await response.clone().json();
          const governedData = governObject(tork, data, receipts);

          return new Response(JSON.stringify(governedData), {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        } catch {
          // Not JSON
        }
      }
    }

    return response;
  };
}

/**
 * Wrap an Astro API route with Tork governance.
 */
export function torkApiRoute<T>(
  tork: Tork,
  handler: (context: AstroAPIContext & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkAstroOptions = {}
): (context: AstroAPIContext) => Promise<T> {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (context: AstroAPIContext): Promise<T> => {
    const receipts: any[] = [];

    // Govern query parameters
    if (governInput) {
      for (const [key, value] of context.url.searchParams.entries()) {
        const result = tork.govern(value);
        receipts.push(result.receipt);
      }
    }

    // Govern request body
    if (governInput && governBody) {
      const contentType = context.request.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const body = await context.request.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed
        }
      }
    }

    // Store receipts
    context.locals._tork_receipts = receipts;

    // Call original handler
    const result = await handler({ ...context, _tork_receipts: receipts });

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
 * Create governed API handlers for Astro.
 */
export function createTorkAstroHandlers(tork: Tork, options: TorkAstroOptions = {}) {
  return {
    GET: (handler: (context: AstroAPIContext & { _tork_receipts?: any[] }) => Promise<Response>) =>
      torkApiRoute(tork, handler, options),
    POST: (handler: (context: AstroAPIContext & { _tork_receipts?: any[] }) => Promise<Response>) =>
      torkApiRoute(tork, handler, options),
    PUT: (handler: (context: AstroAPIContext & { _tork_receipts?: any[] }) => Promise<Response>) =>
      torkApiRoute(tork, handler, options),
    PATCH: (handler: (context: AstroAPIContext & { _tork_receipts?: any[] }) => Promise<Response>) =>
      torkApiRoute(tork, handler, options),
    DELETE: (handler: (context: AstroAPIContext & { _tork_receipts?: any[] }) => Promise<Response>) =>
      torkApiRoute(tork, handler, options),
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
