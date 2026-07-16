/**
 * Tork Governance adapter for Deno Fresh.
 *
 * Provides governance for Fresh handlers and middleware
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkFreshMiddleware } from 'tork-governance';
 *
 * export const handler = torkFreshMiddleware(tork, {
 *   GET: async (req, ctx) => new Response("Hello"),
 * });
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkFreshOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governBody?: boolean;
}

export interface FreshContext {
  params: Record<string, string>;
  state: Record<string, any>;
  render: (data?: any) => Response | Promise<Response>;
  renderNotFound: () => Response | Promise<Response>;
  next: () => Promise<Response>;
}

export type FreshHandler = (
  req: Request,
  ctx: FreshContext
) => Response | Promise<Response>;

export interface FreshHandlers {
  GET?: FreshHandler;
  POST?: FreshHandler;
  PUT?: FreshHandler;
  PATCH?: FreshHandler;
  DELETE?: FreshHandler;
  HEAD?: FreshHandler;
  OPTIONS?: FreshHandler;
}

/**
 * Create governed Fresh handlers.
 */
export function torkFreshMiddleware(
  tork: Tork,
  handlers: FreshHandlers,
  options: TorkFreshOptions = {}
): FreshHandlers {
  const governed: FreshHandlers = {};

  for (const [method, handler] of Object.entries(handlers)) {
    if (handler) {
      governed[method as keyof FreshHandlers] = torkFreshHandler(tork, handler, options);
    }
  }

  return governed;
}

/**
 * Wrap a Fresh handler with Tork governance.
 */
export function torkFreshHandler(
  tork: Tork,
  handler: FreshHandler,
  options: TorkFreshOptions = {}
): FreshHandler {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (req: Request, ctx: FreshContext): Promise<Response> => {
    const receipts: any[] = [];

    // Govern URL search params
    if (governInput) {
      const url = new URL(req.url);
      for (const [key, value] of url.searchParams.entries()) {
        const result = tork.govern(value);
        receipts.push(result.receipt);
      }
    }

    // Govern request body
    if (governInput && governBody) {
      const contentType = req.headers.get('content-type') || '';

      if (contentType.includes('application/json')) {
        try {
          const body = await req.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed
        }
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const formData = await req.clone().formData();
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

    // Store receipts in state
    ctx.state._tork_receipts = receipts;

    // Call original handler
    const response = await handler(req, ctx);

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
 * Create Fresh plugin with Tork governance.
 */
export function torkFreshPlugin(tork: Tork, options: TorkFreshOptions = {}) {
  return {
    name: 'tork-governance',
    middlewares: [
      {
        path: '/',
        middleware: {
          handler: async (req: Request, ctx: FreshContext) => {
            const receipts: any[] = [];

            // Govern query params
            if (options.governInput !== false) {
              const url = new URL(req.url);
              for (const [key, value] of url.searchParams.entries()) {
                const result = tork.govern(value);
                receipts.push(result.receipt);
              }
            }

            ctx.state._tork_receipts = receipts;
            ctx.state._tork = tork;

            return await ctx.next();
          },
        },
      },
    ],
  };
}

/**
 * Helper to govern render data in Fresh routes.
 */
export function governRenderData<T extends object>(
  tork: Tork,
  data: T
): T {
  const receipts: any[] = [];
  return governObject(tork, data, receipts) as T;
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
