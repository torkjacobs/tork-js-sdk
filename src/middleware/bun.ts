/**
 * Tork Governance adapter for Bun.serve.
 *
 * Provides governance for Bun HTTP servers
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkBunHandler } from 'tork-governance';
 *
 * Bun.serve({
 *   fetch: torkBunHandler(tork, async (req) => {
 *     return new Response("Hello");
 *   }),
 * });
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkBunOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governBody?: boolean;
}

export interface BunServer {
  fetch: (req: Request, server: any) => Response | Promise<Response>;
  port?: number;
  hostname?: string;
  error?: (error: Error) => Response | Promise<Response>;
}

/**
 * Wrap a Bun.serve fetch handler with Tork governance.
 */
export function torkBunHandler(
  tork: Tork,
  handler: (req: Request, server?: any) => Response | Promise<Response>,
  options: TorkBunOptions = {}
): (req: Request, server?: any) => Promise<Response> {
  const { governInput = true, governOutput = true, governBody = true } = options;

  return async (req: Request, server?: any): Promise<Response> => {
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
      } else if (contentType.includes('application/x-www-form-urlencoded') ||
                 contentType.includes('multipart/form-data')) {
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
      } else if (contentType.includes('text/')) {
        try {
          const text = await req.clone().text();
          const result = tork.govern(text);
          receipts.push(result.receipt);
        } catch {
          // Text parsing failed
        }
      }
    }

    // Call original handler
    const response = await handler(req, server);

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
      } else if (contentType.includes('text/')) {
        try {
          const text = await response.clone().text();
          const result = tork.govern(text);
          receipts.push(result.receipt);

          if (result.action === 'redact' || result.action === 'REDACT') {
            return new Response(result.output, {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            });
          }
        } catch {
          // Text parsing failed
        }
      }
    }

    return response;
  };
}

/**
 * Create a governed Bun.serve configuration.
 */
export function createTorkBunServer(
  tork: Tork,
  config: BunServer,
  options: TorkBunOptions = {}
): BunServer {
  return {
    ...config,
    fetch: torkBunHandler(tork, config.fetch, options),
  };
}

/**
 * Simple router with Tork governance for Bun.
 */
export function createTorkBunRouter(tork: Tork, options: TorkBunOptions = {}) {
  const routes: Map<string, Map<string, (req: Request) => Response | Promise<Response>>> = new Map();

  const addRoute = (method: string, path: string, handler: (req: Request) => Response | Promise<Response>) => {
    if (!routes.has(path)) {
      routes.set(path, new Map());
    }
    routes.get(path)!.set(method.toUpperCase(), handler);
  };

  return {
    get: (path: string, handler: (req: Request) => Response | Promise<Response>) => addRoute('GET', path, handler),
    post: (path: string, handler: (req: Request) => Response | Promise<Response>) => addRoute('POST', path, handler),
    put: (path: string, handler: (req: Request) => Response | Promise<Response>) => addRoute('PUT', path, handler),
    patch: (path: string, handler: (req: Request) => Response | Promise<Response>) => addRoute('PATCH', path, handler),
    delete: (path: string, handler: (req: Request) => Response | Promise<Response>) => addRoute('DELETE', path, handler),

    fetch: torkBunHandler(tork, async (req: Request): Promise<Response> => {
      const url = new URL(req.url);
      const pathHandlers = routes.get(url.pathname);

      if (pathHandlers) {
        const handler = pathHandlers.get(req.method);
        if (handler) {
          return await handler(req);
        }
        return new Response('Method Not Allowed', { status: 405 });
      }

      return new Response('Not Found', { status: 404 });
    }, options),
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
