/**
 * Tork Governance adapter for SvelteKit.
 *
 * Provides governance for SvelteKit load functions and actions
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkLoad, torkFormAction } from 'tork-governance';
 *
 * export const load = torkLoad(tork, async ({ params }) => {
 *   return { data: "sensitive info" };
 * });
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkSvelteKitOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governFormData?: boolean;
}

export interface SvelteKitLoadEvent {
  params: Record<string, string>;
  url: URL;
  request: Request;
  fetch: typeof fetch;
  locals: Record<string, any>;
  platform?: any;
  route: { id: string | null };
}

export interface SvelteKitRequestEvent {
  params: Record<string, string>;
  url: URL;
  request: Request;
  fetch: typeof fetch;
  locals: Record<string, any>;
  platform?: any;
  route: { id: string | null };
}

/**
 * Wrap a SvelteKit load function with Tork governance.
 */
export function torkLoad<T>(
  tork: Tork,
  load: (event: SvelteKitLoadEvent & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkSvelteKitOptions = {}
): (event: SvelteKitLoadEvent) => Promise<T> {
  const { governInput = true, governOutput = true } = options;

  return async (event: SvelteKitLoadEvent): Promise<T> => {
    const receipts: any[] = [];

    // Govern URL search params
    if (governInput) {
      for (const [key, value] of event.url.searchParams.entries()) {
        const result = tork.govern(value);
        receipts.push(result.receipt);
      }
    }

    // Call original load with receipts
    const result = await load({ ...event, _tork_receipts: receipts });

    // Govern output data
    if (governOutput && result && typeof result === 'object') {
      return governObject(tork, result, receipts) as T;
    }

    return result;
  };
}

/**
 * Wrap a SvelteKit form action with Tork governance.
 */
export function torkFormAction<T>(
  tork: Tork,
  action: (event: SvelteKitRequestEvent & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkSvelteKitOptions = {}
): (event: SvelteKitRequestEvent) => Promise<T> {
  const { governInput = true, governOutput = true, governFormData = true } = options;

  return async (event: SvelteKitRequestEvent): Promise<T> => {
    const receipts: any[] = [];

    // Govern form data
    if (governInput && governFormData) {
      try {
        const formData = await event.request.clone().formData();
        for (const [key, value] of formData.entries()) {
          if (typeof value === 'string') {
            const result = tork.govern(value);
            receipts.push(result.receipt);
          }
        }
      } catch {
        // Form data parsing failed, continue
      }
    }

    // Call original action with receipts
    const result = await action({ ...event, _tork_receipts: receipts });

    // Govern output
    if (governOutput && result && typeof result === 'object') {
      return governObject(tork, result, receipts) as T;
    }

    return result;
  };
}

/**
 * Create Tork middleware for SvelteKit hooks.
 */
export function createTorkSvelteKitHandle(tork: Tork, options: TorkSvelteKitOptions = {}) {
  const { governInput = true, governOutput = true } = options;

  return async ({ event, resolve }: { event: SvelteKitRequestEvent; resolve: (event: SvelteKitRequestEvent) => Promise<Response> }): Promise<Response> => {
    const receipts: any[] = [];

    // Govern request body if JSON
    if (governInput) {
      const contentType = event.request.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          const body = await event.request.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed
        }
      }
    }

    // Store receipts in locals
    event.locals._tork_receipts = receipts;

    // Resolve request
    const response = await resolve(event);

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
 * Create governed actions object for SvelteKit.
 */
export function torkActions<T extends Record<string, (event: SvelteKitRequestEvent) => Promise<any>>>(
  tork: Tork,
  actions: T,
  options: TorkSvelteKitOptions = {}
): T {
  const governed: Record<string, any> = {};

  for (const [name, action] of Object.entries(actions)) {
    governed[name] = torkFormAction(tork, action, options);
  }

  return governed as T;
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
