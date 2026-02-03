/**
 * Tork Governance adapter for Remix.
 *
 * Provides governance for Remix loaders and actions
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkLoader, torkAction } from 'tork-governance';
 *
 * export const loader = torkLoader(tork, async ({ request }) => {
 *   return json({ data: "sensitive info" });
 * });
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkRemixOptions {
  governInput?: boolean;
  governOutput?: boolean;
  governFormData?: boolean;
}

export interface RemixLoaderArgs {
  request: Request;
  params: Record<string, string | undefined>;
  context?: any;
}

export interface RemixActionArgs {
  request: Request;
  params: Record<string, string | undefined>;
  context?: any;
}

/**
 * Wrap a Remix loader with Tork governance.
 */
export function torkLoader<T>(
  tork: Tork,
  loader: (args: RemixLoaderArgs & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkRemixOptions = {}
): (args: RemixLoaderArgs) => Promise<T> {
  const { governInput = true, governOutput = true } = options;

  return async (args: RemixLoaderArgs): Promise<T> => {
    const receipts: any[] = [];

    // Govern URL search params
    if (governInput) {
      const url = new URL(args.request.url);
      for (const [key, value] of url.searchParams.entries()) {
        const result = tork.govern(value);
        if (result.action === 'redact' || result.action === 'REDACT') {
          url.searchParams.set(key, result.output);
        }
        receipts.push(result.receipt);
      }
    }

    // Call original loader with receipts
    const result = await loader({ ...args, _tork_receipts: receipts });

    // Govern output if it's a Response with JSON
    if (governOutput && result instanceof Response) {
      try {
        const cloned = result.clone();
        const data = await cloned.json();
        const governedData = governObject(tork, data, receipts);

        return new Response(JSON.stringify(governedData), {
          status: result.status,
          statusText: result.statusText,
          headers: result.headers,
        }) as T;
      } catch {
        // Not JSON, return as-is
        return result;
      }
    }

    return result;
  };
}

/**
 * Wrap a Remix action with Tork governance.
 */
export function torkAction<T>(
  tork: Tork,
  action: (args: RemixActionArgs & { _tork_receipts?: any[] }) => Promise<T>,
  options: TorkRemixOptions = {}
): (args: RemixActionArgs) => Promise<T> {
  const { governInput = true, governOutput = true, governFormData = true } = options;

  return async (args: RemixActionArgs): Promise<T> => {
    const receipts: any[] = [];

    // Govern form data
    if (governInput && governFormData) {
      const contentType = args.request.headers.get('content-type') || '';

      if (contentType.includes('application/x-www-form-urlencoded') ||
          contentType.includes('multipart/form-data')) {
        try {
          const formData = await args.request.clone().formData();
          const governedFormData = new FormData();

          for (const [key, value] of formData.entries()) {
            if (typeof value === 'string') {
              const result = tork.govern(value);
              receipts.push(result.receipt);
              governedFormData.append(
                key,
                result.action === 'redact' || result.action === 'REDACT'
                  ? result.output
                  : value
              );
            } else {
              governedFormData.append(key, value);
            }
          }
        } catch {
          // Form data parsing failed, continue
        }
      }

      // Govern JSON body
      if (contentType.includes('application/json')) {
        try {
          const body = await args.request.clone().json();
          governObject(tork, body, receipts);
        } catch {
          // JSON parsing failed, continue
        }
      }
    }

    // Call original action with receipts
    const result = await action({ ...args, _tork_receipts: receipts });

    // Govern output
    if (governOutput && result instanceof Response) {
      try {
        const cloned = result.clone();
        const data = await cloned.json();
        const governedData = governObject(tork, data, receipts);

        return new Response(JSON.stringify(governedData), {
          status: result.status,
          statusText: result.statusText,
          headers: result.headers,
        }) as T;
      } catch {
        return result;
      }
    }

    return result;
  };
}

/**
 * Create Tork middleware for Remix request handlers.
 */
export function createTorkRemixMiddleware(tork: Tork, options: TorkRemixOptions = {}) {
  return {
    loader: <T>(fn: (args: RemixLoaderArgs & { _tork_receipts?: any[] }) => Promise<T>) =>
      torkLoader(tork, fn, options),
    action: <T>(fn: (args: RemixActionArgs & { _tork_receipts?: any[] }) => Promise<T>) =>
      torkAction(tork, fn, options),
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
