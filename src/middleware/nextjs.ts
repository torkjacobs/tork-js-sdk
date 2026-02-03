/**
 * Next.js API Route Wrapper for Tork Governance
 */

import { Tork, TorkConfig, GovernanceResult } from '../index';

export interface TorkNextOptions extends TorkConfig {
  /** Extract content from request body */
  extractContent?: (req: any) => string | null;
  /** Skip governance for certain requests */
  skip?: (req: any) => boolean;
}

export interface NextApiRequestWithTork {
  torkResult?: GovernanceResult;
  body: any;
  method?: string;
  query: Record<string, string | string[]>;
  cookies: Record<string, string>;
  headers: Record<string, string | string[] | undefined>;
}

/**
 * Next.js API route wrapper that applies Tork governance
 *
 * @example
 * ```typescript
 * // pages/api/chat.ts
 * import { withTork } from 'tork-governance/middleware/nextjs';
 *
 * async function handler(req, res) {
 *   // req.torkResult contains governance result
 *   // req.body.message is already redacted if needed
 *   res.json({ message: req.body.message });
 * }
 *
 * export default withTork(handler);
 * ```
 */
export function withTork<T extends (...args: any[]) => any>(
  handler: T,
  options: TorkNextOptions = {}
): T {
  const tork = new Tork({
    policyVersion: options.policyVersion,
    defaultAction: options.defaultAction,
    customPatterns: options.customPatterns,
  });

  const extractContent = options.extractContent || ((req: any) => {
    const body = req.body;
    if (!body) return null;
    if (typeof body === 'string') return body;
    if (body.content) return body.content;
    if (body.message) return body.message;
    if (body.text) return body.text;
    if (body.prompt) return body.prompt;
    return null;
  });

  const skip = options.skip || (() => false);

  return (async (req: NextApiRequestWithTork, res: any) => {
    // Only process POST, PUT, PATCH requests
    if (!['POST', 'PUT', 'PATCH'].includes(req.method || '')) {
      return handler(req, res);
    }

    if (skip(req)) {
      return handler(req, res);
    }

    const content = extractContent(req);

    if (!content) {
      return handler(req, res);
    }

    const result = tork.govern(content);
    req.torkResult = result;

    if (result.action === 'deny') {
      return res.status(403).json({
        error: 'Request blocked by governance policy',
        action: result.action,
        receiptId: result.receipt.receiptId,
        piiTypes: result.pii.types,
      });
    }

    // Replace content with redacted version if needed
    if (result.action === 'redact' && result.pii.hasPII && req.body) {
      if (req.body.content) req.body.content = result.output;
      if (req.body.message) req.body.message = result.output;
      if (req.body.text) req.body.text = result.output;
      if (req.body.prompt) req.body.prompt = result.output;
    }

    return handler(req, res);
  }) as T;
}

/**
 * Next.js App Router middleware for route handlers
 *
 * @example
 * ```typescript
 * // app/api/chat/route.ts
 * import { NextResponse } from 'next/server';
 * import { torkRouteHandler } from 'tork-governance/middleware/nextjs';
 *
 * export const POST = torkRouteHandler(async (request, torkResult) => {
 *   const body = await request.json();
 *   return NextResponse.json({ message: body.message });
 * });
 * ```
 */
export function torkRouteHandler(
  handler: (request: Request, torkResult?: GovernanceResult) => Promise<Response>,
  options: TorkNextOptions = {}
) {
  const tork = new Tork({
    policyVersion: options.policyVersion,
    defaultAction: options.defaultAction,
    customPatterns: options.customPatterns,
  });

  return async (request: Request) => {
    // Only process POST, PUT, PATCH requests
    if (!['POST', 'PUT', 'PATCH'].includes(request.method)) {
      return handler(request);
    }

    try {
      const body = await request.clone().json() as Record<string, unknown>;
      const rawContent = body.content || body.message || body.text || body.prompt;

      if (!rawContent || typeof rawContent !== 'string') {
        return handler(request);
      }

      const content = rawContent as string;
      const result = tork.govern(content);

      if (result.action === 'deny') {
        return new Response(JSON.stringify({
          error: 'Request blocked by governance policy',
          action: result.action,
          receiptId: result.receipt.receiptId,
          piiTypes: result.pii.types,
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      return handler(request, result);
    } catch {
      return handler(request);
    }
  };
}

export default withTork;
