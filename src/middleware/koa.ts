/**
 * Koa Middleware for Tork Governance
 */

import { Tork, TorkConfig, GovernanceResult } from '../index';

export interface TorkKoaOptions extends TorkConfig {
  /** Extract content from request body */
  extractContent?: (ctx: any) => string | null;
  /** Skip governance for certain requests */
  skip?: (ctx: any) => boolean;
}

// Note: When using with Koa, the torkResult will be available on ctx.state
// Type: ctx.state.torkResult?: GovernanceResult

/**
 * Koa middleware that applies Tork governance to request bodies
 *
 * @example
 * ```typescript
 * import Koa from 'koa';
 * import bodyParser from 'koa-bodyparser';
 * import { torkKoaMiddleware } from 'tork-governance/middleware/koa';
 *
 * const app = new Koa();
 * app.use(bodyParser());
 * app.use(torkKoaMiddleware());
 *
 * app.use(async (ctx) => {
 *   // ctx.state.torkResult contains governance result
 *   ctx.body = { message: ctx.request.body.message };
 * });
 * ```
 */
export function torkKoaMiddleware(options: TorkKoaOptions = {}) {
  const tork = new Tork({
    policyVersion: options.policyVersion,
    defaultAction: options.defaultAction,
    customPatterns: options.customPatterns,
  });

  const extractContent = options.extractContent || ((ctx: any) => {
    const body = ctx.request.body;
    if (!body) return null;
    if (typeof body === 'string') return body;
    if (body.content) return body.content;
    if (body.message) return body.message;
    if (body.text) return body.text;
    if (body.prompt) return body.prompt;
    return null;
  });

  const skip = options.skip || (() => false);

  return async (ctx: any, next: any) => {
    if (skip(ctx)) {
      return next();
    }

    const content = extractContent(ctx);

    if (!content) {
      return next();
    }

    const result = tork.govern(content);
    ctx.state.torkResult = result;

    if (result.action === 'deny') {
      ctx.status = 403;
      ctx.body = {
        error: 'Request blocked by governance policy',
        action: result.action,
        receiptId: result.receipt.receiptId,
        piiTypes: result.pii.types,
      };
      return;
    }

    // Replace content with redacted version if needed
    if (result.action === 'redact' && result.pii.hasPII && ctx.request.body) {
      if (ctx.request.body.content) ctx.request.body.content = result.output;
      if (ctx.request.body.message) ctx.request.body.message = result.output;
      if (ctx.request.body.text) ctx.request.body.text = result.output;
      if (ctx.request.body.prompt) ctx.request.body.prompt = result.output;
    }

    return next();
  };
}

export default torkKoaMiddleware;
