/**
 * Express.js Middleware for Tork Governance
 */

import { Tork, TorkConfig, GovernanceResult } from '../index';

export interface TorkExpressOptions extends TorkConfig {
  /** Extract content from request body - defaults to body.content || body.message || body.text */
  extractContent?: (req: any) => string | null;
  /** Called when content is blocked */
  onBlock?: (result: GovernanceResult, req: any, res: any) => void;
  /** Skip governance for certain paths */
  skip?: (req: any) => boolean;
}

declare global {
  namespace Express {
    interface Request {
      torkResult?: GovernanceResult;
    }
  }
}

/**
 * Express middleware that applies Tork governance to request bodies
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { torkExpressMiddleware } from 'tork-governance/middleware/express';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(torkExpressMiddleware());
 *
 * app.post('/chat', (req, res) => {
 *   // req.torkResult contains governance result
 *   // req.body.message is already redacted if needed
 *   res.json({ message: req.body.message });
 * });
 * ```
 */
export function torkExpressMiddleware(options: TorkExpressOptions = {}) {
  const tork = new Tork({
    policyVersion: options.policyVersion,
    defaultAction: options.defaultAction,
    customPatterns: options.customPatterns,
  });

  const extractContent = options.extractContent || ((req: any) => {
    if (!req.body) return null;
    if (typeof req.body === 'string') return req.body;
    if (req.body.content) return req.body.content;
    if (req.body.message) return req.body.message;
    if (req.body.text) return req.body.text;
    if (req.body.prompt) return req.body.prompt;
    if (req.body.query) return req.body.query;
    return null;
  });

  const defaultOnBlock = (result: GovernanceResult, _req: any, res: any) => {
    res.status(403).json({
      error: 'Request blocked by governance policy',
      action: result.action,
      receiptId: result.receipt.receiptId,
      piiTypes: result.pii.types,
    });
  };

  const onBlock = options.onBlock || defaultOnBlock;
  const skip = options.skip || (() => false);

  return (req: any, res: any, next: any) => {
    // Skip if configured to skip this request
    if (skip(req)) {
      return next();
    }

    const content = extractContent(req);

    if (!content) {
      return next();
    }

    const result = tork.govern(content);
    req.torkResult = result;

    if (result.action === 'deny') {
      return onBlock(result, req, res);
    }

    // Replace content with redacted version if needed
    if (result.action === 'redact' && result.pii.hasPII) {
      if (req.body.content) req.body.content = result.output;
      if (req.body.message) req.body.message = result.output;
      if (req.body.text) req.body.text = result.output;
      if (req.body.prompt) req.body.prompt = result.output;
      if (req.body.query) req.body.query = result.output;
    }

    next();
  };
}

export default torkExpressMiddleware;
