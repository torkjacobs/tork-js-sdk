/**
 * Fastify Plugin for Tork Governance
 */

import { Tork, TorkConfig, GovernanceResult } from '../index';

export interface TorkFastifyOptions extends TorkConfig {
  /** Extract content from request body */
  extractContent?: (request: any) => string | null;
  /** Skip governance for certain routes */
  skip?: (request: any) => boolean;
}

// Note: When using with Fastify, the torkResult will be available on request
// Type: request.torkResult?: GovernanceResult

/**
 * Fastify plugin that applies Tork governance to request bodies
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { torkFastifyPlugin } from 'tork-governance/middleware/fastify';
 *
 * const fastify = Fastify();
 * fastify.register(torkFastifyPlugin);
 *
 * fastify.post('/chat', async (request, reply) => {
 *   // request.torkResult contains governance result
 *   return { message: request.body.message };
 * });
 * ```
 */
export async function torkFastifyPlugin(fastify: any, options: TorkFastifyOptions = {}) {
  const tork = new Tork({
    policyVersion: options.policyVersion,
    defaultAction: options.defaultAction,
    customPatterns: options.customPatterns,
  });

  const extractContent = options.extractContent || ((request: any) => {
    const body = request.body;
    if (!body) return null;
    if (typeof body === 'string') return body;
    if (body.content) return body.content;
    if (body.message) return body.message;
    if (body.text) return body.text;
    if (body.prompt) return body.prompt;
    return null;
  });

  const skip = options.skip || (() => false);

  fastify.addHook('preHandler', async (request: any, reply: any) => {
    if (skip(request)) {
      return;
    }

    const content = extractContent(request);

    if (!content) {
      return;
    }

    const result = tork.govern(content);
    request.torkResult = result;

    if (result.action === 'deny') {
      reply.code(403).send({
        error: 'Request blocked by governance policy',
        action: result.action,
        receiptId: result.receipt.receiptId,
        piiTypes: result.pii.types,
      });
      return;
    }

    // Replace content with redacted version if needed
    if (result.action === 'redact' && result.pii.hasPII && request.body) {
      if (request.body.content) request.body.content = result.output;
      if (request.body.message) request.body.message = result.output;
      if (request.body.text) request.body.text = result.output;
      if (request.body.prompt) request.body.prompt = result.output;
    }
  });
}

export default torkFastifyPlugin;
