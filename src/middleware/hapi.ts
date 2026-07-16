/**
 * Hapi.js Plugin for Tork Governance
 * @see https://hapi.dev
 */

import { Tork, TorkConfig, GovernanceResult } from '../index';

export interface TorkHapiOptions extends TorkConfig {
  /** Skip governance for certain paths */
  skipPaths?: string[];
  /** Called when content is blocked */
  onBlock?: (result: GovernanceResult, request: any, h: any) => any;
  /** Extract content from request payload */
  extractContent?: (request: any) => string | null;
}

/**
 * Hapi plugin that applies Tork governance to request payloads
 *
 * @example
 * ```typescript
 * import Hapi from '@hapi/hapi';
 * import { torkHapiPlugin } from 'tork-governance/middleware/hapi';
 *
 * const server = Hapi.server({ port: 3000 });
 *
 * await server.register({
 *   plugin: torkHapiPlugin,
 *   options: {
 *     skipPaths: ['/health', '/metrics'],
 *   }
 * });
 *
 * server.route({
 *   method: 'POST',
 *   path: '/chat',
 *   handler: (request, h) => {
 *     // request.app.torkResult contains governance result
 *     // request.payload is already redacted if needed
 *     return { message: request.payload.message };
 *   }
 * });
 * ```
 */
export const torkHapiPlugin = {
  name: 'tork-governance',
  version: '1.0.0',
  register: async (server: any, options: TorkHapiOptions = {}) => {
    const tork = new Tork({
      policyVersion: options.policyVersion,
      defaultAction: options.defaultAction,
      customPatterns: options.customPatterns,
    });

    const skipPaths = options.skipPaths || [];

    const extractContent = options.extractContent || ((request: any) => {
      const payload = request.payload;
      if (!payload) return null;
      if (typeof payload === 'string') return payload;
      if (payload.content) return payload.content;
      if (payload.message) return payload.message;
      if (payload.text) return payload.text;
      if (payload.prompt) return payload.prompt;
      if (payload.query) return payload.query;
      return null;
    });

    const defaultOnBlock = (result: GovernanceResult, _request: any, h: any) => {
      return h.response({
        error: 'Request blocked by governance policy',
        action: result.action,
        receiptId: result.receipt.receiptId,
        piiTypes: result.pii.types,
      }).code(403).takeover();
    };

    const onBlock = options.onBlock || defaultOnBlock;

    // Pre-handler extension for request governance
    server.ext('onPreHandler', async (request: any, h: any) => {
      const path = request.path;

      // Skip specified paths
      if (skipPaths.some((p: string) => path.startsWith(p))) {
        return h.continue;
      }

      // Only process requests with payload
      if (!request.payload) {
        return h.continue;
      }

      const content = extractContent(request);
      if (!content) {
        return h.continue;
      }

      const result = tork.govern(content);
      request.app.torkResult = result;

      // Handle deny action
      if (result.action === 'deny') {
        return onBlock(result, request, h);
      }

      // Replace content with redacted version if needed
      if (result.action === 'redact' && result.pii.hasPII) {
        if (request.payload && typeof request.payload === 'object') {
          if (request.payload.content) request.payload.content = result.output;
          if (request.payload.message) request.payload.message = result.output;
          if (request.payload.text) request.payload.text = result.output;
          if (request.payload.prompt) request.payload.prompt = result.output;
          if (request.payload.query) request.payload.query = result.output;
        }
      }

      return h.continue;
    });

    // Optional: Response governance
    server.ext('onPreResponse', async (request: any, h: any) => {
      const response = request.response;

      // Skip error responses
      if (response.isBoom) {
        return h.continue;
      }

      // Skip if no tork result (path was skipped)
      if (!request.app.torkResult) {
        return h.continue;
      }

      // Only process JSON responses
      const source = response.source;
      if (typeof source === 'object' && source !== null) {
        // Check if response contains content that should be governed
        const content = source.content || source.message || source.text || source.response;
        if (typeof content === 'string') {
          const result = tork.govern(content);

          if (result.action === 'redact' && result.pii.hasPII) {
            const newSource = { ...source };
            if (source.content) newSource.content = result.output;
            if (source.message) newSource.message = result.output;
            if (source.text) newSource.text = result.output;
            if (source.response) newSource.response = result.output;
            return h.response(newSource);
          }
        }
      }

      return h.continue;
    });

    // Decorate request with helper method
    server.decorate('request', 'getTorkResult', function (this: any) {
      return this.app.torkResult;
    });

    server.decorate('request', 'getTorkReceiptId', function (this: any) {
      const result = this.app.torkResult;
      return result?.receipt?.receiptId || null;
    });
  }
};

export default torkHapiPlugin;
