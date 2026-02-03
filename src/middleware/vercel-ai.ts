/**
 * Vercel AI SDK middleware for Tork Governance
 *
 * Provides streaming middleware and message governance for
 * useChat, useCompletion, and streamText patterns.
 */

// PII patterns for governance
const PII_PATTERNS: Record<string, { pattern: RegExp; redaction: string }> = {
  ssn: { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, redaction: '[SSN_REDACTED]' },
  email: { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, redaction: '[EMAIL_REDACTED]' },
  phone: { pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, redaction: '[PHONE_REDACTED]' },
  creditCard: { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, redaction: '[CARD_REDACTED]' },
};

export interface GovernResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  hasPII: boolean;
  piiTypes: string[];
  receiptId: string;
}

export interface VercelAIMessage {
  role: 'user' | 'assistant' | 'system' | 'function' | 'tool';
  content: string;
  id?: string;
  name?: string;
}

export interface TorkVercelAIOptions {
  governInput?: boolean;
  governOutput?: boolean;
  onBlock?: (result: GovernResult) => void;
}

/**
 * Govern text content
 */
function govern(input: string): GovernResult {
  let output = input;
  let hasPII = false;
  const piiTypes: string[] = [];

  for (const [type, config] of Object.entries(PII_PATTERNS)) {
    if (config.pattern.test(input)) {
      hasPII = true;
      piiTypes.push(type);
      output = output.replace(new RegExp(config.pattern.source, 'g'), config.redaction);
    }
  }

  return {
    action: hasPII ? 'redact' : 'allow',
    output,
    hasPII,
    piiTypes,
    receiptId: `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
  };
}

/**
 * Create Vercel AI SDK middleware
 *
 * @example
 * ```typescript
 * import { torkVercelAIMiddleware } from 'tork-governance/middleware/vercel-ai';
 *
 * const tork = torkVercelAIMiddleware();
 *
 * // In API route
 * export async function POST(req: Request) {
 *   const { messages } = await req.json();
 *   const governedMessages = tork.governMessages(messages);
 *
 *   const result = await streamText({
 *     model: openai('gpt-4'),
 *     messages: governedMessages,
 *   });
 *
 *   return result.toDataStreamResponse();
 * }
 * ```
 */
export function torkVercelAIMiddleware(options: TorkVercelAIOptions = {}) {
  const governInput = options.governInput ?? true;
  const governOutput = options.governOutput ?? true;
  const receipts: GovernResult[] = [];

  return {
    /**
     * Govern an array of messages (for useChat)
     */
    governMessages(messages: VercelAIMessage[]): VercelAIMessage[] {
      if (!governInput) return messages;

      return messages.map((msg) => {
        if (typeof msg.content === 'string') {
          const result = govern(msg.content);
          receipts.push(result);
          return { ...msg, content: result.output };
        }
        return msg;
      });
    },

    /**
     * Govern a single prompt (for useCompletion)
     */
    governPrompt(prompt: string): string {
      if (!governInput) return prompt;

      const result = govern(prompt);
      receipts.push(result);
      return result.output;
    },

    /**
     * Wrap a streaming response with governance
     */
    wrapStream(stream: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
      if (!governOutput) return stream;

      const reader = stream.getReader();
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      let buffer = '';

      return new ReadableStream({
        async pull(controller) {
          const { done, value } = await reader.read();

          if (done) {
            // Process any remaining buffer
            if (buffer) {
              const result = govern(buffer);
              receipts.push(result);
              controller.enqueue(encoder.encode(result.output));
            }
            controller.close();
            return;
          }

          // Decode and accumulate
          buffer += decoder.decode(value, { stream: true });

          // Process complete chunks (on newlines or data boundaries)
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.trim()) {
              const result = govern(line);
              receipts.push(result);
              controller.enqueue(encoder.encode(result.output + '\n'));
            } else {
              controller.enqueue(encoder.encode('\n'));
            }
          }
        },
      });
    },

    /**
     * Create a TransformStream for streaming responses
     */
    createTransformStream(): TransformStream<Uint8Array, Uint8Array> {
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();

      return new TransformStream({
        transform(chunk, controller) {
          if (!governOutput) {
            controller.enqueue(chunk);
            return;
          }

          const text = decoder.decode(chunk, { stream: true });
          const result = govern(text);
          receipts.push(result);
          controller.enqueue(encoder.encode(result.output));
        },
      });
    },

    /**
     * Govern text content directly
     */
    govern(text: string): GovernResult {
      const result = govern(text);
      receipts.push(result);
      return result;
    },

    /**
     * Get all governance receipts
     */
    getReceipts(): GovernResult[] {
      return [...receipts];
    },

    /**
     * Clear receipts
     */
    clearReceipts(): void {
      receipts.length = 0;
    },
  };
}

/**
 * Middleware for Next.js API routes with Vercel AI SDK
 *
 * @example
 * ```typescript
 * import { withTorkVercelAI } from 'tork-governance/middleware/vercel-ai';
 *
 * export const POST = withTorkVercelAI(async (req, tork) => {
 *   const { messages } = await req.json();
 *   const governedMessages = tork.governMessages(messages);
 *   // ... rest of handler
 * });
 * ```
 */
export function withTorkVercelAI(
  handler: (
    req: Request,
    tork: ReturnType<typeof torkVercelAIMiddleware>
  ) => Promise<Response>,
  options?: TorkVercelAIOptions
) {
  const tork = torkVercelAIMiddleware(options);

  return async (req: Request): Promise<Response> => {
    return handler(req, tork);
  };
}

/**
 * Hook wrapper for client-side useChat
 *
 * @example
 * ```typescript
 * import { useChat } from 'ai/react';
 * import { createGovernedChat } from 'tork-governance/middleware/vercel-ai';
 *
 * const { messages, input, handleSubmit } = createGovernedChat(useChat, {
 *   api: '/api/chat',
 * });
 * ```
 */
export function createGovernedChat<T extends (...args: any[]) => any>(
  useChat: T,
  options: Parameters<T>[0]
): ReturnType<T> {
  const tork = torkVercelAIMiddleware();

  const modifiedOptions = {
    ...options,
    onFinish: (message: VercelAIMessage) => {
      // Govern the final message
      const governed = tork.governMessages([message]);
      options?.onFinish?.(governed[0]);
    },
  };

  return useChat(modifiedOptions);
}

export default torkVercelAIMiddleware;
