/**
 * Anthropic SDK adapter for Tork Governance
 *
 * Provides governance for Claude messages API with automatic
 * PII detection and redaction.
 *
 * @example
 * ```typescript
 * import { TorkAnthropicClient, governMessage } from 'tork-governance';
 * import Anthropic from '@anthropic-ai/sdk';
 *
 * const anthropic = new Anthropic();
 * const torkClient = new TorkAnthropicClient(anthropic);
 *
 * // Governed message
 * const response = await torkClient.governMessage({
 *   model: 'claude-3-opus-20240229',
 *   max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'My SSN is 123-45-6789' }],
 * });
 *
 * // Or use standalone function
 * const result = await governMessage(anthropic, params);
 * ```
 */

// PII patterns for governance
const PII_PATTERNS: Record<string, { pattern: RegExp; redaction: string }> = {
  ssn: { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, redaction: '[SSN_REDACTED]' },
  email: { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, redaction: '[EMAIL_REDACTED]' },
  phone: { pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, redaction: '[PHONE_REDACTED]' },
  creditCard: { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, redaction: '[CARD_REDACTED]' },
  ipAddress: { pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, redaction: '[IP_REDACTED]' },
};

export interface TorkAnthropicOptions {
  governInput?: boolean;
  governOutput?: boolean;
  onPIIDetected?: (piiTypes: string[], text: string) => void;
}

export interface AnthropicGovernanceResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  hasPII: boolean;
  piiTypes: string[];
  receiptId: string;
  timestamp: string;
}

export interface ContentBlock {
  type: 'text' | 'image' | 'tool_use' | 'tool_result';
  text?: string;
  source?: any;
  id?: string;
  name?: string;
  input?: any;
  tool_use_id?: string;
  content?: string | ContentBlock[];
}

export interface AnthropicMessage {
  role: 'user' | 'assistant';
  content: string | ContentBlock[];
}

export interface MessageParams {
  model: string;
  max_tokens: number;
  messages: AnthropicMessage[];
  system?: string;
  temperature?: number;
  stream?: boolean;
  [key: string]: any;
}

/**
 * Generate receipt ID
 */
function generateReceiptId(): string {
  return `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Detect PII in text
 */
function detectPII(text: string): { type: string; match: string }[] {
  const found: { type: string; match: string }[] = [];
  for (const [type, { pattern }] of Object.entries(PII_PATTERNS)) {
    const matches = text.match(new RegExp(pattern.source, pattern.flags));
    if (matches) {
      matches.forEach(match => found.push({ type, match }));
    }
  }
  return found;
}

/**
 * Redact PII from text
 */
function redactPII(text: string): string {
  let result = text;
  for (const { pattern, redaction } of Object.values(PII_PATTERNS)) {
    result = result.replace(new RegExp(pattern.source, pattern.flags), redaction);
  }
  return result;
}

/**
 * Govern text content
 */
function govern(text: string): AnthropicGovernanceResult {
  const piiFound = detectPII(text);
  const hasPII = piiFound.length > 0;

  return {
    action: hasPII ? 'redact' : 'allow',
    output: hasPII ? redactPII(text) : text,
    hasPII,
    piiTypes: [...new Set(piiFound.map(p => p.type))],
    receiptId: generateReceiptId(),
    timestamp: new Date().toISOString(),
  };
}

/**
 * Govern content blocks (handles Anthropic's content block format)
 */
function governContentBlocks(content: ContentBlock[]): { blocks: ContentBlock[]; receipts: AnthropicGovernanceResult[] } {
  const receipts: AnthropicGovernanceResult[] = [];
  const governedBlocks = content.map(block => {
    if (block.type === 'text' && block.text) {
      const result = govern(block.text);
      receipts.push(result);
      return { ...block, text: result.output };
    }
    if (block.type === 'tool_result' && block.content) {
      if (typeof block.content === 'string') {
        const result = govern(block.content);
        receipts.push(result);
        return { ...block, content: result.output };
      }
      if (Array.isArray(block.content)) {
        const { blocks, receipts: blockReceipts } = governContentBlocks(block.content);
        receipts.push(...blockReceipts);
        return { ...block, content: blocks };
      }
    }
    return block;
  });
  return { blocks: governedBlocks, receipts };
}

/**
 * Govern Anthropic messages
 */
function governMessages(messages: AnthropicMessage[]): { messages: AnthropicMessage[]; receipts: AnthropicGovernanceResult[] } {
  const receipts: AnthropicGovernanceResult[] = [];
  const governedMessages = messages.map(msg => {
    if (typeof msg.content === 'string') {
      const result = govern(msg.content);
      receipts.push(result);
      return { ...msg, content: result.output };
    }
    if (Array.isArray(msg.content)) {
      const { blocks, receipts: blockReceipts } = governContentBlocks(msg.content);
      receipts.push(...blockReceipts);
      return { ...msg, content: blocks };
    }
    return msg;
  });
  return { messages: governedMessages, receipts };
}

/**
 * Tork Anthropic Client - Wraps Anthropic client with governance
 */
export class TorkAnthropicClient {
  private client: any;
  private options: TorkAnthropicOptions;
  private receipts: AnthropicGovernanceResult[] = [];

  constructor(client: any, options: TorkAnthropicOptions = {}) {
    this.client = client;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Govern message request (Claude messages API)
   */
  async governMessage(params: MessageParams): Promise<any> {
    let governedParams = { ...params };

    // Govern system prompt
    if (this.options.governInput !== false && params.system) {
      const systemResult = govern(params.system);
      governedParams.system = systemResult.output;
      this.receipts.push(systemResult);
      if (systemResult.hasPII && this.options.onPIIDetected) {
        this.options.onPIIDetected(systemResult.piiTypes, systemResult.output);
      }
    }

    // Govern input messages
    if (this.options.governInput !== false && params.messages) {
      const { messages, receipts } = governMessages(params.messages);
      governedParams.messages = messages;
      this.receipts.push(...receipts);

      // Notify if PII detected
      receipts.forEach(r => {
        if (r.hasPII && this.options.onPIIDetected) {
          this.options.onPIIDetected(r.piiTypes, r.output);
        }
      });
    }

    // Handle streaming
    if (params.stream) {
      return this.governStreamingMessage(governedParams);
    }

    // Call Anthropic
    const response = await this.client.messages.create(governedParams);

    // Govern output content
    if (this.options.governOutput !== false && response.content) {
      if (Array.isArray(response.content)) {
        const { blocks, receipts } = governContentBlocks(response.content);
        response.content = blocks;
        this.receipts.push(...receipts);
      }
    }

    return response;
  }

  /**
   * Handle streaming message with governance
   */
  private async governStreamingMessage(params: MessageParams): Promise<AsyncIterable<any>> {
    const stream = await this.client.messages.create(params);
    const self = this;

    async function* governedStream() {
      let textBuffer = '';

      for await (const event of stream) {
        // Handle content block delta events
        if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
          const text = event.delta.text || '';
          textBuffer += text;

          // Check for PII in accumulated text
          if (self.options.governOutput !== false) {
            const result = govern(textBuffer);
            if (result.hasPII) {
              // Redact the delta text
              event.delta.text = redactPII(text);
            }
          }
        }

        // Handle message stop event
        if (event.type === 'message_stop' && textBuffer && self.options.governOutput !== false) {
          const finalResult = govern(textBuffer);
          self.receipts.push(finalResult);
        }

        yield event;
      }
    }

    return governedStream();
  }

  /**
   * Get governance receipts
   */
  getReceipts(): AnthropicGovernanceResult[] {
    return [...this.receipts];
  }

  /**
   * Clear receipts
   */
  clearReceipts(): void {
    this.receipts = [];
  }

  /**
   * Get underlying Anthropic client
   */
  getClient(): any {
    return this.client;
  }
}

/**
 * Standalone function to govern message
 */
export async function governMessage(
  client: any,
  params: MessageParams,
  options: TorkAnthropicOptions = {}
): Promise<{ response: any; receipts: AnthropicGovernanceResult[] }> {
  const torkClient = new TorkAnthropicClient(client, options);
  const response = await torkClient.governMessage(params);
  return { response, receipts: torkClient.getReceipts() };
}

/**
 * Decorator to add governance to Anthropic functions
 *
 * @example
 * ```typescript
 * const governedMessage = anthropicGoverned(async (client, params) => {
 *   return client.messages.create(params);
 * });
 * ```
 */
export function anthropicGoverned<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  options: TorkAnthropicOptions = {}
): T {
  const governInput = options.governInput ?? true;
  const governOutput = options.governOutput ?? true;

  return (async (...args: any[]) => {
    // Govern string arguments and message arrays
    if (governInput) {
      args = args.map(arg => {
        if (typeof arg === 'string') {
          return govern(arg).output;
        }
        if (arg?.messages && Array.isArray(arg.messages)) {
          const { messages } = governMessages(arg.messages);
          const governed = { ...arg, messages };
          if (arg.system) {
            governed.system = govern(arg.system).output;
          }
          return governed;
        }
        return arg;
      });
    }

    // Call original function
    let result = await fn(...args);

    // Govern output
    if (governOutput && result?.content) {
      if (Array.isArray(result.content)) {
        const { blocks } = governContentBlocks(result.content);
        result = { ...result, content: blocks };
      }
    }

    return result;
  }) as T;
}

export default TorkAnthropicClient;
