/**
 * OpenAI SDK adapter for Tork Governance
 *
 * Provides governance for chat completions, completions, and embeddings
 * with automatic PII detection and redaction.
 *
 * @example
 * ```typescript
 * import { TorkOpenAIClient, governChatCompletion } from 'tork-governance';
 * import OpenAI from 'openai';
 *
 * const openai = new OpenAI();
 * const torkClient = new TorkOpenAIClient(openai);
 *
 * // Governed chat completion
 * const response = await torkClient.governChatCompletion({
 *   model: 'gpt-4',
 *   messages: [{ role: 'user', content: 'My email is john@example.com' }],
 * });
 *
 * // Or use standalone function
 * const result = await governChatCompletion(openai, params);
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

export interface TorkOpenAIOptions {
  governInput?: boolean;
  governOutput?: boolean;
  onPIIDetected?: (piiTypes: string[], text: string) => void;
}

export interface OpenAIGovernanceResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  hasPII: boolean;
  piiTypes: string[];
  receiptId: string;
  timestamp: string;
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'function' | 'tool';
  content: string | null;
  name?: string;
  function_call?: any;
  tool_calls?: any[];
}

export interface ChatCompletionParams {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
  [key: string]: any;
}

export interface CompletionParams {
  model: string;
  prompt: string | string[];
  temperature?: number;
  max_tokens?: number;
  [key: string]: any;
}

export interface EmbeddingParams {
  model: string;
  input: string | string[];
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
function govern(text: string): OpenAIGovernanceResult {
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
 * Govern chat messages
 */
function governMessages(messages: ChatMessage[]): { messages: ChatMessage[]; receipts: OpenAIGovernanceResult[] } {
  const receipts: OpenAIGovernanceResult[] = [];
  const governedMessages = messages.map(msg => {
    if (msg.content && typeof msg.content === 'string') {
      const result = govern(msg.content);
      receipts.push(result);
      return { ...msg, content: result.output };
    }
    return msg;
  });
  return { messages: governedMessages, receipts };
}

/**
 * Tork OpenAI Client - Wraps OpenAI client with governance
 */
export class TorkOpenAIClient {
  private client: any;
  private options: TorkOpenAIOptions;
  private receipts: OpenAIGovernanceResult[] = [];

  constructor(client: any, options: TorkOpenAIOptions = {}) {
    this.client = client;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Govern chat completion request
   */
  async governChatCompletion(params: ChatCompletionParams): Promise<any> {
    let governedParams = { ...params };

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
      return this.governStreamingChatCompletion(governedParams);
    }

    // Call OpenAI
    const response = await this.client.chat.completions.create(governedParams);

    // Govern output
    if (this.options.governOutput !== false && response.choices) {
      response.choices = response.choices.map((choice: any) => {
        if (choice.message?.content) {
          const result = govern(choice.message.content);
          this.receipts.push(result);
          return {
            ...choice,
            message: { ...choice.message, content: result.output },
          };
        }
        return choice;
      });
    }

    return response;
  }

  /**
   * Handle streaming chat completion with governance
   */
  private async governStreamingChatCompletion(params: ChatCompletionParams): Promise<AsyncIterable<any>> {
    const stream = await this.client.chat.completions.create(params);
    const self = this;

    async function* governedStream() {
      let buffer = '';

      for await (const chunk of stream) {
        if (chunk.choices?.[0]?.delta?.content) {
          const content = chunk.choices[0].delta.content;
          buffer += content;

          // Check for PII patterns in accumulated buffer
          if (self.options.governOutput !== false) {
            const result = govern(buffer);
            if (result.hasPII) {
              // Redact the delta content
              const redactedContent = redactPII(content);
              chunk.choices[0].delta.content = redactedContent;
            }
          }
        }
        yield chunk;
      }

      // Final governance check on complete buffer
      if (buffer && self.options.governOutput !== false) {
        const finalResult = govern(buffer);
        self.receipts.push(finalResult);
      }
    }

    return governedStream();
  }

  /**
   * Govern completion request (legacy completions API)
   */
  async governCompletion(params: CompletionParams): Promise<any> {
    let governedParams = { ...params };

    // Govern input prompt(s)
    if (this.options.governInput !== false) {
      if (typeof params.prompt === 'string') {
        const result = govern(params.prompt);
        governedParams.prompt = result.output;
        this.receipts.push(result);
        if (result.hasPII && this.options.onPIIDetected) {
          this.options.onPIIDetected(result.piiTypes, result.output);
        }
      } else if (Array.isArray(params.prompt)) {
        governedParams.prompt = params.prompt.map(p => {
          const result = govern(p);
          this.receipts.push(result);
          if (result.hasPII && this.options.onPIIDetected) {
            this.options.onPIIDetected(result.piiTypes, result.output);
          }
          return result.output;
        });
      }
    }

    // Call OpenAI
    const response = await this.client.completions.create(governedParams);

    // Govern output
    if (this.options.governOutput !== false && response.choices) {
      response.choices = response.choices.map((choice: any) => {
        if (choice.text) {
          const result = govern(choice.text);
          this.receipts.push(result);
          return { ...choice, text: result.output };
        }
        return choice;
      });
    }

    return response;
  }

  /**
   * Govern embedding request
   */
  async governEmbedding(params: EmbeddingParams): Promise<any> {
    let governedParams = { ...params };

    // Govern input text(s)
    if (this.options.governInput !== false) {
      if (typeof params.input === 'string') {
        const result = govern(params.input);
        governedParams.input = result.output;
        this.receipts.push(result);
        if (result.hasPII && this.options.onPIIDetected) {
          this.options.onPIIDetected(result.piiTypes, result.output);
        }
      } else if (Array.isArray(params.input)) {
        governedParams.input = params.input.map(i => {
          const result = govern(i);
          this.receipts.push(result);
          if (result.hasPII && this.options.onPIIDetected) {
            this.options.onPIIDetected(result.piiTypes, result.output);
          }
          return result.output;
        });
      }
    }

    // Call OpenAI embeddings API
    return this.client.embeddings.create(governedParams);
  }

  /**
   * Get governance receipts
   */
  getReceipts(): OpenAIGovernanceResult[] {
    return [...this.receipts];
  }

  /**
   * Clear receipts
   */
  clearReceipts(): void {
    this.receipts = [];
  }

  /**
   * Get underlying OpenAI client
   */
  getClient(): any {
    return this.client;
  }
}

/**
 * Standalone function to govern chat completion
 */
export async function governChatCompletion(
  client: any,
  params: ChatCompletionParams,
  options: TorkOpenAIOptions = {}
): Promise<{ response: any; receipts: OpenAIGovernanceResult[] }> {
  const torkClient = new TorkOpenAIClient(client, options);
  const response = await torkClient.governChatCompletion(params);
  return { response, receipts: torkClient.getReceipts() };
}

/**
 * Standalone function to govern completion
 */
export async function governCompletion(
  client: any,
  params: CompletionParams,
  options: TorkOpenAIOptions = {}
): Promise<{ response: any; receipts: OpenAIGovernanceResult[] }> {
  const torkClient = new TorkOpenAIClient(client, options);
  const response = await torkClient.governCompletion(params);
  return { response, receipts: torkClient.getReceipts() };
}

/**
 * Standalone function to govern embedding
 */
export async function governEmbedding(
  client: any,
  params: EmbeddingParams,
  options: TorkOpenAIOptions = {}
): Promise<{ response: any; receipts: OpenAIGovernanceResult[] }> {
  const torkClient = new TorkOpenAIClient(client, options);
  const response = await torkClient.governEmbedding(params);
  return { response, receipts: torkClient.getReceipts() };
}

/**
 * Decorator to add governance to OpenAI functions
 *
 * @example
 * ```typescript
 * const governedChat = openaiGoverned(async (client, messages) => {
 *   return client.chat.completions.create({ model: 'gpt-4', messages });
 * });
 * ```
 */
export function openaiGoverned<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  options: TorkOpenAIOptions = {}
): T {
  const governInput = options.governInput ?? true;
  const governOutput = options.governOutput ?? true;

  return (async (...args: any[]) => {
    // Govern string arguments
    if (governInput) {
      args = args.map(arg => {
        if (typeof arg === 'string') {
          return govern(arg).output;
        }
        if (Array.isArray(arg)) {
          return arg.map(item => {
            if (typeof item === 'string') return govern(item).output;
            if (item?.content && typeof item.content === 'string') {
              return { ...item, content: govern(item.content).output };
            }
            return item;
          });
        }
        if (arg?.messages && Array.isArray(arg.messages)) {
          return { ...arg, messages: governMessages(arg.messages).messages };
        }
        return arg;
      });
    }

    // Call original function
    let result = await fn(...args);

    // Govern output
    if (governOutput && result) {
      if (result.choices) {
        result.choices = result.choices.map((choice: any) => {
          if (choice.message?.content) {
            return { ...choice, message: { ...choice.message, content: govern(choice.message.content).output } };
          }
          if (choice.text) {
            return { ...choice, text: govern(choice.text).output };
          }
          return choice;
        });
      }
    }

    return result;
  }) as T;
}

export default TorkOpenAIClient;
