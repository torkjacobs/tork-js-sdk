/**
 * Microsoft Agent Framework adapter for Tork Governance
 *
 * Provides governance for Microsoft's Agent Framework (merging AutoGen + Semantic Kernel).
 * Supports A2A, MCP, AG-UI patterns with multi-agent conversations.
 *
 * @example
 * ```typescript
 * import { TorkMicrosoftAgent, governAgentChat } from 'tork-governance';
 *
 * const agent = new ChatCompletionAgent({ name: 'assistant', model: 'gpt-4o' });
 * const governed = new TorkMicrosoftAgent(agent);
 *
 * const response = await governed.invoke('My email is john@example.com');
 * // PII is automatically redacted
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

export interface TorkMicrosoftAgentOptions {
  governInput?: boolean;
  governOutput?: boolean;
  onPIIDetected?: (piiTypes: string[], text: string) => void;
}

export interface MicrosoftAgentGovernanceResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  hasPII: boolean;
  piiTypes: string[];
  receiptId: string;
  timestamp: string;
}

export interface AgentMessage {
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string | null;
  name?: string;
  toolCalls?: any[];
  toolCallId?: string;
}

function generateReceiptId(): string {
  return `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

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

function redactPII(text: string): string {
  let result = text;
  for (const { pattern, redaction } of Object.values(PII_PATTERNS)) {
    result = result.replace(new RegExp(pattern.source, pattern.flags), redaction);
  }
  return result;
}

function govern(text: string): MicrosoftAgentGovernanceResult {
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
 * Govern an array of agent messages
 */
function governMessages(messages: AgentMessage[]): { messages: AgentMessage[]; receipts: MicrosoftAgentGovernanceResult[] } {
  const receipts: MicrosoftAgentGovernanceResult[] = [];
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
 * Extract text content from a Microsoft Agent response
 */
function extractContent(response: any): string | null {
  if (typeof response === 'string') return response;
  if (response?.content) return String(response.content);
  if (response?.text) return response.text;
  if (response?.message?.content) return String(response.message.content);
  if (response?.choices?.[0]?.message?.content) return String(response.choices[0].message.content);
  return null;
}

/**
 * Tork Microsoft Agent — wraps a Microsoft Agent Framework agent with governance
 *
 * @example
 * ```typescript
 * import { TorkMicrosoftAgent } from 'tork-governance';
 *
 * const agent = new ChatCompletionAgent({ name: 'assistant' });
 * const governed = new TorkMicrosoftAgent(agent);
 *
 * const result = await governed.invoke('My SSN is 123-45-6789');
 * // SSN is redacted before reaching the model
 * ```
 */
export class TorkMicrosoftAgent {
  private agent: any;
  private options: TorkMicrosoftAgentOptions;
  private _receipts: MicrosoftAgentGovernanceResult[] = [];

  constructor(agent: any, options: TorkMicrosoftAgentOptions = {}) {
    this.agent = agent;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Invoke the agent with governance applied
   */
  async invoke(prompt: string, options?: any): Promise<any> {
    let governedPrompt = prompt;

    if (this.options.governInput !== false) {
      const result = govern(prompt);
      this._receipts.push(result);
      governedPrompt = result.output;
      if (result.hasPII && this.options.onPIIDetected) {
        this.options.onPIIDetected(result.piiTypes, prompt);
      }
    }

    const response = this.agent.invoke
      ? await this.agent.invoke(governedPrompt, options)
      : await this.agent(governedPrompt, options);

    if (this.options.governOutput !== false) {
      const outputText = extractContent(response);
      if (outputText) {
        const result = govern(outputText);
        this._receipts.push(result);
        if (typeof response === 'string') return result.output;
        if (response?.content) return { ...response, content: result.output };
        if (response?.text) return { ...response, text: result.output };
        if (response?.message?.content) {
          return { ...response, message: { ...response.message, content: result.output } };
        }
      }
    }

    return response;
  }

  /**
   * Chat with the agent using a message array
   */
  async chat(messages: AgentMessage[], options?: any): Promise<any> {
    let governedMessages = messages;

    if (this.options.governInput !== false) {
      const { messages: governed, receipts } = governMessages(messages);
      governedMessages = governed;
      this._receipts.push(...receipts);
      receipts.forEach(r => {
        if (r.hasPII && this.options.onPIIDetected) {
          this.options.onPIIDetected(r.piiTypes, r.output);
        }
      });
    }

    const response = this.agent.chat
      ? await this.agent.chat(governedMessages, options)
      : await this.agent.invoke(governedMessages, options);

    if (this.options.governOutput !== false) {
      const outputText = extractContent(response);
      if (outputText) {
        const result = govern(outputText);
        this._receipts.push(result);
        if (typeof response === 'string') return result.output;
        if (response?.content) return { ...response, content: result.output };
      }
    }

    return response;
  }

  /**
   * Stream response with governance applied to each chunk
   */
  async *stream(prompt: string, options?: any): AsyncGenerator<string> {
    let governedPrompt = prompt;

    if (this.options.governInput !== false) {
      const result = govern(prompt);
      this._receipts.push(result);
      governedPrompt = result.output;
    }

    if (this.agent.stream) {
      for await (const chunk of this.agent.stream(governedPrompt, options)) {
        if (this.options.governOutput !== false) {
          const text = typeof chunk === 'string' ? chunk : extractContent(chunk) || String(chunk);
          const result = govern(text);
          this._receipts.push(result);
          yield result.output;
        } else {
          yield chunk;
        }
      }
    } else {
      const response = await this.invoke(governedPrompt, options);
      yield typeof response === 'string' ? response : extractContent(response) || String(response);
    }
  }

  /** Access governance receipts */
  get receipts(): MicrosoftAgentGovernanceResult[] {
    return this._receipts;
  }
}

/**
 * Tork Microsoft Tool Wrapper — wraps tools with governance
 *
 * @example
 * ```typescript
 * import { TorkMicrosoftToolWrapper } from 'tork-governance';
 *
 * const wrapper = new TorkMicrosoftToolWrapper();
 * const governedTool = wrapper.wrap(myToolFn);
 * ```
 */
export class TorkMicrosoftToolWrapper {
  private options: TorkMicrosoftAgentOptions;
  private _receipts: MicrosoftAgentGovernanceResult[] = [];

  constructor(options: TorkMicrosoftAgentOptions = {}) {
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Wrap a tool function with governance
   */
  wrap<T extends (...args: any[]) => any>(fn: T): T {
    const self = this;
    const wrapped = async function (this: any, ...args: any[]): Promise<any> {
      if (self.options.governInput !== false) {
        for (let i = 0; i < args.length; i++) {
          if (typeof args[i] === 'string') {
            const result = govern(args[i]);
            self._receipts.push(result);
            args[i] = result.output;
          } else if (typeof args[i] === 'object' && args[i] !== null) {
            for (const key of Object.keys(args[i])) {
              if (typeof args[i][key] === 'string') {
                const result = govern(args[i][key]);
                self._receipts.push(result);
                args[i][key] = result.output;
              }
            }
          }
        }
      }

      const output = await fn.apply(this, args);

      if (self.options.governOutput !== false && typeof output === 'string') {
        const result = govern(output);
        self._receipts.push(result);
        return result.output;
      }

      return output;
    } as unknown as T;
    return wrapped;
  }

  /**
   * Govern tool call arguments
   */
  governToolArgs(toolName: string, args: Record<string, any>): Record<string, any> {
    const governed: Record<string, any> = {};
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === 'string') {
        const result = govern(value);
        this._receipts.push(result);
        governed[key] = result.output;
      } else {
        governed[key] = value;
      }
    }
    return governed;
  }

  /**
   * Govern tool result
   */
  governToolResult(result: any): any {
    if (typeof result === 'string') {
      const govResult = govern(result);
      this._receipts.push(govResult);
      return govResult.output;
    }
    return result;
  }

  /** Access governance receipts */
  get receipts(): MicrosoftAgentGovernanceResult[] {
    return this._receipts;
  }
}

/**
 * Middleware for multi-agent chat sessions
 *
 * @example
 * ```typescript
 * import { governAgentChat } from 'tork-governance';
 *
 * const governed = governAgentChat(async (messages) => {
 *   return agentChat.invoke(messages);
 * });
 *
 * const result = await governed([
 *   { role: 'user', content: 'My email is test@example.com' }
 * ]);
 * ```
 */
export function governAgentChat<T extends (...args: any[]) => any>(
  fn: T,
  options: TorkMicrosoftAgentOptions = {},
): T {
  const opts: TorkMicrosoftAgentOptions = { governInput: true, governOutput: true, ...options };
  const receipts: MicrosoftAgentGovernanceResult[] = [];

  const wrapped = async function (this: any, ...args: any[]): Promise<any> {
    // Govern message arrays
    if (opts.governInput !== false && Array.isArray(args[0])) {
      const { messages, receipts: msgReceipts } = governMessages(args[0]);
      args[0] = messages;
      receipts.push(...msgReceipts);
    } else if (opts.governInput !== false && typeof args[0] === 'string') {
      const result = govern(args[0]);
      receipts.push(result);
      args[0] = result.output;
    }

    const output = await fn.apply(this, args);

    if (opts.governOutput !== false) {
      const text = typeof output === 'string' ? output : extractContent(output);
      if (text) {
        const result = govern(text);
        receipts.push(result);
        if (typeof output === 'string') return result.output;
        return result.output;
      }
    }

    return output;
  } as unknown as T;

  (wrapped as any).receipts = receipts;
  return wrapped;
}

/**
 * Decorator for agent invocations with governance
 *
 * @example
 * ```typescript
 * import { microsoftAgentGoverned } from 'tork-governance';
 *
 * const governed = microsoftAgentGoverned(async (prompt: string) => {
 *   return agent.invoke(prompt);
 * });
 *
 * const result = await governed('My SSN is 123-45-6789');
 * ```
 */
export function microsoftAgentGoverned<T extends (...args: any[]) => any>(
  fn: T,
  options: TorkMicrosoftAgentOptions = {},
): T {
  const opts: TorkMicrosoftAgentOptions = { governInput: true, governOutput: true, ...options };
  const receipts: MicrosoftAgentGovernanceResult[] = [];

  const wrapped = async function (this: any, ...args: any[]): Promise<any> {
    if (opts.governInput !== false && args.length > 0 && typeof args[0] === 'string') {
      const result = govern(args[0]);
      receipts.push(result);
      args[0] = result.output;
      if (result.hasPII && opts.onPIIDetected) {
        opts.onPIIDetected(result.piiTypes, args[0]);
      }
    }

    const output = await fn.apply(this, args);

    if (opts.governOutput !== false) {
      const text = typeof output === 'string' ? output : extractContent(output);
      if (text) {
        const result = govern(text);
        receipts.push(result);
        if (typeof output === 'string') return result.output;
        return result.output;
      }
    }

    return output;
  } as unknown as T;

  (wrapped as any).receipts = receipts;
  return wrapped;
}
