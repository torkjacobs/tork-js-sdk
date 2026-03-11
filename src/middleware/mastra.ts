/**
 * Mastra adapter for Tork Governance
 *
 * Provides governance for the Mastra TypeScript agent framework,
 * including agent wrappers, tool governance, and workflow middleware.
 *
 * @example
 * ```typescript
 * import { TorkMastraAgent, mastraGoverned } from 'tork-governance';
 *
 * const agent = new Agent({ name: 'assistant', model: openai('gpt-4o') });
 * const governed = new TorkMastraAgent(agent);
 *
 * const response = await governed.generate('My email is john@example.com');
 * // PII is automatically redacted before reaching the LLM
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

export interface TorkMastraOptions {
  governInput?: boolean;
  governOutput?: boolean;
  onPIIDetected?: (piiTypes: string[], text: string) => void;
}

export interface MastraGovernanceResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  hasPII: boolean;
  piiTypes: string[];
  receiptId: string;
  timestamp: string;
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

function govern(text: string): MastraGovernanceResult {
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
 * Extract text content from a Mastra agent response
 */
function extractContent(response: any): string | null {
  if (typeof response === 'string') return response;
  if (response?.text) return response.text;
  if (response?.content) return String(response.content);
  if (response?.message) return String(response.message);
  return null;
}

/**
 * Tork Mastra Agent — wraps a Mastra Agent with governance
 *
 * @example
 * ```typescript
 * import { TorkMastraAgent } from 'tork-governance';
 * import { Agent } from '@mastra/core';
 *
 * const agent = new Agent({ name: 'assistant', model: openai('gpt-4o') });
 * const governed = new TorkMastraAgent(agent);
 *
 * const result = await governed.generate('My SSN is 123-45-6789');
 * // SSN is redacted before reaching the model
 * ```
 */
export class TorkMastraAgent {
  private agent: any;
  private options: TorkMastraOptions;
  private _receipts: MastraGovernanceResult[] = [];

  constructor(agent: any, options: TorkMastraOptions = {}) {
    this.agent = agent;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Generate a response with governance applied
   */
  async generate(prompt: string, options?: any): Promise<any> {
    let governedPrompt = prompt;

    // Govern input
    if (this.options.governInput !== false) {
      const result = govern(prompt);
      this._receipts.push(result);
      governedPrompt = result.output;
      if (result.hasPII && this.options.onPIIDetected) {
        this.options.onPIIDetected(result.piiTypes, prompt);
      }
    }

    // Call the agent
    const response = await this.agent.generate(governedPrompt, options);

    // Govern output
    if (this.options.governOutput !== false) {
      const outputText = extractContent(response);
      if (outputText) {
        const result = govern(outputText);
        this._receipts.push(result);
        if (typeof response === 'string') return result.output;
        if (response?.text) return { ...response, text: result.output };
        if (response?.content) return { ...response, content: result.output };
      }
    }

    return response;
  }

  /**
   * Stream a response with governance applied to each chunk
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
      const response = await this.generate(governedPrompt, options);
      yield typeof response === 'string' ? response : extractContent(response) || String(response);
    }
  }

  /** Access governance receipts */
  get receipts(): MastraGovernanceResult[] {
    return this._receipts;
  }
}

/**
 * Tork Mastra Tool Wrapper — wraps individual tools with governance
 *
 * @example
 * ```typescript
 * import { TorkMastraToolWrapper } from 'tork-governance';
 *
 * const wrapper = new TorkMastraToolWrapper();
 * const governedTool = wrapper.wrap(myTool);
 * ```
 */
export class TorkMastraToolWrapper {
  private options: TorkMastraOptions;
  private _receipts: MastraGovernanceResult[] = [];

  constructor(options: TorkMastraOptions = {}) {
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
      // Govern string arguments
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

      // Govern output
      if (self.options.governOutput !== false && typeof output === 'string') {
        const result = govern(output);
        self._receipts.push(result);
        return result.output;
      }

      return output;
    } as unknown as T;
    return wrapped;
  }

  /** Access governance receipts */
  get receipts(): MastraGovernanceResult[] {
    return this._receipts;
  }
}

/**
 * Middleware for Mastra workflow steps — governs input/output at each step
 *
 * @example
 * ```typescript
 * import { governMastraWorkflow } from 'tork-governance';
 *
 * const governedStep = governMastraWorkflow(async (ctx) => {
 *   return { result: 'some output' };
 * });
 * ```
 */
export function governMastraWorkflow<T extends (...args: any[]) => any>(
  stepFn: T,
  options: TorkMastraOptions = {},
): T {
  const opts: TorkMastraOptions = { governInput: true, governOutput: true, ...options };
  const receipts: MastraGovernanceResult[] = [];

  const wrapped = async function (this: any, ...args: any[]): Promise<any> {
    // Govern string fields in context/input
    if (opts.governInput !== false) {
      for (let i = 0; i < args.length; i++) {
        if (typeof args[i] === 'string') {
          const result = govern(args[i]);
          receipts.push(result);
          args[i] = result.output;
        } else if (typeof args[i] === 'object' && args[i] !== null) {
          for (const key of Object.keys(args[i])) {
            if (typeof args[i][key] === 'string') {
              const result = govern(args[i][key]);
              receipts.push(result);
              args[i][key] = result.output;
            }
          }
        }
      }
    }

    const output = await stepFn.apply(this, args);

    // Govern string fields in output
    if (opts.governOutput !== false && typeof output === 'object' && output !== null) {
      for (const key of Object.keys(output)) {
        if (typeof output[key] === 'string') {
          const result = govern(output[key]);
          receipts.push(result);
          output[key] = result.output;
        }
      }
    } else if (opts.governOutput !== false && typeof output === 'string') {
      const result = govern(output);
      receipts.push(result);
      return result.output;
    }

    return output;
  } as unknown as T;

  (wrapped as any).receipts = receipts;
  return wrapped;
}

/**
 * Decorator/wrapper for agent.generate() calls with governance
 *
 * @example
 * ```typescript
 * import { mastraGoverned } from 'tork-governance';
 *
 * const governed = mastraGoverned(async (prompt: string) => {
 *   return agent.generate(prompt);
 * });
 *
 * const result = await governed('My email is test@example.com');
 * ```
 */
export function mastraGoverned<T extends (...args: any[]) => any>(
  fn: T,
  options: TorkMastraOptions = {},
): T {
  const opts: TorkMastraOptions = { governInput: true, governOutput: true, ...options };
  const receipts: MastraGovernanceResult[] = [];

  const wrapped = async function (this: any, ...args: any[]): Promise<any> {
    // Govern first string argument (prompt)
    if (opts.governInput !== false && args.length > 0 && typeof args[0] === 'string') {
      const result = govern(args[0]);
      receipts.push(result);
      args[0] = result.output;
      if (result.hasPII && opts.onPIIDetected) {
        opts.onPIIDetected(result.piiTypes, args[0]);
      }
    }

    const output = await fn.apply(this, args);

    // Govern output
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
