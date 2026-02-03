/**
 * LangChain.js adapter for Tork Governance
 *
 * Provides callbacks, chain wrappers, and tools for LangChain.js.
 *
 * @example
 * ```typescript
 * import { ChatOpenAI } from '@langchain/openai';
 * import { TorkCallbackHandler, withTorkGovernance } from 'tork-governance';
 *
 * const chat = new ChatOpenAI();
 * const governedChat = withTorkGovernance(chat);
 *
 * // Or use callback handler
 * const result = await chat.invoke("Hello", {
 *   callbacks: [new TorkCallbackHandler()]
 * });
 * ```
 */

// PII patterns
const PII_PATTERNS: Record<string, { pattern: RegExp; redaction: string }> = {
  ssn: { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, redaction: '[SSN_REDACTED]' },
  email: { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, redaction: '[EMAIL_REDACTED]' },
  phone: { pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, redaction: '[PHONE_REDACTED]' },
  creditCard: { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, redaction: '[CARD_REDACTED]' },
};

export interface TorkLangChainOptions {
  apiKey?: string;
  governInput?: boolean;
  governOutput?: boolean;
  onPIIDetected?: (piiTypes: string[], text: string) => void;
}

export interface GovernanceResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  piiFound: string[];
  receiptId: string;
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

function generateReceiptId(): string {
  return `rcpt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function govern(text: string): GovernanceResult {
  const piiFound = detectPII(text);
  if (piiFound.length === 0) {
    return {
      action: 'allow',
      output: text,
      piiFound: [],
      receiptId: generateReceiptId(),
    };
  }
  return {
    action: 'redact',
    output: redactPII(text),
    piiFound: piiFound.map(p => p.type),
    receiptId: generateReceiptId(),
  };
}

/**
 * LangChain.js callback handler for Tork governance
 */
export class TorkCallbackHandler {
  private options: TorkLangChainOptions;
  private lastResult?: GovernanceResult;

  constructor(options: TorkLangChainOptions = {}) {
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  // Called when LLM starts
  handleLLMStart(llm: any, prompts: string[]): void {
    if (!this.options.governInput) return;

    for (let i = 0; i < prompts.length; i++) {
      const result = govern(prompts[i]);
      if (result.action === 'redact') {
        prompts[i] = result.output;
        this.lastResult = result;
        this.options.onPIIDetected?.(result.piiFound, prompts[i]);
      }
    }
  }

  // Called when LLM ends
  handleLLMEnd(output: any): void {
    if (!this.options.governOutput) return;

    if (output.generations) {
      for (const generation of output.generations) {
        for (const gen of generation) {
          if (gen.text) {
            const result = govern(gen.text);
            if (result.action === 'redact') {
              gen.text = result.output;
              this.lastResult = result;
            }
          }
        }
      }
    }
  }

  // Called when chain starts
  handleChainStart(chain: any, inputs: Record<string, any>): void {
    if (!this.options.governInput) return;

    for (const key of Object.keys(inputs)) {
      if (typeof inputs[key] === 'string') {
        const result = govern(inputs[key]);
        if (result.action === 'redact') {
          inputs[key] = result.output;
          this.lastResult = result;
        }
      }
    }
  }

  // Called when chain ends
  handleChainEnd(outputs: Record<string, any>): void {
    if (!this.options.governOutput) return;

    for (const key of Object.keys(outputs)) {
      if (typeof outputs[key] === 'string') {
        const result = govern(outputs[key]);
        if (result.action === 'redact') {
          outputs[key] = result.output;
          this.lastResult = result;
        }
      }
    }
  }

  // Called on tool start
  handleToolStart(tool: any, input: string): void {
    if (!this.options.governInput) return;
    // Tools receive string input - would need to modify in place
  }

  getLastResult(): GovernanceResult | undefined {
    return this.lastResult;
  }
}

/**
 * Wrap a LangChain model/chain with Tork governance
 */
export function withTorkGovernance<T extends { invoke: Function }>(
  model: T,
  options: TorkLangChainOptions = {}
): T {
  const originalInvoke = model.invoke.bind(model);

  (model as any).invoke = async function(input: any, config?: any) {
    // Govern input
    let governedInput = input;
    if (options.governInput !== false) {
      if (typeof input === 'string') {
        const result = govern(input);
        governedInput = result.output;
      } else if (Array.isArray(input)) {
        governedInput = input.map(item => {
          if (typeof item === 'string') {
            return govern(item).output;
          }
          if (item.content && typeof item.content === 'string') {
            return { ...item, content: govern(item.content).output };
          }
          return item;
        });
      }
    }

    // Call original
    let result = await originalInvoke(governedInput, config);

    // Govern output
    if (options.governOutput !== false) {
      if (typeof result === 'string') {
        result = govern(result).output;
      } else if (result.content && typeof result.content === 'string') {
        result = { ...result, content: govern(result.content).output };
      }
    }

    return result;
  };

  return model;
}

/**
 * Create a governed LangChain tool
 */
export function createGovernedTool(
  name: string,
  description: string,
  func: (input: string) => Promise<string>,
  options: TorkLangChainOptions = {}
): { name: string; description: string; func: (input: string) => Promise<string> } {
  return {
    name,
    description,
    func: async (input: string) => {
      // Govern input
      let governedInput = input;
      if (options.governInput !== false) {
        governedInput = govern(input).output;
      }

      // Execute tool
      let result = await func(governedInput);

      // Govern output
      if (options.governOutput !== false) {
        result = govern(result).output;
      }

      return result;
    },
  };
}

/**
 * Governance middleware for LangChain Expression Language (LCEL)
 */
export function torkGovernanceRunnable(options: TorkLangChainOptions = {}) {
  return {
    invoke: async (input: any) => {
      if (typeof input === 'string') {
        return govern(input).output;
      }
      if (input.content && typeof input.content === 'string') {
        return { ...input, content: govern(input.content).output };
      }
      return input;
    },
    batch: async (inputs: any[]) => {
      return inputs.map(input => {
        if (typeof input === 'string') {
          return govern(input).output;
        }
        return input;
      });
    },
  };
}

/**
 * Governed LangChain chain wrapper with full invoke/stream/batch support
 */
export class TorkLangChain<T = any> {
  private chain: T;
  private options: TorkLangChainOptions;

  constructor(chain: T, options: TorkLangChainOptions = {}) {
    this.chain = chain;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Invoke the chain with governance
   */
  async invoke(input: string | Record<string, any>, config?: any): Promise<any> {
    let governedInput = input;
    let result: GovernanceResult | null = null;

    // Govern input
    if (this.options.governInput !== false) {
      if (typeof input === 'string') {
        result = govern(input);
        governedInput = result.output;
      } else if (typeof input === 'object' && input !== null) {
        governedInput = this.governObject(input);
      }
    }

    // Call the chain
    const chainAny = this.chain as any;
    const response = await chainAny.invoke(governedInput, config);

    // Govern output
    if (this.options.governOutput !== false && typeof response === 'string') {
      const outputResult = govern(response);
      return {
        output: outputResult.output,
        _tork_receipt: result?.receiptId,
        _tork_output_governed: outputResult.action === 'redact',
      };
    }

    if (typeof response === 'object' && response !== null) {
      return {
        ...response,
        _tork_receipt: result?.receiptId,
      };
    }

    return response;
  }

  /**
   * Stream the chain with governance
   */
  async *stream(input: string | Record<string, any>, config?: any): AsyncGenerator<any> {
    let governedInput = input;

    if (this.options.governInput !== false && typeof input === 'string') {
      governedInput = govern(input).output;
    }

    const chainAny = this.chain as any;
    if (typeof chainAny.stream === 'function') {
      for await (const chunk of chainAny.stream(governedInput, config)) {
        yield chunk;
      }
    }
  }

  /**
   * Batch invoke with governance
   */
  async batch(inputs: (string | Record<string, any>)[], config?: any): Promise<any[]> {
    const governedInputs = inputs.map((input) => {
      if (this.options.governInput !== false && typeof input === 'string') {
        return govern(input).output;
      }
      return input;
    });

    const chainAny = this.chain as any;
    return chainAny.batch(governedInputs, config);
  }

  private governObject(obj: Record<string, any>): Record<string, any> {
    const result: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        result[key] = govern(value).output;
      } else {
        result[key] = value;
      }
    }
    return result;
  }
}

/**
 * Governed LangChain agent wrapper
 */
export class TorkLangChainAgent {
  private agent: any;
  private options: TorkLangChainOptions;

  constructor(agent: any, options: TorkLangChainOptions = {}) {
    this.agent = agent;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  /**
   * Invoke the agent with governance
   */
  async invoke(input: { input: string; [key: string]: any }, config?: any): Promise<any> {
    const governedInput = { ...input };

    if (this.options.governInput !== false && input.input) {
      governedInput.input = govern(input.input).output;
    }

    const response = await this.agent.invoke(governedInput, config);

    if (this.options.governOutput !== false && response.output) {
      response.output = govern(response.output).output;
    }

    return response;
  }
}

/**
 * Wrap LangChain ChatModel with governance
 */
export class TorkChatModel {
  private model: any;
  private options: TorkLangChainOptions;

  constructor(model: any, options: TorkLangChainOptions = {}) {
    this.model = model;
    this.options = {
      governInput: true,
      governOutput: true,
      ...options,
    };
  }

  async invoke(messages: any[], config?: any): Promise<any> {
    // Govern message content
    const governedMessages = messages.map((msg: any) => {
      if (this.options.governInput !== false && msg.content && typeof msg.content === 'string') {
        return {
          ...msg,
          content: govern(msg.content).output,
        };
      }
      return msg;
    });

    const result = await this.model.invoke(governedMessages, config);

    // Govern response
    if (this.options.governOutput !== false && result.content && typeof result.content === 'string') {
      return {
        ...result,
        content: govern(result.content).output,
      };
    }

    return result;
  }

  stream(messages: any[], config?: any): AsyncGenerator<any> {
    const governedMessages = messages.map((msg: any) => {
      if (this.options.governInput !== false && msg.content && typeof msg.content === 'string') {
        return { ...msg, content: govern(msg.content).output };
      }
      return msg;
    });

    return this.model.stream(governedMessages, config);
  }
}

/**
 * Create a governed version of any LangChain runnable
 */
export function createGovernedRunnable<T>(runnable: T, options: TorkLangChainOptions = {}): TorkLangChain<T> {
  return new TorkLangChain(runnable, options);
}

/**
 * Decorator to govern chain methods
 */
export function governChain(options: TorkLangChainOptions = {}) {
  return function <T extends (...args: any[]) => Promise<any>>(
    _target: any,
    _propertyKey: string,
    descriptor: TypedPropertyDescriptor<T>
  ): TypedPropertyDescriptor<T> {
    const originalMethod = descriptor.value!;

    descriptor.value = async function (this: any, ...args: any[]): Promise<any> {
      // Govern string inputs
      const governedArgs = args.map((arg) => {
        if (options.governInput !== false && typeof arg === 'string') {
          return govern(arg).output;
        }
        return arg;
      });

      let result = await originalMethod.apply(this, governedArgs);

      // Govern output
      if (options.governOutput !== false && typeof result === 'string') {
        result = govern(result).output;
      }

      return result;
    } as T;

    return descriptor;
  };
}

export default TorkCallbackHandler;
