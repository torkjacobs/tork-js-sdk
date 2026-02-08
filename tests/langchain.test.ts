/**
 * Tests for LangChain.js middleware
 */

import { describe, it, expect, vi } from 'vitest';
import {
  TorkCallbackHandler,
  withTorkGovernance,
  createGovernedTool,
  torkGovernanceRunnable,
  TorkLangChain,
  TorkLangChainAgent,
  TorkChatModel,
  createGovernedRunnable,
} from '../src/middleware/langchain';

// ============================================================================
// TorkCallbackHandler Tests
// ============================================================================

describe('TorkCallbackHandler', () => {
  describe('constructor', () => {
    it('creates handler with default options', () => {
      const handler = new TorkCallbackHandler();
      expect(handler).toBeDefined();
      expect(handler.getLastResult()).toBeUndefined();
    });

    it('creates handler with custom options', () => {
      const handler = new TorkCallbackHandler({
        governInput: false,
        governOutput: true,
      });
      expect(handler).toBeDefined();
    });
  });

  describe('handleLLMStart', () => {
    it('redacts PII in prompts', () => {
      const handler = new TorkCallbackHandler();
      const prompts = ['My SSN is 123-45-6789'];

      handler.handleLLMStart({}, prompts);

      expect(prompts[0]).toContain('[SSN_REDACTED]');
      expect(prompts[0]).not.toContain('123-45-6789');
    });

    it('redacts email in prompts', () => {
      const handler = new TorkCallbackHandler();
      const prompts = ['Contact admin@secret.com'];

      handler.handleLLMStart({}, prompts);

      expect(prompts[0]).toContain('[EMAIL_REDACTED]');
      expect(prompts[0]).not.toContain('admin@secret.com');
    });

    it('redacts multiple prompts', () => {
      const handler = new TorkCallbackHandler();
      const prompts = [
        'SSN: 123-45-6789',
        'Email: test@example.com',
      ];

      handler.handleLLMStart({}, prompts);

      expect(prompts[0]).toContain('[SSN_REDACTED]');
      expect(prompts[1]).toContain('[EMAIL_REDACTED]');
    });

    it('passes through clean prompts', () => {
      const handler = new TorkCallbackHandler();
      const prompts = ['Hello world, no PII here'];

      handler.handleLLMStart({}, prompts);

      expect(prompts[0]).toBe('Hello world, no PII here');
    });

    it('skips governance when governInput is false', () => {
      const handler = new TorkCallbackHandler({ governInput: false });
      const prompts = ['SSN: 123-45-6789'];

      handler.handleLLMStart({}, prompts);

      expect(prompts[0]).toBe('SSN: 123-45-6789');
    });

    it('sets lastResult on PII detection', () => {
      const handler = new TorkCallbackHandler();
      const prompts = ['SSN: 123-45-6789'];

      handler.handleLLMStart({}, prompts);

      const lastResult = handler.getLastResult();
      expect(lastResult).toBeDefined();
      expect(lastResult!.action).toBe('redact');
      expect(lastResult!.receiptId).toMatch(/^rcpt_/);
    });

    it('calls onPIIDetected callback', () => {
      const onPIIDetected = vi.fn();
      const handler = new TorkCallbackHandler({ onPIIDetected });
      const prompts = ['SSN: 123-45-6789'];

      handler.handleLLMStart({}, prompts);

      expect(onPIIDetected).toHaveBeenCalled();
    });
  });

  describe('handleLLMEnd', () => {
    it('redacts PII in generations', () => {
      const handler = new TorkCallbackHandler();
      const output = {
        generations: [
          [{ text: 'Your SSN is 123-45-6789' }],
        ],
      };

      handler.handleLLMEnd(output);

      expect(output.generations[0][0].text).toContain('[SSN_REDACTED]');
      expect(output.generations[0][0].text).not.toContain('123-45-6789');
    });

    it('redacts email in generations', () => {
      const handler = new TorkCallbackHandler();
      const output = {
        generations: [
          [{ text: 'Contact john@secret.com' }],
        ],
      };

      handler.handleLLMEnd(output);

      expect(output.generations[0][0].text).toContain('[EMAIL_REDACTED]');
    });

    it('skips governance when governOutput is false', () => {
      const handler = new TorkCallbackHandler({ governOutput: false });
      const output = {
        generations: [
          [{ text: 'SSN: 123-45-6789' }],
        ],
      };

      handler.handleLLMEnd(output);

      expect(output.generations[0][0].text).toBe('SSN: 123-45-6789');
    });
  });

  describe('handleChainStart', () => {
    it('redacts PII in chain inputs', () => {
      const handler = new TorkCallbackHandler();
      const inputs: Record<string, any> = {
        query: 'My SSN is 123-45-6789',
      };

      handler.handleChainStart({}, inputs);

      expect(inputs.query).toContain('[SSN_REDACTED]');
    });

    it('handles multiple string inputs', () => {
      const handler = new TorkCallbackHandler();
      const inputs: Record<string, any> = {
        query: 'SSN: 123-45-6789',
        context: 'Email: test@secret.com',
      };

      handler.handleChainStart({}, inputs);

      expect(inputs.query).toContain('[SSN_REDACTED]');
      expect(inputs.context).toContain('[EMAIL_REDACTED]');
    });

    it('skips non-string values', () => {
      const handler = new TorkCallbackHandler();
      const inputs: Record<string, any> = {
        temperature: 0.7,
        max_tokens: 100,
      };

      handler.handleChainStart({}, inputs);

      expect(inputs.temperature).toBe(0.7);
      expect(inputs.max_tokens).toBe(100);
    });
  });

  describe('handleChainEnd', () => {
    it('redacts PII in chain outputs', () => {
      const handler = new TorkCallbackHandler();
      const outputs: Record<string, any> = {
        result: 'Your SSN is 123-45-6789',
      };

      handler.handleChainEnd(outputs);

      expect(outputs.result).toContain('[SSN_REDACTED]');
    });

    it('skips governance when governOutput is false', () => {
      const handler = new TorkCallbackHandler({ governOutput: false });
      const outputs: Record<string, any> = {
        result: 'SSN: 123-45-6789',
      };

      handler.handleChainEnd(outputs);

      expect(outputs.result).toBe('SSN: 123-45-6789');
    });
  });
});

// ============================================================================
// withTorkGovernance Tests
// ============================================================================

describe('withTorkGovernance', () => {
  it('governs string input', async () => {
    // withTorkGovernance replaces invoke in-place, so we track calls manually
    let receivedInput: any = null;
    const mockModel = {
      invoke: async (input: any) => {
        receivedInput = input;
        return 'Response';
      },
    };

    const governed = withTorkGovernance(mockModel);
    await governed.invoke('SSN: 123-45-6789');

    expect(receivedInput).toContain('[SSN_REDACTED]');
    expect(receivedInput).not.toContain('123-45-6789');
  });

  it('governs message array input', async () => {
    let receivedInput: any = null;
    const mockModel = {
      invoke: async (input: any) => {
        receivedInput = input;
        return 'Response';
      },
    };

    const governed = withTorkGovernance(mockModel);
    await governed.invoke([
      { role: 'user', content: 'SSN: 123-45-6789' },
    ]);

    expect(receivedInput[0].content).toContain('[SSN_REDACTED]');
  });

  it('governs string output', async () => {
    const mockModel = {
      invoke: async () => 'Your SSN is 123-45-6789',
    };

    const governed = withTorkGovernance(mockModel);
    const result = await governed.invoke('Hello');

    expect(result).toContain('[SSN_REDACTED]');
    expect(result).not.toContain('123-45-6789');
  });

  it('governs object output with content', async () => {
    const mockModel = {
      invoke: async () => ({ content: 'Email: test@secret.com', role: 'assistant' }),
    };

    const governed = withTorkGovernance(mockModel);
    const result = await governed.invoke('Hello');

    expect(result.content).toContain('[EMAIL_REDACTED]');
    expect(result.content).not.toContain('test@secret.com');
  });

  it('skips input governance when disabled', async () => {
    let receivedInput: any = null;
    const mockModel = {
      invoke: async (input: any) => {
        receivedInput = input;
        return 'OK';
      },
    };

    const governed = withTorkGovernance(mockModel, { governInput: false });
    await governed.invoke('SSN: 123-45-6789');

    expect(receivedInput).toBe('SSN: 123-45-6789');
  });

  it('skips output governance when disabled', async () => {
    const mockModel = {
      invoke: async () => 'SSN: 123-45-6789',
    };

    const governed = withTorkGovernance(mockModel, { governOutput: false });
    const result = await governed.invoke('Hello');

    expect(result).toBe('SSN: 123-45-6789');
  });
});

// ============================================================================
// createGovernedTool Tests
// ============================================================================

describe('createGovernedTool', () => {
  it('creates tool with name and description', () => {
    const tool = createGovernedTool('search', 'Search the web', async (input) => input);
    expect(tool.name).toBe('search');
    expect(tool.description).toBe('Search the web');
  });

  it('governs tool input', async () => {
    let receivedInput = '';
    const tool = createGovernedTool('test', 'Test tool', async (input) => {
      receivedInput = input;
      return 'result';
    });

    await tool.func('SSN: 123-45-6789');

    expect(receivedInput).toContain('[SSN_REDACTED]');
    expect(receivedInput).not.toContain('123-45-6789');
  });

  it('governs tool output', async () => {
    const tool = createGovernedTool('test', 'Test tool', async () => {
      return 'Email: admin@secret.com';
    });

    const result = await tool.func('Hello');

    expect(result).toContain('[EMAIL_REDACTED]');
    expect(result).not.toContain('admin@secret.com');
  });

  it('skips governance when disabled', async () => {
    const tool = createGovernedTool(
      'test',
      'Test tool',
      async (input) => `Got: ${input}`,
      { governInput: false, governOutput: false },
    );

    const result = await tool.func('SSN: 123-45-6789');

    expect(result).toContain('123-45-6789');
  });
});

// ============================================================================
// torkGovernanceRunnable Tests
// ============================================================================

describe('torkGovernanceRunnable', () => {
  it('governs string input via invoke', async () => {
    const runnable = torkGovernanceRunnable();
    const result = await runnable.invoke('SSN: 123-45-6789');

    expect(result).toContain('[SSN_REDACTED]');
  });

  it('governs object with content via invoke', async () => {
    const runnable = torkGovernanceRunnable();
    const result = await runnable.invoke({ content: 'SSN: 123-45-6789' });

    expect(result.content).toContain('[SSN_REDACTED]');
  });

  it('passes through non-string non-content objects', async () => {
    const runnable = torkGovernanceRunnable();
    const input = { temperature: 0.7 };
    const result = await runnable.invoke(input);

    expect(result).toEqual(input);
  });

  it('governs batch of strings', async () => {
    const runnable = torkGovernanceRunnable();
    const results = await runnable.batch([
      'SSN: 123-45-6789',
      'Email: test@example.com',
    ]);

    expect(results[0]).toContain('[SSN_REDACTED]');
    expect(results[1]).toContain('[EMAIL_REDACTED]');
  });
});

// ============================================================================
// TorkLangChain Tests
// ============================================================================

describe('TorkLangChain', () => {
  it('governs string input on invoke', async () => {
    const mockChain = {
      invoke: vi.fn().mockResolvedValue('Response'),
    };

    const governed = new TorkLangChain(mockChain);
    await governed.invoke('SSN: 123-45-6789');

    expect(mockChain.invoke).toHaveBeenCalledWith(
      expect.stringContaining('[SSN_REDACTED]'),
      undefined,
    );
  });

  it('governs object input on invoke', async () => {
    const mockChain = {
      invoke: vi.fn().mockResolvedValue('Response'),
    };

    const governed = new TorkLangChain(mockChain);
    await governed.invoke({ query: 'SSN: 123-45-6789', context: 'Email: test@example.com' });

    const callArgs = mockChain.invoke.mock.calls[0][0];
    expect(callArgs.query).toContain('[SSN_REDACTED]');
    expect(callArgs.context).toContain('[EMAIL_REDACTED]');
  });

  it('governs string output on invoke', async () => {
    const mockChain = {
      invoke: vi.fn().mockResolvedValue('Your SSN is 123-45-6789'),
    };

    const governed = new TorkLangChain(mockChain);
    const result = await governed.invoke('Hello');

    expect(result.output).toContain('[SSN_REDACTED]');
    expect(result._tork_output_governed).toBe(true);
  });

  it('includes receipt in result', async () => {
    const mockChain = {
      invoke: vi.fn().mockResolvedValue({ result: 'OK' }),
    };

    const governed = new TorkLangChain(mockChain);
    const result = await governed.invoke('SSN: 123-45-6789');

    expect(result._tork_receipt).toBeDefined();
  });

  it('batch governs inputs', async () => {
    const mockChain = {
      batch: vi.fn().mockResolvedValue(['Response 1', 'Response 2']),
    };

    const governed = new TorkLangChain(mockChain);
    await governed.batch(['SSN: 123-45-6789', 'Hello world']);

    const callArgs = mockChain.batch.mock.calls[0][0];
    expect(callArgs[0]).toContain('[SSN_REDACTED]');
    expect(callArgs[1]).toBe('Hello world');
  });
});

// ============================================================================
// TorkLangChainAgent Tests
// ============================================================================

describe('TorkLangChainAgent', () => {
  it('governs agent input', async () => {
    const mockAgent = {
      invoke: vi.fn().mockResolvedValue({ output: 'Done' }),
    };

    const governed = new TorkLangChainAgent(mockAgent);
    await governed.invoke({ input: 'SSN: 123-45-6789' });

    const callArgs = mockAgent.invoke.mock.calls[0][0];
    expect(callArgs.input).toContain('[SSN_REDACTED]');
  });

  it('governs agent output', async () => {
    const mockAgent = {
      invoke: vi.fn().mockResolvedValue({ output: 'Your SSN is 123-45-6789' }),
    };

    const governed = new TorkLangChainAgent(mockAgent);
    const result = await governed.invoke({ input: 'What is my SSN?' });

    expect(result.output).toContain('[SSN_REDACTED]');
  });

  it('skips governance when disabled', async () => {
    const mockAgent = {
      invoke: vi.fn().mockResolvedValue({ output: 'SSN: 987-65-4321' }),
    };

    const governed = new TorkLangChainAgent(mockAgent, {
      governInput: false,
      governOutput: false,
    });
    const result = await governed.invoke({ input: 'SSN: 123-45-6789' });

    const callArgs = mockAgent.invoke.mock.calls[0][0];
    expect(callArgs.input).toBe('SSN: 123-45-6789');
    expect(result.output).toBe('SSN: 987-65-4321');
  });
});

// ============================================================================
// TorkChatModel Tests
// ============================================================================

describe('TorkChatModel', () => {
  it('governs message content on invoke', async () => {
    const mockModel = {
      invoke: vi.fn().mockResolvedValue({ content: 'OK', role: 'assistant' }),
    };

    const governed = new TorkChatModel(mockModel);
    await governed.invoke([
      { role: 'user', content: 'SSN: 123-45-6789' },
    ]);

    const callArgs = mockModel.invoke.mock.calls[0][0];
    expect(callArgs[0].content).toContain('[SSN_REDACTED]');
  });

  it('governs response content on invoke', async () => {
    const mockModel = {
      invoke: vi.fn().mockResolvedValue({ content: 'SSN: 123-45-6789', role: 'assistant' }),
    };

    const governed = new TorkChatModel(mockModel);
    const result = await governed.invoke([{ role: 'user', content: 'Hello' }]);

    expect(result.content).toContain('[SSN_REDACTED]');
  });

  it('preserves message role', async () => {
    const mockModel = {
      invoke: vi.fn().mockResolvedValue({ content: 'OK', role: 'assistant' }),
    };

    const governed = new TorkChatModel(mockModel);
    await governed.invoke([
      { role: 'user', content: 'SSN: 123-45-6789' },
      { role: 'system', content: 'You are helpful' },
    ]);

    const callArgs = mockModel.invoke.mock.calls[0][0];
    expect(callArgs[0].role).toBe('user');
    expect(callArgs[1].role).toBe('system');
  });
});

// ============================================================================
// createGovernedRunnable Tests
// ============================================================================

describe('createGovernedRunnable', () => {
  it('creates TorkLangChain instance', () => {
    const mockRunnable = { invoke: vi.fn() };
    const governed = createGovernedRunnable(mockRunnable);
    expect(governed).toBeInstanceOf(TorkLangChain);
  });

  it('passes options through', async () => {
    const mockRunnable = {
      invoke: vi.fn().mockResolvedValue('SSN: 123-45-6789'),
    };

    const governed = createGovernedRunnable(mockRunnable, { governOutput: false });
    const result = await governed.invoke('Hello');

    // With governOutput false, the result should be the raw object response
    expect(result).toBeDefined();
  });
});
