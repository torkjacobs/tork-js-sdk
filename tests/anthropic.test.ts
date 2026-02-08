/**
 * Tests for Anthropic SDK middleware
 */

import { describe, it, expect, vi } from 'vitest';
import {
  TorkAnthropicClient,
  governMessage,
  anthropicGoverned,
} from '../src/middleware/anthropic';

describe('TorkAnthropicClient', () => {
  describe('constructor', () => {
    it('creates client with default options', () => {
      const mockClient = {};
      const client = new TorkAnthropicClient(mockClient);
      expect(client).toBeDefined();
      expect(client.getReceipts()).toHaveLength(0);
    });

    it('creates client with custom options', () => {
      const mockClient = {};
      const client = new TorkAnthropicClient(mockClient, {
        governInput: false,
        governOutput: true,
      });
      expect(client).toBeDefined();
    });

    it('exposes underlying client', () => {
      const mockClient = { name: 'anthropic' };
      const client = new TorkAnthropicClient(mockClient);
      expect(client.getClient()).toBe(mockClient);
    });
  });

  describe('governMessage - input governance', () => {
    it('redacts SSN in user messages', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'Understood.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'My SSN is 123-45-6789' }],
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      expect(callArgs.messages[0].content).toContain('[SSN_REDACTED]');
      expect(callArgs.messages[0].content).not.toContain('123-45-6789');
    });

    it('redacts email in user messages', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Email me at admin@secret.com' }],
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      expect(callArgs.messages[0].content).toContain('[EMAIL_REDACTED]');
      expect(callArgs.messages[0].content).not.toContain('admin@secret.com');
    });

    it('redacts credit card numbers', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'Got it.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Card: 4111-1111-1111-1111' }],
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      expect(callArgs.messages[0].content).toContain('[CARD_REDACTED]');
      expect(callArgs.messages[0].content).not.toContain('4111-1111-1111-1111');
    });

    it('redacts system prompt PII', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'Done.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello' }],
        system: 'User SSN: 123-45-6789',
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      expect(callArgs.system).toContain('[SSN_REDACTED]');
      expect(callArgs.system).not.toContain('123-45-6789');
    });

    it('passes through clean messages unchanged', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'Hi!' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello world' }],
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      expect(callArgs.messages[0].content).toBe('Hello world');
    });

    it('handles content blocks', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: [{ type: 'text', text: 'SSN: 123-45-6789' }],
        }],
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      const textBlock = callArgs.messages[0].content[0];
      expect(textBlock.text).toContain('[SSN_REDACTED]');
      expect(textBlock.text).not.toContain('123-45-6789');
    });
  });

  describe('governMessage - output governance', () => {
    it('redacts PII in output text blocks', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'Your SSN is 123-45-6789' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      const response = await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello' }],
      });

      expect(response.content[0].text).toContain('[SSN_REDACTED]');
      expect(response.content[0].text).not.toContain('123-45-6789');
    });

    it('redacts email in output', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'Contact john@secret.com' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      const response = await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello' }],
      });

      expect(response.content[0].text).toContain('[EMAIL_REDACTED]');
      expect(response.content[0].text).not.toContain('john@secret.com');
    });
  });

  describe('governMessage - disabled governance', () => {
    it('skips input governance when disabled', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient, { governInput: false });
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
      });

      const callArgs = mockClient.messages.create.mock.calls[0][0];
      expect(callArgs.messages[0].content).toBe('SSN: 123-45-6789');
    });

    it('skips output governance when disabled', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'SSN: 123-45-6789' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient, { governOutput: false });
      const response = await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello' }],
      });

      expect(response.content[0].text).toBe('SSN: 123-45-6789');
    });
  });

  describe('receipts', () => {
    it('tracks governance receipts', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
      });

      const receipts = client.getReceipts();
      expect(receipts.length).toBeGreaterThan(0);
      expect(receipts[0].receiptId).toMatch(/^rcpt_/);
    });

    it('clears receipts', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
      });

      expect(client.getReceipts().length).toBeGreaterThan(0);
      client.clearReceipts();
      expect(client.getReceipts()).toHaveLength(0);
    });

    it('receipts have hasPII flag', async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient);
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
      });

      const receipts = client.getReceipts();
      const piiReceipt = receipts.find(r => r.hasPII);
      expect(piiReceipt).toBeDefined();
      expect(piiReceipt!.piiTypes).toContain('ssn');
    });
  });

  describe('onPIIDetected callback', () => {
    it('calls callback when PII is detected in input', async () => {
      const onPIIDetected = vi.fn();
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient, { onPIIDetected });
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
      });

      expect(onPIIDetected).toHaveBeenCalled();
      expect(onPIIDetected.mock.calls[0][0]).toContain('ssn');
    });

    it('calls callback when PII is detected in system prompt', async () => {
      const onPIIDetected = vi.fn();
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({
            content: [{ type: 'text', text: 'OK.' }],
          }),
        },
      };

      const client = new TorkAnthropicClient(mockClient, { onPIIDetected });
      await client.governMessage({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello' }],
        system: 'User email: test@secret.com',
      });

      expect(onPIIDetected).toHaveBeenCalled();
    });
  });
});

describe('governMessage standalone', () => {
  it('governs message and returns receipts', async () => {
    const mockClient = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [{ type: 'text', text: 'OK.' }],
        }),
      },
    };

    const { response, receipts } = await governMessage(mockClient, {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
    });

    expect(response).toBeDefined();
    expect(receipts.length).toBeGreaterThan(0);
    expect(receipts[0].receiptId).toMatch(/^rcpt_/);
  });

  it('passes options to client', async () => {
    const mockClient = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [{ type: 'text', text: 'OK.' }],
        }),
      },
    };

    await governMessage(
      mockClient,
      {
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
      },
      { governInput: false }
    );

    const callArgs = mockClient.messages.create.mock.calls[0][0];
    expect(callArgs.messages[0].content).toBe('SSN: 123-45-6789');
  });
});

describe('anthropicGoverned decorator', () => {
  it('governs input messages', async () => {
    const fn = vi.fn().mockImplementation(async (params: any) => ({
      content: [{ type: 'text', text: 'OK.' }],
    }));

    const governed = anthropicGoverned(fn);
    await governed({
      messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
    });

    const callArgs = fn.mock.calls[0][0];
    const userMsg = callArgs.messages[0];
    expect(userMsg.content).toContain('[SSN_REDACTED]');
    expect(userMsg.content).not.toContain('123-45-6789');
  });

  it('governs system prompt', async () => {
    const fn = vi.fn().mockImplementation(async (params: any) => ({
      content: [{ type: 'text', text: 'OK.' }],
    }));

    const governed = anthropicGoverned(fn);
    await governed({
      messages: [{ role: 'user', content: 'Hello' }],
      system: 'Email: admin@secret.com',
    });

    const callArgs = fn.mock.calls[0][0];
    expect(callArgs.system).toContain('[EMAIL_REDACTED]');
    expect(callArgs.system).not.toContain('admin@secret.com');
  });

  it('governs output content blocks', async () => {
    const fn = vi.fn().mockImplementation(async () => ({
      content: [{ type: 'text', text: 'Your SSN is 123-45-6789' }],
    }));

    const governed = anthropicGoverned(fn);
    const result = await governed({
      messages: [{ role: 'user', content: 'Hello' }],
    });

    expect(result.content[0].text).toContain('[SSN_REDACTED]');
    expect(result.content[0].text).not.toContain('123-45-6789');
  });

  it('skips governance when disabled', async () => {
    const fn = vi.fn().mockImplementation(async (params: any) => ({
      content: [{ type: 'text', text: 'SSN: 987-65-4321' }],
    }));

    const governed = anthropicGoverned(fn, { governInput: false, governOutput: false });
    const result = await governed({
      messages: [{ role: 'user', content: 'SSN: 123-45-6789' }],
    });

    const callArgs = fn.mock.calls[0][0];
    expect(callArgs.messages[0].content).toBe('SSN: 123-45-6789');
    expect(result.content[0].text).toBe('SSN: 987-65-4321');
  });

  it('governs string arguments', async () => {
    const fn = vi.fn().mockImplementation(async (text: string) => text);

    const governed = anthropicGoverned(fn);
    await governed('Email: user@domain.com');

    expect(fn.mock.calls[0][0]).toContain('[EMAIL_REDACTED]');
  });
});
