/**
 * Tests for Vercel AI SDK middleware
 */

import { vi } from 'vitest';
import {
  torkVercelAIMiddleware,
  withTorkVercelAI,
  createGovernedChat,
} from '../src/middleware/vercel-ai';

describe('torkVercelAIMiddleware', () => {
  describe('initialization', () => {
    it('creates middleware with default options', () => {
      const tork = torkVercelAIMiddleware();
      expect(tork).toBeDefined();
      expect(typeof tork.governMessages).toBe('function');
      expect(typeof tork.governPrompt).toBe('function');
      expect(typeof tork.wrapStream).toBe('function');
      expect(typeof tork.govern).toBe('function');
      expect(typeof tork.getReceipts).toBe('function');
      expect(typeof tork.clearReceipts).toBe('function');
    });

    it('creates middleware with custom options', () => {
      const tork = torkVercelAIMiddleware({
        governInput: false,
        governOutput: true,
      });
      expect(tork).toBeDefined();
    });
  });

  describe('governMessages', () => {
    it('passes through clean messages', () => {
      const tork = torkVercelAIMiddleware();
      const messages = [
        { role: 'user' as const, content: 'Hello world' },
        { role: 'assistant' as const, content: 'Hi there!' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].content).toBe('Hello world');
      expect(result[1].content).toBe('Hi there!');
    });

    it('redacts PII in messages', () => {
      const tork = torkVercelAIMiddleware();
      const messages = [
        { role: 'user' as const, content: 'My email is test@example.com' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].content).toContain('[EMAIL_REDACTED]');
      expect(result[0].content).not.toContain('test@example.com');
    });

    it('redacts SSN in messages', () => {
      const tork = torkVercelAIMiddleware();
      const messages = [
        { role: 'user' as const, content: 'SSN: 123-45-6789' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].content).toContain('[SSN_REDACTED]');
    });

    it('redacts phone numbers', () => {
      const tork = torkVercelAIMiddleware();
      const messages = [
        { role: 'user' as const, content: 'Call me at 555-123-4567' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].content).toContain('[PHONE_REDACTED]');
    });

    it('redacts credit card numbers', () => {
      const tork = torkVercelAIMiddleware();
      const messages = [
        { role: 'user' as const, content: 'Card: 4111-1111-1111-1111' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].content).toContain('[CARD_REDACTED]');
    });

    it('skips governance when governInput is false', () => {
      const tork = torkVercelAIMiddleware({ governInput: false });
      const messages = [
        { role: 'user' as const, content: 'Email: test@example.com' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].content).toBe('Email: test@example.com');
    });

    it('preserves message structure', () => {
      const tork = torkVercelAIMiddleware();
      const messages = [
        { role: 'user' as const, content: 'test@example.com', id: 'msg-1', name: 'user1' },
      ];

      const result = tork.governMessages(messages);
      expect(result[0].role).toBe('user');
      expect(result[0].id).toBe('msg-1');
      expect(result[0].name).toBe('user1');
    });
  });

  describe('governPrompt', () => {
    it('passes through clean prompts', () => {
      const tork = torkVercelAIMiddleware();
      const result = tork.governPrompt('Hello world');
      expect(result).toBe('Hello world');
    });

    it('redacts PII in prompts', () => {
      const tork = torkVercelAIMiddleware();
      const result = tork.governPrompt('Contact: user@domain.com');
      expect(result).toContain('[EMAIL_REDACTED]');
    });

    it('skips governance when governInput is false', () => {
      const tork = torkVercelAIMiddleware({ governInput: false });
      const result = tork.governPrompt('Email: test@example.com');
      expect(result).toBe('Email: test@example.com');
    });
  });

  describe('govern', () => {
    it('returns full governance result', () => {
      const tork = torkVercelAIMiddleware();
      const result = tork.govern('My SSN is 123-45-6789');

      expect(result.action).toBe('redact');
      expect(result.output).toContain('[SSN_REDACTED]');
      expect(result.hasPII).toBe(true);
      expect(result.piiTypes).toContain('ssn');
      expect(result.receiptId).toMatch(/^rcpt_/);
    });

    it('allows clean text', () => {
      const tork = torkVercelAIMiddleware();
      const result = tork.govern('Hello world');

      expect(result.action).toBe('allow');
      expect(result.output).toBe('Hello world');
      expect(result.hasPII).toBe(false);
      expect(result.piiTypes).toHaveLength(0);
    });
  });

  describe('receipts', () => {
    it('tracks governance receipts', () => {
      const tork = torkVercelAIMiddleware();
      tork.govern('test@example.com');
      tork.govern('123-45-6789');

      const receipts = tork.getReceipts();
      expect(receipts).toHaveLength(2);
      expect(receipts[0].receiptId).toMatch(/^rcpt_/);
      expect(receipts[1].receiptId).toMatch(/^rcpt_/);
    });

    it('clears receipts', () => {
      const tork = torkVercelAIMiddleware();
      tork.govern('test@example.com');

      expect(tork.getReceipts()).toHaveLength(1);
      tork.clearReceipts();
      expect(tork.getReceipts()).toHaveLength(0);
    });
  });

  describe('createTransformStream', () => {
    it('creates a transform stream', () => {
      const tork = torkVercelAIMiddleware();
      const stream = tork.createTransformStream();
      expect(stream).toBeInstanceOf(TransformStream);
    });
  });
});

describe('withTorkVercelAI', () => {
  it('wraps a handler with tork middleware', async () => {
    let receivedTork: ReturnType<typeof torkVercelAIMiddleware> | undefined;

    const handler = withTorkVercelAI(async (req, tork) => {
      receivedTork = tork;
      return new Response('OK');
    });

    const response = await handler(new Request('http://localhost'));
    expect(response).toBeInstanceOf(Response);
    expect(receivedTork).toBeDefined();
    expect(typeof receivedTork?.governMessages).toBe('function');
  });
});

describe('createGovernedChat', () => {
  it('wraps useChat hook', () => {
    const mockUseChat = vi.fn().mockReturnValue({
      messages: [],
      input: '',
      handleSubmit: vi.fn(),
    });

    const result = createGovernedChat(mockUseChat, { api: '/api/chat' });

    expect(mockUseChat).toHaveBeenCalled();
    expect(result.messages).toBeDefined();
    expect(result.input).toBeDefined();
  });
});
