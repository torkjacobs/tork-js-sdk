import { describe, it, expect, beforeEach } from 'vitest';
import { Tork, detectPII, hashText, generateReceiptId } from './index';

describe('detectPII', () => {
  it('detects SSN', () => {
    const result = detectPII('My SSN is 123-45-6789');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('ssn');
    expect(result.redactedText).toBe('My SSN is [SSN_REDACTED]');
  });

  it('detects email', () => {
    const result = detectPII('Contact: john@example.com');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('email');
  });

  it('detects credit card', () => {
    const result = detectPII('Card: 4111-1111-1111-1111');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('credit_card');
  });

  it('detects phone', () => {
    const result = detectPII('Call 555-123-4567');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('phone');
  });

  it('handles no PII', () => {
    const result = detectPII('Hello world, no sensitive data here.');
    expect(result.hasPII).toBe(false);
    expect(result.count).toBe(0);
  });

  it('detects multiple PII types', () => {
    const result = detectPII('SSN: 123-45-6789, Email: test@test.com');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('ssn');
    expect(result.types).toContain('email');
    expect(result.count).toBe(2);
  });
});

describe('Tork', () => {
  let tork: Tork;

  beforeEach(() => {
    tork = new Tork();
  });

  it('governs text with PII', () => {
    const result = tork.govern('My SSN is 123-45-6789');
    expect(result.action).toBe('redact');
    expect(result.output).toBe('My SSN is [SSN_REDACTED]');
    expect(result.pii.hasPII).toBe(true);
  });

  it('allows text without PII', () => {
    const result = tork.govern('Hello world');
    expect(result.action).toBe('allow');
    expect(result.output).toBe('Hello world');
  });

  it('generates valid receipt', () => {
    const result = tork.govern('Test input');
    expect(result.receipt.receiptId).toMatch(/^rcpt_/);
    expect(result.receipt.inputHash).toMatch(/^sha256:/);
    expect(result.receipt.timestamp).toBeTruthy();
  });

  it('tracks statistics', () => {
    tork.govern('Text 1');
    tork.govern('SSN: 123-45-6789');
    tork.govern('Text 3');

    const stats = tork.getStats();
    expect(stats.totalCalls).toBe(3);
    expect(stats.totalPIIDetected).toBe(1);
  });
});

describe('hashText', () => {
  it('generates consistent SHA256 hash', () => {
    const hash1 = hashText('test');
    const hash2 = hashText('test');
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

describe('generateReceiptId', () => {
  it('generates unique IDs', () => {
    const id1 = generateReceiptId();
    const id2 = generateReceiptId();
    expect(id1).not.toBe(id2);
    expect(id1).toMatch(/^rcpt_/);
  });
});
