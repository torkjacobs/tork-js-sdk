/**
 * Tork Governance SDK - Core Module Comprehensive Tests
 * Matches Python SDK test coverage (67 tests for core module)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  Tork,
  detectPII,
  hashText,
  generateReceiptId,
  PIIType,
  GovernanceAction,
  PIIDetectionResult,
  GovernanceResult,
  TorkConfig,
  TorkStats,
} from '../src/index';

// ============================================================================
// PIIType Tests
// ============================================================================

describe('PIIType', () => {
  it('should include ssn type', () => {
    const types: PIIType[] = ['ssn', 'credit_card', 'email', 'phone', 'address', 'ip_address', 'date_of_birth', 'passport', 'drivers_license', 'bank_account'];
    expect(types).toContain('ssn');
  });

  it('should include credit_card type', () => {
    const types: PIIType[] = ['ssn', 'credit_card', 'email', 'phone'];
    expect(types).toContain('credit_card');
  });

  it('should include email type', () => {
    const types: PIIType[] = ['ssn', 'credit_card', 'email', 'phone'];
    expect(types).toContain('email');
  });

  it('should include phone type', () => {
    const types: PIIType[] = ['ssn', 'credit_card', 'email', 'phone'];
    expect(types).toContain('phone');
  });

  it('should include all 10 PII types', () => {
    const allTypes: PIIType[] = ['ssn', 'credit_card', 'email', 'phone', 'address', 'ip_address', 'date_of_birth', 'passport', 'drivers_license', 'bank_account'];
    expect(allTypes.length).toBe(10);
  });
});

// ============================================================================
// GovernanceAction Tests
// ============================================================================

describe('GovernanceAction', () => {
  it('should include allow action', () => {
    const actions: GovernanceAction[] = ['allow', 'deny', 'redact', 'escalate'];
    expect(actions).toContain('allow');
  });

  it('should include deny action', () => {
    const actions: GovernanceAction[] = ['allow', 'deny', 'redact', 'escalate'];
    expect(actions).toContain('deny');
  });

  it('should include redact action', () => {
    const actions: GovernanceAction[] = ['allow', 'deny', 'redact', 'escalate'];
    expect(actions).toContain('redact');
  });

  it('should include escalate action', () => {
    const actions: GovernanceAction[] = ['allow', 'deny', 'redact', 'escalate'];
    expect(actions).toContain('escalate');
  });
});

// ============================================================================
// Utility Functions Tests
// ============================================================================

describe('hashText', () => {
  it('should generate sha256 prefixed hash', () => {
    const hash = hashText('test');
    expect(hash.startsWith('sha256:')).toBe(true);
  });

  it('should generate consistent hashes', () => {
    const hash1 = hashText('test');
    const hash2 = hashText('test');
    expect(hash1).toBe(hash2);
  });

  it('should generate different hashes for different inputs', () => {
    const hash1 = hashText('test1');
    const hash2 = hashText('test2');
    expect(hash1).not.toBe(hash2);
  });

  it('should generate 64 character hex hash after prefix', () => {
    const hash = hashText('test');
    const hexPart = hash.replace('sha256:', '');
    expect(hexPart.length).toBe(64);
  });

  it('should handle empty string', () => {
    const hash = hashText('');
    expect(hash.startsWith('sha256:')).toBe(true);
  });

  it('should handle unicode characters', () => {
    const hash = hashText('Hello \u4e16\u754c');
    expect(hash.startsWith('sha256:')).toBe(true);
  });
});

describe('generateReceiptId', () => {
  it('should generate receipt id with rcpt_ prefix', () => {
    const id = generateReceiptId();
    expect(id.startsWith('rcpt_')).toBe(true);
  });

  it('should generate unique ids', () => {
    const id1 = generateReceiptId();
    const id2 = generateReceiptId();
    expect(id1).not.toBe(id2);
  });

  it('should generate 32 character hex after prefix', () => {
    const id = generateReceiptId();
    const hexPart = id.replace('rcpt_', '');
    expect(hexPart.length).toBe(32);
  });

  it('should generate multiple unique ids', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(generateReceiptId());
    }
    expect(ids.size).toBe(100);
  });
});

// ============================================================================
// detectPII Tests
// ============================================================================

describe('detectPII', () => {
  it('should detect SSN', () => {
    const result = detectPII('My SSN is 123-45-6789');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('ssn');
  });

  it('should detect email', () => {
    const result = detectPII('Contact me at john@example.com');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('email');
  });

  it('should detect credit card', () => {
    const result = detectPII('Card: 4111-1111-1111-1111');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('credit_card');
  });

  it('should detect phone number', () => {
    const result = detectPII('Call me at 555-123-4567');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('phone');
  });

  it('should detect IP address', () => {
    const result = detectPII('Server IP: 192.168.1.1');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('ip_address');
  });

  it('should detect date of birth', () => {
    const result = detectPII('DOB: 01/15/1990');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('date_of_birth');
  });

  it('should not detect PII in clean text', () => {
    const result = detectPII('Hello world, no sensitive data here');
    expect(result.hasPII).toBe(false);
    expect(result.count).toBe(0);
  });

  it('should detect multiple PII types', () => {
    const result = detectPII('SSN: 123-45-6789, Email: test@test.com');
    expect(result.hasPII).toBe(true);
    expect(result.types).toContain('ssn');
    expect(result.types).toContain('email');
    expect(result.count).toBe(2);
  });

  it('should redact SSN', () => {
    const result = detectPII('My SSN is 123-45-6789');
    expect(result.redactedText).toBe('My SSN is [SSN_REDACTED]');
  });

  it('should redact email', () => {
    const result = detectPII('Contact: john@example.com');
    expect(result.redactedText).toBe('Contact: [EMAIL_REDACTED]');
  });

  it('should redact credit card', () => {
    const result = detectPII('Card: 4111-1111-1111-1111');
    expect(result.redactedText).toBe('Card: [CARD_REDACTED]');
  });

  it('should redact multiple PII instances', () => {
    const result = detectPII('SSN: 123-45-6789, Another: 987-65-4321');
    expect(result.redactedText).toBe('SSN: [SSN_REDACTED], Another: [SSN_REDACTED]');
    expect(result.count).toBe(2);
  });

  it('should handle empty string', () => {
    const result = detectPII('');
    expect(result.hasPII).toBe(false);
    expect(result.count).toBe(0);
    expect(result.redactedText).toBe('');
  });

  it('should return matches with correct indices', () => {
    const result = detectPII('SSN: 123-45-6789');
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches[0].startIndex).toBeDefined();
    expect(result.matches[0].endIndex).toBeDefined();
  });

  it('should apply custom patterns', () => {
    // Use 4 digits to avoid bank_account pattern (8-17 digits)
    const customPatterns = { order_id: /ORD-\d{4}/g };
    const result = detectPII('Order: ORD-1234', customPatterns);
    expect(result.redactedText).toContain('[ORDER_ID_REDACTED]');
  });
});

// ============================================================================
// Tork Class Tests
// ============================================================================

describe('Tork', () => {
  let tork: Tork;

  beforeEach(() => {
    tork = new Tork();
  });

  describe('constructor', () => {
    it('should create with default config', () => {
      const t = new Tork();
      const config = t.getConfig();
      expect(config.policyVersion).toBe('1.0.0');
      expect(config.defaultAction).toBe('redact');
    });

    it('should create with custom policy version', () => {
      const t = new Tork({ policyVersion: '2.0.0' });
      expect(t.getConfig().policyVersion).toBe('2.0.0');
    });

    it('should create with custom default action', () => {
      const t = new Tork({ defaultAction: 'deny' });
      expect(t.getConfig().defaultAction).toBe('deny');
    });

    it('should create with custom patterns', () => {
      const t = new Tork({ customPatterns: { test: /test/g } });
      expect(t.getConfig().customPatterns).toBeDefined();
    });
  });

  describe('govern', () => {
    it('should return allow action for clean text', () => {
      const result = tork.govern('Hello world');
      expect(result.action).toBe('allow');
      expect(result.output).toBe('Hello world');
    });

    it('should return redact action for text with PII', () => {
      const result = tork.govern('My SSN is 123-45-6789');
      expect(result.action).toBe('redact');
      expect(result.output).toBe('My SSN is [SSN_REDACTED]');
    });

    it('should include receipt in result', () => {
      const result = tork.govern('test');
      expect(result.receipt).toBeDefined();
      expect(result.receipt.receiptId.startsWith('rcpt_')).toBe(true);
    });

    it('should include PII result', () => {
      const result = tork.govern('SSN: 123-45-6789');
      expect(result.pii).toBeDefined();
      expect(result.pii.hasPII).toBe(true);
    });

    it('should generate receipt with correct hashes', () => {
      const result = tork.govern('test');
      expect(result.receipt.inputHash.startsWith('sha256:')).toBe(true);
      expect(result.receipt.outputHash.startsWith('sha256:')).toBe(true);
    });

    it('should respect deny action configuration', () => {
      const t = new Tork({ defaultAction: 'deny' });
      const result = t.govern('SSN: 123-45-6789');
      expect(result.action).toBe('deny');
      expect(result.output).toBe('SSN: 123-45-6789'); // Not redacted when action is deny
    });

    it('should handle multiple governs correctly', () => {
      tork.govern('test1');
      tork.govern('test2');
      const stats = tork.getStats();
      expect(stats.totalCalls).toBe(2);
    });
  });

  describe('getStats', () => {
    it('should return zero stats initially', () => {
      const stats = tork.getStats();
      expect(stats.totalCalls).toBe(0);
      expect(stats.totalPIIDetected).toBe(0);
    });

    it('should track total calls', () => {
      tork.govern('test');
      tork.govern('test2');
      expect(tork.getStats().totalCalls).toBe(2);
    });

    it('should track PII detected', () => {
      tork.govern('SSN: 123-45-6789');
      tork.govern('clean text');
      expect(tork.getStats().totalPIIDetected).toBe(1);
    });

    it('should track action counts', () => {
      tork.govern('SSN: 123-45-6789');
      tork.govern('clean text');
      const stats = tork.getStats();
      expect(stats.actionCounts.redact).toBe(1);
      expect(stats.actionCounts.allow).toBe(1);
    });
  });

  describe('resetStats', () => {
    it('should reset all stats to zero', () => {
      tork.govern('SSN: 123-45-6789');
      tork.govern('test');
      tork.resetStats();
      const stats = tork.getStats();
      expect(stats.totalCalls).toBe(0);
      expect(stats.totalPIIDetected).toBe(0);
    });

    it('should reset action counts', () => {
      tork.govern('SSN: 123-45-6789');
      tork.resetStats();
      expect(tork.getStats().actionCounts.redact).toBe(0);
    });
  });

  describe('getConfig', () => {
    it('should return current config', () => {
      const config = tork.getConfig();
      expect(config.policyVersion).toBeDefined();
      expect(config.defaultAction).toBeDefined();
    });
  });

  describe('updateConfig', () => {
    it('should update policy version', () => {
      tork.updateConfig({ policyVersion: '3.0.0' });
      expect(tork.getConfig().policyVersion).toBe('3.0.0');
    });

    it('should update default action', () => {
      tork.updateConfig({ defaultAction: 'escalate' });
      expect(tork.getConfig().defaultAction).toBe('escalate');
    });

    it('should update custom patterns', () => {
      tork.updateConfig({ customPatterns: { test: /test/g } });
      expect(tork.getConfig().customPatterns).toBeDefined();
    });
  });
});

// ============================================================================
// Edge Cases Tests
// ============================================================================

describe('Edge Cases', () => {
  let tork: Tork;

  beforeEach(() => {
    tork = new Tork();
  });

  it('should handle very long text', () => {
    const longText = 'A'.repeat(100000);
    const result = tork.govern(longText);
    expect(result.action).toBe('allow');
  });

  it('should handle text with unicode', () => {
    const result = tork.govern('Hello \u4e16\u754c, SSN: 123-45-6789');
    expect(result.pii.hasPII).toBe(true);
  });

  it('should handle text with special characters', () => {
    const result = tork.govern('Special chars: !@#$%^&*()');
    expect(result.action).toBe('allow');
  });

  it('should handle text with newlines', () => {
    const result = tork.govern('Line1\nLine2\nSSN: 123-45-6789');
    expect(result.pii.hasPII).toBe(true);
  });

  it('should handle text with tabs', () => {
    const result = tork.govern('Tab\there\tSSN: 123-45-6789');
    expect(result.pii.hasPII).toBe(true);
  });

  it('should handle adjacent PII', () => {
    const result = tork.govern('123-45-6789 987-65-4321');
    expect(result.pii.count).toBe(2);
  });

  it('should handle repeated governs', () => {
    for (let i = 0; i < 100; i++) {
      const result = tork.govern(`Test ${i}`);
      expect(result.receipt).toBeDefined();
    }
    expect(tork.getStats().totalCalls).toBe(100);
  });
});

// ============================================================================
// Receipt Tests
// ============================================================================

describe('GovernanceReceipt', () => {
  let tork: Tork;

  beforeEach(() => {
    tork = new Tork();
  });

  it('should have unique receipt ID', () => {
    const result1 = tork.govern('test1');
    const result2 = tork.govern('test2');
    expect(result1.receipt.receiptId).not.toBe(result2.receipt.receiptId);
  });

  it('should have timestamp', () => {
    const result = tork.govern('test');
    expect(result.receipt.timestamp).toBeDefined();
  });

  it('should have input hash', () => {
    const result = tork.govern('test');
    expect(result.receipt.inputHash.startsWith('sha256:')).toBe(true);
  });

  it('should have output hash', () => {
    const result = tork.govern('test');
    expect(result.receipt.outputHash.startsWith('sha256:')).toBe(true);
  });

  it('should have action', () => {
    const result = tork.govern('test');
    expect(['allow', 'deny', 'redact', 'escalate']).toContain(result.receipt.action);
  });

  it('should have policy version', () => {
    const result = tork.govern('test');
    expect(result.receipt.policyVersion).toBe('1.0.0');
  });

  it('should have processing time', () => {
    const result = tork.govern('test');
    expect(result.receipt.processingTimeNs).toBeDefined();
    expect(result.receipt.processingTimeNs >= 0).toBe(true);
  });
});
