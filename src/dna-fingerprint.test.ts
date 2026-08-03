import { describe, it, expect } from 'vitest';
import {
  buildCanonical,
  canonicalJson,
  classifyRisk,
  computeSaltedFingerprint,
  computeScore,
  derivePolicies,
  generateFingerprintSalt,
} from './dna-fingerprint';

// These pin the JS port to lib/governance/dna-fingerprint.ts in the
// tork.network landing repo (and to the identical Python port): same
// canonical shape, same hashing scheme.
describe('TORK-DNA-v2 known-good vector', () => {
  const CANONICAL = {
    hitl: false,
    pii: ['email'],
    policies: ['pii-redact', 'rate-limit'],
    risk: 'low' as const,
    score: 100,
    ts: 1785700000,
    v: '1.0.0',
  };
  const SALT = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const EXPECTED_FINGERPRINT = 'TORK-DNA-v2-cb8605eed6b4878f';

  it('reproduces the known fingerprint accepted by production', () => {
    const cj = canonicalJson(CANONICAL);
    expect(computeSaltedFingerprint(cj, SALT)).toBe(EXPECTED_FINGERPRINT);
  });

  it('buildCanonical reproduces the same shape', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'redact',
      piiTypes: ['email'],
      piiCount: 1,
      hitl: false,
      ts: 1785700000,
    });
    expect(canonical).toEqual(CANONICAL);
  });

  it('end to end from buildCanonical reproduces the fingerprint', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'redact',
      piiTypes: ['email'],
      piiCount: 1,
      hitl: false,
      ts: 1785700000,
    });
    const cj = canonicalJson(canonical);
    expect(computeSaltedFingerprint(cj, SALT)).toBe(EXPECTED_FINGERPRINT);
  });
});

describe('canonical JSON encoding', () => {
  it('has no whitespace', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'allow',
      piiTypes: [],
      piiCount: 0,
      hitl: false,
      ts: 1785700000,
    });
    const cj = canonicalJson(canonical);
    expect(cj).not.toContain(' ');
    expect(cj).not.toContain('\n');
    expect(cj).not.toContain('\t');
  });

  it('sorts keys alphabetically', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'redact',
      piiTypes: ['email', 'ssn'],
      piiCount: 2,
      hitl: true,
      ts: 1785700000,
    });
    const cj = canonicalJson(canonical);
    const parsedOrder = Object.keys(JSON.parse(cj));
    expect(parsedOrder).toEqual([...parsedOrder].sort());
    const keysInStringOrder = Object.keys(canonical).sort();
    expect(cj.startsWith(`{"${keysInStringOrder[0]}"`)).toBe(true);
  });

  it('lowercases booleans', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'allow',
      piiTypes: [],
      piiCount: 0,
      hitl: true,
      ts: 1785700000,
    });
    const cj = canonicalJson(canonical);
    expect(cj).toContain('"hitl":true');
    expect(cj).not.toContain('True');
    expect(cj).not.toContain('False');
  });

  it('omits absent autonomy_level rather than sending null', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'allow',
      piiTypes: [],
      piiCount: 0,
      hitl: false,
      ts: 1785700000,
    });
    expect(canonical.autonomy_level).toBeUndefined();
    expect('autonomy_level' in canonical).toBe(false);
    const cj = canonicalJson(canonical);
    expect(cj).not.toContain('autonomy_level');
    expect(cj).not.toContain('null');
  });

  it('includes autonomy_level when present', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'allow',
      piiTypes: [],
      piiCount: 0,
      hitl: false,
      ts: 1785700000,
      autonomyLevel: 4,
    });
    expect(canonical.autonomy_level).toBe(4);
    expect(canonicalJson(canonical)).toContain('"autonomy_level":4');
  });

  it('serialises score as an integer with no decimal point', () => {
    const canonical = buildCanonical({
      policyVersion: '1.0.0',
      verdict: 'redact',
      piiTypes: ['email'],
      piiCount: 1,
      hitl: false,
      ts: 1785700000,
    });
    const cj = canonicalJson(canonical);
    expect(cj).toContain('"score":100');
    expect(cj).not.toContain('"score":100.0');
  });
});

describe('classifyRisk', () => {
  it('is always critical on deny', () => {
    expect(classifyRisk([], 'deny')).toBe('critical');
    expect(classifyRisk(['email'], 'deny')).toBe('critical');
  });

  it('is none with no PII', () => {
    expect(classifyRisk([], 'allow')).toBe('none');
  });

  it('classifies high-risk PII', () => {
    expect(classifyRisk(['ssn'], 'redact')).toBe('high');
    expect(classifyRisk(['credit_card'], 'redact')).toBe('high');
  });

  it('classifies medium-risk PII', () => {
    expect(classifyRisk(['us_drivers_license'], 'redact')).toBe('medium');
  });

  it('defaults to low risk for other PII', () => {
    expect(classifyRisk(['email'], 'redact')).toBe('low');
    expect(classifyRisk(['phone'], 'redact')).toBe('low');
  });
});

describe('derivePolicies', () => {
  it('uses pii-redact for redact with pii', () => {
    expect(derivePolicies('redact', ['email'])).toEqual(['pii-redact', 'rate-limit']);
  });

  it('uses pii-deny for deny with pii', () => {
    expect(derivePolicies('deny', ['ssn'])).toEqual(['pii-deny', 'rate-limit']);
  });

  it('uses pii-detect for allow/flag with pii', () => {
    expect(derivePolicies('allow', ['email'])).toEqual(['pii-detect', 'rate-limit']);
    expect(derivePolicies('flag', ['email'])).toEqual(['pii-detect', 'rate-limit']);
  });

  it('is rate-limit only with no pii', () => {
    expect(derivePolicies('allow', [])).toEqual(['rate-limit']);
  });
});

describe('computeScore', () => {
  it('is a perfect 100 for allow with no PII', () => {
    expect(computeScore([], 0, 'allow')).toBe(100);
  });

  it('redact recovers points versus deny', () => {
    const redactScore = computeScore(['email'], 1, 'redact');
    const denyScore = computeScore(['email'], 1, 'deny');
    expect(redactScore).toBeGreaterThan(denyScore);
  });

  it('is bounded between 0 and 100', () => {
    const score = computeScore(['ssn', 'credit_card'], 50, 'deny', 5);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });
});

describe('generateFingerprintSalt', () => {
  it('is 32 lowercase hex chars', () => {
    const salt = generateFingerprintSalt();
    expect(salt).toHaveLength(32);
    expect(salt).toBe(salt.toLowerCase());
    expect(() => BigInt(`0x${salt}`)).not.toThrow();
  });

  it('is random across calls', () => {
    const salts = new Set(Array.from({ length: 20 }, () => generateFingerprintSalt()));
    expect(salts.size).toBe(20);
  });
});
