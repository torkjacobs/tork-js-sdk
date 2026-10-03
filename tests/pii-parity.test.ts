import { describe, it, expect } from 'vitest';
import { PII_PATTERNS, detectPII, type PIIType } from '../src/pii';

/**
 * Parity: every PIIType the SDK declares has a working pattern, and a
 * positive and a negative example. `DECLARED` is typed Record<PIIType, ...>, so
 * adding a value to the PIIType union without adding a case here fails the build.
 */
const CASES: Record<PIIType, { positive: string; negative: string }> = {
  ssn: { positive: 'SSN 123-45-6789', negative: 'ref 12-345-6789' },
  credit_card: { positive: 'Card 4111-1111-1111-1111', negative: 'Card 4111-1111-111' },
  email: { positive: 'mail john@example.com', negative: 'mail john at example dot com' },
  phone: { positive: 'call 555-123-4567', negative: 'call 555-12' },
  address: { positive: 'lives at 123 Main Street', negative: 'lives on Main Street' },
  ip_address: { positive: 'host 192.168.1.1', negative: 'host 999.999.999.999' },
  date_of_birth: { positive: 'DOB 01/15/1990', negative: 'DOB 13/45/1990' },
  passport: { positive: 'passport AB1234567', negative: 'passport ab12' },
  drivers_license: { positive: 'licence D12345678', negative: 'licence D123' },
  bank_account: { positive: 'account 12345678901', negative: 'account 1234567' },
};

describe('declared PII types have patterns (parity)', () => {
  const declared = Object.keys(CASES) as PIIType[];

  it('every declared type has a pattern with a redaction token, and vice versa', () => {
    expect(Object.keys(PII_PATTERNS).sort()).toEqual([...declared].sort());
    for (const t of declared) {
      expect(PII_PATTERNS[t].pattern, t).toBeInstanceOf(RegExp);
      expect(PII_PATTERNS[t].redaction, t).toMatch(/^\[[A-Z_]+\]$/);
    }
  });

  for (const t of declared) {
    it(`${t}: pattern matches the positive example`, () => {
      const re = new RegExp(PII_PATTERNS[t].pattern.source, PII_PATTERNS[t].pattern.flags);
      expect(re.test(CASES[t].positive), t).toBe(true);
    });
    it(`${t}: pattern rejects the negative example`, () => {
      const re = new RegExp(PII_PATTERNS[t].pattern.source, PII_PATTERNS[t].pattern.flags);
      expect(re.test(CASES[t].negative), t).toBe(false);
    });
    it(`${t}: detectPII reports it on the positive example`, () => {
      expect(detectPII(CASES[t].positive).types, t).toContain(t);
    });
    it(`${t}: detectPII does not report it on the negative example`, () => {
      expect(detectPII(CASES[t].negative).types, t).not.toContain(t);
    });
  }
});
