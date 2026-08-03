/**
 * TORK-DNA-v2 canonical form + salted fingerprinting.
 *
 * Ports lib/governance/dna-fingerprint.ts (classifyRisk / computeScore /
 * derivePolicies / buildCanonical) byte-for-byte, same as the Python SDK's
 * core.py port. The attestations endpoint independently recomputes
 * risk/policies from the submitted canonical_json and 422s on mismatch, so
 * this must track the TypeScript source exactly, not just approximate it.
 *
 * NOTE ON PII VOCABULARY: PIIType values here (e.g. "passport",
 * "drivers_license") do not all match the server's risk-tier vocabulary
 * (which expects "us_passport", "us_drivers_license"). That is not a bug in
 * this port -- classifyRisk() below runs on whatever strings are passed to
 * it, so the fingerprint stays internally self-consistent either way. It
 * does mean a few PII types are silently scored as "low" risk instead of
 * the "high"/"medium" server-side equivalents would be.
 */

import { createHash, randomBytes } from 'crypto';

export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface CanonicalForm {
  autonomy_level?: number;
  hitl: boolean;
  pii: string[];
  policies: string[];
  risk: RiskLevel;
  score: number;
  ts: number;
  v: string;
}

const HIGH_RISK_PII = new Set([
  'ssn',
  'ssn_undashed',
  'credit_card',
  'credit_card_amex',
  'bank_routing',
  'us_passport',
  'french_ssn',
]);

const MEDIUM_RISK_PII = new Set([
  'us_ein',
  'us_drivers_license',
  'uk_nino',
  'uk_nhs',
  'iban',
  'swift_bic',
  'npi',
  'dea_number',
  'medical_record',
  'au_tfn',
  'au_medicare',
  'crypto_btc',
  'crypto_eth',
]);

/** Port of classifyRisk() in lib/governance/dna-fingerprint.ts. */
export function classifyRisk(piiTypes: string[], verdict: string): RiskLevel {
  if (verdict === 'deny') return 'critical';
  if (piiTypes.length === 0) return 'none';
  if (piiTypes.some((t) => HIGH_RISK_PII.has(t))) return 'high';
  if (piiTypes.some((t) => MEDIUM_RISK_PII.has(t))) return 'medium';
  return 'low';
}

/** Port of computeScore() in lib/governance/dna-fingerprint.ts. */
export function computeScore(
  piiTypes: string[],
  piiCount: number,
  verdict: string,
  autonomyLevel?: number
): number {
  if (piiCount === 0 && verdict === 'allow' && (autonomyLevel === undefined || autonomyLevel <= 3)) {
    return 100;
  }

  let score = 100;

  for (const t of piiTypes) {
    if (HIGH_RISK_PII.has(t)) {
      score -= 15;
    } else if (MEDIUM_RISK_PII.has(t)) {
      score -= 10;
    } else {
      score -= 5;
    }
  }

  score -= Math.min(15, Math.floor(Math.log2(piiCount + 1)) * 3);

  if (verdict === 'redact') score += 10;
  if (verdict === 'deny') score -= 10;

  if (autonomyLevel !== undefined && autonomyLevel >= 4) {
    score -= (autonomyLevel - 3) * 5;
  }

  return Math.max(0, Math.min(100, score));
}

/** Port of derivePolicies() in lib/governance/dna-fingerprint.ts. */
export function derivePolicies(verdict: string, piiTypes: string[]): string[] {
  const policies: string[] = [];
  if (piiTypes.length > 0) {
    if (verdict === 'redact') {
      policies.push('pii-redact');
    } else if (verdict === 'deny') {
      policies.push('pii-deny');
    } else {
      policies.push('pii-detect');
    }
  }
  policies.push('rate-limit');
  policies.sort();
  return policies;
}

export interface BuildCanonicalParams {
  policyVersion: string;
  verdict: string;
  piiTypes: string[];
  piiCount: number;
  hitl: boolean;
  ts: number;
  autonomyLevel?: number;
}

/** Port of buildCanonical() in lib/governance/dna-fingerprint.ts. */
export function buildCanonical(params: BuildCanonicalParams): CanonicalForm {
  const piiSorted = Array.from(new Set(params.piiTypes)).sort();
  const canonical: CanonicalForm = {
    hitl: params.hitl,
    pii: piiSorted,
    policies: derivePolicies(params.verdict, piiSorted),
    risk: classifyRisk(piiSorted, params.verdict),
    score: computeScore(piiSorted, params.piiCount, params.verdict, params.autonomyLevel),
    ts: params.ts,
    v: params.policyVersion,
  };
  if (params.autonomyLevel !== undefined) {
    canonical.autonomy_level = params.autonomyLevel;
  }
  return canonical;
}

/**
 * Byte-exact serialisation the server re-hashes and re-derives from: keys
 * sorted alphabetically, no whitespace, lowercase booleans, integers with no
 * decimal point, autonomy_level omitted entirely (never null) when absent.
 */
export function canonicalJson(canonical: CanonicalForm): string {
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(canonical).sort()) {
    ordered[key] = (canonical as unknown as Record<string, unknown>)[key];
  }
  return JSON.stringify(ordered);
}

/** 32 lowercase hex chars (16 random bytes). */
export function generateFingerprintSalt(): string {
  return randomBytes(16).toString('hex');
}

/** TORK-DNA-v2-{first 16 hex chars of sha256(canonicalJson + '|' + salt)}. */
export function computeSaltedFingerprint(canonicalJsonStr: string, salt: string): string {
  const digest = createHash('sha256').update(`${canonicalJsonStr}|${salt}`, 'utf-8').digest('hex');
  return `TORK-DNA-v2-${digest.slice(0, 16)}`;
}

/**
 * A (ts, decidedAt) pair guaranteed to satisfy the server's check that
 * decidedAt, floored to the second, equals canonical.ts exactly.
 */
export function decidedAtPair(ts?: number): [number, string] {
  const resolvedTs = ts ?? Math.floor(Date.now() / 1000);
  const decidedAt = new Date(resolvedTs * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return [resolvedTs, decidedAt];
}
