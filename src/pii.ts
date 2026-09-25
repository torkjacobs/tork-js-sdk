/**
 * The on-device PII detector.
 *
 * Two layers, both pure and local -- no I/O, no network, no clock:
 *
 *   L0, the ten universal types below (SSN, card, email, ...). Unchanged since
 *   0.1.0 and still the SDK's own; the country bundle deliberately excludes
 *   them.
 *
 *   The COUNTRY layer in ./pii-country.ts: 23 country profiles and 50 patterns
 *   generated from the cloud's own registry, gated by content activation, a
 *   keyword window and 20 check digits. Added in 0.13.0.
 *
 * REDACTION IS NOW ONE PASS. Until 0.12.0 each type was redacted with its own
 * String.replace over the text the previous type had already rewritten, while
 * `matches` carried indices into the ORIGINAL text. Two types matching
 * overlapping spans could therefore leave half an identifier standing next to a
 * redaction token -- digits exposed in something the caller had been told was
 * redacted. Every match is now collected against the original text, overlaps
 * are resolved before anything is rewritten, and the surviving spans are
 * spliced right to left in a single pass. See the no-partial-redaction tests in
 * ./pii-country.test.ts.
 *
 * The public surface -- detectPII, PII_PATTERNS, PIIType, PIIMatch,
 * PIIDetectionResult -- is unchanged. PIIDetectionResult gains three optional
 * fields; nothing was removed or renamed.
 */

import {
  detectCountryPII,
  inferRegions,
  patternsForRegions,
  applyRedactions,
  type CountryPIIMatch,
} from './pii-country';

export type PIIType =
  | 'ssn'
  | 'credit_card'
  | 'email'
  | 'phone'
  | 'address'
  | 'ip_address'
  | 'date_of_birth'
  | 'passport'
  | 'drivers_license'
  | 'bank_account';

export interface PIIMatch {
  type: PIIType;
  value: string;
  startIndex: number;
  endIndex: number;
}

export interface PIIDetectionResult {
  hasPII: boolean;
  types: PIIType[];
  count: number;
  matches: PIIMatch[];
  redactedText: string;
  /**
   * Country-registry matches. Separate from `matches` so that `PIIType` stays
   * the closed ten-value union it has always been and an exhaustive switch in
   * caller code still compiles.
   */
  countryMatches?: CountryPIIMatch[];
  /** Redaction labels of those matches, e.g. ['NATIONAL_ID']. */
  countryLabels?: string[];
  /** Country profiles the text activated, in registry order. */
  regions?: string[];
}

export const PII_PATTERNS: Record<PIIType, { pattern: RegExp; redaction: string }> = {
  ssn: {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    redaction: '[SSN_REDACTED]',
  },
  credit_card: {
    pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    redaction: '[CARD_REDACTED]',
  },
  email: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    redaction: '[EMAIL_REDACTED]',
  },
  phone: {
    pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    redaction: '[PHONE_REDACTED]',
  },
  address: {
    pattern: /\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b/gi,
    redaction: '[ADDRESS_REDACTED]',
  },
  ip_address: {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    redaction: '[IP_REDACTED]',
  },
  date_of_birth: {
    pattern: /\b(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b/g,
    redaction: '[DOB_REDACTED]',
  },
  passport: {
    pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
    redaction: '[PASSPORT_REDACTED]',
  },
  drivers_license: {
    pattern: /\b[A-Z]\d{7,14}\b/g,
    redaction: '[DL_REDACTED]',
  },
  bank_account: {
    pattern: /\b\d{8,17}\b/g,
    redaction: '[ACCOUNT_REDACTED]',
  },
};

interface Span {
  startIndex: number;
  endIndex: number;
  redaction: string;
}

/** The span with leading and trailing non-alphanumeric characters removed. */
function trimmedCore(content: string, start: number, end: number): [number, number] {
  let s = start;
  let e = end;
  while (s < e && !/[0-9A-Za-z]/.test(content[s])) s++;
  while (e > s && !/[0-9A-Za-z]/.test(content[e - 1])) e--;
  return s === e ? [start, end] : [s, e];
}

/**
 * Detect PII in text and return detection results with redacted text.
 *
 * `customPatterns` keeps its 0.1.0 behaviour: each is applied to the redacted
 * text by name, after the two detector layers.
 *
 * `regionOverride` forces a set of country profiles on instead of inferring
 * them from the content, and is what `Tork#govern`'s `region` option now feeds.
 */
export function detectPII(
  text: string,
  customPatterns?: Record<string, RegExp>,
  regionOverride?: string[]
): PIIDetectionResult {
  const matches: PIIMatch[] = [];
  const detectedTypes = new Set<PIIType>();

  // ── L0: collect every match against the ORIGINAL text ──────────────────────
  const l0: { match: PIIMatch; redaction: string }[] = [];
  for (const [type, { pattern, redaction }] of Object.entries(PII_PATTERNS)) {
    const piiType = type as PIIType;
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) {
        regex.lastIndex++;
        continue;
      }
      l0.push({
        match: {
          type: piiType,
          value: '[REDACTED]',
          startIndex: match.index,
          endIndex: match.index + match[0].length,
        },
        redaction,
      });
    }
  }

  // ── Country layer ─────────────────────────────────────────────────────────
  // An explicit `region` from the caller is authoritative; otherwise the
  // country profiles are activated from the content itself. Before 0.13.0 the
  // `region` option was accepted, echoed back in the result, and never used to
  // detect anything.
  const regions =
    regionOverride && regionOverride.length > 0
      ? regionOverride.map((r) => r.toUpperCase())
      : inferRegions(text);
  const countryMatches: CountryPIIMatch[] = detectCountryPII(
    text,
    patternsForRegions(regions),
  );

  // ── Resolve overlaps before anything is rewritten ─────────────────────────
  // A country identifier supersedes any L0 span it fully contains: the cloud
  // does the same, which is how a Saudi national ID stops coming back as
  // [PHONE_REDACTED]. Within L0, the first pattern to claim a span keeps it.
  const spans: Span[] = [];
  const claimed: [number, number][] = [];

  for (const c of countryMatches) {
    spans.push({ startIndex: c.startIndex, endIndex: c.endIndex, redaction: c.redaction });
    claimed.push([c.startIndex, c.endIndex]);
  }

  for (const { match, redaction } of l0) {
    const s = match.startIndex;
    const e = match.endIndex;
    const overlapping = claimed.filter(([rs, re]) => s < re && e > rs);
    if (overlapping.length > 0) {
      // Superseded by, or colliding with, something already claimed.
      const swallowsAll = overlapping.every(([rs, re]) => {
        const [cs, ce] = trimmedCore(text, rs, re);
        return s <= cs && e >= ce;
      });
      if (!swallowsAll) continue;
      // An L0 span that fully contains a country span still loses: the country
      // label is the more specific claim.
      const hitsCountry = overlapping.some(([rs, re]) =>
        countryMatches.some((c) => c.startIndex === rs && c.endIndex === re),
      );
      if (hitsCountry) continue;
      for (const [os, oe] of overlapping) {
        const ci = claimed.findIndex(([rs, re]) => rs === os && re === oe);
        if (ci !== -1) claimed.splice(ci, 1);
        const si = spans.findIndex((sp) => sp.startIndex === os && sp.endIndex === oe);
        if (si !== -1) spans.splice(si, 1);
      }
    }
    claimed.push([s, e]);
    spans.push({ startIndex: s, endIndex: e, redaction });
    matches.push(match);
    detectedTypes.add(match.type);
  }

  let redactedText = applyRedactions(text, spans);

  // Custom patterns keep their original, caller-defined behaviour.
  if (customPatterns) {
    for (const [name, pattern] of Object.entries(customPatterns)) {
      redactedText = redactedText.replace(pattern, `[${name.toUpperCase()}_REDACTED]`);
    }
  }

  matches.sort((a, b) => a.startIndex - b.startIndex);

  return {
    hasPII: matches.length + countryMatches.length > 0,
    types: Array.from(detectedTypes),
    count: matches.length + countryMatches.length,
    matches,
    redactedText,
    countryMatches,
    countryLabels: Array.from(new Set(countryMatches.map((c) => c.label))),
    regions,
  };
}
