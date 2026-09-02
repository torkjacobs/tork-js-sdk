/**
 * The on-device PII detector.
 *
 * Moved out of index.ts verbatim (patterns, redaction labels and detectPII
 * semantics are unchanged) so tool-result-scan.ts can reuse the SAME detector
 * without importing index.ts, which imports it back -- a cycle. index.ts
 * re-exports everything here, so the public surface is identical.
 *
 * Everything in this module is pure and local: no I/O, no network, no clock.
 */

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

/**
 * Detect PII in text and return detection results with redacted text
 */
export function detectPII(
  text: string,
  customPatterns?: Record<string, RegExp>
): PIIDetectionResult {
  const matches: PIIMatch[] = [];
  const detectedTypes = new Set<PIIType>();
  let redactedText = text;

  // Check each PII pattern
  for (const [type, { pattern, redaction }] of Object.entries(PII_PATTERNS)) {
    const piiType = type as PIIType;
    // Reset regex lastIndex
    pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    const regex = new RegExp(pattern.source, pattern.flags);

    while ((match = regex.exec(text)) !== null) {
      detectedTypes.add(piiType);
      matches.push({
        type: piiType,
        value: '[REDACTED]',
        startIndex: match.index,
        endIndex: match.index + match[0].length,
      });
    }

    // Redact this pattern type
    redactedText = redactedText.replace(new RegExp(pattern.source, pattern.flags), redaction);
  }

  // Apply custom patterns if provided
  if (customPatterns) {
    for (const [name, pattern] of Object.entries(customPatterns)) {
      redactedText = redactedText.replace(pattern, `[${name.toUpperCase()}_REDACTED]`);
    }
  }

  return {
    hasPII: matches.length > 0,
    types: Array.from(detectedTypes),
    count: matches.length,
    matches,
    redactedText,
  };
}
