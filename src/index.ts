/**
 * Tork Governance SDK
 * On-device AI governance with PII detection, redaction, and cryptographic receipts
 */

import { createHash, randomBytes } from 'crypto';
import {
  buildCanonical,
  canonicalJson,
  computeSaltedFingerprint,
  decidedAtPair,
  generateFingerprintSalt,
} from './dna-fingerprint';
import {
  disabledAttestationReport,
  failedAttestationReport,
  startAttestationReport,
  type AttestationReport,
} from './attestation-report';

export type { AttestationReport } from './attestation-report';

// ============================================================================
// Types
// ============================================================================

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

export type GovernanceAction = 'allow' | 'deny' | 'redact' | 'escalate';

export interface PIIDetectionResult {
  hasPII: boolean;
  types: PIIType[];
  count: number;
  matches: PIIMatch[];
  redactedText: string;
}

export interface PIIMatch {
  type: PIIType;
  value: string;
  startIndex: number;
  endIndex: number;
}

export interface GovernanceReceipt {
  receiptId: string;
  timestamp: string;
  inputHash: string;
  outputHash: string;
  action: GovernanceAction;
  policyVersion: string;
  processingTimeNs: bigint;
  /** Session context echoed back when agent/session fields are provided. */
  sessionContext?: SessionContext;
}

/**
 * Agent/session context for multi-agent governance tracking.
 */
export interface SessionContext {
  /** Identifier for the agent making the call. */
  agent_id?: string;
  /** Role of the agent: "planner", "worker", or "judge". */
  agent_role?: string;
  /** Groups all calls from the same agent session. */
  session_id?: string;
  /** Position in the conversation (1, 2, 3...). */
  session_turn?: number;
}

export interface GovernOptions {
  region?: string[];
  industry?: string;
  /** Identifier for the agent making the call. */
  agent_id?: string;
  /** Role of the agent: "planner", "worker", or "judge". */
  agent_role?: string;
  /** Groups all calls from the same agent session. */
  session_id?: string;
  /** Position in the conversation (1, 2, 3...). */
  session_turn?: number;
}

export interface GovernanceResult {
  action: GovernanceAction;
  output: string;
  pii: PIIDetectionResult;
  receipt: GovernanceReceipt;
  region?: string[];
  industry?: string;
  /** Session context when agent/session fields are provided. */
  sessionContext?: SessionContext;
  /** Outcome of the optional tork.network attestation report for this call. */
  report: AttestationReport;
}

export interface TorkConfig {
  policyVersion?: string;
  defaultAction?: GovernanceAction;
  customPatterns?: Record<string, RegExp>;
  /**
   * Optional. PII detection and the governance decision are ALWAYS computed
   * on-device regardless of this value. Supplying a key additionally turns
   * on best-effort, metadata-only reporting of each decision to
   * https://tork.network/api/v1/attestations -- never input text, output
   * text, or PII values. The resulting row is recorded as a CLIENT
   * ATTESTATION (attested_by='client'): a self-reported, internally
   * consistent claim that Tork did not itself execute or independently
   * verify, not a Tork-verified decision. Reporting runs on a detached
   * promise and never throws -- check GovernanceResult.report
   * (attempted/succeeded/receiptId/reason) for the outcome, or call
   * report.wait() for the confirmed outcome before proceeding. Omit this to
   * keep the SDK fully local with zero network calls. Providing a value
   * logs a one-time (per process) warning describing exactly what is sent.
   */
  apiKey?: string;
}

export interface TorkStats {
  totalCalls: number;
  totalPIIDetected: number;
  avgProcessingTimeNs: bigint;
  actionCounts: Record<GovernanceAction, number>;
}

// ============================================================================
// PII Patterns
// ============================================================================

const PII_PATTERNS: Record<PIIType, { pattern: RegExp; redaction: string }> = {
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

// ============================================================================
// Attestation reporting (opt-in via TorkConfig.apiKey)
// ============================================================================

// GovernanceAction -> the verdict vocabulary the attestations endpoint
// persists (allow | redact | deny | flag; 'block' normalises to 'deny' on
// the server, never used here). ESCALATE has no analogue in the documented
// 3-value contract (allow|redact|deny); the endpoint's own validator accepts
// a 4th verdict, 'flag', for exactly the human-in-the-loop case ESCALATE
// represents, so it maps there rather than being silently coerced into
// allow or deny.
const ACTION_TO_VERDICT: Record<GovernanceAction, string> = {
  allow: 'allow',
  redact: 'redact',
  deny: 'deny',
  escalate: 'flag',
};

const API_KEY_REPORTING_MESSAGE =
  'You passed an apiKey to tork-governance: reporting to tork.network is now ON. ' +
  'PII detection, redaction, and the returned decision are still computed entirely ' +
  'on-device and are never delayed or changed by this. After each govern() call, ' +
  'this SDK separately POSTs a METADATA-ONLY attestation to ' +
  'https://tork.network/api/v1/attestations: the action taken, PII type labels and ' +
  'counts, a risk/score classification, policy labels, and a salted fingerprint. ' +
  'It NEVER sends input text, output text, redacted content, or ' +
  'PII values -- those never leave this device. The resulting row is recorded as a ' +
  "CLIENT ATTESTATION (attested_by='client'): a self-reported, internally-consistent " +
  'claim that Tork did not itself execute or independently verify, not a ' +
  'Tork-verified decision. Reporting runs on a detached promise and never throws -- ' +
  'check GovernanceResult.report (attempted/succeeded/receiptId/reason) for the ' +
  'outcome, or call report.wait() if you need the confirmed outcome before ' +
  'proceeding. Omit the apiKey option to keep this SDK fully local with zero ' +
  'network calls.';

// Module-level flag so the apiKey warning fires at most once per process.
let apiKeyWarningEmitted = false;

function warnApiKeyReporting(): void {
  if (apiKeyWarningEmitted) return;
  apiKeyWarningEmitted = true;
  if (typeof process !== 'undefined' && typeof process.emitWarning === 'function') {
    process.emitWarning(API_KEY_REPORTING_MESSAGE, 'UserWarning');
  } else {
    // eslint-disable-next-line no-console
    console.warn(API_KEY_REPORTING_MESSAGE);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate a SHA256 hash of text with prefix
 */
export function hashText(text: string): string {
  const hash = createHash('sha256').update(text).digest('hex');
  return `sha256:${hash}`;
}

/**
 * Generate a unique receipt ID
 */
export function generateReceiptId(): string {
  const bytes = randomBytes(16);
  return `rcpt_${bytes.toString('hex')}`;
}

/**
 * Get high-resolution timestamp in nanoseconds
 */
function getNanoseconds(): bigint {
  return process.hrtime.bigint();
}

// ============================================================================
// PII Detection
// ============================================================================

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

// ============================================================================
// Tork Class
// ============================================================================

/**
 * Main Tork governance class
 */
export class Tork {
  private config: Required<Omit<TorkConfig, 'apiKey'>> & Pick<TorkConfig, 'apiKey'>;
  private stats: {
    totalCalls: number;
    totalPIIDetected: number;
    totalProcessingTimeNs: bigint;
    actionCounts: Record<GovernanceAction, number>;
  };

  constructor(config: TorkConfig = {}) {
    this.config = {
      policyVersion: config.policyVersion ?? '1.0.0',
      defaultAction: config.defaultAction ?? 'redact',
      customPatterns: config.customPatterns ?? {},
      apiKey: config.apiKey,
    };

    if (config.apiKey) {
      warnApiKeyReporting();
    }

    this.stats = {
      totalCalls: 0,
      totalPIIDetected: 0,
      totalProcessingTimeNs: BigInt(0),
      actionCounts: {
        allow: 0,
        deny: 0,
        redact: 0,
        escalate: 0,
      },
    };
  }

  /**
   * Apply governance to input text
   * @param input - The text to govern
   * @param options - Optional region and industry parameters for PII v1.1
   */
  govern(input: string, options?: GovernOptions): GovernanceResult {
    const startTime = getNanoseconds();

    // Detect PII
    const pii = detectPII(input, this.config.customPatterns);

    // Determine action
    let action: GovernanceAction;
    let output: string;

    if (pii.hasPII) {
      action = this.config.defaultAction;
      output = pii.redactedText;
    } else {
      action = 'allow';
      output = input;
    }

    const endTime = getNanoseconds();
    const processingTimeNs = endTime - startTime;

    // Build session context if any agent/session fields are provided
    const sessionContext: SessionContext | undefined =
      options?.agent_id ?? options?.agent_role ?? options?.session_id ?? options?.session_turn
        ? {
            ...(options?.agent_id != null && { agent_id: options.agent_id }),
            ...(options?.agent_role != null && { agent_role: options.agent_role }),
            ...(options?.session_id != null && { session_id: options.session_id }),
            ...(options?.session_turn != null && { session_turn: options.session_turn }),
          }
        : undefined;

    // Generate receipt
    const receipt: GovernanceReceipt = {
      receiptId: generateReceiptId(),
      timestamp: new Date().toISOString(),
      inputHash: hashText(input),
      outputHash: hashText(output),
      action,
      policyVersion: this.config.policyVersion,
      processingTimeNs,
      ...(sessionContext && { sessionContext }),
    };

    // Update stats
    this.stats.totalCalls++;
    if (pii.hasPII) {
      this.stats.totalPIIDetected++;
    }
    this.stats.totalProcessingTimeNs += processingTimeNs;
    this.stats.actionCounts[action]++;

    // Optional metadata-only reporting to tork.network. The decision above
    // (action/output/pii/receipt) is already final by this point and
    // reporting can never change it. Canonical-form/fingerprint
    // construction is local and stays synchronous; the network call (and
    // its one retry) runs on a detached promise so govern() always returns
    // immediately regardless of endpoint latency, and a reporting failure
    // never throws into the caller.
    let report: AttestationReport;
    if (this.config.apiKey) {
      const apiKey = this.config.apiKey;
      try {
        const verdict = ACTION_TO_VERDICT[action];
        const [ts, decidedAt] = decidedAtPair();
        const canonical = buildCanonical({
          policyVersion: this.config.policyVersion,
          verdict,
          piiTypes: pii.types,
          piiCount: pii.count,
          hitl: action === 'escalate',
          ts,
        });
        const cjson = canonicalJson(canonical);
        const salt = generateFingerprintSalt();
        const fingerprint = computeSaltedFingerprint(cjson, salt);

        report = startAttestationReport({
          apiKey,
          clientEventId: receipt.receiptId,
          verdict,
          canonicalJsonStr: cjson,
          salt,
          fingerprint,
          decidedAt,
        });
      } catch (exc) {
        report = failedAttestationReport(
          `failed to build attestation: ${exc instanceof Error ? `${exc.name}: ${exc.message}` : String(exc)}`
        );
      }
    } else {
      report = disabledAttestationReport('apiKey not configured; reporting is disabled');
    }

    return {
      action,
      output,
      pii,
      receipt,
      report,
      ...(options?.region && { region: options.region }),
      ...(options?.industry && { industry: options.industry }),
      ...(sessionContext && { sessionContext }),
    };
  }

  /**
   * Get current statistics
   */
  getStats(): TorkStats {
    return {
      totalCalls: this.stats.totalCalls,
      totalPIIDetected: this.stats.totalPIIDetected,
      avgProcessingTimeNs:
        this.stats.totalCalls > 0
          ? this.stats.totalProcessingTimeNs / BigInt(this.stats.totalCalls)
          : BigInt(0),
      actionCounts: { ...this.stats.actionCounts },
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      totalCalls: 0,
      totalPIIDetected: 0,
      totalProcessingTimeNs: BigInt(0),
      actionCounts: {
        allow: 0,
        deny: 0,
        redact: 0,
        escalate: 0,
      },
    };
  }

  /**
   * Get current configuration
   */
  getConfig(): TorkConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<TorkConfig>): void {
    if (config.policyVersion !== undefined) {
      this.config.policyVersion = config.policyVersion;
    }
    if (config.defaultAction !== undefined) {
      this.config.defaultAction = config.defaultAction;
    }
    if (config.customPatterns !== undefined) {
      this.config.customPatterns = config.customPatterns;
    }
    if (config.apiKey !== undefined) {
      this.config.apiKey = config.apiKey;
      if (config.apiKey) {
        warnApiKeyReporting();
      }
    }
  }
}

// ============================================================================
// Framework Middleware Exports
// ============================================================================

// Re-export every framework adapter from the middleware barrel so all 24
// adapters are available as top-level named exports from `tork-governance`.
// This is the single source of truth for the adapter surface; the barrel is a
// superset of the symbols previously enumerated here (it also adds Hono's
// handler, the extended LangChain exports, Hapi, Mastra, Microsoft Agents, and
// the 11 adapters — Remix, SvelteKit, Nuxt, Astro, Elysia, Deno Fresh,
// Bun.serve, tRPC, GraphQL Yoga, Socket.io, WebSocket — that tsup never bundled
// because it only builds from this entry file.
export * from './middleware';

// ============================================================================
// Default Export
// ============================================================================

export default Tork;
