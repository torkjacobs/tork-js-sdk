/**
 * Tork Governance SDK
 * On-device AI governance with PII detection, redaction, and cryptographic receipts
 */

import { createHash, randomBytes } from 'crypto';

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
}

export interface TorkConfig {
  policyVersion?: string;
  defaultAction?: GovernanceAction;
  customPatterns?: Record<string, RegExp>;
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
  private config: Required<TorkConfig>;
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
    };

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

    return {
      action,
      output,
      pii,
      receipt,
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
