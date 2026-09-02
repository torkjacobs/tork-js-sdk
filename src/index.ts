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
import { detectPII, type PIIDetectionResult } from './pii';
import {
  buildToolResultScanBlock,
  scanInjectionCount,
  scanPIICount,
  scanPIITypes,
  scanToolResult,
  type ToolResultScanInput,
  type ToolResultScanOptions,
  type ToolResultScanReceiptBlock,
  type ToolResultScanResult,
} from './tool-result-scan';
import { SDK_VERSION } from './version';

export type { AttestationReport } from './attestation-report';

// The PII detector lives in ./pii so ./tool-result-scan can reuse it without
// importing this module back. Re-exported here so the public surface of
// `tork-governance` is unchanged.
export { detectPII, PII_PATTERNS } from './pii';
export type { PIIType, PIIMatch, PIIDetectionResult } from './pii';

export {
  scanToolResult,
  buildToolResultScanBlock,
  INJECTION_HEURISTIC_PREFIX,
  INJECTION_RULESET,
  INJECTION_TYPES,
} from './tool-result-scan';
export type {
  ToolResultFinding,
  ToolResultFindingKind,
  ToolResultScanInput,
  ToolResultScanOptions,
  ToolResultScanResult,
  ToolResultScanReceiptBlock,
} from './tool-result-scan';

export { SDK_VERSION } from './version';

// ============================================================================
// Types
// ============================================================================

export type GovernanceAction = 'allow' | 'deny' | 'redact' | 'escalate';

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
  /**
   * Present only on receipts produced by `Tork#scanToolResult`. Records the
   * tool-result scan as a CLIENT-ATTESTED, edge-captured control: counts by
   * kind and type, the tool it came from, and the SDK that ran it -- never
   * the payload. snake_case and alphabetically ordered on purpose: this
   * block is the cross-SDK portable artifact (see ./tool-result-scan).
   */
  tool_result_scan?: ToolResultScanReceiptBlock;
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

/**
 * What `Tork#scanToolResult` returns: the pure scan result, plus the receipt
 * recording it and the outcome of the optional attestation report. The four
 * scan fields (`sanitized`, `findings`, `blocked`, `reason`) are exactly the
 * shape of the standalone `scanToolResult()` function's return value, so
 * either form can be consumed by the same code.
 */
export interface GovernedToolResultScanResult extends ToolResultScanResult {
  /** Carries the `tool_result_scan` block. */
  receipt: GovernanceReceipt;
  /** Outcome of the optional tork.network attestation report for this scan. */
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

/**
 * Deterministic serialisation for hashing a tool-result payload: object keys
 * sorted, so two structurally identical payloads always hash the same
 * regardless of key insertion order. Cycles and non-JSON values (functions,
 * symbols, bigints) collapse to a stable placeholder rather than throwing --
 * a receipt must never fail to be produced because a tool returned something
 * exotic. The output is fed straight into SHA256 and is never stored or sent.
 */
function stableStringify(value: unknown, seen: WeakSet<object> = new WeakSet()): string {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'string') return JSON.stringify(value);
  if (type === 'number') return Number.isFinite(value as number) ? String(value) : '"[non-finite]"';
  if (type === 'boolean') return String(value);
  if (type === 'bigint') return `"${String(value)}n"`;
  if (type === 'undefined') return '"[undefined]"';
  if (type === 'function' || type === 'symbol') return `"[${type}]"`;

  const obj = value as object;
  if (seen.has(obj)) return '"[circular]"';
  seen.add(obj);

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item, seen)).join(',')}]`;
  }
  if (value instanceof Date) return JSON.stringify(value.toISOString());

  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v, seen)}`).join(',')}}`;
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
    const report = this.startReport({
      clientEventId: receipt.receiptId,
      action,
      piiTypes: pii.types,
      piiCount: pii.count,
    });

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
   * Scan a tool result (MCP server response, or any external system's output)
   * for PII and prompt injection BEFORE it is appended to model context, and
   * record the scan on a receipt.
   *
   * The scan itself is the pure `scanToolResult()` function -- on-device,
   * synchronous, zero network calls, using the same PII detector as
   * `govern()`. This method adds the receipt: `receipt.tool_result_scan`
   * carries counts by kind and type, the tool name, the server URI, whether
   * the result was blocked, and the SDK version. It never carries the
   * payload, a matched substring, or a location path.
   *
   * This is a CLIENT-SIDE, CLIENT-ATTESTED control: it runs in the caller's
   * process, so the receipt records `attested_by: 'client'` and
   * `capture_mode: 'edge'` -- Tork did not execute this scan and cannot
   * verify it ran at all. Enforcement at the gateway, where a caller cannot
   * skip the scan, is a separate and later control.
   */
  scanToolResult(
    input: ToolResultScanInput,
    options: ToolResultScanOptions = {}
  ): GovernedToolResultScanResult {
    const startTime = getNanoseconds();

    const scan = scanToolResult(input, {
      ...options,
      customPatterns: options.customPatterns ?? this.config.customPatterns,
    });

    // Fixed mapping, deliberately NOT config.defaultAction: unlike govern(),
    // this path always returns masked output when it returns any, so the
    // action must describe what actually happened to the tool result. Every
    // SDK mirroring this must use the same mapping.
    //   blocked            -> deny     (nothing is returned to append)
    //   injection detected -> escalate (returned, flagged for a human)
    //   PII masked         -> redact
    //   nothing found      -> allow
    const piiTypes = scanPIITypes(scan.findings);
    const piiCount = scanPIICount(scan.findings);
    const injectionCount = scanInjectionCount(scan.findings);

    let action: GovernanceAction;
    if (scan.blocked) {
      action = 'deny';
    } else if (injectionCount > 0) {
      action = 'escalate';
    } else if (piiCount > 0) {
      action = 'redact';
    } else {
      action = 'allow';
    }

    const endTime = getNanoseconds();
    const processingTimeNs = endTime - startTime;

    // Hashes, not content: hashText is SHA256, so neither the payload nor the
    // sanitized copy is recoverable from the receipt. A blocked scan has no
    // output to hash and records the hash of the empty string.
    const receipt: GovernanceReceipt = {
      receiptId: generateReceiptId(),
      timestamp: new Date().toISOString(),
      inputHash: hashText(stableStringify(input.payload)),
      outputHash: hashText(scan.blocked ? '' : stableStringify(scan.sanitized)),
      action,
      policyVersion: this.config.policyVersion,
      processingTimeNs,
      tool_result_scan: buildToolResultScanBlock({
        toolName: input.toolName,
        serverUri: input.serverUri,
        result: scan,
        sdkVersion: SDK_VERSION,
      }),
    };

    this.stats.totalCalls++;
    if (piiCount > 0) {
      this.stats.totalPIIDetected++;
    }
    this.stats.totalProcessingTimeNs += processingTimeNs;
    this.stats.actionCounts[action]++;

    // Reporting, when an apiKey is configured, uses the SAME attestation
    // contract as govern() and adds no fields to it. The tool_result_scan
    // block is NOT transmitted: POST /api/v1/attestations validates a fixed
    // field set and there is no column for it, so sending it would be
    // silently dropped -- and a silently dropped block would read, to a
    // caller, exactly like a recorded one. What the endpoint does receive is
    // the decision this scan produced (deny/flag/redact/allow) plus the PII
    // type labels and count, which it already accepts and re-derives.
    const report = this.startReport({
      clientEventId: receipt.receiptId,
      action,
      piiTypes,
      piiCount,
    });

    return { ...scan, receipt, report };
  }

  /**
   * Optional metadata-only reporting to tork.network, shared by govern() and
   * scanToolResult(). The local decision is always already final by the time
   * this is called and reporting can never change it. Canonical-form and
   * fingerprint construction are local and stay synchronous; the network call
   * (and its one retry) runs on a detached promise, so the caller returns
   * immediately regardless of endpoint latency and a reporting failure never
   * throws into it.
   *
   * Every row this produces is recorded server-side as capture_mode='edge',
   * attested_by='client' -- the endpoint hardcodes both; they are not fields
   * a client can assert.
   */
  private startReport(params: {
    clientEventId: string;
    action: GovernanceAction;
    piiTypes: string[];
    piiCount: number;
  }): AttestationReport {
    if (!this.config.apiKey) {
      return disabledAttestationReport('apiKey not configured; reporting is disabled');
    }
    const apiKey = this.config.apiKey;
    try {
      const verdict = ACTION_TO_VERDICT[params.action];
      const [ts, decidedAt] = decidedAtPair();
      const canonical = buildCanonical({
        policyVersion: this.config.policyVersion,
        verdict,
        piiTypes: params.piiTypes,
        piiCount: params.piiCount,
        hitl: params.action === 'escalate',
        ts,
      });
      const cjson = canonicalJson(canonical);
      const salt = generateFingerprintSalt();
      const fingerprint = computeSaltedFingerprint(cjson, salt);

      return startAttestationReport({
        apiKey,
        clientEventId: params.clientEventId,
        verdict,
        canonicalJsonStr: cjson,
        salt,
        fingerprint,
        decidedAt,
      });
    } catch (exc) {
      return failedAttestationReport(
        `failed to build attestation: ${exc instanceof Error ? `${exc.name}: ${exc.message}` : String(exc)}`
      );
    }
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
