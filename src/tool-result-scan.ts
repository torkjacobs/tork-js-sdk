/**
 * Tool-result scanning (DECIDED-TACT2-V2-C).
 *
 * A tool result returned by an MCP server -- or by any external system the
 * caller does not control -- is untrusted input that is about to be appended
 * to a model's context. This module scans it BEFORE that happens, on-device,
 * for two things:
 *
 *   1. PII, using the SAME on-device detector as govern() (detectPII in
 *      ./pii). Nothing new was written for this: same patterns, same
 *      redaction labels, same zero-network guarantee.
 *   2. Prompt injection, using the conservative heuristic pattern set below.
 *      The SDK had NO injection heuristics before this module, so these are
 *      new -- and every injection finding is labelled `heuristic:<type>` in
 *      the findings so no caller can mistake a regex hit for a verified
 *      determination.
 *
 * ZERO NETWORK. Every function here is pure and synchronous: no fetch, no
 * I/O, no clock. The payload never leaves the machine, and the scan itself is
 * unaffected by whether an apiKey is configured.
 *
 * WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
 * the caller attests to. It is not gateway-side enforcement -- a compromised
 * or simply careless caller can skip it entirely, and Tork cannot tell.
 * Enforcement at the gateway, where skipping is not an option, is a separate
 * and later control.
 */

import { detectPII, type PIIType } from './pii';

// ============================================================================
// Types
// ============================================================================

export type ToolResultFindingKind = 'pii' | 'injection';

export interface ToolResultFinding {
  /** 'pii' -- a detector match. 'injection' -- a heuristic pattern match. */
  kind: ToolResultFindingKind;
  /**
   * For 'pii', a PIIType ('ssn', 'email', ...). For 'injection', always
   * `heuristic:<name>` -- the prefix is part of the value, not decoration,
   * so a downstream reader of a receipt cannot mistake a pattern hit for a
   * verified determination.
   */
  type: string;
  /** Number of matches of this (kind, type) at this location. */
  count: number;
  /** JSON path of the string the matches were found in, e.g. `$.content[0].text`. */
  location: string;
}

export interface ToolResultScanInput {
  /** Name of the tool that produced this result. Recorded on the receipt. */
  toolName: string;
  /** URI of the MCP server (or other origin). Recorded on the receipt when present. */
  serverUri?: string;
  /** The tool result itself. Any JSON-shaped value; never leaves the machine. */
  payload: unknown;
}

export interface ToolResultScanOptions {
  /**
   * Block the result when the injection heuristics fire. Default false:
   * detect and report, let the caller decide. When true and an injection
   * pattern matches, `blocked` is true, `reason` is set, and `sanitized` is
   * null -- there is deliberately no masked payload to accidentally append.
   */
  blockOnInjection?: boolean;
  /**
   * Extra redaction patterns, same shape and semantics as
   * TorkConfig.customPatterns. NOTE (inherited from detectPII): custom
   * patterns redact but are not counted, so they can change `sanitized`
   * without producing a finding.
   */
  customPatterns?: Record<string, RegExp>;
  /**
   * Maximum nesting depth to walk. Deeper values are passed through
   * unscanned and unmodified. Default 32.
   */
  maxDepth?: number;
}

export interface ToolResultScanResult {
  /**
   * The payload with PII masked in place, structurally identical otherwise.
   * `null` when `blocked` is true. Sub-trees containing no PII keep their
   * original object identity, so a clean payload comes back untouched.
   */
  sanitized: unknown;
  findings: ToolResultFinding[];
  blocked: boolean;
  /** Present only when blocked. */
  reason?: string;
}

// ============================================================================
// Injection heuristics
// ============================================================================

/**
 * Prefix on every injection finding's `type`. Not cosmetic: these patterns
 * are regexes over untrusted text, they carry false positives and false
 * negatives, and the label travels with the finding into the receipt.
 */
export const INJECTION_HEURISTIC_PREFIX = 'heuristic:';

/**
 * Identifies this exact pattern set in receipts. Bump when the patterns
 * change, so a receipt says which ruleset produced its counts. Every SDK
 * mirroring this implementation must emit the SAME value for the same
 * ruleset -- it is a shared identifier, not a per-language one.
 */
export const INJECTION_RULESET = 'tork-injection-heuristics-v1';

/**
 * Conservative on purpose. Each pattern targets a phrase that has no
 * plausible reason to appear in a legitimate tool result -- a database row, a
 * search hit, a file listing. Broader "suspicious language" matching would
 * fire on ordinary documentation and support tickets, and an alert nobody
 * believes is worse than no alert.
 */
const INJECTION_PATTERNS: ReadonlyArray<{ type: string; pattern: RegExp }> = [
  // -- instruction override --------------------------------------------
  {
    type: 'instruction_override',
    pattern:
      /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b/gi,
  },
  {
    type: 'instruction_override',
    pattern:
      /\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b/gi,
  },
  {
    type: 'instruction_override',
    pattern: /\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b/gi,
  },

  // -- role reassignment ------------------------------------------------
  {
    type: 'role_reassignment',
    pattern: /\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b/gi,
  },
  {
    type: 'role_reassignment',
    pattern: /\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b/gi,
  },
  {
    type: 'role_reassignment',
    pattern: /\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:/gi,
  },
  {
    type: 'role_reassignment',
    pattern: /\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b/gi,
  },
  {
    type: 'role_reassignment',
    pattern: /\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b/gi,
  },
  {
    // A role header smuggled into content -- "system:" / "<|im_start|>system"
    // at the start of a line is a conversation-structure forgery, not prose.
    type: 'role_reassignment',
    pattern: /^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)/gim,
  },

  // -- exfiltration -----------------------------------------------------
  {
    // A markdown image/link whose URL carries the content out as a query
    // parameter -- the classic zero-click exfiltration shape.
    type: 'exfiltration_url',
    pattern:
      /!?\[[^\]\n]*\]\(\s*https?:\/\/[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)/gi,
  },
  {
    type: 'exfiltration_url',
    pattern:
      /\bhttps?:\/\/\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=/gi,
  },
  {
    type: 'exfiltration_url',
    pattern:
      /\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?:\/\/\S+/gi,
  },
];

/** Distinct injection types the ruleset can emit, for documentation/tests. */
export const INJECTION_TYPES: readonly string[] = Array.from(
  new Set(INJECTION_PATTERNS.map((p) => p.type))
).sort();

// ============================================================================
// Traversal
// ============================================================================

const DEFAULT_MAX_DEPTH = 32;

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function childPath(parent: string, key: string): string {
  return IDENTIFIER.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Scan one string: PII (via the shared detector) then injection heuristics.
 * Returns the masked string plus any findings, both keyed to `location`.
 */
function scanString(
  text: string,
  location: string,
  customPatterns: Record<string, RegExp> | undefined,
  findings: ToolResultFinding[]
): string {
  const pii = detectPII(text, customPatterns);

  if (pii.count > 0) {
    // Counts per type, emitted in a stable (sorted) order so two runs over
    // the same payload produce identical findings.
    const perType = new Map<PIIType, number>();
    for (const match of pii.matches) {
      perType.set(match.type, (perType.get(match.type) ?? 0) + 1);
    }
    for (const type of Array.from(perType.keys()).sort()) {
      findings.push({ kind: 'pii', type, count: perType.get(type)!, location });
    }
  }

  const perInjectionType = new Map<string, number>();
  for (const { type, pattern } of INJECTION_PATTERNS) {
    // Fresh regex per call: the module-level literals carry /g, and sharing
    // lastIndex across strings would silently skip matches.
    const regex = new RegExp(pattern.source, pattern.flags);
    const count = (text.match(regex) ?? []).length;
    if (count > 0) {
      perInjectionType.set(type, (perInjectionType.get(type) ?? 0) + count);
    }
  }
  for (const type of Array.from(perInjectionType.keys()).sort()) {
    findings.push({
      kind: 'injection',
      type: `${INJECTION_HEURISTIC_PREFIX}${type}`,
      count: perInjectionType.get(type)!,
      location,
    });
  }

  return pii.redactedText;
}

/**
 * Walk the payload, scanning every string. Returns a structure with PII
 * masked in place; sub-trees with nothing to mask keep their original
 * identity (so an untouched payload is `===` its input).
 *
 * Only strings are scanned. Numbers, booleans, dates, Maps, class instances
 * and anything else non-plain pass through untouched -- a bank account
 * stored as a JSON number is NOT detected. Cycles are left as-is and not
 * re-entered.
 */
function walk(
  value: unknown,
  location: string,
  depth: number,
  maxDepth: number,
  customPatterns: Record<string, RegExp> | undefined,
  findings: ToolResultFinding[],
  seen: WeakSet<object>
): unknown {
  if (typeof value === 'string') {
    return scanString(value, location, customPatterns, findings);
  }

  if (depth >= maxDepth || value === null || typeof value !== 'object') {
    return value;
  }

  if (seen.has(value as object)) return value;
  seen.add(value as object);

  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((item, index) => {
      const next = walk(item, `${location}[${index}]`, depth + 1, maxDepth, customPatterns, findings, seen);
      if (next !== item) changed = true;
      return next;
    });
    return changed ? out : value;
  }

  if (!isPlainObject(value)) return value;

  let changed = false;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    const next = walk(item, childPath(location, key), depth + 1, maxDepth, customPatterns, findings, seen);
    if (next !== item) changed = true;
    out[key] = next;
  }
  return changed ? out : value;
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Scan a tool result for PII and prompt injection before it is appended to
 * model context. Pure, synchronous, on-device: makes no network call and
 * mutates nothing.
 *
 * For the receipt-linked form (attested_by='client', capture_mode='edge'),
 * use `Tork#scanToolResult`, which wraps this and records the scan.
 */
export function scanToolResult(
  input: ToolResultScanInput,
  options: ToolResultScanOptions = {}
): ToolResultScanResult {
  const findings: ToolResultFinding[] = [];
  const sanitized = walk(
    input.payload,
    '$',
    0,
    options.maxDepth ?? DEFAULT_MAX_DEPTH,
    options.customPatterns,
    findings,
    new WeakSet<object>()
  );

  const injectionCount = findings.reduce((n, f) => (f.kind === 'injection' ? n + f.count : n), 0);
  const blocked = Boolean(options.blockOnInjection) && injectionCount > 0;

  if (blocked) {
    const types = Array.from(
      new Set(findings.filter((f) => f.kind === 'injection').map((f) => f.type))
    ).sort();
    return {
      sanitized: null,
      findings,
      blocked: true,
      reason:
        `Blocked: ${injectionCount} prompt-injection heuristic match(es) [${types.join(', ')}] in the result of ` +
        `tool "${input.toolName}". These are heuristic pattern matches (${INJECTION_RULESET}), not a verified ` +
        `determination. sanitized is null so no masked copy can be appended to context by accident.`,
    };
  }

  return { sanitized, findings, blocked: false };
}

// ============================================================================
// Receipt block
// ============================================================================

/**
 * The `tool_result_scan` block recorded on the receipt.
 *
 * snake_case, keys emitted in alphabetical order, optional keys OMITTED
 * entirely rather than set to null -- the same discipline as the TORK-DNA-v2
 * canonical form in dna-fingerprint.ts, and for the same reason: every SDK
 * that mirrors this must produce a byte-identical block for the same scan.
 *
 * It carries COUNTS ONLY. No payload, no matched substring, no location
 * path, no tool argument ever appears here.
 */
export interface ToolResultScanReceiptBlock {
  /** Always 'client'. This scan ran in the caller's process; Tork did not execute it. */
  attested_by: 'client';
  blocked: boolean;
  /** Always 'edge' -- the capture_mode this SDK's client-side work is recorded under. */
  capture_mode: 'edge';
  /** Counts by kind, then by type. Injection types keep their `heuristic:` prefix. */
  findings: {
    injection: Record<string, number>;
    pii: Record<string, number>;
  };
  /** Identifier of the injection ruleset that produced the injection counts. */
  injection_ruleset: string;
  /** Present only when blocked. */
  reason?: string;
  sdk_language: 'javascript';
  sdk_version: string;
  /** Present only when the caller supplied one. */
  server_uri?: string;
  tool_name: string;
  /** Total match counts per kind. */
  totals: { injection: number; pii: number };
}

function countsByType(findings: ToolResultFinding[], kind: ToolResultFindingKind): Record<string, number> {
  const totals = new Map<string, number>();
  for (const finding of findings) {
    if (finding.kind !== kind) continue;
    totals.set(finding.type, (totals.get(finding.type) ?? 0) + finding.count);
  }
  const out: Record<string, number> = {};
  for (const type of Array.from(totals.keys()).sort()) {
    out[type] = totals.get(type)!;
  }
  return out;
}

/**
 * Build the receipt block for a completed scan. Insertion order here IS the
 * emitted key order: alphabetical, with optional keys omitted.
 */
export function buildToolResultScanBlock(params: {
  toolName: string;
  serverUri?: string;
  result: ToolResultScanResult;
  sdkVersion: string;
}): ToolResultScanReceiptBlock {
  const pii = countsByType(params.result.findings, 'pii');
  const injection = countsByType(params.result.findings, 'injection');
  const sum = (counts: Record<string, number>): number =>
    Object.values(counts).reduce((a, b) => a + b, 0);

  const block: ToolResultScanReceiptBlock = {
    attested_by: 'client',
    blocked: params.result.blocked,
    capture_mode: 'edge',
    findings: { injection, pii },
    injection_ruleset: INJECTION_RULESET,
    ...(params.result.reason !== undefined && { reason: params.result.reason }),
    sdk_language: 'javascript',
    sdk_version: params.sdkVersion,
    ...(params.serverUri !== undefined && { server_uri: params.serverUri }),
    tool_name: params.toolName,
    totals: { injection: sum(injection), pii: sum(pii) },
  };

  return block;
}

/** Distinct PII types in a scan result, for the attestation canonical form. */
export function scanPIITypes(findings: ToolResultFinding[]): string[] {
  return Array.from(new Set(findings.filter((f) => f.kind === 'pii').map((f) => f.type))).sort();
}

/** Total PII match count in a scan result. */
export function scanPIICount(findings: ToolResultFinding[]): number {
  return findings.reduce((n, f) => (f.kind === 'pii' ? n + f.count : n), 0);
}

/** Total injection match count in a scan result. */
export function scanInjectionCount(findings: ToolResultFinding[]): number {
  return findings.reduce((n, f) => (f.kind === 'injection' ? n + f.count : n), 0);
}
