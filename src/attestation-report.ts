/**
 * Optional metadata-only reporting to tork.network.
 *
 * Mirrors tork_governance.core's _attempt_attestation_once /
 * _report_attestation_with_retry / AttestationReport in the Python SDK.
 * govern() stays fully on-device and non-blocking: this module's network
 * call (and its one retry) always runs on a detached promise so a slow or
 * failed endpoint never delays or throws into the caller.
 */

import { SDK_VERSION } from './version';

export const ATTESTATIONS_ENDPOINT = 'https://tork.network/api/v1/attestations';

// Measured production latency (3 consecutive calls, 3 Aug): 8.0s, 5.7s,
// 4.8s. 15s gives comfortable headroom above the observed worst case.
export const REPORT_TIMEOUT_MS = 15_000;
export const REPORT_RETRY_BACKOFF_MS = 1_000;

// Cloudflare (fronting tork.network) blocks Node's default fetch
// User-Agent as a bot signature. SDK_VERSION is injected at build time from
// package.json so this can never go stale the way a hardcoded literal
// would (see @torknetwork/sdk, which reports "1.0.0" while its package.json
// says "2.0.0").
const USER_AGENT = `tork-governance-js/${SDK_VERSION}`;

export interface AttestationReport {
  /** Whether a network call was made at all (false when no apiKey is configured). */
  attempted: boolean;
  /** Whether the server confirmed a persisted attestation row. */
  succeeded: boolean;
  receiptId?: string;
  reason?: string;
  /**
   * Block until the background reporting attempt (if any) finishes.
   * Returns true once reporting has settled (or there was nothing to wait
   * on), false if `timeoutMs` elapsed first. Never rejects. The local
   * governance decision this report is attached to is unaffected either
   * way -- this exists for callers/tests that explicitly want the
   * confirmed network outcome.
   */
  wait(timeoutMs?: number): Promise<boolean>;
}

interface AttemptParams {
  apiKey: string;
  clientEventId: string;
  verdict: string;
  canonicalJsonStr: string;
  salt: string;
  fingerprint: string;
  decidedAt: string;
}

interface AttemptResult {
  succeeded: boolean;
  receiptId?: string;
  reason?: string;
}

/** Timeout or 5xx -- the server may or may not have written the row. */
class RetryableReportError extends Error {}

/**
 * 4xx or a malformed response -- the server rejected the claim, or the
 * exchange completed and definitively did not produce a receipt. Retrying
 * would just be noise.
 */
class NonRetryableReportError extends Error {}

async function extractErrorReason(response: Response, fallback: string): Promise<string> {
  try {
    const payload = await response.json();
    if (payload && typeof payload === 'object') {
      const candidate = (payload as Record<string, unknown>).message ?? (payload as Record<string, unknown>).error;
      if (typeof candidate === 'string' && candidate.length > 0) {
        return candidate;
      }
    }
  } catch {
    // Malformed/non-JSON error body -- fall back to the HTTP status.
  }
  return fallback;
}

/**
 * POST a metadata-only attestation to tork.network, once.
 *
 * The request body carries only: client_event_id, action, canonical_json
 * (type labels/counts + structural fields, never PII values), the
 * fingerprint salt, the fingerprint, and decided_at. No input text, output
 * text, or PII value is ever included.
 */
async function attemptAttestationOnce(params: AttemptParams): Promise<AttemptResult> {
  const body = JSON.stringify({
    client_event_id: params.clientEventId,
    action: params.verdict,
    canonical_json: params.canonicalJsonStr,
    fingerprint_salt: params.salt,
    fingerprint: params.fingerprint,
    decided_at: params.decidedAt,
  });

  // A single socket timeout covering the whole exchange, same as Python's
  // urllib `timeout=` there is no separate connect-timeout knob needed:
  // the endpoint is Cloudflare-fronted, so a hung TCP handshake specifically
  // (as opposed to a slow response) isn't the failure mode seen in
  // production. Modeled as a race (rather than inferring "was this abort a
  // timeout?" from signal.aborted after the fact) so the timeout path is
  // unambiguous and independently testable.
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new RetryableReportError('request timed out'));
    }, REPORT_TIMEOUT_MS);
  });

  const fetchPromise = fetch(ATTESTATIONS_ENDPOINT, {
    method: 'POST',
    headers: {
      'x-tork-api-key': params.apiKey,
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
      'x-tork-sdk-language': 'javascript',
      'x-tork-sdk-version': SDK_VERSION,
    },
    body,
    signal: controller.signal,
  });
  // If the timeout wins the race below, fetchPromise will go on to reject
  // too (once aborted) with nothing else observing it -- mark it handled
  // here without affecting what the race itself sees.
  fetchPromise.catch(() => {});

  let response: Response;
  try {
    response = await Promise.race([fetchPromise, timeoutPromise]);
  } catch (exc) {
    if (exc instanceof RetryableReportError) {
      throw exc;
    }
    // Any other fetch-level failure (DNS, connection refused, etc.) is
    // treated as a definitive non-retryable failure, same as Python: only
    // an explicit timeout or a 5xx response is worth retrying.
    throw new NonRetryableReportError(exc instanceof Error ? `${exc.name}: ${exc.message}` : String(exc));
  } finally {
    clearTimeout(timer!);
  }

  if (response.status >= 500 && response.status < 600) {
    throw new RetryableReportError(await extractErrorReason(response, `HTTP ${response.status}`));
  }

  if (response.status !== 200 && response.status !== 201) {
    throw new NonRetryableReportError(await extractErrorReason(response, `HTTP ${response.status}`));
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (exc) {
    throw new NonRetryableReportError(
      `malformed response: ${exc instanceof Error ? exc.message : String(exc)}`
    );
  }

  const receiptId =
    payload && typeof payload === 'object' ? (payload as Record<string, unknown>).receipt_id : undefined;
  if (typeof receiptId !== 'string' || receiptId.length === 0) {
    throw new NonRetryableReportError('server response missing receipt_id');
  }

  return { succeeded: true, receiptId };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * `attemptAttestationOnce`, plus one retry on timeout/5xx. Never rejects.
 *
 * Safe to retry: the endpoint is idempotent on client_event_id, so a retry
 * landing on top of a write that actually succeeded the first time returns
 * the original receipt rather than creating a duplicate. A 4xx is the
 * server correctly rejecting the claim -- retrying it would only add noise,
 * so it is not retried.
 */
export async function reportAttestationWithRetry(params: AttemptParams): Promise<AttemptResult> {
  try {
    return await attemptAttestationOnce(params);
  } catch (exc) {
    if (exc instanceof NonRetryableReportError) {
      return { succeeded: false, reason: exc.message };
    }
    // RetryableReportError -- fall through to the single retry below.
  }

  await sleep(REPORT_RETRY_BACKOFF_MS);

  try {
    return await attemptAttestationOnce(params);
  } catch (exc) {
    if (exc instanceof NonRetryableReportError) {
      return { succeeded: false, reason: exc.message };
    }
    const message = exc instanceof Error ? exc.message : String(exc);
    return {
      succeeded: false,
      reason:
        `not confirmed after retry: ${message}. A timeout or 5xx means the outcome is unknown, ` +
        `not that the write was rejected. If it landed, a later call with ` +
        `client_event_id="${params.clientEventId}" will return the original receipt instead of writing again.`,
    };
  }
}

class AttestationReportImpl implements AttestationReport {
  attempted: boolean;
  succeeded = false;
  receiptId?: string;
  reason?: string;
  private settled: Promise<void> | null = null;

  private constructor(attempted: boolean, reason?: string) {
    this.attempted = attempted;
    this.reason = reason;
  }

  /** No apiKey configured, or canonical/fingerprint construction failed locally. */
  static settledImmediately(attempted: boolean, reason: string): AttestationReportImpl {
    return new AttestationReportImpl(attempted, reason);
  }

  /** Kicks off the (retrying) network call on a detached promise. */
  static start(params: AttemptParams): AttestationReportImpl {
    const report = new AttestationReportImpl(
      true,
      'reporting in progress on a detached promise; call report.wait() for the confirmed outcome'
    );
    report.settled = reportAttestationWithRetry(params).then((result) => {
      report.succeeded = result.succeeded;
      report.receiptId = result.receiptId;
      report.reason = result.reason;
    });
    return report;
  }

  async wait(timeoutMs?: number): Promise<boolean> {
    if (!this.settled) return true;
    if (timeoutMs === undefined) {
      await this.settled;
      return true;
    }

    const TIMED_OUT = Symbol('timed-out');
    let timer: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMED_OUT), timeoutMs);
    });

    const result = await Promise.race([this.settled, timeoutPromise]);
    clearTimeout(timer!);
    return result !== TIMED_OUT;
  }
}

export function disabledAttestationReport(reason: string): AttestationReport {
  return AttestationReportImpl.settledImmediately(false, reason);
}

export function failedAttestationReport(reason: string): AttestationReport {
  return AttestationReportImpl.settledImmediately(true, reason);
}

export function startAttestationReport(params: AttemptParams): AttestationReport {
  return AttestationReportImpl.start(params);
}
