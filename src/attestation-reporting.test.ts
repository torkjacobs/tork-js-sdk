import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Tork } from './index';
import { REPORT_RETRY_BACKOFF_MS, REPORT_TIMEOUT_MS, reportAttestationWithRetry } from './attestation-report';
import { SDK_VERSION } from './version';

// No test in this file makes a real network call -- global.fetch is always
// stubbed. Mirrors tests/test_attestation_reporting.py in the Python SDK.

class FakeResponse {
  constructor(
    public status: number,
    private body: unknown
  ) {}
  async json() {
    return this.body;
  }
}

function fakeFetch(status: number, body: unknown) {
  return vi.fn(async () => new FakeResponse(status, body) as unknown as Response);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('reporting disabled (no apiKey)', () => {
  it('reports not-attempted', () => {
    const tork = new Tork();
    const result = tork.govern('Contact me at test@example.com');
    expect(result.report.attempted).toBe(false);
    expect(result.report.succeeded).toBe(false);
    expect(result.report.receiptId).toBeUndefined();
    expect(result.report.reason).toBeTruthy();
  });

  it('never touches the network', () => {
    const fetchSpy = vi.fn(() => {
      throw new Error('fetch must not be called without an apiKey');
    });
    vi.stubGlobal('fetch', fetchSpy);
    const tork = new Tork();
    expect(() => tork.govern('Contact me at test@example.com')).not.toThrow();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('reporting success', () => {
  it('a new 201 attestation succeeds', async () => {
    vi.stubGlobal('fetch', fakeFetch(201, { receipt_id: 'tork_rcpt_attest_abc123', replayed: false }));
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('Contact me at test@example.com');

    expect(result.report.attempted).toBe(true);
    expect(await result.report.wait(5000)).toBe(true);
    expect(result.report.succeeded).toBe(true);
    expect(result.report.receiptId).toBe('tork_rcpt_attest_abc123');
    expect(result.report.reason).toBeUndefined();
  });

  it('a replayed 200 still succeeds', async () => {
    vi.stubGlobal('fetch', fakeFetch(200, { receipt_id: 'tork_rcpt_attest_abc123', replayed: true }));
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('hello world');

    expect(await result.report.wait(5000)).toBe(true);
    expect(result.report.succeeded).toBe(true);
    expect(result.report.receiptId).toBe('tork_rcpt_attest_abc123');
  });
});

describe('reporting failure never raises', () => {
  it('a connection-level error does not throw', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('simulated network failure');
      })
    );
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('Contact me at test@example.com');

    expect(result.report.attempted).toBe(true);
    expect(await result.report.wait(5000)).toBe(true);
    expect(result.report.succeeded).toBe(false);
    expect(result.report.reason).toContain('simulated network failure');
  });

  it('an HTTP error does not throw', async () => {
    vi.stubGlobal('fetch', fakeFetch(401, { error: 'invalid api key', code: 'UNAUTHORIZED' }));
    const tork = new Tork({ apiKey: 'tork_sk_live_bad' });
    const result = tork.govern('hello world');

    expect(result.report.attempted).toBe(true);
    expect(await result.report.wait(5000)).toBe(true);
    expect(result.report.succeeded).toBe(false);
    expect(result.report.reason).toContain('invalid api key');
  });

  it('a missing receipt_id in the response is a failure', async () => {
    vi.stubGlobal('fetch', fakeFetch(201, { replayed: false }));
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('hello world');

    expect(await result.report.wait(5000)).toBe(true);
    expect(result.report.succeeded).toBe(false);
    expect(result.report.reason).toContain('receipt_id');
  });

  it('the local decision is unaffected by a reporting failure', () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('simulated network failure');
      })
    );
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('My SSN is 123-45-6789');

    expect(result.action).toBe('redact');
    expect(result.output).toContain('[SSN_REDACTED]');
  });
});

describe('request body contract', () => {
  function captureFetch(status = 201, body: unknown = { receipt_id: 'tork_rcpt_attest_abc123' }) {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        calls.push({ url, init });
        return new FakeResponse(status, body) as unknown as Response;
      })
    );
    return calls;
  }

  it('the body has no content field and no PII values', async () => {
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const secretText = 'My SSN is 123-45-6789 and email is test@example.com';
    const result = tork.govern(secretText);
    await result.report.wait(5000);

    const rawBody = calls[0].init.body as string;
    const body = JSON.parse(rawBody);

    expect(Object.keys(body).sort()).toEqual(
      ['action', 'canonical_json', 'client_event_id', 'decided_at', 'fingerprint', 'fingerprint_salt'].sort()
    );
    expect(body).not.toHaveProperty('content');
    expect(body).not.toHaveProperty('input');
    expect(body).not.toHaveProperty('output');
    expect(rawBody).not.toContain('123-45-6789');
    expect(rawBody).not.toContain('test@example.com');
    expect(body.canonical_json).not.toContain('123-45-6789');
    expect(body.canonical_json).not.toContain('test@example.com');
  });

  it('the canonical_json only carries type labels', async () => {
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('My SSN is 123-45-6789');
    await result.report.wait(5000);

    const body = JSON.parse(calls[0].init.body as string);
    const canonical = JSON.parse(body.canonical_json);
    expect(canonical.pii).toEqual(['ssn']);
  });

  it('sends the expected headers', async () => {
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('hello world');
    await result.report.wait(5000);

    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['x-tork-api-key']).toBe('tork_sk_live_test');
    expect(headers['x-tork-sdk-language']).toBe('javascript');
    expect(headers['x-tork-sdk-version']).toBe(SDK_VERSION);
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('sends an explicit User-Agent, not the fetch default', async () => {
    // Cloudflare (fronting tork.network) blocks Node's bare fetch
    // User-Agent as a bot signature (HTTP 403, Cloudflare error 1010). The
    // request must carry an explicit tork-governance-js/<version> UA.
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('hello world');
    await result.report.wait(5000);

    const headers = calls[0].init.headers as Record<string, string>;
    const userAgent = headers['User-Agent'];
    expect(userAgent).not.toMatch(/^node$/i);
    expect(userAgent).toContain('tork-governance');
    expect(userAgent).toContain(SDK_VERSION);
  });

  it('client_event_id matches the local receipt id', async () => {
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('hello world');
    await result.report.wait(5000);

    const body = JSON.parse(calls[0].init.body as string);
    expect(body.client_event_id).toBe(result.receipt.receiptId);
  });

  it('decided_at matches canonical.ts', async () => {
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('hello world');
    await result.report.wait(5000);

    const body = JSON.parse(calls[0].init.body as string);
    const canonical = JSON.parse(body.canonical_json);
    const decidedAtSeconds = Math.floor(new Date(body.decided_at).getTime() / 1000);
    expect(decidedAtSeconds).toBe(canonical.ts);
  });

  it('deny is used verbatim, never coerced to allow', async () => {
    const calls = captureFetch();
    const tork = new Tork({ apiKey: 'tork_sk_live_test', defaultAction: 'deny' });
    const result = tork.govern('My SSN is 123-45-6789');
    await result.report.wait(5000);

    const body = JSON.parse(calls[0].init.body as string);
    expect(['allow', 'redact', 'deny', 'flag']).toContain(body.action);
    expect(body.action).toBe('deny');
  });
});

describe('report timeout constant', () => {
  it('is 15 seconds', () => {
    // Measured production latency (3 consecutive calls, 3 Aug): 8.0s, 5.7s,
    // 4.8s. 15s gives comfortable headroom above the observed worst case.
    expect(REPORT_TIMEOUT_MS).toBe(15_000);
  });
});

describe('retry logic (direct against reportAttestationWithRetry)', () => {
  function kwargs() {
    return {
      apiKey: 'tork_sk_live_test',
      clientEventId: 'rcpt_test123',
      verdict: 'allow',
      canonicalJsonStr: '{"v":"1"}',
      salt: 'deadbeef',
      fingerprint: 'TORK-DNA-v2-deadbeef',
      decidedAt: '2026-08-03T00:00:00Z',
    };
  }

  beforeEach(() => {
    vi.useFakeTimers();
  });

  it('a timeout triggers exactly one retry', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        calls++;
        return new Promise(() => {}); // never resolves -- forces the timeout path
      })
    );

    const promise = reportAttestationWithRetry(kwargs());
    await vi.advanceTimersByTimeAsync(REPORT_TIMEOUT_MS + REPORT_RETRY_BACKOFF_MS + REPORT_TIMEOUT_MS);
    const report = await promise;

    expect(calls).toBe(2);
    expect(report.succeeded).toBe(false);
    expect(report.reason).toContain('not confirmed');
    expect(report.reason).toContain('rcpt_test123');
  });

  it('a timeout then success retries once and succeeds', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        calls++;
        if (calls === 1) return new Promise(() => {});
        return Promise.resolve(new FakeResponse(201, { receipt_id: 'tork_rcpt_attest_abc123' }) as unknown as Response);
      })
    );

    const promise = reportAttestationWithRetry(kwargs());
    await vi.advanceTimersByTimeAsync(REPORT_TIMEOUT_MS + REPORT_RETRY_BACKOFF_MS);
    const report = await promise;

    expect(calls).toBe(2);
    expect(report.succeeded).toBe(true);
    expect(report.receiptId).toBe('tork_rcpt_attest_abc123');
  });

  it('a 5xx triggers one retry', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        calls++;
        return new FakeResponse(503, {}) as unknown as Response;
      })
    );

    const promise = reportAttestationWithRetry(kwargs());
    await vi.advanceTimersByTimeAsync(REPORT_RETRY_BACKOFF_MS);
    const report = await promise;

    expect(calls).toBe(2);
    expect(report.succeeded).toBe(false);
  });

  it('a 422 triggers no retry', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        calls++;
        return new FakeResponse(422, { error: 'canonical_json mismatch' }) as unknown as Response;
      })
    );

    const report = await reportAttestationWithRetry(kwargs());

    expect(calls).toBe(1);
    expect(report.succeeded).toBe(false);
    expect(report.reason).toContain('canonical_json mismatch');
  });

  it('a 4xx reason does not say "not confirmed"', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new FakeResponse(400, {}) as unknown as Response)
    );

    const report = await reportAttestationWithRetry(kwargs());
    expect(report.reason).not.toContain('not confirmed');
  });
});

describe('govern() never blocks or throws on reporting', () => {
  it('returns the local decision immediately even when the endpoint hangs', () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise(() => {})) // never resolves
    );
    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('My SSN is 123-45-6789');

    expect(result.action).toBe('redact');
    expect(result.output).toContain('[SSN_REDACTED]');
    // Reporting is attempted but has not settled yet -- proof govern()
    // did not wait on the network call before returning.
    expect(result.report.attempted).toBe(true);
    expect(result.report.succeeded).toBe(false);
    expect(result.report.reason).toContain('detached promise');
  });

  it('a persistent timeout never throws and the confirmed outcome is reachable via wait()', async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise(() => {}))
    );

    const tork = new Tork({ apiKey: 'tork_sk_live_test' });
    const result = tork.govern('My SSN is 123-45-6789');

    expect(result.action).toBe('redact');

    const waitPromise = result.report.wait();
    await vi.advanceTimersByTimeAsync(REPORT_TIMEOUT_MS + REPORT_RETRY_BACKOFF_MS + REPORT_TIMEOUT_MS);
    expect(await waitPromise).toBe(true);

    expect(result.report.succeeded).toBe(false);
    expect(result.report.reason).toContain('not confirmed');
    expect(result.report.reason?.toLowerCase()).not.toContain('failed to build');
  });
});
