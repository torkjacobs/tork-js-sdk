import { describe, it, expect } from 'vitest';
import { Tork } from '../src/index';

describe('agent telemetry fields on govern()', () => {
  it('omits sessionContext entirely when no field is set', () => {
    const r = new Tork().govern('hello');
    expect(r.sessionContext).toBeUndefined();
    expect(r.receipt.sessionContext).toBeUndefined();
    expect('sessionContext' in r).toBe(false);
  });

  it('passes all four fields through to the result and the receipt', () => {
    const ctx = { agent_id: 'a-1', agent_role: 'planner', session_id: 's-9', session_turn: 3 };
    const r = new Tork().govern('hello', ctx);
    expect(r.sessionContext).toEqual(ctx);
    expect(r.receipt.sessionContext).toEqual(ctx);
  });

  it('includes only the fields that were set', () => {
    const r = new Tork().govern('hello', { agent_role: 'judge' });
    expect(r.sessionContext).toEqual({ agent_role: 'judge' });
  });

  it('keeps session_turn 0 and an empty agent_id (falsy but set)', () => {
    expect(new Tork().govern('hi', { session_turn: 0 }).sessionContext).toEqual({ session_turn: 0 });
    expect(new Tork().govern('hi', { agent_id: '', session_turn: 2 }).sessionContext).toEqual({
      agent_id: '',
      session_turn: 2,
    });
  });

  it('does not change the governance decision', () => {
    const t = new Tork();
    const a = t.govern('SSN 123-45-6789');
    const b = t.govern('SSN 123-45-6789', { agent_id: 'x', session_turn: 1 });
    expect(b.action).toBe(a.action);
    expect(b.output).toBe(a.output);
  });
});
