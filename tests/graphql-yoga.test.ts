/**
 * Tests for GraphQL Yoga middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import {
  torkYogaPlugin,
  torkYogaContext,
  torkResolver,
  torkFieldResolvers,
  torkEnvelopPlugin,
} from '../src/middleware/graphql-yoga';

describe('torkYogaPlugin', () => {
  it('governs variables in onParams', () => {
    const tork = new Tork();
    const plugin = torkYogaPlugin(tork);

    let governedParams: any;
    plugin.onParams({
      params: {
        query: '{ user(id: $id) { name } }',
        variables: { name: 'SSN: 123-45-6789' },
      },
      setParams: (p: any) => { governedParams = p; },
    });

    expect(governedParams.variables.name).toContain('[SSN_REDACTED]');
    expect(governedParams.variables.name).not.toContain('123-45-6789');
  });

  it('governs result data in onResultProcess', () => {
    const tork = new Tork();
    const plugin = torkYogaPlugin(tork);

    let governedResult: any;
    plugin.onResultProcess({
      result: { data: { user: { email: 'admin@secret.com' } } },
      setResult: (r: any) => { governedResult = r; },
    });

    expect(governedResult.data.user.email).toContain('[EMAIL_REDACTED]');
  });

  it('passes through clean variables', () => {
    const tork = new Tork();
    const plugin = torkYogaPlugin(tork);

    let governedParams: any;
    plugin.onParams({
      params: {
        query: '{ users { name } }',
        variables: { limit: 10 },
      },
      setParams: (p: any) => { governedParams = p; },
    });

    expect(governedParams.variables.limit).toBe(10);
  });

  it('skips variable governance when disabled', () => {
    const tork = new Tork();
    const plugin = torkYogaPlugin(tork, { governVariables: false });

    let setParamsCalled = false;
    plugin.onParams({
      params: {
        query: '{ user }',
        variables: { ssn: '123-45-6789' },
      },
      setParams: () => { setParamsCalled = true; },
    });

    expect(setParamsCalled).toBe(false);
  });

  it('skips result governance when disabled', () => {
    const tork = new Tork();
    const plugin = torkYogaPlugin(tork, { governResult: false });

    let setResultCalled = false;
    plugin.onResultProcess({
      result: { data: { email: 'admin@secret.com' } },
      setResult: () => { setResultCalled = true; },
    });

    expect(setResultCalled).toBe(false);
  });
});

describe('torkYogaContext', () => {
  it('adds tork to context', () => {
    const tork = new Tork();
    const contextFactory = torkYogaContext(tork);

    const ctx = contextFactory({});
    expect(ctx.tork).toBe(tork);
    expect(ctx.torkReceipts).toBeDefined();
  });

  it('governs initial context values', () => {
    const tork = new Tork();
    const contextFactory = torkYogaContext(tork);

    const ctx = contextFactory({ userEmail: 'admin@secret.com' });
    expect(ctx.userEmail).toContain('[EMAIL_REDACTED]');
  });
});

describe('torkResolver', () => {
  it('governs resolver args', async () => {
    const tork = new Tork();
    const resolver = torkResolver(
      tork,
      (parent, args: any) => args.name,
    );

    const result = await resolver(null, { name: 'SSN: 123-45-6789' }, {}, {});
    expect(result).toContain('[SSN_REDACTED]');
  });

  it('governs resolver result', async () => {
    const tork = new Tork();
    const resolver = torkResolver(
      tork,
      () => ({ email: 'admin@secret.com' }),
    );

    const result = await resolver(null, {}, {}, {}) as any;
    expect(result.email).toContain('[EMAIL_REDACTED]');
  });

  it('skips arg governance when disabled', async () => {
    const tork = new Tork();
    const resolver = torkResolver(
      tork,
      (_p, args: any) => args.ssn,
      { governVariables: false, governResult: false },
    );

    const result = await resolver(null, { ssn: '123-45-6789' }, {}, {});
    expect(result).toBe('123-45-6789');
  });
});

describe('torkFieldResolvers', () => {
  it('wraps all field resolvers', () => {
    const tork = new Tork();
    const resolvers = torkFieldResolvers(tork, {
      Query: {
        user: () => ({ name: 'Test' }),
        users: () => [],
      },
    });

    expect(typeof resolvers.Query.user).toBe('function');
    expect(typeof resolvers.Query.users).toBe('function');
  });
});

describe('torkEnvelopPlugin', () => {
  it('governs variableValues in onExecute', () => {
    const tork = new Tork();
    const plugin = torkEnvelopPlugin(tork);

    const args: any = {
      variableValues: { name: 'SSN: 123-45-6789' },
      contextValue: {},
    };

    plugin.onExecute({ args });

    expect(args.variableValues.name).toContain('[SSN_REDACTED]');
    expect(args.contextValue.tork).toBe(tork);
  });
});
