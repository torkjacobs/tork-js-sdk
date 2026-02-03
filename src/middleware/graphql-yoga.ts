/**
 * Tork Governance adapter for GraphQL Yoga.
 *
 * Provides governance for GraphQL Yoga servers
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkYogaPlugin } from 'tork-governance';
 *
 * const yoga = createYoga({
 *   plugins: [torkYogaPlugin(tork)],
 * });
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkYogaOptions {
  governVariables?: boolean;
  governResult?: boolean;
  governContext?: boolean;
}

export interface YogaPluginContext {
  request: Request;
  params: {
    query?: string;
    variables?: Record<string, any>;
    operationName?: string;
  };
}

/**
 * Create GraphQL Yoga plugin with Tork governance.
 */
export function torkYogaPlugin(tork: Tork, options: TorkYogaOptions = {}) {
  const { governVariables = true, governResult = true } = options;

  return {
    onParams({ params, setParams }: { params: any; setParams: (p: any) => void }) {
      if (governVariables && params.variables) {
        const receipts: any[] = [];
        const governedVariables = governValueSync(tork, params.variables, receipts);
        setParams({
          ...params,
          variables: governedVariables,
        });
      }
    },

    onResultProcess({ result, setResult }: { result: any; setResult: (r: any) => void }) {
      if (governResult && result.data) {
        const receipts: any[] = [];
        const governedData = governValueSync(tork, result.data, receipts);
        setResult({
          ...result,
          data: governedData,
        });
      }
    },
  };
}

/**
 * Create governed GraphQL Yoga context.
 */
export function torkYogaContext(tork: Tork, options: TorkYogaOptions = {}) {
  const { governContext = true } = options;

  return (initialContext: any) => {
    const receipts: any[] = [];

    // Govern initial context values if they exist
    if (governContext && initialContext) {
      const governedContext = governValueSync(tork, initialContext, receipts);
      return {
        ...governedContext,
        tork,
        torkReceipts: receipts,
      };
    }

    return {
      ...initialContext,
      tork,
      torkReceipts: receipts,
    };
  };
}

/**
 * Wrap a GraphQL resolver with Tork governance.
 */
export function torkResolver<TParent, TArgs, TContext, TResult>(
  tork: Tork,
  resolver: (parent: TParent, args: TArgs, context: TContext, info: any) => TResult | Promise<TResult>,
  options: TorkYogaOptions = {}
): (parent: TParent, args: TArgs, context: TContext, info: any) => Promise<TResult> {
  const { governVariables = true, governResult = true } = options;

  return async (parent: TParent, args: TArgs, context: TContext, info: any): Promise<TResult> => {
    const receipts: any[] = [];
    let governedArgs = args;

    // Govern args
    if (governVariables && args) {
      governedArgs = governValueSync(tork, args, receipts) as TArgs;
    }

    // Call resolver
    const result = await resolver(parent, governedArgs, context, info);

    // Govern result
    if (governResult && result !== undefined) {
      return governValueSync(tork, result, receipts) as TResult;
    }

    return result;
  };
}

/**
 * Create governed field resolvers for GraphQL Yoga.
 */
export function torkFieldResolvers<T extends Record<string, Record<string, Function>>>(
  tork: Tork,
  resolvers: T,
  options: TorkYogaOptions = {}
): T {
  const governed: Record<string, Record<string, Function>> = {};

  for (const [typeName, typeResolvers] of Object.entries(resolvers)) {
    governed[typeName] = {};
    for (const [fieldName, resolver] of Object.entries(typeResolvers)) {
      if (typeof resolver === 'function') {
        governed[typeName][fieldName] = torkResolver(tork, resolver as any, options);
      } else {
        governed[typeName][fieldName] = resolver;
      }
    }
  }

  return governed as T;
}

/**
 * Create Envelop plugin for Tork governance.
 */
export function torkEnvelopPlugin(tork: Tork, options: TorkYogaOptions = {}) {
  return {
    onExecute({ args }: any) {
      const receipts: any[] = [];

      // Govern variables
      if (options.governVariables !== false && args.variableValues) {
        args.variableValues = governValueSync(tork, args.variableValues, receipts);
      }

      // Add tork to context
      args.contextValue = {
        ...args.contextValue,
        tork,
        torkReceipts: receipts,
      };
    },
  };
}

/**
 * Govern a value (sync).
 */
function governValueSync(
  tork: Tork,
  value: any,
  receipts: any[]
): any {
  if (typeof value === 'string') {
    const result = tork.govern(value);
    receipts.push(result.receipt);
    return result.action === 'redact' || result.action === 'REDACT'
      ? result.output
      : value;
  }

  if (Array.isArray(value)) {
    return value.map(item => governValueSync(tork, item, receipts));
  }

  if (value && typeof value === 'object') {
    const governed: Record<string, any> = {};
    for (const [key, val] of Object.entries(value)) {
      governed[key] = governValueSync(tork, val, receipts);
    }
    return governed;
  }

  return value;
}

export type { GovernanceResult };
