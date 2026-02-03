/**
 * Tork Governance adapter for Socket.io.
 *
 * Provides governance for Socket.io events
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkSocketMiddleware } from 'tork-governance';
 *
 * io.use(torkSocketMiddleware(tork));
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkSocketOptions {
  governIncoming?: boolean;
  governOutgoing?: boolean;
  events?: string[];
  excludeEvents?: string[];
}

export interface SocketMiddlewareSocket {
  id: string;
  handshake: {
    query: Record<string, string>;
    headers: Record<string, string>;
  };
  data: Record<string, any>;
  emit: (event: string, ...args: any[]) => void;
  on: (event: string, listener: (...args: any[]) => void) => void;
  use: (fn: (packet: [string, ...any[]], next: (err?: Error) => void) => void) => void;
}

/**
 * Create Socket.io middleware with Tork governance.
 */
export function torkSocketMiddleware(tork: Tork, options: TorkSocketOptions = {}) {
  const { governIncoming = true, events, excludeEvents = [] } = options;

  return (socket: SocketMiddlewareSocket, next: (err?: Error) => void) => {
    // Store tork instance on socket
    socket.data.tork = tork;
    socket.data.torkReceipts = [];

    // Govern handshake query params
    if (governIncoming && socket.handshake.query) {
      for (const [key, value] of Object.entries(socket.handshake.query)) {
        if (typeof value === 'string') {
          const result = tork.govern(value);
          socket.data.torkReceipts.push(result.receipt);
        }
      }
    }

    // Add packet middleware for incoming events
    socket.use((packet, packetNext) => {
      const [event, ...args] = packet;

      // Skip if event is excluded
      if (excludeEvents.includes(event)) {
        return packetNext();
      }

      // Skip if events filter is set and event not included
      if (events && !events.includes(event)) {
        return packetNext();
      }

      // Govern incoming data
      if (governIncoming && args.length > 0) {
        const governedArgs = args.map(arg => governValueSync(tork, arg, socket.data.torkReceipts));
        packet.splice(1, args.length, ...governedArgs);
      }

      packetNext();
    });

    next();
  };
}

/**
 * Wrap a Socket.io event handler with Tork governance.
 */
export function torkSocketHandler<T extends any[]>(
  tork: Tork,
  handler: (...args: T) => void | Promise<void>,
  options: TorkSocketOptions = {}
): (...args: T) => Promise<void> {
  const { governIncoming = true, governOutgoing = true } = options;

  return async (...args: T): Promise<void> => {
    const receipts: any[] = [];
    let governedArgs = args;

    // Govern incoming args
    if (governIncoming) {
      governedArgs = args.map(arg => governValueSync(tork, arg, receipts)) as T;
    }

    // Call original handler
    const result = await handler(...governedArgs);

    // Govern outgoing response if callback
    if (governOutgoing && typeof args[args.length - 1] === 'function') {
      const callback = args[args.length - 1] as Function;
      const originalCallback = callback;
      args[args.length - 1] = ((...callbackArgs: any[]) => {
        const governedCallbackArgs = callbackArgs.map(arg =>
          governValueSync(tork, arg, receipts)
        );
        originalCallback(...governedCallbackArgs);
      }) as any;
    }

    return result;
  };
}

/**
 * Create governed emit function for Socket.io.
 */
export function torkEmit(
  tork: Tork,
  socket: SocketMiddlewareSocket,
  options: TorkSocketOptions = {}
) {
  const { governOutgoing = true } = options;
  const originalEmit = socket.emit.bind(socket);

  return (event: string, ...args: any[]) => {
    if (governOutgoing) {
      const receipts: any[] = [];
      const governedArgs = args.map(arg => governValueSync(tork, arg, receipts));
      return originalEmit(event, ...governedArgs);
    }
    return originalEmit(event, ...args);
  };
}

/**
 * Create governed Socket.io namespace handlers.
 */
export function createTorkSocketHandlers(tork: Tork, options: TorkSocketOptions = {}) {
  return {
    onConnection: (handler: (socket: SocketMiddlewareSocket) => void) => {
      return (socket: SocketMiddlewareSocket) => {
        socket.data.tork = tork;
        socket.data.torkReceipts = [];
        handler(socket);
      };
    },

    wrapHandler: <T extends any[]>(handler: (...args: T) => void | Promise<void>) => {
      return torkSocketHandler(tork, handler, options);
    },

    wrapEmit: (socket: SocketMiddlewareSocket) => {
      return torkEmit(tork, socket, options);
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
