/**
 * Tork Governance adapter for ws (WebSocket library).
 *
 * Provides governance for WebSocket connections
 * with automatic PII detection and policy enforcement.
 *
 * @example
 * import { torkWsServer } from 'tork-governance';
 *
 * const wss = new WebSocket.Server({ port: 8080 });
 * torkWsServer(tork, wss);
 */

import { Tork, GovernanceResult } from '../index';

export interface TorkWsOptions {
  governIncoming?: boolean;
  governOutgoing?: boolean;
  governHeaders?: boolean;
}

export interface WsSocket {
  on: (event: string, listener: (...args: any[]) => void) => void;
  send: (data: string | Buffer, cb?: (err?: Error) => void) => void;
  close: (code?: number, reason?: string) => void;
  _torkReceipts?: any[];
  _tork?: Tork;
}

export interface WsServer {
  on: (event: string, listener: (...args: any[]) => void) => void;
  clients: Set<WsSocket>;
}

/**
 * Apply Tork governance to a WebSocket server.
 */
export function torkWsServer(
  tork: Tork,
  wss: WsServer,
  options: TorkWsOptions = {}
) {
  const { governIncoming = true, governOutgoing = true, governHeaders = true } = options;

  wss.on('connection', (ws: WsSocket, request?: any) => {
    const receipts: any[] = [];
    ws._torkReceipts = receipts;
    ws._tork = tork;

    // Govern headers if available
    if (governHeaders && request?.headers) {
      for (const [key, value] of Object.entries(request.headers)) {
        if (typeof value === 'string') {
          const result = tork.govern(value);
          receipts.push(result.receipt);
        }
      }
    }

    // Govern URL query params if available
    if (governHeaders && request?.url) {
      try {
        const url = new URL(request.url, 'http://localhost');
        for (const [key, value] of url.searchParams.entries()) {
          const result = tork.govern(value);
          receipts.push(result.receipt);
        }
      } catch {
        // URL parsing failed
      }
    }

    // Wrap message handler
    const originalOn = ws.on.bind(ws);
    ws.on = (event: string, listener: (...args: any[]) => void) => {
      if (event === 'message' && governIncoming) {
        originalOn(event, (data: any, isBinary: boolean) => {
          if (!isBinary && typeof data === 'string') {
            const result = tork.govern(data);
            receipts.push(result.receipt);
            const governedData = result.action === 'redact' || result.action === 'REDACT'
              ? result.output
              : data;
            listener(governedData, isBinary);
          } else if (!isBinary && Buffer.isBuffer(data)) {
            const text = data.toString('utf8');
            const result = tork.govern(text);
            receipts.push(result.receipt);
            const governedData = result.action === 'redact' || result.action === 'REDACT'
              ? result.output
              : text;
            listener(governedData, isBinary);
          } else {
            listener(data, isBinary);
          }
        });
      } else {
        originalOn(event, listener);
      }
      return ws;
    };

    // Wrap send method
    if (governOutgoing) {
      const originalSend = ws.send.bind(ws);
      ws.send = (data: string | Buffer, cb?: (err?: Error) => void) => {
        if (typeof data === 'string') {
          const result = tork.govern(data);
          receipts.push(result.receipt);
          const governedData = result.action === 'redact' || result.action === 'REDACT'
            ? result.output
            : data;
          originalSend(governedData, cb);
        } else if (Buffer.isBuffer(data)) {
          const text = data.toString('utf8');
          const result = tork.govern(text);
          receipts.push(result.receipt);
          if (result.action === 'redact' || result.action === 'REDACT') {
            originalSend(Buffer.from(result.output, 'utf8'), cb);
          } else {
            originalSend(data, cb);
          }
        } else {
          originalSend(data, cb);
        }
      };
    }
  });

  return wss;
}

/**
 * Create governed WebSocket message handler.
 */
export function torkWsHandler(
  tork: Tork,
  handler: (data: string, ws: WsSocket) => void | Promise<void>,
  options: TorkWsOptions = {}
): (data: string | Buffer, ws: WsSocket) => Promise<void> {
  const { governIncoming = true } = options;

  return async (data: string | Buffer, ws: WsSocket): Promise<void> => {
    const receipts = ws._torkReceipts || [];
    let governedData: string;

    if (Buffer.isBuffer(data)) {
      governedData = data.toString('utf8');
    } else {
      governedData = data;
    }

    if (governIncoming) {
      const result = tork.govern(governedData);
      receipts.push(result.receipt);
      governedData = result.action === 'redact' || result.action === 'REDACT'
        ? result.output
        : governedData;
    }

    await handler(governedData, ws);
  };
}

/**
 * Create governed send function for WebSocket.
 */
export function torkWsSend(
  tork: Tork,
  ws: WsSocket,
  options: TorkWsOptions = {}
) {
  const { governOutgoing = true } = options;
  const receipts = ws._torkReceipts || [];

  return (data: string, cb?: (err?: Error) => void) => {
    if (governOutgoing) {
      const result = tork.govern(data);
      receipts.push(result.receipt);
      const governedData = result.action === 'redact' || result.action === 'REDACT'
        ? result.output
        : data;
      ws.send(governedData, cb);
    } else {
      ws.send(data, cb);
    }
  };
}

/**
 * Broadcast governed message to all clients.
 */
export function torkWsBroadcast(
  tork: Tork,
  wss: WsServer,
  options: TorkWsOptions = {}
) {
  const { governOutgoing = true } = options;

  return (data: string) => {
    let governedData = data;

    if (governOutgoing) {
      const receipts: any[] = [];
      const result = tork.govern(data);
      receipts.push(result.receipt);
      governedData = result.action === 'redact' || result.action === 'REDACT'
        ? result.output
        : data;
    }

    wss.clients.forEach((client: WsSocket) => {
      client.send(governedData);
    });
  };
}

export type { GovernanceResult };
