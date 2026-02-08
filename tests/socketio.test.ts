/**
 * Tests for Socket.io middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { Tork } from '../src/index';
import {
  torkSocketMiddleware,
  torkSocketHandler,
  torkEmit,
  createTorkSocketHandlers,
} from '../src/middleware/socketio';

function createMockSocket(overrides: Partial<any> = {}): any {
  return {
    id: 'socket-1',
    handshake: {
      query: {},
      headers: {},
    },
    data: {},
    emit: vi.fn(),
    on: vi.fn(),
    use: vi.fn(),
    ...overrides,
  };
}

describe('torkSocketMiddleware', () => {
  it('governs handshake query params', () => {
    const tork = new Tork();
    const middleware = torkSocketMiddleware(tork);
    const next = vi.fn();

    const socket = createMockSocket({
      handshake: {
        query: { token: 'SSN: 123-45-6789' },
        headers: {},
      },
    });

    middleware(socket, next);

    expect(socket.data.torkReceipts.length).toBeGreaterThan(0);
    expect(next).toHaveBeenCalled();
  });

  it('sets up packet middleware', () => {
    const tork = new Tork();
    const middleware = torkSocketMiddleware(tork);
    const next = vi.fn();

    const socket = createMockSocket();
    middleware(socket, next);

    expect(socket.use).toHaveBeenCalled();
  });

  it('stores tork on socket data', () => {
    const tork = new Tork();
    const middleware = torkSocketMiddleware(tork);
    const next = vi.fn();

    const socket = createMockSocket();
    middleware(socket, next);

    expect(socket.data.tork).toBe(tork);
  });

  it('governs incoming packet data', () => {
    const tork = new Tork();
    const middleware = torkSocketMiddleware(tork);
    const next = vi.fn();

    const socket = createMockSocket();
    middleware(socket, next);

    // Get the packet middleware function that was registered
    const packetMiddleware = socket.use.mock.calls[0][0];

    const packet: any[] = ['message', 'SSN: 123-45-6789'];
    const packetNext = vi.fn();

    packetMiddleware(packet, packetNext);

    expect(packet[1]).toContain('[SSN_REDACTED]');
    expect(packet[1]).not.toContain('123-45-6789');
    expect(packetNext).toHaveBeenCalled();
  });

  it('respects excludeEvents', () => {
    const tork = new Tork();
    const middleware = torkSocketMiddleware(tork, {
      excludeEvents: ['heartbeat'],
    });
    const next = vi.fn();

    const socket = createMockSocket();
    middleware(socket, next);

    const packetMiddleware = socket.use.mock.calls[0][0];

    const packet: any[] = ['heartbeat', 'SSN: 123-45-6789'];
    const packetNext = vi.fn();

    packetMiddleware(packet, packetNext);

    // Should not be redacted because event is excluded
    expect(packet[1]).toBe('SSN: 123-45-6789');
  });

  it('respects events filter', () => {
    const tork = new Tork();
    const middleware = torkSocketMiddleware(tork, {
      events: ['chat'],
    });
    const next = vi.fn();

    const socket = createMockSocket();
    middleware(socket, next);

    const packetMiddleware = socket.use.mock.calls[0][0];

    // 'other' event should not be governed
    const packet: any[] = ['other', 'SSN: 123-45-6789'];
    const packetNext = vi.fn();
    packetMiddleware(packet, packetNext);
    expect(packet[1]).toBe('SSN: 123-45-6789');

    // 'chat' event should be governed
    const chatPacket: any[] = ['chat', 'SSN: 123-45-6789'];
    packetMiddleware(chatPacket, vi.fn());
    expect(chatPacket[1]).toContain('[SSN_REDACTED]');
  });
});

describe('torkSocketHandler', () => {
  it('governs handler arguments', async () => {
    const tork = new Tork();
    let receivedArg: string = '';

    const handler = torkSocketHandler(tork, (msg: string) => {
      receivedArg = msg;
    });

    await handler('SSN: 123-45-6789');

    expect(receivedArg).toContain('[SSN_REDACTED]');
  });

  it('governs object arguments', async () => {
    const tork = new Tork();
    let receivedArg: any;

    const handler = torkSocketHandler(tork, (data: any) => {
      receivedArg = data;
    });

    await handler({ message: 'Email: admin@secret.com' });

    expect(receivedArg.message).toContain('[EMAIL_REDACTED]');
  });
});

describe('torkEmit', () => {
  it('governs outgoing emit data', () => {
    const tork = new Tork();
    const socket = createMockSocket();

    const emit = torkEmit(tork, socket);
    emit('message', 'SSN: 123-45-6789');

    expect(socket.emit).toHaveBeenCalledWith(
      'message',
      expect.stringContaining('[SSN_REDACTED]'),
    );
  });

  it('governs outgoing object data', () => {
    const tork = new Tork();
    const socket = createMockSocket();

    const emit = torkEmit(tork, socket);
    emit('data', { email: 'admin@secret.com' });

    const emittedData = socket.emit.mock.calls[0][1];
    expect(emittedData.email).toContain('[EMAIL_REDACTED]');
  });

  it('skips governance when governOutgoing is false', () => {
    const tork = new Tork();
    const socket = createMockSocket();

    const emit = torkEmit(tork, socket, { governOutgoing: false });
    emit('message', 'SSN: 123-45-6789');

    expect(socket.emit).toHaveBeenCalledWith('message', 'SSN: 123-45-6789');
  });
});

describe('createTorkSocketHandlers', () => {
  it('creates handler helpers', () => {
    const tork = new Tork();
    const helpers = createTorkSocketHandlers(tork);

    expect(typeof helpers.onConnection).toBe('function');
    expect(typeof helpers.wrapHandler).toBe('function');
    expect(typeof helpers.wrapEmit).toBe('function');
  });

  it('onConnection sets up socket data', () => {
    const tork = new Tork();
    const helpers = createTorkSocketHandlers(tork);
    const handlerFn = vi.fn();

    const connectionHandler = helpers.onConnection(handlerFn);
    const socket = createMockSocket();

    connectionHandler(socket);

    expect(socket.data.tork).toBe(tork);
    expect(handlerFn).toHaveBeenCalledWith(socket);
  });
});
