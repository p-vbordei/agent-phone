import { test, expect } from 'bun:test';
import { Session } from '../src/session.ts';
import type { Envelope } from '../src/envelope.ts';

function linkedSessions() {
  let aCb: ((e: Envelope) => void) | null = null;
  let bCb: ((e: Envelope) => void) | null = null;
  const a = new Session(
    {
      send: (e) => {
        queueMicrotask(() => bCb?.(e));
      },
      onRecv: (cb) => {
        aCb = cb;
      },
      close: () => {},
    },
    'initiator',
  );
  const b = new Session(
    {
      send: (e) => {
        queueMicrotask(() => aCb?.(e));
      },
      onRecv: (cb) => {
        bCb = cb;
      },
      close: () => {},
    },
    'responder',
  );
  return { a, b };
}

test('unary request/response round-trips through Session', async () => {
  const { a, b } = linkedSessions();
  b.handle('echo', (params) => params);
  const result = await a.call('echo', { hello: 'world' });
  expect(result).toEqual({ hello: 'world' });
});

test('unknown method returns error frame; call rejects', async () => {
  const { a } = linkedSessions();
  await expect(a.call('no_such_method', {})).rejects.toThrow(/method not found/);
});

test('handler that throws → error frame; caller gets rejection', async () => {
  const { a, b } = linkedSessions();
  b.handle('boom', () => {
    throw new Error('kaboom');
  });
  await expect(a.call('boom', {})).rejects.toThrow(/kaboom/);
});
