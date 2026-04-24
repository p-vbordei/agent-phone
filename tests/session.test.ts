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

test('server stream delivers chunks in order', async () => {
  const { a, b } = linkedSessions();
  b.handle('count', async function* () {
    for (let i = 0; i < 5; i++) yield i;
  });
  const got: number[] = [];
  for await (const chunk of a.stream('count', {}, 10)) got.push(chunk as number);
  expect(got).toEqual([0, 1, 2, 3, 4]);
});

test('server blocks at credit=0 and resumes after credits granted', async () => {
  const { a, b } = linkedSessions();
  let emittedCount = 0;
  b.handle('torrent', async function* () {
    for (let i = 0; i < 20; i++) {
      emittedCount = i + 1;
      yield i;
    }
  });
  const initialCredits = 5;
  const iter = a.stream('torrent', {}, initialCredits)[Symbol.asyncIterator]();

  // Pull just 1 chunk — the other 4 from the initial grant should arrive and sit
  // in the client's queue. Server parks at granted=0 until auto-refill kicks in.
  const first = await iter.next();
  expect(first.value).toBe(0);
  await new Promise((r) => setTimeout(r, 10));
  // At this point: server emitted up to initialCredits chunks, then parked.
  expect(emittedCount).toBeLessThanOrEqual(initialCredits);

  // Drain the rest — auto-refill on the client carries us through.
  const got: number[] = [first.value as number];
  for (;;) {
    const r = await iter.next();
    if (r.done) break;
    got.push(r.value as number);
  }
  expect(got.length).toBe(20);
  expect(got[19]).toBe(19);
});
