import { test, expect } from 'bun:test';
import { encode, decode } from '../src/envelope.ts';

test('envelope encodes + decodes a unary request', () => {
  const env = { stream_id: 1, type: 'req' as const, seq: 0, method: 'echo', params: { x: 1 } };
  const bytes = encode(env);
  const back = decode(bytes);
  expect(back).toEqual(env);
});

test('envelope encoding is canonical — key order is sorted', () => {
  const a = encode({
    stream_id: 1,
    type: 'req' as const,
    seq: 0,
    method: 'm',
    params: { b: 2, a: 1 },
  });
  const b = encode({
    stream_id: 1,
    type: 'req' as const,
    seq: 0,
    method: 'm',
    params: { a: 1, b: 2 },
  });
  expect(new TextDecoder().decode(a)).toBe(new TextDecoder().decode(b));
});

test('envelope rejects unknown type', () => {
  const bad = new TextEncoder().encode('{"stream_id":1,"type":"bogus","seq":0}');
  expect(() => decode(bad)).toThrow();
});

test('envelope roundtrips an error frame', () => {
  const env = {
    stream_id: 3,
    type: 'error' as const,
    seq: 0,
    error: { code: -32000, message: 'boom' },
  };
  const bytes = encode(env);
  expect(decode(bytes)).toEqual(env);
});

test('envelope roundtrips a stream chunk with credits', () => {
  const env = {
    stream_id: 5,
    type: 'stream_chunk' as const,
    seq: 42,
    credits: 8,
    result: [1, 2, 3],
  };
  const bytes = encode(env);
  expect(decode(bytes)).toEqual(env);
});
