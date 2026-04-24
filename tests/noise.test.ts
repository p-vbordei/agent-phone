import { test, expect } from 'bun:test';
import { hmacBlake2s } from '../src/noise.ts';

test('hmacBlake2s matches RFC-style construction length', () => {
  // Sanity check: output is 32 bytes and deterministic.
  const a = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  const b = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  expect(a.length).toBe(32);
  expect(a).toEqual(b);
  const c = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 7]));
  expect(a).not.toEqual(c);
});
