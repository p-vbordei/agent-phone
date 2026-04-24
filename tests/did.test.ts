import { test, expect } from 'bun:test';
import { generateKeyPair, encodeDidKey, decodeDidKey } from '../src/did.ts';

test('encode + decode did:key roundtrips an Ed25519 pubkey', () => {
  const kp = generateKeyPair();
  const did = encodeDidKey(kp.publicKey);
  expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
  const decoded = decodeDidKey(did);
  expect(decoded).toEqual(kp.publicKey);
});

test('decodeDidKey rejects bad multicodec prefix', () => {
  // secp256k1 did:key — valid encoding, wrong algorithm.
  const did = 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme';
  expect(() => decodeDidKey(did)).toThrow();
});

test('decodeDidKey rejects truncated input', () => {
  // Valid base58 for just the 2 multicodec bytes — no pubkey body.
  expect(() => decodeDidKey('did:key:zR2')).toThrow();
});
