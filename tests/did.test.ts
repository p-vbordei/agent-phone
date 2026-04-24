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
  const did = 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme';
  expect(() => decodeDidKey(did)).toThrow();
});
