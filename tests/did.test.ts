import { test, expect } from 'bun:test';
import { generateKeyPair, encodeDidKey, decodeDidKey, ed25519PubToX25519, ed25519PrivToX25519 } from '../src/did.ts';
import { x25519 } from '@noble/curves/ed25519';

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

test('Ed25519 keypair converts to a valid X25519 keypair', () => {
  const kp = generateKeyPair();
  const xPriv = ed25519PrivToX25519(kp.privateKey);
  const xPub = ed25519PubToX25519(kp.publicKey);
  expect(xPriv.length).toBe(32);
  expect(xPub.length).toBe(32);
  // The X25519 pubkey derived from the converted private must match the converted public.
  expect(x25519.getPublicKey(xPriv)).toEqual(xPub);
});
