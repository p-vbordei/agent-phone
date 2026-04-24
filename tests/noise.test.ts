import { test, expect } from 'bun:test';
import { hmacBlake2s, buildPrologue, initiatorHandshake, responderHandshake } from '../src/noise.ts';
import {
  generateKeyPair,
  ed25519PrivToX25519,
  ed25519PubToX25519,
  encodeDidKey,
} from '../src/did.ts';

test('hmacBlake2s matches RFC-style construction length', () => {
  // Sanity check: output is 32 bytes and deterministic.
  const a = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  const b = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  expect(a.length).toBe(32);
  expect(a).toEqual(b);
  const c = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 7]));
  expect(a).not.toEqual(c);
});

test('prologue is "agent-phone/1" || len||init || len||resp', () => {
  const p = buildPrologue('did:key:zInit', 'did:key:zResp');
  const text = new TextDecoder().decode(p);
  expect(text.startsWith('agent-phone/1')).toBe(true);
  expect(text.endsWith('did:key:zResp')).toBe(true);
  expect(text).toContain('did:key:zInit');
});

test('Noise_XK handshake completes and transport AEAD interops', () => {
  const initEd = generateKeyPair();
  const respEd = generateKeyPair();
  const initDid = encodeDidKey(initEd.publicKey);
  const respDid = encodeDidKey(respEd.publicKey);
  const prologue = buildPrologue(initDid, respDid);

  const initStaticPriv = ed25519PrivToX25519(initEd.privateKey);
  const initStaticPub = ed25519PubToX25519(initEd.publicKey);
  const respStaticPriv = ed25519PrivToX25519(respEd.privateKey);
  const respStaticPub = ed25519PubToX25519(respEd.publicKey);

  const init = initiatorHandshake({
    prologue,
    staticPriv: initStaticPriv,
    staticPub: initStaticPub,
    responderStaticPub: respStaticPub,
  });
  const resp = responderHandshake({
    prologue,
    staticPriv: respStaticPriv,
    staticPub: respStaticPub,
  });

  const m1 = init.writeMessage1();
  resp.readMessage1(m1);
  const m2 = resp.writeMessage2();
  init.readMessage2(m2);
  const m3 = init.writeMessage3();
  resp.readMessage3(m3);

  const initT = init.finish();
  const respT = resp.finish();

  const ct1 = initT.send(new TextEncoder().encode('hi from initiator'));
  expect(new TextDecoder().decode(respT.recv(ct1))).toBe('hi from initiator');

  const ct2 = respT.send(new TextEncoder().encode('hi back'));
  expect(new TextDecoder().decode(initT.recv(ct2))).toBe('hi back');
});

test('Noise_XK handshake aborts if responder static key does not match', () => {
  const initEd = generateKeyPair();
  const respEd = generateKeyPair();
  const otherEd = generateKeyPair();
  const prologue = buildPrologue(encodeDidKey(initEd.publicKey), encodeDidKey(respEd.publicKey));

  const init = initiatorHandshake({
    prologue,
    staticPriv: ed25519PrivToX25519(initEd.privateKey),
    staticPub: ed25519PubToX25519(initEd.publicKey),
    responderStaticPub: ed25519PubToX25519(respEd.publicKey), // initiator expects respEd
  });
  // ...but the actual responder holds otherEd's key
  const resp = responderHandshake({
    prologue,
    staticPriv: ed25519PrivToX25519(otherEd.privateKey),
    staticPub: ed25519PubToX25519(otherEd.publicKey),
  });

  const m1 = init.writeMessage1();
  resp.readMessage1(m1); // accepts — responder doesn't know what initiator expected
  const m2 = resp.writeMessage2();
  expect(() => init.readMessage2(m2)).toThrow(); // AEAD fails under wrong ee/es derivation
});
