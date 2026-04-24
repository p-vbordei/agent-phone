import { test, expect } from 'bun:test';
import { buildPrologue, initiatorHandshake, responderHandshake } from '../src/noise.ts';
import {
  generateKeyPair,
  encodeDidKey,
  ed25519PrivToX25519,
  ed25519PubToX25519,
} from '../src/did.ts';

test('same initiator running two handshakes produces different ephemerals → different session keys', () => {
  const i = generateKeyPair();
  const r = generateKeyPair();
  const prologue = buildPrologue(encodeDidKey(i.publicKey), encodeDidKey(r.publicKey));
  const iStaticPriv = ed25519PrivToX25519(i.privateKey);
  const iStaticPub = ed25519PubToX25519(i.publicKey);
  const rStaticPriv = ed25519PrivToX25519(r.privateKey);
  const rStaticPub = ed25519PubToX25519(r.publicKey);

  function handshakeOnce(): Uint8Array {
    const a = initiatorHandshake({
      prologue,
      staticPriv: iStaticPriv,
      staticPub: iStaticPub,
      responderStaticPub: rStaticPub,
    });
    const b = responderHandshake({
      prologue,
      staticPriv: rStaticPriv,
      staticPub: rStaticPub,
    });
    b.readMessage1(a.writeMessage1());
    a.readMessage2(b.writeMessage2());
    b.readMessage3(a.writeMessage3());
    const t = a.finish();
    return t.send(new TextEncoder().encode('marker'));
  }

  const ct1 = handshakeOnce();
  const ct2 = handshakeOnce();
  expect(ct1).not.toEqual(ct2);
});
