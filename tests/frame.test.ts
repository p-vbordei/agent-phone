import { test, expect } from 'bun:test';
import { FrameCipher } from '../src/frame.ts';
import {
  buildPrologue,
  initiatorHandshake,
  responderHandshake,
} from '../src/noise.ts';
import {
  generateKeyPair,
  ed25519PrivToX25519,
  ed25519PubToX25519,
  encodeDidKey,
} from '../src/did.ts';

function handshake() {
  const i = generateKeyPair();
  const r = generateKeyPair();
  const prologue = buildPrologue(encodeDidKey(i.publicKey), encodeDidKey(r.publicKey));
  const init = initiatorHandshake({
    prologue,
    staticPriv: ed25519PrivToX25519(i.privateKey),
    staticPub: ed25519PubToX25519(i.publicKey),
    responderStaticPub: ed25519PubToX25519(r.publicKey),
  });
  const resp = responderHandshake({
    prologue,
    staticPriv: ed25519PrivToX25519(r.privateKey),
    staticPub: ed25519PubToX25519(r.publicKey),
  });
  resp.readMessage1(init.writeMessage1());
  init.readMessage2(resp.writeMessage2());
  resp.readMessage3(init.writeMessage3());
  return { init: new FrameCipher(init.finish()), resp: new FrameCipher(resp.finish()) };
}

test('frame cipher encrypts + decrypts a plaintext round-trip', () => {
  const { init, resp } = handshake();
  const pt = new TextEncoder().encode('{"hello":"world"}');
  const wire = init.seal(pt);
  const back = resp.open(wire);
  expect(new TextDecoder().decode(back)).toBe('{"hello":"world"}');
});

test('frame cipher rejects tampered ciphertext', () => {
  const { init, resp } = handshake();
  const wire = init.seal(new TextEncoder().encode('x'));
  wire[0] = (wire[0] ?? 0) ^ 0x80; // flip a bit
  expect(() => resp.open(wire)).toThrow();
});

test('seal rejects plaintext exceeding MAX_PLAINTEXT', () => {
  const { init } = handshake();
  const huge = new Uint8Array(65520);
  expect(() => init.seal(huge)).toThrow(/too large/);
});
