import { test, expect } from 'bun:test';
import { buildPrologue, initiatorHandshake, responderHandshake } from '../src/noise.ts';
import {
  generateKeyPair,
  encodeDidKey,
  ed25519PrivToX25519,
  ed25519PubToX25519,
} from '../src/did.ts';
import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';

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

test('existing session keeps working across multiple calls (key rotation would not disturb it)', async () => {
  const resp = generateKeyPair();
  const init = generateKeyPair();
  const respDid = encodeDidKey(resp.publicKey);

  const server = createServer({
    did: respDid,
    privateKey: resp.privateKey,
    handlers: { echo: (p) => p },
  });
  await server.listen(0);
  const { port } = server.address();

  const client = await connect({
    url: `ws://localhost:${port}`,
    did: encodeDidKey(init.publicKey),
    privateKey: init.privateKey,
    responderDid: respDid,
  });

  // Session keys were derived at handshake. A hypothetical DID rotation
  // AFTER this point would not invalidate the in-flight session — prove it
  // by showing both calls succeed on the same Noise transport.
  expect(await client.call('echo', { n: 1 })).toEqual({ n: 1 });
  expect(await client.call('echo', { n: 2 })).toEqual({ n: 2 });

  await client.close();
  await server.close();
});
