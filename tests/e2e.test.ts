import { test, expect } from 'bun:test';
import { generateKeyPair, encodeDidKey, ed25519PubToX25519 } from '../src/did.ts';
import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';

async function pair() {
  const respKp = generateKeyPair();
  const initKp = generateKeyPair();
  const respDid = encodeDidKey(respKp.publicKey);
  const initDid = encodeDidKey(initKp.publicKey);

  const server = createServer({
    did: respDid,
    privateKey: respKp.privateKey,
    handlers: { echo: (params) => params },
  });
  await server.listen(0); // ephemeral port
  const { port } = server.address();

  const client = await connect({
    url: `ws://localhost:${port}`,
    did: initDid,
    privateKey: initKp.privateKey,
    responderDid: respDid,
    responderPublicKey: ed25519PubToX25519(respKp.publicKey),
  });

  return { server, client };
}

test('end-to-end unary echo over Noise_XK + WebSocket', async () => {
  const { server, client } = await pair();
  const result = await client.call('echo', { message: 'hi' });
  expect(result).toEqual({ message: 'hi' });
  await client.close();
  await server.close();
});

test('connect aborts quickly when responder DID does not match the server static', async () => {
  const respKp = generateKeyPair();
  const impersonatorKp = generateKeyPair();
  const respDid = encodeDidKey(respKp.publicKey);

  // Server claims respDid but runs with the impersonator's private key.
  const server = createServer({
    did: respDid,
    privateKey: impersonatorKp.privateKey, // the lie
    handlers: { echo: (p) => p },
  });
  await server.listen(0);
  const { port } = server.address();

  const initKp = generateKeyPair();

  const t0 = Date.now();
  await expect(
    connect({
      url: `ws://localhost:${port}`,
      did: encodeDidKey(initKp.publicKey),
      privateKey: initKp.privateKey,
      responderDid: respDid, // initiator expects respKp
    }),
  ).rejects.toThrow(/handshake/i);
  const elapsed = Date.now() - t0;
  // Should fail fast, not hang. Under 2 seconds even on slow CI.
  expect(elapsed).toBeLessThan(2000);

  await server.close();
});
