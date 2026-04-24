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
