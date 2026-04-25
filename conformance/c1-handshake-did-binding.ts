import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

export default async function run(): Promise<void> {
  const real = generateKeyPair();
  const fake = generateKeyPair();
  const realDid = encodeDidKey(real.publicKey);

  // Server claims to be realDid but runs with fake's private key.
  const server = createServer({
    did: realDid,
    privateKey: fake.privateKey,
    handlers: {},
  });
  await server.listen(0);
  const { port } = server.address();

  const init = generateKeyPair();
  let aborted = false;
  try {
    await connect({
      url: `ws://localhost:${port}`,
      did: encodeDidKey(init.publicKey),
      privateKey: init.privateKey,
      responderDid: realDid,
    });
  } catch {
    aborted = true;
  }
  await server.close();
  if (!aborted) throw new Error('C1 failed: initiator accepted impostor');
}
