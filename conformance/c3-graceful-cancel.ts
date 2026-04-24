import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

export default async function run(): Promise<void> {
  const resp = generateKeyPair();
  const init = generateKeyPair();
  const respDid = encodeDidKey(resp.publicKey);

  const server = createServer({
    did: respDid,
    privateKey: resp.privateKey,
    handlers: {
      infinite: async function* () {
        for (let i = 0; ; i++) yield i;
      },
      ping: (p) => p,
    },
  });
  await server.listen(0);
  const { port } = server.address();

  const client = await connect({
    url: `ws://localhost:${port}`,
    did: encodeDidKey(init.publicKey),
    privateKey: init.privateKey,
    responderDid: respDid,
  });

  const iter = client.stream('infinite', {}, { credits: 8 })[Symbol.asyncIterator]();
  for (let i = 0; i < 10; i++) await iter.next();
  // biome-ignore lint/style/noNonNullAssertion: iter.return exists
  await (iter as unknown as { return: () => Promise<void> }).return();
  await new Promise((r) => setTimeout(r, 20));

  const r = await client.call('ping', { still: 'alive' });
  if ((r as { still: string }).still !== 'alive') {
    throw new Error('C3: session dead after cancel');
  }

  await client.close();
  await server.close();
}
