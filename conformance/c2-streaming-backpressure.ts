import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

export default async function run(): Promise<void> {
  const resp = generateKeyPair();
  const init = generateKeyPair();
  const respDid = encodeDidKey(resp.publicKey);

  let maxOutstanding = 0;
  let acked = 0;
  const N = 10_000;

  const server = createServer({
    did: respDid,
    privateKey: resp.privateKey,
    handlers: {
      torrent: async function* () {
        for (let i = 0; i < N; i++) {
          const outstanding = i - acked;
          if (outstanding > maxOutstanding) maxOutstanding = outstanding;
          yield i;
        }
      },
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

  const got: number[] = [];
  const credits = 8;
  for await (const v of client.stream('torrent', {}, { credits })) {
    got.push(v as number);
    acked = got.length;
  }
  await client.close();
  await server.close();

  if (got.length !== N) throw new Error(`C2: expected ${N} chunks, got ${got.length}`);
  for (let i = 0; i < N; i++) {
    if (got[i] !== i) throw new Error(`C2: out-of-order at ${i}, got ${got[i]}`);
  }
  // Boundedness check: we grant `credits` at a time, so the server's
  // outstanding-sent-minus-acked should stay bounded. Allow some slack
  // for in-flight network frames and the auto-refresh window.
  if (maxOutstanding > credits * 4) {
    throw new Error(`C2: backpressure blown; maxOutstanding=${maxOutstanding} for credits=${credits}`);
  }
}
