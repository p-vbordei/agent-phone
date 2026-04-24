import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

const resp = generateKeyPair();
const init = generateKeyPair();
const respDid = encodeDidKey(resp.publicKey);

const server = createServer({
  did: respDid,
  privateKey: resp.privateKey,
  handlers: {
    echo: (p) => p,
    search: async function* () {
      for (let i = 0; i < 100; i++) yield { i, hit: `result-${i}` };
    },
  },
});
await server.listen(7777);

const client = await connect({
  url: 'ws://localhost:7777',
  did: encodeDidKey(init.publicKey),
  privateKey: init.privateKey,
  responderDid: respDid,
});

console.log('echo:', await client.call('echo', { hello: 'world' }));

let n = 0;
for await (const hit of client.stream('search', { q: 'bun' }, { credits: 8 })) {
  n += 1;
  if (n === 10) break; // cancel after 10 hits
}
console.log(`got ${n} hits, cancelled cleanly`);

console.log('still alive:', await client.call('echo', { back: 'to unary' }));

await client.close();
await server.close();
