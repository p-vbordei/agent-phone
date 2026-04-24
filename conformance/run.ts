import c1 from './c1-handshake-did-binding.ts';
import c2 from './c2-streaming-backpressure.ts';
import c3 from './c3-graceful-cancel.ts';
import c4 from './c4-frame-determinism.ts';

const vectors: Array<[string, () => Promise<void>]> = [
  ['C1 — handshake DID-binding', c1],
  ['C2 — streaming backpressure (10 000 chunks)', c2],
  ['C3 — graceful cancel', c3],
  ['C4 — frame decoding determinism', c4],
];

let failed = 0;
for (const [name, run] of vectors) {
  const t = Date.now();
  try {
    await run();
    console.log(`PASS  ${name}  (${Date.now() - t} ms)`);
  } catch (err) {
    failed += 1;
    console.log(`FAIL  ${name}`);
    console.error(err);
  }
}
console.log(`${vectors.length - failed}/${vectors.length} vectors passed`);
process.exit(failed === 0 ? 0 : 1);
