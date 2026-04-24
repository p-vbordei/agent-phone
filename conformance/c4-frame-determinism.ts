import { encode, decode, type Envelope } from '../src/envelope.ts';
import vectors from './vectors/c4.json' with { type: 'json' };

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export default async function run(): Promise<void> {
  const v = vectors as Record<
    string,
    { plaintext_envelope: Envelope; canonical_json_hex: string }
  >;
  for (const [name, entry] of Object.entries(v)) {
    const bytes = encode(entry.plaintext_envelope);
    const got = hex(bytes);
    if (got !== entry.canonical_json_hex) {
      throw new Error(
        `C4 ${name}: canonical JSON mismatch\n  expected ${entry.canonical_json_hex}\n  got      ${got}`,
      );
    }
    const decoded = decode(bytes);
    if (JSON.stringify(decoded) !== JSON.stringify(entry.plaintext_envelope)) {
      throw new Error(`C4 ${name}: decode roundtrip mismatch`);
    }
  }
}
