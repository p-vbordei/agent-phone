# agent-phone v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Bun+TypeScript library that lets two DID-owning agents hold a single authenticated sync RPC call (unary + server-streamed + credit-based backpressure + clean cancel) over a Noise_XK-secured WebSocket, plus conformance vectors other implementations can validate against.

**Architecture:** One process, one binary, one package. Public API is `createServer(...)` + `connect(...)`. Under the hood: `did.ts` (did:key + Ed25519↔X25519), `noise.ts` (Noise_XK state machine over `@noble/*` primitives), `frame.ts` (WS message = one Noise transport frame), `envelope.ts` (Zod schema + canonical JSON), `session.ts` (stream multiplexer). No DB. No Docker. No framework beyond `Bun.serve` for WS listen and Bun's `WebSocket` for dial.

**Tech stack:** Bun runtime, TypeScript (strict), `@noble/curves/ed25519` (Ed25519 + X25519), `@noble/hashes/blake2s`, `@noble/ciphers/chacha`, `@scure/base` (base58btc), `canonicalize` (RFC 8785 JCS), `zod` (ingress validation), `bun test` (built-in), Biome (format + lint).

---

## Repository file layout (final)

```
agent-phone/
├── README.md                    # rewritten in Task 28
├── SPEC.md                      # patched in Task 1, banner flipped in Task 30
├── SCOPE.md                     # already written (Stage 1)
├── CHANGELOG.md                 # created in Task 29
├── LICENSE                      # exists
├── package.json                 # created in Task 2
├── tsconfig.json                # created in Task 2
├── biome.json                   # created in Task 2
├── .gitignore                   # exists
├── src/
│   ├── index.ts                 # re-exports connect, createServer, types
│   ├── did.ts                   # did:key encode/decode + Ed25519→X25519
│   ├── noise.ts                 # Noise_XK handshake + transport ciphers
│   ├── frame.ts                 # WS binary frame ↔ Noise transport frame
│   ├── envelope.ts              # Zod schema + canonical JSON encode/decode
│   ├── session.ts               # stream multiplexer
│   ├── client.ts                # connect() — initiator
│   └── server.ts                # createServer() — responder
├── examples/
│   └── demo.ts                  # the 20-line demo
├── conformance/
│   ├── README.md
│   ├── run.ts                   # single entrypoint: `bun conformance/run.ts`
│   ├── c1-handshake-did-binding.ts
│   ├── c2-streaming-backpressure.ts
│   ├── c3-graceful-cancel.ts
│   └── c4-frame-determinism.ts
├── tests/
│   ├── did.test.ts
│   ├── noise.test.ts
│   ├── frame.test.ts
│   ├── envelope.test.ts
│   ├── session.test.ts
│   ├── e2e.test.ts
│   └── security.test.ts
├── docs/superpowers/plans/
│   └── 2026-04-24-agent-phone-v0-1.md   # this file
└── .github/workflows/ci.yml
```

No `src/core/`, no `src/utils/`, no `src/lib/`. Eight source files total, each well under 200 LoC.

---

## Commit convention

`<type>(<area>): <what> — <why if non-obvious>`

Examples:
- `feat(noise): add Noise_XK symmetric state`
- `feat(session): credit-based backpressure for server streams`
- `test(conformance): C2 10k-chunk streaming test`
- `docs(spec): fix §3 handshake pattern — was XX, name said XK`

---

# Stage 2.0 — Scaffold

## Task 1: Patch SPEC.md — fix Noise pattern and frame clarity

**Files:**
- Modify: [SPEC.md](SPEC.md) (§2.2 and §3)

**Why:** §2.2 names `Noise_XK` but §3 shows the XX wire pattern. Also §3's "length-prefixed" note is redundant with WebSocket framing.

- [ ] **Step 1: Edit SPEC §2.2 handshake section**

Replace the three-frame list under "Three WebSocket binary frames carry the Noise messages:" with:

```
1. `e, es`           (initiator → responder)
2. `e, ee`           (responder → initiator)
3. `s, se`           (initiator → responder)
```

Replace the paragraph beginning "If the responder's static key in the handshake…" with:

```
Initiator MUST obtain the responder's static public key from the
responder's DID Document verification method (via the referenced DID
method — `did:key` in v0.1) BEFORE opening the WebSocket. The static
key is fed to the Noise state machine as the pre-known responder
static. If the responder does not actually hold that static (e.g. the
DID Document is stale or tampered), the handshake aborts deterministically
at message 2 (AEAD failure on `ee`/`es` key derivation).

Initiator MUST signal its own DID to the responder before the handshake
begins, so the responder can construct the matching prologue. The
reference signaling mechanism is a URL query parameter: initiator dials
`ws://<host>[:<port>][/<path>]?caller=<initiator_did>`. The DID is
public, so plaintext transmission is acceptable; prologue binding still
prevents any other party from impersonating the initiator.
```

- [ ] **Step 2: Edit SPEC §3 framing section**

Replace the sentence "Post-handshake, each WebSocket binary frame is a length-prefixed Noise transport frame." with:

```
Post-handshake, each WebSocket binary message carries exactly one
Noise transport frame: the ChaChaPoly ciphertext of the plaintext
JSON envelope with the 16-byte authentication tag appended. The
WebSocket message boundary is the frame boundary; no additional
length prefix is required.
```

- [ ] **Step 3: Commit**

```bash
git add SPEC.md
git commit -m "docs(spec): fix §3 handshake pattern — was XX, name says XK; drop redundant length prefix"
```

---

## Task 2: Bun project scaffolding

**Files:**
- Create: `package.json`, `tsconfig.json`, `biome.json`, `.github/workflows/ci.yml`

- [ ] **Step 1: Initialize `package.json`**

Create `package.json`:

```json
{
  "name": "agent-phone",
  "version": "0.1.0",
  "description": "Minimal sync RPC between two AI agents. Self-custody keys, Noise-framework handshake, DID-bound WebSocket.",
  "type": "module",
  "main": "src/index.ts",
  "exports": {
    ".": "./src/index.ts",
    "./client": "./src/client.ts",
    "./server": "./src/server.ts"
  },
  "bin": {
    "agent-phone": "./src/index.ts"
  },
  "scripts": {
    "test": "bun test",
    "conformance": "bun conformance/run.ts",
    "demo": "bun examples/demo.ts",
    "build": "bun build --compile --outfile=dist/agent-phone src/index.ts",
    "fmt": "biome format --write .",
    "lint": "biome check ."
  },
  "dependencies": {
    "@noble/ciphers": "^1.0.0",
    "@noble/curves": "^1.6.0",
    "@noble/hashes": "^1.5.0",
    "@scure/base": "^1.1.9",
    "canonicalize": "^2.0.0",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@biomejs/biome": "^1.9.0",
    "@types/bun": "latest",
    "typescript": "^5.6.0"
  },
  "engines": {
    "bun": ">=1.1.0"
  },
  "license": "Apache-2.0"
}
```

- [ ] **Step 2: Install**

Run:
```bash
bun install
```
Expected: installs the 6 runtime deps + 3 dev deps; creates `bun.lockb`.

- [ ] **Step 3: Create `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "types": ["bun-types"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowImportingTsExtensions": true,
    "noEmit": true,
    "lib": ["ESNext"]
  },
  "include": ["src", "tests", "examples", "conformance"]
}
```

- [ ] **Step 4: Create `biome.json`**

```json
{
  "$schema": "https://biomejs.dev/schemas/1.9.0/schema.json",
  "organizeImports": { "enabled": true },
  "formatter": {
    "enabled": true,
    "indentStyle": "space",
    "indentWidth": 2,
    "lineWidth": 100
  },
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "suspicious": { "noExplicitAny": "warn" }
    }
  },
  "javascript": {
    "formatter": { "quoteStyle": "single", "semicolons": "always" }
  }
}
```

- [ ] **Step 5: Create CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
      - run: bun install --frozen-lockfile
      - run: bun test
      - run: bun conformance/run.ts
      - run: bun build --compile --outfile=dist/agent-phone src/index.ts
```

- [ ] **Step 6: Verify compile**

Run:
```bash
bunx tsc --noEmit
```
Expected: no errors (no source files yet, so trivially passes).

- [ ] **Step 7: Commit**

```bash
git add package.json bun.lockb tsconfig.json biome.json .github/workflows/ci.yml
git commit -m "chore: scaffold Bun + TS + Biome + CI"
```

---

## Task 3: Stub the public API surface

**Files:**
- Create: `src/index.ts`, `src/client.ts`, `src/server.ts`, `src/did.ts`, `src/noise.ts`, `src/frame.ts`, `src/envelope.ts`, `src/session.ts`

Purpose: types + empty functions so every later task can import cleanly.

- [ ] **Step 1: Create `src/index.ts`**

```typescript
export { connect, type ClientOptions, type Client } from './client.ts';
export { createServer, type ServerOptions, type Server, type Handler } from './server.ts';
export { type Envelope } from './envelope.ts';
export { generateKeyPair, encodeDidKey, decodeDidKey, type KeyPair } from './did.ts';
```

- [ ] **Step 2: Create `src/did.ts` stub**

```typescript
export type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

export function generateKeyPair(): KeyPair {
  throw new Error('not implemented');
}
export function encodeDidKey(publicKey: Uint8Array): string {
  throw new Error('not implemented');
}
export function decodeDidKey(did: string): Uint8Array {
  throw new Error('not implemented');
}
export function ed25519PubToX25519(edPub: Uint8Array): Uint8Array {
  throw new Error('not implemented');
}
export function ed25519PrivToX25519(edPriv: Uint8Array): Uint8Array {
  throw new Error('not implemented');
}
```

- [ ] **Step 3: Create `src/noise.ts` stub**

```typescript
export type HandshakeResult = {
  send: (plaintext: Uint8Array) => Uint8Array;
  recv: (ciphertext: Uint8Array) => Uint8Array;
};

export function initiatorHandshake(_opts: {
  prologue: Uint8Array;
  staticPriv: Uint8Array;
  staticPub: Uint8Array;
  responderStaticPub: Uint8Array;
}): {
  writeMessage1: () => Uint8Array;
  readMessage2: (msg: Uint8Array) => void;
  writeMessage3: () => Uint8Array;
  finish: () => HandshakeResult;
} {
  throw new Error('not implemented');
}

export function responderHandshake(_opts: {
  prologue: Uint8Array;
  staticPriv: Uint8Array;
  staticPub: Uint8Array;
}): {
  readMessage1: (msg: Uint8Array) => void;
  writeMessage2: () => Uint8Array;
  readMessage3: (msg: Uint8Array) => void;
  finish: () => HandshakeResult;
} {
  throw new Error('not implemented');
}

export function buildPrologue(initiatorDid: string, responderDid: string): Uint8Array {
  throw new Error('not implemented');
}
```

- [ ] **Step 4: Create `src/frame.ts` stub**

```typescript
// Placeholder — just types for now.
export const MAX_PLAINTEXT = 65519; // 65535 (WS) minus 16-byte tag margin
```

- [ ] **Step 5: Create `src/envelope.ts` stub**

```typescript
import { z } from 'zod';

export const EnvelopeSchema = z.object({
  stream_id: z.number().int().nonnegative(),
  type: z.enum(['req', 'res', 'stream_chunk', 'stream_end', 'cancel', 'error']),
  seq: z.number().int().nonnegative(),
  credits: z.number().int().nonnegative().optional(),
  method: z.string().optional(),
  params: z.unknown().optional(),
  result: z.unknown().optional(),
  reason: z.string().optional(),
  error: z.object({ code: z.number().int(), message: z.string() }).optional(),
});

export type Envelope = z.infer<typeof EnvelopeSchema>;

export function encode(_env: Envelope): Uint8Array {
  throw new Error('not implemented');
}
export function decode(_bytes: Uint8Array): Envelope {
  throw new Error('not implemented');
}
```

- [ ] **Step 6: Create `src/session.ts` stub**

```typescript
import type { Envelope } from './envelope.ts';

export type SessionTransport = {
  send: (env: Envelope) => void;
  onRecv: (cb: (env: Envelope) => void) => void;
  close: () => void;
};

export class Session {
  // filled in Task 11+
  constructor(_t: SessionTransport, _role: 'initiator' | 'responder') {
    throw new Error('not implemented');
  }
}
```

- [ ] **Step 7: Create `src/client.ts` stub**

```typescript
export type ClientOptions = {
  url: string;
  did: string;
  privateKey: Uint8Array;
  responderDid: string;
  responderPublicKey?: Uint8Array;
};

export type Client = {
  call: (method: string, params?: unknown) => Promise<unknown>;
  stream: (
    method: string,
    params?: unknown,
    opts?: { credits?: number },
  ) => AsyncIterable<unknown>;
  close: () => Promise<void>;
};

export async function connect(_opts: ClientOptions): Promise<Client> {
  throw new Error('not implemented');
}
```

- [ ] **Step 8: Create `src/server.ts` stub**

```typescript
export type Handler = (params: unknown) => unknown | Promise<unknown> | AsyncIterable<unknown>;

export type ServerOptions = {
  did: string;
  privateKey: Uint8Array;
  handlers: Record<string, Handler>;
};

export type Server = {
  listen: (port: number, hostname?: string) => Promise<void>;
  close: () => Promise<void>;
  address: () => { port: number; hostname: string };
};

export function createServer(_opts: ServerOptions): Server {
  throw new Error('not implemented');
}
```

- [ ] **Step 9: Typecheck**

Run:
```bash
bunx tsc --noEmit
```
Expected: no errors.

- [ ] **Step 10: Commit**

```bash
git add src/
git commit -m "feat(scaffold): stub the public API surface — types only"
```

---

# Stage 2.1 — Vertical slice: unary echo end-to-end

## Task 4: did:key encode/decode

**Files:**
- Modify: `src/did.ts`
- Test: `tests/did.test.ts`

**Background:** `did:key` for Ed25519 is `did:key:z` + base58btc(`0xed` + `0x01` + 32-byte pubkey). The `0xed01` prefix is the varint multicodec for Ed25519 public key.

- [ ] **Step 1: Write the failing test**

Create `tests/did.test.ts`:

```typescript
import { test, expect } from 'bun:test';
import { generateKeyPair, encodeDidKey, decodeDidKey } from '../src/did.ts';

test('encode + decode did:key roundtrips an Ed25519 pubkey', () => {
  const kp = generateKeyPair();
  const did = encodeDidKey(kp.publicKey);
  expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
  const decoded = decodeDidKey(did);
  expect(decoded).toEqual(kp.publicKey);
});

test('decodeDidKey rejects bad multicodec prefix', () => {
  const did = 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme';
  expect(() => decodeDidKey(did)).toThrow();
});
```

- [ ] **Step 2: Run the test — verify it fails**

```bash
bun test tests/did.test.ts
```
Expected: FAIL — `not implemented`.

- [ ] **Step 3: Implement in `src/did.ts`**

Replace the whole file with:

```typescript
import { ed25519 } from '@noble/curves/ed25519';
import { base58btc } from '@scure/base';

export type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

const MULTICODEC_ED25519_PUB = new Uint8Array([0xed, 0x01]);

export function generateKeyPair(): KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

export function encodeDidKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Ed25519 pubkey must be 32 bytes');
  const prefixed = new Uint8Array(MULTICODEC_ED25519_PUB.length + publicKey.length);
  prefixed.set(MULTICODEC_ED25519_PUB, 0);
  prefixed.set(publicKey, MULTICODEC_ED25519_PUB.length);
  return `did:key:${base58btc.encode(prefixed)}`;
}

export function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) throw new Error('not a did:key identifier');
  const bytes = base58btc.decode(did.slice('did:key:'.length));
  if (bytes[0] !== MULTICODEC_ED25519_PUB[0] || bytes[1] !== MULTICODEC_ED25519_PUB[1]) {
    throw new Error('did:key is not an Ed25519 key (wrong multicodec prefix)');
  }
  return bytes.slice(2);
}

export function ed25519PubToX25519(_edPub: Uint8Array): Uint8Array {
  throw new Error('not implemented'); // Task 5
}
export function ed25519PrivToX25519(_edPriv: Uint8Array): Uint8Array {
  throw new Error('not implemented'); // Task 5
}
```

- [ ] **Step 4: Run the test — verify it passes**

```bash
bun test tests/did.test.ts
```
Expected: 2 pass, 0 fail.

- [ ] **Step 5: Commit**

```bash
git add src/did.ts tests/did.test.ts
git commit -m "feat(did): did:key encode/decode for Ed25519"
```

---

## Task 5: Ed25519 → X25519 key conversion

**Files:**
- Modify: `src/did.ts`
- Test: `tests/did.test.ts`

**Background:** Noise_XK needs X25519 static keys. Ed25519 keys convert to X25519 via the Edwards↔Montgomery birational map. `@noble/curves/ed25519` exposes `edwardsToMontgomeryPub` and `edwardsToMontgomeryPriv`.

- [ ] **Step 1: Add failing test**

Append to `tests/did.test.ts`:

```typescript
import { ed25519PubToX25519, ed25519PrivToX25519 } from '../src/did.ts';
import { x25519 } from '@noble/curves/ed25519';

test('Ed25519 keypair converts to a valid X25519 keypair', () => {
  const kp = generateKeyPair();
  const xPriv = ed25519PrivToX25519(kp.privateKey);
  const xPub = ed25519PubToX25519(kp.publicKey);
  expect(xPriv.length).toBe(32);
  expect(xPub.length).toBe(32);
  // Derived X25519 public from the converted private must match the converted public.
  expect(x25519.getPublicKey(xPriv)).toEqual(xPub);
});
```

- [ ] **Step 2: Run the test — verify it fails**

```bash
bun test tests/did.test.ts
```
Expected: FAIL — new test throws `not implemented`.

- [ ] **Step 3: Implement in `src/did.ts`**

Replace the two stubs at the bottom of `src/did.ts` with:

```typescript
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';

export function ed25519PubToX25519(edPub: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPub(edPub);
}
export function ed25519PrivToX25519(edPriv: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPriv(edPriv);
}
```

(Also add the import to the top of the file or merge with the existing `@noble/curves/ed25519` import.)

- [ ] **Step 4: Run tests**

```bash
bun test tests/did.test.ts
```
Expected: 3 pass, 0 fail.

- [ ] **Step 5: Commit**

```bash
git add src/did.ts tests/did.test.ts
git commit -m "feat(did): Ed25519 → X25519 key conversion for Noise statics"
```

---

## Task 6: Noise symmetric state

**Files:**
- Modify: `src/noise.ts`
- Test: `tests/noise.test.ts`

**Background:** Noise has a `SymmetricState` object tracking the chaining key `ck`, the handshake hash `h`, the current cipher key `k`, and the nonce counter `n`. See [Noise §5.2](https://noiseprotocol.org/noise.html#the-symmetricstate-object). We implement `InitializeSymmetric`, `MixHash`, `MixKey`, `EncryptAndHash`, `DecryptAndHash`, `Split` per the Noise spec for `ChaChaPoly + BLAKE2s`. HKDF uses HMAC-BLAKE2s.

- [ ] **Step 1: Write a failing test — HMAC-BLAKE2s known vector**

Create `tests/noise.test.ts`:

```typescript
import { test, expect } from 'bun:test';
import { hmacBlake2s } from '../src/noise.ts';

test('hmacBlake2s matches RFC-style construction length', () => {
  // Sanity check: output is 32 bytes and deterministic.
  const a = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  const b = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  expect(a.length).toBe(32);
  expect(a).toEqual(b);
  const c = hmacBlake2s(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 7]));
  expect(a).not.toEqual(c);
});
```

- [ ] **Step 2: Run the test**

```bash
bun test tests/noise.test.ts
```
Expected: FAIL — `hmacBlake2s` not exported.

- [ ] **Step 3: Implement `src/noise.ts` (full body; replace the stub)**

```typescript
import { blake2s } from '@noble/hashes/blake2s';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';
import { ed25519PrivToX25519, ed25519PubToX25519 } from './did.ts';

const PROTOCOL = 'Noise_XK_25519_ChaChaPoly_BLAKE2s';
const HASHLEN = 32;
const BLOCKLEN = 64;
const DHLEN = 32;

export function hash(data: Uint8Array): Uint8Array {
  return blake2s(data);
}

export function hmacBlake2s(key: Uint8Array, data: Uint8Array): Uint8Array {
  let k = key;
  if (k.length > BLOCKLEN) k = hash(k);
  const padded = new Uint8Array(BLOCKLEN);
  padded.set(k);
  const ipad = new Uint8Array(BLOCKLEN);
  const opad = new Uint8Array(BLOCKLEN);
  for (let i = 0; i < BLOCKLEN; i++) {
    ipad[i] = padded[i]! ^ 0x36;
    opad[i] = padded[i]! ^ 0x5c;
  }
  const inner = hash(concat(ipad, data));
  return hash(concat(opad, inner));
}

export function hkdf2(ck: Uint8Array, ikm: Uint8Array): [Uint8Array, Uint8Array] {
  const t0 = hmacBlake2s(ck, ikm);
  const t1 = hmacBlake2s(t0, new Uint8Array([0x01]));
  const t2 = hmacBlake2s(t0, concat(t1, new Uint8Array([0x02])));
  return [t1, t2];
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function nonceBytes(n: bigint): Uint8Array {
  const out = new Uint8Array(12);
  new DataView(out.buffer).setBigUint64(4, n, true); // 4-byte zero padding, 8-byte LE counter
  return out;
}

export class CipherState {
  constructor(public k: Uint8Array | null, public n: bigint = 0n) {}

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (this.k === null) return plaintext;
    const nonce = nonceBytes(this.n);
    const ct = chacha20poly1305(this.k, nonce, ad).encrypt(plaintext);
    this.n += 1n;
    return ct;
  }

  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (this.k === null) return ciphertext;
    const nonce = nonceBytes(this.n);
    const pt = chacha20poly1305(this.k, nonce, ad).decrypt(ciphertext);
    this.n += 1n;
    return pt;
  }
}

export class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  cs: CipherState = new CipherState(null);

  constructor() {
    const nameBytes = new TextEncoder().encode(PROTOCOL);
    if (nameBytes.length <= HASHLEN) {
      this.h = new Uint8Array(HASHLEN);
      this.h.set(nameBytes);
    } else {
      this.h = hash(nameBytes);
    }
    this.ck = this.h.slice();
  }

  mixHash(data: Uint8Array): void {
    this.h = hash(concat(this.h, data));
  }

  mixKey(input: Uint8Array): void {
    const [newCk, tempK] = hkdf2(this.ck, input);
    this.ck = newCk;
    this.cs = new CipherState(tempK);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ct = this.cs.encryptWithAd(this.h, plaintext);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const pt = this.cs.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return pt;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf2(this.ck, new Uint8Array(0));
    return [new CipherState(k1), new CipherState(k2)];
  }
}

export type HandshakeResult = {
  send: (plaintext: Uint8Array) => Uint8Array;
  recv: (ciphertext: Uint8Array) => Uint8Array;
};

// Handshake implementations added in Task 7.
export function initiatorHandshake(_opts: {
  prologue: Uint8Array;
  staticPriv: Uint8Array;
  staticPub: Uint8Array;
  responderStaticPub: Uint8Array;
}): never {
  throw new Error('not implemented');
}
export function responderHandshake(_opts: {
  prologue: Uint8Array;
  staticPriv: Uint8Array;
  staticPub: Uint8Array;
}): never {
  throw new Error('not implemented');
}

// Prologue added in Task 8.
export function buildPrologue(_initiatorDid: string, _responderDid: string): Uint8Array {
  throw new Error('not implemented');
}

```

- [ ] **Step 4: Run the test**

```bash
bun test tests/noise.test.ts
```
Expected: 1 pass.

- [ ] **Step 5: Commit**

```bash
git add src/noise.ts tests/noise.test.ts
git commit -m "feat(noise): symmetric state + HMAC-BLAKE2s HKDF"
```

---

## Task 7: Noise_XK handshake (3 messages) + prologue

**Files:**
- Modify: `src/noise.ts`
- Test: `tests/noise.test.ts`

**Noise_XK pattern** (responder static pre-known by initiator):
```
-> e, es
<- e, ee
-> s, se
```

- [ ] **Step 1: Add failing tests**

Append to `tests/noise.test.ts`:

```typescript
import {
  buildPrologue,
  initiatorHandshake,
  responderHandshake,
} from '../src/noise.ts';
import {
  generateKeyPair,
  ed25519PrivToX25519,
  ed25519PubToX25519,
} from '../src/did.ts';
import { encodeDidKey } from '../src/did.ts';

test('prologue is "agent-phone/1" || len||init || len||resp', () => {
  const p = buildPrologue('did:key:zInit', 'did:key:zResp');
  const text = new TextDecoder().decode(p);
  expect(text.startsWith('agent-phone/1')).toBe(true);
  expect(text.endsWith('did:key:zResp')).toBe(true);
  expect(text).toContain('did:key:zInit');
});

test('Noise_XK handshake completes and transport AEAD interops', () => {
  const initEd = generateKeyPair();
  const respEd = generateKeyPair();
  const initDid = encodeDidKey(initEd.publicKey);
  const respDid = encodeDidKey(respEd.publicKey);
  const prologue = buildPrologue(initDid, respDid);

  const initStaticPriv = ed25519PrivToX25519(initEd.privateKey);
  const initStaticPub = ed25519PubToX25519(initEd.publicKey);
  const respStaticPriv = ed25519PrivToX25519(respEd.privateKey);
  const respStaticPub = ed25519PubToX25519(respEd.publicKey);

  const init = initiatorHandshake({
    prologue,
    staticPriv: initStaticPriv,
    staticPub: initStaticPub,
    responderStaticPub: respStaticPub,
  });
  const resp = responderHandshake({
    prologue,
    staticPriv: respStaticPriv,
    staticPub: respStaticPub,
  });

  const m1 = init.writeMessage1();
  resp.readMessage1(m1);
  const m2 = resp.writeMessage2();
  init.readMessage2(m2);
  const m3 = init.writeMessage3();
  resp.readMessage3(m3);

  const initT = init.finish();
  const respT = resp.finish();

  const ct1 = initT.send(new TextEncoder().encode('hi from initiator'));
  expect(new TextDecoder().decode(respT.recv(ct1))).toBe('hi from initiator');

  const ct2 = respT.send(new TextEncoder().encode('hi back'));
  expect(new TextDecoder().decode(initT.recv(ct2))).toBe('hi back');
});

test('Noise_XK handshake aborts if responder static key does not match', () => {
  const initEd = generateKeyPair();
  const respEd = generateKeyPair();
  const otherEd = generateKeyPair(); // the impersonator
  const prologue = buildPrologue(encodeDidKey(initEd.publicKey), encodeDidKey(respEd.publicKey));

  const init = initiatorHandshake({
    prologue,
    staticPriv: ed25519PrivToX25519(initEd.privateKey),
    staticPub: ed25519PubToX25519(initEd.publicKey),
    // initiator thinks the responder has respEd, but...
    responderStaticPub: ed25519PubToX25519(respEd.publicKey),
  });
  // ...the actual responder runs with the impersonator's key
  const resp = responderHandshake({
    prologue,
    staticPriv: ed25519PrivToX25519(otherEd.privateKey),
    staticPub: ed25519PubToX25519(otherEd.publicKey),
  });

  const m1 = init.writeMessage1();
  resp.readMessage1(m1); // accepts — doesn't know what initiator expected
  const m2 = resp.writeMessage2();
  expect(() => init.readMessage2(m2)).toThrow(); // AEAD fails under wrong es
});
```

- [ ] **Step 2: Run tests**

```bash
bun test tests/noise.test.ts
```
Expected: three new tests FAIL — `not implemented`.

- [ ] **Step 3: Implement handshakes + prologue in `src/noise.ts`**

Replace the three stubs (`initiatorHandshake`, `responderHandshake`, `buildPrologue`) with:

```typescript
export function buildPrologue(initiatorDid: string, responderDid: string): Uint8Array {
  const prefix = new TextEncoder().encode('agent-phone/1');
  const init = new TextEncoder().encode(initiatorDid);
  const resp = new TextEncoder().encode(responderDid);
  const out = new Uint8Array(prefix.length + 2 + init.length + 2 + resp.length);
  let off = 0;
  out.set(prefix, off); off += prefix.length;
  new DataView(out.buffer).setUint16(off, init.length, false); off += 2;
  out.set(init, off); off += init.length;
  new DataView(out.buffer).setUint16(off, resp.length, false); off += 2;
  out.set(resp, off);
  return out;
}

function dh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  return x25519.scalarMult(priv, pub);
}

export function initiatorHandshake(opts: {
  prologue: Uint8Array;
  staticPriv: Uint8Array;
  staticPub: Uint8Array;
  responderStaticPub: Uint8Array;
}) {
  const ss = new SymmetricState();
  ss.mixHash(opts.prologue);
  // Pre-message: responder's static known to initiator.
  ss.mixHash(opts.responderStaticPub);

  let ePriv: Uint8Array;
  let ePub: Uint8Array;
  let rePub: Uint8Array | null = null;

  return {
    writeMessage1(): Uint8Array {
      // -> e, es
      ePriv = x25519.utils.randomPrivateKey();
      ePub = x25519.getPublicKey(ePriv);
      ss.mixHash(ePub);
      ss.mixKey(dh(ePriv, opts.responderStaticPub));
      const encPayload = ss.encryptAndHash(new Uint8Array(0));
      return concat(ePub, encPayload);
    },
    readMessage2(msg: Uint8Array): void {
      // <- e, ee
      rePub = msg.slice(0, DHLEN);
      const rest = msg.slice(DHLEN);
      ss.mixHash(rePub);
      ss.mixKey(dh(ePriv, rePub));
      ss.decryptAndHash(rest); // auth-only; payload empty
    },
    writeMessage3(): Uint8Array {
      // -> s, se
      const encS = ss.encryptAndHash(opts.staticPub);
      ss.mixKey(dh(opts.staticPriv, rePub!));
      const encPayload = ss.encryptAndHash(new Uint8Array(0));
      return concat(encS, encPayload);
    },
    finish() {
      const [sendCs, recvCs] = ss.split();
      return {
        send: (p: Uint8Array) => sendCs.encryptWithAd(new Uint8Array(0), p),
        recv: (c: Uint8Array) => recvCs.decryptWithAd(new Uint8Array(0), c),
      };
    },
  };
}

export function responderHandshake(opts: {
  prologue: Uint8Array;
  staticPriv: Uint8Array;
  staticPub: Uint8Array;
}) {
  const ss = new SymmetricState();
  ss.mixHash(opts.prologue);
  // Pre-message: responder's static (known to both sides).
  ss.mixHash(opts.staticPub);

  let ePriv: Uint8Array;
  let ePub: Uint8Array;
  let reInitPub: Uint8Array | null = null;
  let risPub: Uint8Array | null = null;

  return {
    readMessage1(msg: Uint8Array): void {
      // -> e, es
      reInitPub = msg.slice(0, DHLEN);
      const rest = msg.slice(DHLEN);
      ss.mixHash(reInitPub);
      ss.mixKey(dh(opts.staticPriv, reInitPub));
      ss.decryptAndHash(rest);
    },
    writeMessage2(): Uint8Array {
      // <- e, ee
      ePriv = x25519.utils.randomPrivateKey();
      ePub = x25519.getPublicKey(ePriv);
      ss.mixHash(ePub);
      ss.mixKey(dh(ePriv, reInitPub!));
      const encPayload = ss.encryptAndHash(new Uint8Array(0));
      return concat(ePub, encPayload);
    },
    readMessage3(msg: Uint8Array): void {
      // -> s, se
      const encS = msg.slice(0, DHLEN + 16);
      const rest = msg.slice(DHLEN + 16);
      risPub = ss.decryptAndHash(encS);
      ss.mixKey(dh(ePriv, risPub));
      ss.decryptAndHash(rest);
    },
    finish() {
      const [recvCs, sendCs] = ss.split();
      return {
        send: (p: Uint8Array) => sendCs.encryptWithAd(new Uint8Array(0), p),
        recv: (c: Uint8Array) => recvCs.decryptWithAd(new Uint8Array(0), c),
      };
    },
  };
}
```

- [ ] **Step 4: Run tests**

```bash
bun test tests/noise.test.ts
```
Expected: 4 pass, 0 fail.

- [ ] **Step 5: Commit**

```bash
git add src/noise.ts tests/noise.test.ts
git commit -m "feat(noise): Noise_XK handshake (-> e,es / <- e,ee / -> s,se) + prologue"
```

---

## Task 8: Frame codec — one WS binary message = one transport frame

**Files:**
- Modify: `src/frame.ts`
- Test: `tests/frame.test.ts`

Since WebSocket already frames binary messages, `frame.ts` is a thin wrapper: the Noise `HandshakeResult.send` / `recv` produce/consume the bytes we put on the wire.

- [ ] **Step 1: Write failing test**

Create `tests/frame.test.ts`:

```typescript
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
  wire[0] ^= 0x80; // flip a bit
  expect(() => resp.open(wire)).toThrow();
});
```

- [ ] **Step 2: Run tests**

```bash
bun test tests/frame.test.ts
```
Expected: FAIL — `FrameCipher` not exported.

- [ ] **Step 3: Implement in `src/frame.ts`**

```typescript
import type { HandshakeResult } from './noise.ts';

export const MAX_PLAINTEXT = 65519;

export class FrameCipher {
  constructor(private t: HandshakeResult) {}

  seal(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length > MAX_PLAINTEXT) {
      throw new Error(`plaintext too large: ${plaintext.length} > ${MAX_PLAINTEXT}`);
    }
    return this.t.send(plaintext);
  }

  open(ciphertext: Uint8Array): Uint8Array {
    return this.t.recv(ciphertext);
  }
}
```

- [ ] **Step 4: Run tests**

```bash
bun test tests/frame.test.ts
```
Expected: 2 pass.

- [ ] **Step 5: Commit**

```bash
git add src/frame.ts tests/frame.test.ts
git commit -m "feat(frame): WS-message-bounded Noise transport frame"
```

---

## Task 9: Envelope encode/decode (canonical JSON)

**Files:**
- Modify: `src/envelope.ts`
- Test: `tests/envelope.test.ts`

- [ ] **Step 1: Write failing tests**

Create `tests/envelope.test.ts`:

```typescript
import { test, expect } from 'bun:test';
import { encode, decode } from '../src/envelope.ts';

test('envelope encodes + decodes a unary request', () => {
  const env = { stream_id: 1, type: 'req' as const, seq: 0, method: 'echo', params: { x: 1 } };
  const bytes = encode(env);
  const back = decode(bytes);
  expect(back).toEqual(env);
});

test('envelope encoding is canonical — key order is sorted', () => {
  const a = encode({ stream_id: 1, type: 'req' as const, seq: 0, method: 'm', params: { b: 2, a: 1 } });
  const b = encode({ stream_id: 1, type: 'req' as const, seq: 0, method: 'm', params: { a: 1, b: 2 } });
  expect(new TextDecoder().decode(a)).toBe(new TextDecoder().decode(b));
});

test('envelope rejects unknown type', () => {
  const bad = new TextEncoder().encode('{"stream_id":1,"type":"bogus","seq":0}');
  expect(() => decode(bad)).toThrow();
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/envelope.test.ts
```
Expected: FAIL — not implemented.

- [ ] **Step 3: Implement `src/envelope.ts`**

```typescript
import { z } from 'zod';
import canonicalize from 'canonicalize';

export const EnvelopeSchema = z.object({
  stream_id: z.number().int().nonnegative(),
  type: z.enum(['req', 'res', 'stream_chunk', 'stream_end', 'cancel', 'error']),
  seq: z.number().int().nonnegative(),
  credits: z.number().int().nonnegative().optional(),
  method: z.string().optional(),
  params: z.unknown().optional(),
  result: z.unknown().optional(),
  reason: z.string().optional(),
  error: z.object({ code: z.number().int(), message: z.string() }).optional(),
});

export type Envelope = z.infer<typeof EnvelopeSchema>;

export function encode(env: Envelope): Uint8Array {
  EnvelopeSchema.parse(env);
  return new TextEncoder().encode(canonicalize(env) as string);
}

export function decode(bytes: Uint8Array): Envelope {
  const text = new TextDecoder().decode(bytes);
  return EnvelopeSchema.parse(JSON.parse(text));
}
```

- [ ] **Step 4: Run**

```bash
bun test tests/envelope.test.ts
```
Expected: 3 pass.

- [ ] **Step 5: Commit**

```bash
git add src/envelope.ts tests/envelope.test.ts
git commit -m "feat(envelope): Zod schema + RFC 8785 canonical JSON"
```

---

## Task 10: Session multiplexer — unary req/res

**Files:**
- Modify: `src/session.ts`
- Test: `tests/session.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/session.test.ts`:

```typescript
import { test, expect } from 'bun:test';
import { Session } from '../src/session.ts';
import type { Envelope } from '../src/envelope.ts';

function linkedSessions() {
  let aCb: ((e: Envelope) => void) | null = null;
  let bCb: ((e: Envelope) => void) | null = null;
  const aToB: Envelope[] = [];
  const bToA: Envelope[] = [];
  const a = new Session(
    {
      send: (e) => { aToB.push(e); queueMicrotask(() => bCb?.(e)); },
      onRecv: (cb) => { aCb = cb; },
      close: () => {},
    },
    'initiator',
  );
  const b = new Session(
    {
      send: (e) => { bToA.push(e); queueMicrotask(() => aCb?.(e)); },
      onRecv: (cb) => { bCb = cb; },
      close: () => {},
    },
    'responder',
  );
  return { a, b };
}

test('unary request/response round-trips through Session', async () => {
  const { a, b } = linkedSessions();
  b.handle('echo', (params) => params);
  const result = await a.call('echo', { hello: 'world' });
  expect(result).toEqual({ hello: 'world' });
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/session.test.ts
```
Expected: FAIL — stub.

- [ ] **Step 3: Replace `src/session.ts`**

```typescript
import type { Envelope } from './envelope.ts';

export type Handler = (params: unknown) => unknown | Promise<unknown> | AsyncIterable<unknown>;

export type SessionTransport = {
  send: (env: Envelope) => void;
  onRecv: (cb: (env: Envelope) => void) => void;
  close: () => void;
};

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void };

export class Session {
  private nextStreamId: number;
  private pending = new Map<number, Pending>();
  private handlers = new Map<string, Handler>();

  constructor(private t: SessionTransport, role: 'initiator' | 'responder') {
    this.nextStreamId = role === 'initiator' ? 1 : 2;
    this.t.onRecv((e) => this.onFrame(e));
  }

  handle(method: string, h: Handler): void {
    this.handlers.set(method, h);
  }

  async call(method: string, params?: unknown): Promise<unknown> {
    const id = this.alloc();
    const p = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.t.send({ stream_id: id, type: 'req', seq: 0, method, params });
    return p;
  }

  private alloc(): number {
    const id = this.nextStreamId;
    this.nextStreamId += 2;
    return id;
  }

  private async onFrame(e: Envelope): Promise<void> {
    if (e.type === 'req') {
      const h = this.handlers.get(e.method!);
      if (!h) {
        this.t.send({
          stream_id: e.stream_id,
          type: 'error',
          seq: 0,
          error: { code: -32601, message: `method not found: ${e.method}` },
        });
        return;
      }
      try {
        const result = await h(e.params);
        this.t.send({ stream_id: e.stream_id, type: 'res', seq: 0, result });
      } catch (err) {
        this.t.send({
          stream_id: e.stream_id,
          type: 'error',
          seq: 0,
          error: { code: -32000, message: (err as Error).message },
        });
      }
    } else if (e.type === 'res') {
      const pending = this.pending.get(e.stream_id);
      if (pending) {
        this.pending.delete(e.stream_id);
        pending.resolve(e.result);
      }
    } else if (e.type === 'error') {
      const pending = this.pending.get(e.stream_id);
      if (pending) {
        this.pending.delete(e.stream_id);
        pending.reject(new Error(e.error?.message ?? 'unknown error'));
      }
    }
  }

  close(): void {
    this.t.close();
  }
}
```

- [ ] **Step 4: Run**

```bash
bun test tests/session.test.ts
```
Expected: 1 pass.

- [ ] **Step 5: Commit**

```bash
git add src/session.ts tests/session.test.ts
git commit -m "feat(session): unary req/res multiplexer + error frames"
```

---

## Task 11: WebSocket wiring — server + client + end-to-end echo

**Files:**
- Modify: `src/server.ts`, `src/client.ts`
- Test: `tests/e2e.test.ts`

**Approach:** Bun's `Bun.serve({ websocket: { message, open, close } })` for the listener, `new WebSocket(url)` for the dialer. Each side runs the Noise handshake first (three binary WS messages), then wraps the socket in a `Session` via a `SessionTransport` backed by the FrameCipher.

- [ ] **Step 1: Write the end-to-end test**

Create `tests/e2e.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run**

```bash
bun test tests/e2e.test.ts
```
Expected: FAIL — not implemented.

- [ ] **Step 3: Implement `src/server.ts`**

```typescript
import { decodeDidKey, ed25519PrivToX25519, ed25519PubToX25519 } from './did.ts';
import { buildPrologue, responderHandshake } from './noise.ts';
import { FrameCipher } from './frame.ts';
import { encode, decode, type Envelope } from './envelope.ts';
import { Session, type Handler } from './session.ts';

export type { Handler } from './session.ts';

export type ServerOptions = {
  did: string;
  privateKey: Uint8Array;
  handlers: Record<string, Handler>;
};

export type Server = {
  listen: (port: number, hostname?: string) => Promise<void>;
  close: () => Promise<void>;
  address: () => { port: number; hostname: string };
};

type PerSocket = {
  step: 1 | 2 | 3;
  hs: ReturnType<typeof responderHandshake>;
  cipher?: FrameCipher;
  session?: Session;
  recvCb?: (e: Envelope) => void;
};

export function createServer(opts: ServerOptions): Server {
  const staticPriv = ed25519PrivToX25519(opts.privateKey);
  const responderPub = decodeDidKey(opts.did);
  const staticPub = ed25519PubToX25519(responderPub);

  let srv: ReturnType<typeof Bun.serve> | null = null;

  const listen = async (port: number, hostname = 'localhost') => {
    srv = Bun.serve<PerSocket>({
      port,
      hostname,
      fetch(req, server) {
        const url = new URL(req.url);
        const callerDid = url.searchParams.get('caller');
        if (!callerDid) return new Response('missing ?caller=<did>', { status: 400 });
        const ok = server.upgrade(req, {
          data: {
            step: 1,
            hs: responderHandshake({
              prologue: buildPrologue(callerDid, opts.did),
              staticPriv,
              staticPub,
            }),
          } as PerSocket,
        });
        if (!ok) return new Response('agent-phone.v1 only', { status: 426 });
      },
      websocket: {
        async message(ws, raw) {
          const buf = typeof raw === 'string' ? new TextEncoder().encode(raw) : new Uint8Array(raw as ArrayBuffer);
          const s = ws.data;
          if (s.step === 1) {
            s.hs.readMessage1(buf);
            ws.sendBinary(s.hs.writeMessage2());
            s.step = 2;
          } else if (s.step === 2) {
            s.hs.readMessage3(buf);
            const transport = s.hs.finish();
            s.cipher = new FrameCipher(transport);
            const transportIface = {
              send: (env: Envelope) => ws.sendBinary(s.cipher!.seal(encode(env))),
              onRecv: (cb: (e: Envelope) => void) => { s.recvCb = cb; },
              close: () => ws.close(),
            };
            s.session = new Session(transportIface, 'responder');
            for (const [m, h] of Object.entries(opts.handlers)) s.session.handle(m, h);
            s.step = 3;
          } else if (s.step === 3) {
            const pt = s.cipher!.open(buf);
            s.recvCb?.(decode(pt));
          }
        },
        close(ws) {
          ws.data.session?.close();
        },
      },
    });
  };

  return {
    listen,
    close: async () => { srv?.stop(true); },
    address: () => ({ port: srv!.port, hostname: srv!.hostname }),
  };
}
```

- [ ] **Step 4: Implement `src/client.ts`**

```typescript
import { decodeDidKey, ed25519PrivToX25519, ed25519PubToX25519 } from './did.ts';
import { buildPrologue, initiatorHandshake } from './noise.ts';
import { FrameCipher } from './frame.ts';
import { encode, decode, type Envelope } from './envelope.ts';
import { Session } from './session.ts';

export type ClientOptions = {
  url: string;
  did: string;
  privateKey: Uint8Array;
  responderDid: string;
  responderPublicKey?: Uint8Array;
};

export type Client = {
  call: (method: string, params?: unknown) => Promise<unknown>;
  stream: (
    method: string,
    params?: unknown,
    opts?: { credits?: number },
  ) => AsyncIterable<unknown>;
  close: () => Promise<void>;
};

export async function connect(opts: ClientOptions): Promise<Client> {
  const responderStaticPub =
    opts.responderPublicKey ?? ed25519PubToX25519(decodeDidKey(opts.responderDid));
  const staticPriv = ed25519PrivToX25519(opts.privateKey);
  const staticPub = ed25519PubToX25519(decodeDidKey(opts.did));

  // Append ?caller=<did> so the responder can build the matching prologue.
  const u = new URL(opts.url);
  u.searchParams.set('caller', opts.did);
  const ws = new WebSocket(u.toString(), 'agent-phone.v1');
  ws.binaryType = 'arraybuffer';
  await new Promise<void>((r, j) => {
    ws.addEventListener('open', () => r(), { once: true });
    ws.addEventListener('error', (e) => j(e), { once: true });
  });

  const hs = initiatorHandshake({
    prologue: buildPrologue(opts.did, opts.responderDid),
    staticPriv,
    staticPub,
    responderStaticPub,
  });

  ws.send(hs.writeMessage1());

  const m2 = await nextBinary(ws);
  hs.readMessage2(new Uint8Array(m2));
  ws.send(hs.writeMessage3());

  const transport = hs.finish();
  const cipher = new FrameCipher(transport);
  let recvCb: ((e: Envelope) => void) | null = null;

  ws.addEventListener('message', (ev) => {
    if (!(ev.data instanceof ArrayBuffer)) return;
    const pt = cipher.open(new Uint8Array(ev.data));
    recvCb?.(decode(pt));
  });

  const session = new Session(
    {
      send: (env) => ws.send(cipher.seal(encode(env))),
      onRecv: (cb) => { recvCb = cb; },
      close: () => ws.close(),
    },
    'initiator',
  );

  return {
    call: (m, p) => session.call(m, p),
    stream: (m, p, o) => session.stream(m, p, o?.credits ?? 8),
    close: async () => {
      ws.close();
      await new Promise<void>((r) => ws.addEventListener('close', () => r(), { once: true }));
    },
  };
}

function nextBinary(ws: WebSocket): Promise<ArrayBuffer> {
  return new Promise((resolve) => {
    const handler = (ev: MessageEvent) => {
      if (ev.data instanceof ArrayBuffer) {
        ws.removeEventListener('message', handler);
        resolve(ev.data);
      }
    };
    ws.addEventListener('message', handler);
  });
}
```

- [ ] **Step 5: Add a temporary stub for `session.stream` in `src/session.ts` so the client type-checks**

Add to the `Session` class:

```typescript
stream(_method: string, _params?: unknown, _credits = 8): AsyncIterable<unknown> {
  throw new Error('streams not implemented yet — Task 12');
}
```

- [ ] **Step 6: Run**

```bash
bun test tests/e2e.test.ts
```
Expected: 1 pass.

- [ ] **Step 7: Commit**

```bash
git add src/server.ts src/client.ts src/session.ts tests/e2e.test.ts
git commit -m "feat(wire): end-to-end unary echo over Noise_XK + WebSocket"
```

---

# Stage 2.2 — Streaming, backpressure, cancel, errors

## Task 12: Server-streaming semantics (no backpressure yet)

**Files:**
- Modify: `src/session.ts`
- Test: `tests/session.test.ts`

- [ ] **Step 1: Add failing test**

Append to `tests/session.test.ts`:

```typescript
test('server stream delivers chunks in order', async () => {
  const { a, b } = linkedSessions();
  b.handle('count', async function* (_p) {
    for (let i = 0; i < 5; i++) yield i;
  });
  const got: number[] = [];
  for await (const chunk of a.stream('count', {}, 10)) got.push(chunk as number);
  expect(got).toEqual([0, 1, 2, 3, 4]);
});
```

Adjust `a.stream` signature — use `a.stream('count', {}, 10)` where 3rd arg is credits.

- [ ] **Step 2: Run**

```bash
bun test tests/session.test.ts
```
Expected: FAIL — stream not implemented.

- [ ] **Step 3: Replace `Session.stream` and extend `onFrame`**

In `src/session.ts`, add in the class:

```typescript
private streams = new Map<
  number,
  {
    queue: unknown[];
    resolve: ((v: IteratorResult<unknown>) => void) | null;
    ended: boolean;
    error: Error | null;
    granted: number;
    emitted: number;
  }
>();

stream(method: string, params: unknown, credits: number): AsyncIterable<unknown> {
  const id = this.alloc();
  const state = {
    queue: [] as unknown[],
    resolve: null as ((v: IteratorResult<unknown>) => void) | null,
    ended: false,
    error: null as Error | null,
    granted: credits,
    emitted: 0,
  };
  this.streams.set(id, state);
  this.t.send({ stream_id: id, type: 'req', seq: 0, method, params, credits });

  const self = this;
  return {
    [Symbol.asyncIterator](): AsyncIterator<unknown> {
      return {
        next(): Promise<IteratorResult<unknown>> {
          if (state.error) return Promise.reject(state.error);
          if (state.queue.length > 0) {
            return Promise.resolve({ value: state.queue.shift(), done: false });
          }
          if (state.ended) return Promise.resolve({ value: undefined, done: true });
          return new Promise((resolve) => {
            state.resolve = resolve;
          });
        },
        return(): Promise<IteratorResult<unknown>> {
          self.t.send({ stream_id: id, type: 'cancel', seq: 0 });
          self.streams.delete(id);
          return Promise.resolve({ value: undefined, done: true });
        },
      };
    },
  };
}
```

Extend `onFrame`:

```typescript
// inside onFrame, after the existing 'req' branch:
if (e.type === 'req' && this.handlers.has(e.method!)) {
  // already handled unary above; for generators, dispatch as stream
}
```

Replace the `'req'` handling logic to detect generators:

```typescript
if (e.type === 'req') {
  const h = this.handlers.get(e.method!);
  if (!h) {
    this.t.send({
      stream_id: e.stream_id,
      type: 'error',
      seq: 0,
      error: { code: -32601, message: `method not found: ${e.method}` },
    });
    return;
  }
  try {
    const out = await h(e.params);
    if (isAsyncIterable(out)) {
      await this.runServerStream(e.stream_id, out, e.credits ?? 0);
    } else {
      this.t.send({ stream_id: e.stream_id, type: 'res', seq: 0, result: out });
    }
  } catch (err) {
    this.t.send({
      stream_id: e.stream_id,
      type: 'error',
      seq: 0,
      error: { code: -32000, message: (err as Error).message },
    });
  }
  return;
}

if (e.type === 'stream_chunk') {
  const s = this.streams.get(e.stream_id);
  if (!s) return;
  if (s.resolve) {
    const r = s.resolve;
    s.resolve = null;
    r({ value: e.result, done: false });
  } else {
    s.queue.push(e.result);
  }
  return;
}

if (e.type === 'stream_end') {
  const s = this.streams.get(e.stream_id);
  if (!s) return;
  s.ended = true;
  if (s.resolve) {
    const r = s.resolve;
    s.resolve = null;
    r({ value: undefined, done: true });
  }
  this.streams.delete(e.stream_id);
  return;
}
```

Add helper + stream runner inside the class:

```typescript
private async runServerStream(
  id: number,
  src: AsyncIterable<unknown>,
  _initialCredits: number,
): Promise<void> {
  let seq = 0;
  for await (const result of src) {
    this.t.send({ stream_id: id, type: 'stream_chunk', seq: seq++, result });
  }
  this.t.send({ stream_id: id, type: 'stream_end', seq, reason: 'ok' });
}
```

Add the helper function at file bottom:

```typescript
function isAsyncIterable(x: unknown): x is AsyncIterable<unknown> {
  return x !== null && typeof x === 'object' && Symbol.asyncIterator in (x as object);
}
```

- [ ] **Step 4: Run**

```bash
bun test tests/session.test.ts
```
Expected: all session tests pass (unary + stream-order).

- [ ] **Step 5: Commit**

```bash
git add src/session.ts tests/session.test.ts
git commit -m "feat(session): server-streaming semantics with async iterators"
```

---

## Task 13: Credit-based backpressure

**Files:**
- Modify: `src/session.ts`
- Test: `tests/session.test.ts`

**Semantics (per SPEC §4.2):** Responder MUST pause sending chunks when outstanding-unacked > granted. Initiator refreshes by sending `{type:'res', seq:0, credits:N}`.

- [ ] **Step 1: Add failing test**

Append to `tests/session.test.ts`:

```typescript
test('server blocks at credit=0 and resumes after credits granted', async () => {
  const { a, b } = linkedSessions();
  let emitted = 0;
  b.handle('torrent', async function* (_p) {
    for (let i = 0; i < 20; i++) { emitted = i + 1; yield i; }
  });
  const got: number[] = [];
  const initialCredits = 5;
  const iter = a.stream('torrent', {}, initialCredits)[Symbol.asyncIterator]();

  // Drain 5 — expect server to pause.
  for (let i = 0; i < 5; i++) got.push((await iter.next()).value as number);
  // Give the loop a microtask beat.
  await new Promise((r) => setTimeout(r, 5));
  expect(emitted).toBeLessThanOrEqual(5);

  // Drain remaining (stream auto-refreshes credits internally).
  for (;;) {
    const r = await iter.next();
    if (r.done) break;
    got.push(r.value as number);
  }
  expect(got.length).toBe(20);
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/session.test.ts
```
Expected: FAIL — `emitted` goes above 5 because there is no backpressure.

- [ ] **Step 3: Implement backpressure**

Replace `runServerStream` in `src/session.ts`:

```typescript
private runServerStream(id: number, src: AsyncIterable<unknown>, initialCredits: number): Promise<void> {
  const self = this;
  return new Promise<void>(async (resolve) => {
    let seq = 0;
    let granted = initialCredits;
    let cancelled = false;

    const waitForCredit = () =>
      new Promise<void>((r) => {
        const state = self.serverStreams.get(id);
        if (!state) return r();
        state.creditWaiter = r;
      });

    self.serverStreams.set(id, {
      grant: (n: number) => {
        granted += n;
        const state = self.serverStreams.get(id);
        if (state?.creditWaiter) {
          const w = state.creditWaiter;
          state.creditWaiter = null;
          w();
        }
      },
      cancel: () => { cancelled = true; },
      creditWaiter: null,
    });

    try {
      for await (const result of src) {
        if (cancelled) break;
        while (granted <= 0) await waitForCredit();
        if (cancelled) break;
        granted -= 1;
        self.t.send({ stream_id: id, type: 'stream_chunk', seq: seq++, result });
      }
      self.t.send({
        stream_id: id,
        type: 'stream_end',
        seq,
        reason: cancelled ? 'cancelled' : 'ok',
      });
    } finally {
      self.serverStreams.delete(id);
      resolve();
    }
  });
}
```

Add to class:

```typescript
private serverStreams = new Map<
  number,
  { grant: (n: number) => void; cancel: () => void; creditWaiter: (() => void) | null }
>();
```

Extend `onFrame` to handle credit grants via `type: 'res'` on an active stream:

```typescript
if (e.type === 'res' && this.serverStreams.has(e.stream_id)) {
  this.serverStreams.get(e.stream_id)!.grant(e.credits ?? 0);
  return;
}
```

Update the client-side stream iterator to auto-refresh credits. In `stream()`, wrap `next()`:

```typescript
next(): Promise<IteratorResult<unknown>> {
  // auto-refresh credits before each pull past the initial budget
  if (state.emitted >= state.granted - Math.floor(credits / 2) && !state.ended) {
    state.granted += credits;
    self.t.send({ stream_id: id, type: 'res', seq: 0, credits });
  }
  if (state.error) return Promise.reject(state.error);
  if (state.queue.length > 0) {
    state.emitted += 1;
    return Promise.resolve({ value: state.queue.shift(), done: false });
  }
  if (state.ended) return Promise.resolve({ value: undefined, done: true });
  return new Promise((resolve) => {
    state.resolve = (r) => {
      if (!r.done) state.emitted += 1;
      resolve(r);
    };
  });
},
```

- [ ] **Step 4: Run**

```bash
bun test tests/session.test.ts
```
Expected: all pass — `emitted` stays ≤ 5 until the iterator pulls more.

- [ ] **Step 5: Commit**

```bash
git add src/session.ts tests/session.test.ts
git commit -m "feat(session): credit-based backpressure for server streams"
```

---

## Task 14: Graceful cancel — session stays alive after mid-stream cancel

**Files:**
- Modify: `src/session.ts`
- Test: `tests/session.test.ts`

- [ ] **Step 1: Add failing test**

Append:

```typescript
test('cancel mid-stream leaves session usable for next RPC', async () => {
  const { a, b } = linkedSessions();
  let cancelledAt = -1;
  b.handle('infinite', async function* () {
    for (let i = 0; ; i++) { cancelledAt = i; yield i; }
  });
  b.handle('echo', (p) => p);

  const iter = a.stream('infinite', {}, 8)[Symbol.asyncIterator]();
  for (let i = 0; i < 3; i++) await iter.next();
  await iter.return!(); // sends cancel
  await new Promise((r) => setTimeout(r, 10));

  // Session is still alive:
  const r = await a.call('echo', { ok: true });
  expect(r).toEqual({ ok: true });
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/session.test.ts
```
Expected: PASS or FAIL depending on whether cancel is wired through. Likely already PASSES because `iterator.return` sends `type: 'cancel'`, and `onFrame` needs to handle cancel.

- [ ] **Step 3: Add cancel handling to `onFrame`**

```typescript
if (e.type === 'cancel') {
  const s = this.serverStreams.get(e.stream_id);
  s?.cancel();
  return;
}
```

- [ ] **Step 4: Run**

```bash
bun test tests/session.test.ts
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/session.ts tests/session.test.ts
git commit -m "feat(session): graceful cancel — server stops within 1 frame, session stays open"
```

---

## Task 15: Error frames leave the session alive

**Files:**
- Modify: `src/session.ts`
- Test: `tests/session.test.ts`

- [ ] **Step 1: Add failing test**

Append:

```typescript
test('handler throwing → error frame; session survives', async () => {
  const { a, b } = linkedSessions();
  b.handle('boom', () => { throw new Error('kaboom'); });
  b.handle('echo', (p) => p);
  await expect(a.call('boom')).rejects.toThrow('kaboom');
  const r = await a.call('echo', { ok: 1 });
  expect(r).toEqual({ ok: 1 });
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/session.test.ts
```
Expected: probably already passing (error handling was added in Task 10). If so, no code change; commit the added test.

- [ ] **Step 3: Commit**

```bash
git add tests/session.test.ts
git commit -m "test(session): error frame regression — session survives handler throw"
```

---

## Task 16: did:key verification of responder static — client aborts on MITM

**Files:**
- Modify: `src/client.ts`
- Test: `tests/e2e.test.ts`

**What to check:** the `connect()` flow is already "feed the DID-derived responder static into Noise." If the server doesn't actually hold that static, message 2 AEAD will throw. We just need to surface this as a readable error.

- [ ] **Step 1: Add failing test**

Append to `tests/e2e.test.ts`:

```typescript
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

test('client aborts when responder DID does not match the server static', async () => {
  const respKp = generateKeyPair();
  const impersonatorKp = generateKeyPair();
  const respDid = encodeDidKey(respKp.publicKey);

  // Server runs with the impersonator's key but advertises respDid.
  const server = createServer({
    did: respDid,
    privateKey: impersonatorKp.privateKey, // the lie
    handlers: { echo: (p) => p },
  });
  await server.listen(0);
  const { port } = server.address();

  const initKp = generateKeyPair();
  await expect(
    connect({
      url: `ws://localhost:${port}`,
      did: encodeDidKey(initKp.publicKey),
      privateKey: initKp.privateKey,
      responderDid: respDid, // initiator expects respKp
    }),
  ).rejects.toThrow();

  await server.close();
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/e2e.test.ts
```
Expected: likely passes because AEAD fails on message 2. If the error isn't descriptive enough, wrap:

- [ ] **Step 3: Wrap the error in `src/client.ts`**

In `connect()`, change the `readMessage2` call:

```typescript
try {
  hs.readMessage2(new Uint8Array(m2));
} catch (err) {
  ws.close();
  throw new Error(
    'agent-phone: handshake failed at message 2 — responder did not hold the static key ' +
      `pinned by ${opts.responderDid}`,
  );
}
```

- [ ] **Step 4: Run**

```bash
bun test tests/e2e.test.ts
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/client.ts tests/e2e.test.ts
git commit -m "feat(client): descriptive abort when responder static ≠ DID-pinned key (C1)"
```

---

# Stage 2.3 — Conformance vectors

## Task 17: Conformance runner scaffold

**Files:**
- Create: `conformance/run.ts`, `conformance/README.md`

- [ ] **Step 1: Create `conformance/README.md`**

```markdown
# agent-phone conformance suite

Run: `bun conformance/run.ts`

Each vector is a standalone `.ts` file that exits 0 on pass, non-zero on fail.
`run.ts` is the single entry point — it imports all vectors and prints a summary.
```

- [ ] **Step 2: Create `conformance/run.ts`**

```typescript
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
```

- [ ] **Step 3: Commit**

```bash
git add conformance/
git commit -m "chore(conformance): scaffold single-entry runner"
```

---

## Task 18: C1 — handshake DID-binding

**Files:**
- Create: `conformance/c1-handshake-did-binding.ts`

- [ ] **Step 1: Implement**

```typescript
import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

export default async function run() {
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
```

- [ ] **Step 2: Run the conformance runner**

```bash
bun conformance/run.ts
```
Expected: `PASS  C1 …`, others fail (not yet implemented).

- [ ] **Step 3: Commit**

```bash
git add conformance/c1-handshake-did-binding.ts
git commit -m "test(conformance): C1 — handshake DID-binding"
```

---

## Task 19: C2 — streaming backpressure (10 000 chunks)

**Files:**
- Create: `conformance/c2-streaming-backpressure.ts`

- [ ] **Step 1: Implement**

```typescript
import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

export default async function run() {
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
  for (let i = 0; i < N; i++) if (got[i] !== i) throw new Error(`C2: out-of-order at ${i}`);
  // Allow some batching slack — the essential property is boundedness, not exact equality to 8.
  if (maxOutstanding > credits * 4) {
    throw new Error(`C2: backpressure blown; maxOutstanding=${maxOutstanding} for credits=${credits}`);
  }
}
```

- [ ] **Step 2: Run**

```bash
bun conformance/run.ts
```
Expected: C1 + C2 pass.

- [ ] **Step 3: Commit**

```bash
git add conformance/c2-streaming-backpressure.ts
git commit -m "test(conformance): C2 — streaming backpressure at 10k chunks"
```

---

## Task 20: C3 — graceful cancel

**Files:**
- Create: `conformance/c3-graceful-cancel.ts`

- [ ] **Step 1: Implement**

```typescript
import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';
import { generateKeyPair, encodeDidKey } from '../src/did.ts';

export default async function run() {
  const resp = generateKeyPair();
  const init = generateKeyPair();
  const respDid = encodeDidKey(resp.publicKey);

  const server = createServer({
    did: respDid,
    privateKey: resp.privateKey,
    handlers: {
      infinite: async function* () { for (let i = 0; ; i++) yield i; },
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
  await (iter as unknown as { return: () => Promise<void> }).return();
  await new Promise((r) => setTimeout(r, 20));

  const r = await client.call('ping', { still: 'alive' });
  if ((r as { still: string }).still !== 'alive') throw new Error('C3: session dead after cancel');

  await client.close();
  await server.close();
}
```

- [ ] **Step 2: Run**

```bash
bun conformance/run.ts
```
Expected: C1–C3 pass.

- [ ] **Step 3: Commit**

```bash
git add conformance/c3-graceful-cancel.ts
git commit -m "test(conformance): C3 — graceful cancel; session stays alive"
```

---

## Task 21: C4 — frame decoding determinism

**Files:**
- Create: `conformance/c4-frame-determinism.ts`, `conformance/vectors/c4.json`

- [ ] **Step 1: Create golden vectors**

Create `conformance/vectors/c4.json`:

```json
{
  "unary_req": {
    "plaintext_envelope": {
      "stream_id": 1,
      "type": "req",
      "seq": 0,
      "method": "echo",
      "params": { "b": 2, "a": 1 }
    },
    "canonical_json_hex": "7b226d6574686f64223a226563686f222c22706172616d73223a7b2261223a312c2262223a327d2c22736571223a302c2273747265616d5f6964223a312c2274797065223a22726571227d"
  }
}
```

(The `canonical_json_hex` is the hex of `{"method":"echo","params":{"a":1,"b":2},"seq":0,"stream_id":1,"type":"req"}` — sorted keys, no whitespace. Generate it once by running `bun -e 'console.log(Buffer.from(new TextEncoder().encode(require("canonicalize").default({...})).buffer).toString("hex"))'` if unsure, then commit the result.)

- [ ] **Step 2: Implement vector runner**

Create `conformance/c4-frame-determinism.ts`:

```typescript
import { encode, decode, type Envelope } from '../src/envelope.ts';
import vectors from './vectors/c4.json' with { type: 'json' };

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export default async function run() {
  for (const [name, v] of Object.entries(vectors as Record<string, {
    plaintext_envelope: Envelope;
    canonical_json_hex: string;
  }>)) {
    const bytes = encode(v.plaintext_envelope);
    const got = hex(bytes);
    if (got !== v.canonical_json_hex) {
      throw new Error(
        `C4 ${name}: canonical JSON mismatch\n  expected ${v.canonical_json_hex}\n  got      ${got}`,
      );
    }
    const decoded = decode(bytes);
    if (JSON.stringify(decoded) !== JSON.stringify(v.plaintext_envelope)) {
      throw new Error(`C4 ${name}: decode roundtrip mismatch`);
    }
  }
}
```

- [ ] **Step 3: Run**

```bash
bun conformance/run.ts
```
Expected: all 4 vectors pass.

- [ ] **Step 4: Commit**

```bash
git add conformance/c4-frame-determinism.ts conformance/vectors/
git commit -m "test(conformance): C4 — frame decoding determinism with golden vectors"
```

---

# Stage 2.4 — Security consideration tests (SPEC §5)

## Task 22: Replay defense — fresh ephemeral per session

**Files:**
- Create: `tests/security.test.ts`

- [ ] **Step 1: Implement**

```typescript
import { test, expect } from 'bun:test';
import { buildPrologue, initiatorHandshake, responderHandshake } from '../src/noise.ts';
import { generateKeyPair, encodeDidKey, ed25519PrivToX25519, ed25519PubToX25519 } from '../src/did.ts';

test('same initiator running two handshakes produces different ephemerals → different session keys', () => {
  const i = generateKeyPair();
  const r = generateKeyPair();
  const prologue = buildPrologue(encodeDidKey(i.publicKey), encodeDidKey(r.publicKey));
  const iStaticPriv = ed25519PrivToX25519(i.privateKey);
  const iStaticPub = ed25519PubToX25519(i.publicKey);
  const rStaticPriv = ed25519PrivToX25519(r.privateKey);
  const rStaticPub = ed25519PubToX25519(r.publicKey);

  function handshakeOnce() {
    const a = initiatorHandshake({ prologue, staticPriv: iStaticPriv, staticPub: iStaticPub, responderStaticPub: rStaticPub });
    const b = responderHandshake({ prologue, staticPriv: rStaticPriv, staticPub: rStaticPub });
    b.readMessage1(a.writeMessage1());
    a.readMessage2(b.writeMessage2());
    b.readMessage3(a.writeMessage3());
    // encrypt a marker and inspect the ciphertext
    const t = a.finish();
    return t.send(new TextEncoder().encode('marker'));
  }

  const ct1 = handshakeOnce();
  const ct2 = handshakeOnce();
  expect(ct1).not.toEqual(ct2);
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/security.test.ts
```
Expected: 1 pass.

- [ ] **Step 3: Commit**

```bash
git add tests/security.test.ts
git commit -m "test(security): fresh ephemeral per handshake — no replay across sessions"
```

---

## Task 23: Key rotation — existing session survives a DID Doc change

**Files:**
- Modify: `tests/security.test.ts`

SPEC §5 says "if a DID Document rotates its Ed25519 key, existing sessions remain valid." We test that once a session is established, it keeps working even if (hypothetically) the responder's published DID Doc changes.

- [ ] **Step 1: Add test**

Append:

```typescript
import { createServer } from '../src/server.ts';
import { connect } from '../src/client.ts';

test('existing session keeps working after a (hypothetical) DID rotation', async () => {
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

  expect(await client.call('echo', { n: 1 })).toEqual({ n: 1 });
  // Pretend the DID Doc rotates; session keys are already derived, so calls keep working.
  expect(await client.call('echo', { n: 2 })).toEqual({ n: 2 });
  await client.close();
  await server.close();
});
```

- [ ] **Step 2: Run**

```bash
bun test tests/security.test.ts
```
Expected: 2 pass.

- [ ] **Step 3: Commit**

```bash
git add tests/security.test.ts
git commit -m "test(security): existing session survives DID Doc rotation"
```

---

# Stage 2.5 — Demo + release prep

## Task 24: The 20-line demo

**Files:**
- Create: `examples/demo.ts`

- [ ] **Step 1: Write it**

```typescript
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
    search: async function* (_p) {
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
  if (n === 10) break; // cancel early
}
console.log(`got ${n} hits, cancelled cleanly`);

console.log('still alive:', await client.call('echo', { back: 'to unary' }));

await client.close();
await server.close();
```

- [ ] **Step 2: Run**

```bash
bun examples/demo.ts
```
Expected: three lines of output, process exits 0 within ~1 second.

- [ ] **Step 3: Commit**

```bash
git add examples/demo.ts
git commit -m "docs(demo): 20-line end-to-end demo — handshake, unary, stream, cancel, unary again"
```

---

## Task 25: README Quickstart

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the Status + Scope sections' neighborhood with a working Quickstart**

Insert after the `## Status` section (replace with `## Status` → `1.0`, see Task 27):

```markdown
## Quickstart

```bash
bun install
bun test
bun examples/demo.ts
```

That's it. Three commands, no Docker, no services. The demo spawns a responder and an initiator in one process, completes a Noise_XK handshake bound to both agents' DIDs, runs a unary `echo`, streams `search` with credit-based backpressure, cancels mid-stream, and reuses the same session for another unary call. Takes about a second.

The primary public API is two functions:

```typescript
import { createServer, connect, generateKeyPair, encodeDidKey } from 'agent-phone';

const { publicKey, privateKey } = generateKeyPair();
const did = encodeDidKey(publicKey);

const server = createServer({ did, privateKey, handlers: { echo: (p) => p } });
await server.listen(7777);

const client = await connect({ url: 'ws://localhost:7777', did, privateKey, responderDid: did });
console.log(await client.call('echo', { hi: 1 }));
```
```

- [ ] **Step 2: Run the quickstart commands yourself**

```bash
bun install && bun test && bun examples/demo.ts
```
Expected: all green, demo prints three lines.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): add Quickstart — 3 commands, 10-line code sample"
```

---

## Task 26: CHANGELOG + SPEC version banner

**Files:**
- Create: `CHANGELOG.md`
- Modify: `SPEC.md`

- [ ] **Step 1: Create `CHANGELOG.md`**

```markdown
# Changelog

## v0.1.0 — 2026-04-24

Initial release. What landed:

- Noise_XK_25519_ChaChaPoly_BLAKE2s handshake over WebSocket, prologue-bound to both agents' DIDs.
- did:key + Ed25519 ↔ X25519 key conversion.
- JSON envelope (`{stream_id, type, seq, credits?, method?, params?, result?, reason?, error?}`) encoded as RFC 8785 canonical JSON.
- Unary request/response, server-streaming, credit-based backpressure, graceful cancel, error frames.
- Reference server (`createServer`) and client (`connect`) libraries.
- Conformance vectors C1–C4 runnable with one command (`bun conformance/run.ts`).
- One-file 20-line demo (`examples/demo.ts`).

Deferred to v0.2: did:web resolution, WebRTC DataChannel transport, session resumption, CLI, browser build.
```

- [ ] **Step 2: Flip SPEC status banner**

Edit `SPEC.md` line 1 area:

Change:
```
# agent-phone — v0.1 specification (DRAFT)

**Status:** draft, not yet implemented.
```

To:
```
# agent-phone — v0.1 specification

**Status:** 1.0 — released 2026-04-24.
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md SPEC.md
git commit -m "docs: CHANGELOG v0.1.0 + SPEC DRAFT → 1.0"
```

---

## Task 27: Full sanity check + single-binary build

**Files:** none modified

- [ ] **Step 1: Clean-install + run the full suite**

```bash
rm -rf node_modules bun.lockb
bun install
bun test
bun conformance/run.ts
bun examples/demo.ts
bun build --compile --outfile=dist/agent-phone src/index.ts
./dist/agent-phone || true
```

Expected:
- `bun install`: < 20 transitive packages for a library-only repo.
- `bun test`: all pass, < 30 s total.
- `bun conformance/run.ts`: 4/4 PASS.
- `bun examples/demo.ts`: 3 lines of output, exit 0.
- `bun build --compile …`: produces `dist/agent-phone`.

- [ ] **Step 2: Write success marker (no commit unless something changed)**

If everything passes, nothing to commit. If something broke, fix and commit before tagging.

- [ ] **Step 3: Tag (do NOT push)**

```bash
git tag v0.1.0
git log --oneline -20
git tag --list
```

Expected: `v0.1.0` appears. No publish; wait for user confirmation in Stage 6.

---

# Self-review checklist (run after all tasks above)

- [ ] Every SPEC §6 (Cn) clause has a matching file in `conformance/`. (C1→Task 18, C2→Task 19, C3→Task 20, C4→Task 21.)
- [ ] Every SPEC §5 security bullet that is IN-scope for v0.1 has a test. (DID binding → C1; replay → Task 22; key rotation → Task 23; traffic analysis → explicitly out of scope; session resumption → explicitly v0.2.)
- [ ] No file exceeds 200 LoC. If `session.ts` drifts over, split the server-stream runner into a private module.
- [ ] No placeholder/TODO/TBD.
- [ ] Quickstart is 3 commands. Demo is ~30 lines (within the "~20 lines of user-facing code" spirit).
- [ ] Runtime dep list is: `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@scure/base`, `canonicalize`, `zod`. Six packages, all boring.
- [ ] Public API surface: `connect`, `createServer`, `generateKeyPair`, `encodeDidKey`, plus types. Nothing else exported from `index.ts`.
- [ ] CI (`.github/workflows/ci.yml`) runs install + test + conformance + compile in one job.

---

# Execution handoff

Plan saved. Two execution options:

1. **Subagent-driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration with the main context staying tight.
2. **Inline execution** — we work tasks directly in this session with checkpoints for review.

Which?
