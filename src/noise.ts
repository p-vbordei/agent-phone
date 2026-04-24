import { blake2s } from '@noble/hashes/blake2s';
import { chacha20poly1305 } from '@noble/ciphers/chacha';

const PROTOCOL = 'Noise_XK_25519_ChaChaPoly_BLAKE2s';
const HASHLEN = 32;
const BLOCKLEN = 64;

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
    ipad[i] = (padded[i] ?? 0) ^ 0x36;
    opad[i] = (padded[i] ?? 0) ^ 0x5c;
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
  // ChaChaPoly Noise nonce: 4 zero bytes || 8-byte little-endian counter
  new DataView(out.buffer).setBigUint64(4, n, true);
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

// Handshake state machines implemented in Task 7.
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

// buildPrologue implemented in Task 7.
export function buildPrologue(_initiatorDid: string, _responderDid: string): Uint8Array {
  throw new Error('not implemented');
}
