import { blake2s } from '@noble/hashes/blake2s';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';

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

export function buildPrologue(initiatorDid: string, responderDid: string): Uint8Array {
  const prefix = new TextEncoder().encode('agent-phone/1');
  const init = new TextEncoder().encode(initiatorDid);
  const resp = new TextEncoder().encode(responderDid);
  const out = new Uint8Array(prefix.length + 2 + init.length + 2 + resp.length);
  let off = 0;
  out.set(prefix, off);
  off += prefix.length;
  new DataView(out.buffer).setUint16(off, init.length, false); // big-endian
  off += 2;
  out.set(init, off);
  off += init.length;
  new DataView(out.buffer).setUint16(off, resp.length, false);
  off += 2;
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
  // XK pre-message: responder's static is known to the initiator.
  ss.mixHash(opts.responderStaticPub);

  let ePriv: Uint8Array | null = null;
  let rePub: Uint8Array | null = null;

  return {
    writeMessage1(): Uint8Array {
      // -> e, es  (no payload; AEAD deferred to message 3)
      ePriv = x25519.utils.randomPrivateKey();
      const ePub = x25519.getPublicKey(ePriv);
      ss.mixHash(ePub);
      ss.mixKey(dh(ePriv, opts.responderStaticPub));
      return ePub;
    },
    readMessage2(msg: Uint8Array): void {
      // <- e, ee
      if (ePriv === null) throw new Error('writeMessage1 must run first');
      rePub = msg.slice(0, 32);
      const rest = msg.slice(32);
      ss.mixHash(rePub);
      ss.mixKey(dh(ePriv, rePub));
      ss.decryptAndHash(rest); // AEAD tag (auth over h derived from both es and ee)
    },
    writeMessage3(): Uint8Array {
      // -> s, se
      if (rePub === null) throw new Error('readMessage2 must run first');
      const encS = ss.encryptAndHash(opts.staticPub);
      ss.mixKey(dh(opts.staticPriv, rePub));
      const encPayload = ss.encryptAndHash(new Uint8Array(0));
      return concat(encS, encPayload);
    },
    finish(): HandshakeResult {
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
  // XK pre-message: responder's own static is absorbed.
  ss.mixHash(opts.staticPub);

  let ePriv: Uint8Array | null = null;
  let reInitPub: Uint8Array | null = null;

  return {
    readMessage1(msg: Uint8Array): void {
      // -> e, es  (no payload in message 1)
      reInitPub = msg.slice(0, 32);
      ss.mixHash(reInitPub);
      ss.mixKey(dh(opts.staticPriv, reInitPub));
    },
    writeMessage2(): Uint8Array {
      // <- e, ee
      if (reInitPub === null) throw new Error('readMessage1 must run first');
      ePriv = x25519.utils.randomPrivateKey();
      const ePub = x25519.getPublicKey(ePriv);
      ss.mixHash(ePub);
      ss.mixKey(dh(ePriv, reInitPub));
      const encPayload = ss.encryptAndHash(new Uint8Array(0));
      return concat(ePub, encPayload);
    },
    readMessage3(msg: Uint8Array): void {
      // -> s, se
      if (ePriv === null) throw new Error('writeMessage2 must run first');
      const encS = msg.slice(0, 32 + 16);
      const rest = msg.slice(32 + 16);
      const risPub = ss.decryptAndHash(encS);
      ss.mixKey(dh(ePriv, risPub));
      ss.decryptAndHash(rest);
    },
    finish(): HandshakeResult {
      const [recvCs, sendCs] = ss.split();
      return {
        send: (p: Uint8Array) => sendCs.encryptWithAd(new Uint8Array(0), p),
        recv: (c: Uint8Array) => recvCs.decryptWithAd(new Uint8Array(0), c),
      };
    },
  };
}
