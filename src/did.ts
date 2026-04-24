import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';

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
  return `did:key:z${base58.encode(prefixed)}`;
}

export function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) throw new Error('not a did:key identifier');
  const bytes = base58.decode(did.slice('did:key:z'.length));
  if (
    bytes.length < 34 ||
    bytes[0] !== MULTICODEC_ED25519_PUB[0] ||
    bytes[1] !== MULTICODEC_ED25519_PUB[1]
  ) {
    throw new Error('did:key is not an Ed25519 key (wrong multicodec prefix or truncated)');
  }
  return bytes.slice(2);
}

export function ed25519PubToX25519(_edPub: Uint8Array): Uint8Array {
  throw new Error('not implemented');
}
export function ed25519PrivToX25519(_edPriv: Uint8Array): Uint8Array {
  throw new Error('not implemented');
}
