export type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

export function generateKeyPair(): KeyPair {
  throw new Error('not implemented');
}
export function encodeDidKey(_publicKey: Uint8Array): string {
  throw new Error('not implemented');
}
export function decodeDidKey(_did: string): Uint8Array {
  throw new Error('not implemented');
}
export function ed25519PubToX25519(_edPub: Uint8Array): Uint8Array {
  throw new Error('not implemented');
}
export function ed25519PrivToX25519(_edPriv: Uint8Array): Uint8Array {
  throw new Error('not implemented');
}
