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
