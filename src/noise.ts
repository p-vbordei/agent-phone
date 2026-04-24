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

export function buildPrologue(_initiatorDid: string, _responderDid: string): Uint8Array {
  throw new Error('not implemented');
}
