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
