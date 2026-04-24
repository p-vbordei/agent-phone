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
