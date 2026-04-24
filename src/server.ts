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
          const buf =
            typeof raw === 'string'
              ? new TextEncoder().encode(raw)
              : raw instanceof Uint8Array
                ? raw
                : new Uint8Array(raw as ArrayBuffer);
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
              send: (env: Envelope) => {
                ws.sendBinary(s.cipher!.seal(encode(env)));
              },
              onRecv: (cb: (e: Envelope) => void) => {
                s.recvCb = cb;
              },
              close: () => {
                ws.close();
              },
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
    close: async () => {
      srv?.stop(true);
    },
    address: () => {
      if (!srv) throw new Error('server not started');
      const port = srv.port;
      const hostname = srv.hostname;
      if (port === undefined || hostname === undefined) throw new Error('server not bound');
      return { port, hostname };
    },
  };
}
