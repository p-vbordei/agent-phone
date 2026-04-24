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

  const u = new URL(opts.url);
  u.searchParams.set('caller', opts.did);
  const ws = new WebSocket(u.toString(), 'agent-phone.v1');
  ws.binaryType = 'arraybuffer';

  await new Promise<void>((resolve, reject) => {
    ws.addEventListener('open', () => resolve(), { once: true });
    ws.addEventListener('error', (e) => reject(e), { once: true });
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
      send: (env) => {
        ws.send(cipher.seal(encode(env)));
      },
      onRecv: (cb) => {
        recvCb = cb;
      },
      close: () => {
        ws.close();
      },
    },
    'initiator',
  );

  return {
    call: (m, p) => session.call(m, p),
    stream: (m, p, o) => session.stream(m, p, o?.credits ?? 8),
    close: async () => {
      ws.close();
      await new Promise<void>((resolve) =>
        ws.addEventListener('close', () => resolve(), { once: true }),
      );
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
