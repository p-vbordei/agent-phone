import type { Envelope } from './envelope.ts';

export type Handler = (
  params: unknown,
) => unknown | Promise<unknown> | AsyncIterable<unknown>;

export type SessionTransport = {
  send: (env: Envelope) => void;
  onRecv: (cb: (env: Envelope) => void) => void;
  close: () => void;
};

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void };

export class Session {
  private nextStreamId: number;
  private pending = new Map<number, Pending>();
  private handlers = new Map<string, Handler>();

  constructor(
    private t: SessionTransport,
    role: 'initiator' | 'responder',
  ) {
    this.nextStreamId = role === 'initiator' ? 1 : 2;
    this.t.onRecv((e) => {
      this.onFrame(e);
    });
  }

  handle(method: string, h: Handler): void {
    this.handlers.set(method, h);
  }

  async call(method: string, params?: unknown): Promise<unknown> {
    const id = this.alloc();
    const p = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.t.send({ stream_id: id, type: 'req', seq: 0, method, params });
    return p;
  }

  stream(_method: string, _params?: unknown, _credits = 8): AsyncIterable<unknown> {
    throw new Error('streams not implemented yet — Task 12');
  }

  close(): void {
    this.t.close();
  }

  private alloc(): number {
    const id = this.nextStreamId;
    this.nextStreamId += 2;
    return id;
  }

  private async onFrame(e: Envelope): Promise<void> {
    if (e.type === 'req') {
      const h = this.handlers.get(e.method!);
      if (!h) {
        this.t.send({
          stream_id: e.stream_id,
          type: 'error',
          seq: 0,
          error: { code: -32601, message: `method not found: ${e.method}` },
        });
        return;
      }
      try {
        const result = await h(e.params);
        this.t.send({ stream_id: e.stream_id, type: 'res', seq: 0, result });
      } catch (err) {
        this.t.send({
          stream_id: e.stream_id,
          type: 'error',
          seq: 0,
          error: { code: -32000, message: (err as Error).message },
        });
      }
      return;
    }

    if (e.type === 'res') {
      const pending = this.pending.get(e.stream_id);
      if (pending) {
        this.pending.delete(e.stream_id);
        pending.resolve(e.result);
      }
      return;
    }

    if (e.type === 'error') {
      const pending = this.pending.get(e.stream_id);
      if (pending) {
        this.pending.delete(e.stream_id);
        pending.reject(new Error(e.error?.message ?? 'unknown error'));
      }
      return;
    }
  }
}
