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

type StreamState = {
  queue: unknown[];
  resolve: ((v: IteratorResult<unknown>) => void) | null;
  ended: boolean;
  error: Error | null;
};

export class Session {
  private nextStreamId: number;
  private pending = new Map<number, Pending>();
  private handlers = new Map<string, Handler>();
  private streams = new Map<number, StreamState>();

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

  stream(method: string, params: unknown, credits: number): AsyncIterable<unknown> {
    const id = this.alloc();
    const state: StreamState = { queue: [], resolve: null, ended: false, error: null };
    this.streams.set(id, state);
    this.t.send({ stream_id: id, type: 'req', seq: 0, method, params, credits });

    const self = this;
    return {
      [Symbol.asyncIterator](): AsyncIterator<unknown> {
        return {
          next(): Promise<IteratorResult<unknown>> {
            if (state.error) return Promise.reject(state.error);
            if (state.queue.length > 0) {
              return Promise.resolve({ value: state.queue.shift(), done: false });
            }
            if (state.ended) return Promise.resolve({ value: undefined, done: true });
            return new Promise((resolve) => {
              state.resolve = resolve;
            });
          },
          return(): Promise<IteratorResult<unknown>> {
            self.t.send({ stream_id: id, type: 'cancel', seq: 0 });
            self.streams.delete(id);
            return Promise.resolve({ value: undefined, done: true });
          },
        };
      },
    };
  }

  close(): void {
    this.t.close();
  }

  private alloc(): number {
    const id = this.nextStreamId;
    this.nextStreamId += 2;
    return id;
  }

  private async runServerStream(id: number, src: AsyncIterable<unknown>): Promise<void> {
    let seq = 0;
    for await (const result of src) {
      this.t.send({ stream_id: id, type: 'stream_chunk', seq: seq++, result });
    }
    this.t.send({ stream_id: id, type: 'stream_end', seq, reason: 'ok' });
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
        const out = await h(e.params);
        if (isAsyncIterable(out)) {
          await this.runServerStream(e.stream_id, out);
        } else {
          this.t.send({ stream_id: e.stream_id, type: 'res', seq: 0, result: out });
        }
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

    if (e.type === 'stream_chunk') {
      const s = this.streams.get(e.stream_id);
      if (!s) return;
      if (s.resolve) {
        const r = s.resolve;
        s.resolve = null;
        r({ value: e.result, done: false });
      } else {
        s.queue.push(e.result);
      }
      return;
    }

    if (e.type === 'stream_end') {
      const s = this.streams.get(e.stream_id);
      if (!s) return;
      s.ended = true;
      if (s.resolve) {
        const r = s.resolve;
        s.resolve = null;
        r({ value: undefined, done: true });
      }
      this.streams.delete(e.stream_id);
      return;
    }
  }
}

function isAsyncIterable(x: unknown): x is AsyncIterable<unknown> {
  return x !== null && typeof x === 'object' && Symbol.asyncIterator in (x as object);
}
