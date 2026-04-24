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
  granted: number;
  emitted: number;
};

export class Session {
  private nextStreamId: number;
  private pending = new Map<number, Pending>();
  private handlers = new Map<string, Handler>();
  private streams = new Map<number, StreamState>();
  private serverStreams = new Map<
    number,
    { grant: (n: number) => void; cancel: () => void; creditWaiter: (() => void) | null }
  >();

  constructor(
    private t: SessionTransport,
    role: 'initiator' | 'responder',
  ) {
    this.nextStreamId = role === 'initiator' ? 1 : 2;
    this.t.onRecv((e) => { this.onFrame(e); });
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
    const state: StreamState = { queue: [], resolve: null, ended: false, error: null, granted: credits, emitted: 0 };
    this.streams.set(id, state);
    this.t.send({ stream_id: id, type: 'req', seq: 0, method, params, credits });
    const self = this;
    return {
      [Symbol.asyncIterator](): AsyncIterator<unknown> {
        return {
          next(): Promise<IteratorResult<unknown>> {
            // Auto-refresh: top up when consumed past halfway through the grant.
            if (!state.ended && state.emitted >= state.granted - Math.floor(credits / 2)) {
              state.granted += credits;
              self.t.send({ stream_id: id, type: 'res', seq: 0, credits });
            }
            if (state.error) return Promise.reject(state.error);
            if (state.queue.length > 0) {
              state.emitted += 1;
              return Promise.resolve({ value: state.queue.shift(), done: false });
            }
            if (state.ended) return Promise.resolve({ value: undefined, done: true });
            return new Promise((resolve) => {
              state.resolve = (r) => { if (!r.done) state.emitted += 1; resolve(r); };
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

  close(): void { this.t.close(); }

  private alloc(): number {
    const id = this.nextStreamId;
    this.nextStreamId += 2;
    return id;
  }

  private runServerStream(id: number, src: AsyncIterable<unknown>, initialCredits: number): Promise<void> {
    const self = this;
    return new Promise<void>(async (resolve) => {
      let seq = 0, granted = initialCredits, cancelled = false;

      const wakeWaiter = () => {
        const s = self.serverStreams.get(id);
        if (s?.creditWaiter) { const w = s.creditWaiter; s.creditWaiter = null; w(); }
      };
      const waitForCredit = () => new Promise<void>((r) => {
        const s = self.serverStreams.get(id);
        if (!s) { r(); return; }
        s.creditWaiter = r;
      });

      self.serverStreams.set(id, {
        grant: (n) => { granted += n; wakeWaiter(); },
        cancel: () => { cancelled = true; wakeWaiter(); },
        creditWaiter: null,
      });

      try {
        const iter = src[Symbol.asyncIterator]();
        for (;;) {
          // Check credits BEFORE pulling from the generator so emittedCount stays accurate.
          while (granted <= 0) { await waitForCredit(); if (cancelled) break; }
          if (cancelled) break;
          const next = await iter.next();
          if (next.done) break;
          granted -= 1;
          self.t.send({ stream_id: id, type: 'stream_chunk', seq: seq++, result: next.value });
        }
        self.t.send({ stream_id: id, type: 'stream_end', seq, reason: cancelled ? 'cancelled' : 'ok' });
      } finally {
        self.serverStreams.delete(id);
        resolve();
      }
    });
  }

  private async onFrame(e: Envelope): Promise<void> {
    if (e.type === 'req') {
      const h = this.handlers.get(e.method!);
      if (!h) {
        this.t.send({ stream_id: e.stream_id, type: 'error', seq: 0, error: { code: -32601, message: `method not found: ${e.method}` } });
        return;
      }
      try {
        const out = await h(e.params);
        if (isAsyncIterable(out)) {
          await this.runServerStream(e.stream_id, out, e.credits ?? 0);
        } else {
          this.t.send({ stream_id: e.stream_id, type: 'res', seq: 0, result: out });
        }
      } catch (err) {
        this.t.send({ stream_id: e.stream_id, type: 'error', seq: 0, error: { code: -32000, message: (err as Error).message } });
      }
      return;
    }

    if (e.type === 'res') {
      // Credit grant for an active server stream takes priority over unary response.
      const s = this.serverStreams.get(e.stream_id);
      if (s) { s.grant(e.credits ?? 0); return; }
      const pending = this.pending.get(e.stream_id);
      if (pending) { this.pending.delete(e.stream_id); pending.resolve(e.result); }
      return;
    }

    if (e.type === 'error') {
      const pending = this.pending.get(e.stream_id);
      if (pending) { this.pending.delete(e.stream_id); pending.reject(new Error(e.error?.message ?? 'unknown error')); }
      return;
    }

    if (e.type === 'stream_chunk') {
      const s = this.streams.get(e.stream_id);
      if (!s) return;
      if (s.resolve) { const r = s.resolve; s.resolve = null; r({ value: e.result, done: false }); }
      else { s.queue.push(e.result); }
      return;
    }

    if (e.type === 'cancel') {
      const s = this.serverStreams.get(e.stream_id);
      s?.cancel();
      return;
    }

    if (e.type === 'stream_end') {
      const s = this.streams.get(e.stream_id);
      if (!s) return;
      s.ended = true;
      if (s.resolve) { const r = s.resolve; s.resolve = null; r({ value: undefined, done: true }); }
      this.streams.delete(e.stream_id);
      return;
    }
  }
}

function isAsyncIterable(x: unknown): x is AsyncIterable<unknown> {
  return x !== null && typeof x === 'object' && Symbol.asyncIterator in (x as object);
}
