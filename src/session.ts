import type { Envelope } from './envelope.ts';

export type SessionTransport = {
  send: (env: Envelope) => void;
  onRecv: (cb: (env: Envelope) => void) => void;
  close: () => void;
};

export class Session {
  constructor(_t: SessionTransport, _role: 'initiator' | 'responder') {
    throw new Error('not implemented');
  }
}
