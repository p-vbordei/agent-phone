# agent-phone

> Minimal sync RPC between two AI agents. Self-custody keys, Noise-framework handshake, DID-bound WebSocket.

## What

`agent-phone` is a small protocol for two agents to hold a live, authenticated, bidirectional conversation over WebSocket (or WebRTC data channel). Both agents identify with self-custody DIDs. The Noise-framework handshake binds the transport session to those DIDs — the session cannot be MITM-swapped. On top of the authenticated channel sits a tight JSON-RPC-like frame with stream support and credit-based backpressure.

Think "two agents picking up the phone, proving who they are, and talking." Not a mailbox. Not a group chat. Just a call.

## Status

**v0.1.0 — released 2026-04-24.** Spec: [SPEC.md](./SPEC.md). Reference implementation in TypeScript + Bun.

## Quickstart

```bash
bun install
bun test
bun examples/demo.ts
```

That's it. Three commands, no Docker, no services. The demo spawns a responder and an initiator in one process, completes a Noise_XK handshake bound to both agents' DIDs, runs a unary `echo`, streams `search` with credit-based backpressure, cancels mid-stream, and reuses the same session for another unary call. Takes about a second.

The primary public API is two functions:

```typescript
import { createServer, connect, generateKeyPair, encodeDidKey } from 'agent-phone';

const { publicKey, privateKey } = generateKeyPair();
const did = encodeDidKey(publicKey);

const server = createServer({ did, privateKey, handlers: { echo: (p) => p } });
await server.listen(7777);

const client = await connect({ url: 'ws://localhost:7777', did, privateKey, responderDid: did });
console.log(await client.call('echo', { hi: 1 }));
```

Conformance vectors that other implementations can validate against live in [conformance/](./conformance/). Run them with `bun conformance/run.ts`.

## The gap

Google A2A solves agent↔agent RPC but anchors identity in TLS / DNS / CAs — not self-custody. A2A also assumes always-on HTTPS services, which doesn't fit an agent running inside a user's laptop. DIDComm v2 is self-custody but the JWE envelope is heavy (~15k LoC of JOSE in `didcomm-rust`), designed for store-and-forward, and lacks first-class RPC semantics. libp2p is too heavy to adopt for a narrow agent-to-agent RPC. The Noise + WebSocket + DID-bound pattern exists in Lightning (BOLT-8) and some Nostr NIPs, but not as a reusable agent RPC library.

## Scope

**In scope**

- Noise_XK handshake (static keys derived from Ed25519 → X25519)
- WebSocket transport (default), WebRTC DataChannel (optional)
- Prologue binding: `"agent-phone/1" || initiator_did || responder_did`
- JSON-RPC 2.0 frame with `stream_id`, `type`, `seq`, `credits`
- Server-sent streaming + backpressure
- Graceful cancel + teardown
- Rust reference server + client

**Out of scope**

- NAT traversal (that belongs in `agent-mesh`)
- Durable inbox / offline delivery (that's `agent-inbox`)
- Tool calling (MCP)
- Human voice / video
- Session resumption (defer to v0.2)

## Dependencies and companions

- **Depends on:** `agent-id` (DIDs + Ed25519 keys).
- **Can log via:** `agent-scroll` (canonical transcripts of calls), `agent-toolprint` (tool-call receipts made during a call).

## Validation scoring

| Criterion | Score |
|---|---|
| Scope (1-3w solo) | 4 |
| Composes mature primitives | 5 |
| Standalone | 5 |
| Clear gap | 4 |
| Light deps | 5 |
| Testable | 4 |
| **Total** | **27/30** |

Verdict: **EASY, ship it.** Full validation: [`../research/validations/agent-phone.md`](../research/validations/agent-phone.md). Biggest risk: scope creep (NAT / session resumption). Ruthlessly defer both.

## Prior art

- **Google A2A** — TLS / DNS anchor; not self-custody; always-on HTTPS.
- **DIDComm v2** — self-custody but heavy, store-and-forward shaped.
- **libp2p** — solves identity + transport but too heavy.
- **Noise libraries** — `snow` (Rust, mature), `noise-c`, `@chainsafe/libp2p-noise`.
- **Lightning BOLT-8** — Noise-XK + Ed25519 → X25519; same pattern, different domain.

## Implementation skeleton

**Wire format**

- **Handshake:** Noise_XK_25519_ChaChaPoly_BLAKE2s. Three WS binary frames (`e`, `e,ee,s,es`, `s,se`). Prologue = `"agent-phone/1" || initiator_did || responder_did`.
- **Post-handshake:** length-prefixed Noise transport frames carrying JSON-RPC 2.0 envelopes with `{ stream_id, type: req|res|stream_chunk|stream_end|cancel|error, seq, credits }`.

**Dependencies (Rust ref):** `snow`, `tokio-tungstenite`, `ed25519-dalek`, `x25519-dalek`, `serde_json`.

**Repo sizing:** ~2k LoC core + ~1k LoC tests. Target < 5k LoC total, single-binary reference server, < 30s `cargo test`.

## Conformance tests

1. **Handshake DID-binding:** swap responder's static key mid-handshake → initiator MUST abort.
2. **Streaming backpressure:** server emits 10k chunks, client grants 8 at a time → server blocks after 8, resumes on credit.
3. **Graceful teardown + cancel:** client sends `cancel(stream_id)` → server stops within 1 frame, emits `stream_end{reason: cancelled}`; socket stays open for next RPC.

## License

Apache 2.0 — see [LICENSE](./LICENSE).

## Research

Landscape, prior art, scoring rationale: [`../research/`](../research/).
