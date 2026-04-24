# agent-phone — v0.1 scope sheet

Output of Stage 1 scope compression. Locked 2026-04-24. Inclusion requires either (a) a named first-party caller in the 8-repo family today, or (b) the primary use case dies without it. Default is DEFERRED.

**Primary use case:** two DID-owning agents hold a single authenticated sync call with unary RPC, server-streamed responses, credit-based backpressure, and clean cancel — over WebSocket, self-custody, no TLS / CA / JWE envelope.

**Language:** TypeScript + Bun (follows the family default; build-prompt tailoring for this repo).

---

## IN-V0.1

| # | Feature | Why |
|---|---|---|
| 1 | Noise_XK handshake (ChaChaPoly + X25519 + BLAKE2s) | Authenticated channel; use-case dies without it |
| 2 | Ed25519 → X25519 static-key derivation | Agents hold Ed25519 signing keys (agent-id) |
| 3 | Prologue DID-binding `"agent-phone/1" \|\| lp(init_did) \|\| lp(resp_did)` | Core MITM defense (C1) |
| 4 | Responder static-key ↔ DID-Document check (did:key only) | SPEC §2.2 MUST |
| 5 | WebSocket transport, subprotocol `agent-phone.v1` | Only transport in v0.1 |
| 6 | Length-prefixed Noise transport framing (post-handshake) | Wire demux |
| 7 | JSON envelope `{stream_id, type, seq, credits?, method?, params?, result?, reason?, error?}` | Wire contract |
| 8 | Unary request/response | Simplest call |
| 9 | Server-streaming with credit-based backpressure | Half the pitch; C2 |
| 10 | Graceful cancel | C3; stops runaway streams |
| 11 | Error frames | Failures without dropping the session |
| 12 | Reference server library (mountable on Hono/Bun ws) | Half the product |
| 13 | Reference client library | Other half |
| 14 | Conformance vectors C1–C4 (SPEC §6) | The vectors ARE the product |

## DEFERRED-TO-V0.2

- did:web resolution (adds HTTP/DNS to the handshake; did:key covers demo + conformance)
- WebRTC DataChannel transport (no caller today; ~5k LoC STUN/ICE surface)
- Session resumption / 0-RTT on reconnect (SPEC §5 + README explicitly defer)
- Key-rotation-mid-session handling (SPEC §5 notes existing sessions survive; new sessions use new key)
- CLI (`agent-phone listen` / `agent-phone call`) — library-first; revisit if users ask
- Browser build / published npm package (single-binary `bun build --compile` + the demo is enough for v0.1.0)

## CUT

- NAT traversal — belongs in `agent-mesh`
- Traffic-analysis padding — SPEC §5 explicitly out of scope
- Tool calling (MCP) — out of scope per README
- Durable inbox / offline delivery — `agent-inbox` owns this
- Human voice / video — not this protocol

---

## Budget

- ~2k LoC core + ~1k LoC tests, under 5k LoC total.
- Single binary via `bun build --compile`.
- Zero database. Zero Docker. Zero services besides the process itself.
- < 30s full test run.
- Demo: one command, < 20 lines of user-facing code, shows handshake → unary → stream → backpressure → cancel → session reuse.
