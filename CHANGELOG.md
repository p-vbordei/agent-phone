# Changelog

## v0.1.0 — 2026-04-24

Initial release. What landed:

- Noise_XK_25519_ChaChaPoly_BLAKE2s handshake over WebSocket, prologue-bound to both agents' DIDs (`"agent-phone/1" || lp(initiator_did) || lp(responder_did)`).
- did:key + Ed25519 ↔ X25519 key conversion (the Ed25519 signing key derives the X25519 static used by Noise).
- JSON envelope (`{stream_id, type, seq, credits?, method?, params?, result?, reason?, error?}`) encoded as RFC 8785 canonical JSON (byte-deterministic).
- Unary request/response, server-streaming, credit-based backpressure, graceful cancel, error frames.
- Reference server (`createServer`) and client (`connect`) libraries. Single-binary compile via `bun build --compile`.
- Conformance vectors C1–C4 runnable with one command (`bun conformance/run.ts`).
- 20-line end-to-end demo (`examples/demo.ts`).

Deferred to v0.2: `did:web` resolution, WebRTC DataChannel transport, session resumption, CLI, browser build, key rotation mid-session signaling.
