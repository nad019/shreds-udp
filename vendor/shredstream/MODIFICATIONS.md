# Modifications to the vendored `shredstream` crate

Upstream: [`shredstream` 2.0.0](https://crates.io/crates/shredstream) — <https://github.com/shredstream/shredstream-sdk-rust>,
© ShredStream.com, **MIT License** (see `LICENSE` in this folder, kept unchanged).

This copy is **modified**. The upstream license and copyright notice apply to the upstream code; the changes below
are distributed under the same MIT terms.

| File | Change |
|---|---|
| `Cargo.toml` | `solana-entry` / `solana-transaction` / `solana-message` pinned to the versions used by upstream 3.0.0 (4.x line) so **version-1 transactions** (SIMD-0385) decode |
| `src/decoder.rs` | `RawTx`: every transaction is cut out of the entry as its **original wire bytes** (no decode / re-encode); `decode()` on demand; `first_signature()`, `tx_wire_len()`; last-decode-failure diagnostics |
| `src/accumulator.rs` | out-of-order batch flush (deliver batches behind a stalled one) with duplicate suppression; per-phase timing counters |
| `src/fec.rs` | cached Reed-Solomon codec, fast path for few missing shreds, recovery statistics |
| `src/listener.rs` | `handle_packet()` drive mode (the caller owns the socket), `last_slot()`, per-phase timing, unparseable-index counter, salvage-delivery switch |
| `src/lib.rs`, `src/error.rs` | exports for the above |
| `examples/` | adapted to the API changes |
