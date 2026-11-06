# shreds-udp

Receives **Solana shreds over unicast UDP** (from a shred provider), reassembles them (Reed-Solomon FEC + entry
decoding) and delivers the transactions **as their original wire bytes** to local consumers — with an optional
raw-shred forward to your validator / RPC node's TVU port.

```
shred provider ──UDP──► shreds-udp (--src 0.0.0.0:<port>)
                           ├─► unix socket : [len u32][slot u64][tx bytes] frames
                           ├─► --node      : raw shreds → 127.0.0.1:8001 (node TVU)
                           └─► --listen    : Yellowstone gRPC Subscribe (transactions)
```

## Features
- One receive+decode thread, no channel hops; optional pinning (`--cpu`) and `SO_BUSY_POLL`.
- Transactions emitted as soon as their entry is complete, **as the original bytes** (legacy, v0 and v1),
  framed `[len u32 LE][slot u64 LE][bytes]` on a unix socket.
- `--node`: forwards every raw packet to a UDP address (your node's TVU), fire-and-forget (a full node buffer drops
  the packet, never stalls decoding); `--node-first` forwards before decoding.
- Stale gate: batches from slots already left behind are dropped.
- Feed-gap instrumentation: gaps between packets and slot-advance stalls, bucketed.
- Status line every 10 s: decoded tx/s, FEC recoveries, decode / write / packet→socket latency, forward drops.

## Requirements
- Linux, Rust (stable).
- A shred provider sending UDP shreds to this machine (bind the wildcard address: providers send to your
  **public** IP; a loopback bind receives nothing). Open the port in your firewall.

## Build & run
```bash
cargo build --release
./target/release/shreds-udp --cpu 30 --src 0.0.0.0:23000 \
    --node 127.0.0.1:8001 --node-first --socket /tmp/shreds-udp.sock --listen 127.0.0.1:9003
```

| Flag | Default | |
|---|---|---|
| `--src` | `0.0.0.0:21000` | UDP address to receive shreds on |
| `--stuck-timeout-ms` | `50` | how long an incomplete batch waits before being decoded from what it has |
| `--cpu` | — | pin the receive+decode thread |
| `--node` / `--node-first` | — | raw packet forward to a UDP address (e.g. node TVU) |
| `--busy-poll-us` | `0` | `SO_BUSY_POLL` on the receive socket |
| `--slow-forensics` | off | per-packet getrusage around slow (>50 ms) decode calls |
| `--listen` | — | Yellowstone gRPC address; absent = no gRPC, no full decode |
| `--socket` | — | unix socket path for the raw transaction feed |

Check that packets arrive: the status line shows `pkts=` growing and `(+N/s)` decoded transactions.

## Related
- [dz-udp](https://github.com/nad019/dz-udp) — same pipeline for the **DoubleZero multicast** feed.
- [node-latency](https://github.com/nad019/node-latency) — measure how far your node's execution trails these shreds.

## Credits & third-party licenses
This project is MIT-licensed (see `LICENSE`). It includes or depends on third-party software; their licenses are
respected and apply to their code:

| Component | Use | License |
|---|---|---|
| [`shredstream`](https://github.com/shredstream/shredstream-sdk-rust) 2.0.0 by ShredStream.com | **vendored and modified** in `vendor/shredstream` (changes listed in `vendor/shredstream/MODIFICATIONS.md`; original `LICENSE` kept) | MIT |
| [`yellowstone-grpc-proto`](https://github.com/rpcpool/yellowstone-grpc) (Triton One) | gRPC types | Apache-2.0 |
| Solana / Anza crates (`solana-transaction`, `solana-message`, `solana-signature`, `solana-entry`, …) | transaction types | Apache-2.0 |
| `tokio`, `tonic`, `prost`, `clap`, `socket2`, `libc`, `anyhow` | runtime / gRPC / CLI / sockets | MIT or MIT/Apache-2.0 |
