//! UDP shred source (default 0.0.0.0:21000) → shredstream crate → Yellowstone gRPC.
//!
//! Pipeline:
//!   plain UDP socket (unicast shreds fed by a local source) → broadcast → gRPC
//!   + raw wire-bytes unix socket for the consumer (original tx bytes, no re-encode)
//!
//! Sibling of dz-udp: identical decode/delivery pipeline, only the packet SOURCE differs —
//! no DoubleZero tunnel, no multicast join, no interface resolution. A shred provider (or
//! a local process) sends shreds to our UDP port; each datagram is expected to be one raw
//! shred, the exact same wire bytes a multicast feed carries. If the
//! source ever frames differently, the accumulator simply yields no batches — visible
//! in the status line as pkts>0 with batches=0.
//!
//! Uses the shredstream crate (crates.io) for canonical shred decoding with
//! Reed-Solomon FEC recovery (SIMD-accelerated on x86_64) and solana-entry
//! deserialization. No jito dependency, no hand-rolled decoder.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use shredstream::{ListenerOptions, ShredListener};
use solana_message::VersionedMessage;
use solana_transaction::versioned::VersionedTransaction;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use yellowstone_grpc_proto::geyser::{
    geyser_server::{Geyser, GeyserServer},
    subscribe_update::UpdateOneof,
    GetBlockHeightRequest, GetBlockHeightResponse, GetLatestBlockhashRequest,
    GetLatestBlockhashResponse, GetSlotRequest, GetSlotResponse, GetVersionRequest,
    GetVersionResponse, IsBlockhashValidRequest, IsBlockhashValidResponse, PingRequest,
    PongResponse, SubscribeDeshredRequest, SubscribeReplayInfoRequest,
    SubscribeReplayInfoResponse, SubscribeRequest, SubscribeUpdate, SubscribeUpdateDeshred,
    SubscribeUpdateTransaction, SubscribeUpdateTransactionInfo,
};
use yellowstone_grpc_proto::solana::storage::confirmed_block::{
    CompiledInstruction, Message as ProtoMessage, MessageAddressTableLookup, MessageHeader,
    Transaction as ProtoTransaction,
};

#[derive(Parser, Debug)]
#[command(about = "Local UDP shreds → shredstream decode → Yellowstone gRPC")]
struct Args {
    /// Local UDP address to receive shreds on. The external source feeds this port.
    ///
    /// Default is the WILDCARD, not 127.0.0.1: a remote provider typically sends unicast to the machine's PUBLIC IP (<public-ip>:<port>) from
    /// <provider-ip> — a loopback bind silently receives nothing (pkts=0).
    #[arg(long, default_value = "0.0.0.0:21000")]
    src: String,

    /// How long an incomplete entry batch waits for its missing shreds before being
    /// force-finalized and decoded from whatever contiguous runs it has.
    ///
    /// This is the tail. A batch that never completes blocks delivery of everything behind
    /// it for exactly this long, so the p99 sits near this value. The SDK default is 50ms,
    /// which is why a ~45ms p99 shows up: it is not jitter, it is this timer. Lowering it
    /// trades completeness for latency — a batch cut short delivers only the transactions
    /// in its intact runs, and the ones spanning the gap are lost rather than late.
    #[arg(long, default_value_t = 50)]
    stuck_timeout_ms: u64,

    /// Pin the receive+decode thread to this CPU. Unset = unpinned.
    ///
    /// That thread spins in blocking recv, so it holds a core. Pin it to a core the node
    /// does not use, or the receive competes with the very work it exists to stay ahead
    /// of. Pinning the THREAD, not the process: `taskset` would also confine the tokio
    /// runtime, the gRPC server and the unix-socket feed to that one core, which is the
    /// opposite of useful.
    #[arg(long)]
    cpu: Option<usize>,

    /// Optional: forward every RAW packet (pre-decode, untouched wire bytes) to this
    /// UDP address — e.g. a local validator's TVU port (127.0.0.1:8001), the Jito
    /// shredstream-proxy trick without the extra hop in front of OUR receive path.
    ///
    /// The consumer keeps the direct path: this process still binds `src` first and decodes
    /// from its own copy. By default the forward happens AFTER this packet's decode (and,
    /// when the packet completes transactions, after they are written to the consumer socket):
    /// the consumer comes first, the node gets each packet a few µs later. See --node-first.
    /// Fire-and-forget: the send socket is non-blocking and a full node-side buffer drops
    /// the packet (counted in the status line) rather than ever stalling the decode loop.
    /// Unset = no forwarding, exactly the previous behavior.
    #[arg(long)]
    node: Option<String>,

    /// With --node: forward each raw packet to the node IMMEDIATELY after recv, BEFORE
    /// decode/FEC/the consumer write. The node gains the decode time (avg ~2µs, rare spikes of
    /// hundreds of µs); the consumer's delivery pays one loopback send (a few µs) per packet.
    #[arg(long, default_value_t = false)]
    node_first: bool,

    /// SO_BUSY_POLL (µs) on the receive socket: the kernel polls the NIC queue for this
    /// long before sleeping. The source is REMOTE (<provider-ip> → public IP), i.e. a NIC
    /// path, not loopback. 0 = off (default, previous behaviour).
    #[arg(long, default_value_t = 0)]
    busy_poll_us: u32,

    /// Per-packet getrusage forensics around handle_packet (2 syscalls per packet).
    /// Off by default: it only served the >50ms slow-call dump.
    #[arg(long, default_value_t = false)]
    slow_forensics: bool,

    /// gRPC listen address (e.g. 0.0.0.0:9003). Absent = no gRPC server, no broadcast
    /// channel and no full tx decode at all — only the raw socket feed and node forward.
    #[arg(long)]
    listen: Option<String>,

    /// Unix socket path for the raw wire-bytes feed consumed by the consumer. Empty = not served.
    ///
    /// Separate from the gRPC endpoint on purpose, and both run at once: geyserbench
    /// speaks Yellowstone and measures this like any other endpoint, while the consumer wants
    /// the transaction bytes themselves. Encoding them as protobuf and re-parsing a proto
    /// Message on the far side would only reconstruct what already exists here.
    #[arg(long, default_value = "")]
    socket: String,
}

// ── Global counters for the periodic status line ────────────────────────

static N_DECODED: AtomicU64 = AtomicU64::new(0);
static N_SENT: AtomicU64 = AtomicU64::new(0);
static N_LAGGED: AtomicU64 = AtomicU64::new(0);
static N_BATCHES: AtomicU64 = AtomicU64::new(0);
static N_FEC: AtomicU64 = AtomicU64::new(0);
static N_PACKETS: AtomicU64 = AtomicU64::new(0);
// [Tail] Why a batch was cut short. `timeout` is the stuck-batch timer expiring — the
// p99's direct cause. `skipped` is a batch that yielded nothing at all.
static N_FORCE_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static N_FORCE_CORRUPT: AtomicU64 = AtomicU64::new(0);
static N_SKIPPED: AtomicU64 = AtomicU64::new(0);
static N_OOO_BATCH: AtomicU64 = AtomicU64::new(0);
static N_OOO_TX: AtomicU64 = AtomicU64::new(0);
static N_OOO_DUP: AtomicU64 = AtomicU64::new(0);
// [--node] raw-packet forward: delivered vs dropped (node-side buffer full). Drops are
// expected to sit near zero — a rising drop rate means the node isn't draining its TVU
// socket fast enough, not that our path is unhealthy.
static N_FWD: AtomicU64 = AtomicU64::new(0);
static N_FWD_DROP: AtomicU64 = AtomicU64::new(0);

// [Stale gate] Deliveries older than the live edge. `disable_salvage_delivery` closes
// the eviction path, but shreds that arrive seconds late (relay retransmits, upstream
// gaps) still trigger stuck-batch salvage inside a still-live slot and decode into
// transactions that are old news by the time they are emitted — the 3.5-4.5s tail gRPC
// subscribers saw. Anything from a slot more than STALE_MAX_SLOTS behind `last_slot`
// is already outdated, so it is counted and dropped instead of forwarded.
const STALE_MAX_SLOTS: u64 = 2;
static N_STALE_BATCH: AtomicU64 = AtomicU64::new(0);
static N_STALE_TX: AtomicU64 = AtomicU64::new(0);
static STALE_MAX_AGE: AtomicU64 = AtomicU64::new(0);
// [Decode errors] Entries that failed to deserialise. Our vendored decoder predates
// transaction version 1 (upstream 3.0.0 added V1 via solana-transaction 4.x); a rising
// count here is the signature of V1 entries being dropped wholesale = lost transactions.
static N_DECODE_ERRORS: AtomicU64 = AtomicU64::new(0);

// [Feed gaps] Silence detection, the instrument for the seconds-late tail that the
// stale gate proved slot-fresh: if the relay path goes quiet for seconds, the live
// edge freezes and everything afterwards arrives "on time" relative to a feed that is
// itself seconds behind — wall-late, slot-fresh, invisible to age gating. Two views:
// recv gaps (no packets at all) and slot-advance stalls (packets still flowing —
// duplicates/coding — but no new slot). Both second-scale buckets.
const RECV_GAP_BOUNDS_US: [u64; 8] =
    [10_000, 100_000, 500_000, 1_000_000, 2_000_000, 3_500_000, 6_000_000, 12_000_000];
static RECV_GAP_BUCKETS: [AtomicU64; 9] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0),
];
const SLOT_STALL_BOUNDS_US: [u64; 8] =
    [500_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000, 6_000_000, 10_000_000];
static SLOT_STALL_BUCKETS: [AtomicU64; 9] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0),
];

fn bucket_add(buckets: &[AtomicU64; 9], bounds: &[u64; 8], v: u64) {
    let b = bounds.iter().position(|&x| v < x).unwrap_or(8);
    buckets[b].fetch_add(1, Relaxed);
}

fn hex_head(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("")
}

fn buckets_line(buckets: &[AtomicU64; 9], labels: &[&str; 9]) -> String {
    let v: Vec<u64> = buckets.iter().map(|x| x.load(Relaxed)).collect();
    if v.iter().all(|&x| x == 0) {
        return String::new();
    }
    let parts: Vec<String> =
        v.iter().zip(labels).map(|(n, l)| format!("{l}:{}", n)).collect();
    format!("{}", parts.join(" "))
}
// Age (in slots) of dropped batches at delivery, bucketed. The shape identifies the
// mechanism: a spike at 3-8 slots = salvage after short feed gaps; values in the tens =
// shreds landing far behind the live edge.
const STALE_AGE_BOUNDS: [u64; 7] = [4, 6, 8, 12, 16, 32, 64];
static STALE_AGE_BUCKETS: [AtomicU64; 8] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

fn record_stale_age(age: u64) {
    let b = STALE_AGE_BOUNDS.iter().position(|&x| age < x).unwrap_or(7);
    STALE_AGE_BUCKETS[b].fetch_add(1, Relaxed);
}

// [Decode cost] Wall time inside `handle_packet` — shred parse, FEC, entry
// deserialisation, everything the accumulator does. Measured on EVERY packet, not only
// the ones that emit, because a packet that produces nothing still costs the thread. At
// ~9k packets/s the budget is 111µs each; consistently above that and we fall behind the
// wire no matter how fast the socket write is.
const DEC_BOUNDS_US: [u64; 8] = [5, 10, 25, 50, 100, 250, 1_000, 5_000];
static DEC_BUCKETS: [AtomicU64; 9] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0),
];
static DEC_SUM_US: AtomicU64 = AtomicU64::new(0);
static DEC_MAX_US: AtomicU64 = AtomicU64::new(0);

// [Write cost] The single `write_all` plus the mutex around it, on its own. Splits the
// gap between decode and delivery into serialise-versus-syscall instead of guessing.
static WR_BUCKETS: [AtomicU64; 9] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0),
];
static WR_SUM_US: AtomicU64 = AtomicU64::new(0);
static WR_MAX_US: AtomicU64 = AtomicU64::new(0);
// Serialise phase: the framing loop, without the write.
static SER_SUM_US: AtomicU64 = AtomicU64::new(0);
static SER_MAX_US: AtomicU64 = AtomicU64::new(0);
static SER_N: AtomicU64 = AtomicU64::new(0);

#[inline]
fn record_write(us: u64) {
    let b = DEC_BOUNDS_US.iter().position(|&x| us < x).unwrap_or(8);
    WR_BUCKETS[b].fetch_add(1, Relaxed);
    WR_SUM_US.fetch_add(us, Relaxed);
    WR_MAX_US.fetch_max(us, Relaxed);
}

fn wr_pct(p: f64) -> Option<String> {
    let b: Vec<u64> = WR_BUCKETS.iter().map(|x| x.load(Relaxed)).collect();
    let total: u64 = b.iter().sum();
    if total == 0 {
        return None;
    }
    let target = (total as f64 * p) as u64;
    let mut acc = 0u64;
    for (i, c) in b.iter().enumerate() {
        acc += c;
        if acc >= target {
            return Some(match DEC_BOUNDS_US.get(i) {
                Some(&u) if u < 1_000 => format!("<{}µs", u),
                Some(&u) => format!("<{}ms", u / 1_000),
                None => ">=5ms".into(),
            });
        }
    }
    None
}

#[inline]
fn record_decode(us: u64) {
    let b = DEC_BOUNDS_US.iter().position(|&x| us < x).unwrap_or(8);
    DEC_BUCKETS[b].fetch_add(1, Relaxed);
    DEC_SUM_US.fetch_add(us, Relaxed);
    DEC_MAX_US.fetch_max(us, Relaxed);
}

fn dec_pct(p: f64) -> Option<String> {
    let b: Vec<u64> = DEC_BUCKETS.iter().map(|x| x.load(Relaxed)).collect();
    let total: u64 = b.iter().sum();
    if total == 0 {
        return None;
    }
    let target = (total as f64 * p) as u64;
    let mut acc = 0u64;
    for (i, c) in b.iter().enumerate() {
        acc += c;
        if acc >= target {
            return Some(match DEC_BOUNDS_US.get(i) {
                Some(&u) if u < 1_000 => format!("<{}µs", u),
                Some(&u) => format!("<{}ms", u / 1_000),
                None => ">=5ms".into(),
            });
        }
    }
    None
}
static N_FALLBACK: AtomicU64 = AtomicU64::new(0);

// [Entry size] How many transactions each decode emits at once. `StreamingDecoder`
// deserialises a whole `Entry` or nothing, so every transaction in an entry waits for the
// last byte of the last one. If entries are small this costs nothing; if they are large it
// is pure latency for the ones that arrived first. Buckets rather than percentiles — the
// question is only "are entries big", and that needs one order of magnitude, not precision.
static EMIT_BUCKETS: [AtomicU64; 7] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static EMIT_SUM: AtomicU64 = AtomicU64::new(0);
static EMIT_MAX: AtomicU64 = AtomicU64::new(0);

#[inline]
fn record_emit(n: usize) {
    let b = match n {
        0..=1 => 0, 2..=3 => 1, 4..=7 => 2, 8..=15 => 3,
        16..=31 => 4, 32..=63 => 5, _ => 6,
    };
    EMIT_BUCKETS[b].fetch_add(1, Relaxed);
    EMIT_SUM.fetch_add(n as u64, Relaxed);
    EMIT_MAX.fetch_max(n as u64, Relaxed);
}

// [E2E] Packet arrival → unix-socket write, per transaction. This is the only latency
// number that describes what the consumer experiences: no cross-tool comparison, no borrowed
// timestamps. shredtop's LEAD column cannot answer it — that tool credits every
// transaction in a slot with the timestamp of the slot's EARLIEST shred
// (decoder.rs `earliest_recv_ns`), so its "lead" is really how deep into the slot a
// transaction sat, and it barely moves when this pipeline gets faster.
//
// Bucket boundaries in microseconds; percentiles are resolved to the bucket, which is
// all that is needed to tell "sub-millisecond" from "tens of milliseconds".
const E2E_BOUNDS_US: [u64; 9] = [100, 250, 500, 1_000, 2_000, 5_000, 10_000, 25_000, 50_000];
static E2E_BUCKETS: [AtomicU64; 10] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0),
];
static E2E_SUM_US: AtomicU64 = AtomicU64::new(0);
static E2E_MAX_US: AtomicU64 = AtomicU64::new(0);

/// Connected unix clients, written to DIRECTLY by the decode thread.
///
/// The broadcast channel is still how gRPC subscribers are fed — they are tooling, and a
/// task hop costs them nothing. The socket is the consumer's path, so it gets no hop at all:
/// a transaction is framed and written the moment the decoder produces it, on the same
/// thread, with no channel, no `Arc`, and no task wakeup. That wakeup was the last
/// per-transaction scheduler round-trip left in the pipeline; the receive side lost its
/// two earlier today.
static UNIX_CLIENTS: std::sync::OnceLock<std::sync::Mutex<Vec<UnixClient>>> =
    std::sync::OnceLock::new();

/// A connected reader plus the unsent tail of a frame batch. The socket is non-blocking,
/// and a non-blocking stream write can be PARTIAL — dropping the remainder would cut a
/// frame in half and the consumer would parse the next bytes as a length header (garbage
/// transactions until the length happens to exceed MAX_FRAME). The tail is kept and sent
/// first on the next write, so the byte stream always stays frame-aligned.
struct UnixClient {
    sock: std::os::unix::net::UnixStream,
    pending: Vec<u8>,
}

/// Unsent bytes a slow client may accumulate before WHOLE new batches start being dropped.
const UNIX_PENDING_CAP: usize = 4 * 1024 * 1024;

fn unix_clients() -> &'static std::sync::Mutex<Vec<UnixClient>> {
    UNIX_CLIENTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Frames dropped because a client's socket buffer was full. Dropping beats stalling the
/// decoder: a blocked write here would hold up every transaction behind it, and the consumer
/// recovers from a gap far better than from a stall.
static N_SOCK_DROP: AtomicU64 = AtomicU64::new(0);

/// Write a pre-built buffer of N frames to every connected client. Dead clients dropped.
///
/// One `write_all` per decode batch, not per transaction. A packet that completes a gap
/// can release hundreds of transactions at once — measured max 419 — and writing them one
/// by one made the last of them wait on 418 syscalls ahead of it. That was the whole gap
/// between `handle_packet` (7µs) and delivery (245µs); the decode was never the cost. The
/// socket is a byte stream and every frame carries its own length, so the reader cannot
/// tell whether they arrived in one write or four hundred.
fn write_unix(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    let mut guard = match unix_clients().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if guard.is_empty() {
        return;
    }
    use std::io::Write;
    // Ok(n) = n bytes accepted (0 on WouldBlock); Err = client gone.
    fn try_write(sock: &mut std::os::unix::net::UnixStream, b: &[u8]) -> std::io::Result<usize> {
        let mut off = 0;
        while off < b.len() {
            match sock.write(&b[off..]) {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(k) => off += k,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(off)
    }
    guard.retain_mut(|c| {
        // Older bytes first — the stream must stay in order.
        if !c.pending.is_empty() {
            match try_write(&mut c.sock, &c.pending) {
                Ok(k) => {
                    c.pending.drain(..k);
                }
                Err(_) => {
                    println!("unix client disconnected");
                    return false;
                }
            }
        }
        if c.pending.is_empty() {
            match try_write(&mut c.sock, buf) {
                Ok(k) if k == buf.len() => {}
                Ok(k) => c.pending.extend_from_slice(&buf[k..]),
                Err(_) => {
                    println!("unix client disconnected");
                    return false;
                }
            }
        } else if c.pending.len() + buf.len() <= UNIX_PENDING_CAP {
            c.pending.extend_from_slice(buf);
        } else {
            // Whole batch dropped — never a partial frame.
            N_SOCK_DROP.fetch_add(1, Relaxed);
        }
        true
    });
}

/// Monotonic clock shared by the receive thread and the socket writer.
fn mono_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
}

/// Per-thread resource usage (this thread only — the receive thread is the one whose
/// slow calls matter). Cheap enough to bracket every packet: a single syscall into the
/// task's accounting fields, no lock.
fn thread_rusage() -> libc::rusage {
    // SAFETY: rusage is a plain C struct written by the kernel; zeroed init is valid.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: FFI, pointer to a valid struct of the expected type.
    unsafe {
        libc::getrusage(libc::RUSAGE_THREAD, &mut ru);
    }
    ru
}

// [2026-09-29] Where the time goes on packets that EMIT transactions. handle_packet's
// overall histogram is ~97% idle packets; the pachet→socket average is tx-weighted and
// dominated by the few packets that release a big batch at once. Per emitting packet:
// count, handle_packet sum, tx-weighted sum, and the six listener phases (ns).
static EMIT_PKT_N: AtomicU64 = AtomicU64::new(0);
static EMIT_PKT_US: AtomicU64 = AtomicU64::new(0);
static EMIT_PKT_MAX_US: AtomicU64 = AtomicU64::new(0);
static EMIT_TXW_US: AtomicU64 = AtomicU64::new(0);
static EMIT_TXW_N: AtomicU64 = AtomicU64::new(0);
static EMIT_PH_NS: [AtomicU64; 6] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

#[inline]
fn record_e2e(us: u64) {
    let b = E2E_BOUNDS_US.iter().position(|&x| us < x).unwrap_or(9);
    E2E_BUCKETS[b].fetch_add(1, Relaxed);
    E2E_SUM_US.fetch_add(us, Relaxed);
    E2E_MAX_US.fetch_max(us, Relaxed);
}

/// Percentile resolved to a bucket upper bound. Returns `None` before any sample.
fn e2e_pct(p: f64) -> Option<String> {
    let b: Vec<u64> = E2E_BUCKETS.iter().map(|x| x.load(Relaxed)).collect();
    let total: u64 = b.iter().sum();
    if total == 0 {
        return None;
    }
    let target = (total as f64 * p) as u64;
    let mut acc = 0u64;
    for (i, c) in b.iter().enumerate() {
        acc += c;
        if acc >= target {
            return Some(match E2E_BOUNDS_US.get(i) {
                Some(&u) if u < 1_000 => format!("<{}µs", u),
                Some(&u) => format!("<{}ms", u / 1_000),
                None => ">=50ms".into(),
            });
        }
    }
    None
}

/// Lightweight decoded tx for the gRPC broadcast channel.
struct DecodedTx {
    transaction: VersionedTransaction,
    slot: u64,
}

// ══════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let src: std::net::SocketAddr = args.src.parse()?;

    // ── Broadcast channel: decoder → gRPC ────────────────────────────────
    // Created only with --listen: without it the recv thread gets None and skips the
    // decode/broadcast block entirely (not even a receiver_count check).
    let bcast_tx: Option<tokio::sync::broadcast::Sender<Arc<DecodedTx>>> = args
        .listen
        .as_ref()
        .map(|_| tokio::sync::broadcast::channel::<Arc<DecodedTx>>(65_536).0);

    // ── ONE receive+decode thread ────────────────────────────────────────
    //
    // Receive AND decode happen on ONE thread, which is what removes the per-packet cost
    // a receive→channel→decoder split pays twice (two scheduler wakeups + one allocation
    // per packet). One blocking recv per packet on the local source; no channel hop.
    //
    // [dz-udp heritage] The multicast variant merges three multicast pipeline stages into a
    // single accumulator so one path could fill another's gaps. Here there is one source
    // by construction — the accumulator config is unchanged, FEC recovery included, so a
    // lost data shred is still recoverable from coding shreds the source sends.
    {
        let bcast = bcast_tx.clone();
        let cpu = args.cpu;
        let stuck_ms = args.stuck_timeout_ms;
        let busy_poll_us = args.busy_poll_us;
        let slow_forensics = args.slow_forensics;
        let node_first = args.node_first;
        let node = args
            .node
            .map(|s| s.parse::<std::net::SocketAddr>())
            .transpose()?;
        std::thread::Builder::new()
            .name("recv-decode".into())
            .spawn(move || {
                if let Some(id) = cpu {
                    match shredstream::pin_current_thread_to_cpu(id) {
                        Ok(()) => println!("recv-decode pinned to cpu {id}"),
                        Err(e) => eprintln!("warning: could not pin to cpu {id}: {e}"),
                    }
                }
                if let Err(e) = run_receive_decode(src, stuck_ms, node, bcast, busy_poll_us, slow_forensics, node_first) {
                    eprintln!("recv-decode exited: {e}");
                }
            })?;
    }
    println!("receiving shreds on udp://{src}");

    // ── Status line every 10 s ──────────────────────────────────────────
    tokio::spawn(async move {
        let mut prev_decoded = 0u64;
        let mut prev_fail_seq: u64 = u64::MAX;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            let decoded = N_DECODED.load(Relaxed);
            let sent = N_SENT.load(Relaxed);
            let lagged = N_LAGGED.load(Relaxed);
            println!(
                "[shreds-udp] tx decoded={} (+{}/s) broadcast={} lagged={} | \
                 pkts={} batches={} fec={} sock_drop={} | tail: timeout={} corrupt={} skipped={} fallback={} \
                 | ooo: batches={} tx={} dup={} | fwd={} fwd_drop={} \
                 | stale: batches={} tx={} max_age={} | decode_err={} | idx_bad={}",
                decoded,
                (decoded - prev_decoded) / 10,
                sent,
                lagged,
                N_PACKETS.load(Relaxed),
                N_BATCHES.load(Relaxed),
                N_FEC.load(Relaxed),
                N_SOCK_DROP.load(Relaxed),
                N_FORCE_TIMEOUT.load(Relaxed),
                N_FORCE_CORRUPT.load(Relaxed),
                N_SKIPPED.load(Relaxed),
                N_FALLBACK.load(Relaxed),
                N_OOO_BATCH.load(Relaxed),
                N_OOO_TX.load(Relaxed),
                N_OOO_DUP.load(Relaxed),
                N_FWD.load(Relaxed),
                N_FWD_DROP.load(Relaxed),
                N_STALE_BATCH.load(Relaxed),
                N_STALE_TX.load(Relaxed),
                STALE_MAX_AGE.load(Relaxed),
                N_DECODE_ERRORS.load(Relaxed),
                shredstream::listener::UNPARSEABLE_SHRED_INDEX.load(Relaxed),
            );
            let stale_buckets: Vec<u64> =
                STALE_AGE_BUCKETS.iter().map(|x| x.load(Relaxed)).collect();
            if stale_buckets.iter().any(|&x| x > 0) {
                println!(
                    "           stale dropped ages: ≤3:{} 4-5:{} 6-7:{} 8-11:{} 12-15:{} \
                     16-31:{} 32-63:{} 64+:{}",
                    stale_buckets[0], stale_buckets[1], stale_buckets[2], stale_buckets[3],
                    stale_buckets[4], stale_buckets[5], stale_buckets[6], stale_buckets[7],
                );
            }
            let l = buckets_line(
                &RECV_GAP_BUCKETS,
                &["<10ms", "10-100ms", "100-500ms", "0.5-1s", "1-2s", "2-3.5s", "3.5-6s",
                  "6-12s", "12s+"],
            );
            if !l.is_empty() {
                println!("           recv gaps (between packets): {l}");
            }
            let l = buckets_line(
                &SLOT_STALL_BUCKETS,
                &["<0.5s", "0.5-1s", "1-1.5s", "1.5-2s", "2-3s", "3-4s", "4-6s", "6-10s",
                  "10s+"],
            );
            if !l.is_empty() {
                println!("           slot-advance stalls: {l}");
            }
            if N_DECODE_ERRORS.load(Relaxed) > 0 {
                match shredstream::decoder::last_decode_fail() {
                    Some((seq, err, head, len)) if seq != prev_fail_seq => {
                        prev_fail_seq = seq;
                        println!(
                            "           last decode fail #{} len={} err=\"{}\" head={}",
                            seq,
                            len,
                            err,
                            hex_head(&head)
                        );
                    }
                    _ => {}
                }
            }
            if let (Some(p50), Some(p95), Some(p99)) =
                (dec_pct(0.50), dec_pct(0.95), dec_pct(0.99))
            {
                let n: u64 = DEC_BUCKETS.iter().map(|x| x.load(Relaxed)).sum();
                println!(
                    "           handle_packet: p50={} p95={} p99={} | avg={:.0}µs max={}µs (n={})",
                    p50, p95, p99,
                    DEC_SUM_US.load(Relaxed) as f64 / n as f64,
                    DEC_MAX_US.load(Relaxed), n,
                );
            }
            let en = EMIT_PKT_N.load(Relaxed);
            if en > 0 {
                let ph: Vec<f64> = EMIT_PH_NS
                    .iter()
                    .map(|x| x.load(Relaxed) as f64 / en as f64 / 1_000.0)
                    .collect();
                println!(
                    "           emitting pkts: n={} avg={:.1}µs max={}µs tx-weighted={:.1}µs | \
                     phases avg µs: pool={:.1} parse={:.1} push={:.1} (advance={:.1} fec={:.1} flush={:.1})",
                    en,
                    EMIT_PKT_US.load(Relaxed) as f64 / en as f64,
                    EMIT_PKT_MAX_US.load(Relaxed),
                    EMIT_TXW_US.load(Relaxed) as f64 / EMIT_TXW_N.load(Relaxed).max(1) as f64,
                    ph[0], ph[1], ph[2], ph[3], ph[4], ph[5],
                );
            }
            let [rs_n, rs_miss, rs_core, rs_total] = shredstream::rs_stats();
            if rs_n > 0 {
                println!(
                    "           reed-solomon: recoveries={} data rebuilt/rec={:.1} | reconstruct avg={:.1}µs, with copies={:.1}µs",
                    rs_n,
                    rs_miss as f64 / rs_n as f64,
                    rs_core as f64 / rs_n as f64 / 1_000.0,
                    rs_total as f64 / rs_n as f64 / 1_000.0,
                );
            }
            if let (Some(p50), Some(p95), Some(p99)) =
                (wr_pct(0.50), wr_pct(0.95), wr_pct(0.99))
            {
                let n = SER_N.load(Relaxed).max(1);
                println!(
                    "           serialize: avg={:.0}µs max={}µs | write: p50={} p95={} p99={} avg={:.0}µs max={}µs",
                    SER_SUM_US.load(Relaxed) as f64 / n as f64,
                    SER_MAX_US.load(Relaxed),
                    p50, p95, p99,
                    WR_SUM_US.load(Relaxed) as f64 / n as f64,
                    WR_MAX_US.load(Relaxed),
                );
            }
            if let (Some(p50), Some(p95), Some(p99)) =
                (e2e_pct(0.50), e2e_pct(0.95), e2e_pct(0.99))
            {
                let n: u64 = E2E_BUCKETS.iter().map(|x| x.load(Relaxed)).sum();
                println!(
                    "           pachet→socket: p50={} p95={} p99={} | avg={:.0}µs max={}µs (n={})",
                    p50, p95, p99,
                    E2E_SUM_US.load(Relaxed) as f64 / n as f64,
                    E2E_MAX_US.load(Relaxed), n,
                );
            }
            let b: Vec<u64> = EMIT_BUCKETS.iter().map(|x| x.load(Relaxed)).collect();
            let n: u64 = b.iter().sum();
            if n > 0 {
                println!(
                    "           tx/entry: 1:{} 2-3:{} 4-7:{} 8-15:{} 16-31:{} 32-63:{} 64+:{} \
                     | avg={:.1} max={}",
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6],
                    EMIT_SUM.load(Relaxed) as f64 / n as f64,
                    EMIT_MAX.load(Relaxed),
                );
            }
            prev_decoded = decoded;
        }
    });

    // ── Unix socket feed (the consumer) ──────────────────────────────────────
    if !args.socket.is_empty() {
        serve_unix(args.socket.clone())?;
    }

    // ── gRPC ────────────────────────────────────────────────────────────
    let (Some(listen), Some(bcast_tx)) = (args.listen.as_ref(), bcast_tx) else {
        println!("gRPC disabled (no --listen) — raw socket / node forward only, no tx decode");
        std::future::pending::<()>().await;
        return Ok(());
    };
    let addr: std::net::SocketAddr = listen.parse()?;
    println!(
        "gRPC listening on {} — point geyserbench at http://{}",
        addr, addr
    );
    tonic::transport::Server::builder()
        .add_service(GeyserServer::new(ShredsUdp { bcast: bcast_tx }))
        .serve(addr)
        .await?;
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════
// Local UDP source
// ══════════════════════════════════════════════════════════════════════════

/// Bind the local UDP receive socket. socket2 for the large receive buffer — std's
/// UdpSocket has no set_recv_buffer_size.
///
/// SO_REUSEADDR so a restart during a busy source can rebind without an EADDRINUSE
/// dance. No SO_BUSY_POLL / IP_PKTINFO: those mattered on the NIC path (kernel-side
/// driver poll, per-group destination attribution); loopback delivery has neither NIC
/// nor groups, so plain blocking recv is already the minimum-latency path.
fn bind_src(src: std::net::SocketAddr, busy_poll_us: u32) -> Result<std::net::UdpSocket> {
    let sock = socket2::Socket::new(
        if src.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    sock.set_recv_buffer_size(64 * 1024 * 1024)?;
    if busy_poll_us > 0 {
        use std::os::unix::io::AsRawFd;
        let val = busy_poll_us as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BUSY_POLL,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if rc != 0 {
            eprintln!("warning: SO_BUSY_POLL={busy_poll_us} failed: {}", std::io::Error::last_os_error());
        } else {
            println!("SO_BUSY_POLL={busy_poll_us}µs on udp://{src}");
        }
    }
    sock.bind(&src.into())?;
    Ok(sock.into())
}

/// One thread, one socket, one accumulator, no channel.
///
/// The listener is driven with `handle_packet` instead of owning a socket, which keeps
/// receive and decode on the same thread.
fn run_receive_decode(
    src: std::net::SocketAddr,
    stuck_timeout_ms: u64,
    node: Option<std::net::SocketAddr>,
    bcast: Option<tokio::sync::broadcast::Sender<Arc<DecodedTx>>>,
    busy_poll_us: u32,
    slow_forensics: bool,
    node_first: bool,
) -> Result<()> {
    let socket = bind_src(src, busy_poll_us)?;
    if node_first && node.is_some() {
        println!("node-first: raw packets go to the node BEFORE decode");
    }

    // Raw-packet forward to `--node`, if given. Non-blocking send socket created once:
    // a send that would block (node-side buffer full) returns WouldBlock immediately and
    // the packet is dropped for the node — the decode path below must never wait on it.
    let fwd_sock = match node {
        Some(addr) => {
            let s = std::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
            s.set_nonblocking(true)?;
            s.connect(addr)?;
            println!("raw packet forwarding to udp://{addr}");
            Some(s)
        }
        None => None,
    };

    let opts = ListenerOptions {
        recv_buf: 64 * 1024 * 1024,
        max_age: 3,
        busy_poll_us: Some(200),
        pool_size: 4096,
        enable_fec: true,
        // Salvaged tail transactions are delivered when a slot is evicted at `max_age`, so
        // they are at least 3 slots — over 1.2 seconds — old by the time they arrive. They
        // are too late to be useful, so their only remaining effect was to waste consumer work on
        // transactions that were stale before they were decoded.
        disable_salvage_delivery: true,
        accumulator: shredstream::AccumulatorConfig {
            stuck_batch_timeout: std::time::Duration::from_millis(stuck_timeout_ms),
            ..shredstream::AccumulatorConfig::default()
        },
    };

    // The listener needs a socket to exist, but never reads it — packets arrive through
    // `handle_packet`. Bound to an ephemeral port so it cannot collide with anything.
    let dummy = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let mut listener = ShredListener::from_socket(dummy, opts)?;

    let mut buf = vec![0u8; 2048];
    let mut frame_buf: Vec<u8> = Vec::with_capacity(256 * 1024);
    // Gap instrumentation state: time of the previous packet and of the previous
    // live-edge advance.
    let mut t_prev_pkt = mono_ns();
    let mut prev_live_slot: u64 = 0;
    let mut t_last_advance = mono_ns();

    // [2026-09-29] Forward AFTER our own work on the packet, not before: the send is a
    // syscall (~1-3µs) that used to sit in front of every emitting packet's socket write.
    // The node replays on a millisecond scale — a few µs later is invisible to it — while
    // the consumer sees the transaction that much sooner. Fire-and-forget: errors (incl.
    // WouldBlock on a full node buffer) drop the node's copy and are counted.
    let forward = |pkt: &[u8]| {
        if let Some(fwd) = &fwd_sock {
            match fwd.send(pkt) {
                Ok(_) => {
                    N_FWD.fetch_add(1, Relaxed);
                }
                Err(_) => {
                    N_FWD_DROP.fetch_add(1, Relaxed);
                }
            }
        }
    };

    loop {
        // One blocking recv per packet. Local source: no NIC interrupt path to shortcut,
        // so blocking recv is the minimum-syscall wait.
        let n = match socket.recv(&mut buf) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        N_PACKETS.fetch_add(1, Relaxed);
        // [--node-first] node gets the packet before any decode work.
        if node_first {
            forward(&buf[..n]);
        }
        // Taken after recv returns, so it is the moment the last byte of this packet was
        // available to us — not when we started waiting.
        let pkt_ns = mono_ns();
        // [Feed gaps] The blocking recv ended now; the wait itself was the silence.
        bucket_add(
            &RECV_GAP_BUCKETS,
            &RECV_GAP_BOUNDS_US,
            (pkt_ns.saturating_sub(t_prev_pkt)) / 1_000,
        );
        t_prev_pkt = pkt_ns;

        // Straight from the reusable buffer — no per-packet allocation.
        // [Slow-call forensics] Per-thread rusage around the call splits a slow call
        // three ways: ru_utime delta ≈ wall delta means the thread RAN (real work);
        // a minflt spike means it faulted (alloc/compaction grind); a majflt spike
        // means it read from disk; both ~zero means it never got CPU at all.
        // [2026-09-29] rusage only with --slow-forensics: two syscalls per packet on the
        // receive thread otherwise, for a dump that only fires on >50ms calls.
        let ru_before = if slow_forensics { Some(thread_rusage()) } else { None };
        let decoded = listener.handle_packet(&buf[..n]);
        let decode_us = (mono_ns().saturating_sub(pkt_ns)) / 1_000;
        record_decode(decode_us);
        // [Slow-call trap] handle_packet has no legitimate reason to take >50ms; when it
        // does, dump the packet head so the culprit (shred type, slot, FEC params) is on
        // record instead of hiding behind a p99.
        if decode_us > 50_000 {
            let head: String =
                buf[..n.min(96)].iter().map(|b| format!("{b:02x}")).collect();
            let (minflt, majflt, cpu_us) = match ru_before {
                Some(ru_before) => {
                    let ru_after = thread_rusage();
                    (
                        ru_after.ru_minflt.saturating_sub(ru_before.ru_minflt),
                        ru_after.ru_majflt.saturating_sub(ru_before.ru_majflt),
                        (ru_after.ru_utime.tv_sec.saturating_sub(ru_before.ru_utime.tv_sec)) * 1_000_000
                            + ru_after.ru_utime.tv_usec.saturating_sub(ru_before.ru_utime.tv_usec),
                    )
                }
                None => (-1, -1, -1),
            };
            let phases = shredstream::listener::slow_phases();
            eprintln!(
                "[slow-call] {decode_us}µs pkts_len={n} cpu={cpu_us}µs minflt={minflt} majflt={majflt} \
                 phases(ns): pool={} parse={} push={} advance={} fec={} flush={} head={head}",
                phases[0], phases[1], phases[2], phases[3], phases[4], phases[5],
            );
        }
        // [Feed gaps] Second view: how long between live-edge advances. Packets can keep
        // flowing (coding/duplicates) while no new slot arrives — that is a stall the
        // recv-gap view cannot see.
        let live = listener.last_slot();
        if live != prev_live_slot {
            bucket_add(
                &SLOT_STALL_BUCKETS,
                &SLOT_STALL_BOUNDS_US,
                (pkt_ns.saturating_sub(t_last_advance)) / 1_000,
            );
            t_last_advance = pkt_ns;
            prev_live_slot = live;
        }
        let Some((slot, txs)) = decoded else {
            if !node_first { forward(&buf[..n]); }
            continue;
        };
        EMIT_PKT_N.fetch_add(1, Relaxed);
        EMIT_PKT_US.fetch_add(decode_us, Relaxed);
        EMIT_PKT_MAX_US.fetch_max(decode_us, Relaxed);
        EMIT_TXW_US.fetch_add(decode_us * txs.len() as u64, Relaxed);
        EMIT_TXW_N.fetch_add(txs.len() as u64, Relaxed);
        for (acc, v) in EMIT_PH_NS.iter().zip(shredstream::listener::slow_phases()) {
            acc.fetch_add(v, Relaxed);
        }
        N_DECODED.fetch_add(txs.len() as u64, Relaxed);

        // [Stale gate] Drop deliveries from slots the feed has already moved past. Live
        // slots have age 0 (the slot being decoded IS the live edge), age 1-2 tolerates
        // last-slot stragglers; everything later is salvage/retransmit residue.
        let age = listener.last_slot().saturating_sub(slot);
        if age > STALE_MAX_SLOTS {
            N_STALE_BATCH.fetch_add(1, Relaxed);
            N_STALE_TX.fetch_add(txs.len() as u64, Relaxed);
            STALE_MAX_AGE.fetch_max(age, Relaxed);
            record_stale_age(age);
            if !node_first { forward(&buf[..n]); }
            continue;
        }

        N_BATCHES.fetch_add(1, Relaxed);
        record_emit(txs.len());

        // Frame the whole batch into one reused buffer, then one write.
        // [RAW-TX 2026-09-29] The payload is the transaction's ORIGINAL wire bytes as the
        // decoder cut them out of the entry — no decode, no re-serialisation (bincode also
        // wrote V1 in a non-wire format consumers cannot read).
        let t_ser = mono_ns();
        frame_buf.clear();
        let mut framed = 0u64;
        for raw in &txs {
            let bytes = raw.bytes();
            frame_buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            frame_buf.extend_from_slice(&slot.to_le_bytes());
            frame_buf.extend_from_slice(bytes);
            framed += 1;
        }
        let t_wr = mono_ns();
        SER_SUM_US.fetch_add((t_wr.saturating_sub(t_ser)) / 1_000, Relaxed);
        SER_MAX_US.fetch_max((t_wr.saturating_sub(t_ser)) / 1_000, Relaxed);
        SER_N.fetch_add(1, Relaxed);

        write_unix(&frame_buf);
        record_write((mono_ns().saturating_sub(t_wr)) / 1_000);
        if !node_first { forward(&buf[..n]); }

        // Every transaction in the batch became visible at the same instant, so they all
        // carry the same measurement.
        if framed > 0 {
            let e2e = (mono_ns().saturating_sub(pkt_ns)) / 1_000;
            for _ in 0..framed {
                record_e2e(e2e);
            }
        }

        // gRPC subscribers after the socket: tooling, and a task hop costs them nothing.
        // [RAW-TX] Full decode only when someone is subscribed — the socket path above
        // never needs a VersionedTransaction.
        if let Some(bcast) = bcast.as_ref().filter(|b| b.receiver_count() > 0) {
            for raw in &txs {
                let Some(tx) = raw.decode() else { continue };
                if bcast
                    .send(Arc::new(DecodedTx {
                        transaction: tx,
                        slot,
                    }))
                    .is_ok()
                {
                    N_SENT.fetch_add(1, Relaxed);
                }
            }
        }

        if N_BATCHES.load(Relaxed) % 100 == 0 {
            N_FEC.store(listener.fec_recoveries_total(), Relaxed);
            N_FORCE_TIMEOUT.store(listener.batches_force_finalized_timeout_total(), Relaxed);
            N_FORCE_CORRUPT.store(listener.batches_force_finalized_corrupted_total(), Relaxed);
            N_SKIPPED.store(listener.batches_skipped_total(), Relaxed);
            N_FALLBACK.store(listener.batches_decoded_fallback_total(), Relaxed);
            N_OOO_BATCH.store(listener.out_of_order_flushed_total(), Relaxed);
            N_OOO_TX.store(listener.out_of_order_txs_total(), Relaxed);
            N_OOO_DUP.store(listener.dup_suppressed_total(), Relaxed);
            N_DECODE_ERRORS.store(listener.decode_errors_total(), Relaxed);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
// gRPC — Yellowstone Subscribe endpoint
// ══════════════════════════════════════════════════════════════════════════

struct ShredsUdp {
    bcast: tokio::sync::broadcast::Sender<Arc<DecodedTx>>,
}

#[tonic::async_trait]
impl Geyser for ShredsUdp {
    type SubscribeStream = ReceiverStream<Result<SubscribeUpdate, Status>>;

    async fn subscribe(
        &self,
        _request: Request<Streaming<SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let mut rx = self.bcast.subscribe();
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(16_384);

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(dtx) => {
                        if out_tx.send(Ok(to_update(&dtx))).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        N_LAGGED.fetch_add(n, Relaxed);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(out_rx)))
    }

    type SubscribeDeshredStream = ReceiverStream<Result<SubscribeUpdateDeshred, Status>>;
    async fn subscribe_deshred(
        &self,
        _: Request<Streaming<SubscribeDeshredRequest>>,
    ) -> Result<Response<Self::SubscribeDeshredStream>, Status> {
        Err(Status::unimplemented("shreds-udp serves Subscribe only"))
    }
    async fn subscribe_replay_info(
        &self,
        _: Request<SubscribeReplayInfoRequest>,
    ) -> Result<Response<SubscribeReplayInfoResponse>, Status> {
        Err(Status::unimplemented("shreds-udp serves Subscribe only"))
    }
    async fn ping(&self, _: Request<PingRequest>) -> Result<Response<PongResponse>, Status> {
        Ok(Response::new(PongResponse { count: 1 }))
    }
    async fn get_latest_blockhash(
        &self,
        _: Request<GetLatestBlockhashRequest>,
    ) -> Result<Response<GetLatestBlockhashResponse>, Status> {
        Err(Status::unimplemented("shreds-udp serves Subscribe only"))
    }
    async fn get_block_height(
        &self,
        _: Request<GetBlockHeightRequest>,
    ) -> Result<Response<GetBlockHeightResponse>, Status> {
        Err(Status::unimplemented("shreds-udp serves Subscribe only"))
    }
    async fn get_slot(
        &self,
        _: Request<GetSlotRequest>,
    ) -> Result<Response<GetSlotResponse>, Status> {
        Err(Status::unimplemented("shreds-udp serves Subscribe only"))
    }
    async fn is_blockhash_valid(
        &self,
        _: Request<IsBlockhashValidRequest>,
    ) -> Result<Response<IsBlockhashValidResponse>, Status> {
        Err(Status::unimplemented("shreds-udp serves Subscribe only"))
    }
    async fn get_version(
        &self,
        _: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            version: r#"{"package":"shreds-udp"}"#.to_string(),
        }))
    }
}

/// Convert a `DecodedTx` into a Yellowstone `SubscribeUpdate`.
/// Decoder-independent: only reads `.transaction` and `.slot`.
fn to_update(d: &DecodedTx) -> SubscribeUpdate {
    let (header, account_keys, recent_blockhash, instructions, lookups, versioned) =
        match &d.transaction.message {
            VersionedMessage::Legacy(m) => (
                m.header,
                m.account_keys.clone(),
                m.recent_blockhash,
                m.instructions.clone(),
                Vec::new(),
                false,
            ),
            VersionedMessage::V0(m) => (
                m.header,
                m.account_keys.clone(),
                m.recent_blockhash,
                m.instructions.clone(),
                m.address_table_lookups.clone(),
                true,
            ),
            // [3.0.0 ALIGNMENT] V1: static account keys only — the type has no
            // address-table lookups (`address_table_lookups()` returns None); the
            // blockhash slot is carried by `lifetime_specifier`.
            VersionedMessage::V1(m) => (
                m.header,
                m.account_keys.clone(),
                m.lifetime_specifier,
                m.instructions.clone(),
                Vec::new(),
                true,
            ),
        };

    let signature = d
        .transaction
        .signatures
        .first()
        .map(|s| s.as_ref().to_vec())
        .unwrap_or_default();

    let proto_tx = ProtoTransaction {
        signatures: d
            .transaction
            .signatures
            .iter()
            .map(|s| s.as_ref().to_vec())
            .collect(),
        message: Some(ProtoMessage {
            header: Some(MessageHeader {
                num_required_signatures: header.num_required_signatures as u32,
                num_readonly_signed_accounts: header.num_readonly_signed_accounts as u32,
                num_readonly_unsigned_accounts: header.num_readonly_unsigned_accounts as u32,
            }),
            account_keys: account_keys.iter().map(|k| k.to_bytes().to_vec()).collect(),
            recent_blockhash: recent_blockhash.to_bytes().to_vec(),
            instructions: instructions
                .iter()
                .map(|ix| CompiledInstruction {
                    program_id_index: ix.program_id_index as u32,
                    accounts: ix.accounts.clone(),
                    data: ix.data.clone(),
                })
                .collect(),
            versioned,
            address_table_lookups: lookups
                .iter()
                .map(|l| MessageAddressTableLookup {
                    account_key: l.account_key.to_bytes().to_vec(),
                    writable_indexes: l.writable_indexes.clone(),
                    readonly_indexes: l.readonly_indexes.clone(),
                })
                .collect(),
        }),
    };

    SubscribeUpdate {
        filters: vec!["orbit".to_string()],
        update_oneof: Some(UpdateOneof::Transaction(SubscribeUpdateTransaction {
            transaction: Some(SubscribeUpdateTransactionInfo {
                signature,
                is_vote: false,
                transaction: Some(proto_tx),
                meta: None,
                index: 0,
            }),
            slot: d.slot,
        })),
        created_at: None,
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Unix socket — raw wire-bytes feed for the consumer
// ══════════════════════════════════════════════════════════════════════════

/// Frame layout, little-endian:
///
///   [u32 payload_len][u64 slot][payload_len bytes]
///
/// where payload is the transaction's ORIGINAL wire bytes (legacy / v0 / V1), cut out of
/// the entry by the decoder — never decoded or re-encoded here. A consumer can decode them
/// with any Solana transaction decoder, or forward these very bytes as-is.
fn serve_unix(path: String) -> Result<()> {
    // A stale socket file from a previous run makes bind() fail with EADDRINUSE even
    // though nothing is listening; removing it is the standard unix-socket dance.
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    println!("unix socket listening on {} — point your consumer at this path", path);

    // Accept on a plain thread rather than a tokio task: the accepted socket is handed to
    // the decode thread, which writes it with std::io, so tokio never touches this path.
    std::thread::Builder::new()
        .name("unix-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(sock) => {
                        // Non-blocking so a stalled reader can never block the decoder,
                        // plus a generous send buffer so it takes a real stall to overflow.
                        if let Err(e) = sock.set_nonblocking(true) {
                            eprintln!("unix set_nonblocking failed: {e}");
                            continue;
                        }
                        set_sndbuf(&sock, 8 * 1024 * 1024);
                        println!("unix client connected");
                        let client = UnixClient { sock, pending: Vec::new() };
                        match unix_clients().lock() {
                            Ok(mut g) => g.push(client),
                            Err(e) => e.into_inner().push(client),
                        }
                    }
                    Err(e) => {
                        eprintln!("unix accept failed: {e}");
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        })?;

    Ok(())
}

/// Best-effort: a small send buffer would turn a brief reader hiccup into dropped frames.
fn set_sndbuf(sock: &std::os::unix::net::UnixStream, bytes: usize) {
    use std::os::unix::io::AsRawFd;
    let val = bytes as libc::c_int;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
    }
}
