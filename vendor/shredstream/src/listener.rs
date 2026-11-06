use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use rustc_hash::{FxHashMap, FxHashSet};
use socket2::{Domain, Protocol, Socket, Type};

use crate::accumulator::{AccumulatorConfig, SlotAccumulator};
use crate::accumulator::{PHASE_ADVANCE_US, PHASE_FEC_US, PHASE_FLUSH_US};
use crate::fec::ReedSolomonCache;
use crate::parser::{self, ParseError, ShredKind};
use crate::pool::{BufferHandle, ShredPool};

const DEFAULT_RECV_BUF: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_AGE: u64 = 3;
const DEFAULT_POOL_SIZE: usize = 4096;
const MAX_PLAUSIBLE_SLOT: u64 = 1 << 40;
const MAX_SLOT_JUMP_FORWARD: u64 = 1_000_000;
const MAX_BOOTSTRAP_SLOT: u64 = 10_000_000_000;
const BLACKLIST_EXTRA_SLOTS: u64 = 50;
const COMPLETED_RETENTION_SLOTS: u64 = 1;

/// Hard bound on the data-shred index / fec-set index taken from the wire. A real slot
/// carries at most 32,768 data shreds (agave's cap); we allow up to u16::MAX for slack.
/// Anything above cannot be legitimate — a wild `batch_complete` index used to reach
/// eviction and drive `salvage_contiguous_runs_in` one-by-one across the whole range,
/// burning seconds of pure CPU (the recurring 4-6s pipeline freeze).
const MAX_SHRED_INDEX: u32 = u16::MAX as u32;

/// Cross-thread view of [`Self::unparseable_shred_index`] for the status printer, which
/// runs on a tokio task and cannot touch the listener behind the receive thread.
pub static UNPARSEABLE_SHRED_INDEX: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// [Slow-call forensics] Coarse phase timers for one `handle_packet` call, zeroed at
/// entry and read only when the caller's >50ms trap fires. `PUSH` covers the whole
/// accumulate-and-decode section (it includes ADVANCE/FEC/FLUSH).
pub static PHASE_POOL_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PHASE_PARSE_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PHASE_PUSH_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Snapshot of all six per-call phases, in µs:
/// (pool, parse, push_total, advance_streaming, fec_fill, flush_batches).
pub fn slow_phases() -> [u64; 6] {
    use std::sync::atomic::Ordering::Relaxed;
    [
        PHASE_POOL_US.load(Relaxed),
        PHASE_PARSE_US.load(Relaxed),
        PHASE_PUSH_US.load(Relaxed),
        PHASE_ADVANCE_US.load(Relaxed),
        PHASE_FEC_US.load(Relaxed),
        PHASE_FLUSH_US.load(Relaxed),
    ]
}

/// Adds its elapsed time to a phase counter when dropped — covers every early return
/// in `handle_packet_owned` without touching each one.
struct PhaseGuard(&'static std::sync::atomic::AtomicU64, Instant);
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.0
            .fetch_add(self.1.elapsed().as_nanos() as u64, Relaxed);
    }
}

#[derive(Clone, Debug)]
pub struct ListenerOptions {
    pub recv_buf: usize,
    pub max_age: u64,
    pub busy_poll_us: Option<u32>,
    pub pool_size: usize,
    pub enable_fec: bool,
    pub disable_salvage_delivery: bool,
    pub accumulator: AccumulatorConfig,
}

impl Default for ListenerOptions {
    fn default() -> Self {
        Self {
            recv_buf: DEFAULT_RECV_BUF,
            max_age: DEFAULT_MAX_AGE,
            busy_poll_us: Some(200),
            pool_size: DEFAULT_POOL_SIZE,
            enable_fec: true,
            disable_salvage_delivery: false,
            accumulator: AccumulatorConfig::default(),
        }
    }
}

pub struct ShredListener {
    socket: std::net::UdpSocket,
    slots: FxHashMap<u64, SlotAccumulator>,
    recently_seen_slots: FxHashSet<u64>,
    pending_batches: VecDeque<(u64, Vec<crate::decoder::RawTx>)>,
    max_age: u64,
    last_slot: u64,
    pool: Arc<ShredPool>,
    pool_exhausted: u64,
    rs_cache: ReedSolomonCache,
    enable_fec: bool,
    disable_salvage_delivery: bool,
    accumulator_cfg: AccumulatorConfig,
    data_shred_count: u64,
    code_shred_count: u64,
    bytes_received: u64,
    unparseable_too_short: u64,
    unparseable_variant: u64,
    unparseable_payload: u64,
    unparseable_slot_range: u64,
    /// Shreds whose data index / fec-set index exceeds any value a real slot can carry
    /// (32.768 data shreds/slot hard cap in agave; we allow up to u16::MAX). A wild
    /// index used to flow into `pending` and later drive `salvage_contiguous_runs_in`
    /// over a billions-wide range at eviction — seconds of pure CPU, the recurring
    /// 4-6s pipeline freeze.
    unparseable_shred_index: u64,
    dropped_known_slots: u64,
    decode_errors_total: u64,
    fec_recoveries_total: u64,
    fec_recovery_failures_total: u64,
    batches_skipped_total: u64,
    batches_decoded_streaming_total: u64,
    batches_decoded_fallback_total: u64,
    slots_completed_total: u64,
    slots_evicted_by_age: u64,
    harvested_batches_total: u64,
    salvaged_tail_tx_total: u64,
    out_of_order_flushed_total: u64,
    out_of_order_txs_total: u64,
    dup_suppressed_total: u64,
    fec_sets_discarded_unused_total: u64,
    fec_sets_evicted_early_total: u64,
    batches_force_finalized_corrupted_total: u64,
    batches_force_finalized_timeout_total: u64,
    last_io_error_kind: Option<io::ErrorKind>,
    busy_poll_active: bool,
}

impl ShredListener {
    pub fn bind(port: u16) -> io::Result<Self> {
        Self::bind_with_options(port, ListenerOptions::default())
    }

    pub fn bind_with_options(port: u16, opts: ListenerOptions) -> io::Result<Self> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        raw.set_reuse_address(true)?;
        raw.set_recv_buffer_size(opts.recv_buf)?;
        raw.set_nonblocking(false)?;
        raw.bind(&addr.into())?;

        let busy_poll_active = match opts.busy_poll_us {
            Some(us) => set_busy_poll(&raw, us).is_ok(),
            None => false,
        };

        let std_socket: std::net::UdpSocket = raw.into();
        let mut listener = Self::from_socket_inner(std_socket, opts)?;
        listener.busy_poll_active = busy_poll_active;
        Ok(listener)
    }

    pub fn from_socket(socket: std::net::UdpSocket, opts: ListenerOptions) -> io::Result<Self> {
        Self::from_socket_inner(socket, opts)
    }

    fn from_socket_inner(socket: std::net::UdpSocket, opts: ListenerOptions) -> io::Result<Self> {
        eprintln!(
            "\x1b[2m⚡ShredStream.com SDK v{} initiated\x1b[0m",
            env!("CARGO_PKG_VERSION")
        );
        let slots_cap = 32;
        let recently_seen_cap = 128;
        let pending_cap = 32;
        Ok(Self {
            socket,
            slots: FxHashMap::with_capacity_and_hasher(slots_cap, Default::default()),
            recently_seen_slots: FxHashSet::with_capacity_and_hasher(
                recently_seen_cap,
                Default::default(),
            ),
            pending_batches: VecDeque::with_capacity(pending_cap),
            max_age: opts.max_age,
            last_slot: 0,
            pool: ShredPool::new(opts.pool_size),
            pool_exhausted: 0,
            rs_cache: ReedSolomonCache::new(),
            enable_fec: opts.enable_fec,
            disable_salvage_delivery: opts.disable_salvage_delivery,
            accumulator_cfg: opts.accumulator,
            data_shred_count: 0,
            code_shred_count: 0,
            bytes_received: 0,
            unparseable_too_short: 0,
            unparseable_variant: 0,
            unparseable_payload: 0,
            unparseable_shred_index: 0,
            unparseable_slot_range: 0,
            dropped_known_slots: 0,
            decode_errors_total: 0,
            fec_recoveries_total: 0,
            fec_recovery_failures_total: 0,
            batches_skipped_total: 0,
            batches_decoded_streaming_total: 0,
            batches_decoded_fallback_total: 0,
            slots_completed_total: 0,
            slots_evicted_by_age: 0,
            harvested_batches_total: 0,
            salvaged_tail_tx_total: 0,
            out_of_order_flushed_total: 0,
            out_of_order_txs_total: 0,
            dup_suppressed_total: 0,
            fec_sets_discarded_unused_total: 0,
            fec_sets_evicted_early_total: 0,
            batches_force_finalized_corrupted_total: 0,
            batches_force_finalized_timeout_total: 0,
            last_io_error_kind: None,
            busy_poll_active: false,
        })
    }

    pub fn transactions(&mut self) -> TransactionIter<'_> {
        TransactionIter { listener: self }
    }

    pub fn shreds(&mut self) -> ShredIter<'_> {
        ShredIter {
            listener: self,
            buf: [0u8; 2048],
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Highest slot a shred has been seen for — the live edge of this feed. Callers
    /// gating delivery on freshness compare a batch's slot against this.
    pub fn last_slot(&self) -> u64 {
        self.last_slot
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn pool_exhausted_count(&self) -> u64 {
        self.pool_exhausted
    }

    pub fn last_io_error_kind(&self) -> Option<io::ErrorKind> {
        self.last_io_error_kind
    }

    pub fn busy_poll_active(&self) -> bool {
        self.busy_poll_active
    }

    pub fn data_shred_count_total(&self) -> u64 {
        self.data_shred_count
    }

    pub fn code_shred_count_total(&self) -> u64 {
        self.code_shred_count
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn unparseable_packets(&self) -> u64 {
        self.unparseable_too_short
            .wrapping_add(self.unparseable_variant)
            .wrapping_add(self.unparseable_payload)
            .wrapping_add(self.unparseable_slot_range)
    }

    pub fn unparseable_too_short(&self) -> u64 {
        self.unparseable_too_short
    }

    pub fn unparseable_variant(&self) -> u64 {
        self.unparseable_variant
    }

    pub fn unparseable_payload(&self) -> u64 {
        self.unparseable_payload
    }

    pub fn unparseable_slot_range(&self) -> u64 {
        self.unparseable_slot_range
    }

    pub fn unparseable_shred_index(&self) -> u64 {
        self.unparseable_shred_index
    }

    pub fn dropped_known_slots(&self) -> u64 {
        self.dropped_known_slots
    }

    pub fn harvested_batches_total(&self) -> u64 {
        self.harvested_batches_total
    }

    pub fn decode_errors_total(&self) -> u64 {
        self.decode_errors_total + self.sum_live(|a| a.decode_errors() as u64)
    }

    pub fn fec_recoveries_total(&self) -> u64 {
        self.fec_recoveries_total + self.sum_live(|a| a.recoveries_done())
    }

    pub fn fec_recovery_failures_total(&self) -> u64 {
        self.fec_recovery_failures_total + self.sum_live(|a| a.recovery_failures())
    }

    pub fn batches_skipped_total(&self) -> u64 {
        self.batches_skipped_total + self.sum_live(|a| a.batches_skipped())
    }

    pub fn batches_decoded_streaming_total(&self) -> u64 {
        self.batches_decoded_streaming_total
            + self.sum_live(|a| a.batches_decoded_streaming())
    }

    /// [ADDED] Out-of-order flush counters. `dup_suppressed_total` is the safety check:
    /// zero means the deduplication guarding this path never fired.
    pub fn out_of_order_flushed_total(&self) -> u64 {
        self.out_of_order_flushed_total + self.sum_live(|a| a.out_of_order_flushed())
    }
    pub fn out_of_order_txs_total(&self) -> u64 {
        self.out_of_order_txs_total + self.sum_live(|a| a.out_of_order_txs())
    }
    pub fn dup_suppressed_total(&self) -> u64 {
        self.dup_suppressed_total + self.sum_live(|a| a.dup_suppressed())
    }

    pub fn batches_decoded_fallback_total(&self) -> u64 {
        self.batches_decoded_fallback_total
            + self.sum_live(|a| a.batches_decoded_fallback())
    }

    pub fn slots_completed_total(&self) -> u64 {
        self.slots_completed_total
    }

    pub fn slots_evicted_by_age(&self) -> u64 {
        self.slots_evicted_by_age
    }

    pub fn salvaged_tail_tx_total(&self) -> u64 {
        self.salvaged_tail_tx_total + self.sum_live(|a| a.salvaged_tail_tx())
    }

    pub fn fec_sets_discarded_unused_total(&self) -> u64 {
        self.fec_sets_discarded_unused_total
            + self.sum_live(|a| a.fec_sets_discarded_unused())
    }

    pub fn fec_sets_evicted_early_total(&self) -> u64 {
        self.fec_sets_evicted_early_total
            + self.sum_live(|a| a.fec_sets_evicted_early())
    }

    pub fn batches_force_finalized_corrupted_total(&self) -> u64 {
        self.batches_force_finalized_corrupted_total
            + self.sum_live(|a| a.batches_force_finalized_corrupted())
    }

    pub fn batches_force_finalized_timeout_total(&self) -> u64 {
        self.batches_force_finalized_timeout_total
            + self.sum_live(|a| a.batches_force_finalized_timeout())
    }

    fn sum_live<F: Fn(&SlotAccumulator) -> u64>(&self, f: F) -> u64 {
        self.slots.values().map(f).sum()
    }

    fn rollup_accumulator(&mut self, acc: &SlotAccumulator) {
        self.decode_errors_total = self
            .decode_errors_total
            .wrapping_add(acc.decode_errors() as u64);
        self.fec_recoveries_total = self
            .fec_recoveries_total
            .wrapping_add(acc.recoveries_done());
        self.fec_recovery_failures_total = self
            .fec_recovery_failures_total
            .wrapping_add(acc.recovery_failures());
        self.batches_skipped_total = self
            .batches_skipped_total
            .wrapping_add(acc.batches_skipped());
        self.batches_decoded_streaming_total = self
            .batches_decoded_streaming_total
            .wrapping_add(acc.batches_decoded_streaming());
        self.batches_decoded_fallback_total = self
            .batches_decoded_fallback_total
            .wrapping_add(acc.batches_decoded_fallback());
        self.salvaged_tail_tx_total = self
            .salvaged_tail_tx_total
            .wrapping_add(acc.salvaged_tail_tx());
        self.out_of_order_flushed_total = self
            .out_of_order_flushed_total
            .wrapping_add(acc.out_of_order_flushed());
        self.out_of_order_txs_total = self
            .out_of_order_txs_total
            .wrapping_add(acc.out_of_order_txs());
        self.dup_suppressed_total = self
            .dup_suppressed_total
            .wrapping_add(acc.dup_suppressed());
        self.fec_sets_discarded_unused_total = self
            .fec_sets_discarded_unused_total
            .wrapping_add(acc.fec_sets_discarded_unused());
        self.fec_sets_evicted_early_total = self
            .fec_sets_evicted_early_total
            .wrapping_add(acc.fec_sets_evicted_early());
        self.batches_force_finalized_corrupted_total = self
            .batches_force_finalized_corrupted_total
            .wrapping_add(acc.batches_force_finalized_corrupted());
        self.batches_force_finalized_timeout_total = self
            .batches_force_finalized_timeout_total
            .wrapping_add(acc.batches_force_finalized_timeout());
    }

    pub fn handle_packet(&mut self, raw: &[u8]) -> Option<(u64, Vec<crate::decoder::RawTx>)> {
        use std::sync::atomic::Ordering::Relaxed;
        PHASE_POOL_US.store(0, Relaxed);
        PHASE_PARSE_US.store(0, Relaxed);
        PHASE_PUSH_US.store(0, Relaxed);
        PHASE_ADVANCE_US.store(0, Relaxed);
        PHASE_FEC_US.store(0, Relaxed);
        PHASE_FLUSH_US.store(0, Relaxed);
        let t_pool = Instant::now();
        let mut handle = match self.acquire_buffer_with_fallback() {
            Some(h) => h,
            None => {
                self.pool_exhausted = self.pool_exhausted.wrapping_add(1);
                return None;
            }
        };
        PHASE_POOL_US.fetch_add(t_pool.elapsed().as_nanos() as u64, Relaxed);
        let n = raw.len().min(handle.as_mut_slice().len());
        handle.as_mut_slice()[..n].copy_from_slice(&raw[..n]);
        handle.set_len(n);
        self.handle_packet_owned(handle)
    }

    fn handle_packet_owned(
        &mut self,
        handle: BufferHandle,
    ) -> Option<(u64, Vec<crate::decoder::RawTx>)> {
        use std::sync::atomic::Ordering::Relaxed;
        self.bytes_received = self.bytes_received.wrapping_add(handle.len() as u64);

        let t_parse = Instant::now();
        let kind = match parser::parse_kind(&handle) {
            Ok(k) => k,
            Err(e) => {
                match e {
                    ParseError::TooShort => {
                        self.unparseable_too_short =
                            self.unparseable_too_short.wrapping_add(1);
                    }
                    ParseError::UnknownVariant => {
                        self.unparseable_variant = self.unparseable_variant.wrapping_add(1);
                    }
                    ParseError::PayloadInvalid => {
                        self.unparseable_payload = self.unparseable_payload.wrapping_add(1);
                    }
                }
                return None;
            }
        };
        PHASE_PARSE_US.fetch_add(t_parse.elapsed().as_nanos() as u64, Relaxed);
        let _push_guard = PhaseGuard(&PHASE_PUSH_US, Instant::now());

        if let ShredKind::Data(d) = &kind {
            let slot = d.slot;
            let index = d.index;
            let fec_set_index = d.fec_set_index;
            let payload_end = (parser::DATA_HEADER_SIZE + d.payload.len()) as u16;
            let batch_complete = d.batch_complete;
            let last_in_slot = d.last_in_slot;
            drop(kind);

            if slot > MAX_PLAUSIBLE_SLOT
                || (self.last_slot == 0 && slot > MAX_BOOTSTRAP_SLOT)
                || (self.last_slot > 0
                    && slot > self.last_slot.saturating_add(MAX_SLOT_JUMP_FORWARD))
            {
                self.unparseable_slot_range = self.unparseable_slot_range.wrapping_add(1);
                return None;
            }
            if index > MAX_SHRED_INDEX || fec_set_index > MAX_SHRED_INDEX {
                self.unparseable_shred_index = self.unparseable_shred_index.wrapping_add(1);
                UNPARSEABLE_SHRED_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            if self.recently_seen_slots.contains(&slot) {
                self.dropped_known_slots = self.dropped_known_slots.wrapping_add(1);
                return None;
            }

            self.data_shred_count = self.data_shred_count.wrapping_add(1);
            if slot > self.last_slot {
                self.last_slot = slot;
                self.evict_old_slots();
            }
            debug_assert!(self.last_slot <= MAX_PLAUSIBLE_SLOT);

            let cfg = self.accumulator_cfg;
            let acc = self
                .slots
                .entry(slot)
                .or_insert_with(|| SlotAccumulator::with_config(cfg));
            let txs = acc.push_data(
                index,
                fec_set_index,
                handle,
                payload_end,
                batch_complete,
                last_in_slot,
                &mut self.rs_cache,
            );

            return if txs.is_empty() {
                None
            } else {
                Some((slot, txs))
            };
        }

        let ShredKind::Code(c) = kind else {
            return None;
        };

        let slot = c.slot;
        if slot > MAX_PLAUSIBLE_SLOT
            || (self.last_slot == 0 && slot > MAX_BOOTSTRAP_SLOT)
            || (self.last_slot > 0 && slot > self.last_slot.saturating_add(MAX_SLOT_JUMP_FORWARD))
        {
            self.unparseable_slot_range = self.unparseable_slot_range.wrapping_add(1);
            return None;
        }
        if c.fec_set_index > MAX_SHRED_INDEX {
            self.unparseable_shred_index = self.unparseable_shred_index.wrapping_add(1);
            UNPARSEABLE_SHRED_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        if self.recently_seen_slots.contains(&slot) {
            self.dropped_known_slots = self.dropped_known_slots.wrapping_add(1);
            return None;
        }

        self.code_shred_count = self.code_shred_count.wrapping_add(1);
        if !self.enable_fec {
            return None;
        }
        if slot > self.last_slot {
            self.last_slot = slot;
            self.evict_old_slots();
        }
        debug_assert!(self.last_slot <= MAX_PLAUSIBLE_SLOT);

        let cfg = self.accumulator_cfg;
        let acc = self
            .slots
            .entry(slot)
            .or_insert_with(|| SlotAccumulator::with_config(cfg));
        let txs = acc.push_code(
            c.fec_set_index,
            c.num_data_shreds,
            c.num_coding_shreds,
            c.position,
            c.coded,
            c.variant,
            &mut self.rs_cache,
        );

        if txs.is_empty() {
            None
        } else {
            Some((slot, txs))
        }
    }

    fn evict_old_slots(&mut self) {
        let last = self.last_slot;
        let max_age = self.max_age;
        let to_evict: Vec<u64> = self
            .slots
            .iter()
            .filter_map(|(&s, acc)| {
                let threshold = if acc.slot_complete {
                    COMPLETED_RETENTION_SLOTS
                } else {
                    max_age
                };
                if last > s.saturating_add(threshold) {
                    Some(s)
                } else {
                    None
                }
            })
            .collect();
        if !to_evict.is_empty() {
            for s in to_evict {
                if let Some(mut acc) = self.slots.remove(&s) {
                    let tail_txs = acc.try_harvest_tail(&mut self.rs_cache);
                    if !tail_txs.is_empty() {
                        self.harvested_batches_total =
                            self.harvested_batches_total.wrapping_add(1);
                        if !self.disable_salvage_delivery {
                            self.pending_batches.push_back((s, tail_txs));
                        }
                    }
                    if acc.slot_complete {
                        self.slots_completed_total =
                            self.slots_completed_total.wrapping_add(1);
                    } else {
                        self.slots_evicted_by_age =
                            self.slots_evicted_by_age.wrapping_add(1);
                    }
                    self.rollup_accumulator(&acc);
                    self.recently_seen_slots.insert(s);
                }
            }
        }

        let blacklist_floor = self
            .last_slot
            .saturating_sub(self.max_age + BLACKLIST_EXTRA_SLOTS);
        if !self.recently_seen_slots.is_empty() {
            self.recently_seen_slots.retain(|&s| s >= blacklist_floor);
        }
    }

    fn recv_one(&mut self) -> io::Result<Option<(u64, Vec<crate::decoder::RawTx>)>> {
        if let Some(batch) = self.pending_batches.pop_front() {
            return Ok(Some(batch));
        }
        let mut handle = match self.acquire_buffer_with_fallback() {
            Some(h) => h,
            None => {
                self.pool_exhausted = self.pool_exhausted.wrapping_add(1);
                let mut dummy = [0u8; 2048];
                let _ = self.socket.recv(&mut dummy)?;
                return Ok(None);
            }
        };
        let len = self.socket.recv(handle.as_mut_slice())?;
        handle.set_len(len);
        Ok(self.handle_packet_owned(handle))
    }

    fn acquire_buffer_with_fallback(&mut self) -> Option<BufferHandle> {
        if let Some(h) = self.pool.acquire() {
            return Some(h);
        }
        self.evict_old_slots();
        if let Some(h) = self.pool.acquire() {
            return Some(h);
        }
        self.force_evict_oldest_slot();
        self.pool.acquire()
    }

    fn force_evict_oldest_slot(&mut self) {
        let oldest = self.slots.keys().copied().min();
        if let Some(s) = oldest {
            if let Some(mut acc) = self.slots.remove(&s) {
                let tail_txs = acc.try_harvest_tail(&mut self.rs_cache);
                if !tail_txs.is_empty() {
                    self.harvested_batches_total =
                        self.harvested_batches_total.wrapping_add(1);
                    if !self.disable_salvage_delivery {
                        self.pending_batches.push_back((s, tail_txs));
                    }
                }
                if acc.slot_complete {
                    self.slots_completed_total =
                        self.slots_completed_total.wrapping_add(1);
                } else {
                    self.slots_evicted_by_age =
                        self.slots_evicted_by_age.wrapping_add(1);
                }
                self.rollup_accumulator(&acc);
                self.recently_seen_slots.insert(s);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn set_busy_poll(socket: &Socket, us: u32) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let val = us as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_busy_poll(_socket: &Socket, _us: u32) -> io::Result<()> {
    Ok(())
}

pub struct RawShred {
    pub slot: u64,
    pub index: u32,
    pub payload_len: usize,
}

pub struct TransactionIter<'a> {
    listener: &'a mut ShredListener,
}

impl TransactionIter<'_> {
    pub fn listener(&self) -> &ShredListener {
        self.listener
    }
}

impl Iterator for TransactionIter<'_> {
    type Item = (u64, Vec<crate::decoder::RawTx>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.listener.recv_one() {
                Ok(Some(batch)) => return Some(batch),
                Ok(None) => continue,
                Err(e) => {
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::TimedOut
                    ) {
                        continue;
                    }
                    self.listener.last_io_error_kind = Some(e.kind());
                    return None;
                }
            }
        }
    }
}

pub struct ShredIter<'a> {
    listener: &'a mut ShredListener,
    buf: [u8; 2048],
}

impl Iterator for ShredIter<'_> {
    type Item = RawShred;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let len = match self.listener.socket.recv(&mut self.buf) {
                Ok(n) => n,
                Err(e) => {
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::TimedOut
                    ) {
                        continue;
                    }
                    self.listener.last_io_error_kind = Some(e.kind());
                    return None;
                }
            };
            let raw = &self.buf[..len];
            if let Some(shred) = parser::parse_shred(raw) {
                return Some(RawShred {
                    slot: shred.slot,
                    index: shred.index,
                    payload_len: shred.payload.len(),
                });
            }
        }
    }
}

/// End-to-end FEC tests on REAL Agave Merkle shreds (solana-ledger's Shredder), fed
/// through `handle_packet` exactly as the UDP loop does.
#[cfg(test)]
mod fec_e2e_tests {
    use super::*;
    use solana_entry::entry::Entry;
    use solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shred, Shredder};
    use solana_transaction::versioned::VersionedTransaction;

    const SLOT: u64 = 400_000_000;

    fn tx(n: u32) -> VersionedTransaction {
        let mut sig = [0u8; 64];
        sig[..4].copy_from_slice(&n.to_le_bytes());
        sig[63] = 0xAB;
        VersionedTransaction {
            signatures: vec![solana_signature::Signature::from(sig)],
            message: solana_message::VersionedMessage::Legacy(solana_message::legacy::Message::default()),
        }
    }

    fn id(raw: &crate::decoder::RawTx) -> u32 {
        let s = raw.first_signature().unwrap();
        u32::from_le_bytes(s[..4].try_into().unwrap())
    }

    /// `n` one-tx entries serialised as ONE entry batch, shredded into Merkle data +
    /// coding shreds.
    fn shreds(n: u32, last_in_slot: bool) -> (Vec<Shred>, Vec<Shred>) {
        let entries: Vec<Entry> = (0..n)
            .map(|i| Entry { num_hashes: 1, hash: Default::default(), transactions: vec![tx(i)] })
            .collect();
        Shredder::new(SLOT, SLOT - 1, 0, 0)
            .unwrap()
            .entries_to_merkle_shreds_for_tests(
                &solana_keypair::Keypair::new(),
                &entries,
                last_in_slot,
                Default::default(),
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
    }

    fn listener() -> ShredListener {
        let opts = ListenerOptions {
            disable_salvage_delivery: true,
            ..ListenerOptions::default()
        };
        ShredListener::from_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), opts).unwrap()
    }

    fn feed(l: &mut ShredListener, s: &Shred, out: &mut Vec<u32>) {
        if let Some((_, txs)) = l.handle_packet(s.payload()) {
            out.extend(txs.iter().map(id));
        }
    }

    /// The slot's LAST data shred is lost and rebuilt by FEC. It closes the final batch,
    /// so dropping it (as the recovery path used to) stalled that batch until the stuck
    /// timeout and lost the transactions it carried.
    #[test]
    fn recovered_last_in_slot_shred_completes_the_final_batch() {
        // Sizes chosen so the batch's last bytes land in the slot's last shred for at
        // least some of them (Agave spreads the payload over the padded FEC set).
        let mut failures = Vec::new();
        for n in [5u32, 40, 90, 150, 230, 300, 420, 555] {
            let (data, code) = shreds(n, true);
            let last = data.iter().max_by_key(|s| s.index()).unwrap();
            assert!(last.last_in_slot());
            let mut l = listener();
            let mut out = Vec::new();
            for s in data.iter().filter(|s| s.index() != last.index()) {
                feed(&mut l, s, &mut out);
            }
            for s in code.iter().filter(|s| s.fec_set_index() == last.fec_set_index()) {
                feed(&mut l, s, &mut out);
            }
            out.sort_unstable();
            out.dedup();
            if out != (0..n).collect::<Vec<_>>() {
                failures.push((n, out.len()));
            }
        }
        assert!(failures.is_empty(), "final batch incomplete after FEC (n, got): {failures:?}");
    }

    /// A shred rebuilt by FEC must not stop the incremental decoder: the transactions
    /// after it in the same batch go out as soon as their bytes are present, not when the
    /// batch's later FEC sets finally arrive.
    #[test]
    fn streaming_continues_through_recovered_shred() {
        let (data, code) = shreds(600, false);
        let sets: std::collections::BTreeSet<u32> = data.iter().map(|s| s.fec_set_index()).collect();
        assert!(sets.len() >= 2, "need a batch spanning several FEC sets, got {sets:?}");
        let first = *sets.iter().next().unwrap();
        let lost = first + 5;

        let mut l = listener();
        let mut out = Vec::new();
        for s in data.iter().filter(|s| s.fec_set_index() == first && s.index() != lost) {
            feed(&mut l, s, &mut out);
        }
        let before_fec = out.len();
        for s in code.iter().filter(|s| s.fec_set_index() == first) {
            feed(&mut l, s, &mut out);
        }
        let after_fec = out.len();
        assert!(
            after_fec > before_fec,
            "nothing emitted after FEC rebuilt shred {lost} ({before_fec} before)"
        );
        // Everything whose bytes lie in the first set is out; the batch is not complete.
        for s in data.iter().filter(|s| s.fec_set_index() != first) {
            feed(&mut l, s, &mut out);
        }
        let mut all = out.clone();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), out.len(), "a transaction was delivered twice");
        assert_eq!(all, (0..600).collect::<Vec<_>>());
    }
}

#[cfg(test)]
mod fec_waste_tests {
    use super::fec_e2e_tests_support::*;

    fn calls(l: &super::ShredListener) -> u64 {
        l.slots.values().map(|a| a.reconstruct_calls).sum()
    }

    /// Every data shred arrived, then the set's coding shreds: nothing is missing, so
    /// Reed-Solomon must not run — it used to run again on every coding shred.
    #[test]
    fn complete_set_never_reconstructs() {
        let (data, code) = shreds_at(SLOT_BASE, 600, false);
        let first = data.iter().map(|s| s.fec_set_index()).min().unwrap();
        let mut l = listener();
        for s in data.iter().filter(|s| s.fec_set_index() == first) {
            let _ = l.handle_packet(s.payload());
        }
        for s in code.iter().filter(|s| s.fec_set_index() == first) {
            let _ = l.handle_packet(s.payload());
        }
        assert_eq!(calls(&l), 0, "reconstructed a set with no data missing");
    }

    /// One data shred lost: exactly one reconstruction, however many further coding
    /// shreds of that set arrive afterwards.
    #[test]
    fn one_gap_reconstructs_once() {
        let (data, code) = shreds_at(SLOT_BASE, 600, false);
        let first = data.iter().map(|s| s.fec_set_index()).min().unwrap();
        let mut l = listener();
        for s in data.iter().filter(|s| s.fec_set_index() == first && s.index() != first + 7) {
            let _ = l.handle_packet(s.payload());
        }
        for s in code.iter().filter(|s| s.fec_set_index() == first) {
            let _ = l.handle_packet(s.payload());
        }
        // later sets too, so the flush path's FEC hints run
        for s in data.iter().filter(|s| s.fec_set_index() != first) {
            let _ = l.handle_packet(s.payload());
        }
        assert_eq!(calls(&l), 1);
    }
}

#[cfg(test)]
pub(crate) mod fec_e2e_tests_support {
    use super::*;
    use solana_entry::entry::Entry;
    use solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shred, Shredder};
    use solana_transaction::versioned::VersionedTransaction;

    pub const SLOT_BASE: u64 = 400_000_000;

    fn tx(n: u32) -> VersionedTransaction {
        let mut sig = [0u8; 64];
        sig[..4].copy_from_slice(&n.to_le_bytes());
        VersionedTransaction {
            signatures: vec![solana_signature::Signature::from(sig)],
            message: solana_message::VersionedMessage::Legacy(solana_message::legacy::Message::default()),
        }
    }

    pub fn shreds_at(slot: u64, n: u32, last_in_slot: bool) -> (Vec<Shred>, Vec<Shred>) {
        let entries: Vec<Entry> = (0..n)
            .map(|i| Entry { num_hashes: 1, hash: Default::default(), transactions: vec![tx(i)] })
            .collect();
        Shredder::new(slot, slot - 1, 0, 0).unwrap().entries_to_merkle_shreds_for_tests(
            &solana_keypair::Keypair::new(), &entries, last_in_slot, Default::default(), 0, 0,
            &ReedSolomonCache::default(), &mut ProcessShredsStats::default(),
        )
    }

    pub fn listener() -> ShredListener {
        let opts = ListenerOptions { disable_salvage_delivery: true, ..ListenerOptions::default() };
        ShredListener::from_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), opts).unwrap()
    }
}

#[cfg(test)]
mod fec_bench {
    use super::fec_e2e_tests_support::*;

    /// Not a correctness test: prints what one recovery costs on real shreds.
    /// cargo test --release --lib fec_bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn fec_recovery_cost() {
        for missing in [1usize, 2, 4, 8] {
            let mut samples = Vec::new();
            let mut l = listener(); // persistent, like production (warm RS cache)
            for round in 0..200u32 {
                let (data, code) = shreds_at(SLOT_BASE + round as u64, 600, false);
                let first = data.iter().map(|s| s.fec_set_index()).min().unwrap();
                let lost: Vec<u32> = (0..missing as u32).map(|k| first + 3 + ((round + k * 7) % 29)).collect();
                for s in data.iter().filter(|s| s.fec_set_index() == first && !lost.contains(&s.index())) {
                    let _ = l.handle_packet(s.payload());
                }
                // the code shred that makes the set recoverable
                let mut t = None;
                for s in code.iter().filter(|s| s.fec_set_index() == first) {
                    let t0 = std::time::Instant::now();
                    let r = l.handle_packet(s.payload());
                    let dt = t0.elapsed();
                    if r.is_some() {
                        t = Some((dt, crate::listener::slow_phases()));
                        break;
                    }
                }
                if let Some(x) = t {
                    samples.push(x);
                }
            }
            samples.sort_by_key(|x| x.0);
            let med = samples[samples.len() / 2];
            // raw reed-solomon-erasure on the same geometry, same RS instance throughout
            let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(32, 32).unwrap();
            let mut raw_t = Vec::new();
            for round in 0..200usize {
                let mut shards: Vec<Vec<u8>> = (0..64).map(|i| vec![(i * 7 + round) as u8; 1051]).collect();
                rs.encode(&mut shards).unwrap();
                let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
                for k in 0..missing { opt[(round + k * 7) % 32] = None; }
                // drop coding shards so exactly 32 remain
                let mut extra = 32 - missing;
                for i in 32..64 { if extra == 0 { opt[i] = None; } else { extra -= 1; } }
                let t0 = std::time::Instant::now();
                rs.reconstruct_data(&mut opt).unwrap();
                raw_t.push(t0.elapsed());
            }
            raw_t.sort();
            eprintln!("missing={missing}: raw reconstruct_data median={:?} p90={:?}", raw_t[100], raw_t[180]);
            eprintln!(
                "missing={missing}: n={} median handle_packet={:?} phases(ns) fec={} advance={} flush={}",
                samples.len(), med.0, med.1[4], med.1[3], med.1[5]
            );
        }
    }
}
