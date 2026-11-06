use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rustc_hash::FxHashSet;
#[cfg(test)]
use solana_transaction::versioned::VersionedTransaction;

use crate::decoder::{decode_batch, decode_concatenated, RawTx, StreamingDecoder};
use crate::fec::{FecSetBuffer, ReedSolomonCache};
use crate::parser::{self, DATA_HEADER_SIZE};
use crate::pool::BufferHandle;
use crate::variant::VariantKind;

const DEFAULT_MAX_FEC_SETS_PER_SLOT: usize = 32;
const DEFAULT_STUCK_BATCH_TIMEOUT: Duration = Duration::from_millis(50);

/// [Slow-call forensics] Per-call phase timers, zeroed by the listener at the start of
/// each `handle_packet` and summed by the call sites below. Only read when a call trips
/// the >50ms trap, so the cost is a handful of atomic adds per packet.
pub static PHASE_ADVANCE_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PHASE_FEC_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PHASE_FLUSH_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub struct AccumulatorConfig {
    pub max_fec_sets_per_slot: usize,
    pub stuck_batch_timeout: Duration,
}

impl Default for AccumulatorConfig {
    fn default() -> Self {
        Self {
            max_fec_sets_per_slot: DEFAULT_MAX_FEC_SETS_PER_SLOT,
            stuck_batch_timeout: DEFAULT_STUCK_BATCH_TIMEOUT,
        }
    }
}

enum PayloadSource {
    Pool(BufferHandle),
    Recovered(Vec<u8>),
}

impl PayloadSource {
    fn slice(&self) -> &[u8] {
        match self {
            Self::Pool(h) => &h[..],
            Self::Recovered(v) => v,
        }
    }
}

struct PendingShred {
    source: PayloadSource,
    payload_end: u16,
    batch_complete: bool,
    fec_set_index: u32,
}

impl PendingShred {
    fn payload(&self) -> Option<&[u8]> {
        let buf = self.source.slice();
        let end = self.payload_end as usize;
        if end < DATA_HEADER_SIZE || end > buf.len() {
            return None;
        }
        Some(&buf[DATA_HEADER_SIZE..end])
    }
}

pub struct SlotAccumulator {
    cfg: AccumulatorConfig,
    pending: BTreeMap<u32, PendingShred>,
    fec_sets: BTreeMap<u32, FecSetBuffer>,

    batch_complete_indices: BTreeMap<u32, Instant>,

    streaming_cursor: u32,
    streaming_decoder: StreamingDecoder,
    /// Signatures already emitted for this slot. [MODIFIED FROM UPSTREAM] Upstream
    /// cleared this on every `complete_batch`, which is safe only while batches are
    /// emitted strictly in order. Out-of-order flushing can deliver a batch before the
    /// one ahead of it, and the same transaction may then also arrive through the
    /// in-order path after FEC fills the gap — so the set has to live as long as the
    /// slot. Bounded by transactions per slot, a few thousand entries.
    yielded_sigs: FxHashSet<[u8; 64]>,
    /// `batch_complete` indices already emitted ahead of `batch_start`.
    flushed_batches: FxHashSet<u32>,
    /// [2026-09-29] FEC sets with nothing left to recover (every data position present
    /// or behind `batch_start`, or already reconstructed). Their late coding shreds are
    /// ignored — before, each one re-created the set and re-ran Reed-Solomon on a set
    /// with nothing missing: 32 reconstructions per set measured, ~9x the useful ones.
    fec_done: FxHashSet<u32>,

    batch_start: u32,

    pub slot_complete: bool,

    decode_errors: u32,
    recoveries_done: u64,
    recovery_failures: u64,
    batches_decoded_streaming: u64,
    batches_decoded_fallback: u64,
    batches_skipped: u64,
    fec_sets_discarded_unused: u64,
    fec_sets_evicted_early: u64,
    salvaged_tail_tx: u64,
    out_of_order_flushed: u64,
    out_of_order_txs: u64,
    dup_suppressed: u64,
    batches_force_finalized_corrupted: u64,
    batches_force_finalized_timeout: u64,
    combined_scratch: Vec<u8>,
    /// Reed-Solomon reconstructions actually run (tests / diagnostics).
    pub(crate) reconstruct_calls: u64,
}

impl SlotAccumulator {
    pub fn with_config(cfg: AccumulatorConfig) -> Self {
        Self {
            cfg,
            pending: BTreeMap::new(),
            fec_sets: BTreeMap::new(),
            batch_complete_indices: BTreeMap::new(),
            streaming_cursor: 0,
            streaming_decoder: StreamingDecoder::new(),
            yielded_sigs: FxHashSet::with_capacity_and_hasher(4096, Default::default()),
            flushed_batches: FxHashSet::with_capacity_and_hasher(16, Default::default()),
            fec_done: FxHashSet::with_capacity_and_hasher(64, Default::default()),
            batch_start: 0,
            slot_complete: false,
            reconstruct_calls: 0,
            decode_errors: 0,
            recoveries_done: 0,
            recovery_failures: 0,
            batches_decoded_streaming: 0,
            batches_decoded_fallback: 0,
            batches_skipped: 0,
            fec_sets_discarded_unused: 0,
            fec_sets_evicted_early: 0,
            salvaged_tail_tx: 0,
            out_of_order_flushed: 0,
            out_of_order_txs: 0,
            dup_suppressed: 0,
            batches_force_finalized_corrupted: 0,
            batches_force_finalized_timeout: 0,
            combined_scratch: Vec::with_capacity(24 * 1024),
        }
    }

    pub fn new() -> Self {
        Self::with_config(AccumulatorConfig::default())
    }

    pub fn decode_errors(&self) -> u32 {
        self.decode_errors
    }
    pub fn recoveries_done(&self) -> u64 {
        self.recoveries_done
    }
    pub fn recovery_failures(&self) -> u64 {
        self.recovery_failures
    }
    pub fn batches_decoded_streaming(&self) -> u64 {
        self.batches_decoded_streaming
    }
    pub fn batches_decoded_fallback(&self) -> u64 {
        self.batches_decoded_fallback
    }
    pub fn batches_skipped(&self) -> u64 {
        self.batches_skipped
    }
    pub fn fec_sets_discarded_unused(&self) -> u64 {
        self.fec_sets_discarded_unused
    }
    pub fn fec_sets_evicted_early(&self) -> u64 {
        self.fec_sets_evicted_early
    }
    pub fn salvaged_tail_tx(&self) -> u64 {
        self.salvaged_tail_tx
    }
    pub fn out_of_order_flushed(&self) -> u64 {
        self.out_of_order_flushed
    }
    pub fn out_of_order_txs(&self) -> u64 {
        self.out_of_order_txs
    }
    /// Transactions blocked by `yielded_sigs` on a second delivery. Zero means the dedup
    /// is never exercised — the out-of-order path is then unproven, not proven safe.
    pub fn dup_suppressed(&self) -> u64 {
        self.dup_suppressed
    }
    pub fn batches_force_finalized_corrupted(&self) -> u64 {
        self.batches_force_finalized_corrupted
    }
    pub fn batches_force_finalized_timeout(&self) -> u64 {
        self.batches_force_finalized_timeout
    }

    pub fn push_data(
        &mut self,
        index: u32,
        fec_set_index: u32,
        handle: BufferHandle,
        payload_end: u16,
        batch_complete: bool,
        last_in_slot: bool,
        rs_cache: &mut ReedSolomonCache,
    ) -> Vec<RawTx> {
        use std::collections::btree_map::Entry as BTreeEntry;
        if last_in_slot {
            self.slot_complete = true;
            let mut out = Vec::new();
            // [FIXED vs UPSTREAM 2.0.0] Upstream returned here without storing the shred,
            // dropping `handle` on the floor. LAST_SHRED_IN_SLOT implies DATA_COMPLETE, so
            // this shred CLOSES the final entry batch and carries its last bytes — losing
            // it means that batch can never complete, and its transactions only ever
            // surface through `try_harvest_tail` at slot eviction. With salvage delivery
            // disabled they are lost outright: the tail of every single slot.
            if index >= self.batch_start {
                if let BTreeEntry::Vacant(slot) = self.pending.entry(index) {
                    slot.insert(PendingShred {
                        source: PayloadSource::Pool(handle),
                        payload_end,
                        batch_complete,
                        fec_set_index,
                    });
                    if batch_complete {
                        self.batch_complete_indices
                            .entry(index)
                            .or_insert_with(Instant::now);
                    }
                    let t = Instant::now();
                    self.advance_streaming(&mut out);
                    PHASE_ADVANCE_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
                }
            }
            let t = Instant::now();
            self.try_flush_batches(rs_cache, &mut out);
            PHASE_FLUSH_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            return out;
        }
        if index < self.batch_start {
            return Vec::new();
        }
        match self.pending.entry(index) {
            BTreeEntry::Occupied(_) => return Vec::new(),
            BTreeEntry::Vacant(slot) => {
                slot.insert(PendingShred {
                    source: PayloadSource::Pool(handle),
                    payload_end,
                    batch_complete,
                    fec_set_index,
                });
            }
        }
        if batch_complete {
            self.batch_complete_indices
                .entry(index)
                .or_insert_with(Instant::now);
        }

        let mut out = Vec::new();
        let t = Instant::now();
        self.advance_streaming(&mut out);
        PHASE_ADVANCE_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);

        if self.streaming_cursor <= index {
            let t = Instant::now();
            let filled = self.try_fec_fill(fec_set_index, rs_cache);
            PHASE_FEC_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            if filled {
                let t = Instant::now();
                self.advance_streaming(&mut out);
                PHASE_ADVANCE_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let t = Instant::now();
        self.try_flush_batches(rs_cache, &mut out);
        PHASE_FLUSH_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);

        out
    }

    pub fn push_code(
        &mut self,
        fec_set_index: u32,
        num_data: u16,
        num_coding: u16,
        position: u16,
        coded: &[u8],
        variant: VariantKind,
        rs_cache: &mut ReedSolomonCache,
    ) -> Vec<RawTx> {
        if self.fec_done.contains(&fec_set_index) {
            let mut out = Vec::new();
            let t = Instant::now();
            self.try_flush_batches(rs_cache, &mut out);
            PHASE_FLUSH_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            return out;
        }
        if self.fec_sets.len() >= self.cfg.max_fec_sets_per_slot
            && !self.fec_sets.contains_key(&fec_set_index)
        {
            if let Some((&oldest, _)) = self.fec_sets.iter().next() {
                if oldest < fec_set_index {
                    self.fec_sets.remove(&oldest);
                    self.fec_sets_evicted_early =
                        self.fec_sets_evicted_early.saturating_add(1);
                }
            }
        }
        let entry = self
            .fec_sets
            .entry(fec_set_index)
            .or_insert_with(|| FecSetBuffer::new(fec_set_index));
        entry.record_code(position, num_data, num_coding, coded, variant);

        let mut out = Vec::new();
        let t = Instant::now();
        let filled = self.try_fec_fill(fec_set_index, rs_cache);
        PHASE_FEC_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        if filled {
            let t = Instant::now();
            self.advance_streaming(&mut out);
            PHASE_ADVANCE_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        let t = Instant::now();
        self.try_flush_batches(rs_cache, &mut out);
        PHASE_FLUSH_US.fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        out
    }

    fn advance_streaming(&mut self, out: &mut Vec<RawTx>) {
        debug_assert!(
            self.streaming_cursor >= self.batch_start,
            "streaming cursor cannot rewind behind batch_start"
        );
        loop {
            let Some(ps) = self.pending.get(&self.streaming_cursor) else {
                break;
            };
            // [2026-09-29] Upstream stopped here at the first FEC-recovered shred and left
            // the rest of the batch to the whole-batch fallback once every later shred had
            // arrived — the transactions after the rebuilt shred waited for the batch's
            // later FEC sets for no reason. A recovered payload is the same bytes the
            // fallback decodes (`payload()` is identical for both sources), so stream it.
            let batch_complete_flag = ps.batch_complete;
            let payload = match ps.payload() {
                Some(p) => p,
                None => {
                    let dropped_idx = self.streaming_cursor;
                    self.pending.remove(&dropped_idx);
                    if batch_complete_flag {
                        self.batch_complete_indices.remove(&dropped_idx);
                    }
                    self.streaming_cursor = self.streaming_cursor.saturating_add(1);
                    self.decode_errors = self.decode_errors.saturating_add(1);

                    if batch_complete_flag && dropped_idx > self.batch_start {
                        let salvaged = self.salvage_contiguous_runs_in(
                            self.batch_start,
                            dropped_idx.saturating_sub(1),
                            out,
                        );
                        if salvaged > 0 {
                            self.batches_decoded_fallback =
                                self.batches_decoded_fallback.saturating_add(1);
                        } else {
                            self.batches_skipped =
                                self.batches_skipped.saturating_add(1);
                        }
                        self.batches_force_finalized_corrupted =
                            self.batches_force_finalized_corrupted.saturating_add(1);
                        self.complete_batch(dropped_idx);
                    }
                    continue;
                }
            };
            let push_result = self.streaming_decoder.push(payload);
            self.streaming_cursor = self.streaming_cursor.saturating_add(1);
            match push_result {
                Ok(txs) => {
                    for tx in txs {
                        if self.record_sig(&tx) {
                            out.push(tx);
                        }
                    }
                }
                Err(_) => {
                    self.decode_errors = self.decode_errors.saturating_add(1);
                    self.streaming_decoder.reset();
                    return;
                }
            }
            let batch_complete = batch_complete_flag;
            if batch_complete {
                return;
            }
        }
    }

    fn try_fec_fill(&mut self, hint: u32, rs_cache: &mut ReedSolomonCache) -> bool {
        let target = self.select_recoverable_set(hint);
        let set_idx = match target {
            Some(i) => i,
            None => return false,
        };

        let recovered = {
            let fec = match self.fec_sets.get(&set_idx) {
                Some(f) => f,
                None => return false,
            };
            let nd = fec.num_data as usize;
            if nd == 0 {
                return false;
            }
            // Nothing to gain unless a data position at/after batch_start is missing.
            let start = self.batch_start;
            let missing = (set_idx..set_idx + nd as u32)
                .filter(|i| *i >= start && !self.pending.contains_key(i))
                .count();
            if missing == 0 {
                self.fec_sets.remove(&set_idx);
                self.fec_done.insert(set_idx);
                return false;
            }
            self.reconstruct_calls += 1;
            let data_refs: Vec<(u16, &[u8])> = self
                .pending
                .iter()
                .filter(|(&idx, ps)| {
                    idx >= set_idx
                        && (idx - set_idx) < nd as u32
                        && ps.fec_set_index == set_idx
                })
                .map(|(&idx, ps)| ((idx - set_idx) as u16, ps.source.slice()))
                .collect();
            match fec.try_reconstruct(&data_refs, rs_cache) {
                Ok(v) => v,
                Err(_) => {
                    self.recovery_failures = self.recovery_failures.saturating_add(1);
                    return false;
                }
            }
        };

        if recovered.is_empty() {
            return false;
        }
        // One reconstruction yields every data shard of the set; whatever it did not
        // insert is already present, so the set is finished either way.
        self.fec_sets.remove(&set_idx);
        self.fec_done.insert(set_idx);

        let mut any = false;
        for (position_in_set, bytes) in recovered {
            let global_index = set_idx + position_in_set as u32;
            if global_index < self.batch_start || self.pending.contains_key(&global_index) {
                continue;
            }
            let (payload_end, batch_complete, last_in_slot) = match parser::parse_kind(&bytes) {
                Ok(parser::ShredKind::Data(d)) => (
                    (DATA_HEADER_SIZE + d.payload.len()) as u16,
                    d.batch_complete,
                    d.last_in_slot,
                ),
                _ => continue,
            };
            // [2026-09-29] Kept, like `push_data` does for a received one. Upstream
            // marked the slot complete and dropped the shred — but it CLOSES the slot's
            // final batch and carries its last bytes, so that batch could never complete:
            // it sat until the stuck timeout and the transactions in this shred were lost.
            if last_in_slot {
                self.slot_complete = true;
            }
            self.pending.insert(
                global_index,
                PendingShred {
                    source: PayloadSource::Recovered(bytes),
                    payload_end,
                    batch_complete,
                    fec_set_index: set_idx,
                },
            );
            if batch_complete {
                self.batch_complete_indices
                    .entry(global_index)
                    .or_insert_with(Instant::now);
            }
            any = true;
        }

        if any {
            self.recoveries_done = self.recoveries_done.saturating_add(1);
        }
        any
    }

    fn select_recoverable_set(&self, hint: u32) -> Option<u32> {
        let cursor = self.streaming_cursor;
        let data_count_for = |set_idx: u32, fec: &FecSetBuffer| -> usize {
            let nd = fec.num_data as u32;
            if nd == 0 {
                return 0;
            }
            self.pending
                .range(set_idx..set_idx.saturating_add(nd))
                .filter(|(_, ps)| ps.fec_set_index == set_idx)
                .count()
        };
        if let Some(fec) = self.fec_sets.get(&hint) {
            if fec.can_recover_with(data_count_for(hint, fec)) {
                return Some(hint);
            }
        }
        for (&set_idx, fec) in self.fec_sets.iter() {
            let nd = fec.num_data as u32;
            if nd == 0 {
                continue;
            }
            if set_idx <= cursor
                && cursor < set_idx + nd
                && fec.can_recover_with(data_count_for(set_idx, fec))
            {
                return Some(set_idx);
            }
        }
        None
    }

    fn try_flush_batches(
        &mut self,
        rs_cache: &mut ReedSolomonCache,
        out: &mut Vec<RawTx>,
    ) {
        loop {
            let (bc_idx, first_seen) = match self
                .batch_complete_indices
                .range(self.batch_start..)
                .next()
            {
                Some((&k, &t)) => (k, t),
                None => return,
            };
            let start = self.batch_start;

            let expected = (bc_idx - start + 1) as usize;
            let mut present = self.pending.range(start..=bc_idx).count();
            if present < expected {
                let hints: Vec<u32> = self
                    .fec_sets
                    .iter()
                    .filter(|(&f, fec)| {
                        let nd = fec.num_data as u32;
                        nd != 0 && f + nd > start && f <= bc_idx
                    })
                    .map(|(&f, _)| f)
                    .collect();
                for h in hints {
                    self.try_fec_fill(h, rs_cache);
                }
                present = self.pending.range(start..=bc_idx).count();
            }

            if present < expected {
                // Stalled: everything behind this batch is still deliverable.
                self.try_flush_out_of_order(out);
                if first_seen.elapsed() >= self.cfg.stuck_batch_timeout {
                    let salvaged =
                        self.salvage_contiguous_runs_in(start, bc_idx, out);
                    if salvaged > 0 {
                        self.batches_decoded_fallback =
                            self.batches_decoded_fallback.saturating_add(1);
                    } else {
                        self.batches_skipped =
                            self.batches_skipped.saturating_add(1);
                    }
                    self.batches_force_finalized_timeout =
                        self.batches_force_finalized_timeout.saturating_add(1);
                    self.complete_batch(bc_idx);
                    continue;
                }
                return;
            }

            // Already delivered ahead of the cursor: advance past it without decoding
            // again. `record_sig` would suppress the duplicates anyway, but re-running
            // `decode_batch` on a batch we have already emitted is pure waste.
            if self.flushed_batches.contains(&bc_idx) {
                self.complete_batch(bc_idx);
                continue;
            }

            // [ADDED] The streaming decoder has already walked past this batch's last
            // shred, so it emitted every transaction in it. Upstream still ran
            // `decode_batch` over the whole batch here and let `record_sig` discard the
            // results — measured 73% of transactions deserialised twice, with only 1% of
            // batches actually needing the fallback. That second pass is what made the
            // emitting packets cost ~90µs while the idle ones cost ~1µs.
            if self.streaming_cursor > bc_idx {
                self.batches_decoded_streaming = self.batches_decoded_streaming.saturating_add(1);
                self.complete_batch(bc_idx);
                continue;
            }

            self.combined_scratch.clear();
            for i in start..=bc_idx {
                if let Some(ps) = self.pending.get(&i) {
                    if let Some(p) = ps.payload() {
                        self.combined_scratch.extend_from_slice(p);
                    }
                }
            }
            match decode_batch(&self.combined_scratch) {
                Some(txs) => {
                    let mut any_new = false;
                    for tx in txs {
                        if self.record_sig(&tx) {
                            out.push(tx);
                            any_new = true;
                        }
                    }
                    if any_new {
                        self.batches_decoded_fallback =
                            self.batches_decoded_fallback.saturating_add(1);
                    } else {
                        self.batches_decoded_streaming =
                            self.batches_decoded_streaming.saturating_add(1);
                    }
                }
                None => {
                    self.decode_errors = self.decode_errors.saturating_add(1);
                    self.batches_skipped = self.batches_skipped.saturating_add(1);
                }
            }
            self.complete_batch(bc_idx);
        }
    }

    /// Emit batches that are complete but sit BEHIND an incomplete one.
    ///
    /// [ADDED, NOT IN UPSTREAM 2.0.0] `advance_streaming` stops at the first missing
    /// shred and `batch_start` only moves in order, so one gap holds back every
    /// transaction after it in the slot — not 2-3% of transactions but everything queued
    /// behind the hole, released in a burst once FEC fills it. That burst is what the
    /// 32-63 and 64+ emit buckets were, and what put p95/p99 at ~15ms while p50 was 0.
    ///
    /// Boundaries come from the shreds' own `DATA_COMPLETE` flag, never from scanning for
    /// something that parses — a batch whose start is not known (its preceding boundary
    /// shred is itself missing) is left alone rather than guessed at. The gapped batch
    /// keeps its existing path: FEC, then the stuck-batch timeout, then salvage.
    fn try_flush_out_of_order(&mut self, out: &mut Vec<RawTx>) {
        // First boundary at/after `batch_start` closes the stalled batch; every later one
        // starts at its predecessor + 1, which is why a lone boundary is not enough.
        let bcs: Vec<u32> = self
            .batch_complete_indices
            .range(self.batch_start..)
            .map(|(&k, _)| k)
            .collect();
        if bcs.len() < 2 {
            return;
        }

        for w in bcs.windows(2) {
            let (prev_bc, bc) = (w[0], w[1]);
            if self.flushed_batches.contains(&bc) {
                continue;
            }
            let start = prev_bc.saturating_add(1);
            if start > bc {
                continue;
            }
            let expected = (bc - start + 1) as usize;
            if self.pending.range(start..=bc).count() < expected {
                continue;
            }

            self.combined_scratch.clear();
            for i in start..=bc {
                if let Some(ps) = self.pending.get(&i) {
                    if let Some(p) = ps.payload() {
                        self.combined_scratch.extend_from_slice(p);
                    }
                }
            }

            if let Some(txs) = decode_batch(&self.combined_scratch) {
                let mut emitted = 0u64;
                for tx in txs {
                    if self.record_sig(&tx) {
                        out.push(tx);
                        emitted += 1;
                    }
                }
                self.out_of_order_txs = self.out_of_order_txs.saturating_add(emitted);
                self.out_of_order_flushed = self.out_of_order_flushed.saturating_add(1);
                self.flushed_batches.insert(bc);
            }
        }
    }

    fn complete_batch(&mut self, bc_idx: u32) {
        let next_start = bc_idx.saturating_add(1);
        self.pending.retain(|&k, _| k >= next_start);
        self.batch_complete_indices.retain(|&k, _| k >= next_start);
        self.fec_sets.retain(|&set_idx, fec| {
            let nd = fec.num_data as u32;
            !(nd > 0 && set_idx.saturating_add(nd) <= next_start)
        });
        self.batch_start = next_start;
        self.streaming_cursor = self.streaming_cursor.max(next_start);
        self.streaming_decoder.reset();
        self.flushed_batches.retain(|&k| k >= next_start);
        // yielded_sigs deliberately NOT cleared here — see its declaration.
    }

    pub fn try_harvest_tail(
        &mut self,
        rs_cache: &mut ReedSolomonCache,
    ) -> Vec<RawTx> {
        let mut out = Vec::new();

        let fec_hints: Vec<u32> = self.fec_sets.keys().copied().collect();
        for h in fec_hints {
            let _ = self.try_fec_fill(h, rs_cache);
        }

        let boundaries: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, ps)| ps.batch_complete)
            .map(|(&k, _)| k)
            .filter(|&k| k >= self.batch_start)
            .collect();

        for bc_idx in boundaries {
            let start = self.batch_start;
            if bc_idx < start {
                continue;
            }
            if (start..=bc_idx).all(|i| self.pending.contains_key(&i)) {
                self.combined_scratch.clear();
                for i in start..=bc_idx {
                    if let Some(ps) = self.pending.get(&i) {
                        if let Some(p) = ps.payload() {
                            self.combined_scratch.extend_from_slice(p);
                        }
                    }
                }
                if let Some(txs) = decode_batch(&self.combined_scratch) {
                    let mut any_new = false;
                    for tx in txs {
                        if self.record_sig(&tx) {
                            out.push(tx);
                            any_new = true;
                        }
                    }
                    if any_new {
                        self.batches_decoded_fallback =
                            self.batches_decoded_fallback.saturating_add(1);
                    } else {
                        self.batches_decoded_streaming =
                            self.batches_decoded_streaming.saturating_add(1);
                    }
                } else {
                    self.decode_errors = self.decode_errors.saturating_add(1);
                    self.batches_skipped = self.batches_skipped.saturating_add(1);
                }
            } else {
                let salvaged =
                    self.salvage_contiguous_runs_in(start, bc_idx, &mut out);
                if salvaged > 0 {
                    self.batches_decoded_fallback =
                        self.batches_decoded_fallback.saturating_add(1);
                } else {
                    self.batches_skipped = self.batches_skipped.saturating_add(1);
                }
            }
            self.complete_batch(bc_idx);
        }

        if !self.pending.is_empty() {
            let indices: Vec<u32> = self.pending.keys().copied().collect();
            let mut i = 0;
            while i < indices.len() {
                let run_start = indices[i];
                self.combined_scratch.clear();
                let mut expected = run_start;
                while i < indices.len() && indices[i] == expected {
                    if let Some(ps) = self.pending.get(&indices[i]) {
                        if let Some(p) = ps.payload() {
                            self.combined_scratch.extend_from_slice(p);
                        }
                    }
                    expected = indices[i].saturating_add(1);
                    i += 1;
                }
                if !self.combined_scratch.is_empty() {
                    for tx in decode_concatenated(&self.combined_scratch) {
                        if self.record_sig(&tx) {
                            out.push(tx);
                        }
                    }
                }
            }
        }

        self.fec_sets_discarded_unused = self
            .fec_sets_discarded_unused
            .saturating_add(self.fec_sets.len() as u64);
        self.salvaged_tail_tx = self.salvaged_tail_tx.saturating_add(out.len() as u64);

        out
    }

    fn salvage_contiguous_runs_in(
        &mut self,
        start: u32,
        end: u32,
        out: &mut Vec<RawTx>,
    ) -> usize {
        // The cursor below steps one index at a time, so the cost is O(end - start).
        // A slot cannot carry more than u16::MAX shreds — anything wider than that is a
        // corrupt boundary and would burn seconds of pure CPU walking empty indices.
        if end >= start.saturating_add(u16::MAX as u32) {
            return 0;
        }
        let mut salvaged = 0usize;
        let mut cursor = start;
        while cursor <= end {
            while cursor <= end && !self.pending.contains_key(&cursor) {
                cursor = cursor.saturating_add(1);
            }
            if cursor > end {
                break;
            }
            self.combined_scratch.clear();
            while cursor <= end && self.pending.contains_key(&cursor) {
                if let Some(ps) = self.pending.get(&cursor) {
                    if let Some(p) = ps.payload() {
                        self.combined_scratch.extend_from_slice(p);
                    }
                }
                cursor = cursor.saturating_add(1);
            }
            if !self.combined_scratch.is_empty() {
                for tx in decode_concatenated(&self.combined_scratch) {
                    if self.record_sig(&tx) {
                        out.push(tx);
                        salvaged = salvaged.saturating_add(1);
                    }
                }
            }
        }
        salvaged
    }

    fn record_sig(&mut self, tx: &RawTx) -> bool {
        // [RAW-TX] first signature straight from the wire bytes
        let bytes: [u8; 64] = match tx.first_signature() {
            Some(s) => s,
            None => return false,
        };
        let fresh = self.yielded_sigs.insert(bytes);
        if !fresh {
            self.dup_suppressed = self.dup_suppressed.saturating_add(1);
        }
        fresh
    }
}

impl Default for SlotAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod out_of_order_tests {
    use super::*;
    use crate::pool::{ShredPool, BUF_SIZE};
    use solana_entry::entry::Entry;
    use solana_hash::Hash;
    use solana_message::{legacy::Message as LegacyMessage, VersionedMessage};
    use solana_signature::Signature;

    fn tx(n: u8) -> VersionedTransaction {
        VersionedTransaction {
            signatures: vec![Signature::from([n; 64])],
            message: VersionedMessage::Legacy(LegacyMessage::default()),
        }
    }

    fn serialize_batch(txs: Vec<VersionedTransaction>) -> Vec<u8> {
        let entries = vec![Entry { num_hashes: 1, hash: Hash::default(), transactions: txs }];
        wincode::serialize(&entries).unwrap()
    }

    /// Split a serialised batch across shreds and push them, honouring `skip`.
    /// Returns the index after the batch's `DATA_COMPLETE` shred.
    fn push_batch(
        acc: &mut SlotAccumulator,
        pool: &std::sync::Arc<ShredPool>,
        rs: &mut ReedSolomonCache,
        mut index: u32,
        bytes: &[u8],
        chunk: usize,
        skip: Option<u32>,
        out: &mut Vec<RawTx>,
    ) -> u32 {
        let chunks: Vec<&[u8]> = bytes.chunks(chunk).collect();
        let last = chunks.len() - 1;
        for (i, c) in chunks.iter().enumerate() {
            if Some(index) != skip {
                let mut h = pool.acquire().unwrap();
                let end = DATA_HEADER_SIZE + c.len();
                assert!(end <= BUF_SIZE);
                h.as_mut_slice()[DATA_HEADER_SIZE..end].copy_from_slice(c);
                h.set_len(end);
                out.extend(acc.push_data(index, 0, h, end as u16, i == last, false, rs));
            }
            index += 1;
        }
        index
    }

    /// A gap in batch 1 must not hold back batches 2 and 3, and once the gap is filled
    /// every transaction must have been delivered exactly once.
    #[test]
    fn gap_does_not_block_later_batches_and_nothing_duplicates() {
        let pool = ShredPool::new(256);
        let mut rs = ReedSolomonCache::new();
        let mut acc = SlotAccumulator::new();
        let mut out = Vec::new();

        let b1 = serialize_batch((1..=6).map(tx).collect());
        let b2 = serialize_batch((20..=25).map(tx).collect());
        let b3 = serialize_batch((40..=45).map(tx).collect());
        let chunk = 200;

        // Batch 1 with shred index 1 withheld — it stalls, and upstream would stall
        // everything after it too.
        let after1 = push_batch(&mut acc, &pool, &mut rs, 0, &b1, chunk, Some(1), &mut out);
        let after2 = push_batch(&mut acc, &pool, &mut rs, after1, &b2, chunk, None, &mut out);
        let _ = push_batch(&mut acc, &pool, &mut rs, after2, &b3, chunk, None, &mut out);

        let seen: Vec<u8> = out.iter().map(|t| t.first_signature().unwrap()[0]).collect();
        assert!(seen.contains(&20), "batch 2 blocked behind the gap: {seen:?}");
        assert!(seen.contains(&40), "batch 3 blocked behind the gap: {seen:?}");
        // tx 1 lives entirely in shred 0, so the incremental decoder rightly emits it
        // before the gap. tx 6 is past the hole and must NOT appear yet.
        assert!(!seen.contains(&6), "a transaction past the gap leaked out early: {seen:?}");
        assert!(acc.out_of_order_flushed() >= 2, "out-of-order path never ran");

        // Now supply the withheld shred: batch 1 completes and must not re-emit 2 or 3.
        let before = out.len();
        let c: Vec<&[u8]> = b1.chunks(chunk).collect();
        let mut h = pool.acquire().unwrap();
        let end = DATA_HEADER_SIZE + c[1].len();
        h.as_mut_slice()[DATA_HEADER_SIZE..end].copy_from_slice(c[1]);
        h.set_len(end);
        out.extend(acc.push_data(1, 0, h, end as u16, c.len() == 2, false, &mut rs));

        let all: Vec<u8> = out.iter().map(|t| t.first_signature().unwrap()[0]).collect();
        let mut uniq = all.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(all.len(), uniq.len(), "a transaction was delivered twice: {all:?}");
        assert!(out.len() > before, "batch 1 never arrived after the gap was filled");
        assert!(all.contains(&6), "batch 1 tail missing after recovery: {all:?}");
    }
}
