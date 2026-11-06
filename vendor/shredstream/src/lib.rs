pub mod accumulator;
pub mod affinity;
pub mod decoder;
pub mod error;
pub(crate) mod fec;
pub mod listener;
pub mod parser;
pub(crate) mod pool;
pub mod variant;

pub use accumulator::AccumulatorConfig;
pub use affinity::pin_current_thread_to_cpu;
pub use listener::{ListenerOptions, ShredListener};
pub use variant::{classify_variant, VariantKind};

/// [DIAG] Reed-Solomon totals: (reconstructions, data shards rebuilt, ns in
/// reconstruct_data, ns in the whole try_reconstruct incl. shard copies).
pub fn rs_stats() -> [u64; 4] {
    use std::sync::atomic::Ordering::Relaxed;
    [
        fec::RS_CALLS.load(Relaxed),
        fec::RS_MISSING.load(Relaxed),
        fec::RS_CORE_NS.load(Relaxed),
        fec::RS_TOTAL_NS.load(Relaxed),
    ]
}
