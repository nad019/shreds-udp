#[cfg(test)]
use solana_entry::entry::Entry;
use solana_transaction::versioned::VersionedTransaction;

use crate::error::DecodeError;

const MAX_ENTRY_COUNT: u64 = 50_000;

/// `Entry` header on the wire: `u64 num_hashes` + `[u8; 32] hash` +
/// `u64 transactions.len()`. The hash is a fixed array, so it carries no length prefix.
const ENTRY_HEADER_LEN: usize = 8 + 32 + 8;

/// Sanity bound on an entry's transaction count. Only reachable through a corrupt or
/// misaligned buffer; a real entry never comes close.
const MAX_TXS_PER_ENTRY: u64 = 10_000;
const INITIAL_BUFFER_CAPACITY: usize = 64 * 1024;

/// [3.0.0 ALIGNMENT] Version 1 transactions are live in shreds. solana 3.x types cannot
/// represent them, so every entry carrying one died at deserialise — and worse, the
/// misread length prefixes sent bincode into multi-second allocator grinds (the 4-7s
/// pipeline freezes). This module now deserialises through wincode against
/// solana-entry 4.2.2 / solana-transaction 4.1.6, the same trio upstream 3.0.0 pins.
/// The per-transaction streaming structure below is our own (upstream regressed to
/// whole-entry deserialise in 3.0.0) and is kept.

#[allow(dead_code)] // superseded by tx_wire_len's Ok(None) in the streaming path
fn is_truncated(err: &wincode::error::ReadError) -> bool {
    match err {
        wincode::error::ReadError::Io(wincode::io::ReadError::ReadSizeLimit(_)) => true,
        wincode::error::ReadError::Io(wincode::io::ReadError::Io(e)) => {
            e.kind() == std::io::ErrorKind::UnexpectedEof
        }
        _ => false,
    }
}

/// [RAW-TX 2026-09-29] A transaction exactly as it appeared on the wire, inside the
/// entry — no decode, no re-encode. Consumers that only need the bytes (the unix-socket
/// feed to a consumer that decodes them itself) get the leader's original
/// bytes for every version (legacy / v0 / V1); `decode()` is there for the few that need
/// a `VersionedTransaction` (gRPC). Before this, every transaction was fully decoded
/// here, measured with a second walk (`serialized_size`) and then re-serialised by the
/// consumer with bincode — which for V1 does NOT produce the wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawTx(pub Vec<u8>);

impl RawTx {
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// First signature (the tx id), read straight from the bytes.
    /// legacy/v0: `shortvec(n) | n*64 sigs | message` (n < 128 → one prefix byte);
    /// V1: `0x81 | header(num_required_signatures, ..) | … | n*64 sigs` at the tail.
    pub fn first_signature(&self) -> Option<[u8; 64]> {
        let b = &self.0;
        let first = *b.first()?;
        let start = if first & 0x80 == 0 {
            if first == 0 {
                return None;
            }
            1
        } else {
            let n = *b.get(1)? as usize;
            if n == 0 {
                return None;
            }
            b.len().checked_sub(n * 64)?
        };
        b.get(start..start + 64)?.try_into().ok()
    }

    /// Full decode (wincode = the wire format for all versions).
    pub fn decode(&self) -> Option<VersionedTransaction> {
        wincode::deserialize(&self.0).ok()
    }

    /// Wire bytes of an already-decoded transaction (fallback decode paths only).
    pub fn from_tx(tx: &VersionedTransaction) -> Option<RawTx> {
        wincode::serialize(tx).ok().map(RawTx)
    }
}

/// Byte length of the transaction at the start of `b`, by walking the wire layout
/// without decoding or allocating. `Ok(None)` = not all of its bytes are here yet
/// (wait for more shreds); `Err` = malformed. Must agree with wincode's
/// `serialized_size` for every valid transaction — see `wire_len_tests`.
///
/// legacy / v0: shortvec(num_sigs) + 64*num_sigs, then the message:
///   [0x80 prefix if v0] header(3) shortvec(nkeys)+32*nkeys blockhash(32)
///   shortvec(nix) × { program_id(1) shortvec(nacc)+nacc shortvec(ndata)+ndata }
///   [v0: shortvec(nlookups) × { key(32) shortvec(nw)+nw shortvec(nr)+nr }]
/// V1 (SIMD-0385): 0x81 header(3) config_mask(u32 LE) lifetime(32) nix(u8) naddr(u8)
///   32*naddr config_values(by mask) nix*{program_id u8, nacc u8, data_len u16 LE}
///   payloads(Σ nacc+ndata) then 64*num_required_signatures at the tail.
pub fn tx_wire_len(b: &[u8]) -> Result<Option<usize>, &'static str> {
    const MAX_TX: usize = 4096;
    let mut p: usize = 0;
    macro_rules! need {
        ($n:expr) => {{
            let n: usize = $n;
            match p.checked_add(n) {
                Some(end) if end <= MAX_TX => {
                    if end > b.len() {
                        return Ok(None);
                    }
                }
                _ => return Err("tx too large"),
            }
        }};
    }
    macro_rules! shortvec {
        () => {{
            let mut val: usize = 0;
            let mut i = 0;
            loop {
                need!(1);
                let byte = b[p];
                p += 1;
                val |= ((byte & 0x7f) as usize) << (7 * i);
                if byte & 0x80 == 0 {
                    break;
                }
                i += 1;
                if i == 3 {
                    return Err("shortvec");
                }
            }
            val
        }};
    }
    need!(1);
    let d = b[0];
    if d & 0x80 == 0 {
        // legacy / v0: d is the (single-byte) signature count
        p = 1;
        let nsig = d as usize;
        need!(nsig * 64);
        p += nsig * 64;
        need!(1);
        let versioned = b[p] & 0x80 != 0;
        if versioned {
            if b[p] != 0x80 {
                return Err("message version");
            }
            p += 1;
        }
        need!(3);
        p += 3;
        let nkeys = shortvec!();
        need!(nkeys * 32);
        p += nkeys * 32;
        need!(32);
        p += 32;
        let nix = shortvec!();
        for _ in 0..nix {
            need!(1);
            p += 1;
            let nacc = shortvec!();
            need!(nacc);
            p += nacc;
            let ndata = shortvec!();
            need!(ndata);
            p += ndata;
        }
        if versioned {
            let nl = shortvec!();
            for _ in 0..nl {
                need!(32);
                p += 32;
                let nw = shortvec!();
                need!(nw);
                p += nw;
                let nr = shortvec!();
                need!(nr);
                p += nr;
            }
        }
        Ok(Some(p))
    } else {
        if d != 0x81 {
            return Err("tx version");
        }
        p = 1;
        need!(3);
        let nsig = b[p] as usize;
        p += 3;
        need!(4);
        let mask = u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]);
        p += 4;
        const KNOWN: u32 = 0b11111;
        if mask & !KNOWN != 0 {
            return Err("v1 config mask");
        }
        let pf = mask & 0b11;
        if pf != 0 && pf != 0b11 {
            return Err("v1 priority fee bits");
        }
        let cfg = (if pf == 0b11 { 8 } else { 0 })
            + (mask >> 2 & 1) as usize * 4
            + (mask >> 3 & 1) as usize * 4
            + (mask >> 4 & 1) as usize * 4;
        need!(32);
        p += 32;
        need!(2);
        let nix = b[p] as usize;
        let naddr = b[p + 1] as usize;
        p += 2;
        if nix > 64 || naddr > 64 || nsig > 12 {
            return Err("v1 counts");
        }
        need!(naddr * 32);
        p += naddr * 32;
        need!(cfg);
        p += cfg;
        need!(nix * 4);
        let hdr = p;
        p += nix * 4;
        let mut payload = 0usize;
        for i in 0..nix {
            let h = hdr + 4 * i;
            payload += b[h + 1] as usize + u16::from_le_bytes([b[h + 2], b[h + 3]]) as usize;
        }
        need!(payload);
        p += payload;
        need!(nsig * 64);
        p += nsig * 64;
        Ok(Some(p))
    }
}

/// Incremental entry decoder.
///
/// [MODIFIED FROM UPSTREAM] Upstream deserialised a whole `Entry` at a time:
/// either the complete entry parsed or nothing was emitted, so every transaction in an
/// entry waited for the last byte of the last one. Measured on DoubleZero multicast
/// 2026-08-06: 95% of emits carried 1-3 transactions, but the tail reached 415, and
/// roughly a third of all transactions arrived inside entries of 16+. Each of those
/// waited on transactions it had nothing to do with — a p50 of 0.00ms with a p95/p99 of
/// tens of milliseconds, which is exactly the shape we were chasing.
///
/// This version parses the entry header, then deserialises transactions ONE AT A TIME,
/// emitting each as its bytes complete. Same input, same output set, same order — only
/// the granularity of delivery changes.
pub struct StreamingDecoder {
    buffer: Vec<u8>,
    cursor: usize,
    expected_count: Option<u64>,
    entries_yielded: u64,
    /// Transactions still owed by the entry being parsed. `None` = between entries, so
    /// the next bytes in the buffer are an entry header.
    txs_remaining: Option<u64>,
}

impl StreamingDecoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(INITIAL_BUFFER_CAPACITY),
            cursor: 0,
            expected_count: None,
            entries_yielded: 0,
            txs_remaining: None,
        }
    }

    #[inline]
    pub fn push(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<RawTx>, DecodeError> {
        self.buffer.extend_from_slice(payload);
        self.try_deserialize()
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
        self.expected_count = None;
        self.entries_yielded = 0;
        self.txs_remaining = None;
    }

    fn try_deserialize(&mut self) -> Result<Vec<RawTx>, DecodeError> {
        if self.expected_count.is_none() {
            if self.buffer.len() < self.cursor + 8 {
                return Ok(Vec::new());
            }
            let bytes: [u8; 8] = self.buffer[self.cursor..self.cursor + 8]
                .try_into()
                .map_err(|_| DecodeError::Corruption("slice len".into()))?;
            let count = u64::from_le_bytes(bytes);
            if count > MAX_ENTRY_COUNT {
                return Err(DecodeError::Corruption("invalid entry count".into()));
            }
            self.cursor += 8;
            self.expected_count = Some(count);
        }

        let expected = match self.expected_count {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };

        let mut txs = Vec::new();

        loop {
            match self.txs_remaining {
                // Between entries: read the next header if it has fully arrived.
                None => {
                    if self.entries_yielded >= expected {
                        break;
                    }
                    if self.buffer.len() < self.cursor + ENTRY_HEADER_LEN {
                        break;
                    }
                    let lo = self.cursor + ENTRY_HEADER_LEN - 8;
                    let bytes: [u8; 8] = self.buffer[lo..self.cursor + ENTRY_HEADER_LEN]
                        .try_into()
                        .map_err(|_| DecodeError::Corruption("slice len".into()))?;
                    let n = u64::from_le_bytes(bytes);
                    if n > MAX_TXS_PER_ENTRY {
                        return Err(DecodeError::Corruption("invalid tx count".into()));
                    }
                    self.cursor += ENTRY_HEADER_LEN;
                    // A tick entry carries no transactions and closes immediately.
                    if n == 0 {
                        self.entries_yielded += 1;
                    } else {
                        self.txs_remaining = Some(n);
                    }
                }
                // Entry exhausted — close it and move to the next header.
                Some(0) => {
                    self.entries_yielded += 1;
                    self.txs_remaining = None;
                }
                // Mid-entry: take one transaction if its bytes are all here.
                Some(n) => {
                    let remaining = &self.buffer[self.cursor..];
                    if remaining.is_empty() {
                        break;
                    }
                    // [RAW-TX] measure, don't decode: the bytes ARE the transaction.
                    match tx_wire_len(remaining) {
                        Ok(Some(len)) => {
                            txs.push(RawTx(remaining[..len].to_vec()));
                            self.cursor += len;
                            self.txs_remaining = Some(n - 1);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            capture_fail(remaining, e);
                            return Err(DecodeError::Corruption(e.to_string()));
                        }
                    }
                }
            }
        }

        Ok(txs)
    }
}

impl Default for StreamingDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Diagnostics for entry-decode failures: the wire error string plus the head bytes of
/// the most recent failing input, with a monotonic sequence so callers can tell new
/// failures from old.
pub static DECODE_FAIL: std::sync::Mutex<Option<(u64, String, [u8; 160], usize)>> =
    std::sync::Mutex::new(None);

fn capture_fail(bytes: &[u8], err: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut head = [0u8; 160];
    let n = bytes.len().min(160);
    head[..n].copy_from_slice(&bytes[..n]);
    if let Ok(mut slot) = DECODE_FAIL.lock() {
        *slot = Some((seq, err.to_string(), head, bytes.len()));
    }
}

/// Latest captured decode failure: (sequence, error, first 160 bytes, input length).
pub fn last_decode_fail() -> Option<(u64, String, [u8; 160], usize)> {
    DECODE_FAIL.lock().ok().and_then(|s| (*s).clone())
}

/// Walk ONE serialised `Vec<Entry>` from the start of `bytes` by length only, cutting
/// each transaction's original wire bytes out as it goes. Err if the batch is corrupt OR
/// incomplete — callers here hold whole batches, so running out of bytes is a failure.
/// Returns the transactions and the number of bytes the batch occupied.
///
/// [2026-09-29] Replaces a full `wincode::deserialize::<Vec<Entry>>` + per-tx re-encode
/// on the fallback paths (out-of-order flush, FEC-recovered batches, stuck-batch
/// salvage). Those are exactly the batches that were already late — a gap held them
/// back — and they paid ~0.5µs decode + ~0.2µs encode per transaction on top.
fn walk_entries(bytes: &[u8]) -> Result<(Vec<RawTx>, usize), &'static str> {
    if bytes.len() < 8 {
        return Err("short entry count");
    }
    let count = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| "slice len")?);
    if count > MAX_ENTRY_COUNT {
        return Err("invalid entry count");
    }
    let mut cur = 8usize;
    let mut txs = Vec::new();
    for _ in 0..count {
        if bytes.len() < cur + ENTRY_HEADER_LEN {
            return Err("truncated entry header");
        }
        let lo = cur + ENTRY_HEADER_LEN - 8;
        let n = u64::from_le_bytes(bytes[lo..cur + ENTRY_HEADER_LEN].try_into().map_err(|_| "slice len")?);
        if n > MAX_TXS_PER_ENTRY {
            return Err("invalid tx count");
        }
        cur += ENTRY_HEADER_LEN;
        for _ in 0..n {
            match tx_wire_len(&bytes[cur..])? {
                Some(len) => {
                    txs.push(RawTx(bytes[cur..cur + len].to_vec()));
                    cur += len;
                }
                None => return Err("truncated transaction"),
            }
        }
    }
    Ok((txs, cur))
}

pub fn decode_batch(bytes: &[u8]) -> Option<Vec<RawTx>> {
    if !validate_vec_prefix(bytes) {
        capture_fail(bytes, "vec_prefix");
        return None;
    }
    match walk_entries(bytes) {
        Ok((txs, _)) => Some(txs),
        Err(e) => {
            capture_fail(bytes, e);
            None
        }
    }
}

pub fn decode_concatenated(bytes: &[u8]) -> Vec<RawTx> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 8 <= bytes.len() {
        let remaining = &bytes[offset..];
        if !validate_vec_prefix(remaining) {
            break;
        }
        let Ok((txs, consumed)) = walk_entries(remaining) else {
            break;
        };
        if consumed == 0 {
            break;
        }
        out.extend(txs);
        offset += consumed;
    }
    out
}

fn validate_vec_prefix(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let arr: [u8; 8] = match bytes[..8].try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let count = u64::from_le_bytes(arr);
    if count > MAX_ENTRY_COUNT {
        return false;
    }
    if count.saturating_mul(48) > bytes.len() as u64 {
        return false;
    }
    true
}

#[cfg(test)]
mod wire_len_tests {
    use super::*;
    use solana_hash::Hash;
    use solana_message::{compiled_instruction::CompiledInstruction, v0, v1, MessageHeader, VersionedMessage};
    use solana_signature::Signature;

    fn pk(i: u8) -> solana_pubkey::Pubkey { solana_pubkey::Pubkey::new_from_array([i; 32]) }

    fn ixs(n: usize, seed: u8) -> Vec<CompiledInstruction> {
        (0..n).map(|i| CompiledInstruction {
            program_id_index: (i % 5) as u8,
            accounts: (0..((i * 7 + seed as usize) % 40) as u8).collect(),
            data: vec![seed; (i * 37 + seed as usize * 3) % 300],
        }).collect()
    }

    fn samples() -> Vec<VersionedTransaction> {
        let mut out = Vec::new();
        for seed in 0u8..12 {
            let nsig = 1 + (seed % 3);
            let header = MessageHeader { num_required_signatures: nsig, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 2 };
            let keys: Vec<_> = (0..(5 + seed * 3)).map(pk).collect();
            let sigs: Vec<Signature> = (0..nsig).map(|i| Signature::from([i + seed; 64])).collect();
            out.push(VersionedTransaction { signatures: sigs.clone(), message: VersionedMessage::Legacy(solana_message::legacy::Message {
                header, account_keys: keys.clone(), recent_blockhash: Hash::new_from_array([seed; 32]), instructions: ixs(seed as usize % 6 + 1, seed) }) });
            out.push(VersionedTransaction { signatures: sigs.clone(), message: VersionedMessage::V0(v0::Message {
                header, account_keys: keys.clone(), recent_blockhash: Hash::new_from_array([seed; 32]), instructions: ixs(seed as usize % 7 + 1, seed),
                address_table_lookups: (0..(seed % 3)).map(|i| v0::MessageAddressTableLookup { account_key: pk(200 + i), writable_indexes: (0..(seed + i)).collect(), readonly_indexes: (0..(i * 3)).collect() }).collect() }) });
            let config = v1::TransactionConfig {
                priority_fee: if seed % 2 == 0 { Some(1000 + seed as u64) } else { None },
                compute_unit_limit: if seed % 3 == 0 { Some(200_000) } else { None },
                loaded_accounts_data_size_limit: if seed % 4 == 0 { Some(64 * 1024) } else { None },
                heap_size: if seed % 5 == 0 { Some(64 * 1024) } else { None },
            };
            out.push(VersionedTransaction { signatures: sigs, message: VersionedMessage::V1(v1::Message::new(
                header, config, Hash::new_from_array([seed; 32]), keys, ixs(seed as usize % 6 + 1, seed))) });
        }
        out
    }

    #[test]
    fn wire_len_matches_wincode_and_detects_truncation() {
        for tx in samples() {
            let wire = wincode::serialize(&tx).unwrap();
            // exact length, also with trailing bytes of the next tx behind it
            assert_eq!(tx_wire_len(&wire), Ok(Some(wire.len())), "{:?}", tx.message);
            let mut more = wire.clone();
            more.extend_from_slice(&[0x55; 300]);
            assert_eq!(tx_wire_len(&more), Ok(Some(wire.len())));
            // every strict prefix is "not complete yet", never a wrong length
            for cut in 0..wire.len() {
                assert_eq!(tx_wire_len(&wire[..cut]), Ok(None), "cut={cut} of {}", wire.len());
            }
            // raw bytes round-trip and first signature straight from the bytes
            let raw = RawTx(wire.clone());
            assert_eq!(raw.decode().as_ref(), Some(&tx));
            let sig0: [u8; 64] = tx.signatures[0].into();
            assert_eq!(raw.first_signature(), Some(sig0));
        }
    }

    #[test]
    fn streaming_decoder_emits_original_bytes() {
        let txs = samples();
        let entry = Entry { num_hashes: 1, hash: Hash::new_from_array([9; 32]), transactions: txs.clone() };
        let bytes = wincode::serialize(&vec![entry]).unwrap();
        // feed in small chunks, like shreds
        let mut dec = StreamingDecoder::new();
        let mut got = Vec::new();
        for chunk in bytes.chunks(97) {
            got.extend(dec.push(chunk).unwrap());
        }
        assert_eq!(got.len(), txs.len());
        for (raw, tx) in got.iter().zip(&txs) {
            assert_eq!(raw.bytes(), &wincode::serialize(tx).unwrap()[..]);
        }
    }

    #[test]
    fn batch_walk_matches_full_decode() {
        let txs = samples();
        let tick = Entry { num_hashes: 5, hash: Hash::new_from_array([1; 32]), transactions: vec![] };
        let e1 = Entry { num_hashes: 1, hash: Hash::new_from_array([2; 32]), transactions: txs[..txs.len() / 2].to_vec() };
        let e2 = Entry { num_hashes: 1, hash: Hash::new_from_array([3; 32]), transactions: txs[txs.len() / 2..].to_vec() };
        let batch = vec![tick.clone(), e1, tick, e2];
        let bytes = wincode::serialize(&batch).unwrap();
        let want: Vec<Vec<u8>> = batch
            .iter()
            .flat_map(|e| e.transactions.iter().map(|t| wincode::serialize(t).unwrap()))
            .collect();

        let got = decode_batch(&bytes).unwrap();
        assert_eq!(got.iter().map(|r| r.bytes().to_vec()).collect::<Vec<_>>(), want);
        // Trailing bytes after the batch are ignored, like the full decode did.
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0u8; 40]);
        assert_eq!(decode_batch(&padded).unwrap().len(), want.len());
        // A truncated batch is a failure, not a partial result.
        for cut in [bytes.len() - 1, bytes.len() / 2, 60] {
            assert!(decode_batch(&bytes[..cut]).is_none(), "cut {cut}");
        }
        // Two batches back to back.
        let mut two = bytes.clone();
        two.extend_from_slice(&bytes);
        assert_eq!(decode_concatenated(&two).len(), 2 * want.len());
    }
}
