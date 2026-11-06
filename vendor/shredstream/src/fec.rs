use std::collections::BTreeMap;

use reed_solomon_erasure::galois_8::{self as gf, ReedSolomon};

use crate::variant::VariantKind;

const CACHE_CAPACITY: usize = 32;

/// [DIAG 2026-09-29] Reed-Solomon cost split: reconstructions, data shards rebuilt,
/// ns inside `reconstruct_data`, ns in the whole `try_reconstruct` (copies included).
pub static RS_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RS_MISSING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RS_CORE_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RS_TOTAL_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub const SIZE_OF_SIGNATURE: usize = 64;
pub const SIZE_OF_CODING_SHRED_HEADERS: usize = 89;
pub const SIZE_OF_MERKLE_ROOT: usize = 32;
pub const SIZE_OF_MERKLE_PROOF_ENTRY: usize = 20;
pub const DATA_SHRED_PAYLOAD_LEN: usize = 1203;
pub const CODE_SHRED_PAYLOAD_LEN: usize = 1228;

#[inline]
pub fn shard_size(proof_size: u8, resigned: bool) -> usize {
    CODE_SHRED_PAYLOAD_LEN
        - SIZE_OF_CODING_SHRED_HEADERS
        - SIZE_OF_MERKLE_ROOT
        - (proof_size as usize) * SIZE_OF_MERKLE_PROOF_ENTRY
        - if resigned { SIZE_OF_SIGNATURE } else { 0 }
}

pub fn data_shard_slice(raw: &[u8], variant: VariantKind) -> Option<&[u8]> {
    match variant {
        VariantKind::DataMerkle {
            proof_size,
            resigned,
        } => {
            let len = shard_size(proof_size, resigned);
            let end = SIZE_OF_SIGNATURE.checked_add(len)?;
            raw.get(SIZE_OF_SIGNATURE..end)
        }
        _ => None,
    }
}

pub fn code_shard_slice(raw: &[u8], variant: VariantKind) -> Option<&[u8]> {
    match variant {
        VariantKind::CodeMerkle {
            proof_size,
            resigned,
        } => {
            let len = shard_size(proof_size, resigned);
            let end = SIZE_OF_CODING_SHRED_HEADERS.checked_add(len)?;
            raw.get(SIZE_OF_CODING_SHRED_HEADERS..end)
        }
        _ => None,
    }
}

/// A codec plus its parity matrix, for the fast missing-only solver below.
pub struct CachedCodec {
    pub rs: ReedSolomon,
    nd: usize,
    nc: usize,
    /// Parity coefficients, row-major `nc × nd`: parity_j = Σ_i parity[j*nd+i] · data_i.
    /// Read off the library's own encoder (unit-vector encodes), so it is the very
    /// matrix `reconstruct_data` inverts — identical results by construction.
    parity: Vec<u8>,
}

impl CachedCodec {
    fn new(nd: usize, nc: usize) -> Result<Self, reed_solomon_erasure::Error> {
        let rs = ReedSolomon::new(nd, nc)?;
        let mut parity = vec![0u8; nc * nd];
        let mut sh: Vec<Vec<u8>> = (0..nd + nc).map(|_| vec![0u8; 1]).collect();
        for i in 0..nd {
            for v in sh.iter_mut() {
                v[0] = 0;
            }
            sh[i][0] = 1;
            rs.encode(&mut sh)?;
            for j in 0..nc {
                parity[j * nd + i] = sh[nd + j][0];
            }
        }
        Ok(Self { rs, nd, nc, parity })
    }

    /// [2026-09-29] Rebuild ONLY the missing data shards by solving the k×k system on
    /// k present parity rows (k = missing count). `reconstruct_data` inverts the full
    /// nd×nd sub-matrix for every new loss pattern — measured 87µs for 16 missing of 32
    /// with random patterns, ~65µs of it the inversion. This does k³ instead of nd³:
    /// 34µs for the same case, bit-identical output (the missing data is the unique
    /// solution of the same linear system). Returns false when it cannot run (too few
    /// parity rows, singular pick) — the caller then falls back to the library.
    pub fn reconstruct_missing_data(&self, shards: &mut [Option<Vec<u8>>]) -> bool {
        let (nd, nc) = (self.nd, self.nc);
        if shards.len() != nd + nc {
            return false;
        }
        let mut missing = [0usize; MAX_FAST_MISSING];
        let mut k = 0;
        for i in 0..nd {
            if shards[i].is_none() {
                if k == MAX_FAST_MISSING {
                    return false;
                }
                missing[k] = i;
                k += 1;
            }
        }
        if k == 0 {
            return true;
        }
        let missing = &missing[..k];
        let mut par = [0usize; MAX_FAST_MISSING];
        let mut np = 0;
        for j in 0..nc {
            if np == k {
                break;
            }
            if shards[nd + j].is_some() {
                par[np] = j;
                np += 1;
            }
        }
        if np < k {
            return false;
        }
        let par = &par[..k];
        let len = match shards.iter().flatten().next() {
            Some(s) => s.len(),
            None => return false,
        };

        // A = parity rows `par` restricted to the missing columns; invert in place.
        let mut a = [[0u8; MAX_FAST_MISSING]; MAX_FAST_MISSING];
        let mut inv = [[0u8; MAX_FAST_MISSING]; MAX_FAST_MISSING];
        for r in 0..k {
            for c in 0..k {
                a[r][c] = self.parity[par[r] * nd + missing[c]];
            }
            inv[r][r] = 1;
        }
        for c in 0..k {
            let Some(p) = (c..k).find(|&r| a[r][c] != 0) else {
                return false;
            };
            a.swap(c, p);
            inv.swap(c, p);
            let f = gf::div(1, a[c][c]);
            for x in 0..k {
                a[c][x] = gf::mul(a[c][x], f);
                inv[c][x] = gf::mul(inv[c][x], f);
            }
            for r in 0..k {
                let g = a[r][c];
                if r != c && g != 0 {
                    for x in 0..k {
                        a[r][x] ^= gf::mul(g, a[c][x]);
                        inv[r][x] ^= gf::mul(g, inv[c][x]);
                    }
                }
            }
        }

        // rhs_r = parity_{par[r]} + Σ_{present i} M[par[r]][i] · data_i   (GF add = xor)
        let mut rhs: Vec<Vec<u8>> = Vec::with_capacity(k);
        for &j in par {
            let mut v = match shards[nd + j].as_ref() {
                Some(p) if p.len() == len => p.clone(),
                _ => return false,
            };
            for i in 0..nd {
                if let Some(d) = shards[i].as_ref() {
                    let coef = self.parity[j * nd + i];
                    if coef != 0 {
                        if d.len() != len {
                            return false;
                        }
                        gf::mul_slice_xor(coef, d, &mut v);
                    }
                }
            }
            rhs.push(v);
        }
        for (t, &i) in missing.iter().enumerate() {
            let mut out = vec![0u8; len];
            for r in 0..k {
                let coef = inv[t][r];
                if coef != 0 {
                    gf::mul_slice_xor(coef, &rhs[r], &mut out);
                }
            }
            shards[i] = Some(out);
        }
        true
    }
}

/// Above this many missing data shards the library wins (its multiply work stays nd·k
/// while ours adds the k³ inversion; measured crossover between 24 and 32 of 32).
pub const MAX_FAST_MISSING: usize = 24;

pub struct ReedSolomonCache {
    entries: Vec<((u16, u16), CachedCodec)>,
}

impl Default for ReedSolomonCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReedSolomonCache {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(CACHE_CAPACITY),
        }
    }

    pub fn get_or_build(
        &mut self,
        data: u16,
        coding: u16,
    ) -> Result<&CachedCodec, reed_solomon_erasure::Error> {
        if let Some(pos) = self.entries.iter().position(|(k, _)| *k == (data, coding)) {
            let entry = self.entries.swap_remove(pos);
            self.entries.push(entry);
            return Ok(&self.entries.last().unwrap().1);
        }
        // [DIAG] A matrix build is the only unbounded-cost operation on this path; the
        // (data, coding) pair comes straight off the wire. Real Solana FEC sets stay
        // within 32+32 — anything above is worth seeing.
        if data > 64 || coding > 64 {
            eprintln!("[rs-build] data={data} coding={coding}");
        }
        let codec = CachedCodec::new(data as usize, coding as usize)?;
        if self.entries.len() >= CACHE_CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push(((data, coding), codec));
        Ok(&self.entries.last().unwrap().1)
    }
}

pub struct FecSetBuffer {
    #[allow(dead_code)]
    pub(crate) fec_set_index: u32,
    pub(crate) num_data: u16,
    pub(crate) num_coding: u16,
    pub(crate) shard_size: usize,
    pub(crate) variant: Option<VariantKind>,
    pub(crate) code: BTreeMap<u16, Vec<u8>>,
}

impl FecSetBuffer {
    pub fn new(fec_set_index: u32) -> Self {
        Self {
            fec_set_index,
            num_data: 0,
            num_coding: 0,
            shard_size: 0,
            variant: None,
            code: BTreeMap::new(),
        }
    }

    pub fn record_code(
        &mut self,
        position: u16,
        num_data: u16,
        num_coding: u16,
        raw: &[u8],
        variant: VariantKind,
    ) {
        if self.num_data == 0 {
            self.num_data = num_data;
        }
        if self.num_coding == 0 {
            self.num_coding = num_coding;
        }
        if self.variant.is_none() {
            self.variant = Some(variant);
        }
        if self.shard_size == 0 {
            if let VariantKind::CodeMerkle {
                proof_size,
                resigned,
            } = variant
            {
                self.shard_size = shard_size(proof_size, resigned);
            }
        }
        self.code.entry(position).or_insert_with(|| raw.to_vec());
    }

    pub fn can_recover_with(&self, data_received: usize) -> bool {
        self.num_data > 0 && data_received + self.code.len() >= self.num_data as usize
    }

    pub fn try_reconstruct(
        &self,
        data_shards: &[(u16, &[u8])],
        cache: &mut ReedSolomonCache,
    ) -> Result<Vec<(u16, Vec<u8>)>, reed_solomon_erasure::Error> {
        let t_total = std::time::Instant::now();
        let r = self.try_reconstruct_inner(data_shards, cache);
        RS_TOTAL_NS.fetch_add(t_total.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        r
    }

    fn try_reconstruct_inner(
        &self,
        data_shards: &[(u16, &[u8])],
        cache: &mut ReedSolomonCache,
    ) -> Result<Vec<(u16, Vec<u8>)>, reed_solomon_erasure::Error> {
        if self.num_data == 0 || self.shard_size == 0 {
            return Ok(Vec::new());
        }
        let variant = match self.variant {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };
        let (proof_size, resigned) = match variant {
            VariantKind::CodeMerkle {
                proof_size,
                resigned,
            } => (proof_size, resigned),
            _ => return Ok(Vec::new()),
        };

        let nd = self.num_data as usize;
        let nc = self.num_coding as usize;
        let total = nd + nc;
        let shard_len = self.shard_size;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];

        for (&pos, raw) in self.code.iter() {
            let idx = nd + pos as usize;
            if idx >= total {
                continue;
            }
            let shard = match code_shard_slice(raw, variant) {
                Some(s) if s.len() == shard_len => s.to_vec(),
                _ => continue,
            };
            shards[idx] = Some(shard);
        }

        for (pos, raw) in data_shards.iter() {
            let p = *pos as usize;
            if p >= nd || shards[p].is_some() {
                continue;
            }
            let shard = match data_shard_slice(raw, variant_as_data(variant)) {
                Some(s) if s.len() == shard_len => s.to_vec(),
                _ => continue,
            };
            shards[p] = Some(shard);
        }

        let have = shards.iter().flatten().count();
        if have < nd {
            return Ok(Vec::new());
        }

        let rs = cache.get_or_build(self.num_data, self.num_coding)?;
        let t_core = std::time::Instant::now();
        if !rs.reconstruct_missing_data(&mut shards) {
            rs.rs.reconstruct_data(&mut shards)?;
        }
        {
            use std::sync::atomic::Ordering::Relaxed;
            RS_CORE_NS.fetch_add(t_core.elapsed().as_nanos() as u64, Relaxed);
            RS_CALLS.fetch_add(1, Relaxed);
            RS_MISSING.fetch_add((nd - data_shards.len().min(nd)) as u64, Relaxed);
        }

        let data_positions_present: std::collections::BTreeSet<u16> =
            data_shards.iter().map(|(p, _)| *p).collect();

        let mut out = Vec::new();
        for pos in 0..nd as u16 {
            if data_positions_present.contains(&pos) {
                continue;
            }
            let shard = match shards[pos as usize].take() {
                Some(s) if s.len() == shard_len => s,
                _ => continue,
            };
            let _ = (proof_size, resigned);
            let mut raw = vec![0u8; DATA_SHRED_PAYLOAD_LEN];
            raw[SIZE_OF_SIGNATURE..SIZE_OF_SIGNATURE + shard_len].copy_from_slice(&shard);
            out.push((pos, raw));
        }
        Ok(out)
    }
}

fn variant_as_data(v: VariantKind) -> VariantKind {
    match v {
        VariantKind::CodeMerkle {
            proof_size,
            resigned,
        } => VariantKind::DataMerkle {
            proof_size,
            resigned,
        },
        other => other,
    }
}

#[cfg(test)]
mod fast_solver_tests {
    use super::*;

    /// Differential: the missing-only solver must rebuild exactly what
    /// `reed_solomon_erasure::reconstruct_data` rebuilds — and the original data — for
    /// every geometry Solana uses and random loss patterns up to the fast-path limit.
    #[test]
    fn matches_library_on_random_losses() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut checked = 0;
        for &(nd, nc) in &[(32usize, 32usize), (1, 17), (5, 27), (17, 21), (31, 33), (64, 64), (67, 67)] {
            let codec = CachedCodec::new(nd, nc).unwrap();
            for _ in 0..150 {
                let len = 1 + (rnd() as usize % 1100);
                let mut shards: Vec<Vec<u8>> =
                    (0..nd + nc).map(|_| (0..len).map(|_| rnd() as u8).collect()).collect();
                codec.rs.encode(&mut shards).unwrap();
                let max_k = nd.min(nc).min(MAX_FAST_MISSING);
                let k = 1 + rnd() as usize % max_k;
                let mut d: Vec<usize> = (0..nd).collect();
                for i in (1..nd).rev() {
                    d.swap(i, rnd() as usize % (i + 1));
                }
                let mut c: Vec<usize> = (nd..nd + nc).collect();
                for i in (1..nc).rev() {
                    c.swap(i, rnd() as usize % (i + 1));
                }
                // leave between k and nc parity shards
                let keep_parity = k + rnd() as usize % (nc - k + 1);
                let mut opt: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
                for &i in &d[..k] {
                    opt[i] = None;
                }
                for &j in &c[..nc - keep_parity] {
                    opt[j] = None;
                }
                let mut lib = opt.clone();
                codec.rs.reconstruct_data(&mut lib).unwrap();
                assert!(codec.reconstruct_missing_data(&mut opt), "fast path refused nd={nd} nc={nc} k={k}");
                for i in 0..nd {
                    assert_eq!(opt[i].as_ref(), Some(&shards[i]), "nd={nd} nc={nc} k={k} shard {i}");
                    assert_eq!(opt[i], lib[i]);
                }
                checked += 1;
            }
        }
        assert!(checked > 1000);
    }

    #[test]
    fn refuses_what_it_cannot_do() {
        let codec = CachedCodec::new(32, 32).unwrap();
        let shards: Vec<Option<Vec<u8>>> = (0..64)
            .map(|i| if i < MAX_FAST_MISSING + 1 { None } else { Some(vec![0u8; 8]) })
            .collect();
        let mut s = shards.clone();
        assert!(!codec.reconstruct_missing_data(&mut s), "over the limit must fall back");
        assert_eq!(s, shards, "a refusal must leave the shards untouched");
    }
}

#[cfg(test)]
mod fast_solver_bench {
    use super::*;
    /// cargo test --release --lib fast_solver_bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn random_patterns_32_32() {
        let codec = CachedCodec::new(32, 32).unwrap();
        let mut seed = 7u64;
        let mut rnd = move || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
        for k in [1usize, 4, 8, 16, 24] {
            let (mut lib_t, mut fast_t) = (Vec::new(), Vec::new());
            for _ in 0..400 {
                let mut shards: Vec<Vec<u8>> = (0..64).map(|_| (0..1051).map(|_| rnd() as u8).collect()).collect();
                codec.rs.encode(&mut shards).unwrap();
                let mut d: Vec<usize> = (0..32).collect();
                for i in (1..32).rev() { d.swap(i, rnd() as usize % (i + 1)); }
                let mut c: Vec<usize> = (32..64).collect();
                for i in (1..32).rev() { c.swap(i, rnd() as usize % (i + 1)); }
                let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
                for &i in &d[..k] { opt[i] = None; }
                for &j in &c[..32 - k] { opt[j] = None; }
                let mut lib = opt.clone();
                let t = std::time::Instant::now(); codec.rs.reconstruct_data(&mut lib).unwrap(); lib_t.push(t.elapsed());
                let t = std::time::Instant::now(); assert!(codec.reconstruct_missing_data(&mut opt)); fast_t.push(t.elapsed());
            }
            lib_t.sort(); fast_t.sort();
            eprintln!("missing={k:2}: library {:?}  fast {:?}", lib_t[200], fast_t[200]);
        }
    }
}
