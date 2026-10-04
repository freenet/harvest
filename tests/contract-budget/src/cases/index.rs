//! The Ghost Key index at its cap (harvest#226).
//!
//! An index holds at most `MAX_INDEX_ENTRIES` (64) entries, one per store
//! key, and every fixture here holds exactly 64. That count is the only cap
//! on the state; the other bound is per entry, the certificate, which may be
//! up to `MAX_CERTIFICATE_PEM_BYTES` (4096) bytes.
//!
//! What the contract checks of an entry, and so what this fixture makes
//! genuine: the statement names the index's Ghost Key as its backer, its
//! certificate is within the bound, and the Ghost Key's Ed25519 signature
//! over the vault's `ScopedPayload` envelope of the statement verifies, with
//! the Harvest webapp as requestor (`IndexEntry::verify`). Every entry is
//! signed for real by the fixture's Ghost Key through `store_key_envelope`,
//! exactly as the vault signs a backing statement.
//!
//! What the contract does NOT check: the certificate. It has no view of
//! Freenet's master key, and readers check the chain, not the contract. So
//! every entry carries the genuine Ghost Key certificate in
//! `tests/fixtures/ghostkey-certificate.pem` (1634 bytes), which is the real
//! size of a certificate and what an honest index carries: one Ghost Key has
//! one certificate, repeated in every entry. That certificate belongs to the
//! E2E test Ghost Key, whose signing key this harness does not hold, so it
//! names a different key than the one that signs here; since the contract
//! never reads it, that changes nothing it computes. A certificate padded to
//! the 4096-byte bound would be possible only for the Ghost Key's own holder
//! and is not a real certificate, so it is not the case measured.
//!
//! The held state is built by `GhostKeyIndexV1::apply_delta` from empty, so
//! it is canonical and passes `verify`, as the contract would hold it.

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};
use harvest_common::backing::{store_key_envelope, BackingStatement, MAX_CERTIFICATE_PEM_BYTES};
use harvest_common::ghostkey_index::{
    GhostKeyIndexV1, IndexEntry, IndexParameters, MAX_INDEX_ENTRIES,
};
use harvest_common::store::Bytes32;

use super::{array, cbor, signing_key, Case, Kind, Update};

/// A genuine Ghost Key certificate, as a backing statement carries it.
const CERTIFICATE_PEM: &str = include_str!("../../../fixtures/ghostkey-certificate.pem");

/// A Bitcoin mainnet height near the fixture's date ([`super::NOW`]): five
/// CBOR bytes, as every real height is.
const HEIGHT: u32 = 960_000;

fn ghost() -> SigningKey {
    signing_key("index/ghost", 0)
}

/// The Ghost Key's signed statement that it backs the store with key
/// `store`, made when the chain was at `HEIGHT + i`.
fn entry(store: &SigningKey, i: u64) -> Result<IndexEntry> {
    let statement = BackingStatement {
        store: store.verifying_key(),
        backer: ghost().verifying_key(),
        certificate_pem: CERTIFICATE_PEM.into(),
        network: BitcoinNetwork::Bitcoin,
        block: BlockAnchor {
            height: HEIGHT + i as u32,
            hash: BlockHash(array("index/block", i)),
        },
    };
    let scoped = store_key_envelope(cbor(&statement)).map_err(|e| anyhow!("{e}"))?;
    let signature = ghost().sign(&scoped).to_bytes().to_vec();
    Ok(IndexEntry {
        statement,
        scoped_payload: scoped,
        signature,
    })
}

/// `2 * MAX_INDEX_ENTRIES` store keys, ordered by their bytes, which is the
/// order the cap ranks them in (it keeps the smallest).
fn store_keys() -> Vec<SigningKey> {
    let mut keys: Vec<SigningKey> = (0..2 * MAX_INDEX_ENTRIES as u64)
        .map(|i| signing_key("index/store", i))
        .collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    keys
}

/// An index at its cap, holding the entries of every other store key in
/// [`store_keys`] order, starting at `parity`. Two indexes built with
/// parities 0 and 1 interleave, so the cap on their union keeps the 64
/// smallest of 128 keys: half of each, and neither one.
fn at_cap(params: &IndexParameters, keys: &[SigningKey], parity: usize) -> Result<GhostKeyIndexV1> {
    let entries = keys
        .iter()
        .enumerate()
        .skip(parity)
        .step_by(2)
        .map(|(i, k)| entry(k, i as u64))
        .collect::<Result<Vec<_>>>()?;
    let mut index = GhostKeyIndexV1::default();
    index
        .apply_delta(params, &entries)
        .map_err(|e| anyhow!("{e}"))?;
    index
        .verify(params)
        .map_err(|e| anyhow!("the index fixture fails verify: {e}"))?;
    if index.entries.len() != MAX_INDEX_ENTRIES {
        bail!(
            "the index fixture is not at its cap: {} entries",
            index.entries.len()
        );
    }
    if CERTIFICATE_PEM.len() > MAX_CERTIFICATE_PEM_BYTES {
        bail!("the fixture certificate is over the bound");
    }
    Ok(index)
}

pub fn cases() -> Result<Vec<Case>> {
    let params = IndexParameters::new(ghost().verifying_key());
    let parameters = cbor(&params);
    let keys = store_keys();
    let held = at_cap(&params, &keys, 0)?;
    let held_bytes = cbor(&held);

    // (a) The Ghost Key backs one more store, and the entry is published as
    // a one-entry delta. Its store key is the second smallest of the 128,
    // below the held index's largest, so the cap keeps it and evicts that
    // largest one: the update changes the state and leaves it at the cap.
    let one = vec![entry(&keys[1], 1)?];
    let mut expected = held.clone();
    expected
        .apply_delta(&params, &one)
        .map_err(|e| anyhow!("{e}"))?;
    let new_slot = Bytes32(keys[1].verifying_key().to_bytes());
    if expected.entries.len() != MAX_INDEX_ENTRIES || !expected.entries.contains_key(&new_slot) {
        bail!("the one-entry delta is not kept by the cap");
    }

    // (b) A full state of a second, different index at its cap, as a PUT or
    // a resync delivers it: the other 64 store keys. The merge keeps the 64
    // smallest of the 128, so the result differs from both and stays at the
    // cap.
    let other = at_cap(&params, &keys, 1)?;
    let mut merged = held.clone();
    merged.merge(&params, &other).map_err(|e| anyhow!("{e}"))?;
    if merged.entries.len() != MAX_INDEX_ENTRIES || merged == held || merged == other {
        bail!("the full-state merge does not change the held index at its cap");
    }

    Ok(vec![
        Case {
            kind: Kind::Index,
            name: "64 at cap + one-entry delta".into(),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(cbor(&one)),
        },
        Case {
            kind: Kind::Index,
            name: "64 at cap + another 64-at-cap state".into(),
            parameters,
            held: held_bytes,
            update: Update::State(cbor(&other)),
        },
    ])
}
