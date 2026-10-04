//! The fixtures: each contract at its caps, and the updates a node is sent
//! against it.
//!
//! Every fixture is deterministic. Keys come from fixed seeds, "random"
//! bytes from BLAKE3 in XOF mode over a label, and every timestamp from
//! [`NOW`], so repeated runs produce byte-identical states and identical
//! fuel. Each held state is built with `harvest_common`'s own merge code
//! where the contract has one, so it is a state the contract would hold
//! rather than one assembled by hand.

mod index;
mod mailbox;
mod reputation;
mod store;

use anyhow::Result;
use chrono::{DateTime, Utc};

/// The contracts this harness measures, by their committed artifact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Mailbox,
    Store,
    Index,
    Reputation,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Mailbox, Kind::Store, Kind::Index, Kind::Reputation];

    pub fn file(self) -> &'static str {
        match self {
            Kind::Mailbox => "mailbox_contract.wasm",
            Kind::Store => "store_contract.wasm",
            Kind::Index => "index_contract.wasm",
            Kind::Reputation => "reputation_contract.wasm",
        }
    }

    /// Whether an over-budget call of this contract fails the run. A
    /// report-only contract is measured and printed every run, with the
    /// issue that will make it gate, so the number is never out of sight:
    ///
    /// * the store, until harvest#230 (its caps and byte strings) lands;
    /// * reputation, until harvest#228 is fixed.
    ///
    /// Flipping one to `true` is part of the change that brings it within
    /// budget, not a later cleanup.
    pub fn gates(self) -> bool {
        match self {
            Kind::Mailbox | Kind::Index => true,
            Kind::Store | Kind::Reputation => false,
        }
    }

    /// The issue that will make a report-only contract gate.
    pub fn tracked_by(self) -> &'static str {
        match self {
            Kind::Mailbox | Kind::Index => "",
            Kind::Store => "harvest#230 (store caps and byte strings)",
            Kind::Reputation => "harvest#228",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Mailbox => "mailbox",
            Kind::Store => "store",
            Kind::Index => "index",
            Kind::Reputation => "reputation",
        }
    }
}

/// What a node is sent: `UpdateData::Delta` or `UpdateData::State`, as the
/// contract's own encoding.
pub enum Update {
    Delta(Vec<u8>),
    State(Vec<u8>),
    /// A delta the contract must REFUSE: only `update_state` runs, and it
    /// must answer an error. Measures that the refusal is cheap.
    RefusedDelta(Vec<u8>),
}

/// One update against one held state.
pub struct Case {
    pub kind: Kind,
    pub name: String,
    /// The contract's parameters, encoded as the contract decodes them.
    pub parameters: Vec<u8>,
    /// The state the node holds, encoded canonically.
    pub held: Vec<u8>,
    pub update: Update,
}

/// Every case, in report order.
pub fn all() -> Result<Vec<Case>> {
    let mut out = mailbox::cases()?;
    out.extend(store::cases()?);
    out.extend(index::cases()?);
    out.extend(reputation::cases()?);
    Ok(out)
}

/// The fixed instant every fixture is dated from (2026-09-21).
pub fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(NOW, 0).expect("fixed instant")
}

pub const NOW: i64 = 1_790_000_000;

/// `len` deterministic bytes for `label` and `i`: BLAKE3 in XOF mode. Stands
/// in for ciphertext, nonces and other bytes that are random in real use.
/// Random bytes are also the realistic case for the encoding: most bytes are
/// above 23, which costs two bytes each when a `Vec<u8>` is a CBOR integer
/// array.
pub fn bytes(label: &str, i: u64, len: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("harvest contract-budget fixture v1");
    hasher.update(label.as_bytes());
    hasher.update(&i.to_le_bytes());
    let mut out = vec![0u8; len];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// [`bytes`] as a fixed-size array.
pub fn array<const N: usize>(label: &str, i: u64) -> [u8; N] {
    bytes(label, i, N).try_into().expect("length")
}

/// A deterministic Ed25519 key for `label` and `i`.
pub fn signing_key(label: &str, i: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&array::<32>(label, i))
}

/// CBOR as the contracts write it (`ciborium::into_writer`).
pub fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("encode fixture");
    out
}
