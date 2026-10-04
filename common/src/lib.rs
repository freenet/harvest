//! Shared types for Harvest, the decentralized marketplace on Freenet.
//!
//! This crate defines the wire-format schemas used by the Harvest contracts,
//! delegate, and UI: store listings, orders and payments, and the reputation
//! contract's complaints.

#![deny(unsafe_code)]

// Fixed placeholder parameter values for the contract-address guard, and the
// binary that prints the addresses. Behind a feature that is OFF by default and
// enabled only by the guard's own invocations, because this crate is compiled
// INTO all three contracts and the delegate: adding even unreferenced code here
// moved all four code hashes when it was first tried, which is to say the guard
// would have re-keyed the artifacts it exists to watch.
#[cfg(feature = "address-guard")]
pub mod address;
pub mod backing;
pub mod bitcoin_delegate;
pub mod custody;
pub mod delegate;
pub mod feedback;
pub mod fulfilment;
pub mod ghostkey_index;
pub mod listing;
pub mod mailbox;
pub mod migration;
pub mod payment;
pub mod presence;
pub mod reputation;
#[cfg(feature = "sealed")]
pub mod sealed;
pub mod store;
#[cfg(test)]
pub(crate) mod test_orders;
pub mod util;

// Re-exports for convenience
pub use bitcoin_delegate::{
    BitcoinDelegateRequest, BitcoinDelegateResponse, BridgeAuthMode, BridgeEndpoint,
    DerivedAddress, PaymentXpubStatus, WatchedPayment,
};
pub use delegate::{
    BackupString, ConversationKey, ConversationSecret, EvictedConversation, HarvestDelegateRequest,
    HarvestDelegateResponse, ImportedConversation, MigratedSecretValue, PredecessorMarkerState,
    RecalledConversation, RememberedStore, SecretImport, StoreRegistration,
};
pub use feedback::FeedbackCategory;
pub use listing::{AuthorizedListing, Listing, ListingId, ListingKind, PriceInfo};
pub use mailbox::{ConversationId, EncryptedMessage, MailboxParameters, MailboxStateV1};
pub use payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus, ProofError};
pub use reputation::{Complaint, ReputationParameters, ReputationStateV1};
pub use store::{StoreParameters, StoreStateV1};

/// Contract id of the Harvest webapp container that this build targets.
///
/// Read at compile time from `published-contract/contract-id.txt` so that:
///
/// * Production, staging, dev, and forked Harvest builds each pin to
///   their own deployed id — a fork that publishes under a different
///   container id verifies its own signatures rather than always
///   trying to match the upstream Harvest deployment.
/// * The file `published-contract/contract-id.txt`, written by
///   `cargo make publish-harvest`, is the single source of truth. The
///   constant tracks whatever's checked in.
///
/// Used as the `expected_requestor` when verifying ghostkey-signed
/// listings and store info: every signature must have been produced
/// by a delegate call originating from this webapp, ensuring an app
/// the user has separately granted ghostkey access to via
/// `RequestAnyAccess` cannot mint signatures that pass Harvest's
/// contract verifiers.
///
/// **Migration note:** if the webapp container WASM is ever rebuilt
/// with a different hash (e.g. a stdlib bump), the deployed id changes
/// and listings/stores published under the old id are orphaned. The
/// migration path is to add the previous id to
/// `LEGACY_HARVEST_WEBAPP_CONTRACT_IDS` below so historical signatures
/// continue to verify, similar to how `legacy_delegates.toml` works
/// for the delegate WASM.
pub const HARVEST_WEBAPP_CONTRACT_ID: &str =
    include_str!("../../published-contract/contract-id.txt").trim_ascii();

/// Webapp container ids that previous Harvest deployments used. New
/// listings/stores sign under `HARVEST_WEBAPP_CONTRACT_ID`; signatures
/// that arrive carrying one of these ids verify too, so a container
/// WASM bump doesn't invalidate every existing signed object on the
/// network. Empty today; populate when the container WASM hash ever
/// changes (and bump the canonical id above to the new value).
pub const LEGACY_HARVEST_WEBAPP_CONTRACT_IDS: &[&str] = &[];

/// Cached parsed `SignatureRequestor` for `HARVEST_WEBAPP_CONTRACT_ID`.
/// Without this, every signature verification re-parses the constant.
#[cfg(feature = "ghostkey")]
static EXPECTED_HARVEST_REQUESTOR: std::sync::LazyLock<ghostkey_common::SignatureRequestor> =
    std::sync::LazyLock::new(|| {
        use freenet_stdlib::prelude::ContractInstanceId;
        // `from_bytes` under freenet-stdlib 0.6; renamed to `from_base58` in
        // 0.8 because the old name read as "raw 32 bytes" when it always
        // parsed base58 TEXT. Same function, and the constant is base58.
        let id = ContractInstanceId::from_base58(HARVEST_WEBAPP_CONTRACT_ID)
            .expect("HARVEST_WEBAPP_CONTRACT_ID must parse as a valid ContractInstanceId");
        ghostkey_common::SignatureRequestor::WebApp(id)
    });

/// Build the runtime-attested `SignatureRequestor` value that signatures
/// produced for Harvest must carry. Verifiers compare the requestor
/// embedded in the `ScopedPayload` against this; mismatch is a hard fail.
#[cfg(feature = "ghostkey")]
pub fn expected_harvest_requestor() -> ghostkey_common::SignatureRequestor {
    (*EXPECTED_HARVEST_REQUESTOR).clone()
}

/// Test that the canonical webapp id parses cleanly. Surfaces a typo or
/// stray whitespace in `contract-id.txt` at `cargo test` time rather
/// than as a panic on first signature verify in WASM.
#[cfg(test)]
#[test]
fn harvest_webapp_contract_id_parses() {
    let bytes = bs58::decode(HARVEST_WEBAPP_CONTRACT_ID)
        .into_vec()
        .expect("HARVEST_WEBAPP_CONTRACT_ID must decode as base58");
    assert_eq!(
        bytes.len(),
        32,
        "HARVEST_WEBAPP_CONTRACT_ID must decode to 32 bytes; got {}",
        bytes.len()
    );
}

#[cfg(all(test, feature = "ghostkey"))]
#[test]
fn expected_harvest_requestor_constructs() {
    // Ensures the LazyLock initialiser doesn't panic on first access.
    let r = expected_harvest_requestor();
    match r {
        ghostkey_common::SignatureRequestor::WebApp(_) => {}
        other => panic!("expected WebApp, got {other:?}"),
    }
}

/// Serialize a value to CBOR bytes.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| format!("CBOR serialize: {e}"))?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes.
pub fn from_cbor<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| format!("CBOR deserialize: {e}"))
}

/// Whether `bytes` is exactly what [`to_cbor`] produces for the value they
/// decode to.
///
/// A contract's `validate_state` decodes leniently: `ciborium` stops after one
/// item and ignores trailing bytes, serde skips unknown map keys, and CBOR
/// admits more than one encoding of an integer or a length. A state encoded
/// any of those ways passed `verify` and was then rewritten by the next merge,
/// while its summary matched a canonical peer's, so no delta ever repaired
/// it -- the #26 defect one layer down (PR #82 review, Should Fix 2). Every
/// contract now refuses a state that does not re-encode to its own bytes.
pub fn is_canonical_cbor<T: serde::Serialize>(value: &T, bytes: &[u8]) -> bool {
    // Compared as it is written, never re-encoded into a second copy (step
    // 2): a store at its caps is tens of MiB, and the copy ran the store
    // contract's `validate_state` out of the node's 256 MiB of WASM memory
    // (freenet-core `DEFAULT_MAX_MEMORY_PAGES`). Stops at the first byte that
    // differs; the same answer as encoding and comparing (pinned by
    // `canonical_check_tests`).
    let mut compare = CompareWriter { rest: bytes };
    ciborium::into_writer(value, &mut compare).is_ok() && compare.rest.is_empty()
}

/// A writer that accepts exactly the bytes in `rest`, in order, and refuses
/// the first that differs (or any past its end).
struct CompareWriter<'a> {
    rest: &'a [u8],
}

impl std::io::Write for CompareWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.rest.strip_prefix(buf) {
            Some(rest) => {
                self.rest = rest;
                Ok(buf.len())
            }
            None => Err(std::io::ErrorKind::InvalidData.into()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A seeded, deterministic merge-law checker for the per-state property tests
/// (PR #82 review, Should Fix 3). No new dependency: a xorshift generator is
/// enough to pick subsets and orders, and a fixed seed keeps every run, and
/// every failure, reproducible.
#[cfg(test)]
pub(crate) mod merge_laws {
    pub(crate) struct Rng(u64);

    impl Rng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        /// A random subset of `pool`, of at most `max` items, in random order.
        pub(crate) fn subset<T: Clone>(&mut self, pool: &[T], max: usize) -> Vec<T> {
            let n = self.below(max + 1);
            (0..n)
                .map(|_| pool[self.below(pool.len())].clone())
                .collect()
        }
    }

    /// Byte-level idempotence on every state, and commutativity and
    /// associativity on `cases` random pairs and triples drawn from `states`.
    pub(crate) fn assert_laws<S>(
        states: &[S],
        cases: usize,
        rng: &mut Rng,
        merge: impl Fn(&S, &S) -> S,
        enc: impl Fn(&S) -> Vec<u8>,
    ) {
        for (i, a) in states.iter().enumerate() {
            assert_eq!(enc(&merge(a, a)), enc(a), "idempotence on state {i}");
        }
        for case in 0..cases {
            let (i, j, k) = (
                rng.below(states.len()),
                rng.below(states.len()),
                rng.below(states.len()),
            );
            let (a, b, c) = (&states[i], &states[j], &states[k]);
            assert_eq!(
                enc(&merge(a, b)),
                enc(&merge(b, a)),
                "commutativity, case {case}: states {i}, {j}"
            );
            assert_eq!(
                enc(&merge(&merge(a, b), c)),
                enc(&merge(a, &merge(b, c))),
                "associativity, case {case}: states {i}, {j}, {k}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_roundtrip() {
        let original = "hello harvest";
        let bytes = to_cbor(&original).unwrap();
        let decoded: String = from_cbor(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}

// Declared here, after everything else, rather than in the list at the top:
// a line inserted above `is_canonical_cbor` moves its panic locations, and
// with them the code hash of every contract that links it. That reduces
// artifact movement; it does not prevent it (adding this module moved every
// contract anyway, harvest images PR 2).
pub mod listing_image;

// After everything else for the same reason as `listing_image` above.
pub mod store_pause;

/// The encoding every generation before step 2 wrote (step 2, harvest#227):
/// the same bytes with each signed record's outer byte fields -- its signed
/// payload and signature, which `serde_bytes` now writes as CBOR byte
/// strings -- as arrays of integers, which is how ciborium writes a plain
/// `Vec<u8>`. Only fields named in [`EARLIER_BYTE_FIELDS`] are rewritten, so
/// a field that was a byte string all along (`store::Bytes32`) stays one.
#[cfg(test)]
pub(crate) mod earlier_encoding {
    use ciborium::Value;

    /// The fields step 2 moved to byte strings.
    pub(crate) const EARLIER_BYTE_FIELDS: [&str; 8] = [
        "scoped_payload",
        "signature",
        "backer_scoped_payload",
        "backer_signature",
        "acceptance_scoped_payload",
        "acceptance_signature",
        "status_scoped_payload",
        "status_signature",
    ];

    fn rewrite(value: Value) -> Value {
        match value {
            Value::Map(entries) => Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| {
                        let named = matches!(&k, Value::Text(t) if EARLIER_BYTE_FIELDS.contains(&t.as_str()));
                        let v = match v {
                            Value::Bytes(b) if named => Value::Array(
                                b.into_iter().map(|x| Value::Integer(x.into())).collect(),
                            ),
                            other => rewrite(other),
                        };
                        (k, v)
                    })
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.into_iter().map(rewrite).collect()),
            Value::Tag(t, inner) => Value::Tag(t, Box::new(rewrite(*inner))),
            other => other,
        }
    }

    /// `bytes` (today's encoding) as an earlier generation wrote them.
    pub(crate) fn of(bytes: &[u8]) -> Vec<u8> {
        let value: Value = crate::from_cbor(bytes).expect("CBOR");
        crate::to_cbor(&rewrite(value)).expect("encodes")
    }

    /// How many of the named fields `bytes` holds as byte strings.
    pub(crate) fn byte_string_fields(bytes: &[u8]) -> usize {
        fn count(value: &Value) -> usize {
            match value {
                Value::Map(entries) => entries
                    .iter()
                    .map(|(k, v)| {
                        let named = matches!(k, Value::Text(t) if EARLIER_BYTE_FIELDS.contains(&t.as_str()));
                        usize::from(named && matches!(v, Value::Bytes(_))) + count(v)
                    })
                    .sum(),
                Value::Array(items) => items.iter().map(count).sum(),
                Value::Tag(_, inner) => count(inner),
                _ => 0,
            }
        }
        count(&crate::from_cbor::<Value>(bytes).expect("CBOR"))
    }
}

/// Step 2: `is_canonical_cbor` compares as it encodes. Its verdict is the
/// one encoding into a copy and comparing gave, kept here as the reference.
#[cfg(test)]
mod canonical_check_tests {
    use super::*;

    fn reference<T: serde::Serialize>(value: &T, bytes: &[u8]) -> bool {
        to_cbor(value).is_ok_and(|re| re == bytes)
    }

    #[derive(serde::Serialize)]
    struct Sample {
        name: String,
        bytes: Vec<u8>,
        n: u64,
        list: Vec<u32>,
    }

    fn sample() -> Sample {
        Sample {
            name: "plum jam".into(),
            bytes: (0..300u32).map(|i| (i * 7) as u8).collect(),
            n: 1_700_000_000,
            list: vec![1, 24, 255, 256, 65_536],
        }
    }

    /// Identical bytes pass; a difference at the first, a middle and the last
    /// byte fails; a strict prefix and trailing bytes fail. Mutated red by
    /// dropping the length check, and by accepting a short write.
    #[test]
    fn exactly_the_encoding_passes() {
        let value = sample();
        let bytes = to_cbor(&value).unwrap();
        assert!(is_canonical_cbor(&value, &bytes));
        for at in [0, bytes.len() / 2, bytes.len() - 1] {
            let mut other = bytes.clone();
            other[at] ^= 0x01;
            assert!(!is_canonical_cbor(&value, &other), "a difference at {at}");
        }
        assert!(
            !is_canonical_cbor(&value, &bytes[..bytes.len() - 1]),
            "a prefix"
        );
        assert!(!is_canonical_cbor(&value, &[]), "nothing");
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(!is_canonical_cbor(&value, &longer), "trailing bytes");
    }

    /// The same verdict as the reference over every single-byte change,
    /// truncation and extension of a sample and of a store holding every
    /// signed record, and over a store in the earlier encoding (not
    /// canonical today). Mutated red by a writer that stops early with
    /// success.
    #[test]
    fn the_verdict_is_the_reference_one() {
        let value = sample();
        let bytes = to_cbor(&value).unwrap();
        let mut cases: Vec<Vec<u8>> = vec![bytes.clone()];
        for at in 0..bytes.len() {
            let mut other = bytes.clone();
            other[at] = other[at].wrapping_add(1);
            cases.push(other);
            cases.push(bytes[..at].to_vec());
        }
        cases.push([bytes.clone(), vec![0xff]].concat());
        for case in &cases {
            assert_eq!(
                is_canonical_cbor(&value, case),
                reference(&value, case),
                "{case:?}"
            );
        }
        let store = crate::store::StoreStateV1::default();
        let encoded = to_cbor(&store).unwrap();
        assert_eq!(
            is_canonical_cbor(&store, &encoded),
            reference(&store, &encoded)
        );
        assert!(is_canonical_cbor(&store, &encoded));
        let earlier = earlier_encoding::of(&to_cbor(&sample_store()).unwrap());
        let decoded: crate::store::StoreStateV1 = from_cbor(&earlier).unwrap();
        assert!(!is_canonical_cbor(&decoded, &earlier));
        assert_eq!(
            is_canonical_cbor(&decoded, &earlier),
            reference(&decoded, &earlier)
        );
    }

    /// A store with a signed record whose payload is written as bytes, so
    /// the earlier encoding differs from today's.
    fn sample_store() -> crate::store::StoreStateV1 {
        let owner = crate::test_orders::store_key().verifying_key();
        let mut state = crate::store::StoreStateV1 {
            owner: Some(owner),
            ..Default::default()
        };
        state.closed.records.insert(
            crate::store::Bytes32(owner.to_bytes()),
            crate::backing::AuthorizedClosure {
                closure: crate::backing::StoreClosure { store: owner },
                scoped_payload: vec![0x2a; 40],
                signature: vec![0x2b; 64],
            },
        );
        state
    }
}
