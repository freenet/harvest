//! Shared types for Harvest, the decentralized marketplace on Freenet.
//!
//! This crate defines the wire-format schemas used by the Harvest contracts,
//! delegate, and UI: store listings, feedback-token protocol messages, and
//! reputation contract state.

#![deny(unsafe_code)]

pub mod delegate;
pub mod feedback;
pub mod listing;
pub mod mailbox;
pub mod reputation;
pub mod store;
pub mod util;

// Re-exports for convenience
pub use delegate::{
    HarvestDelegateRequest, HarvestDelegateResponse, StoreRegistration, TransactionRecord,
};
pub use feedback::{FeedbackCategory, FeedbackToken, FeedbackTokenMsg};
pub use listing::{AuthorizedListing, Listing, ListingId, ListingKind, PriceInfo};
pub use mailbox::{ConversationId, EncryptedMessage, MailboxParameters, MailboxStateV1};
pub use reputation::{FeedbackEntry, ReputationParameters, ReputationStateV1};
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
        let id = ContractInstanceId::from_bytes(HARVEST_WEBAPP_CONTRACT_ID)
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
