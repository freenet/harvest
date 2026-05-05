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

/// Stable contract id of the published Harvest webapp container. Used as
/// the `expected_requestor` when verifying ghostkey-signed listings and
/// store info: every signature must have been produced by a delegate
/// call originating from this webapp, ensuring an app the user has
/// granted ghostkey access to (Harvest itself or another) cannot mint
/// signatures that pass Harvest's contract verifiers.
///
/// The id is stable across Harvest releases because the underlying web
/// container contract WASM rarely changes; releases ship by updating
/// the container's *state* (the bundled UI bytes), not the container
/// code. If the container code is ever rebuilt with a different hash,
/// this constant will need to be updated and old stores re-published.
pub const HARVEST_WEBAPP_CONTRACT_ID: &str = "6FzSeAUKcqJrveKyU8RJgGKc5jRB1Z2juvxXtwTA4Em9";

/// Build the runtime-attested `SignatureRequestor` value that signatures
/// produced for Harvest must carry. Verifiers compare the requestor
/// embedded in the `ScopedPayload` against this; mismatch is a hard fail.
#[cfg(feature = "ghostkey")]
pub fn expected_harvest_requestor() -> ghostkey_common::SignatureRequestor {
    use freenet_stdlib::prelude::ContractInstanceId;
    let id = ContractInstanceId::from_bytes(HARVEST_WEBAPP_CONTRACT_ID)
        .expect("HARVEST_WEBAPP_CONTRACT_ID must parse as a valid ContractInstanceId");
    ghostkey_common::SignatureRequestor::WebApp(id)
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
