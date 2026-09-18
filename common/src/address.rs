//! Fixed parameter values for the contract-address guard.
//!
//! # Why this exists
//!
//! A contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`. Both halves are
//! part of the address, but for a long time both of Harvest's guards --
//! `scripts/check-code-hashes.sh` and `.github/workflows/contract-drift.yml` --
//! compared only the compiled WASM. So a change that touched *only* a parameter
//! struct moved every published instance to a new address while both guards
//! reported "unchanged", because the WASM really was byte-identical.
//!
//! That is not hypothetical. Removing `trusted_bitcoin_bridges` and
//! `bitcoin_address_code_hash` from [`crate::store::StoreParameters`] took its
//! CBOR from 109 bytes to 56 and re-keyed every store ever published. It was
//! caught by someone measuring the encoding by hand; nothing in CI objected,
//! and nothing at runtime would have either -- the migration probe would have
//! walked addresses that never existed, taken `NotFound` at each, and reported
//! a clean "nothing to migrate". See [`crate::store::StoreParameters`],
//! `ui/src/migrate.rs`'s `LAST_LEGACY_STORE_PARAM_GENERATION`, and
//! `legacy/README.md`.
//!
//! # What a placeholder is for
//!
//! The guard is detecting a change in the **encoding shape**, not in any
//! particular seller's key, so every value here is a constant. Two builds of
//! the same source must produce the same bytes or the comparison is noise.
//!
//! # Why every field is named, and why the impls are all in this file
//!
//! Each placeholder is a full struct literal with every field spelled out, not
//! a `#[derive(Default)]`. Adding or removing a field is then a **compile
//! error** here, which is the point -- a defaulted construction would have
//! compiled straight through the change this guard exists to catch. (CI builds
//! with `address-guard` on, so that error is reached; see `ci.yml`.)
//!
//! They live in this file rather than beside the structs they describe for a
//! reason worth knowing before moving them back. `harvest-common` is compiled
//! into all three contracts and the delegate, and the release profile bakes
//! `file:line:col` panic locations into the WASM -- so merely *inserting lines*
//! into `store.rs` re-keyed `store_contract`, with the added code itself
//! `#[cfg]`-ed out. A new file shifts nothing. This is the same hazard
//! `scripts/build-contract-wasm.sh` warns about when it says a `cargo fmt` can
//! move an address.

use ed25519_dalek::{SigningKey, VerifyingKey};

/// A parameter struct the address guard can encode.
///
/// Implemented by every parameter type whose CBOR reaches a contract address.
/// **An unimplemented parameter struct is a struct the guard does not watch**,
/// exactly like an artifact missing from `scripts/build-contract-wasm.sh`.
pub trait AddressGuardParams: serde::Serialize + Sized {
    /// This struct filled with the fixed values above.
    fn address_guard_placeholder() -> Self;
}

/// A fixed, valid Ed25519 verifying key.
///
/// Derived from a constant seed rather than written out as 32 bytes because a
/// hand-written array is only a *probably* canonical point: `VerifyingKey`
/// serializes the compressed encoding it was given, so a bad literal would
/// still encode to something and the guard would compare bytes nobody could
/// ever publish. Going through `SigningKey` cannot produce one.
pub fn placeholder_verifying_key() -> VerifyingKey {
    SigningKey::from_bytes(&[0x42; 32]).verifying_key()
}

/// The CBOR a parameter struct's placeholder encodes to, using the same
/// encoder the app publishes with ([`crate::to_cbor`]).
pub fn placeholder_params_cbor<T: AddressGuardParams>() -> Result<Vec<u8>, String> {
    crate::to_cbor(&T::address_guard_placeholder())
}

// --- placeholders -------------------------------------------------------
//
// One `impl` per parameter struct whose CBOR reaches a contract address. Keep
// in step with the parameter types named in
// `common/src/bin/harvest-addresses.rs`; a struct with no `impl` here is a
// struct the guard does not watch.

impl AddressGuardParams for crate::store::StoreParameters {
    fn address_guard_placeholder() -> Self {
        Self::new(placeholder_verifying_key())
    }
}

impl AddressGuardParams for crate::mailbox::MailboxParameters {
    fn address_guard_placeholder() -> Self {
        Self {
            owner_verifying_key: placeholder_verifying_key(),
        }
    }
}

impl AddressGuardParams for crate::reputation::ReputationParameters {
    fn address_guard_placeholder() -> Self {
        Self {
            // Deliberately not empty: an empty `Vec<u8>` and a populated one
            // differ in CBOR by more than their contents, and the guard should
            // compare the shape a real key produces.
            rsa_public_key_der: b"harvest-address-guard-placeholder-rsa-der".to_vec(),
            owner_verifying_key: placeholder_verifying_key(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::MailboxParameters;
    use crate::reputation::ReputationParameters;
    use crate::store::StoreParameters;

    /// The whole guard rests on this: the same source must encode to the same
    /// bytes every run, or a comparison between two builds is noise.
    #[test]
    fn placeholders_are_deterministic() {
        for _ in 0..2 {
            assert_eq!(
                placeholder_params_cbor::<StoreParameters>().unwrap(),
                placeholder_params_cbor::<StoreParameters>().unwrap()
            );
            assert_eq!(
                placeholder_params_cbor::<ReputationParameters>().unwrap(),
                placeholder_params_cbor::<ReputationParameters>().unwrap()
            );
            assert_eq!(
                placeholder_params_cbor::<MailboxParameters>().unwrap(),
                placeholder_params_cbor::<MailboxParameters>().unwrap()
            );
        }
    }

    /// A placeholder that encoded to nothing would make every artifact's
    /// address equal to `BLAKE3(code_hash)`, so a parameter change would move
    /// no address and the guard would pass forever.
    #[test]
    fn placeholders_encode_to_something() {
        assert!(placeholder_params_cbor::<StoreParameters>().unwrap().len() > 1);
        assert!(
            placeholder_params_cbor::<ReputationParameters>()
                .unwrap()
                .len()
                > 1
        );
        assert!(
            placeholder_params_cbor::<MailboxParameters>()
                .unwrap()
                .len()
                > 1
        );
    }

    /// Distinct structs must not collide, or a field moved from one to another
    /// would look like no change at all.
    #[test]
    fn placeholders_differ_between_structs() {
        let store = placeholder_params_cbor::<StoreParameters>().unwrap();
        let mailbox = placeholder_params_cbor::<MailboxParameters>().unwrap();
        let reputation = placeholder_params_cbor::<ReputationParameters>().unwrap();
        assert_ne!(store, mailbox);
        assert_ne!(store, reputation);
        assert_ne!(mailbox, reputation);
    }

    /// `placeholder_verifying_key` is only useful if it is a real point: a
    /// non-canonical encoding would give the guard bytes no publish could
    /// produce.
    #[test]
    fn placeholder_verifying_key_is_canonical() {
        let vk = placeholder_verifying_key();
        assert_eq!(VerifyingKey::from_bytes(vk.as_bytes()).unwrap(), vk);
    }
}
