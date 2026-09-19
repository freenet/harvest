//! Store-key custody: how every device a seller uses gets the same store key
//! without the Ghost Key ever leaving the vault (harvest#93, phase 1b).
//!
//! Design: `docs/design/entity-model.md`, section 3 ("Store key custody"),
//! section 6.3, and the phase 1 API. Validated by the spike on branch
//! `spike/store-key-custody` (`efa6930`), whose known-answer vectors are
//! carried here unchanged.
//!
//! # The mechanism
//!
//! A store's 32-byte secret seed is kept in the store's own state, wrapped
//! once to each backing Ghost Key:
//!
//! 1. The UI asks the vault for `SignMessage { fingerprint, message:
//!    wrap_message(store_vk) }`. The vault signs `to_cbor(ScopedPayload {
//!    requestor: WebApp(HARVEST_WEBAPP_CONTRACT_ID), payload: message })`
//!    with plain RFC 8032 Ed25519, which is deterministic: the same Ghost Key,
//!    requestor and message give the same 64 bytes on every call and every
//!    device.
//! 2. That signature is a SECRET ([`WrapSecret`]). HKDF-SHA256 turns it into
//!    an AES-256-GCM key and nonce, bound to the store, the backing key and
//!    the requestor it was made under.
//! 3. The Harvest delegate seals ([`wrap_store_key`]) and opens
//!    ([`unwrap_store_key`]) the seed. Unwrap checks the recovered seed really
//!    is the store's key. The UI never holds the seed.
//!
//! The store's inbox X25519 key and its record (blind-signing RSA) key derive
//! from the store key ([`inbox_secret`], [`record_rsa_key`]), so every device
//! agrees on them.
//!
//! # What lives where
//!
//! The state types ([`StoreKeyCopy`], [`AuthorizedCopy`], [`WrappedStoreKey`])
//! are always compiled: the store contract holds and checks them. The
//! cryptography is behind the `custody` feature, which the delegate and the UI
//! enable and no contract does.
//!
//! # A copy in store state
//!
//! Each wrapped copy is an [`AuthorizedCopy`]: a [`StoreKeyCopy`] (store,
//! backing Ghost Key, webapp scope, ciphertext) signed by the store key, so no
//! third party can plant or replace one. Copies live in the store's
//! `copies` set, one per (backer, scope). The contract checks shape and
//! signature; it cannot check that a ciphertext opens, and never needs to.
//! `StoreStateV1::normalize_backings` keeps a copy exactly while its backer
//! holds a backing that is not retired: the backing's retirement is the
//! custody tombstone, so one signed act stops a key being current AND stops
//! it recovering the store key from state (section 6.3, check 4).

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::listing::verify_scoped_signature;
use crate::store::Bytes32;

// --- Domain labels ----------------------------------------------------------
//
// Every label is versioned. Changing any of them changes every wrapping key,
// so a change is a re-wrap migration, never an edit. The known-answer tests
// turn red on any accidental change.

/// Prefix of the message the vault is asked to sign. ASCII, versioned,
/// NUL-terminated so no later label can extend it.
pub const WRAP_DOMAIN: &[u8] = b"harvest/store-key-wrap/v1\0";

/// The part of [`WRAP_DOMAIN`] shared by every version. [`is_wrap_message`]
/// matches on this, so a future `v2` request is still recognised as secret.
pub const WRAP_DOMAIN_FAMILY: &[u8] = b"harvest/store-key-wrap/";

/// `WrappedStoreKey::scheme` for HKDF-SHA256 + AES-256-GCM with a derived nonce.
pub const SCHEME_V1: u8 = 1;

/// Seed (32) + GCM tag (16).
pub const WRAPPED_LEN_V1: usize = 48;

/// How many wrapped copies one backing Ghost Key may have, one per webapp
/// scope. A scope changes only when Harvest's container id changes, which
/// has not happened since the first release; this bounds the state against a
/// store-key holder, not against honest use. Past it the copies with the
/// smallest scope bytes are kept, so the merge stays total (see
/// `StoreStateV1::normalize_backings`).
pub const MAX_SCOPES_PER_BACKER: usize = 4;

/// The exact bytes to hand the vault as `SignMessage::message`.
///
/// The full 32-byte store verifying key, not the 16-character store code: the
/// code is a prefix many keys share, the key is the one thing the recovered
/// seed is checked against, and either way one leaked signature opens one
/// store, not every store the Ghost Key backs.
pub fn wrap_message(store_vk: &VerifyingKey) -> Vec<u8> {
    let mut m = Vec::with_capacity(WRAP_DOMAIN.len() + 32);
    m.extend_from_slice(WRAP_DOMAIN);
    m.extend_from_slice(store_vk.as_bytes());
    m
}

/// Whether a message handed to (or returned by) the vault is a wrap request,
/// of any version. The UI's `SignResult` router asks this FIRST and sends a
/// match down the custody path, never into `pending_signatures` or any
/// publish path.
pub fn is_wrap_message(message: &[u8]) -> bool {
    message.starts_with(WRAP_DOMAIN_FAMILY)
}

/// The store key a wrap message names, if `message` is one.
pub fn wrap_message_store(message: &[u8]) -> Option<VerifyingKey> {
    let key: [u8; 32] = message.strip_prefix(WRAP_DOMAIN)?.try_into().ok()?;
    VerifyingKey::from_bytes(&key).ok()
}

/// The `SignatureRequestor::WebApp` contract instance id a wrap signature was
/// scoped to. Part of every wrapped copy's identity: a new webapp container id
/// means new signatures, so copies are re-wrapped under the new scope and the
/// old scope's copy stays until its backer is retired.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WrapScope(pub [u8; 32]);

impl WrapScope {
    /// The scope for a base58 webapp contract id, e.g.
    /// [`crate::HARVEST_WEBAPP_CONTRACT_ID`].
    pub fn from_base58(id: &str) -> Result<Self, CustodyError> {
        let bytes = bs58::decode(id)
            .into_vec()
            .map_err(|_| CustodyError::Malformed("webapp contract id is not base58"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CustodyError::Malformed("webapp contract id is not 32 bytes"))?;
        Ok(Self(arr))
    }

    /// The scope Harvest signs under today.
    pub fn current() -> Self {
        Self::from_base58(crate::HARVEST_WEBAPP_CONTRACT_ID).expect(
            "HARVEST_WEBAPP_CONTRACT_ID is a valid contract id (pinned by a test in lib.rs)",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    /// The vault's answer is not a wrap signature for this store, backer and
    /// scope (wrong message, wrong requestor, or a signature that does not
    /// verify). Never derive a key from it.
    NotAWrapSignature(&'static str),
    /// The ciphertext does not open under this wrap secret.
    WrongKeyOrCorrupt,
    /// It opened, but to a seed that is not this store's key.
    NotThisStoresKey,
    UnknownScheme(u8),
    Malformed(&'static str),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// One wrapped copy of the store key's seed.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WrappedStoreKey {
    pub scheme: u8,
    /// A CBOR byte string (not an array of integers): about 50 bytes, not 90.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl WrappedStoreKey {
    /// Shape check a contract can run without any key.
    pub fn check_shape(&self) -> Result<(), CustodyError> {
        match self.scheme {
            SCHEME_V1 if self.ciphertext.len() == WRAPPED_LEN_V1 => Ok(()),
            SCHEME_V1 => Err(CustodyError::Malformed("v1 ciphertext must be 48 bytes")),
            other => Err(CustodyError::UnknownScheme(other)),
        }
    }
}

/// A wrapped copy of the store key, as the store key publishes it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreKeyCopy {
    /// The store whose key this is. Must be the owner.
    pub store: VerifyingKey,
    /// The backing Ghost Key whose vault signature opens it.
    pub backer: VerifyingKey,
    /// The webapp scope that signature is made under.
    pub scope: WrapScope,
    pub wrapped: WrappedStoreKey,
}

/// A [`StoreKeyCopy`] signed by the store key.
///
/// Signed so that nobody but the store key's holder can put a copy in the
/// store's state, or replace one: an unsigned copy could be replaced by
/// garbage, and the smaller-encoding rule on a clash would then let a third
/// party choose which copy every replica keeps.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedCopy {
    pub copy: StoreKeyCopy,
    pub scoped_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AuthorizedCopy {
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        if self.copy.store != *owner {
            return Err("wrapped copy names a different store key than this store's owner".into());
        }
        self.copy
            .wrapped
            .check_shape()
            .map_err(|e| format!("wrapped copy is malformed: {e}"))?;
        verify_scoped_signature(&self.scoped_payload, &self.signature, owner, &self.copy)
            .map_err(|e| format!("wrapped copy is not signed by the store key: {e}"))
    }

    /// The slot a copy occupies: one per (backer, scope).
    pub fn slot_for(backer: &VerifyingKey, scope: &WrapScope) -> Bytes32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"harvest/store-key-copy/slot/v1");
        hasher.update(backer.as_bytes());
        hasher.update(&scope.0);
        Bytes32(*hasher.finalize().as_bytes())
    }
}

impl crate::backing::SignedRecord for AuthorizedCopy {
    fn slot(&self) -> Bytes32 {
        Self::slot_for(&self.copy.backer, &self.copy.scope)
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    const WHAT: &'static str = "wrapped copy";
}

/// Every wrapped copy a store holds.
pub type CopiesV1 = crate::backing::SignedSetV1<AuthorizedCopy>;

#[cfg(feature = "custody")]
mod crypto;
#[cfg(feature = "custody")]
pub use crypto::*;

#[cfg(all(test, feature = "custody"))]
mod tests;
