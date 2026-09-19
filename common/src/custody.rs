//! Store-key custody: how every device a seller uses gets the same store key
//! without the Ghost Key ever leaving the vault.
//!
//! Design: `harvest-entity-model.md`, revision 2, section 3 ("Store key
//! custody") and section 6.3. SPIKE: behind the off-by-default `custody`
//! feature, because this crate is compiled into every contract and the
//! delegate, and new code here can move their code hashes.
//!
//! # The mechanism
//!
//! A store has its own Ed25519 key, the **store key**. Its 32-byte secret seed
//! is kept in the store's own state, wrapped once to each backing Ghost Key:
//!
//! 1. Harvest asks the vault for `SignMessage { fingerprint, message:
//!    wrap_message(store_vk) }`. The vault signs `to_cbor(ScopedPayload {
//!    requestor: WebApp(HARVEST_WEBAPP_CONTRACT_ID), payload: message })`
//!    with plain RFC 8032 Ed25519, which is deterministic: the same Ghost Key,
//!    requestor and message give the same 64 bytes on every call and every
//!    device.
//! 2. That signature is treated as a SECRET ([`WrapSecret`]). HKDF-SHA256
//!    turns it into an AES-256-GCM key and nonce, bound to the store, the
//!    backing key and the requestor it was made under.
//! 3. [`wrap_store_key`] / [`unwrap_store_key`] seal and open the seed. Unwrap
//!    checks the recovered seed really is the store's key.
//!
//! The store's inbox X25519 key and its record (blind-signing RSA) key derive
//! from the store key ([`inbox_secret`], [`record_rsa_key`]), so every device
//! agrees on them too.
//!
//! [`StoreKeyCustody`] is the store-state field that holds the wrapped copies:
//! a grow-only map with per-backer tombstones, whose merge is commutative,
//! associative and idempotent.

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

// --- Domain labels ----------------------------------------------------------
//
// Every label is versioned. Changing any of them changes every wrapping key,
// so a change is a re-wrap migration, never an edit. The known-answer tests
// below turn red on any accidental change.

/// Prefix of the message the vault is asked to sign. The same shape as
/// freenet-bitcoin's `b"freenet-bitcoin/inbox-entry/v1\0"`: ASCII, versioned,
/// NUL-terminated so no later label can extend it.
pub const WRAP_DOMAIN: &[u8] = b"harvest/store-key-wrap/v1\0";

/// The part of [`WRAP_DOMAIN`] shared by every version. [`is_wrap_message`]
/// matches on this, so a future `v2` request is still recognised as secret.
pub const WRAP_DOMAIN_FAMILY: &[u8] = b"harvest/store-key-wrap/";

const WRAP_HKDF_SALT: &[u8] = b"harvest/store-key-wrap/v1/hkdf-salt";
const WRAP_HKDF_INFO: &[u8] = b"harvest/store-key-wrap/v1/aes-256-gcm-key+nonce";
const WRAP_AAD_LABEL: &[u8] = b"harvest/store-key-wrap/v1/aad";

const SUBKEY_HKDF_SALT: &[u8] = b"harvest/store-key/v1/subkeys";
const INBOX_INFO: &[u8] = b"harvest/store-key/v1/inbox-x25519";
const RECORD_INFO: &[u8] = b"harvest/store-key/v1/record-rsa-2048-seed";

/// `WrappedStoreKey::scheme` for HKDF-SHA256 + AES-256-GCM with a derived nonce.
pub const SCHEME_V1: u8 = 1;

/// Seed (32) + GCM tag (16).
pub const WRAPPED_LEN_V1: usize = 48;

/// Upper bound on wrapped copies a store may hold (live ones; tombstones are
/// 32 bytes each and bounded by the backings, which the store bounds already).
/// Several backers times a couple of container ids is the realistic case.
pub const MAX_WRAPPED_COPIES: usize = 32;

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
/// of any version. The UI's `SignResult` router must ask this FIRST and send
/// a match down the custody path, never into `pending_signatures` or any
/// publish path.
pub fn is_wrap_message(message: &[u8]) -> bool {
    message.starts_with(WRAP_DOMAIN_FAMILY)
}

/// The `SignatureRequestor::WebApp` contract instance id a wrap signature was
/// scoped to. Part of every wrapped copy's identity: a new webapp container id
/// means new signatures, so copies are re-wrapped under the new scope and the
/// old scope's copy stays until the old container is retired.
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

    fn requestor(&self) -> ghostkey_common::SignatureRequestor {
        ghostkey_common::SignatureRequestor::WebApp(
            freenet_stdlib::prelude::ContractInstanceId::new(self.0),
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
    /// The backing key has been retired; its copy is a tombstone.
    Retired,
    TooManyCopies,
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A vault signature over [`wrap_message`], checked and held as a secret.
///
/// No `Serialize`, no `Clone`, a redacted `Debug`, and zeroed on drop: the
/// type exists so the signature cannot be published, logged or copied by
/// accident. Construct it only through [`WrapSecret::from_sign_result`].
pub struct WrapSecret {
    signature: Zeroizing<[u8; 64]>,
    store_vk: VerifyingKey,
    backer_vk: VerifyingKey,
    scope: WrapScope,
}

impl std::fmt::Debug for WrapSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapSecret")
            .field("signature", &"<redacted>")
            .field("store_vk", &self.store_vk)
            .field("backer_vk", &self.backer_vk)
            .field("scope", &self.scope)
            .finish()
    }
}

impl WrapSecret {
    /// Accept the vault's `SignResult { scoped_payload, signature, .. }` for a
    /// wrap request, after checking it is exactly that:
    ///
    /// - `scoped_payload` decodes as a `ScopedPayload` whose requestor is
    ///   `WebApp(scope)` and whose payload is `wrap_message(store_vk)`, so a
    ///   signature Harvest obtained for anything else (a listing, an order,
    ///   store details, an inbox entry) is refused;
    /// - `signature` verifies (strictly) under the backing Ghost Key.
    ///
    /// The strict check also separates "the vault changed how it encodes
    /// what it signs" (the payload check fails) from "the ciphertext is
    /// corrupt" (unwrap fails), which is the difference between a migration
    /// and a bug.
    pub fn from_sign_result(
        scoped_payload: &[u8],
        signature: &[u8],
        backer_vk: &VerifyingKey,
        store_vk: &VerifyingKey,
        scope: WrapScope,
    ) -> Result<Self, CustodyError> {
        let scoped: ghostkey_common::ScopedPayload = crate::from_cbor(scoped_payload)
            .map_err(|_| CustodyError::NotAWrapSignature("scoped payload does not decode"))?;
        if scoped.requestor != scope.requestor() {
            return Err(CustodyError::NotAWrapSignature(
                "signed for a different requestor",
            ));
        }
        if scoped.payload != wrap_message(store_vk) {
            return Err(CustodyError::NotAWrapSignature(
                "not the wrap message for this store",
            ));
        }
        // The bytes we would have built ourselves. If the vault's encoding of
        // ScopedPayload ever drifts, this says so here rather than as an
        // unexplained unwrap failure.
        let expected = ghostkey_common::to_cbor(&scoped)
            .map_err(|_| CustodyError::Malformed("re-encode scoped payload"))?;
        if expected != scoped_payload {
            return Err(CustodyError::NotAWrapSignature(
                "scoped payload is not canonically encoded",
            ));
        }
        let sig: [u8; 64] = signature
            .try_into()
            .map_err(|_| CustodyError::NotAWrapSignature("signature is not 64 bytes"))?;
        let sig = Zeroizing::new(sig);
        backer_vk
            .verify_strict(scoped_payload, &Signature::from_bytes(&sig))
            .map_err(|_| CustodyError::NotAWrapSignature("signature does not verify"))?;
        Ok(Self {
            signature: sig,
            store_vk: *store_vk,
            backer_vk: *backer_vk,
            scope,
        })
    }

    pub fn store_vk(&self) -> &VerifyingKey {
        &self.store_vk
    }
    pub fn backer_vk(&self) -> &VerifyingKey {
        &self.backer_vk
    }
    pub fn scope(&self) -> WrapScope {
        self.scope
    }

    /// The copy id this secret seals and opens.
    pub fn copy_id(&self) -> CopyId {
        CopyId {
            backer: self.backer_vk.to_bytes(),
            scope: self.scope,
        }
    }

    /// `(key, nonce)` for AES-256-GCM.
    ///
    /// The nonce is derived, not random, which makes wrapping deterministic:
    /// two devices wrapping for the same backer produce the same bytes, so
    /// concurrent writes merge to one copy. That is safe here because the key
    /// is unique to (signature, store, backer, scope) and the only plaintext
    /// ever sealed under it is the store's own seed, which the store key
    /// determines: the (key, nonce) pair can never meet a second plaintext.
    fn aead_key_nonce(&self) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
        let hk = Hkdf::<Sha256>::new(Some(WRAP_HKDF_SALT), self.signature.as_slice());
        let mut okm = Zeroizing::new([0u8; 44]);
        let info: [&[u8]; 4] = [
            WRAP_HKDF_INFO,
            self.store_vk.as_bytes(),
            self.backer_vk.as_bytes(),
            &self.scope.0,
        ];
        hk.expand_multi_info(&info, okm.as_mut_slice())
            .expect("44 bytes is a valid HKDF-SHA256 output length");
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&okm[..32]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&okm[32..]);
        (key, nonce)
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(WRAP_AAD_LABEL.len() + 1 + 96);
        aad.extend_from_slice(WRAP_AAD_LABEL);
        aad.push(SCHEME_V1);
        aad.extend_from_slice(self.store_vk.as_bytes());
        aad.extend_from_slice(self.backer_vk.as_bytes());
        aad.extend_from_slice(&self.scope.0);
        aad
    }
}

/// One wrapped copy of the store key, as held in store state.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WrappedStoreKey {
    pub scheme: u8,
    /// A CBOR byte string (not an array of integers): ~50 bytes, not ~90.
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

/// Seal the store key's seed for one backer.
pub fn wrap_store_key(
    store_sk: &SigningKey,
    secret: &WrapSecret,
) -> Result<WrappedStoreKey, CustodyError> {
    if store_sk.verifying_key() != secret.store_vk {
        return Err(CustodyError::NotThisStoresKey);
    }
    let (key, nonce) = secret.aead_key_nonce();
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| CustodyError::Malformed("aes key length"))?;
    let seed = Zeroizing::new(store_sk.to_bytes());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: seed.as_slice(),
                aad: &secret.aad(),
            },
        )
        .map_err(|_| CustodyError::Malformed("aes-gcm encrypt"))?;
    Ok(WrappedStoreKey {
        scheme: SCHEME_V1,
        ciphertext,
    })
}

/// Open a wrapped copy, and check what comes out is this store's key.
pub fn unwrap_store_key(
    wrapped: &WrappedStoreKey,
    secret: &WrapSecret,
) -> Result<SigningKey, CustodyError> {
    wrapped.check_shape()?;
    let (key, nonce) = secret.aead_key_nonce();
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| CustodyError::Malformed("aes key length"))?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: &secret.aad(),
                },
            )
            .map_err(|_| CustodyError::WrongKeyOrCorrupt)?,
    );
    let seed: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| CustodyError::Malformed("plaintext is not a 32-byte seed"))?;
    let seed = Zeroizing::new(seed);
    let sk = SigningKey::from_bytes(&seed);
    if sk.verifying_key() != secret.store_vk {
        return Err(CustodyError::NotThisStoresKey);
    }
    Ok(sk)
}

// --- Keys derived from the store key ---------------------------------------

fn subkey_seed(store_sk: &SigningKey, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let seed = Zeroizing::new(store_sk.to_bytes());
    let hk = Hkdf::<Sha256>::new(Some(SUBKEY_HKDF_SALT), seed.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The store's inbox (X25519) secret. Same on every device holding the store
/// key; replaces today's random-per-device `harvest:x25519_sk:<fp>`.
///
/// Derived through HKDF with its own label rather than by converting the
/// Ed25519 key to X25519, so the signing key is never used in a second
/// protocol.
pub fn inbox_secret(store_sk: &SigningKey) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(*subkey_seed(store_sk, INBOX_INFO))
}

/// The 32-byte seed the record (blind-signing) key is generated from.
pub fn record_key_seed(store_sk: &SigningKey) -> Zeroizing<[u8; 32]> {
    subkey_seed(store_sk, RECORD_INFO)
}

/// The store's record key: RSA-2048 generated from [`record_key_seed`] with a
/// seeded ChaCha20 RNG.
///
/// CAVEAT, and why the public half must also be published: RSA key generation
/// is an algorithm, not a function the `rsa` crate promises to keep stable. A
/// crate bump may generate a different key from the same seed. The known-answer
/// test pins today's output so a bump turns red; the protocol should still
/// publish the public key in store state and treat a mismatch on another
/// device as "regenerate from an older crate or re-key the record", never as
/// silent success.
pub fn record_rsa_key(store_sk: &SigningKey) -> Result<rsa::RsaPrivateKey, CustodyError> {
    use rand_chacha::rand_core::SeedableRng;
    let seed = record_key_seed(store_sk);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
    rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|_| CustodyError::Malformed("rsa keygen"))
}

// --- Store-state field ------------------------------------------------------

/// Which wrapped copy: the backing Ghost Key and the webapp scope its
/// signature was made under.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CopyId {
    pub backer: [u8; 32],
    pub scope: WrapScope,
}

/// The wrapped copies of a store's key, as a store-state field.
///
/// Grow-only with tombstones. A backer in `retired` has no live copies under
/// any scope, and never will again: a copy arriving later from a stale peer,
/// or written under a new scope after the retirement, is dropped by the merge.
/// Retirement is per BACKER, not per copy, so a re-wrap under a new container
/// id cannot resurrect a retired key's access.
///
/// Merge: union of `retired`; union of `copies`, keeping the larger
/// `WrappedStoreKey` on a clash (with deterministic wrapping, honest clashes
/// are byte-equal, so this only ever picks between a copy and garbage); then
/// drop every copy whose backer is retired. Each step is a semilattice join,
/// and the prune only depends on the union of `retired`, so the whole is
/// commutative, associative and idempotent (checked below).
///
/// In phase 1 `retired` should BE the store's backing-retirement set, not a
/// second copy of it: one signed retirement, both effects.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct StoreKeyCustody {
    pub copies: BTreeMap<CopyId, WrappedStoreKey>,
    pub retired: BTreeSet<[u8; 32]>,
}

impl StoreKeyCustody {
    pub fn merge(&mut self, other: &Self) {
        self.retired.extend(other.retired.iter().copied());
        for (id, copy) in &other.copies {
            match self.copies.get(id) {
                Some(mine) if mine >= copy => {}
                _ => {
                    self.copies.insert(*id, copy.clone());
                }
            }
        }
        self.normalize();
    }

    /// Drop the ciphertext of every retired backer. A state holding one is
    /// not canonical; a contract should refuse it in `verify` (the merge
    /// never produces one).
    pub fn normalize(&mut self) {
        let retired = &self.retired;
        self.copies.retain(|id, _| !retired.contains(&id.backer));
    }

    pub fn is_normalized(&self) -> bool {
        self.copies
            .keys()
            .all(|id| !self.retired.contains(&id.backer))
    }

    /// Add a copy (the caller signs the resulting update with the store key).
    pub fn add_copy(&mut self, id: CopyId, copy: WrappedStoreKey) -> Result<(), CustodyError> {
        copy.check_shape()?;
        if self.retired.contains(&id.backer) {
            return Err(CustodyError::Retired);
        }
        if !self.copies.contains_key(&id) && self.copies.len() >= MAX_WRAPPED_COPIES {
            return Err(CustodyError::TooManyCopies);
        }
        self.copies.insert(id, copy);
        Ok(())
    }

    /// Tombstone a backer: every copy it had is dropped, now and on merge.
    pub fn retire(&mut self, backer: &VerifyingKey) {
        self.retired.insert(backer.to_bytes());
        self.normalize();
    }

    /// Contract-side checks that need no key: shapes, canonical form, cap.
    pub fn check(&self) -> Result<(), CustodyError> {
        if !self.is_normalized() {
            return Err(CustodyError::Retired);
        }
        if self.copies.len() > MAX_WRAPPED_COPIES {
            return Err(CustodyError::TooManyCopies);
        }
        self.copies
            .values()
            .try_for_each(WrappedStoreKey::check_shape)
    }

    pub fn copy_for(&self, id: &CopyId) -> Option<&WrappedStoreKey> {
        self.copies.get(id)
    }
}

#[cfg(test)]
mod tests;
