//! The cryptography of store-key custody, behind the `custody` feature. See
//! the parent module for the mechanism.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{wrap_message, CustodyError, WrapScope, WrappedStoreKey, SCHEME_V1};

const WRAP_HKDF_SALT: &[u8] = b"harvest/store-key-wrap/v1/hkdf-salt";
const WRAP_HKDF_INFO: &[u8] = b"harvest/store-key-wrap/v1/aes-256-gcm-key+nonce";
const WRAP_AAD_LABEL: &[u8] = b"harvest/store-key-wrap/v1/aad";

const SUBKEY_HKDF_SALT: &[u8] = b"harvest/store-key/v1/subkeys";
const INBOX_INFO: &[u8] = b"harvest/store-key/v1/inbox-x25519";
const RECORD_INFO: &[u8] = b"harvest/store-key/v1/record-rsa-2048-seed";

impl WrapScope {
    pub(crate) fn requestor(&self) -> ghostkey_common::SignatureRequestor {
        ghostkey_common::SignatureRequestor::WebApp(
            freenet_stdlib::prelude::ContractInstanceId::new(self.0),
        )
    }
}

/// A vault signature over [`wrap_message`], checked and held as a secret.
///
/// No `Serialize`, no `Clone`, a redacted `Debug`, and zeroed on drop: the
/// type exists so the signature cannot be published, logged or copied by
/// accident. Construct it only through [`WrapSecret::from_sign_result`].
pub struct WrapSecret {
    pub(super) signature: Zeroizing<[u8; 64]>,
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
    ///   store details, an inbox entry, a backing statement) is refused;
    /// - it is canonically encoded, so encoding drift shows up as that and
    ///   not as an unexplained unwrap failure;
    /// - `signature` verifies (strictly) under the backing Ghost Key.
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

    /// `(key, nonce)` for AES-256-GCM.
    ///
    /// The nonce is derived, not random, which makes wrapping deterministic:
    /// two devices wrapping for the same backer produce the same bytes, so
    /// concurrent writes merge to one copy. That is safe because the key is
    /// unique to (signature, store, backer, scope) and the only plaintext ever
    /// sealed under it is the store's own seed, which the store key
    /// determines: the (key, nonce) pair never meets a second plaintext.
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
/// key; replaces the random-per-device `harvest:x25519_sk:<fp>` for a store.
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
/// CAVEAT, and why the public half is also published: RSA key generation is
/// an algorithm, not a function the `rsa` crate promises to keep stable. A
/// crate bump may generate a different key from the same seed. The
/// known-answer test pins today's output so a bump turns red, and the store
/// publishes the public key (`StoreInfoV1::record_public_key`) so another
/// device can check its own derivation against it rather than trust it
/// silently.
pub fn record_rsa_key(store_sk: &SigningKey) -> Result<rsa::RsaPrivateKey, CustodyError> {
    use rand_chacha::rand_core::SeedableRng;
    let seed = record_key_seed(store_sk);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
    rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|_| CustodyError::Malformed("rsa keygen"))
}

/// The DER (PKCS#1) of the store's record public key: what the store
/// publishes, and what the record contract's parameters carry.
pub fn record_public_key_der(store_sk: &SigningKey) -> Result<Vec<u8>, CustodyError> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    record_rsa_key(store_sk)?
        .to_public_key()
        .to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|_| CustodyError::Malformed("rsa public key encode"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// What a copy opens to is kept only if it IS the store's key: a copy
    /// sealed under this store's wrapping key over another key's seed (which
    /// only the store key's holder could make, since `wrap_store_key`
    /// refuses) is refused, not handed back. Mutated red by removing the
    /// check at the end of `unwrap_store_key`.
    #[test]
    fn a_copy_that_opens_to_another_key_is_refused() {
        let ghost = SigningKey::from_bytes(&[1; 32]);
        let store = SigningKey::from_bytes(&[2; 32]);
        let other = SigningKey::from_bytes(&[3; 32]);
        let scope = WrapScope::current();
        let scoped = ghostkey_common::to_cbor(&ghostkey_common::ScopedPayload {
            requestor: scope.requestor(),
            payload: wrap_message(&store.verifying_key()),
        })
        .unwrap();
        let signature = ghost.sign(&scoped).to_bytes();
        let secret = WrapSecret::from_sign_result(
            &scoped,
            &signature,
            &ghost.verifying_key(),
            &store.verifying_key(),
            scope,
        )
        .unwrap();
        let (key, nonce) = secret.aead_key_nonce();
        let ciphertext = Aes256Gcm::new_from_slice(key.as_slice())
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: other.to_bytes().as_slice(),
                    aad: &secret.aad(),
                },
            )
            .unwrap();
        let wrapped = WrappedStoreKey {
            scheme: SCHEME_V1,
            ciphertext,
        };
        assert_eq!(
            unwrap_store_key(&wrapped, &secret).unwrap_err(),
            CustodyError::NotThisStoresKey
        );
    }
}
