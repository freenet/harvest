use crate::secrets::RemovableSecrets;
use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::MessageOrigin;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2::Sha256;

use harvest_common::delegate::{
    HarvestDelegateRequest, HarvestDelegateResponse, StoreRegistration, TransactionRecord,
};
use harvest_common::{from_cbor, to_cbor};

// Secret key prefixes for delegate storage
fn rsa_sk_key(fp: &str) -> Vec<u8> {
    format!("harvest:rsa_sk:{fp}").into_bytes()
}
fn rsa_pk_key(fp: &str) -> Vec<u8> {
    format!("harvest:rsa_pk:{fp}").into_bytes()
}
fn tx_key(tx_id: &str) -> Vec<u8> {
    format!("harvest:tx:{tx_id}").into_bytes()
}
fn stores_key(fp: &str) -> Vec<u8> {
    format!("harvest:stores:{fp}").into_bytes()
}
pub(crate) const TX_INDEX_KEY: &[u8] = b"harvest:tx_index";

/// Every shape of secret key this delegate writes, for a sample fingerprint
/// and transaction id.
///
/// Exists so `migration`'s tests can assert that all of them fall under the
/// prefix an export covers. A key builder that stopped starting with
/// `harvest:` would be silently omitted from every future migration -- no
/// error, no warning, just a secret that does not arrive -- and nothing else
/// connects the two.
///
/// Keep in step with the builders above and with `crate::bitcoin`'s two
/// constants.
#[cfg(test)]
pub(crate) fn all_secret_key_shapes(fp: &str, tx_id: &str) -> Vec<Vec<u8>> {
    vec![
        rsa_sk_key(fp),
        rsa_pk_key(fp),
        tx_key(tx_id),
        stores_key(fp),
        crate::messaging::x25519_sk_key(fp),
        TX_INDEX_KEY.to_vec(),
        crate::bitcoin::BITCOIN_WATCHES_KEY.to_vec(),
        crate::bitcoin::BITCOIN_BRIDGE_KEY.to_vec(),
        crate::bitcoin::BITCOIN_PAYMENT_XPUB_KEY.to_vec(),
        crate::markers::marker_secret_key("v1.store.aa.bb"),
        crate::messaging::buyer_conversation_key(&[3u8; 32], &[4u8; 32]),
        crate::known_stores::known_store_key("3Bn8xWqLd6Tz9Kf2"),
        crate::store_keys::store_key_secret(
            &ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]).verifying_key(),
        ),
        crate::store_keys::creation_secret(fp),
    ]
}

fn load_tx_index<S: SecretStore>(store: &S) -> Vec<String> {
    store
        .get_secret(TX_INDEX_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_tx_index<S: SecretStore>(store: &mut S, index: &[String]) {
    if let Ok(bytes) = to_cbor(&index) {
        store.set_secret(TX_INDEX_KEY, &bytes);
    }
}

/// Answer one Harvest request, for the Harvest web app only.
///
/// # Why every variant below is behind the gate, reads included
///
/// The writes are the obvious half. `InitReputationKeys` mints an RSA key the
/// store's whole reputation identity then rests on; `BeginTransaction` and
/// `RecordBlindSignature` write the transaction ledger; `RegisterStore` decides
/// which contracts the seller's UI will treat as their own stores;
/// `SetMigrationMarker` can seal a migration as done that never ran, which
/// loses data silently rather than loudly (see [`crate::markers`]).
/// `BlindSignFeedbackToken` is the sharpest of them: it signs caller-supplied
/// bytes with the seller's reputation key, so an ungated caller gets a signing
/// oracle for an identity that is not theirs.
///
/// The reads are gated for the same reason as `crate::bitcoin`'s: each hands
/// back something whose value is that it is private. `ListStores` and
/// `ListTransactions` are the seller's commercial history -- which stores are
/// theirs, who they have traded with -- and `GetRsaPublicKey` plus
/// `GetMigrationMarker` let a caller confirm which pseudonymous ghostkey
/// fingerprints and which store generations belong to this one user, which is
/// exactly the linkage a pseudonymous marketplace exists to avoid.
///
/// No caller outside the Harvest web app is broken by this, because none
/// exists: this delegate is Harvest's own, and nothing else is expected to
/// speak `HarvestDelegateRequest`.
pub fn handle<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    origin: Option<&MessageOrigin>,
    request: HarvestDelegateRequest,
) -> HarvestDelegateResponse {
    // A refusal is reported rather than swallowed: a caller that got a
    // plausible-looking empty answer would be indistinguishable, to whoever is
    // reading the node's log later, from one that legitimately had no data.
    if let Err(refusal) = crate::origin::authorize(origin) {
        return HarvestDelegateResponse::Error {
            message: match refusal {
                freenet_stdlib::prelude::DelegateError::Other(message) => message,
                other => format!("{other:?}"),
            },
        };
    }

    match request {
        HarvestDelegateRequest::InitReputationKeys {
            ghostkey_fingerprint,
        } => handle_init_reputation_keys(store, &ghostkey_fingerprint),

        HarvestDelegateRequest::GetRsaPublicKey {
            ghostkey_fingerprint,
        } => handle_get_rsa_public_key(store, &ghostkey_fingerprint),

        HarvestDelegateRequest::BlindSignFeedbackToken {
            request_id,
            ghostkey_fingerprint,
            blinded_token,
        } => handle_blind_sign(store, request_id, &ghostkey_fingerprint, &blinded_token),

        HarvestDelegateRequest::CreateListing { request_id, .. } => {
            // Listing creation requires calling the ghostkey delegate for signing.
            // For now, return an error -- this will be implemented when we add
            // inter-delegate communication support.
            HarvestDelegateResponse::ListingCreated {
                request_id,
                result: Err("listing creation via delegate not yet implemented -- sign listings from the UI via ghostkey delegate directly".into()),
            }
        }

        HarvestDelegateRequest::BeginTransaction {
            request_id,
            transaction_id,
            our_token,
            our_blinded_token,
        } => handle_begin_transaction(
            store,
            request_id,
            &transaction_id,
            our_token,
            our_blinded_token,
        ),

        HarvestDelegateRequest::RecordBlindSignature {
            request_id,
            transaction_id,
            blind_signature,
        } => handle_record_blind_signature(store, request_id, &transaction_id, blind_signature),

        HarvestDelegateRequest::ListTransactions => handle_list_transactions(store),

        // Buyer-to-seller messaging. `messaging` owns the secret and the
        // Diffie-Hellman; this is only the routing, the same shape as the
        // migration markers below.
        //
        // Both are gated by the `authorize` above -- and by the one in
        // `lib.rs::handle_request`, which every request family passes
        // through, so a new family is gated by arriving rather than by
        // somebody remembering. `DeriveConversationKeys` is a read of the
        // seller's private correspondence and `InitEncryptionKey` decides
        // which key buyers will encrypt to, so neither may be reached by
        // another web app.
        HarvestDelegateRequest::InitEncryptionKey {
            ghostkey_fingerprint,
        } => crate::messaging::init_encryption_key(store, &ghostkey_fingerprint),

        HarvestDelegateRequest::DeriveConversationKeys {
            request_id,
            ghostkey_fingerprint,
            peer_public_keys,
            store_verifying_key,
        } => crate::messaging::derive_conversation_keys(
            store,
            request_id,
            &ghostkey_fingerprint,
            &peer_public_keys,
            store_verifying_key,
        ),

        // The buyer's half of messaging: the secrets that make a seller's
        // reply readable after the tab that asked the question is gone.
        //
        // Gated like everything else, and it matters here in a direction the
        // seller's half does not have. `ListBuyerConversations` answers the
        // conversation keys for every conversation this node has had with a
        // store, so an ungated caller could read a buyer's private
        // correspondence out of a public mailbox; `ForgetBuyerConversation`
        // destroys a capability that exists nowhere else.
        HarvestDelegateRequest::StoreBuyerConversation {
            request_id,
            store_contract_id,
            secret,
            seller_public_key,
            conversation_id,
            created_at,
        } => crate::messaging::store_buyer_conversation(
            store,
            request_id,
            &store_contract_id,
            &crate::messaging::BuyerConversationRecord {
                secret,
                seller_public_key,
                conversation_id,
                created_at,
                // Never true on the way in: a conversation is backed up when
                // the buyer says they have saved it, not when it is created,
                // and it was opened here rather than restored.
                backed_up: false,
                imported: false,
            },
        ),

        HarvestDelegateRequest::ListBuyerConversations {
            request_id,
            store_contract_id,
        } => crate::messaging::list_buyer_conversations(store, request_id, &store_contract_id),

        // Backup. The export answers the secrets themselves, so its need for
        // the gate is obvious. `MarkConversationsBackedUp` is the one whose
        // need is NOT obvious and matters as much: it silences the warning
        // that a conversation exists in one place only, and the party that
        // benefits from silence is not the party that loses the
        // conversation. An app that could set it without the user holding a
        // backup would stop the warning for a conversation about to be lost
        // with the machine -- worse than never warning, because the buyer
        // stops looking. Same reasoning as the ghostkey vault gating
        // `MarkBackedUp` on the `Export` scope only it is granted.
        HarvestDelegateRequest::ExportBuyerConversation {
            request_id,
            store_contract_id,
            buyer_public_key,
        } => crate::messaging::export_buyer_conversation(
            store,
            request_id,
            &store_contract_id,
            &buyer_public_key,
        ),

        HarvestDelegateRequest::ImportBuyerConversation { request_id, backup } => {
            crate::messaging::import_buyer_conversation(store, request_id, &backup.0)
        }

        HarvestDelegateRequest::MarkConversationBackedUp {
            request_id,
            store_contract_id,
            buyer_public_key,
        } => crate::messaging::mark_conversation_backed_up(
            store,
            request_id,
            &store_contract_id,
            &buyer_public_key,
        ),

        HarvestDelegateRequest::ForgetBuyerConversation {
            request_id,
            store_contract_id,
            buyer_public_key,
        } => crate::messaging::forget_buyer_conversation(
            store,
            request_id,
            &store_contract_id,
            &buyer_public_key,
        ),

        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint,
            store_contract_id,
            reputation_contract_id,
            mailbox_contract_id,
            store_verifying_key,
        } => handle_register_store(
            store,
            &ghostkey_fingerprint,
            StoreRegistration {
                store_contract_id,
                reputation_contract_id,
                mailbox_contract_id,
                store_contract_key: None,
                store_verifying_key,
            },
        ),

        HarvestDelegateRequest::ListStores {
            ghostkey_fingerprint,
        } => handle_list_stores(store, &ghostkey_fingerprint),

        // The migration repeat-gate. `markers` owns both the namespace and the
        // fail-safe direction; this is only the routing.
        HarvestDelegateRequest::GetMigrationMarker { marker } => {
            crate::markers::get_marker(store, &marker)
        }

        HarvestDelegateRequest::SetMigrationMarker { marker, note } => {
            crate::markers::set_marker(store, &marker, &note)
        }

        // Importing a predecessor delegate's secrets (harvest#123). Gated like
        // everything else, and it matters most here: an import writes
        // secrets, private keys included. `import` owns the per-family rules.
        HarvestDelegateRequest::GetPredecessorMarker { predecessor } => {
            crate::import::get_marker(store, predecessor)
        }

        HarvestDelegateRequest::RecordPredecessorMarker {
            predecessor,
            marker,
        } => crate::import::record_marker(store, predecessor, marker),

        HarvestDelegateRequest::ImportMigratedSecret {
            predecessor,
            key,
            value,
        } => crate::import::import(store, predecessor, key, &value.0),

        // The stores this node has visited. Gated like everything else: the
        // list is a record of which sellers this user has dealt with, which
        // is exactly the linkage a pseudonymous marketplace keeps private.
        HarvestDelegateRequest::RememberStore { store_code } => {
            crate::known_stores::remember(store, &store_code)
        }

        HarvestDelegateRequest::SetStoreArchived {
            store_code,
            archived,
        } => crate::known_stores::set_archived(store, &store_code, archived),

        HarvestDelegateRequest::ListRememberedStores => crate::known_stores::list(store),

        // Store keys (harvest#93). Behind the same gate as everything else,
        // and the gate matters most here: `SignStoreUpdate` signs for a whole
        // store, so an ungated caller would own it.
        HarvestDelegateRequest::CreateStoreKey {
            request_id,
            ghostkey_fingerprint,
            another_store,
        } => {
            // Section 6.2 across the device (see `CreateStoreKey`): a Ghost
            // Key with a registered store-key store gets no NEW key unless
            // the seller asked for another store. Its unfinished creation,
            // if any, is still resumed.
            if let Some(fp) = ghostkey_fingerprint.as_deref() {
                if !another_store
                    && crate::store_keys::unfinished_creation(store, fp).is_none()
                    && load_stores(store, fp)
                        .iter()
                        .any(|s| s.store_verifying_key.is_some())
                {
                    return HarvestDelegateResponse::StoreKeyCreated {
                        request_id,
                        result: Err("this Ghost Key already backs a store on this device. A \
                                     Ghost Key backs one store at a time: use a different \
                                     Ghost Key, or open a second store under this one on \
                                     purpose"
                            .into()),
                    };
                }
            }
            crate::store_keys::create(store, request_id, ghostkey_fingerprint.as_deref())
        }

        HarvestDelegateRequest::SignStoreUpdate {
            request_id,
            store_verifying_key,
            payload,
        } => crate::store_keys::sign(store, request_id, store_verifying_key, payload),

        // Custody (harvest#93 phase 1b). The gate matters as much here: an
        // unwrap writes a store key, and a wrap signs a copy with one.
        HarvestDelegateRequest::WrapStoreKeyFor {
            request_id,
            store_verifying_key,
            backer_verifying_key,
            scoped_payload,
            signature,
        } => crate::store_keys::wrap_for(
            store,
            request_id,
            store_verifying_key,
            backer_verifying_key,
            &scoped_payload,
            &signature.0,
        ),

        HarvestDelegateRequest::UnwrapStoreKey {
            request_id,
            store_verifying_key,
            backer_verifying_key,
            scoped_payload,
            signature,
            wrapped,
        } => crate::store_keys::unwrap(
            store,
            request_id,
            store_verifying_key,
            backer_verifying_key,
            &scoped_payload,
            &signature.0,
            &wrapped,
        ),

        HarvestDelegateRequest::GetStoreSubkeys {
            request_id,
            store_verifying_key,
        } => crate::store_keys::subkeys(store, request_id, store_verifying_key),

        _ => HarvestDelegateResponse::Error {
            message: "unsupported request variant for this delegate version".into(),
        },
    }
}

fn handle_init_reputation_keys<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    // Check if keys already exist
    if store
        .get_secret(&rsa_pk_key(ghostkey_fingerprint))
        .is_some()
    {
        // Return existing public key
        return match store.get_secret(&rsa_pk_key(ghostkey_fingerprint)) {
            Some(pk_der) => HarvestDelegateResponse::ReputationKeysInitialized {
                ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
                rsa_public_key_der: pk_der,
            },
            None => HarvestDelegateResponse::Error {
                message: "RSA public key not found after existence check".into(),
            },
        };
    }

    // Generate a new RSA-2048 keypair for blind signing
    // Use getrandom for the RNG in WASM context
    let mut rng = rsa::rand_core::OsRng;
    let private_key = match rsa::RsaPrivateKey::new(&mut rng, 2048) {
        Ok(k) => k,
        Err(e) => {
            return HarvestDelegateResponse::Error {
                message: format!("RSA key generation failed: {e}"),
            }
        }
    };

    let public_key = private_key.to_public_key();

    // Serialize keys to DER
    let sk_der = match private_key.to_pkcs1_der() {
        Ok(d) => d.as_bytes().to_vec(),
        Err(e) => {
            return HarvestDelegateResponse::Error {
                message: format!("serialize RSA private key: {e}"),
            }
        }
    };

    let pk_der = match public_key.to_pkcs1_der() {
        Ok(d) => d.as_bytes().to_vec(),
        Err(e) => {
            return HarvestDelegateResponse::Error {
                message: format!("serialize RSA public key: {e}"),
            }
        }
    };

    // Store both keys
    store.set_secret(&rsa_sk_key(ghostkey_fingerprint), &sk_der);
    store.set_secret(&rsa_pk_key(ghostkey_fingerprint), &pk_der);

    HarvestDelegateResponse::ReputationKeysInitialized {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        rsa_public_key_der: pk_der,
    }
}

fn handle_get_rsa_public_key<S: SecretStore>(
    store: &S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    match store.get_secret(&rsa_pk_key(ghostkey_fingerprint)) {
        Some(pk_der) => HarvestDelegateResponse::RsaPublicKey {
            ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
            rsa_public_key_der: pk_der,
        },
        None => HarvestDelegateResponse::Error {
            message: format!(
                "no RSA keys for ghostkey {ghostkey_fingerprint} -- call InitReputationKeys first"
            ),
        },
    }
}

/// Blind-sign a feedback token with the Ghost Key's per-device RSA key.
///
/// KNOWN GAP (harvest#93 phase 1b, #99 review): a store created since phase
/// 1b addresses its record contract by the record key its STORE KEY derives
/// (`custody::record_rsa_key`), not by this per-device key, so a token signed
/// here would not verify against that record. Nothing reaches this today:
/// feedback submission is not wired (#53). The store-key path belongs with
/// that work; recorded in `docs/untested-invariants.md`.
fn handle_blind_sign<S: SecretStore>(
    store: &S,
    request_id: u64,
    ghostkey_fingerprint: &str,
    blinded_token: &[u8],
) -> HarvestDelegateResponse {
    // Load RSA private key
    let sk_der = match store.get_secret(&rsa_sk_key(ghostkey_fingerprint)) {
        Some(b) => b,
        None => {
            return HarvestDelegateResponse::BlindSignatureResult {
                request_id,
                result: Err(format!("no RSA keys for ghostkey {ghostkey_fingerprint}")),
            }
        }
    };

    let private_key = match rsa::RsaPrivateKey::from_pkcs1_der(&sk_der) {
        Ok(k) => k,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureResult {
                request_id,
                result: Err(format!("deserialize RSA private key: {e}")),
            }
        }
    };

    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);

    // Blind-sign the token
    let mut rng = rsa::rand_core::OsRng;
    let signature = match signing_key.try_sign_with_rng(&mut rng, blinded_token) {
        Ok(sig) => sig,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureResult {
                request_id,
                result: Err(format!("blind signing failed: {e}")),
            }
        }
    };

    HarvestDelegateResponse::BlindSignatureResult {
        request_id,
        result: Ok(signature.to_bytes().to_vec()),
    }
}

fn handle_begin_transaction<S: SecretStore>(
    store: &mut S,
    request_id: u64,
    transaction_id: &str,
    our_token: harvest_common::FeedbackToken,
    our_blinded_token: Vec<u8>,
) -> HarvestDelegateResponse {
    let record = TransactionRecord {
        transaction_id: transaction_id.to_string(),
        our_token,
        our_blinded_token,
        blind_signature: None,
        // A delegate MAY read the host clock -- unlike a contract, whose
        // verdict must be a pure function of its inputs. This uses the host's
        // clock via the runtime rather than chrono's `wasmbind` backend, which
        // would make the module unloadable.
        created_at: freenet_stdlib::time::now(),
    };

    let record_bytes = match to_cbor(&record) {
        Ok(b) => b,
        Err(e) => {
            return HarvestDelegateResponse::TransactionRecorded {
                request_id,
                result: Err(format!("serialize transaction: {e}")),
            }
        }
    };

    store.set_secret(&tx_key(transaction_id), &record_bytes);

    // Update index
    let mut index = load_tx_index(store);
    if !index.contains(&transaction_id.to_string()) {
        index.push(transaction_id.to_string());
        save_tx_index(store, &index);
    }

    HarvestDelegateResponse::TransactionRecorded {
        request_id,
        result: Ok(()),
    }
}

fn handle_record_blind_signature<S: SecretStore>(
    store: &mut S,
    request_id: u64,
    transaction_id: &str,
    blind_signature: Vec<u8>,
) -> HarvestDelegateResponse {
    let record_bytes = match store.get_secret(&tx_key(transaction_id)) {
        Some(b) => b,
        None => {
            return HarvestDelegateResponse::BlindSignatureRecorded {
                request_id,
                result: Err(format!("transaction {transaction_id} not found")),
            }
        }
    };

    let mut record: TransactionRecord = match from_cbor(&record_bytes) {
        Ok(r) => r,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureRecorded {
                request_id,
                result: Err(format!("deserialize transaction: {e}")),
            }
        }
    };

    record.blind_signature = Some(blind_signature);

    let updated_bytes = match to_cbor(&record) {
        Ok(b) => b,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureRecorded {
                request_id,
                result: Err(format!("serialize updated transaction: {e}")),
            }
        }
    };

    store.set_secret(&tx_key(transaction_id), &updated_bytes);

    HarvestDelegateResponse::BlindSignatureRecorded {
        request_id,
        result: Ok(()),
    }
}

fn handle_list_transactions<S: SecretStore>(store: &S) -> HarvestDelegateResponse {
    let index = load_tx_index(store);
    let mut transactions = Vec::new();

    for tx_id in &index {
        if let Some(bytes) = store.get_secret(&tx_key(tx_id)) {
            if let Ok(record) = from_cbor::<TransactionRecord>(&bytes) {
                transactions.push(record);
            }
        }
    }

    HarvestDelegateResponse::TransactionList { transactions }
}

fn load_stores<S: SecretStore>(store: &S, ghostkey_fingerprint: &str) -> Vec<StoreRegistration> {
    store
        .get_secret(&stores_key(ghostkey_fingerprint))
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_stores<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
    stores: &[StoreRegistration],
) {
    if let Ok(bytes) = to_cbor(&stores) {
        store.set_secret(&stores_key(ghostkey_fingerprint), &bytes);
    }
}

fn handle_register_store<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
    registration: StoreRegistration,
) -> HarvestDelegateResponse {
    let mut stores = load_stores(store, ghostkey_fingerprint);
    // A registered store ends the creation that minted its key, so the next
    // `CreateStoreKey` for this Ghost Key mints a new one (#98 review, M1).
    let finished = registration.store_verifying_key;

    // Check for duplicate (same store contract)
    if stores
        .iter()
        .any(|s| s.store_contract_id == registration.store_contract_id)
    {
        if let Some(key) = finished {
            crate::store_keys::finish_creation(store, ghostkey_fingerprint, &key);
        }
        return HarvestDelegateResponse::StoreRegistered {
            ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        };
    }

    stores.push(registration);
    save_stores(store, ghostkey_fingerprint, &stores);
    if let Some(key) = finished {
        crate::store_keys::finish_creation(store, ghostkey_fingerprint, &key);
    }

    HarvestDelegateResponse::StoreRegistered {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
    }
}

fn handle_list_stores<S: SecretStore>(
    store: &S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    let stores = load_stores(store, ghostkey_fingerprint);
    HarvestDelegateResponse::StoreList {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        stores,
    }
}

// ---------------------------------------------------------------------------
// Origin gating.
//
// Driven through `handle` against a real in-memory store, so the assertions
// are about what is left in the store afterwards rather than merely about what
// was returned.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod origin_gating_tests {
    use super::*;
    use crate::origin::test_origins::{a_different_web_app, harvest};
    use crate::secrets::MemSecrets;

    const FINGERPRINT: &str = "fp1";

    /// The store the attacker would like registered under the seller's
    /// fingerprint, and the seller's own. They differ, so an assertion that
    /// only one of them is present can actually fail.
    const ATTACKERS_STORE: [u8; 4] = [0xaa, 0xaa, 0xaa, 0xaa];
    const SELLERS_STORE: [u8; 4] = [0xbb, 0xbb, 0xbb, 0xbb];

    fn register(store_contract_id: [u8; 4]) -> HarvestDelegateRequest {
        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            store_contract_id: store_contract_id.to_vec(),
            reputation_contract_id: vec![1],
            mailbox_contract_id: vec![2],
            store_verifying_key: None,
        }
    }

    fn refusal_message(response: &HarvestDelegateResponse) -> &str {
        match response {
            HarvestDelegateResponse::Error { message } => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The registry decides which contracts the seller's own UI will treat as
    /// their stores, so a foreign write here is a way to put an attacker's
    /// contract in front of the seller as if it were their own.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    #[test]
    fn another_web_app_cannot_register_a_store() {
        let mut store = MemSecrets::default();

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            register(ATTACKERS_STORE),
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "the refusal must say why: {}",
            refusal_message(&response)
        );
        assert!(
            store.is_empty(),
            "a foreign web app wrote to the delegate's secret store"
        );

        // The genuine caller still works, and registers a DIFFERENT store --
        // so this half would fail if the write had silently done nothing.
        match handle(&mut store, Some(&harvest()), register(SELLERS_STORE)) {
            HarvestDelegateResponse::StoreRegistered { .. } => {}
            other => panic!("the Harvest web app must be able to register: {other:?}"),
        }
        match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::ListStores {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
        ) {
            HarvestDelegateResponse::StoreList { stores, .. } => {
                let ids: Vec<Vec<u8>> =
                    stores.iter().map(|s| s.store_contract_id.clone()).collect();
                assert_eq!(ids, vec![SELLERS_STORE.to_vec()], "wrong registry contents");
            }
            other => panic!("expected a StoreList, got {other:?}"),
        }
    }

    /// A store key signs for a whole store, so the gate is the whole of what
    /// stops another web app granted access to this node from publishing
    /// listings, invoices or a closure in the seller's name. Neither minting
    /// nor signing answers anyone but Harvest.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    /// Registering the store ends its creation: the same `CreateStoreKey`
    /// answered the same key before; after, a NEW key is refused unless the
    /// seller asks for another store (#98 review M1 and re-check). Mutated
    /// red by not finishing in `handle_register_store` and by removing the
    /// refusal.
    #[test]
    fn registering_a_store_ends_its_resumable_creation() {
        let mut store = MemSecrets::default();
        let first = mint(&mut store, 1, false).unwrap();
        assert_eq!(mint(&mut store, 2, false).unwrap(), first);
        register_as(&mut store, vec![7; 32], Some(first));
        let refused = mint(&mut store, 3, false).expect_err("one store per Ghost Key");
        assert!(refused.contains("already backs a store"), "{refused}");
        let second = mint(&mut store, 4, true).expect("asked for on purpose");
        assert_ne!(second, first);
    }

    /// The duplicate-registration branch ends the creation too: a store
    /// registered first without its key (an older UI) and again with it.
    /// Mutated red by not finishing on that branch.
    #[test]
    fn a_repeated_registration_naming_the_key_ends_the_creation() {
        let mut store = MemSecrets::default();
        let first = mint(&mut store, 1, false).unwrap();
        register_as(&mut store, vec![7; 32], None);
        assert_eq!(
            mint(&mut store, 2, false).unwrap(),
            first,
            "not finished yet"
        );
        register_as(&mut store, vec![7; 32], Some(first));
        assert!(
            crate::store_keys::unfinished_creation(&store, FINGERPRINT).is_none(),
            "finished by the duplicate registration"
        );
    }

    fn mint(store: &mut MemSecrets, id: u64, another_store: bool) -> Result<[u8; 32], String> {
        match handle(
            store,
            Some(&harvest()),
            HarvestDelegateRequest::CreateStoreKey {
                request_id: id,
                ghostkey_fingerprint: Some(FINGERPRINT.to_string()),
                another_store,
            },
        ) {
            HarvestDelegateResponse::StoreKeyCreated { result, .. } => result,
            other => panic!("expected a store key answer, got {other:?}"),
        }
    }

    fn register_as(store: &mut MemSecrets, id: Vec<u8>, key: Option<[u8; 32]>) {
        handle(
            store,
            Some(&harvest()),
            HarvestDelegateRequest::RegisterStore {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
                store_contract_id: id,
                reputation_contract_id: vec![1],
                mailbox_contract_id: vec![2],
                store_verifying_key: key,
            },
        );
    }

    #[test]
    fn another_web_app_can_neither_mint_nor_use_a_store_key() {
        let mut store = MemSecrets::default();
        let refused = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::CreateStoreKey {
                request_id: 1,
                ghostkey_fingerprint: None,
                another_store: false,
            },
        );
        assert!(refusal_message(&refused).contains("Harvest web app"));
        assert!(store.is_empty(), "a foreign web app minted a store key");

        // Harvest mints one; the foreign app still cannot sign with it.
        let store_key = match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::CreateStoreKey {
                request_id: 2,
                ghostkey_fingerprint: None,
                another_store: false,
            },
        ) {
            HarvestDelegateResponse::StoreKeyCreated {
                result: Ok(key), ..
            } => key,
            other => panic!("Harvest must be able to mint a store key: {other:?}"),
        };
        let closure = harvest_common::backing::StoreClosure {
            store: ed25519_dalek::VerifyingKey::from_bytes(&store_key).unwrap(),
        };
        let sign = |request_id| HarvestDelegateRequest::SignStoreUpdate {
            request_id,
            store_verifying_key: store_key,
            payload: to_cbor(&closure).unwrap(),
        };
        let refused = handle(&mut store, Some(&a_different_web_app()), sign(3));
        assert!(refusal_message(&refused).contains("Harvest web app"));
        match handle(&mut store, Some(&harvest()), sign(4)) {
            HarvestDelegateResponse::StoreUpdateSigned { result: Ok(_), .. } => {}
            other => panic!("Harvest must be able to sign with its store key: {other:?}"),
        }
    }

    /// An unattested caller is refused as well.
    #[test]
    fn an_unattested_caller_cannot_register_a_store() {
        let mut store = MemSecrets::default();
        let response = handle(&mut store, None, register(ATTACKERS_STORE));
        assert!(refusal_message(&response).contains("could not attest"));
        assert!(store.is_empty(), "an unattested caller wrote a secret");
    }

    /// Reads are gated too: which stores and which transactions are this
    /// user's is the linkage a pseudonymous marketplace exists to withhold.
    #[test]
    fn another_web_app_cannot_read_the_sellers_registry_or_ledger() {
        let mut store = MemSecrets::default();
        handle(&mut store, Some(&harvest()), register(SELLERS_STORE));

        for request in [
            HarvestDelegateRequest::ListStores {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
            HarvestDelegateRequest::ListTransactions,
            HarvestDelegateRequest::GetRsaPublicKey {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
        ] {
            let response = handle(&mut store, Some(&a_different_web_app()), request);
            assert!(
                refusal_message(&response).contains("Harvest web app"),
                "a foreign web app read Harvest's private state"
            );
        }
    }

    /// The stores a buyer has visited are a list of who they have dealt
    /// with, and archiving is theirs to decide: another web app can neither
    /// read the list nor change it (harvest#52).
    #[test]
    fn another_web_app_cannot_read_or_change_the_remembered_stores() {
        let mut store = MemSecrets::default();
        let listed = handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::RememberStore {
                store_code: "3Bn8xWqLd6Tz9Kf2".to_string(),
            },
        );
        assert!(
            matches!(listed, HarvestDelegateResponse::RememberedStores { ref stores } if stores.len() == 1),
            "the Harvest web app remembers a store through the handler: {listed:?}"
        );
        let before = store.list_secrets(b"");

        for request in [
            HarvestDelegateRequest::ListRememberedStores,
            HarvestDelegateRequest::RememberStore {
                store_code: "Qp5vMe7RkT2cHw4n".to_string(),
            },
            HarvestDelegateRequest::SetStoreArchived {
                store_code: "3Bn8xWqLd6Tz9Kf2".to_string(),
                archived: true,
            },
        ] {
            let response = handle(&mut store, Some(&a_different_web_app()), request);
            assert!(
                refusal_message(&response).contains("Harvest web app"),
                "a foreign web app reached the remembered stores: {response:?}"
            );
        }
        assert_eq!(store.list_secrets(b""), before, "and nothing changed");
    }

    /// The seller's messaging key, both halves of the exposure.
    ///
    /// `InitEncryptionKey` decides which key every future buyer encrypts to,
    /// so a foreign caller reaching it before the seller does gets to publish
    /// a key of its own choosing under the seller's identity.
    /// `DeriveConversationKeys` is a Diffie-Hellman oracle against the
    /// seller's long-term secret, which is to say it is a read of the
    /// seller's entire private correspondence.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    #[test]
    fn another_web_app_cannot_mint_or_use_the_sellers_encryption_key() {
        let mut store = MemSecrets::default();

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::InitEncryptionKey {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "a foreign web app minted the seller's encryption key"
        );
        assert!(store.is_empty(), "a foreign web app wrote a secret");

        // The seller mints it for real, so the assertions above are not
        // passing because the request does nothing.
        let seller_key = match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::InitEncryptionKey {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
        ) {
            HarvestDelegateResponse::EncryptionKeyReady {
                x25519_public_key, ..
            } => x25519_public_key,
            other => panic!("the seller must be able to mint their key: {other:?}"),
        };
        assert_eq!(seller_key.len(), 32);

        // And now that a secret exists, the oracle is refused too -- which is
        // the half that would otherwise read the seller's messages.
        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::DeriveConversationKeys {
                request_id: 1,
                ghostkey_fingerprint: FINGERPRINT.to_string(),
                peer_public_keys: vec![vec![9u8; 32]],
                store_verifying_key: None,
            },
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "a foreign web app derived a conversation key against the seller's secret"
        );
    }

    /// A marker sealed by a foreign caller would report a migration as already
    /// done that never ran, which loses the seller's data silently.
    #[test]
    fn another_web_app_cannot_seal_a_migration_marker() {
        let mut store = MemSecrets::default();
        let marker = "v1.store.aabb.ccdd";

        handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::SetMigrationMarker {
                marker: marker.to_string(),
                note: "sealed by nobody".into(),
            },
        );
        assert!(store.is_empty(), "a foreign web app sealed a marker");

        // Sealing it for real does write, so the assertion above is not
        // passing because the request is inert.
        handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::SetMigrationMarker {
                marker: marker.to_string(),
                note: "recovered".into(),
            },
        );
        assert!(!store.is_empty(), "the seller could not seal their marker");
    }

    /// The buyer's conversations, reached the way the UI reaches them.
    ///
    /// `handle` is what the wire arrives at, so this is the boundary that
    /// matters: a store that only ever exercised `messaging`'s functions
    /// directly would say nothing about whether the request variants are
    /// routed at all.
    fn store_conversation(secret: [u8; 32], seller: [u8; 32]) -> HarvestDelegateRequest {
        HarvestDelegateRequest::StoreBuyerConversation {
            request_id: 1,
            store_contract_id: SELLERS_STORE_ID.to_vec(),
            secret: harvest_common::ConversationSecret(secret),
            seller_public_key: seller,
            conversation_id: [5u8; 32],
            created_at: 1_700_000_000,
        }
    }

    /// A 32-byte store id, which `StoreBuyerConversation` requires -- the
    /// 4-byte ids the registration tests use are deliberately not contract
    /// ids.
    const SELLERS_STORE_ID: [u8; 32] = [0xbb; 32];

    fn buyer_conversations(store: &MemSecrets) -> Vec<Vec<u8>> {
        store.list_secrets(crate::messaging::BUYER_CONVERSATION_PREFIX)
    }

    /// **A buyer's conversation survives the round trip through `handle`.**
    ///
    /// Stored through the handler, recalled through the handler, and the keys
    /// that come back are the ones the SELLER derives -- which is what makes
    /// them able to read the thread rather than merely well-formed.
    #[test]
    fn a_buyer_conversation_is_stored_and_recalled_through_the_handler() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut store = MemSecrets::default();
        let buyer = StaticSecret::from([23u8; 32]);
        let seller = StaticSecret::from([77u8; 32]);
        let seller_public = *PublicKey::from(&seller).as_bytes();

        match handle(
            &mut store,
            Some(&harvest()),
            store_conversation(buyer.to_bytes(), seller_public),
        ) {
            HarvestDelegateResponse::BuyerConversationStored { result, .. } => {
                result.expect("must store")
            }
            other => panic!("expected BuyerConversationStored, got {other:?}"),
        }

        let recalled = match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::ListBuyerConversations {
                request_id: 3,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
            },
        ) {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => conversations,
            other => panic!("expected BuyerConversationList, got {other:?}"),
        };
        assert_eq!(recalled.len(), 1);

        let shared = seller
            .diffie_hellman(&PublicKey::from(recalled[0].buyer_public_key))
            .to_bytes();
        assert_eq!(
            recalled[0].buyer_to_seller,
            harvest_common::mailbox::conversation_key_from_dh(
                &shared,
                harvest_common::mailbox::MessageDirection::BuyerToSeller
            ),
            "the recalled key is not the one the seller derives, so it reads nothing"
        );

        // And forgetting it, through the handler, removes it.
        match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::ForgetBuyerConversation {
                request_id: 2,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
                buyer_public_key: recalled[0].buyer_public_key,
            },
        ) {
            HarvestDelegateResponse::BuyerConversationForgotten { result, .. } => {
                result.expect("must forget")
            }
            other => panic!("expected BuyerConversationForgotten, got {other:?}"),
        }
        assert!(
            buyer_conversations(&store).is_empty(),
            "the conversation survived a forget issued through the handler"
        );
    }

    /// **A foreign web app can neither read nor destroy a buyer's
    /// conversations.**
    ///
    /// Sharper than the seller-side reads this module already covers.
    /// `ListBuyerConversations` hands back the keys that decrypt this buyer's
    /// half of a public mailbox, and `ForgetBuyerConversation` destroys a
    /// capability that exists in exactly one place -- after Phase 2, the
    /// buyer's only means of complaining about the seller they paid.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    #[test]
    fn another_web_app_cannot_read_or_destroy_a_buyers_conversations() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut store = MemSecrets::default();
        let buyer = StaticSecret::from([31u8; 32]);
        let tag = *PublicKey::from(&buyer).as_bytes();
        handle(
            &mut store,
            Some(&harvest()),
            store_conversation(buyer.to_bytes(), [3u8; 32]),
        );
        assert_eq!(buyer_conversations(&store).len(), 1, "precondition");

        // A conversation of the attacker's own, which must not be kept.
        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            store_conversation([41u8; 32], [3u8; 32]),
        );
        assert!(refusal_message(&response).contains("Harvest web app"));
        assert_eq!(
            buyer_conversations(&store).len(),
            1,
            "a foreign web app wrote a buyer conversation"
        );

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::ListBuyerConversations {
                request_id: 3,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
            },
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "a foreign web app read a buyer's conversation keys"
        );

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::ForgetBuyerConversation {
                request_id: 9,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
                buyer_public_key: tag,
            },
        );
        assert!(refusal_message(&response).contains("Harvest web app"));
        assert_eq!(
            buyer_conversations(&store).len(),
            1,
            "a foreign web app destroyed a buyer's only copy of their conversation key"
        );
    }

    /// **A foreign web app cannot carry a buyer's conversations off, nor
    /// silence the warning that they exist in one place only.**
    ///
    /// The export half is the obvious one: it answers the secrets, which are
    /// the capability to read the conversation and, after Phase 2, to file
    /// the complaint it authorizes.
    ///
    /// The MARKER half is the one worth having its own test. It writes no
    /// secret and answers none, so it reads as harmless -- and what it does
    /// is stop the UI saying "this exists only on this device" about a
    /// conversation nobody has a copy of. Silence costs the buyer everything
    /// and costs the app nothing, which is exactly the shape that needs a
    /// gate. The ghostkey vault reaches the same conclusion by gating
    /// `MarkBackedUp` on the `Export` scope only the vault is granted.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    #[test]
    fn another_web_app_cannot_export_or_silence_a_buyers_backup_warning() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut store = MemSecrets::default();
        let buyer = StaticSecret::from([53u8; 32]);
        let tag = *PublicKey::from(&buyer).as_bytes();
        handle(
            &mut store,
            Some(&harvest()),
            store_conversation(buyer.to_bytes(), [3u8; 32]),
        );

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::ExportBuyerConversation {
                request_id: 1,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
                buyer_public_key: tag,
            },
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "a foreign web app exported a buyer's conversation secrets"
        );

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::MarkConversationBackedUp {
                request_id: 2,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
                buyer_public_key: tag,
            },
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "a foreign web app silenced the backup warning"
        );

        // And the warning is still there afterwards, which is the assertion
        // that would fail if the refusal were reported but the write happened
        // anyway.
        match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::ListBuyerConversations {
                request_id: 3,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
            },
        ) {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => {
                assert!(
                    !conversations[0].backed_up,
                    "the conversation is reported as backed up, so the buyer is no longer warned \
                     about a secret that exists in exactly one place"
                );
            }
            other => panic!("expected BuyerConversationList, got {other:?}"),
        }

        // A foreign import is refused too, so an attacker cannot plant a
        // conversation whose secret they also hold.
        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::ImportBuyerConversation {
                request_id: 3,
                backup: harvest_common::BackupString("harvest-conv-backup-v2:whatever".to_string()),
            },
        );
        assert!(refusal_message(&response).contains("Harvest web app"));
    }

    /// **The buyer's own backup round trip, through the handler.**
    ///
    /// Export on one node, import on another, and the restored conversation
    /// derives the keys the seller derives -- which is what "readable" means.
    #[test]
    fn a_conversation_is_exported_and_imported_through_the_handler() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut laptop = MemSecrets::default();
        let buyer = StaticSecret::from([61u8; 32]);
        let seller = StaticSecret::from([62u8; 32]);
        handle(
            &mut laptop,
            Some(&harvest()),
            store_conversation(buyer.to_bytes(), *PublicKey::from(&seller).as_bytes()),
        );

        let backup = match handle(
            &mut laptop,
            Some(&harvest()),
            HarvestDelegateRequest::ExportBuyerConversation {
                request_id: 1,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
                buyer_public_key: *PublicKey::from(&buyer).as_bytes(),
            },
        ) {
            HarvestDelegateResponse::BuyerConversationExported { result, .. } => {
                result.expect("must export")
            }
            other => panic!("expected BuyerConversationExported, got {other:?}"),
        };

        let mut phone = MemSecrets::default();
        let outcome = match handle(
            &mut phone,
            Some(&harvest()),
            HarvestDelegateRequest::ImportBuyerConversation {
                request_id: 2,
                backup,
            },
        ) {
            HarvestDelegateResponse::BuyerConversationImported { result, .. } => {
                result.expect("must import")
            }
            other => panic!("expected BuyerConversationImported, got {other:?}"),
        };
        assert!(matches!(
            outcome,
            harvest_common::ImportedConversation::Imported { .. }
        ));
        assert_eq!(outcome.store_contract_id(), SELLERS_STORE_ID);

        let restored = match handle(
            &mut phone,
            Some(&harvest()),
            HarvestDelegateRequest::ListBuyerConversations {
                request_id: 3,
                store_contract_id: SELLERS_STORE_ID.to_vec(),
            },
        ) {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => conversations,
            other => panic!("expected BuyerConversationList, got {other:?}"),
        };
        assert_eq!(restored.len(), 1);
        let shared = seller
            .diffie_hellman(&PublicKey::from(restored[0].buyer_public_key))
            .to_bytes();
        assert_eq!(
            restored[0].seller_to_buyer,
            harvest_common::mailbox::conversation_key_from_dh(
                &shared,
                harvest_common::mailbox::MessageDirection::SellerToBuyer
            ),
            "the restored conversation cannot read the seller's reply, which is the whole point"
        );
        assert!(
            restored[0].backed_up,
            "a conversation restored from a backup the buyer is holding was reported as \
             existing in one place only"
        );
    }
}
