//! Application state managed via Dioxus GlobalSignal.
//!
//! Centralizes all reactive state so the response handler and UI components
//! can read/write from a single source of truth.

use dioxus::logger::tracing::info;
use harvest_common::listing::AuthorizedListing;
use harvest_common::mailbox::EncryptedMessage;
use harvest_common::reputation::FeedbackEntry;
use harvest_common::store::StoreInfoV1;
use harvest_common::{HarvestDelegateResponse, StoreRegistration};
use std::collections::HashMap;

/// The main application state.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// The harvest delegate key (set after registration during app startup).
    pub harvest_delegate_key: Option<freenet_stdlib::prelude::DelegateKey>,

    /// The ghostkey delegate key (set after registration during app startup).
    pub ghostkey_delegate_key: Option<freenet_stdlib::prelude::DelegateKey>,

    /// Stores we're currently browsing, keyed by store contract ID.
    pub browsing_stores: HashMap<Vec<u8>, BrowsingStore>,

    /// Maps reputation contract IDs back to their store contract IDs,
    /// so reputation state can be matched to the right store.
    pub reputation_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Maps mailbox contract IDs back to their store contract IDs.
    pub mailbox_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Our own stores (ghostkey fingerprint -> list of registrations).
    pub my_stores: HashMap<String, Vec<StoreRegistration>>,

    /// Ghostkey identities available to us. Each successful
    /// `RequestAnyAccess` response merges (deduped by fingerprint) into
    /// this list rather than replacing it, so users can connect a
    /// second key without losing visibility into the first.
    pub ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,

    /// Set while a `RequestAnyAccess` is in flight, so the UI can
    /// disable the "Connect" button and rapid double-clicks don't queue
    /// multiple delegate prompts. Cleared on every terminal response
    /// (GhostKeyList success, AccessDenied, NoIdentityAvailable, Error).
    pub request_any_access_in_flight: bool,

    /// RSA public keys for our identities (fingerprint -> DER bytes).
    pub rsa_public_keys: HashMap<String, Vec<u8>>,

    /// Store creation pending RSA key response. When InitReputationKeys
    /// is sent, the store details are stored here. When ReputationKeysInitialized
    /// arrives, the response handler picks this up and creates the contracts.
    pub pending_store_creation: Option<PendingStoreCreation>,

    /// A listing that's been submitted for signing and is waiting for
    /// the ghostkey delegate's SignResult response.
    pub pending_listing: Option<PendingListing>,

    /// Signed listings ready to be submitted to the store contract.
    /// The UI should pick these up and send them as contract updates.
    pub signed_listings_ready: Vec<AuthorizedListing>,

    /// Pending messages/events for the UI to display.
    pub notifications: Vec<String>,
}

/// Details for a store being created, waiting for RSA key generation.
#[derive(Clone, Debug)]
pub struct PendingStoreCreation {
    pub ghostkey_fingerprint: String,
    pub seller_verifying_key_bytes: [u8; 32],
    pub certificate_pem: String,
    pub store_name: String,
    pub description: String,
    pub payment_instructions: String,
}

/// A listing awaiting signature from the ghostkey delegate.
#[derive(Clone, Debug)]
pub struct PendingListing {
    pub fingerprint: String,
    pub listing: harvest_common::listing::Listing,
    /// Store contract ID to submit the signed listing to.
    pub store_contract_id: Option<Vec<u8>>,
}

/// State for a store we're browsing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BrowsingStore {
    pub info: Option<StoreInfoV1>,
    pub listings: Vec<AuthorizedListing>,
    /// Reputation contract ID (extracted from StoreInfoV1 on first load).
    pub reputation_contract_id: Option<Vec<u8>>,
    /// Mailbox contract ID (will be set when we know it).
    pub mailbox_contract_id: Option<Vec<u8>>,
    /// Negative feedback entries from the reputation contract.
    pub feedback: Vec<FeedbackEntry>,
    /// Encrypted messages from the mailbox contract.
    pub mailbox_messages: Vec<EncryptedMessage>,
}

impl AppState {
    /// Start browsing a store: subscribe to it and prepare state.
    pub fn begin_browsing(&mut self, store_contract_id: Vec<u8>) {
        self.browsing_stores.entry(store_contract_id).or_default();
    }

    /// Handle full contract state received from a GET response.
    pub fn on_contract_state(&mut self, contract_id: Vec<u8>, state_bytes: Vec<u8>) {
        if state_bytes.is_empty() {
            return;
        }

        // Try store contract first
        if let Ok(store_state) =
            harvest_common::from_cbor::<harvest_common::store::StoreStateV1>(&state_bytes)
        {
            info!(
                "Received store state for {:?}",
                &contract_id[..8.min(contract_id.len())]
            );
            let reputation_id = store_state.info.info.reputation_contract_id.to_vec();

            let store = self.browsing_stores.entry(contract_id.clone()).or_default();
            store.info = Some(store_state.info.info);
            store.listings = store_state.listings.listings;
            store.reputation_contract_id = Some(reputation_id.clone());

            // Register the reverse mapping so incoming reputation state
            // can be matched to this store
            self.reputation_to_store.insert(reputation_id, contract_id);
            return;
        }

        // Try reputation contract
        if let Ok(reputation_state) =
            harvest_common::from_cbor::<harvest_common::reputation::ReputationStateV1>(&state_bytes)
        {
            info!(
                "Received reputation state ({} entries)",
                reputation_state.feedback.len()
            );

            // Look up which store this reputation belongs to
            if let Some(store_id) = self.reputation_to_store.get(&contract_id).cloned() {
                if let Some(store) = self.browsing_stores.get_mut(&store_id) {
                    store.feedback = reputation_state.feedback;
                }
            } else {
                info!("Reputation state for unknown store -- caching by contract ID");
                // Cache it; will be linked when the store state arrives
                let store = self.browsing_stores.entry(contract_id).or_default();
                store.feedback = reputation_state.feedback;
            }
            return;
        }

        // Try mailbox contract
        if let Ok(mailbox_state) =
            harvest_common::from_cbor::<harvest_common::mailbox::MailboxStateV1>(&state_bytes)
        {
            info!(
                "Received mailbox state ({} messages)",
                mailbox_state.messages.len()
            );

            if let Some(store_id) = self.mailbox_to_store.get(&contract_id).cloned() {
                if let Some(store) = self.browsing_stores.get_mut(&store_id) {
                    store.mailbox_messages = mailbox_state.messages;
                }
            }
            return;
        }

        info!(
            "Received unknown contract state ({} bytes)",
            state_bytes.len()
        );
    }

    /// Handle a contract update notification (delta).
    pub fn on_contract_update(&mut self, contract_id: Vec<u8>, update_bytes: Vec<u8>) {
        // Deltas for our contract types can be applied incrementally.
        // For reputation, a delta is Vec<FeedbackEntry> (new entries to append).
        // For store, a delta is StoreStateV1Delta (composable).
        // For now, we re-GET the full state on update notification.
        // This is correct but inefficient -- proper delta application can be
        // added once the basic flow works end-to-end.
        self.on_contract_state(contract_id, update_bytes);
    }

    /// Handle a response from the harvest delegate.
    pub fn on_delegate_response(&mut self, response: HarvestDelegateResponse) {
        match response {
            HarvestDelegateResponse::ReputationKeysInitialized {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                info!("RSA keys initialized for {}", ghostkey_fingerprint);
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint.clone(), rsa_public_key_der.clone());

                // If we have a pending store creation for this fingerprint,
                // trigger the contract creation flow
                if let Some(pending) = self.pending_store_creation.take() {
                    if pending.ghostkey_fingerprint == ghostkey_fingerprint {
                        #[cfg(target_arch = "wasm32")]
                        {
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Err(e) = crate::gateway::store_ops::create_store_contracts(
                                    pending.ghostkey_fingerprint,
                                    pending.seller_verifying_key_bytes,
                                    rsa_public_key_der,
                                    pending.certificate_pem,
                                    pending.store_name,
                                    pending.description,
                                    pending.payment_instructions,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!("Store creation failed: {}", e);
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!("Store creation failed: {e}"));
                                }
                            });
                        }
                    } else {
                        // Wrong fingerprint -- put it back
                        self.pending_store_creation = Some(pending);
                    }
                }
            }

            HarvestDelegateResponse::RsaPublicKey {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint, rsa_public_key_der);
            }

            HarvestDelegateResponse::StoreRegistered {
                ghostkey_fingerprint,
            } => {
                info!("Store registered for {}", ghostkey_fingerprint);
            }

            HarvestDelegateResponse::StoreList {
                ghostkey_fingerprint,
                stores,
            } => {
                self.my_stores.insert(ghostkey_fingerprint, stores);
            }

            HarvestDelegateResponse::Error { message } => {
                self.notifications
                    .push(format!("Delegate error: {message}"));
            }

            _ => {
                info!("Unhandled delegate response: {:?}", response);
            }
        }
    }

    /// Handle a response from the ghostkey delegate.
    pub fn on_ghostkey_response(&mut self, response: ghostkey_common::GhostkeyResponse) {
        match response {
            ghostkey_common::GhostkeyResponse::GhostKeyList { keys } => {
                info!("Received {} ghostkeys", keys.len());
                // If any ghostkey has verifying_key_bytes and we have a pending
                // store creation for it, fill in the key
                for key in &keys {
                    if let Some(ref vk_bytes) = key.verifying_key_bytes {
                        if let Some(ref mut pending) = self.pending_store_creation {
                            if pending.ghostkey_fingerprint == key.fingerprint
                                && pending.seller_verifying_key_bytes == [0u8; 32]
                                && vk_bytes.len() == 32
                            {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(vk_bytes);
                                pending.seller_verifying_key_bytes = arr;
                                info!(
                                    "Filled verifying key for pending store creation: {}",
                                    key.fingerprint
                                );
                            }
                        }
                    }
                }
                // Merge new keys into the existing list (dedup by
                // fingerprint, prefer the newer entry). Wholesale
                // replacement would drop previously-connected keys
                // when a second `RequestAnyAccess` returns a single
                // newly-shared key.
                for key in keys {
                    if let Some(slot) = self
                        .ghostkeys
                        .iter_mut()
                        .find(|k| k.fingerprint == key.fingerprint)
                    {
                        *slot = key;
                    } else {
                        self.ghostkeys.push(key);
                    }
                }
                self.request_any_access_in_flight = false;
            }

            ghostkey_common::GhostkeyResponse::SignResult {
                scoped_payload,
                signature,
                certificate_pem,
            } => {
                info!("Received signature from ghostkey delegate");
                if let Some(pending) = self.pending_listing.take() {
                    let authorized = AuthorizedListing {
                        listing: pending.listing,
                        scoped_payload,
                        signature,
                        certificate_pem,
                    };
                    info!(
                        "Constructed AuthorizedListing: {}",
                        authorized.listing.title
                    );

                    // Submit to the store contract if we know which one
                    #[cfg(target_arch = "wasm32")]
                    if let Some(store_id) = pending.store_contract_id {
                        let listing = authorized.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Err(e) =
                                crate::gateway::store_ops::submit_listing_by_id(&store_id, listing)
                                    .await
                            {
                                dioxus::logger::tracing::error!("Failed to submit listing: {}", e);
                                crate::gateway::APP_STATE
                                    .write()
                                    .notifications
                                    .push(format!("Failed to submit listing: {e}"));
                            }
                        });
                    }

                    self.signed_listings_ready.push(authorized);
                } else {
                    info!("SignResult received but no pending listing");
                }
            }

            ghostkey_common::GhostkeyResponse::Certificate {
                fingerprint,
                certificate_pem,
            } => {
                info!("Received certificate for {}", fingerprint);
                // If we have a pending store creation for this fingerprint,
                // fill in the certificate PEM. The verifying key is extracted
                // by the store creation code from the certificate at contract
                // creation time.
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                        info!("Updated pending store creation with certificate");
                    }
                }
            }

            ghostkey_common::GhostkeyResponse::GhostKeyDetail {
                fingerprint,
                certificate_pem,
                ..
            } => {
                info!("Received ghostkey detail for {}", fingerprint);
                // Also update pending store creation if applicable
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                    }
                }
            }

            ghostkey_common::GhostkeyResponse::Error { message } => {
                self.notifications
                    .push(format!("Ghostkey error: {message}"));
                self.pending_listing = None;
                self.request_any_access_in_flight = false;
            }

            // The user denied a `RequestAnyAccess` prompt. Surface a
            // notification, clear the in-flight flag so the button is
            // enabled again, and clear any pending listing/store
            // creation that was waiting on this grant. Without this
            // cleanup, a subsequent successful SignResult would
            // consume the stale pending listing.
            ghostkey_common::GhostkeyResponse::AccessDenied { .. } => {
                self.notifications.push(
                    "Ghostkey access was denied. Click 'Connect a ghostkey' again to retry.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_listing = None;
                self.pending_store_creation = None;
            }

            // The vault has no ghostkeys at all. Tell the user where
            // to go to create one. Same cleanup as AccessDenied.
            ghostkey_common::GhostkeyResponse::NoIdentityAvailable => {
                self.notifications.push(
                    "No ghostkey identities found. Open the Ghostkey Vault to create one, then come back and click 'Connect a ghostkey'.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_listing = None;
                self.pending_store_creation = None;
            }

            // Per-fingerprint denial: the user denied a specific-key
            // prompt, or the vault revoked the grant between connect
            // and sign. Same cleanup as the access-denial arms.
            ghostkey_common::GhostkeyResponse::PermissionDenied { fingerprint, .. } => {
                self.notifications
                    .push(format!("Ghostkey access denied for {fingerprint}."));
                self.request_any_access_in_flight = false;
                self.pending_listing = None;
                self.pending_store_creation = None;
            }

            // Vault-only responses Harvest doesn't act on. The
            // explicit arms above cover every user-visible failure
            // mode in the current ghostkey-common protocol; this
            // wildcard is just for vault-management responses
            // (PermissionGranted / PermissionRevoked / PermissionList /
            // KeyNotFound / VerifyResult / Deleted / LabelSet, etc).
            // A future response variant with a failure semantic
            // would slip through here -- worth re-auditing on every
            // ghostkey-common bump.
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => {
                info!("Unhandled ghostkey response: {:?}", response);
            }
        }
    }
}
