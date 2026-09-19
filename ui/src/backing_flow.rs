//! Creating a store backed by a Ghost Key, and moving a store made before
//! revision 2 onto a store key of its own (harvest#93, phase 1a).
//!
//! # Creating a store
//!
//! A store has its own Ed25519 key since revision 2
//! (`docs/design/entity-model.md`, section 3). Creating one is, in order:
//!
//! 1. `CreateStoreKey` to the Harvest delegate, alongside the certificate,
//!    RSA and encryption-key requests store creation already made. The gate
//!    in `AppState::start_store_creation_if_ready` waits for it.
//! 2. The Ghost Key signs a [`BackingStatement`] naming the new store key,
//!    through the vault's `SignMessage` ([`AppState::begin_backing`]).
//! 3. The store key signs the `BackingAcceptance`, through the Harvest
//!    delegate ([`AppState::on_backing_statement_signed`]).
//! 4. The contracts are published with the backing already in the store's
//!    first state, and the store key signs the details
//!    ([`AppState::on_backing_accepted`], then
//!    `store_ops::create_store_contracts`).
//!
//! Each signature is queued in `pending_signatures` like any other and
//! matched by its signed bytes, so nothing here depends on answers coming
//! back in order.
//!
//! # Moving a store made before revision 2
//!
//! Every store up to generation V18 was owned by its seller's Ghost Key
//! directly: the key was the store's owner and signed its records. The
//! current contract still accepts such a state -- an owner is only a key, and
//! every record in it verifies against that key -- so the migration probe
//! carries those stores forward into the current generation unchanged, as
//! pure data transfer. What it cannot do is make them revision-2 stores:
//! they have no backing, so every reader treats them as unbacked and buyers'
//! software refuses to pay them, and this build signs a store's records only
//! with a store key, which such a store does not have.
//!
//! So a seller whose only store is one of these is offered a move, on their
//! own device (the Ghost Key has to sign the backing, so nobody else can do
//! it): [`AppState::move_legacy_store`] runs the creation flow above with
//! the old store's name and description and its listings, re-signed by the
//! new store key. A listing's id is derived from its terms alone
//! (`ListingId::from_terms`), which name no seller, so every listing keeps
//! its id. The new store has a new store code, and so a new link, which the
//! seller has to share again; the old store stays where it was, unbacked.
//!
//! Orders are not carried. An order's terms are payable only within
//! `MAX_ANCHOR_AGE_BLOCKS` of its anchor (about eight hours), so an open
//! invoice from before the move is one the buyer can no longer pay anyway,
//! and a Paid order stays readable at the old store. Harvest is pre-launch,
//! so this is the simplest correct path rather than a complete one; see
//! `docs/design/entity-model.md`, "Phase 1a: what was built".

use harvest_common::backing::{AuthorizedBacking, BackingStatement};
use harvest_common::listing::Listing;

use crate::state::{AppState, PendingSignature, PendingStoreCreation, StoreDetails};

/// A backing on its way through the two signatures it needs.
#[derive(Clone, Debug)]
pub struct PendingBacking {
    /// The Ghost Key doing the backing.
    pub fingerprint: String,
    pub statement: BackingStatement,
    /// Everything the store's creation needs once the backing is signed.
    pub creation: PendingStoreCreation,
    /// The Ghost Key's half, once the vault has answered. Empty before.
    pub backer_scoped_payload: Vec<u8>,
    pub backer_signature: Vec<u8>,
}

/// What a seller is told when a store cannot be backed for want of a recent
/// Bitcoin block to date the backing to.
pub(crate) const NO_BLOCK_FOR_BACKING: &str =
    "Harvest has not loaded a recent Bitcoin block yet, and a store's backing has to name \
     one. Wait for the chain data to load and try again.";

impl AppState {
    /// Start creating a store for the Ghost Key `fingerprint`: record what is
    /// known, and return the request id `CreateStoreKey` must go out under.
    ///
    /// `carried_listings` are listings to re-sign into the new store once it
    /// exists; empty for an ordinary new store. See
    /// [`AppState::move_legacy_store`].
    pub(crate) fn begin_store_creation(
        &mut self,
        fingerprint: String,
        seller_verifying_key_bytes: [u8; 32],
        details: StoreDetails,
        carried_listings: Vec<Listing>,
    ) -> u64 {
        let store_key_request = self.next_messaging_request_id();
        self.pending_store_creation = Some(PendingStoreCreation {
            ghostkey_fingerprint: fingerprint,
            seller_verifying_key_bytes,
            certificate_pem: String::new(),
            store_name: details.store_name,
            description: details.description,
            rsa_public_key_der: None,
            encryption_public_key: None,
            store_verifying_key: None,
            store_key_request: Some(store_key_request),
            carried_listings,
        });
        store_key_request
    }

    /// The Harvest delegate answered `CreateStoreKey`.
    ///
    /// Only the answer to the request the pending creation made is taken: a
    /// late answer to an abandoned creation would otherwise hand a store key
    /// nobody is waiting for to the next one.
    pub(crate) fn on_store_key_created(
        &mut self,
        request_id: u64,
        result: Result<[u8; 32], String>,
    ) {
        let Some(pending) = self.pending_store_creation.as_mut() else {
            return;
        };
        if pending.store_key_request != Some(request_id) {
            return;
        }
        match result {
            Ok(key) => {
                pending.store_verifying_key = Some(key);
                self.start_store_creation_if_ready();
            }
            Err(why) => {
                self.pending_store_creation = None;
                self.notifications
                    .push(format!("Could not create a key for your store: {why}"));
            }
        }
    }

    /// Ask the Ghost Key to back the store about to be created.
    ///
    /// The backing names a recent block of the network Harvest pays on. With
    /// no block loaded the creation stops and the seller is told, rather than
    /// the backing being dated to nothing: readers order backings by that
    /// block (`harvest_common::backing::current_backing`).
    pub(crate) fn begin_backing(&mut self, creation: PendingStoreCreation) {
        let Some(store_key) = creation
            .store_verifying_key
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        else {
            self.notifications
                .push("Store creation failed: the store key is not a valid key.".into());
            return;
        };
        let Ok(backer) =
            ed25519_dalek::VerifyingKey::from_bytes(&creation.seller_verifying_key_bytes)
        else {
            self.notifications
                .push("Store creation failed: the Ghost Key's verifying key is not known.".into());
            return;
        };
        let network = crate::gateway::bitcoin_config::default_network();
        let Some(block) = self
            .bitcoin
            .tips
            .get(&network)
            .and_then(|tip| tip.current_anchor())
        else {
            self.notifications
                .push(format!("Store creation failed: {NO_BLOCK_FOR_BACKING}"));
            return;
        };
        let statement = BackingStatement {
            store: store_key,
            backer,
            certificate_pem: creation.certificate_pem.clone(),
            network,
            block,
        };
        let pending = PendingBacking {
            fingerprint: creation.ghostkey_fingerprint.clone(),
            statement,
            creation,
            backer_scoped_payload: Vec::new(),
            backer_signature: Vec::new(),
        };
        self.pending_signatures
            .push_back(PendingSignature::BackingStatement(Box::new(
                pending.clone(),
            )));
        #[cfg(target_arch = "wasm32")]
        spawn_backing_statement_signature(pending);
    }

    /// The vault signed the backing statement: ask the store key to accept it.
    pub(crate) fn on_backing_statement_signed(
        &mut self,
        mut pending: PendingBacking,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) {
        pending.backer_scoped_payload = scoped_payload;
        pending.backer_signature = signature;
        let store_key = pending.statement.store.to_bytes();
        if let Err(e) = self.request_store_key_signature(
            PendingSignature::BackingAcceptance(Box::new(pending)),
            store_key,
        ) {
            self.notifications
                .push(format!("Store creation failed: {e}"));
        }
    }

    /// The store key accepted the backing: the store can be published.
    ///
    /// Checked here against the same rule the store contract applies, so a
    /// backing that would be refused is reported to the seller instead of
    /// being published into a PUT that fails with nothing to say why.
    pub(crate) fn on_backing_accepted(
        &mut self,
        pending: PendingBacking,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let backing = AuthorizedBacking {
            statement: pending.statement,
            backer_scoped_payload: pending.backer_scoped_payload,
            backer_signature: pending.backer_signature,
            acceptance_scoped_payload: scoped_payload,
            acceptance_signature: signature,
        };
        if let Err(why) = backing.verify(&backing.statement.store) {
            self.notifications.push(format!(
                "Store creation failed: the backing did not verify ({why})."
            ));
            return;
        }
        #[cfg(target_arch = "wasm32")]
        crate::state::spawn_store_creation(pending.creation, backing);
        #[cfg(not(target_arch = "wasm32"))]
        self.created_backings.push((pending.creation, backing));
    }

    /// Queue a listing for the store key's signature, for the store
    /// `store_contract_id`, which must be one of ours with a store key.
    pub(crate) fn queue_listing_signature(
        &mut self,
        store_contract_id: Vec<u8>,
        fingerprint: String,
        listing: Listing,
    ) -> Result<(), String> {
        let store_key = self
            .store_owner_key(&store_contract_id)
            .ok_or(crate::state::NO_STORE_KEY_MESSAGE)?;
        self.request_store_key_signature(
            PendingSignature::Listing(crate::state::PendingListing {
                fingerprint,
                listing,
                store_contract_id: Some(store_contract_id),
            }),
            store_key.to_bytes(),
        )
    }

    /// The store a new listing from the Ghost Key `fingerprint` goes to: the
    /// first of its stores this device holds a store key for.
    ///
    /// A store made before revision 2 is never chosen, because this build
    /// cannot sign for it; its seller is offered a move instead.
    pub(crate) fn signable_store_for(&self, fingerprint: &str) -> Option<Vec<u8>> {
        self.my_stores
            .get(fingerprint)?
            .iter()
            .find(|registration| registration.store_verifying_key.is_some())
            .map(|registration| registration.store_contract_id.clone())
    }

    /// What moving a store made before revision 2 would carry, if the
    /// Ghost Key `fingerprint` has one and no revision-2 store yet: its
    /// details and its listings, as last loaded.
    ///
    /// `None` when there is nothing to move, or when the old store has not
    /// loaded yet: moving before it loads would create an empty store and
    /// leave the seller to retype everything.
    pub(crate) fn legacy_store_to_move(
        &self,
        fingerprint: &str,
    ) -> Option<(Vec<u8>, StoreDetails, Vec<Listing>)> {
        let stores = self.my_stores.get(fingerprint)?;
        if stores
            .iter()
            .any(|store| store.store_verifying_key.is_some())
        {
            return None;
        }
        stores.iter().find_map(|registration| {
            let loaded = self.browsing_stores.get(&registration.store_contract_id)?;
            let info = loaded.info.as_ref()?;
            Some((
                registration.store_contract_id.clone(),
                StoreDetails {
                    store_name: info.store_name.clone(),
                    description: info.description.clone(),
                },
                loaded
                    .listings
                    .iter()
                    .map(|authorized| authorized.listing.clone())
                    .collect(),
            ))
        })
    }

    /// Move the Ghost Key `fingerprint`'s pre-revision-2 store onto a new
    /// store key. Returns the `CreateStoreKey` request id to send.
    pub(crate) fn move_legacy_store(
        &mut self,
        fingerprint: &str,
        seller_verifying_key_bytes: [u8; 32],
    ) -> Result<u64, String> {
        let (_, details, listings) = self
            .legacy_store_to_move(fingerprint)
            .ok_or("there is no store made before store keys to move, or it has not loaded yet")?;
        if self.pending_store_creation.is_some() {
            return Err("a store is already being created; wait for it to finish".into());
        }
        Ok(self.begin_store_creation(
            fingerprint.to_string(),
            seller_verifying_key_bytes,
            details,
            listings,
        ))
    }
}

/// Ask the vault to sign a backing statement. Same discipline as every other
/// signature: queued before this runs, withdrawn if the send fails.
#[cfg(target_arch = "wasm32")]
fn spawn_backing_statement_signature(pending: PendingBacking) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};

        let queued = PendingSignature::BackingStatement(Box::new(pending.clone()));
        let fail = |reason: String| {
            dioxus::logger::tracing::error!("{reason}");
            let mut state = crate::gateway::APP_STATE.write();
            state.withdraw_pending_signature(&queued);
            state
                .notifications
                .push(format!("Store creation failed: {reason}"));
        };
        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            fail("the Ghost Key vault is not registered".to_string());
            return;
        };
        let message = match harvest_common::to_cbor(&pending.statement) {
            Ok(message) => message,
            Err(e) => {
                fail(format!("serialize the backing for signing: {e}"));
                return;
            }
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint: pending.fingerprint.clone(),
            message,
        };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                fail(format!("serialize SignMessage: {e}"));
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            fail(format!("send the backing for signing: {e}"));
        }
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::state::{BackingView, BlockRow, PaymentBlocker, Signer, TipView};
    use ed25519_dalek::{Signer as _, SigningKey};
    use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};
    use harvest_common::delegate::StoreKeySignature;
    use harvest_common::HarvestDelegateResponse;

    const FINGERPRINT: &str = "fp-backer";
    const TIP: u32 = 250_000;

    fn ghost() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }

    fn store_key() -> SigningKey {
        SigningKey::from_bytes(&[0x62; 32])
    }

    fn tip() -> TipView {
        TipView {
            network: BitcoinNetwork::Signet,
            tip_height: Some(TIP),
            signed_tip: None,
            last_block_time: None,
            recent_blocks: vec![BlockRow {
                height: TIP,
                hash: BlockHash([0x33; 32]),
                tx_count: 1,
                block_time: 0,
            }],
        }
    }

    fn statement() -> BackingStatement {
        BackingStatement {
            store: store_key().verifying_key(),
            backer: ghost().verifying_key(),
            certificate_pem: "CERT".to_string(),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height: TIP,
                hash: BlockHash([0x33; 32]),
            },
        }
    }

    fn creation_ready() -> PendingStoreCreation {
        PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: ghost().verifying_key().to_bytes(),
            certificate_pem: "CERT".to_string(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            rsa_public_key_der: Some(vec![1, 2, 3]),
            encryption_public_key: None,
            store_verifying_key: Some(store_key().verifying_key().to_bytes()),
            store_key_request: Some(1),
            carried_listings: Vec::new(),
        }
    }

    /// A backing statement waiting on the vault, for tests elsewhere that need
    /// one in the queue.
    pub(crate) fn pending_backing_statement() -> PendingSignature {
        PendingSignature::BackingStatement(Box::new(PendingBacking {
            fingerprint: FINGERPRINT.to_string(),
            statement: statement(),
            creation: creation_ready(),
            backer_scoped_payload: Vec::new(),
            backer_signature: Vec::new(),
        }))
    }

    /// `(scoped_payload, signature)` over `data`, as the vault or the Harvest
    /// delegate builds it.
    fn sign<T: serde::Serialize>(key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
        let scoped = harvest_common::backing::store_key_envelope(
            harvest_common::to_cbor(data).expect("serialize"),
        )
        .expect("envelope");
        let signature = key.sign(&scoped).to_bytes().to_vec();
        (scoped, signature)
    }

    fn vault_answer(
        key: &SigningKey,
        statement: &BackingStatement,
    ) -> ghostkey_common::GhostkeyResponse {
        let (scoped_payload, signature) = sign(key, statement);
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload,
            signature,
            certificate_pem: "CERT".to_string(),
        }
    }

    fn store_key_answer(key: &SigningKey, statement: &BackingStatement) -> HarvestDelegateResponse {
        let (scoped_payload, signature) = sign(
            key,
            &harvest_common::backing::BackingAcceptance {
                backing: statement.clone(),
            },
        );
        HarvestDelegateResponse::StoreUpdateSigned {
            request_id: 0,
            store_verifying_key: store_key().verifying_key().to_bytes(),
            result: Ok(StoreKeySignature {
                scoped_payload,
                signature,
            }),
        }
    }

    fn queued_statement(state: &AppState) -> Option<BackingStatement> {
        state
            .pending_signatures
            .iter()
            .find_map(|pending| match pending {
                PendingSignature::BackingStatement(p) => Some(p.statement.clone()),
                _ => None,
            })
    }

    /// Creation waits for the store key: without one there is no store to
    /// back. Mutated red by dropping the store-key condition from
    /// `start_store_creation_if_ready`.
    #[test]
    fn creation_waits_for_the_store_key_then_asks_the_ghost_key_to_back_it() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        let request = state.begin_store_creation(
            FINGERPRINT.to_string(),
            ghost().verifying_key().to_bytes(),
            StoreDetails {
                store_name: "Bean Shop".to_string(),
                description: String::new(),
            },
            Vec::new(),
        );
        {
            let pending = state.pending_store_creation.as_mut().unwrap();
            pending.certificate_pem = "CERT".to_string();
            pending.rsa_public_key_der = Some(vec![1]);
        }
        state.start_store_creation_if_ready();
        assert!(queued_statement(&state).is_none(), "no store key yet");

        // An answer to some other request does not fill it.
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request + 7,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        assert!(queued_statement(&state).is_none());

        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        let statement = queued_statement(&state).expect("the Ghost Key is asked to back the store");
        assert_eq!(statement.store, store_key().verifying_key());
        assert_eq!(statement.backer, ghost().verifying_key());
        assert_eq!(statement.certificate_pem, "CERT");
        assert_eq!(statement.network, BitcoinNetwork::Signet);
        assert_eq!(
            statement.block.height, TIP,
            "dated to the newest block this reader has"
        );
        assert!(state.pending_store_creation.is_none());
    }

    #[test]
    fn a_refused_store_key_abandons_the_creation_and_says_so() {
        let mut state = AppState::default();
        let request = state.begin_store_creation(
            FINGERPRINT.to_string(),
            ghost().verifying_key().to_bytes(),
            StoreDetails::default(),
            Vec::new(),
        );
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Err("full".to_string()),
        });
        assert!(state.pending_store_creation.is_none());
        assert!(state.notifications.iter().any(|n| n.contains("full")));
    }

    /// No block, no backing: the creation stops and the seller is told,
    /// rather than a backing dated to nothing.
    #[test]
    fn with_no_block_loaded_nothing_is_backed() {
        let mut state = AppState::default();
        state.begin_backing(creation_ready());
        assert!(queued_statement(&state).is_none());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains(NO_BLOCK_FOR_BACKING)));
    }

    /// The whole signing sequence: the vault's statement, then the store
    /// key's acceptance, then a backing the store contract would accept.
    #[test]
    fn both_signatures_make_a_backing_the_contract_accepts() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        state.begin_backing(creation_ready());
        let statement = queued_statement(&state).expect("queued");

        state.on_ghostkey_response(vault_answer(&ghost(), &statement));
        assert!(queued_statement(&state).is_none());
        assert!(
            state
                .pending_signatures
                .iter()
                .any(|p| matches!(p, PendingSignature::BackingAcceptance(_))
                    && p.signer() == Signer::StoreKey),
            "the store key is asked to accept it"
        );

        state.on_delegate_response(store_key_answer(&store_key(), &statement));
        let (creation, backing) = state.created_backings.pop().expect("a store to create");
        assert_eq!(creation.store_name, "Bean Shop");
        backing
            .verify(&store_key().verifying_key())
            .expect("the contract's own rule accepts it");
        assert!(state.pending_signatures.is_empty());
    }

    /// A backing that would not verify is reported, not published. Mutated
    /// red by removing the `verify` call from `on_backing_accepted`.
    #[test]
    fn a_backing_that_would_not_verify_is_not_published() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        state.begin_backing(creation_ready());
        let statement = queued_statement(&state).expect("queued");
        // The vault answers with the WRONG key's signature over the right
        // bytes: the answer matches the request, and the result must not
        // be published.
        state.on_ghostkey_response(vault_answer(&SigningKey::from_bytes(&[9; 32]), &statement));
        state.on_delegate_response(store_key_answer(&store_key(), &statement));
        assert!(state.created_backings.is_empty());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("did not verify")));
    }

    fn legacy_registration() -> harvest_common::StoreRegistration {
        harvest_common::StoreRegistration {
            store_contract_id: vec![7; 32],
            reputation_contract_id: vec![8; 32],
            mailbox_contract_id: vec![9; 32],
            store_contract_key: None,
            store_verifying_key: None,
        }
    }

    fn legacy_seller() -> AppState {
        let mut state = AppState::default();
        state
            .my_stores
            .insert(FINGERPRINT.to_string(), vec![legacy_registration()]);
        let listing = harvest_common::listing::Listing {
            id: harvest_common::listing::ListingId([0; 32]),
            title: "Beans".to_string(),
            description: String::new(),
            kind: harvest_common::listing::ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
        .with_derived_id();
        let store = state.browsing_stores.entry(vec![7; 32]).or_default();
        store.info = Some(harvest_common::store::StoreInfoV1 {
            version: 3,
            certificate_pem: String::new(),
            seller_fingerprint: FINGERPRINT.to_string(),
            reputation_contract_id: [8; 32],
            store_name: "Old Shop".to_string(),
            description: "since 2026".to_string(),
            encryption_public_key: None,
        });
        store.listings = vec![harvest_common::listing::AuthorizedListing {
            listing,
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            certificate_pem: String::new(),
        }];
        state
    }

    /// A store made before revision 2 is moved with its details and
    /// listings, and each listing keeps its id because its terms name no
    /// seller.
    #[test]
    fn moving_a_legacy_store_carries_its_details_and_listings() {
        let mut state = legacy_seller();
        assert!(
            state.signable_store_for(FINGERPRINT).is_none(),
            "nothing to sign for yet"
        );
        let old_id = state.browsing_stores[&vec![7; 32]].listings[0]
            .listing
            .id
            .clone();

        state
            .move_legacy_store(FINGERPRINT, ghost().verifying_key().to_bytes())
            .expect("there is a store to move");

        let pending = state.pending_store_creation.as_ref().expect("a creation");
        assert_eq!(pending.store_name, "Old Shop");
        assert_eq!(pending.description, "since 2026");
        assert_eq!(pending.carried_listings.len(), 1);
        assert_eq!(
            harvest_common::listing::ListingId::from_terms(&pending.carried_listings[0]),
            old_id,
            "a carried listing keeps its id"
        );
    }

    /// Nothing is offered once the Ghost Key has a store it can sign for, nor
    /// before the old store has loaded (a move then would create an empty
    /// store and leave the seller to retype everything).
    #[test]
    fn a_move_is_offered_only_for_a_loaded_legacy_store_with_nothing_newer() {
        let mut state = legacy_seller();
        assert!(state.legacy_store_to_move(FINGERPRINT).is_some());

        let mut unloaded = state.clone();
        unloaded.browsing_stores.clear();
        assert!(unloaded.legacy_store_to_move(FINGERPRINT).is_none());

        let mut keyed = legacy_registration();
        keyed.store_contract_id = vec![5; 32];
        keyed.store_verifying_key = Some(store_key().verifying_key().to_bytes());
        state.my_stores.get_mut(FINGERPRINT).unwrap().push(keyed);
        assert!(state.legacy_store_to_move(FINGERPRINT).is_none());
        assert_eq!(state.signable_store_for(FINGERPRINT), Some(vec![5; 32]));
    }

    fn view(store: u8, backer: u8) -> BackingView {
        BackingView {
            store: SigningKey::from_bytes(&[store; 32])
                .verifying_key()
                .to_bytes(),
            backer: SigningKey::from_bytes(&[backer; 32])
                .verifying_key()
                .to_bytes(),
            certificate_status: crate::ghostkey_cert::CertificateStatus::Verified,
            block_height: TIP,
        }
    }

    /// A Ghost Key backing two loaded stores counts for NEITHER, and each
    /// comes back once the other stops being backed by it (section 6.2).
    /// Mutated red by skipping the `conflicted` check in
    /// `refresh_backing_verdicts`.
    #[test]
    fn a_key_backing_two_stores_counts_for_neither() {
        let mut state = AppState::default();
        state
            .browsing_stores
            .entry(vec![1; 32])
            .or_default()
            .backing = Some(view(0x71, 0x41));
        state
            .browsing_stores
            .entry(vec![2; 32])
            .or_default()
            .backing = Some(view(0x72, 0x41));
        state
            .browsing_stores
            .entry(vec![3; 32])
            .or_default()
            .backing = Some(view(0x73, 0x42));
        state.refresh_backing_verdicts();

        for id in [vec![1u8; 32], vec![2u8; 32]] {
            let store = &state.browsing_stores[&id];
            assert!(store.store_verifying_key.is_none());
            assert!(store.seller_verifying_key.is_none());
            assert!(!store.certificate_status.is_verified());
        }
        let third = &state.browsing_stores[&vec![3u8; 32]];
        assert_eq!(third.store_verifying_key, Some(view(0x73, 0x42).store));
        assert_eq!(third.seller_verifying_key, Some(view(0x73, 0x42).backer));

        // The second store's backing moves to another key: the first counts
        // again.
        state
            .browsing_stores
            .get_mut(&vec![2u8; 32])
            .unwrap()
            .backing = Some(view(0x72, 0x43));
        state.refresh_backing_verdicts();
        assert_eq!(
            state.browsing_stores[&vec![1u8; 32]].store_verifying_key,
            Some(view(0x71, 0x41).store)
        );
    }

    /// A backing whose certificate does not verify is no backing to a buyer,
    /// and a store with none is unbacked.
    #[test]
    fn an_unverified_or_missing_backing_gives_no_identity() {
        let mut state = AppState::default();
        let mut bad = view(0x71, 0x41);
        bad.certificate_status =
            crate::ghostkey_cert::CertificateStatus::Invalid("not genuine".to_string());
        state
            .browsing_stores
            .entry(vec![1; 32])
            .or_default()
            .backing = Some(bad);
        state.browsing_stores.entry(vec![2; 32]).or_default();
        state.refresh_backing_verdicts();
        for id in [vec![1u8; 32], vec![2u8; 32]] {
            assert!(state.browsing_stores[&id].store_verifying_key.is_none());
        }
        assert_eq!(
            state.browsing_stores[&vec![2u8; 32]].certificate_status,
            crate::ghostkey_cert::CertificateStatus::Absent
        );
    }

    /// The current backing is read from the state the contract accepted, and
    /// its store key is the owner's.
    #[test]
    fn the_backing_view_is_the_current_backing() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        let statement = statement();
        let (backer_scoped_payload, backer_signature) = sign(&ghost(), &statement);
        let (acceptance_scoped_payload, acceptance_signature) = sign(
            &store_key(),
            &harvest_common::backing::BackingAcceptance {
                backing: statement.clone(),
            },
        );
        let backing = AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        };
        let store = harvest_common::store::StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            backings: harvest_common::backing::BackingsV1 {
                records: std::iter::once((
                    harvest_common::store::Bytes32(ghost().verifying_key().to_bytes()),
                    backing,
                ))
                .collect(),
            },
            ..Default::default()
        };
        let view = state.backing_view(&store).expect("a current backing");
        assert_eq!(view.store, store_key().verifying_key().to_bytes());
        assert_eq!(view.backer, ghost().verifying_key().to_bytes());
        assert!(
            !view.certificate_status.is_verified(),
            "\"CERT\" is not a certificate"
        );
        assert!(state
            .backing_view(&harvest_common::store::StoreStateV1::default())
            .is_none());
    }

    /// Buyers' software refuses to pay a closed store before looking at
    /// anything else (section 6.4). Mutated red by removing the `closed`
    /// check from `payment_blockers`.
    #[test]
    fn a_closed_store_is_refused_before_anything_else() {
        let state = AppState::default();
        let store = crate::state::BrowsingStore {
            closed: true,
            store_verifying_key: Some([1; 32]),
            seller_verifying_key: Some([2; 32]),
            ..Default::default()
        };
        assert_eq!(
            state.payment_blockers_for_test(&store),
            vec![PaymentBlocker::StoreClosed]
        );
        let open = crate::state::BrowsingStore {
            closed: false,
            ..store
        };
        assert_ne!(
            state.payment_blockers_for_test(&open),
            vec![PaymentBlocker::StoreClosed]
        );
    }
}
