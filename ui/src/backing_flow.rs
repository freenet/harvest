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

/// How many blocks behind the newest known one a new backing is dated.
///
/// A reader leaves out a backing dated above ITS tip
/// (`harvest_common::backing::current_backing`), and a buyer's node can be a
/// block or two behind the seller's. Dated at the seller's tip, a new store
/// would read as unbacked to exactly those buyers until they caught up
/// (harvest#93 review, Should Fix 5). Six blocks is about an hour.
///
/// The block is also how readers ORDER backings (the highest is current),
/// so a new backing dated six blocks back ranks below one dated within the
/// last hour. That costs nothing in practice: a new backing becomes current
/// by retiring the old one, not by outranking it.
pub(crate) const BACKING_BLOCK_DEPTH: usize = 6;

/// The block a backing made now is dated to: [`BACKING_BLOCK_DEPTH`] behind
/// the newest this reader holds, or the oldest it holds if it holds fewer.
pub(crate) fn backing_block(
    tip: &crate::state::TipView,
) -> Option<freenet_bitcoin_common::BlockAnchor> {
    let row = tip
        .recent_blocks
        .get(BACKING_BLOCK_DEPTH)
        .or_else(|| tip.recent_blocks.last())?;
    Some(freenet_bitcoin_common::BlockAnchor {
        height: row.height,
        hash: row.hash,
    })
}

impl AppState {
    /// Start creating a store for the Ghost Key `fingerprint`: record what is
    /// known, and return the request id `CreateStoreKey` must go out under.
    ///
    /// `carried_listings` are listings to re-sign into the new store once it
    /// exists; empty for an ordinary new store. See
    /// [`AppState::move_legacy_store`].
    ///
    /// # Refused, rather than started, when (harvest#93 review, Must Fix 3)
    ///
    /// * a creation is already under way (`store_creation_in_flight` stays
    ///   set until the store is published or creation fails, so a second
    ///   click, or a retry while the first is still going, cannot make a
    ///   second store backed by the same Ghost Key);
    /// * the Ghost Key already backs a store this reader has loaded: a Ghost
    ///   Key backs one store at a time (section 6.2), and a second store
    ///   would make both count for nothing;
    /// * there is no recent block to date the backing to, checked BEFORE a
    ///   store key is minted, so a creation that could not finish does not
    ///   burn one of the delegate's store-key slots.
    pub(crate) fn begin_store_creation(
        &mut self,
        fingerprint: String,
        seller_verifying_key_bytes: [u8; 32],
        details: StoreDetails,
        carried_listings: Vec<Listing>,
        another_store: bool,
    ) -> Result<u64, String> {
        if self.store_creation_in_flight.is_some() {
            return Err("a store is already being created; wait for it to finish".into());
        }
        // Section 6.2 is checked once the store key is known
        // (`on_store_key_created`), not here: a retry of a creation whose
        // store already exists must not be refused by that very store, and
        // until the delegate answers, this tab cannot tell which store a
        // retry resumes (#98 review, M1).
        let network = crate::gateway::bitcoin_config::default_network();
        if self
            .bitcoin
            .tips
            .get(&network)
            .and_then(backing_block)
            .is_none()
        {
            return Err(NO_BLOCK_FOR_BACKING.to_string());
        }
        self.store_creation_in_flight = Some(fingerprint.clone());
        let store_key_request = self.next_messaging_request_id();
        self.pending_store_creation = Some(PendingStoreCreation {
            another_store,
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
        Ok(store_key_request)
    }

    /// The name of a loaded store whose current backing is the Ghost Key
    /// `backer`, if any: the seller-facing half of section 6.2. A store
    /// owned by `except` (the store a retry is re-creating) does not count.
    pub(crate) fn store_backed_by(
        &self,
        backer: &[u8; 32],
        except: Option<[u8; 32]>,
    ) -> Option<String> {
        self.browsing_stores.values().find_map(|store| {
            let view = store.backing.as_ref()?;
            let owner = store.backing_state.owner.map(|k| k.to_bytes());
            (view.backer == *backer && (except.is_none() || owner != except)).then(|| {
                store
                    .info
                    .as_ref()
                    .map(|info| info.store_name.clone())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| "another store".to_string())
            })
        })
    }

    /// A store creation (or move) has failed: say so, and release it so the
    /// seller can try again. Every failure after [`Self::begin_store_creation`]
    /// comes through here, because a failure that left
    /// `store_creation_in_flight` set would leave "Creating contracts..." on
    /// screen with no way to retry.
    pub(crate) fn store_creation_failed(&mut self, why: &str) {
        self.store_creation_in_flight = None;
        self.store_publishing = false;
        self.pending_store_creation = None;
        self.notifications
            .push(format!("Store creation failed: {why}"));
    }

    /// The seller gave up on a creation that is not finishing (#98 review,
    /// L1): release it and withdraw the signatures it asked for. The store
    /// key and any signed backing are kept, so trying again resumes it.
    pub(crate) fn cancel_store_creation(&mut self) {
        // Once the PUTs are under way the creation finishes or fails on its
        // own; releasing it here would let a second one start beside it.
        if self.store_publishing {
            return;
        }
        self.pending_signatures.retain(|pending| {
            !matches!(
                pending,
                PendingSignature::BackingStatement(_) | PendingSignature::BackingAcceptance(_)
            )
        });
        self.store_creation_in_flight = None;
        self.pending_store_creation = None;
        self.notifications
            .push("Store creation cancelled. Trying again picks up where it stopped.".to_string());
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
                // The delegate answers the same key to a retry; a backing
                // kept for another key is for a creation that is gone.
                if self
                    .resumable_backing
                    .as_ref()
                    .is_some_and(|b| b.statement.store.to_bytes() != key)
                {
                    self.resumable_backing = None;
                }
                // Section 6.2 again, now the key is known: a store of this
                // key is the one being resumed, not another store. The
                // seller can say they meant a second store (see
                // `SecondStoreOffer`), and then this does not apply.
                let backer = pending.seller_verifying_key_bytes;
                let deliberate = pending.another_store;
                let refused = (!deliberate)
                    .then(|| self.store_backed_by(&backer, Some(key)))
                    .flatten();
                if let Some(name) = refused {
                    self.offer_second_store(&name);
                    self.store_creation_failed(&format!(
                        "this Ghost Key already backs {name}. A Ghost Key backs one store at a \
                         time: use a different Ghost Key, or open a second store under this one \
                         on purpose"
                    ));
                    return;
                }
                if let Some(pending) = self.pending_store_creation.as_mut() {
                    pending.store_verifying_key = Some(key);
                }
                // The record and inbox keys derive from the store key
                // (harvest#93 phase 1b); creation waits on them. A retry
                // gets the same key back, whose subkeys this session may
                // already hold: use them, or the delegate, asked once per
                // session, is never asked again and creation waits forever
                // (#99 re-check).
                if !self.fill_creation_from_subkeys(key) {
                    self.request_store_subkeys(key);
                }
                self.start_store_creation_if_ready();
            }
            Err(why) => {
                self.store_creation_failed(&format!("no key could be made for the store: {why}"))
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
        // A retry: the backing both keys signed last time is reused, so no
        // signature is asked for again and the same store is published.
        if let Some(backing) = self.resumable_backing.clone().filter(|b| {
            Some(b.statement.store.to_bytes()) == creation.store_verifying_key
                && b.statement.backer.to_bytes() == creation.seller_verifying_key_bytes
                && b.verify(&b.statement.store).is_ok()
        }) {
            self.publish_backed_store(creation, backing);
            return;
        }
        let Some(store_key) = creation
            .store_verifying_key
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        else {
            self.store_creation_failed("the store key is not a valid key.");
            return;
        };
        let Ok(backer) =
            ed25519_dalek::VerifyingKey::from_bytes(&creation.seller_verifying_key_bytes)
        else {
            self.store_creation_failed("the Ghost Key's verifying key is not known.");
            return;
        };
        let network = crate::gateway::bitcoin_config::default_network();
        let Some(block) = self.bitcoin.tips.get(&network).and_then(backing_block) else {
            self.store_creation_failed(NO_BLOCK_FOR_BACKING);
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
            self.store_creation_failed(&e);
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
            self.store_creation_failed(&format!("the backing did not verify ({why})."));
            return;
        }
        self.resumable_backing = Some(backing.clone());
        self.publish_backed_store(pending.creation, backing);
    }

    fn publish_backed_store(&mut self, creation: PendingStoreCreation, backing: AuthorizedBacking) {
        self.store_publishing = true;
        #[cfg(target_arch = "wasm32")]
        crate::state::spawn_store_creation(creation, backing);
        #[cfg(not(target_arch = "wasm32"))]
        self.created_backings.push((creation, backing));
    }

    /// Queue a listing for the store key's signature, for the store
    /// `store_contract_id`, which must be one of ours with a store key.
    ///
    /// The listing has to carry the certificate of the Ghost Key
    /// `fingerprint`, and the store key's answer brings none (harvest#93), so
    /// it is attached here, before signing (`certificate_for`). When this
    /// device has no copy yet, the listing waits in
    /// `listings_awaiting_certificate` and the vault is asked for it. It is
    /// never sent without one: before #118 it went out with an empty
    /// certificate, and every buyer was told it was not the seller's and
    /// offered no way to buy it.
    pub(crate) fn queue_listing_signature(
        &mut self,
        store_contract_id: Vec<u8>,
        fingerprint: String,
        listing: Listing,
    ) -> Result<(), String> {
        if self.store_owner_key(&store_contract_id).is_none() {
            return Err(crate::state::NO_STORE_KEY_MESSAGE.to_string());
        }
        let mut pending = crate::state::PendingListing {
            fingerprint,
            listing,
            store_contract_id: Some(store_contract_id),
            certificate_pem: String::new(),
        };
        if let Some(pem) = self.certificate_for(&pending) {
            pending.certificate_pem = pem;
            return self.request_listing_signature(pending);
        }
        // Asked for every listing that waits, not once per Ghost Key, so
        // adding a listing again is a real retry if an earlier request was
        // lost. A duplicate answer costs nothing -- any `Certificate`
        // releases every listing waiting on that key -- but a duplicate
        // REFUSAL is not free: a refusal names no request, so a second one
        // landing after the first has cleared the vault can be taken for
        // whatever was asked next. Rare, since the backing's certificate
        // spares the vault in the ordinary case, and bounded to one wrong
        // attribution.
        let fingerprint = pending.fingerprint.clone();
        dioxus::logger::tracing::info!(
            "Listing \"{}\" is waiting on the certificate for {fingerprint}",
            pending.listing.title
        );
        self.listings_awaiting_certificate
            .push(crate::state::ListingAwaitingCertificate {
                since_ms: crate::state::now_ms(),
                pending,
            });
        #[cfg(target_arch = "wasm32")]
        {
            crate::state::request_certificate(fingerprint);
            spawn_listing_certificate_timeout();
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = fingerprint;
        Ok(())
    }

    /// The certificate a listing for `pending`'s store, signed for the Ghost
    /// Key `pending.fingerprint`, should carry, if this device has it.
    ///
    /// The vault's answer, if this session has had one; otherwise the
    /// certificate inside that Ghost Key's own backing of the store, as last
    /// loaded. The second is the one a buyer already checks the store
    /// against, it certifies the same key, and it needs no round trip to the
    /// vault, so the ordinary case -- the seller's store is loaded -- signs
    /// at once.
    fn certificate_for(&self, pending: &crate::state::PendingListing) -> Option<String> {
        let usable = |pem: &String| !pem.trim().is_empty();
        if let Some(pem) = self
            .certificates
            .get(&pending.fingerprint)
            .filter(|p| usable(p))
        {
            return Some(pem.clone());
        }
        let backer = self
            .ghostkeys
            .iter()
            .find(|key| key.fingerprint == pending.fingerprint)?
            .verifying_key_bytes
            .as_deref()?;
        let backer: [u8; 32] = backer.try_into().ok()?;
        self.browsing_stores
            .get(pending.store_contract_id.as_deref()?)?
            .backing_state
            .backings
            .records
            .get(&harvest_common::store::Bytes32(backer))
            .map(|backing| &backing.statement.certificate_pem)
            .filter(|pem| usable(pem))
            .cloned()
    }

    /// Send a listing that already carries its certificate for the store
    /// key's signature.
    fn request_listing_signature(
        &mut self,
        pending: crate::state::PendingListing,
    ) -> Result<(), String> {
        debug_assert!(!pending.certificate_pem.trim().is_empty());
        let store_key = pending
            .store_contract_id
            .as_deref()
            .and_then(|id| self.store_owner_key(id))
            .ok_or(crate::state::NO_STORE_KEY_MESSAGE)?;
        self.request_store_key_signature(PendingSignature::Listing(pending), store_key.to_bytes())
    }

    /// A certificate response for `fingerprint` has arrived: send the
    /// listings waiting on it for signing, or, if there is still no
    /// certificate to attach, drop them and say so rather than wait forever.
    pub(crate) fn release_listings_awaiting_certificate(&mut self, fingerprint: &str) {
        let (ready, waiting): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.listings_awaiting_certificate)
                .into_iter()
                .partition(|waiting| waiting.pending.fingerprint == fingerprint);
        self.listings_awaiting_certificate = waiting;
        for crate::state::ListingAwaitingCertificate { mut pending, .. } in ready {
            let title = pending.listing.title.clone();
            let Some(pem) = self.certificate_for(&pending) else {
                self.notifications.push(listing_not_published(
                    &title,
                    "the Ghost Key vault returned no certificate for your Ghost Key",
                ));
                continue;
            };
            pending.certificate_pem = pem;
            if let Err(e) = self.request_listing_signature(pending) {
                // Not "add it again": the store itself cannot be signed for.
                self.notifications
                    .push(format!("Your listing \"{title}\" was not published: {e}"));
            }
        }
    }

    /// Give up on the listings waiting on a certificate -- those for
    /// `fingerprint`, or all of them for `None` -- because it is not coming.
    ///
    /// Each is named in a notification, so the seller knows to add it again.
    /// A parked listing also counts as vault work under way
    /// (`user_signature_under_way`), which holds back custody and watch
    /// requests, so leaving one parked after its answer failed would stall
    /// those for the rest of the session.
    pub(crate) fn drop_listings_awaiting_certificate(
        &mut self,
        fingerprint: Option<&str>,
        why: &str,
    ) {
        let (dropped, kept): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.listings_awaiting_certificate)
                .into_iter()
                .partition(|waiting| {
                    fingerprint.is_none_or(|fp| waiting.pending.fingerprint == fp)
                });
        self.listings_awaiting_certificate = kept;
        for waiting in dropped {
            self.notifications
                .push(listing_not_published(&waiting.pending.listing.title, why));
        }
    }

    /// Give up on the listings that have waited on a certificate for
    /// [`crate::state::LISTING_CERTIFICATE_TIMEOUT_MS`] or longer.
    ///
    /// A request the vault never answers -- a lost message, a prompt left
    /// unanswered -- would otherwise hold the listing, and the vault with it,
    /// until a reload, and the seller would never learn it was not published.
    pub(crate) fn expire_listings_awaiting_certificate(&mut self, now_ms: u64) {
        let (expired, kept): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.listings_awaiting_certificate)
                .into_iter()
                .partition(|waiting| {
                    now_ms.saturating_sub(waiting.since_ms)
                        >= crate::state::LISTING_CERTIFICATE_TIMEOUT_MS
                });
        self.listings_awaiting_certificate = kept;
        if expired.is_empty() {
            return;
        }
        for waiting in expired {
            self.notifications.push(listing_not_published(
                &waiting.pending.listing.title,
                "the Ghost Key vault did not send your Ghost Key's certificate in time",
            ));
        }
        // The vault may be free now for a custody request that was deferred
        // while the listing waited.
        self.start_custody_where_needed();
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

    /// Whether the Ghost Key `fingerprint` has a store made before revision 2
    /// whose state has not arrived yet, and no revision-2 store: My Store
    /// waits for it rather than offering "Create Store", which would make a
    /// second store instead of moving this one (#98 review, L3).
    pub(crate) fn legacy_store_loading(&self, fingerprint: &str) -> bool {
        let Some(stores) = self.my_stores.get(fingerprint) else {
            return false;
        };
        !stores.iter().any(|s| s.store_verifying_key.is_some())
            && stores.iter().any(|s| {
                s.store_verifying_key.is_none()
                    && self
                        .browsing_stores
                        .get(&s.store_contract_id)
                        .is_none_or(|loaded| loaded.owner.is_none())
            })
    }

    /// Remember the creation the section 6.2 refusal just stopped, so My
    /// Store can ask whether the seller meant a second store under this
    /// Ghost Key. Called before `store_creation_failed`, which takes the
    /// pending creation away.
    fn offer_second_store(&mut self, other_store: &str) {
        let Some(pending) = self.pending_store_creation.as_ref() else {
            return;
        };
        self.second_store_offer = Some(crate::state::SecondStoreOffer {
            fingerprint: pending.ghostkey_fingerprint.clone(),
            seller_verifying_key_bytes: pending.seller_verifying_key_bytes,
            other_store: other_store.to_string(),
            details: StoreDetails {
                store_name: pending.store_name.clone(),
                description: pending.description.clone(),
            },
            carried_listings: pending.carried_listings.clone(),
        });
    }

    /// The seller said yes to a second store under this Ghost Key: start the
    /// creation again, this time telling the delegate it is deliberate.
    pub(crate) fn confirm_second_store(&mut self) -> Result<u64, String> {
        let offer = self
            .second_store_offer
            .take()
            .ok_or("there is no store waiting on that answer")?;
        self.begin_store_creation(
            offer.fingerprint,
            offer.seller_verifying_key_bytes,
            offer.details,
            offer.carried_listings,
            true,
        )
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
        self.begin_store_creation(
            fingerprint.to_string(),
            seller_verifying_key_bytes,
            details,
            listings,
            false,
        )
    }
}

/// What a seller is told about a listing that was not published because its
/// certificate could not be had (#118).
fn listing_not_published(title: &str, why: &str) -> String {
    format!("Your listing \"{title}\" was not published ({why}). Add it again to retry.")
}

/// Expire listings still waiting on their certificate once they are due.
///
/// Re-checked rather than fired once, like custody's timer: a one-shot timer
/// that goes off a millisecond early would leave the listing waiting for the
/// session. Stops as soon as nothing waits.
#[cfg(target_arch = "wasm32")]
fn spawn_listing_certificate_timeout() {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};
        for _ in 0..4 {
            gloo_timers::future::TimeoutFuture::new(
                (crate::state::LISTING_CERTIFICATE_TIMEOUT_MS / 2).max(1) as u32,
            )
            .await;
            crate::gateway::APP_STATE
                .write()
                .expire_listings_awaiting_certificate(crate::state::now_ms());
            if crate::gateway::APP_STATE
                .read()
                .listings_awaiting_certificate
                .is_empty()
            {
                return;
            }
        }
    });
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
            state.store_creation_failed(&reason);
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
    use crate::state::{BlockRow, PaymentBlocker, Signer, TipView};
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
            // Newest first, ten deep.
            recent_blocks: (0..10u32)
                .map(|back| BlockRow {
                    height: TIP - back,
                    hash: BlockHash([0x33u8.wrapping_add(back as u8); 32]),
                    tx_count: 1,
                    block_time: 0,
                })
                .collect(),
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
            another_store: false,
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
    pub(crate) fn sign<T: serde::Serialize>(key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
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
        let request = state
            .begin_store_creation(
                FINGERPRINT.to_string(),
                ghost().verifying_key().to_bytes(),
                StoreDetails {
                    store_name: "Bean Shop".to_string(),
                    description: String::new(),
                },
                Vec::new(),
                false,
            )
            .expect("started");
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
            statement.block.height,
            TIP - BACKING_BLOCK_DEPTH as u32,
            "dated a few blocks behind the newest this reader has (Should Fix 5)"
        );
        assert!(state.pending_store_creation.is_none());
    }

    #[test]
    fn a_refused_store_key_abandons_the_creation_and_says_so() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        let request = state
            .begin_store_creation(
                FINGERPRINT.to_string(),
                ghost().verifying_key().to_bytes(),
                StoreDetails::default(),
                Vec::new(),
                false,
            )
            .expect("started");
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Err("full".to_string()),
        });
        assert!(state.pending_store_creation.is_none());
        assert!(state.notifications.iter().any(|n| n.contains("full")));
        assert!(
            state.store_creation_in_flight.is_none(),
            "a failure releases the creation, so the seller can retry"
        );
    }

    /// Single-flight (harvest#93 review, Must Fix 3): while a creation is
    /// under way, however far it has got, a second is refused, including
    /// after `pending_store_creation` has been taken. Mutated red by removing
    /// the in-flight check from `begin_store_creation`.
    #[test]
    fn a_second_creation_is_refused_until_the_first_finishes() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        let start = |state: &mut AppState| {
            state.begin_store_creation(
                FINGERPRINT.to_string(),
                ghost().verifying_key().to_bytes(),
                StoreDetails::default(),
                Vec::new(),
                false,
            )
        };
        start(&mut state).expect("the first starts");
        // Its inputs arrive and the pending creation is taken, as it is in
        // the real flow, long before the store is published.
        state.pending_store_creation = None;
        let err = start(&mut state).expect_err("a second is refused");
        assert!(err.contains("already being created"), "{err}");

        state.store_creation_failed("the vault said no");
        start(&mut state).expect("after a failure the seller can try again");
    }

    /// A Ghost Key backs one store at a time (section 6.2): creating or
    /// moving a store with one that already backs a loaded store is refused,
    /// with the store named. Mutated red by removing the check.
    /// Start a creation for `ghost()` and hand it every input but the store
    /// key.
    fn started(state: &mut AppState) -> u64 {
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        let request = state
            .begin_store_creation(
                FINGERPRINT.to_string(),
                ghost().verifying_key().to_bytes(),
                StoreDetails {
                    store_name: "Bean Shop".to_string(),
                    description: String::new(),
                },
                Vec::new(),
                false,
            )
            .expect("started");
        let pending = state.pending_store_creation.as_mut().unwrap();
        pending.certificate_pem = "CERT".to_string();
        request
    }

    /// The Harvest delegate's answer to `GetStoreSubkeys` for `store_key()`,
    /// as the real path receives it (#99 re-check: a retry must not depend
    /// on a hand-filled record key).
    fn answer_subkeys(state: &mut AppState) {
        state.on_delegate_response(HarvestDelegateResponse::StoreSubkeys {
            request_id: 0,
            store_verifying_key: store_key().verifying_key().to_bytes(),
            result: Ok(harvest_common::delegate::StoreSubkeyInfo {
                inbox_public_key: [0x1b; 32],
                record_public_key: vec![0x2e; 4],
            }),
        });
    }

    /// A publish that failed after both keys signed the backing is retried
    /// with the SAME store key (the delegate resumes it) and the SAME
    /// backing, asking for no signature again, so the same store is
    /// published (#98 review, M1). Mutated red by not keeping the backing
    /// and by not reusing it.
    #[test]
    fn a_retry_after_a_failed_publish_reuses_the_key_and_the_backing() {
        let mut state = AppState::default();
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        answer_subkeys(&mut state);
        let dated = queued_statement(&state).expect("asked to back");
        state.on_ghostkey_response(vault_answer(&ghost(), &dated));
        state.on_delegate_response(store_key_answer(&store_key(), &dated));
        let (_, first) = state.created_backings.pop().expect("published once");
        // The PUT failed.
        state.store_creation_failed("the node refused the PUT");
        assert!(state.store_creation_in_flight.is_none());

        // The retry: the delegate answers the same key, and its subkeys are
        // already known from the first attempt, so nothing is asked of the
        // delegate again (#99 re-check: this hung before).
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        assert!(
            state.pending_signatures.is_empty(),
            "no signature is asked for again"
        );
        let (_, again) = state.created_backings.pop().expect("published again");
        assert_eq!(again, first, "the same backing, so the same store");
    }

    /// The store a retry is re-creating does not count against section
    /// 6.2: its Ghost Key backs it, and that is the point. Another store it
    /// backs still does. Mutated red by dropping the `except` owner.
    #[test]
    fn a_retry_is_not_refused_by_the_store_it_is_re_creating() {
        let mut state = AppState::default();
        load_backed(&mut state, 9, 0x62, vec![signed_backing(0x62, 0x61, 10)]);
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        assert!(
            state.store_creation_in_flight.is_some(),
            "resumed, not refused: {:?}",
            state.notifications
        );

        // A different key answered while the Ghost Key backs that store: a
        // second store, refused.
        let mut state = AppState::default();
        load_backed(&mut state, 9, 0x62, vec![signed_backing(0x62, 0x61, 10)]);
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(SigningKey::from_bytes(&[0x63; 32])
                .verifying_key()
                .to_bytes()),
        });
        assert!(state.store_creation_in_flight.is_none());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("already backs")));
    }

    /// A delegate Error while the creation waits for its store key releases
    /// it; Cancel releases it at any stage and withdraws its signatures
    /// (#98 review, L1). Mutated red by removing each.
    #[test]
    fn a_stalled_creation_can_be_released() {
        let mut state = AppState::default();
        started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::Error {
            message: "no".into(),
        });
        assert!(state.store_creation_in_flight.is_none());

        let mut state = AppState::default();
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        answer_subkeys(&mut state);
        assert!(!state.pending_signatures.is_empty(), "waiting on the vault");
        state.cancel_store_creation();
        assert!(state.store_creation_in_flight.is_none());
        assert!(state.pending_signatures.is_empty());

        // Once the PUTs are under way, Cancel does nothing (#98 re-check):
        // the single-flight marker stays until the creation ends.
        let mut state = AppState::default();
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        answer_subkeys(&mut state);
        let dated = queued_statement(&state).expect("asked to back");
        state.on_ghostkey_response(vault_answer(&ghost(), &dated));
        state.on_delegate_response(store_key_answer(&store_key(), &dated));
        assert!(state.store_publishing);
        state.cancel_store_creation();
        assert!(
            state.store_creation_in_flight.is_some(),
            "not released mid-PUT"
        );
    }

    /// A refusal under section 6.2 is escapable: the seller is offered the
    /// second store, and confirming starts the creation again with
    /// `another_store`, which the delegate's own rule honours. Mutated red
    /// by not recording the offer and by not carrying the flag.
    #[test]
    fn a_refused_second_store_can_be_confirmed() {
        let mut state = AppState::default();
        load_backed(&mut state, 9, 0x62, vec![signed_backing(0x62, 0x61, 10)]);
        let request = started(&mut state);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(SigningKey::from_bytes(&[0x63; 32])
                .verifying_key()
                .to_bytes()),
        });
        let offer = state.second_store_offer.clone().expect("offered");
        assert_eq!(offer.fingerprint, FINGERPRINT);
        assert_eq!(offer.details.store_name, "Bean Shop");
        assert!(state.store_creation_in_flight.is_none());

        state.confirm_second_store().expect("started again");
        assert!(state.second_store_offer.is_none(), "answered");
        assert!(
            state
                .pending_store_creation
                .as_ref()
                .is_some_and(|p| p.another_store),
            "the delegate is told it is deliberate"
        );

        // And this tab's own check lets it through now.
        let request = state
            .pending_store_creation
            .as_ref()
            .and_then(|p| p.store_key_request)
            .expect("a key was asked for");
        {
            let pending = state.pending_store_creation.as_mut().unwrap();
            pending.certificate_pem = "CERT".to_string();
            pending.rsa_public_key_der = Some(vec![1]);
        }
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(SigningKey::from_bytes(&[0x64; 32])
                .verifying_key()
                .to_bytes()),
        });
        assert!(
            queued_statement(&state).is_some(),
            "the second store is being backed: {:?}",
            state.notifications
        );
    }

    /// A store made before revision 2 that has not loaded holds back
    /// "Create Store"; once loaded it is offered a move instead (#98
    /// review, L3). Mutated red by returning false.
    #[test]
    fn an_unloaded_legacy_store_holds_back_creation() {
        let mut state = AppState::default();
        state
            .my_stores
            .insert(FINGERPRINT.to_string(), vec![legacy_registration()]);
        assert!(state.legacy_store_loading(FINGERPRINT));
        let id = legacy_registration().store_contract_id;
        state.browsing_stores.entry(id).or_default().owner = Some([0x61; 32]);
        assert!(!state.legacy_store_loading(FINGERPRINT));
        assert!(!AppState::default().legacy_store_loading(FINGERPRINT));
    }

    #[test]
    fn a_ghost_key_that_already_backs_a_store_cannot_back_another() {
        let mut state = AppState::default();
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
        let store = state.browsing_stores.entry(vec![9; 32]).or_default();
        store.backing = Some(crate::state::BackingView {
            store: [1; 32],
            backer: ghost().verifying_key().to_bytes(),
            certificate_status: crate::ghostkey_cert::CertificateStatus::Verified,
            block_height: TIP,
        });
        store.info = Some(harvest_common::store::StoreInfoV1 {
            version: 1,
            certificate_pem: String::new(),
            seller_fingerprint: String::new(),
            reputation_contract_id: [0; 32],
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            encryption_public_key: None,
            record_public_key: None,
        });
        // Checked once the store key is known (a retry must be able to
        // resume its own store; see `a_retry_is_not_refused_...`).
        let request = state
            .begin_store_creation(
                FINGERPRINT.to_string(),
                ghost().verifying_key().to_bytes(),
                StoreDetails::default(),
                Vec::new(),
                false,
            )
            .expect("started");
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyCreated {
            request_id: request,
            result: Ok(store_key().verifying_key().to_bytes()),
        });
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("already backs Bean Shop")));
        assert!(state.store_creation_in_flight.is_none());
        assert!(queued_statement(&state).is_none(), "nothing signed");
    }

    /// With no block to date the backing to, nothing starts, and so no store
    /// key is minted to be thrown away (Should Fix 8).
    #[test]
    fn with_no_block_no_creation_starts() {
        let mut state = AppState::default();
        let err = state
            .begin_store_creation(
                FINGERPRINT.to_string(),
                ghost().verifying_key().to_bytes(),
                StoreDetails::default(),
                Vec::new(),
                false,
            )
            .expect_err("no tip");
        assert_eq!(err, NO_BLOCK_FOR_BACKING);
        assert!(state.pending_store_creation.is_none());
        assert!(state.store_creation_in_flight.is_none());
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
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, tip());
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
            record_public_key: None,
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

    /// A signed backing of the store keyed by `store` seed by the Ghost Key
    /// `backer` seed, dated `height`.
    pub(crate) fn signed_backing(store: u8, backer: u8, height: u32) -> AuthorizedBacking {
        let store_key = SigningKey::from_bytes(&[store; 32]);
        let ghost = SigningKey::from_bytes(&[backer; 32]);
        let statement = BackingStatement {
            store: store_key.verifying_key(),
            backer: ghost.verifying_key(),
            certificate_pem: format!("CERT-{backer}"),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height,
                hash: BlockHash([1; 32]),
            },
        };
        let (backer_scoped_payload, backer_signature) = sign(&ghost, &statement);
        let (acceptance_scoped_payload, acceptance_signature) = sign(
            &store_key,
            &harvest_common::backing::BackingAcceptance {
                backing: statement.clone(),
            },
        );
        AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        }
    }

    /// Load a store owned by `store`, holding `backings`, into `state` the
    /// way the ingest path keeps it, with each backing's certificate already
    /// judged genuine (no test holds Freenet's master key, so the verdict is
    /// seeded into the cache `backing_view` consults).
    pub(crate) fn load_backed(
        state: &mut AppState,
        id: u8,
        store: u8,
        backings: Vec<AuthorizedBacking>,
    ) {
        for b in &backings {
            state.certificate_verdicts.borrow_mut().insert(
                (
                    b.statement.certificate_pem.clone(),
                    b.statement.backer.to_bytes(),
                ),
                crate::ghostkey_cert::CertificateStatus::Verified,
            );
        }
        let backing_state = harvest_common::store::StoreStateV1 {
            owner: Some(SigningKey::from_bytes(&[store; 32]).verifying_key()),
            backings: harvest_common::backing::BackingsV1 {
                records: backings
                    .into_iter()
                    .map(|b| {
                        (
                            harvest_common::store::Bytes32(b.statement.backer.to_bytes()),
                            b,
                        )
                    })
                    .collect(),
            },
            ..Default::default()
        };
        state
            .browsing_stores
            .entry(vec![id; 32])
            .or_default()
            .backing_state = backing_state;
        state.refresh_backing_verdicts();
    }

    /// The ordinary case of #118: the seller's store is loaded, so the
    /// certificate a listing needs is already here, inside the Ghost Key's
    /// own backing of that store -- the certificate buyers check the store
    /// against. The listing is signed at once, carrying it, with no vault
    /// round trip. A connected Ghost Key that is NOT the backer does not get
    /// the backer's certificate: its listing waits for its own.
    ///
    /// Mutated red by removing the backing lookup from `certificate_for`, and
    /// by matching any backing rather than the Ghost Key's own.
    #[test]
    fn a_listing_takes_its_certificate_from_the_ghost_keys_own_backing() {
        const STORE: u8 = 0x71;
        const BACKER: u8 = 0x41;
        let listing = |title: &str| {
            harvest_common::listing::Listing {
                id: harvest_common::listing::ListingId([0; 32]),
                title: title.to_string(),
                description: String::new(),
                kind: harvest_common::listing::ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }
            .with_derived_id()
        };
        let seller = |fingerprint: &str, key: u8| {
            let mut state = AppState::default();
            load_backed(
                &mut state,
                5,
                STORE,
                vec![signed_backing(STORE, BACKER, 10)],
            );
            state.my_stores.insert(
                fingerprint.to_string(),
                vec![harvest_common::StoreRegistration {
                    store_contract_id: vec![5; 32],
                    reputation_contract_id: vec![6; 32],
                    mailbox_contract_id: vec![7; 32],
                    store_contract_key: None,
                    store_verifying_key: Some(store_key_of(STORE)),
                }],
            );
            state.ghostkeys.push(ghostkey_common::GhostKeyInfo {
                fingerprint: fingerprint.to_string(),
                label: None,
                notary_info: String::new(),
                verifying_key_bytes: Some(
                    SigningKey::from_bytes(&[key; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                ),
                backed_up: false,
            });
            state
        };

        let mut state = seller(FINGERPRINT, BACKER);
        assert!(state.certificates.is_empty(), "nothing from the vault");
        state
            .queue_listing_signature(vec![5; 32], FINGERPRINT.to_string(), listing("Beans"))
            .expect("accepted");
        assert!(state.listings_awaiting_certificate.is_empty(), "no wait");
        let certificates: Vec<_> = state
            .pending_signatures
            .iter()
            .filter_map(|p| match p {
                PendingSignature::Listing(l) => Some(l.certificate_pem.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(certificates, vec![format!("CERT-{BACKER}")]);

        let mut stranger = seller("fp-stranger", 0x42);
        stranger
            .queue_listing_signature(vec![5; 32], "fp-stranger".to_string(), listing("Rice"))
            .expect("accepted");
        assert_eq!(
            stranger.listings_awaiting_certificate.len(),
            1,
            "another key's backing is not this key's certificate"
        );
        assert!(stranger.pending_signatures.is_empty());
    }

    fn store_key_of(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// A Ghost Key backing two loaded stores counts for NEITHER, and each
    /// comes back once the other stops being backed by it (section 6.2).
    /// Mutated red by skipping the `conflicted` check in
    /// `refresh_backing_verdicts`.
    #[test]
    fn a_key_backing_two_stores_counts_for_neither() {
        let mut state = AppState::default();
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, 0x41, 10)]);
        load_backed(&mut state, 2, 0x72, vec![signed_backing(0x72, 0x41, 10)]);
        load_backed(&mut state, 3, 0x73, vec![signed_backing(0x73, 0x42, 10)]);

        for id in [vec![1u8; 32], vec![2u8; 32]] {
            let store = &state.browsing_stores[&id];
            assert!(store.store_verifying_key.is_none());
            assert!(store.seller_verifying_key.is_none());
            assert!(!store.certificate_status.is_verified());
        }
        assert_eq!(
            state.browsing_stores[&vec![3u8; 32]].store_verifying_key,
            Some(store_key_of(0x73))
        );

        // The second store's backing moves to another key: the first counts
        // again.
        load_backed(&mut state, 2, 0x72, vec![signed_backing(0x72, 0x43, 10)]);
        assert_eq!(
            state.browsing_stores[&vec![1u8; 32]].store_verifying_key,
            Some(store_key_of(0x71))
        );
    }

    /// A backing dated above this reader's tip is not current yet, and
    /// becomes current when the tip catches up, without the store's state
    /// arriving again (harvest#93 review, Should Fix 5). Mutated red by not
    /// recomputing the verdicts in `apply_tip_state`.
    #[test]
    fn a_tip_update_makes_a_backing_dated_ahead_of_it_current() {
        let mut state = AppState::default();
        let mut behind = tip();
        behind.tip_height = Some(TIP - 10);
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, behind);
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, 0x41, TIP)]);
        assert!(state.browsing_stores[&vec![1u8; 32]]
            .store_verifying_key
            .is_none());

        // The tip contract reports the new block, through the real path.
        let entry = freenet_bitcoin_common::SignedTipEntry::sign(
            &SigningKey::from_bytes(&[0x22; 32]),
            &freenet_bitcoin_common::TipEntryBody {
                network: BitcoinNetwork::Signet,
                anchor: BlockAnchor {
                    height: TIP,
                    hash: BlockHash([0x33; 32]),
                },
                prev_hash: BlockHash([0x32; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .expect("sign a tip entry");
        let mut tip_state = freenet_bitcoin_common::BitcoinTipStateV1::default();
        tip_state.blocks.blocks.insert(TIP, entry);
        state.apply_tip_state(BitcoinNetwork::Signet, &tip_state);
        assert_eq!(
            state.browsing_stores[&vec![1u8; 32]].store_verifying_key,
            Some(store_key_of(0x71))
        );
    }

    /// A backing whose certificate does not verify is no backing to a buyer,
    /// and a store with none is unbacked.
    #[test]
    fn an_unverified_or_missing_backing_gives_no_identity() {
        let mut state = AppState::default();
        // Not seeded: "CERT-65" is judged for real, and is not a certificate.
        let backing_state = harvest_common::store::StoreStateV1 {
            owner: Some(SigningKey::from_bytes(&[0x71; 32]).verifying_key()),
            backings: harvest_common::backing::BackingsV1 {
                records: std::iter::once(signed_backing(0x71, 0x41, 10))
                    .map(|b| {
                        (
                            harvest_common::store::Bytes32(b.statement.backer.to_bytes()),
                            b,
                        )
                    })
                    .collect(),
            },
            ..Default::default()
        };
        state
            .browsing_stores
            .entry(vec![1; 32])
            .or_default()
            .backing_state = backing_state;
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
