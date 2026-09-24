//! A seller changing what is known about a listing after it is published
//! (harvest#70): how many are left, that it sold out, that it is taken down,
//! and editing it.
//!
//! A listing's terms never change (its id is a hash of them), so every one of
//! these is a store-key-signed [`ListingStatus`] with a higher revision than
//! the one it replaces. Editing the terms publishes a new listing, and takes
//! the old one down only once the new one has published, so a failed publish
//! leaves the old listing up rather than the store without either. The old
//! one stays in the store, so a buyer whose conversation names it can still
//! read what they asked about.
//!
//! # What the seller's page shows, and for how long
//!
//! A status is signed, then published, and the page reads it back out of the
//! store's own state like everything else. Between asking and the state
//! showing it, the row says "Saving" so the seller cannot act on the old
//! value (two quick "One sold" clicks would otherwise both count down from
//! the same number). That wait has two halves:
//!
//! * the store key signing: the pending-signature queue answers this, and
//!   every failure answer and failed send clears it;
//! * the publish: [`SentStatus`] answers this, cleared when the state arrives
//!   with the revision, when the publish fails, or after
//!   [`SAVING_WINDOW_MS`], so a publish whose echo never comes cannot hold the
//!   row forever (the #107 defect class).
//!
//! A signature the delegate never answers at all still holds its row until
//! reload; that is true of every store-key request and is tracked with them.

use harvest_common::listing::{
    AuthorizedListingStatus, Listing, ListingAvailability, ListingId, ListingStatus,
};

use crate::state::{AppState, PendingSignature};

/// How long a sent status holds its row at "Saving" waiting for the store's
/// state to show it. The seller's own node applies its own update at once,
/// so this is only reached when something went wrong without saying so.
pub(crate) const SAVING_WINDOW_MS: i64 = 60_000;

/// Said when a listing's availability could not be signed or published. A
/// listing with no status reads as on sale with no count, so an edited
/// listing whose carried-over status failed (sold out, or a count) is on sale
/// until the seller sets it again; the message says so, since the row alone
/// cannot (harvest#125 review).
pub(crate) const LISTING_STATUS_NOT_SAVED: &str =
    "A listing's availability was not saved, so buyers see what the store last had (an edited \
     listing shows as on sale with no count). Set it again from Listings.";

/// How long an edit's original shows "Saving" while its replacement goes out:
/// the certificate wait (`LISTING_CERTIFICATE_TIMEOUT_MS`) plus the saving
/// window, after which every drop path has reported.
pub(crate) const REPLACING_WINDOW_MS: i64 =
    crate::state::LISTING_CERTIFICATE_TIMEOUT_MS as i64 + SAVING_WINDOW_MS;

/// A listing status waiting for the store key's signature.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingListingStatus {
    pub store_contract_id: Vec<u8>,
    pub status: ListingStatus,
}

/// A status this session signed and sent.
#[derive(Clone, Debug, PartialEq)]
pub struct SentStatus {
    /// The highest revision sent for this listing: the floor for the next
    /// one, kept even after the row stops waiting, because a revision reused
    /// while the store's copy lags would tie with the first and be settled by
    /// encoding rather than by the seller's latest choice.
    pub revision: u64,
    /// When the row started waiting for the store's state, or `None` once it
    /// stopped (the state showed it, or the publish failed).
    pub waiting_since_ms: Option<i64>,
}

/// The revision a new status gets: above anything held or already asked for,
/// and no lower than the current time in milliseconds, so a later change wins
/// on another device that never saw the earlier one, clocks permitting.
///
/// `None` at the top of the range: a listing whose held revision is
/// `u64::MAX` can never be superseded, because every later status would tie
/// with it and ties go by encoding. Only the store key could have signed one.
pub(crate) fn next_revision(highest_known: Option<u64>, now_ms: u64) -> Option<u64> {
    match highest_known {
        Some(u64::MAX) => None,
        Some(known) => Some((known + 1).max(now_ms)),
        None => Some(now_ms.max(1)),
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// What an edit leaves a listing as.
///
/// On sale stays on sale, with the count the form gave. A sold-out listing
/// stays sold out unless the seller gave a count, which is a restock. A
/// taken-down listing is not edited (the page offers only "Put back").
pub(crate) fn availability_after_edit(
    current: &ListingAvailability,
    quantity: Option<u32>,
) -> ListingAvailability {
    match (current, quantity) {
        (ListingAvailability::Withdrawn, _) => ListingAvailability::Withdrawn,
        // Sold out, or counted down to none: blank keeps it off sale.
        (current, None) if !current.is_buyable() => ListingAvailability::SoldOut,
        (_, quantity) => ListingAvailability::Available { quantity },
    }
}

/// A new listing on its way to the network (harvest#161).
#[derive(Clone, Debug, PartialEq)]
pub struct Publishing {
    pub store_contract_id: Vec<u8>,
    pub title: String,
    /// The notice shown while it is on its way, taken down when it ends.
    pub notice: String,
}

impl AppState {
    /// A listing's availability as its store holds it: on sale and uncounted
    /// when the store holds no status for it.
    pub fn listing_availability(
        &self,
        store_contract_id: &[u8],
        listing: &ListingId,
    ) -> ListingAvailability {
        self.browsing_stores
            .get(store_contract_id)
            .map(|store| store.availability(listing))
            .unwrap_or_default()
    }

    fn held_revision(&self, store_contract_id: &[u8], listing: &ListingId) -> Option<u64> {
        self.browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.listing_statuses.get(listing))
            .map(|status| status.revision)
    }

    /// Whether a change to this listing is still on its way: waiting for the
    /// store key, or sent and not yet shown by the store's state.
    pub fn listing_status_pending(&self, store_contract_id: &[u8], listing: &ListingId) -> bool {
        self.listing_status_pending_at(store_contract_id, listing, now_ms())
    }

    pub(crate) fn listing_status_pending_at(
        &self,
        store_contract_id: &[u8],
        listing: &ListingId,
        now_ms: i64,
    ) -> bool {
        let signing = self.pending_signatures.iter().any(|pending| {
            matches!(pending, PendingSignature::ListingStatus(p)
                if p.store_contract_id == store_contract_id && p.status.listing == *listing)
        });
        let held = self.held_revision(store_contract_id, listing);
        let publishing = self
            .listing_statuses_sent
            .get(&(store_contract_id.to_vec(), listing.clone()))
            .is_some_and(|sent| {
                sent.waiting_since_ms
                    .is_some_and(|since| now_ms - since < SAVING_WINDOW_MS)
                    && held.is_none_or(|held| held < sent.revision)
            });
        // An edit of this listing whose replacement has not published yet:
        // a second edit now would publish a second replacement beside the
        // first. Bounded like the rest, in case a drop path is ever missed.
        let replacing = self
            .withdraw_after_publish
            .values()
            .any(|(store, old, since)| {
                store.as_slice() == store_contract_id
                    && old == listing
                    && now_ms - since < REPLACING_WINDOW_MS
            });
        signing || publishing || replacing
    }

    /// Ask the store key to sign a new availability for one listing of one of
    /// our stores.
    pub(crate) fn queue_listing_status(
        &mut self,
        store_contract_id: Vec<u8>,
        listing: ListingId,
        availability: ListingAvailability,
    ) -> Result<(), String> {
        let now = u64::try_from(now_ms()).unwrap_or(0);
        self.queue_listing_status_at(store_contract_id, listing, availability, now)
    }

    pub(crate) fn queue_listing_status_at(
        &mut self,
        store_contract_id: Vec<u8>,
        listing: ListingId,
        availability: ListingAvailability,
        now_ms: u64,
    ) -> Result<(), String> {
        let store_key = self
            .store_owner_key(&store_contract_id)
            .ok_or(crate::state::NO_STORE_KEY_MESSAGE)?;
        let held = self.held_revision(&store_contract_id, &listing);
        // A second click before the first is signed must not reuse its
        // revision: two statuses at one revision resolve by encoding, not by
        // which the seller chose last. Nor one sent whose echo has not come.
        let asked = self
            .pending_signatures
            .iter()
            .filter_map(|pending| match pending {
                PendingSignature::ListingStatus(p)
                    if p.store_contract_id == store_contract_id && p.status.listing == listing =>
                {
                    Some(p.status.revision)
                }
                _ => None,
            })
            .max();
        let sent = self
            .listing_statuses_sent
            .get(&(store_contract_id.clone(), listing.clone()))
            .map(|sent| sent.revision);
        let revision = next_revision(held.max(asked).max(sent), now_ms)
            .ok_or("this listing's status is at the last revision there is and cannot change")?;
        self.request_store_key_signature(
            PendingSignature::ListingStatus(Box::new(PendingListingStatus {
                store_contract_id,
                status: ListingStatus {
                    listing,
                    revision,
                    availability,
                },
            })),
            store_key.to_bytes(),
        )
    }

    /// Publish a new listing to one of our stores, with a count when the
    /// seller gave one.
    ///
    /// The status names the listing by the id its terms give, which is known
    /// before either is signed, so the two go out independently and in either
    /// order; a status arriving first is kept (see
    /// `harvest_common::store::ListingStatusesV1`).
    pub(crate) fn publish_new_listing(
        &mut self,
        store_contract_id: Vec<u8>,
        fingerprint: String,
        listing: Listing,
        quantity: Option<u32>,
    ) -> Result<(), String> {
        let availability = ListingAvailability::Available { quantity };
        let (id, title) = (listing.id.clone(), listing.title.clone());
        self.publish_listing_as(
            store_contract_id.clone(),
            fingerprint,
            listing,
            availability,
        )?;
        let notice = format!("Publishing \u{201c}{title}\u{201d}\u{2026}");
        self.notifications.push(notice.clone());
        self.publishing_listings.insert(
            id,
            Publishing {
                store_contract_id,
                title,
                notice,
            },
        );
        Ok(())
    }

    /// A new listing is no longer on its way: take its "Publishing" notice
    /// down (harvest#161). Notices otherwise stay for the session, so one
    /// left up reads as a publish that never finished.
    fn end_publishing(&mut self, listing: &ListingId) -> Option<Publishing> {
        let publishing = self.publishing_listings.remove(listing)?;
        self.notifications.retain(|n| *n != publishing.notice);
        Some(publishing)
    }

    /// A store's state arrived: every new listing it now holds is published.
    ///
    /// Only the state of the generation the listing was written to counts
    /// (harvest#164): an earlier generation can hold the same terms.
    pub(crate) fn settle_publishing(&mut self, contract_id: &[u8]) {
        let Some(store) = self.browsing_stores.get(contract_id) else {
            return;
        };
        let landed: Vec<ListingId> = self
            .publishing_listings
            .iter()
            .filter(|(id, p)| {
                self.current_generation_of(&p.store_contract_id) == contract_id
                    && store.listings.iter().any(|l| &l.listing.id == *id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in landed {
            self.end_publishing(&id);
        }
    }

    /// The generation a write to `store_contract_id` goes to.
    fn current_generation_of(&self, store_contract_id: &[u8]) -> Vec<u8> {
        match self.store_write_target(store_contract_id) {
            crate::state::StoreWriteTarget::Ready(id) => id,
            crate::state::StoreWriteTarget::Moving { current, .. } => current,
            crate::state::StoreWriteTarget::NotOurs => store_contract_id.to_vec(),
        }
    }

    /// The node refused an update to `contract_id` (harvest#161). Its error
    /// names the contract only in its text and carries no request id, so it
    /// cannot be matched to one write: every new listing waiting on that
    /// store is reported as not published, and a refusal matching none of
    /// them is still said, if the store is one of ours.
    pub(crate) fn on_update_refused(&mut self, contract_id: &[u8], reason: &str) {
        let waiting: Vec<ListingId> = self
            .publishing_listings
            .iter()
            .filter(|(_, p)| self.current_generation_of(&p.store_contract_id) == contract_id)
            .map(|(id, _)| id.clone())
            .collect();
        if waiting.is_empty() {
            if self.store_write_target(contract_id) != crate::state::StoreWriteTarget::NotOurs {
                self.notifications.push(format!(
                    "A change to your store was refused by the network: {reason}"
                ));
            }
            return;
        }
        for id in waiting {
            if let Some(publishing) = self.end_publishing(&id) {
                self.notifications.push(format!(
                    "Your listing \u{201c}{}\u{201d} was not published: the network refused \
                     it ({reason}).",
                    publishing.title
                ));
            }
        }
    }

    fn publish_listing_as(
        &mut self,
        store_contract_id: Vec<u8>,
        fingerprint: String,
        listing: Listing,
        availability: ListingAvailability,
    ) -> Result<(), String> {
        let id = listing.id.clone();
        self.queue_listing_signature(store_contract_id.clone(), fingerprint, listing)?;
        // No status is the same as on sale and uncounted, so that one is
        // not published.
        if availability != ListingAvailability::default() {
            self.queue_listing_status(store_contract_id, id, availability)?;
        }
        Ok(())
    }

    /// Replace one of our listings with an edited version.
    ///
    /// Edited terms are a new listing with a new id, published with the
    /// availability the old one had (see [`availability_after_edit`]); the old
    /// one is taken down once the new one has published
    /// ([`Self::on_listing_published`]). When only the count changed, the
    /// terms, and so the id, are the same, and only the status is published.
    pub(crate) fn replace_listing(
        &mut self,
        store_contract_id: Vec<u8>,
        fingerprint: String,
        old: ListingId,
        edited: Listing,
        quantity: Option<u32>,
    ) -> Result<(), String> {
        let current = self.listing_availability(&store_contract_id, &old);
        let wanted = availability_after_edit(&current, quantity);
        if edited.id == old {
            if current == wanted {
                return Ok(());
            }
            return self.queue_listing_status(store_contract_id, old, wanted);
        }
        let new_id = edited.id.clone();
        self.publish_listing_as(store_contract_id.clone(), fingerprint, edited, wanted)?;
        self.withdraw_after_publish
            .insert(new_id, (store_contract_id, old, now_ms()));
        Ok(())
    }

    /// A listing's publish finished: if it replaces one, take that one down
    /// now, or, if it failed, leave it up.
    pub(crate) fn on_listing_published(&mut self, listing: &ListingId, published: bool) {
        if !published {
            self.end_publishing(listing);
        }
        let Some((store_contract_id, old, _)) = self.withdraw_after_publish.remove(listing) else {
            return;
        };
        if !published {
            self.notifications.push(
                "That was an edit: the original listing is still up, so edit it again rather \
                 than adding it."
                    .into(),
            );
            return;
        }
        if let Err(e) =
            self.queue_listing_status(store_contract_id, old, ListingAvailability::Withdrawn)
        {
            self.notifications.push(format!(
                "The edited listing is up, but the original could not be taken down: {e}"
            ));
        }
    }

    /// A listing will not be published (#118's drop paths, a store-key
    /// refusal). A new listing is reported with `message`; an edit's
    /// replacement is reported by [`Self::on_listing_published`] instead, as
    /// "edit it again", since adding it again would publish a second listing
    /// beside the original that is still up.
    pub(crate) fn listing_dropped(&mut self, listing: &ListingId, message: String) {
        self.end_publishing(listing);
        if self.withdraw_after_publish.remove(listing).is_some() {
            // Keep the reason, which may be the part the seller can act on
            // (no store key on this device), and swap "add it again" for
            // "edit it again".
            let reason = message
                .replace(" Add it again to retry.", "")
                .replace(" Add it again.", "");
            self.notifications.push(format!(
                "{reason} That was an edit: the original listing is still up, so edit it again \
                 rather than adding it."
            ));
        } else {
            self.notifications.push(message);
        }
    }

    /// The store key signed a listing status: publish it.
    pub(crate) fn on_listing_status_signed(
        &mut self,
        pending: PendingListingStatus,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let key = (
            pending.store_contract_id.clone(),
            pending.status.listing.clone(),
        );
        let revision = pending.status.revision;
        let floor = self
            .listing_statuses_sent
            .get(&key)
            .map_or(revision, |sent| sent.revision.max(revision));
        self.listing_statuses_sent.insert(
            key,
            SentStatus {
                revision: floor,
                waiting_since_ms: Some(now_ms()),
            },
        );
        let authorized = AuthorizedListingStatus {
            status: pending.status,
            scoped_payload,
            signature,
        };
        #[cfg(target_arch = "wasm32")]
        {
            let store_id = pending.store_contract_id;
            wasm_bindgen_futures::spawn_local(async move {
                use dioxus::prelude::WritableExt;
                let listing = authorized.status.listing.clone();
                let revision = authorized.status.revision;
                if let Err(e) =
                    crate::gateway::store_ops::submit_listing_status_by_id(&store_id, authorized)
                        .await
                {
                    dioxus::logger::tracing::error!("Failed to publish a listing status: {e}");
                    let mut state = crate::gateway::APP_STATE.write();
                    state.on_listing_status_publish_failed(&store_id, &listing, revision);
                    state
                        .notifications
                        .push(format!("{LISTING_STATUS_NOT_SAVED} ({e})"));
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.signed_statuses_ready
            .push((pending.store_contract_id, authorized));
    }

    /// A status publish failed: stop holding its row, unless a newer one is
    /// still on its way. The revision floor stays, so a retry does not reuse
    /// the revision.
    pub(crate) fn on_listing_status_publish_failed(
        &mut self,
        store_contract_id: &[u8],
        listing: &ListingId,
        revision: u64,
    ) {
        if let Some(sent) = self
            .listing_statuses_sent
            .get_mut(&(store_contract_id.to_vec(), listing.clone()))
            .filter(|sent| sent.revision == revision)
        {
            sent.waiting_since_ms = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{test_store_key, BrowsingStore};
    use harvest_common::StoreRegistration;

    const STORE: [u8; 32] = [7u8; 32];
    const FINGERPRINT: &str = "fp-seller";

    fn seller_state() -> AppState {
        let mut state = AppState::default();
        state.my_stores.insert(
            FINGERPRINT.to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE.to_vec(),
                reputation_contract_id: vec![8u8; 32],
                mailbox_contract_id: vec![9u8; 32],
                store_contract_key: None,
                store_verifying_key: Some(test_store_key()),
            }],
        );
        state
            .browsing_stores
            .insert(STORE.to_vec(), BrowsingStore::default());
        // A listing goes for signing only with its Ghost Key certificate
        // attached (harvest#118); have it to hand, as a session that has
        // loaded its store does.
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "CERT".to_string());
        state
    }

    fn listing(title: &str) -> Listing {
        Listing {
            checkout: None,
            choices: Vec::new(),
            id: ListingId([0u8; 32]),
            title: title.to_string(),
            description: String::new(),
            kind: harvest_common::listing::ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("time"),
        }
        .with_derived_id()
    }

    fn queued_statuses(state: &AppState) -> Vec<ListingStatus> {
        state
            .pending_signatures
            .iter()
            .filter_map(|p| match p {
                PendingSignature::ListingStatus(p) => Some(p.status.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_new_revision_is_above_what_is_held_and_no_older_than_now() {
        assert_eq!(next_revision(None, 1_000), Some(1_000));
        assert_eq!(next_revision(None, 0), Some(1), "never zero");
        assert_eq!(next_revision(Some(5), 1_000), Some(1_000));
        assert_eq!(
            next_revision(Some(5_000), 1_000),
            Some(5_001),
            "a clock behind the held revision still moves forward"
        );
        assert_eq!(
            next_revision(Some(u64::MAX), 1_000),
            None,
            "a revision that could only tie is refused, not issued"
        );
    }

    /// Editing keeps a sold-out listing sold out unless the seller gave a
    /// count; an on-sale listing takes the count the form gave.
    #[test]
    fn an_edit_keeps_sold_out_unless_restocked() {
        use ListingAvailability::*;
        assert_eq!(availability_after_edit(&SoldOut, None), SoldOut);
        assert_eq!(
            availability_after_edit(&SoldOut, Some(2)),
            Available { quantity: Some(2) }
        );
        assert_eq!(
            availability_after_edit(&Available { quantity: Some(3) }, None),
            Available { quantity: None }
        );
        assert_eq!(availability_after_edit(&Withdrawn, Some(1)), Withdrawn);
        assert_eq!(
            availability_after_edit(&Available { quantity: Some(0) }, None),
            SoldOut,
            "none left is sold out too"
        );
    }

    /// Two changes before the first is signed get increasing revisions, so
    /// the seller's last click is the one that wins. Mutated red by dropping
    /// the pending-queue term from the revision.
    #[test]
    fn a_second_change_before_the_first_is_signed_gets_a_higher_revision() {
        let mut state = seller_state();
        let id = ListingId([3u8; 32]);
        state
            .queue_listing_status_at(
                STORE.to_vec(),
                id.clone(),
                ListingAvailability::SoldOut,
                1_000,
            )
            .expect("queued");
        state
            .queue_listing_status_at(
                STORE.to_vec(),
                id.clone(),
                ListingAvailability::Withdrawn,
                1_000,
            )
            .expect("queued");
        let queued = queued_statuses(&state);
        assert_eq!(queued.len(), 2);
        assert!(queued[1].revision > queued[0].revision, "{queued:?}");
        assert!(state.listing_status_pending(&STORE, &id));
        assert!(!state.listing_status_pending(&STORE, &ListingId([4u8; 32])));
    }

    /// The revision is above the one the store already holds, whatever the
    /// clock says.
    #[test]
    fn a_change_outranks_the_status_the_store_holds() {
        let mut state = seller_state();
        let id = ListingId([3u8; 32]);
        state
            .browsing_stores
            .get_mut(STORE.as_slice())
            .unwrap()
            .listing_statuses
            .insert(
                id.clone(),
                ListingStatus {
                    listing: id.clone(),
                    revision: 9_000,
                    availability: ListingAvailability::SoldOut,
                },
            );
        state
            .queue_listing_status_at(
                STORE.to_vec(),
                id,
                ListingAvailability::Available { quantity: Some(2) },
                10,
            )
            .expect("queued");
        assert_eq!(queued_statuses(&state)[0].revision, 9_001);
    }

    /// A store this device holds no store key for cannot have a status
    /// signed; the seller is told why rather than a request being sent.
    #[test]
    fn a_store_without_a_store_key_is_refused() {
        let mut state = seller_state();
        state.my_stores.get_mut(FINGERPRINT).unwrap()[0].store_verifying_key = None;
        let refused = state.queue_listing_status(
            STORE.to_vec(),
            ListingId([1u8; 32]),
            ListingAvailability::SoldOut,
        );
        assert!(refused.is_err());
        assert!(state.pending_signatures.is_empty());
    }

    /// A new listing with a count asks for both the listing and its status,
    /// the status naming the listing's own id; without a count, only the
    /// listing.
    #[test]
    fn a_new_listing_with_a_count_also_publishes_its_status() {
        let mut state = seller_state();
        let with = listing("Mugs");
        state
            .publish_new_listing(STORE.to_vec(), FINGERPRINT.into(), with.clone(), Some(4))
            .expect("queued");
        let statuses = queued_statuses(&state);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].listing, with.id);
        assert_eq!(
            statuses[0].availability,
            ListingAvailability::Available { quantity: Some(4) }
        );
        assert!(state
            .pending_signatures
            .iter()
            .any(|p| matches!(p, PendingSignature::Listing(l) if l.listing.id == with.id)));

        let mut state = seller_state();
        state
            .publish_new_listing(STORE.to_vec(), FINGERPRINT.into(), listing("Bowls"), None)
            .expect("queued");
        assert!(queued_statuses(&state).is_empty());
        assert_eq!(state.pending_signatures.len(), 1);
    }

    fn current_generation() -> Vec<u8> {
        crate::gateway::store_ops::store_instance_id(&harvest_common::store::StoreParameters::new(
            ed25519_dalek::VerifyingKey::from_bytes(&test_store_key()).unwrap(),
        ))
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    fn holding(state: &mut AppState, store: Vec<u8>, listing: &Listing) {
        state
            .browsing_stores
            .entry(store)
            .or_default()
            .listings
            .push(harvest_common::listing::AuthorizedListing {
                listing: listing.clone(),
                scoped_payload: Vec::new(),
                signature: Vec::new(),
                certificate_pem: String::new(),
            });
    }

    /// **"Publishing" comes down once the listing is in the store it was
    /// written to (harvest#161).** Notices stay for the session, so the E2E
    /// seller saw "Publishing" for a listing that was live. An EARLIER
    /// generation holding the same terms does not count (harvest#164): the
    /// write went to the current one. Mutated red by never ending it, and by
    /// dropping the generation check.
    #[test]
    fn the_publishing_notice_ends_when_the_listing_lands() {
        let mut state = seller_state();
        let mugs = listing("Mugs");
        state
            .publish_new_listing(STORE.to_vec(), FINGERPRINT.into(), mugs.clone(), None)
            .expect("queued");
        let notice = "Publishing \u{201c}Mugs\u{201d}\u{2026}".to_string();
        assert!(state.notifications.contains(&notice));

        holding(&mut state, STORE.to_vec(), &mugs);
        state.settle_publishing(&STORE);
        assert!(
            state.notifications.contains(&notice),
            "an earlier generation holding it is not the publish"
        );

        holding(&mut state, current_generation(), &mugs);
        state.settle_publishing(&current_generation());
        assert!(!state.notifications.contains(&notice));
        assert!(state.publishing_listings.is_empty());
    }

    /// **A refused publish is said, and "Publishing" comes down
    /// (harvest#161).** The E2E seller's listing was refused by the store
    /// contract and the page said "Publishing" forever. Mutated red by
    /// ignoring the refusal.
    #[test]
    fn a_refused_listing_is_reported() {
        let mut state = seller_state();
        state
            .publish_new_listing(STORE.to_vec(), FINGERPRINT.into(), listing("Mugs"), None)
            .expect("queued");
        state.on_update_refused(&current_generation(), "the listing is not valid");
        assert!(!state
            .notifications
            .iter()
            .any(|n| n.starts_with("Publishing")));
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("\u{201c}Mugs\u{201d} was not published")
                && n.contains("the listing is not valid")));
        assert!(state.publishing_listings.is_empty());

        // A refusal no new listing is waiting on is still said, for a store
        // of ours, and not for anyone else's.
        let before = state.notifications.len();
        state.on_update_refused(&STORE, "an order is not valid");
        assert_eq!(state.notifications.len(), before + 1);
        state.on_update_refused(&[0x44; 32], "not ours");
        assert_eq!(state.notifications.len(), before + 1);
    }

    /// A publish that fails before it is sent ends its notice too.
    #[test]
    fn a_failed_send_ends_the_publishing_notice() {
        let mut state = seller_state();
        let mugs = listing("Mugs");
        state
            .publish_new_listing(STORE.to_vec(), FINGERPRINT.into(), mugs.clone(), None)
            .expect("queued");
        state.on_listing_published(&mugs.id, false);
        assert!(!state
            .notifications
            .iter()
            .any(|n| n.starts_with("Publishing")));
    }

    /// Editing the terms publishes the new listing, and takes the old one
    /// down only once the new one has published: a failed publish leaves the
    /// old one up. Changing only the count publishes only a status, and
    /// changing nothing publishes nothing. Mutated red by withdrawing at
    /// once, and by always withdrawing.
    #[test]
    fn an_edit_replaces_the_listing_and_a_count_change_does_not() {
        let old = listing("Mug");
        let edited = listing("Mug, blue");

        let mut state = seller_state();
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                edited.clone(),
                None,
            )
            .expect("queued");
        assert!(queued_statuses(&state).is_empty(), "nothing comes down yet");
        assert!(state
            .pending_signatures
            .iter()
            .any(|p| matches!(p, PendingSignature::Listing(l) if l.listing.id == edited.id)));
        state.on_listing_published(&edited.id, true);
        let statuses = queued_statuses(&state);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].listing, old.id);
        assert_eq!(statuses[0].availability, ListingAvailability::Withdrawn);
        state.on_listing_published(&edited.id, true);
        assert_eq!(queued_statuses(&state).len(), 1, "and only once");

        // The replacement failing to publish leaves the original up.
        let mut state = seller_state();
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                edited.clone(),
                None,
            )
            .expect("queued");
        state.on_listing_published(&edited.id, false);
        assert!(queued_statuses(&state).is_empty());

        let mut state = seller_state();
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                old.clone(),
                Some(2),
            )
            .expect("queued");
        let statuses = queued_statuses(&state);
        assert_eq!(statuses.len(), 1, "a count change is one status");
        assert_eq!(statuses[0].listing, old.id);
        assert_eq!(
            statuses[0].availability,
            ListingAvailability::Available { quantity: Some(2) }
        );
        assert_eq!(state.pending_signatures.len(), 1, "and no new listing");

        let mut state = seller_state();
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                old.clone(),
                None,
            )
            .expect("nothing to do");
        assert!(state.pending_signatures.is_empty());
    }

    /// While an edit's replacement goes out, the original shows "Saving" so a
    /// second edit cannot publish a second replacement; a replacement dropped
    /// for want of its certificate (#118) releases it and forgets the
    /// withdrawal. Mutated red by dropping the replacing term, and by dropping
    /// the call from the drop path.
    #[test]
    fn an_edit_in_flight_holds_the_original_until_it_lands_or_is_dropped() {
        let old = listing("Mug");
        let edited = listing("Mug, blue");
        let mut state = seller_state();
        state.certificates.clear();
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                edited.clone(),
                None,
            )
            .expect("queued");
        assert_eq!(
            state.listings_awaiting_certificate.len(),
            1,
            "parked for its certificate"
        );
        assert!(state.listing_status_pending(&STORE, &old.id));
        state.drop_listings_awaiting_certificate(Some(FINGERPRINT), "test");
        assert!(!state.listing_status_pending(&STORE, &old.id));
        assert!(state.withdraw_after_publish.is_empty());
        assert!(queued_statuses(&state).is_empty(), "the original stays up");
    }

    /// The vault answering with no certificate drops a parked replacement
    /// too, and an edit is reported as "edit it again", never "add it again".
    /// Mutated red by dropping the call from that path.
    #[test]
    fn a_replacement_the_vault_gives_no_certificate_for_releases_the_original() {
        let old = listing("Mug");
        let edited = listing("Mug, blue");
        let mut state = seller_state();
        state.certificates.clear();
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                edited,
                None,
            )
            .expect("queued");
        state.release_listings_awaiting_certificate(FINGERPRINT);
        assert!(state.withdraw_after_publish.is_empty());
        assert!(!state.listing_status_pending(&STORE, &old.id));
        let said = state.notifications.join(" | ");
        assert!(said.contains("edit it again"), "{said}");
        assert!(!said.contains("Add it again"), "{said}");
        assert!(
            said.contains("returned no certificate"),
            "the reason is kept: {said}"
        );
    }

    /// Editing a sold-out listing's terms publishes the replacement sold out,
    /// not back on sale, and saving it unchanged publishes nothing. Mutated
    /// red by publishing the replacement uncounted.
    #[test]
    fn an_edit_of_a_sold_out_listing_stays_sold_out() {
        let old = listing("Mug");
        let edited = listing("Mug, blue");
        let mut state = seller_state();
        hold(&mut state, &old.id, 5, ListingAvailability::SoldOut);
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                old.clone(),
                None,
            )
            .expect("nothing to do");
        assert!(state.pending_signatures.is_empty());
        state
            .replace_listing(
                STORE.to_vec(),
                FINGERPRINT.into(),
                old.id.clone(),
                edited.clone(),
                None,
            )
            .expect("queued");
        let statuses = queued_statuses(&state);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].listing, edited.id);
        assert_eq!(statuses[0].availability, ListingAvailability::SoldOut);
    }

    fn hold(
        state: &mut AppState,
        id: &ListingId,
        revision: u64,
        availability: ListingAvailability,
    ) {
        state
            .browsing_stores
            .get_mut(STORE.as_slice())
            .unwrap()
            .listing_statuses
            .insert(
                id.clone(),
                ListingStatus {
                    listing: id.clone(),
                    revision,
                    availability,
                },
            );
    }

    fn sign_next(state: &mut AppState) -> u64 {
        let pending = match state.pending_signatures.pop_front() {
            Some(PendingSignature::ListingStatus(p)) => *p,
            other => panic!("{other:?}"),
        };
        let revision = pending.status.revision;
        state.on_listing_status_signed(pending, vec![], vec![]);
        revision
    }

    /// Once signed, a status holds its row until the store's state shows it,
    /// the publish fails, or the window passes; and a later change still gets
    /// a higher revision though nothing is pending any more. Mutated red by
    /// dropping the sent entry from `listing_status_pending_at`, and the sent
    /// floor from the revision.
    #[test]
    fn a_sent_status_holds_its_row_until_the_state_shows_it() {
        let mut state = seller_state();
        let id = ListingId([5u8; 32]);
        state
            .queue_listing_status_at(STORE.to_vec(), id.clone(), ListingAvailability::SoldOut, 10)
            .expect("queued");
        let revision = sign_next(&mut state);
        let now = chrono::Utc::now().timestamp_millis();
        assert!(
            state.listing_status_pending_at(&STORE, &id, now),
            "sent, not yet shown"
        );
        assert!(
            !state.listing_status_pending_at(&STORE, &id, now + SAVING_WINDOW_MS + 1),
            "and not forever"
        );

        state
            .queue_listing_status_at(
                STORE.to_vec(),
                id.clone(),
                ListingAvailability::Withdrawn,
                10,
            )
            .expect("queued");
        assert!(queued_statuses(&state)[0].revision > revision);
        state.pending_signatures.clear();

        hold(&mut state, &id, revision, ListingAvailability::SoldOut);
        assert!(
            !state.listing_status_pending_at(&STORE, &id, now),
            "the state shows it"
        );

        let other = ListingId([6u8; 32]);
        state
            .queue_listing_status_at(
                STORE.to_vec(),
                other.clone(),
                ListingAvailability::SoldOut,
                10,
            )
            .expect("queued");
        sign_next(&mut state);
        assert!(state.listing_status_pending_at(&STORE, &other, now));
        let failed = state.listing_statuses_sent[&(STORE.to_vec(), other.clone())].revision;
        state.on_listing_status_publish_failed(&STORE, &other, failed - 1);
        assert!(
            state.listing_status_pending_at(&STORE, &other, now),
            "an older failure leaves a newer send waiting"
        );
        state.on_listing_status_publish_failed(&STORE, &other, failed);
        assert!(
            !state.listing_status_pending_at(&STORE, &other, now),
            "a failed publish"
        );
    }

    /// A store's state arriving brings its listing statuses with it, and a
    /// listing it holds no status for reads as on sale. Mutated red by
    /// dropping the ingest in `on_contract_state`.
    #[test]
    fn a_stores_statuses_are_read_from_its_state() {
        use ed25519_dalek::SigningKey;
        use harvest_common::store::{StoreStateV1, StoreStateV1Delta};
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let params = harvest_common::StoreParameters::new(key.verifying_key());
        let status = ListingStatus {
            listing: ListingId([6u8; 32]),
            revision: 2,
            availability: ListingAvailability::SoldOut,
        };
        let (scoped_payload, signature) = harvest_common::backing::sign_with_store_key(
            &key,
            harvest_common::to_cbor(&status).unwrap(),
        )
        .unwrap();
        let mut store_state = StoreStateV1::default();
        freenet_scaffold::ComposableState::apply_delta(
            &mut store_state,
            &StoreStateV1::default(),
            &params,
            &Some(StoreStateV1Delta {
                owner: Some(key.verifying_key()),
                listing_statuses: Some(vec![AuthorizedListingStatus {
                    status,
                    scoped_payload,
                    signature,
                }]),
                ..Default::default()
            }),
        )
        .expect("applies");
        let mut state = AppState::default();
        state.on_contract_state(
            STORE.to_vec(),
            harvest_common::to_cbor(&store_state).unwrap(),
        );
        assert_eq!(
            state.listing_availability(&STORE, &ListingId([6u8; 32])),
            ListingAvailability::SoldOut
        );
        assert_eq!(
            state.listing_availability(&STORE, &ListingId([7u8; 32])),
            ListingAvailability::Available { quantity: None }
        );
    }

    /// The store key's answer settles the status it was asked for and hands
    /// it on to be published, with the signature attached.
    #[test]
    fn a_signed_status_is_published() {
        let mut state = seller_state();
        let id = ListingId([5u8; 32]);
        state
            .queue_listing_status(STORE.to_vec(), id.clone(), ListingAvailability::SoldOut)
            .expect("queued");
        let pending = state.pending_signatures.front().cloned().expect("queued");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: harvest_common::expected_harvest_requestor(),
            payload: pending.signed_bytes().expect("bytes"),
        };
        state.on_delegate_response(harvest_common::HarvestDelegateResponse::StoreUpdateSigned {
            request_id: 1,
            store_verifying_key: test_store_key(),
            result: Ok(harvest_common::delegate::StoreKeySignature {
                scoped_payload: harvest_common::to_cbor(&scoped).expect("scoped"),
                signature: vec![1, 2, 3],
            }),
        });
        assert!(state.pending_signatures.is_empty());
        assert_eq!(state.signed_statuses_ready.len(), 1);
        let (store, published) = &state.signed_statuses_ready[0];
        assert_eq!(store, &STORE.to_vec());
        assert_eq!(published.status.listing, id);
        assert_eq!(published.signature, vec![1, 2, 3]);
        assert!(
            state.listing_status_pending(&STORE, &id),
            "still saving until the store's state shows it"
        );
    }
}
