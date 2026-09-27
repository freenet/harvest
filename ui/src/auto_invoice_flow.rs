//! Instant checkout, the seller's side: keeping the Harvest delegate able to
//! invoice a buyer while the seller is away.
//!
//! The delegate does the invoicing (`delegates/harvest-delegate/src/
//! auto_invoice.rs`). What it cannot do on its own is ask the Bitcoin bridge
//! to watch an address: that takes the seller's Ghost Key, which only an open
//! Harvest can reach. A payment the bridge was not watching for is never seen
//! (the bridge does not look back, freenet-bitcoin#7), so the delegate
//! invoices only on an address this module has had watched. While Harvest is
//! open, this module:
//!
//! 1. asks the delegate for its next few addresses without spending them
//!    (`PeekOrderAddresses`);
//! 2. adds them to the watch requests the seller's Ghost Key already sends
//!    for unpaid orders ([`AppState::prewatch_wanted`], merged into
//!    `watches_wanted`);
//! 3. once the bridge has read those requests, arms the delegate for each
//!    store that sells with instant checkout, naming the watched addresses
//!    and when the watch lapses ([`AppState::auto_invoice_arm`]).
//!
//! A bridge lets a watch lapse about a day after the request that last asked
//! for it, and an invoice must stay watched through its whole payment window
//! (about eleven hours: the delegate's `WATCH_NEEDED_MS`). While Harvest is open
//! the watch on those addresses is renewed every four hours, so instant
//! checkout stays on while Harvest is open, and for seven to eleven hours
//! after the seller closes it; then requests wait for them again. A longer
//! bridge watch (freenet-bitcoin#26) is what would stretch that.
//!
//! # Watching with no tab at all
//!
//! Once per Ghost Key and bridge, while the seller has a store selling with
//! instant checkout, this module also asks the seller's Ghost Key to delegate
//! its bridge watch requests to the delegate's watch key
//! ([`AppState::plan_watch_delegation`]): the vault signs a
//! `freenet_bitcoin_inbox::DelegationBody` and the delegate keeps it
//! (`SetWatchDelegation`). From then on the delegate asks the bridge to watch
//! its next addresses itself, on its five-minute wake-ups, so the store keeps
//! taking orders with Harvest closed. This tab keeps the delegate told which
//! inbox the bridge serves and the latest `made_at_ms` it has sent
//! (`UpdateWatchDelegation`), and dates its own requests above the
//! delegate's: the two share one timeline per Ghost Key.

use std::collections::{HashMap, HashSet};

use freenet_bitcoin_common::{BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::GhostkeyId;
use harvest_common::delegate::{
    AutoInvoiceArm, AutoInvoiceStatus, HarvestDelegateRequest, WatchDelegationGrant,
    WatchDelegationStatus,
};
use harvest_common::DerivedAddress;

use crate::state::AppState;

/// How often an unchanged arm is sent again. Re-arming re-subscribes, which
/// is what brings the delegate back after the node restarts.
pub const REARM_EVERY_MS: u64 = 10 * 60 * 1000;
/// How long to wait for an answer to `PeekOrderAddresses` before asking again.
pub const PEEK_RETRY_MS: u64 = 60 * 1000;
/// How long a bridge keeps watching after the request that last asked, and
/// the margin kept below it: the bridge ends a watch by block time, and a
/// block may be dated up to two hours ahead.
pub const WATCH_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const WATCH_MARGIN_MS: u64 = 2 * 60 * 60 * 1000;
/// How long after the first arm a delegate that has never run in the
/// background is taken to be unable to: a new block arrives about every ten
/// minutes, and each one runs it.
pub const NO_BACKGROUND_RUN_AFTER_MS: u64 = 30 * 60 * 1000;
/// The time counted per block of a watch horizon when telling the delegate
/// how long its watch has left: half the ten-minute target, so a run of fast
/// blocks does not outrun the estimate. The delegate also checks the height.
pub const HORIZON_BLOCK_MS: u64 = 5 * 60 * 1000;

/// What the seller's side of instant checkout holds.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AutoInvoiceUi {
    /// The delegate's next addresses, the payment key they were read under,
    /// and when they arrived. The delegate spends them in the background
    /// without telling this tab, so they are read again every
    /// [`REARM_EVERY_MS`], and at once when the key changes or this tab
    /// spends one itself.
    pub upcoming: Vec<DerivedAddress>,
    pub upcoming_for: Option<(String, u64)>,
    /// When `PeekOrderAddresses` was last sent.
    pub peek_sent_ms: Option<u64>,
    /// The last arm sent for each store (with `watch_left_ms` zeroed, since
    /// it shrinks with the clock), when its watch lapses, and when it went.
    pub sent: HashMap<Vec<u8>, (AutoInvoiceArm, u64, u64)>,
    /// What the delegate last said about each store.
    pub status: HashMap<Vec<u8>, Result<AutoInvoiceStatus, String>>,
    /// The delegate's watch key, once it has said, and when it was last
    /// asked.
    pub watch_key: Option<[u8; 32]>,
    pub watch_key_asked_ms: Option<u64>,
    /// The Ghost Key and bridge pairs this session has asked the vault to
    /// delegate for: once each, never on every open.
    pub delegation_asked: HashSet<(GhostkeyId, BridgeId)>,
    /// The delegation the delegate holds for each bridge, as it last said.
    pub delegations: HashMap<BridgeId, WatchDelegationStatus>,
    /// The last `UpdateWatchDelegation` sent per bridge: the inbox and
    /// `made_at_ms` it named, and when.
    pub delegation_update_sent: HashMap<BridgeId, ([u8; 32], u64, u64)>,
}

/// A delegation of watch requests queued for the Ghost Key's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingWatchDelegation {
    pub fingerprint: String,
    pub ghostkey: GhostkeyId,
    pub network: BitcoinNetwork,
    pub bridge: BridgeId,
    pub inbox_contract_id: [u8; 32],
    /// `DelegationBody::signing_payload`, and so what the answer is matched
    /// by.
    pub signing_payload: Vec<u8>,
    pub queued_at_ms: u64,
}

/// What the delegation step should do now.
#[derive(Debug, Default, PartialEq)]
pub struct DelegationWork {
    /// Ask the delegate for its watch key.
    pub get_watch_key: bool,
    /// Ask the vault to sign this delegation.
    pub delegate: Option<PendingWatchDelegation>,
    /// Tell the delegate a moved inbox or a later `made_at_ms`.
    pub update: Option<HarvestDelegateRequest>,
}

/// What the instant-checkout loop should send now.
#[derive(Debug, Default, PartialEq)]
pub struct AutoInvoiceWork {
    pub peek: bool,
    pub arms: Vec<AutoInvoiceArm>,
    /// For each of `arms`, when its day-long watch lapses by this tab's
    /// clock (0 when nothing is watched): what the next plan compares to
    /// tell a renewed watch from an unchanged one.
    pub lapses_at_ms: Vec<u64>,
    /// The delegation of watch requests to the delegate's watch key.
    pub delegation: DelegationWork,
}

impl AppState {
    /// This node's own stores that sell at least one listing with instant
    /// checkout, with the Ghost Key fingerprint each is registered under.
    pub(crate) fn instant_checkout_stores(
        &self,
    ) -> Vec<(String, harvest_common::delegate::StoreRegistration)> {
        let mut out = Vec::new();
        let mut fingerprints: Vec<&String> = self.my_stores.keys().collect();
        fingerprints.sort();
        for fingerprint in fingerprints {
            for registration in &self.my_stores[fingerprint] {
                if registration.store_verifying_key.is_none() {
                    continue;
                }
                // The delegate writes its orders to the store the arm names,
                // so never an earlier generation (harvest#164). Armed once
                // this session has moved to the current one.
                if !matches!(
                    self.store_write_target(&registration.store_contract_id),
                    crate::state::StoreWriteTarget::Ready(_)
                ) {
                    continue;
                }
                let Some(store) = self.browsing_stores.get(&registration.store_contract_id) else {
                    continue;
                };
                let sells = store.listings.iter().any(|l| {
                    l.listing.offers_instant_checkout()
                        && self
                            .listing_availability(&registration.store_contract_id, &l.listing.id)
                            .is_buyable()
                });
                if sells {
                    out.push((fingerprint.clone(), registration.clone()));
                }
            }
        }
        out
    }

    /// The delegate's next addresses, if they were read under the payment key
    /// and counter the delegate now reports.
    fn current_upcoming(&self) -> Option<(BitcoinNetwork, &[DerivedAddress])> {
        let xpub = self.bitcoin.payment_xpub.as_ref()?;
        let (key, _) = self.auto_invoice.upcoming_for.as_ref()?;
        let first = self.auto_invoice.upcoming.first()?;
        (*key == xpub.xpub && first.index >= xpub.next_index)
            .then_some((xpub.network, self.auto_invoice.upcoming.as_slice()))
    }

    /// Whether the next addresses should be read again.
    fn peek_due(&self, now_ms: u64) -> bool {
        let Some(xpub) = self.bitcoin.payment_xpub.as_ref() else {
            return false;
        };
        let stale = match &self.auto_invoice.upcoming_for {
            None => true,
            Some((key, at)) => {
                *key != xpub.xpub
                    || now_ms.saturating_sub(*at) >= REARM_EVERY_MS
                    || self
                        .auto_invoice
                        .upcoming
                        .first()
                        .is_none_or(|a| a.index < xpub.next_index)
            }
        };
        stale
            && self
                .auto_invoice
                .peek_sent_ms
                .is_none_or(|at| now_ms.saturating_sub(at) >= PEEK_RETRY_MS)
    }

    /// The addresses to have `bridge` watch ahead of use, and the Ghost Key
    /// that asks: the first store (by fingerprint) that sells with instant
    /// checkout. `None` when no store does or the addresses are not known.
    pub(crate) fn prewatch_wanted(
        &self,
        bridge: freenet_bitcoin_common::BridgeId,
    ) -> Option<(
        String,
        freenet_bitcoin_inbox::GhostkeyId,
        Vec<crate::bitcoin_inbox::WatchWanted>,
    )> {
        let (network, upcoming) = self.current_upcoming()?;
        if !crate::gateway::bitcoin_config::default_trusted_bridges(network)
            .is_ok_and(|bridges| bridges.contains(&bridge))
        {
            return None;
        }
        let tip_height = self.bitcoin.tips.get(&network).and_then(|t| t.tip_height);
        self.instant_checkout_stores()
            .into_iter()
            .filter(|(fingerprint, _)| {
                self.ghostkeys.iter().any(|k| &k.fingerprint == fingerprint)
                    && !self.bitcoin.watch_requests_stopped.contains(fingerprint)
            })
            .find_map(|(fingerprint, registration)| {
                let seller_key = self
                    .browsing_stores
                    .get(&registration.store_contract_id)?
                    .seller_verifying_key?;
                Some((
                    fingerprint,
                    freenet_bitcoin_inbox::GhostkeyId(seller_key),
                    upcoming
                        .iter()
                        .map(|a| crate::bitcoin_inbox::WatchWanted {
                            renew_after_ms: crate::bitcoin_inbox::PREWATCH_RENEW_AFTER_MS,
                            network,
                            script: a.script_pubkey.clone(),
                            anchor_height: tip_height,
                            // As far ahead as a bridge will watch: the store
                            // keeps taking orders with no tab open until the
                            // tip nears it or these addresses are used.
                            until_height: tip_height.map(|tip| {
                                tip.saturating_add(freenet_bitcoin_inbox::MAX_WATCH_AHEAD_BLOCKS)
                            }),
                        })
                        .collect(),
                ))
            })
    }

    /// The arm for one store, as things stand, and when its watch lapses by
    /// this tab's clock (0 when nothing is watched): `None` until everything
    /// it names is known.
    pub(crate) fn auto_invoice_arm(
        &self,
        fingerprint: &str,
        registration: &harvest_common::delegate::StoreRegistration,
        now_ms: u64,
    ) -> Option<(AutoInvoiceArm, u64)> {
        let store_verifying_key = registration.store_verifying_key?;
        let mailbox_contract_id: [u8; 32] = registration
            .mailbox_contract_id
            .as_slice()
            .try_into()
            .ok()?;
        let (network, upcoming) = self.current_upcoming()?;
        let tip_contract_id: [u8; 32] = self
            .bitcoin
            .tip_contract_network
            .iter()
            .find(|(_, n)| **n == network)
            .and_then(|(id, _)| id.as_slice().try_into().ok())?;
        let trusted_bridges =
            crate::gateway::bitcoin_config::default_trusted_bridges(network).ok()?;
        let address_code_hash = self.bitcoin.address_generation.0.clone().ok()?;
        // Only what the bridge has READ a request for, and the watch is
        // counted from the earliest of those requests. A renewal not yet read
        // does not end the watch the last read request started.
        let inbox = self.bitcoin.inbox.as_ref()?;
        let mut watched_scripts = Vec::new();
        let mut earliest: Option<u64> = None;
        // The nearest horizon among them, or `None` once any lacks one.
        let mut horizon: Option<Option<u32>> = None;
        for address in upcoming {
            let Some(sent) = inbox.sent.get(&(network, address.script_pubkey.clone())) else {
                break;
            };
            let Some(read_at) = (if sent.read {
                Some(sent.sent_at_ms)
            } else {
                sent.read_lease_ms
            }) else {
                // The delegate hands addresses out in order, so one not
                // watched ends the usable run.
                break;
            };
            watched_scripts.push(address.script_pubkey.clone());
            earliest = Some(earliest.map_or(read_at, |e| e.min(read_at)));
            let this = sent.watched_until_height();
            horizon = Some(match horizon {
                None => this,
                Some(held) => held.zip(this).map(|(a, b)| a.min(b)),
            });
        }
        let watched_until_height = horizon.flatten();
        let tip_height = self.bitcoin.tips.get(&network).and_then(|t| t.tip_height);
        // When the day the earliest read request bought runs out. Also what
        // the caller compares to tell a renewed watch from an unchanged one,
        // so it must not move with the clock.
        let lapses_at_ms = earliest
            .map(|at| at + WATCH_LIFETIME_MS - WATCH_MARGIN_MS)
            .filter(|until| *until > now_ms)
            .unwrap_or(0);
        // Past the day, a horizon keeps the watch until the tip passes it:
        // counted at a pessimistic block rate here, since the delegate checks
        // the height itself (`watched_until_height`).
        let horizon_left_ms = match (watched_until_height, tip_height) {
            (Some(until), Some(tip)) if !watched_scripts.is_empty() => {
                u64::from(until.saturating_sub(tip)) * HORIZON_BLOCK_MS
            }
            _ => 0,
        };
        let watch_left_ms = lapses_at_ms.saturating_sub(now_ms).max(horizon_left_ms);
        if watch_left_ms == 0 {
            watched_scripts.clear();
        }
        let arm = AutoInvoiceArm {
            store_contract_id: registration.store_contract_id.clone(),
            store_verifying_key,
            mailbox_contract_id,
            seller_fingerprint: fingerprint.to_string(),
            network,
            tip_contract_id,
            trusted_bridges,
            address_code_hash,
            watched_until_height: if watched_scripts.is_empty() {
                None
            } else {
                watched_until_height
            },
            watched_scripts,
            watch_left_ms,
            presence_contract_id: presence_instance_bytes(&store_verifying_key),
        };
        Some((arm, lapses_at_ms))
    }

    /// What is due to be sent now. Changes nothing, so the minute timer can
    /// ask without taking the state for writing.
    pub(crate) fn plan_auto_invoice(&self, now_ms: u64) -> AutoInvoiceWork {
        let mut work = AutoInvoiceWork::default();
        let stores = self.instant_checkout_stores();
        if stores.is_empty() {
            return work;
        }
        work.peek = self.peek_due(now_ms);
        for (fingerprint, registration) in stores {
            let Some((arm, lapses_at)) = self.auto_invoice_arm(&fingerprint, &registration, now_ms)
            else {
                continue;
            };
            let due = match self.auto_invoice.sent.get(&registration.store_contract_id) {
                Some((sent, sent_lapses_at, at)) => {
                    *sent != without_left(&arm)
                        || *sent_lapses_at != lapses_at
                        || now_ms.saturating_sub(*at) >= REARM_EVERY_MS
                }
                None => true,
            };
            if due {
                work.arms.push(arm);
                work.lapses_at_ms.push(lapses_at);
            }
        }
        work.delegation = self.plan_watch_delegation(now_ms);
        work
    }

    /// The delegation step: what to ask, if anything.
    ///
    /// For the Ghost Key and bridge [`Self::prewatch_wanted`] picks (a store
    /// selling with instant checkout, a payment key, the inbox served with a
    /// floor), once the delegate has answered for that store and holds no
    /// usable delegation for them: its watch key first, then the vault's
    /// signature over a delegation issued at `sender_height` of the current
    /// floor. Once per Ghost Key and bridge per session, and not while any
    /// other vault signature is outstanding, so a refusal is always about one
    /// thing. For a delegation the delegate already holds: tell it a moved
    /// inbox, or a `made_at_ms` of this tab's later than any it knows.
    pub(crate) fn plan_watch_delegation(&self, now_ms: u64) -> DelegationWork {
        let mut work = DelegationWork::default();
        let Some(inbox) = self.bitcoin.inbox.as_ref() else {
            return work;
        };
        let bridge = inbox.bridge;
        let Some((fingerprint, ghostkey, _)) = self.prewatch_wanted(bridge) else {
            return work;
        };
        let Some((network, _)) = self.current_upcoming() else {
            return work;
        };
        let Ok(inbox_contract_id) = <[u8; 32]>::try_from(inbox.contract_key.id().as_bytes()) else {
            return work;
        };
        // Only once the delegate has answered for this Ghost Key's store:
        // before that, "holds none" is not known.
        let answered = self
            .instant_checkout_stores()
            .iter()
            .any(|(fp, registration)| {
                *fp == fingerprint
                    && matches!(
                        self.auto_invoice
                            .status
                            .get(&registration.store_contract_id),
                        Some(Ok(_))
                    )
            });
        if !answered {
            return work;
        }
        let held = self.auto_invoice.delegations.get(&bridge);
        if let Some(held) = held.filter(|d| d.ghostkey == ghostkey.0 && !d.stalled) {
            let tab_last = inbox.last_made_at_ms().unwrap_or(0);
            let behind = held.inbox_contract_id != inbox_contract_id || tab_last > held.made_at_ms;
            let just_sent = self
                .auto_invoice
                .delegation_update_sent
                .get(&bridge)
                .is_some_and(|(id, made_at, at)| {
                    *id == inbox_contract_id
                        && *made_at >= tab_last
                        && now_ms.saturating_sub(*at) < REARM_EVERY_MS
                });
            if behind && !just_sent {
                work.update = Some(HarvestDelegateRequest::UpdateWatchDelegation {
                    bridge,
                    inbox_contract_id,
                    last_made_at_ms: tab_last,
                });
            }
            return work;
        }
        if self
            .auto_invoice
            .delegation_asked
            .contains(&(ghostkey, bridge))
        {
            return work;
        }
        let Some(watch_key) = self.auto_invoice.watch_key else {
            work.get_watch_key = self
                .auto_invoice
                .watch_key_asked_ms
                .is_none_or(|at| now_ms.saturating_sub(at) >= PEEK_RETRY_MS);
            return work;
        };
        if self.user_signature_under_way()
            || self
                .pending_signatures
                .iter()
                .any(|p| p.is_watch_signature())
        {
            return work;
        }
        let Some(floor) = inbox.state.as_ref().and_then(|s| s.floor.as_ref()) else {
            return work;
        };
        let issued = freenet_bitcoin_inbox::sender_height(floor.height);
        // A replacement must be issued later than what it replaces, or the
        // bridge keeps honouring the old one: wait for the floor to move.
        if held.is_some_and(|d| d.ghostkey == ghostkey.0 && issued <= d.issued_mainnet_height) {
            return work;
        }
        let body = freenet_bitcoin_inbox::DelegationBody {
            bridge,
            watch_key: freenet_bitcoin_inbox::WatchKeyId(watch_key),
            issued_mainnet_height: issued,
            expires_mainnet_height: None,
        };
        let Ok(signing_payload) = body.signing_payload() else {
            return work;
        };
        work.delegate = Some(PendingWatchDelegation {
            fingerprint,
            ghostkey,
            network,
            bridge,
            inbox_contract_id,
            signing_payload,
            queued_at_ms: now_ms,
        });
        work
    }

    /// The vault signed a delegation: the request that hands it to the
    /// delegate, or `None` if there is nothing worth sending.
    pub(crate) fn on_watch_delegation_signed(
        &mut self,
        pending: PendingWatchDelegation,
        certificate_pem: String,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Option<HarvestDelegateRequest> {
        // Prepared for an inbox this tab has since stopped using: its bridge
        // may be another, and the next plan asks again against the current one.
        let inbox = self
            .bitcoin
            .inbox
            .as_ref()
            .filter(|inbox| inbox.bridge == pending.bridge)?;
        Some(HarvestDelegateRequest::SetWatchDelegation {
            grant: Box::new(WatchDelegationGrant {
                network: pending.network,
                bridge: pending.bridge,
                ghostkey: pending.ghostkey.0,
                certificate_pem,
                delegation_scoped_payload: scoped_payload,
                delegation_signature: signature,
                inbox_contract_id: pending.inbox_contract_id,
                last_made_at_ms: inbox.last_made_at_ms().unwrap_or(0),
            }),
        })
    }

    /// The delegate's answer to `GetWatchKey`.
    pub(crate) fn on_watch_key(&mut self, result: Result<[u8; 32], String>) {
        match result {
            Ok(key) => self.auto_invoice.watch_key = Some(key),
            Err(e) => dioxus::logger::tracing::warn!("the delegate gave no watch key: {e}"),
        }
    }

    /// The delegate's answer to `SetWatchDelegation` or
    /// `UpdateWatchDelegation`.
    pub(crate) fn on_watch_delegation(
        &mut self,
        bridge: BridgeId,
        result: Result<WatchDelegationStatus, String>,
    ) {
        match result {
            Ok(status) => self.note_watch_delegation(status),
            Err(e) => dioxus::logger::tracing::warn!(
                "the delegate did not take the watch delegation for bridge {}: {e}",
                bs58::encode(bridge.0).into_string()
            ),
        }
    }

    /// Record what the delegate holds, and date this tab's next request
    /// above the delegate's last.
    fn note_watch_delegation(&mut self, status: WatchDelegationStatus) {
        if let Some(inbox) = self
            .bitcoin
            .inbox
            .as_mut()
            .filter(|inbox| inbox.bridge == status.bridge)
        {
            inbox.raise_made_at(status.made_at_ms);
        }
        self.auto_invoice.delegations.insert(status.bridge, status);
    }

    /// Whether [`Self::send_due_auto_invoice`] would send anything.
    pub fn auto_invoice_due(&self, now_ms: u64) -> bool {
        self.plan_auto_invoice(now_ms) != AutoInvoiceWork::default()
    }

    /// Plan, and note what is about to be sent as sent.
    pub(crate) fn queue_auto_invoice(&mut self, now_ms: u64) -> AutoInvoiceWork {
        let work = self.plan_auto_invoice(now_ms);
        if work.peek {
            self.auto_invoice.peek_sent_ms = Some(now_ms);
        }
        if work.delegation.get_watch_key {
            self.auto_invoice.watch_key_asked_ms = Some(now_ms);
        }
        if let Some(pending) = &work.delegation.delegate {
            self.auto_invoice
                .delegation_asked
                .insert((pending.ghostkey, pending.bridge));
            self.pending_signatures
                .push_back(crate::state::PendingSignature::WatchDelegation(Box::new(
                    pending.clone(),
                )));
        }
        if let Some(HarvestDelegateRequest::UpdateWatchDelegation {
            bridge,
            inbox_contract_id,
            last_made_at_ms,
        }) = &work.delegation.update
        {
            self.auto_invoice
                .delegation_update_sent
                .insert(*bridge, (*inbox_contract_id, *last_made_at_ms, now_ms));
        }
        for (arm, lapses_at) in work.arms.iter().zip(&work.lapses_at_ms) {
            self.auto_invoice.sent.insert(
                arm.store_contract_id.clone(),
                // As `auto_invoice_arm` gives it: 0 when nothing is watched.
                (without_left(arm), *lapses_at, now_ms),
            );
        }
        work
    }

    /// Send what [`Self::queue_auto_invoice`] decided.
    pub fn send_due_auto_invoice(&mut self) {
        let work = self.queue_auto_invoice(crate::state::now_ms());
        #[cfg(target_arch = "wasm32")]
        {
            if work.delegation.get_watch_key {
                crate::state::spawn_harvest_request(
                    HarvestDelegateRequest::GetWatchKey,
                    "the watch key request",
                );
            }
            if let Some(update) = work.delegation.update.clone() {
                crate::state::spawn_harvest_request(update, "the watch delegation update");
            }
            if let Some(pending) = work.delegation.delegate.clone() {
                spawn_delegation_signature(pending);
            }
            if work.peek || !work.arms.is_empty() {
                wasm_bindgen_futures::spawn_local(async move {
                    if work.peek {
                        if let Err(e) = crate::gateway::bitcoin_ops::peek_order_addresses().await {
                            dioxus::logger::tracing::warn!(
                                "could not ask for the next payment addresses: {e}"
                            );
                        }
                    }
                    for arm in work.arms {
                        if let Err(e) = crate::gateway::arm_auto_invoice(arm).await {
                            dioxus::logger::tracing::warn!("could not arm instant checkout: {e}");
                        }
                    }
                });
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = work;
    }

    /// The delegate's answer to `PeekOrderAddresses`.
    pub(crate) fn on_upcoming_addresses(
        &mut self,
        result: Result<Vec<DerivedAddress>, String>,
        now_ms: u64,
    ) {
        match (result, self.bitcoin.payment_xpub.as_ref()) {
            (Ok(upcoming), Some(xpub)) => {
                self.auto_invoice.upcoming_for = Some((xpub.xpub.clone(), now_ms));
                self.auto_invoice.upcoming = upcoming;
            }
            (Err(e), _) => {
                dioxus::logger::tracing::warn!("the delegate did not list its next addresses: {e}")
            }
            (Ok(_), None) => {}
        }
    }

    /// The delegate's answer to `ArmAutoInvoice`.
    pub(crate) fn on_auto_invoice_status(
        &mut self,
        store_contract_id: Vec<u8>,
        result: Result<AutoInvoiceStatus, String>,
    ) {
        if let Some(delegation) = result
            .as_ref()
            .ok()
            .and_then(|s| s.watch_delegation.clone())
        {
            self.note_watch_delegation(delegation);
        }
        self.auto_invoice.status.insert(store_contract_id, result);
    }

    /// Whether this store has, in the last two weeks, been paid at an
    /// address a wallet with the usual gap limit may not look at
    /// (`AutoInvoiceStatus::wallet_gap_paid_at_ms`). Per store, on the page
    /// of the store it happened at.
    /// The gap limit to tell the seller to set, when that is due.
    pub fn wallet_gap_note_due(&self, store_contract_id: &[u8]) -> Option<u32> {
        match self.auto_invoice.status.get(store_contract_id) {
            Some(Ok(s)) if s.wallet_gap_paid_at_ms.is_some() => Some(s.wallet_gap_limit.max(100)),
            _ => None,
        }
    }

    /// What the seller's store page says about instant checkout, or `None`
    /// when the store sells nothing with it.
    pub fn instant_checkout_notice(&self, store_contract_id: &[u8], now_ms: u64) -> Option<String> {
        if !self
            .instant_checkout_stores()
            .iter()
            .any(|(_, r)| r.store_contract_id == store_contract_id)
        {
            return None;
        }
        if self.bitcoin.payment_xpub.is_none() {
            return Some(
                "Buyers can't buy from this store until you add your wallet's payment key in \
                 Settings. Each order is paid to a new address from it."
                    .into(),
            );
        }
        Some(match self.auto_invoice.status.get(store_contract_id) {
            None => "Your store is starting to take orders on this device.".into(),
            Some(Err(why)) => format!("Your store can't take orders on this device: {why}."),
            Some(Ok(status)) => instant_checkout_status_text(status, now_ms),
        })
    }
}

/// Ask the Ghost Key vault to sign a delegation queued by
/// `AppState::queue_auto_invoice`. Withdrawn if the send fails; not asked
/// again this session (the pair is marked asked when queued).
#[cfg(target_arch = "wasm32")]
fn spawn_delegation_signature(pending: PendingWatchDelegation) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};
        let queued = crate::state::PendingSignature::WatchDelegation(Box::new(pending.clone()));
        let withdraw = |reason: String| {
            dioxus::logger::tracing::warn!("watch delegation not asked for: {reason}");
            crate::gateway::APP_STATE
                .write()
                .withdraw_pending_signature(&queued);
        };
        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            withdraw("ghostkey delegate not registered".to_string());
            return;
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint: pending.fingerprint,
            message: pending.signing_payload,
        };
        match ghostkey_common::to_cbor(&request) {
            Ok(payload) => {
                if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await
                {
                    withdraw(format!("send for signing: {e}"));
                }
            }
            Err(e) => withdraw(format!("serialize SignMessage: {e}")),
        }
    });
}

/// The instance id of the presence contract of the store `store_key` owns,
/// as this build addresses it.
pub(crate) fn presence_instance_bytes(store_key: &[u8; 32]) -> Option<[u8; 32]> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(store_key).ok()?;
    crate::gateway::presence_ops::presence_contract_key(&key)
        .ok()
        .map(|k| *k.id())
        .map(|id| {
            let mut out = [0u8; 32];
            out.copy_from_slice(id.as_bytes());
            out
        })
}

/// `arm` with its shrinking duration zeroed, for telling whether anything
/// else about it changed.
fn without_left(arm: &AutoInvoiceArm) -> AutoInvoiceArm {
    AutoInvoiceArm {
        watch_left_ms: 0,
        ..arm.clone()
    }
}

/// The store page's line for an armed store, led by any order that was paid
/// after its item had gone to another buyer.
pub fn instant_checkout_status_text(status: &AutoInvoiceStatus, now_ms: u64) -> String {
    let line = instant_checkout_state_text(status, now_ms);
    if status.oversold.is_empty() {
        return line;
    }
    let orders: Vec<String> = status.oversold.iter().map(|id| id.short()).collect();
    format!(
        "Paid when the listing's count no longer covered them (the item went to another \
         buyer, or you marked it sold out or took it down): {}. Refund or fulfil these by \
         hand. {line}",
        orders.join(", ")
    )
}

fn instant_checkout_state_text(status: &AutoInvoiceStatus, now_ms: u64) -> String {
    let line = instant_checkout_state_line(status, now_ms);
    match &status.capped {
        Some(why) => format!(
            "In the last hour a buyer couldn't order because {why}; they were told to try again \
             later. {line}"
        ),
        None => line,
    }
}

fn instant_checkout_state_line(status: &AutoInvoiceStatus, now_ms: u64) -> String {
    if status.last_background_run_ms.is_none()
        && now_ms.saturating_sub(status.armed_at_ms) >= NO_BACKGROUND_RUN_AFTER_MS
    {
        return "Your store can't take orders on this node. This happens when you use Harvest \
                through a hosted service such as try.freenet.org, where nothing runs while you \
                are away. Run Harvest on your own Freenet node to sell."
            .into();
    }
    if let Some(why) = &status.paused {
        return format!("Your store isn't taking orders right now: {why}.");
    }
    // Ready, but this node has not yet shown it runs in the background: the
    // tip read on arming (harvest#162) is answered even on a hosted gateway,
    // where nothing ever runs. The next block or buyer request is the proof.
    if status.last_background_run_ms.is_none() {
        return "Your store is starting to take orders: it can once this node has run it in \
                the background, at the next Bitcoin block or buyer order. On a hosted service \
                such as try.freenet.org that never happens."
            .into();
    }
    let hours = status.invoicing_until_ms.saturating_sub(now_ms) / (60 * 60 * 1000);
    let renews = match &status.watch_delegation {
        Some(delegation) if !delegation.stalled => {
            "and keeps renewing that on its own while this node runs"
        }
        _ => "and renews that whenever Harvest is open",
    };
    format!(
        "Your store is taking orders. This device sends buyers the payment details for about \
         {hours} more hours, up to {} more orders, {renews}.",
        status.watched_remaining
    )
}
