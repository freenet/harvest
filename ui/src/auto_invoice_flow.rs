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
//! for it. So instant checkout keeps working for about a day after the seller
//! last had Harvest open, and then requests wait for them again.

use std::collections::HashMap;

use freenet_bitcoin_common::BitcoinNetwork;
use harvest_common::delegate::{AutoInvoiceArm, AutoInvoiceStatus};
use harvest_common::DerivedAddress;

use crate::state::AppState;

/// How often an unchanged arm is sent again. Re-arming re-subscribes, which
/// is what brings the delegate back after the node restarts.
pub const REARM_EVERY_MS: u64 = 10 * 60 * 1000;
/// How long to wait for an answer to `PeekOrderAddresses` before asking again.
pub const PEEK_RETRY_MS: u64 = 60 * 1000;
/// How long a bridge keeps watching after the request that last asked, and
/// the margin kept below it.
pub const WATCH_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const WATCH_MARGIN_MS: u64 = 60 * 60 * 1000;
/// How long after arming a delegate that has never run in the background is
/// taken to be unable to: a new block arrives about every ten minutes, and
/// each one runs it.
pub const NO_BACKGROUND_RUN_AFTER_MS: u64 = 40 * 60 * 1000;

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
    /// The last arm sent for each store, and when.
    pub sent: HashMap<Vec<u8>, (AutoInvoiceArm, u64)>,
    /// What the delegate last said about each store.
    pub status: HashMap<Vec<u8>, Result<AutoInvoiceStatus, String>>,
}

/// What the instant-checkout loop should send now.
#[derive(Debug, Default, PartialEq)]
pub struct AutoInvoiceWork {
    pub peek: bool,
    pub arms: Vec<AutoInvoiceArm>,
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
                            network,
                            script: a.script_pubkey.clone(),
                            anchor_height: tip_height,
                        })
                        .collect(),
                ))
            })
    }

    /// The arm for one store, as things stand: `None` until everything it
    /// names is known.
    pub(crate) fn auto_invoice_arm(
        &self,
        fingerprint: &str,
        registration: &harvest_common::delegate::StoreRegistration,
        now_ms: u64,
    ) -> Option<AutoInvoiceArm> {
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
        // counted from the earliest of those requests.
        let inbox = self.bitcoin.inbox.as_ref()?;
        let mut watched_scripts = Vec::new();
        let mut earliest: Option<u64> = None;
        for address in upcoming {
            let Some(sent) = inbox
                .sent
                .get(&(network, address.script_pubkey.clone()))
                .filter(|s| s.read)
            else {
                // The delegate hands addresses out in order, so one not
                // watched ends the usable run.
                break;
            };
            watched_scripts.push(address.script_pubkey.clone());
            earliest = Some(earliest.map_or(sent.sent_at_ms, |e| e.min(sent.sent_at_ms)));
        }
        let watched_until_ms = earliest
            .map(|at| at + WATCH_LIFETIME_MS - WATCH_MARGIN_MS)
            .filter(|until| *until > now_ms)
            .unwrap_or(0);
        if watched_until_ms == 0 {
            watched_scripts.clear();
        }
        Some(AutoInvoiceArm {
            store_contract_id: registration.store_contract_id.clone(),
            store_verifying_key,
            mailbox_contract_id,
            seller_fingerprint: fingerprint.to_string(),
            network,
            tip_contract_id,
            trusted_bridges,
            address_code_hash,
            watched_scripts,
            watched_until_ms,
        })
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
            let Some(arm) = self.auto_invoice_arm(&fingerprint, &registration, now_ms) else {
                continue;
            };
            let due = match self.auto_invoice.sent.get(&registration.store_contract_id) {
                Some((sent, at)) => *sent != arm || now_ms.saturating_sub(*at) >= REARM_EVERY_MS,
                None => true,
            };
            if due {
                work.arms.push(arm);
            }
        }
        work
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
        for arm in &work.arms {
            self.auto_invoice
                .sent
                .insert(arm.store_contract_id.clone(), (arm.clone(), now_ms));
        }
        work
    }

    /// Send what [`Self::queue_auto_invoice`] decided.
    pub fn send_due_auto_invoice(&mut self) {
        let work = self.queue_auto_invoice(crate::state::now_ms());
        #[cfg(target_arch = "wasm32")]
        {
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

    /// The delegate's answer to `ArmAutoInvoice` or `GetAutoInvoiceStatus`.
    pub(crate) fn on_auto_invoice_status(
        &mut self,
        store_contract_id: Vec<u8>,
        result: Result<AutoInvoiceStatus, String>,
    ) {
        self.auto_invoice.status.insert(store_contract_id, result);
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
                "Instant checkout needs your wallet's payment key. Until you add it, buyers \
                 send you a request instead."
                    .into(),
            );
        }
        Some(match self.auto_invoice.status.get(store_contract_id) {
            None => "Instant checkout is starting on this device.".into(),
            Some(Err(why)) => format!("Instant checkout is off on this device: {why}."),
            Some(Ok(status)) => instant_checkout_status_text(status, now_ms),
        })
    }
}

/// The store page's line for an armed store.
pub fn instant_checkout_status_text(status: &AutoInvoiceStatus, now_ms: u64) -> String {
    if status.last_background_run_ms.is_none()
        && now_ms.saturating_sub(status.armed_at_ms) >= NO_BACKGROUND_RUN_AFTER_MS
    {
        return "Instant checkout is not running on this node. This happens when you use Harvest \
                through a hosted service such as try.freenet.org: buyers send you a request \
                instead, and you answer it when you are here. Run Harvest on your own Freenet \
                node for instant checkout."
            .into();
    }
    if let Some(why) = &status.paused {
        return format!("Instant checkout is paused: {why}. Buyers send you a request instead.");
    }
    let hours = status.watched_until_ms.saturating_sub(now_ms) / (60 * 60 * 1000);
    format!(
        "Instant checkout is on. This device invoices buyers for you for about {hours} more \
         hours, up to {} more orders, and renews that whenever Harvest is open.",
        status.watched_remaining
    )
}
