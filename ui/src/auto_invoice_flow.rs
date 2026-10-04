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
//! (`SetWatchDelegation`). From then on the delegate keeps the bridge
//! watching the addresses this tab armed (the window it read clear) itself,
//! on its five-minute wake-ups, so the store keeps taking orders with Harvest
//! closed until that window is used; it never watches or invoices past it
//! (harvest#198). This tab keeps the delegate told which
//! inbox the bridge serves and the latest `made_at_ms` it has sent
//! (`UpdateWatchDelegation`), and dates its own requests above the
//! delegate's: the two share one timeline per Ghost Key.

use std::collections::HashMap;

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
    /// Set when an address in the window was newly found paid, and cleared
    /// when the next window arrives (or the key changes): until then every
    /// arm goes out EMPTY, so the delegate stops renewing and invoicing on
    /// the window at once, and the next peek re-reads and re-arms it.
    /// Instant checkout pauses meanwhile (round 4 of batch 2: this replaced a
    /// trim of the stale window that kept needing more checks).
    pub paid_since_read: bool,
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
    /// delegate for, and the height the last delegation asked for was
    /// issued at: once each, never on every open, and again only when the
    /// delegate reports THAT delegation (or a later one) stalled.
    pub delegation_asked: HashMap<(GhostkeyId, BridgeId), u32>,
    /// The delegation the delegate holds for each bridge, as it last said.
    pub delegations: HashMap<BridgeId, WatchDelegationStatus>,
    /// The last `UpdateWatchDelegation` sent per bridge: the inbox and
    /// `made_at_ms` it named, and when.
    pub delegation_update_sent: HashMap<BridgeId, ([u8; 32], u64, u64)>,
    /// A signed delegation handed to the delegate and not yet taken, per
    /// bridge: the request, the height it was issued at, when it was last
    /// sent, and how many times (0, and dated a resend period back, while it
    /// is held unsent because the address window is shut, harvest#183). Resent as it is (no new vault prompt) until
    /// the delegate's answer shows it held, so a send that never arrived or a
    /// passing refusal does not leave delegated watching off for the session
    /// behind the once-only `delegation_asked`.
    pub delegation_in_flight: HashMap<BridgeId, InFlightDelegation>,
    /// Pairs whose signed delegation went unanswered through every send:
    /// how many times in a row, and until when the vault is not asked again.
    /// Doubling from `UNANSWERED_BACKOFF_MS`, so a delegate that is simply
    /// unreachable does not bring a vault prompt every few minutes.
    pub delegation_unanswered: HashMap<(GhostkeyId, BridgeId), (u32, u64)>,
    /// What each of the delegate's next addresses' address contract showed,
    /// by payment script ([`AddressVet`], harvest#183). None of them goes
    /// to the bridge or into an arm before it is clear. Pruned to the
    /// current window whenever the window is read again,
    /// so an address that leaves the window and comes back is read again.
    pub vets: HashMap<Vec<u8>, AddressVet>,
    /// The token the next address-contract read is started under, so a
    /// timer left from an earlier read cannot end a later one.
    pub next_vet_token: u64,
    /// When the delegate was last asked to move its counter past used
    /// addresses, and the counter it was asked at.
    pub raise_sent: Option<(u32, u64)>,
    /// The address requests that are such raises, not invoices: their
    /// answers are dropped quietly.
    pub raise_requests: std::collections::HashSet<u64>,
    /// Until when no raise is started, after one whose catch-up could not
    /// finish (#206), so it is not started again at once.
    pub raise_held_until_ms: Option<u64>,
    /// The used addresses this session has asked the delegate to move past,
    /// recorded when each raise is sent (so a sale the delegate made
    /// and a buyer paid, which also shows up as a payment, is not counted).
    pub moved_past: std::collections::HashSet<Vec<u8>>,
    /// Whether the seller has been told that many addresses turned out used.
    pub vets_many_used_told: bool,
    /// Set when a payment turned an address used: the lowest peek request
    /// id whose answer may count. The window must be read again, by a peek
    /// sent after the verdict, before anything is raised on it. Request ids
    /// only grow, so this needs no clock.
    pub stale_from_peek: Option<u64>,
    /// The request id of the last peek sent.
    pub last_peek_id: Option<u64>,
    /// The request id of the last peek answer taken: an older answer landing
    /// after it is dropped, never replacing a newer window.
    pub last_answered_peek: Option<u64>,
    /// The lowest peek request id asked under the payment key held now: an
    /// answer to a peek sent under an earlier key lists that key's addresses
    /// and must not be read as this key's.
    pub key_floor_peek: Option<u64>,
    /// Reads still out under an earlier address-contract build, by that
    /// build's contract id: a late answer showing a payment still makes the
    /// address used (a payment under any build stands).
    pub retired_reads: HashMap<[u8; 32], Vec<u8>>,
}

/// What an upcoming address's address contract showed (harvest#183).
///
/// # Why instant checkout reads it before watching
///
/// The delegate's address counter is floored only by the scripts on orders
/// the seller's LOADED stores hold (harvest#77). A delegate that lost its
/// counter (a re-key with no migration row, a new device) and is given the
/// same payment key starts again at the lowest index that no loaded order
/// names, and orders on another store, on an earlier store generation, or
/// pruned from the store are invisible to that floor. Invoices by hand read
/// the address contract before signing (`check_address_before_signing`);
/// instant checkout, which invoices with no tab, had nothing, and in the
/// 0.2.139 release E2E it put already-paid addresses 0, 1 and 2 on the first
/// three buyers' invoices.
///
/// So the tab reads each of the delegate's next addresses' address contract
/// first. Only PAYMENT history counts ([`address_state_payments`]): a scan
/// watermark alone is what this tab's own watch (or an earlier device's)
/// leaves on every upcoming address, and counting it would burn the whole
/// pool on every visit. An address with history makes the tab ask the
/// delegate for one address with that script among the published ones
/// (`DeriveOrderAddress`, which floors the key the delegate HOLDS, so it can
/// never put back a key the seller replaced), which moves the counter past
/// it. That skips every index up to the highest used one, clear ones between
/// included, and the one address handed back is dropped too. Then the tab
/// reads the next window.
///
/// # A payment on an address the delegate has since spent is not reuse
///
/// The tab's window can be up to [`REARM_EVERY_MS`] old: the delegate hands
/// its addresses out in the background without telling it. A buyer paying
/// such an instant invoice shows up as a payment on an address still in the
/// window. So any address newly found paid only makes the window stale: it is
/// read again (and the counter with it), by a peek sent after the verdict,
/// before anything is raised, and a raise goes out only for a used address in
/// that window.
///
/// Silence for [`ADDRESS_VET_TIMEOUT_MS`], or `NotFound`, counts as clear: a
/// fresh address's contract does not exist, and Freenet reports absence
/// slowly or not at all (see `AppState::on_address_reuse_timeout`). A late
/// answer, or a later read, that shows a payment still turns a clear address
/// used, and a clear verdict is read again every [`VET_REFRESH_MS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressVet {
    /// The address contract read for it.
    pub contract_id: [u8; 32],
    pub verdict: VetVerdict,
    /// When the verdict was reached (0 while the first read is out).
    pub at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VetVerdict {
    /// Asked under this token, nothing known yet.
    Asking { token: u64 },
    /// No payment was recorded there, or nothing answered in time.
    Clear,
    /// Clear, and being read again under this token.
    Rechecking { token: u64 },
    /// A payment (or a retraction of one) is recorded there.
    Used,
    /// Its state did not decode (at `at_ms`): not clear, not filed as used,
    /// read again after [`PEEK_RETRY_MS`].
    Unreadable,
}

impl AddressVet {
    /// Whether the gate may pass it.
    pub fn is_clear(&self) -> bool {
        matches!(
            self.verdict,
            VetVerdict::Clear | VetVerdict::Rechecking { .. }
        )
    }
    fn token(&self) -> Option<u64> {
        match self.verdict {
            VetVerdict::Asking { token } | VetVerdict::Rechecking { token } => Some(token),
            _ => None,
        }
    }
}

/// How long an upcoming address's contract read may go unanswered before
/// the address counts as clear. The same wait an invoice by hand gives.
pub const ADDRESS_VET_TIMEOUT_MS: u32 = crate::state::ADDRESS_REUSE_CHECK_TIMEOUT_MS;

/// How long a clear verdict stands before the address is read again (the
/// address stays usable meanwhile). The same period the tab re-arms at.
pub const VET_REFRESH_MS: u64 = REARM_EVERY_MS;

/// How long after a raise before another may go at the same counter. Long
/// enough for the answer and the refreshed count to come back: each raise
/// burns an index.
pub const RAISE_RETRY_MS: u64 = 5 * 60 * 1000;

/// How many used addresses in one session before the seller is told: a
/// stale counter recovers in a window or two, and far more than that means
/// something else is issuing from the key, or the wallet's gap limit needs
/// to cover the skipped run.
pub const MANY_VETTED_USED: usize = crate::state::MAX_REUSED_ADDRESS_SKIPS as usize;

/// Whether an address contract's state records any payment: a payment or
/// retraction claim, not merely a bridge's scan watermark. `None` for a
/// state that does not decode: the address is then neither clear nor filed
/// as used (it would be moved past on every visit if the state format ever
/// drifted from this build's decoder), and is read again.
pub fn address_state_payments(state_bytes: &[u8]) -> Option<bool> {
    if state_bytes.is_empty() {
        return Some(false);
    }
    freenet_bitcoin_common::from_cbor::<freenet_bitcoin_common::BitcoinAddressStateV1>(state_bytes)
        .ok()
        .map(|state| !state.claims.claims.is_empty())
}

/// The instance id of the address contract build `code_hash` for `script`
/// on `network`, watched by `trusted_bridges`: what an order naming that
/// address, those bridges and that build would watch
/// (`Order::bitcoin_address_instance_id_under`, which a test holds this to).
///
/// A deliberate copy of that derivation rather than a shared function in
/// `harvest-common`: common is compiled into the contracts and the delegate,
/// and moving code there can change their WASM. A change to one side must
/// be made to both; the test fails when they differ.
pub fn address_instance_id(
    network: BitcoinNetwork,
    script: &[u8],
    trusted_bridges: &[BridgeId],
    code_hash: [u8; 32],
) -> [u8; 32] {
    let params = freenet_bitcoin_common::BitcoinAddressParameters {
        network,
        script_pubkey: script.to_vec(),
        trusted_bridges: trusted_bridges.to_vec(),
        pow_floor: network.default_pow_floor(),
    };
    let params = harvest_common::to_cbor(&params)
        .expect("BitcoinAddressParameters always serializes to CBOR");
    let mut hasher = blake3::Hasher::new();
    hasher.update(&code_hash);
    hasher.update(&params);
    *hasher.finalize().as_bytes()
}

/// The first wait before the vault is asked again after a signed delegation
/// went unanswered; doubled each time in a row, up to
/// `UNANSWERED_BACKOFF_MAX_MS`.
pub const UNANSWERED_BACKOFF_MS: u64 = 10 * 60 * 1000;
pub const UNANSWERED_BACKOFF_MAX_MS: u64 = 4 * 60 * 60 * 1000;

/// The wait after the `times`-th unanswered delegation in a row.
pub fn unanswered_wait(times: u32) -> u64 {
    (UNANSWERED_BACKOFF_MS << times.saturating_sub(1).min(8)).min(UNANSWERED_BACKOFF_MAX_MS)
}

/// See [`AutoInvoiceUi::delegation_in_flight`].
#[derive(Clone, Debug, PartialEq)]
pub struct InFlightDelegation {
    pub request: HarvestDelegateRequest,
    pub ghostkey: [u8; 32],
    pub issued_mainnet_height: u32,
    pub sent_ms: u64,
    pub attempts: u32,
}

/// How long a signed delegation may go unanswered before it is sent again.
pub const DELEGATION_RESEND_MS: u64 = 60 * 1000;

/// How many times a signed delegation is sent in all. Past this it is given
/// up: a refusal that keeps coming is the delegate's verdict (a wrong key,
/// an older delegation), and asking the vault again would only repeat it.
pub const DELEGATION_SEND_ATTEMPTS: u32 = 3;

/// A delegation of watch requests queued for the Ghost Key's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingWatchDelegation {
    pub fingerprint: String,
    pub ghostkey: GhostkeyId,
    pub network: BitcoinNetwork,
    pub bridge: BridgeId,
    pub inbox_contract_id: [u8; 32],
    pub issued_mainnet_height: u32,
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
    /// Send again a signed delegation the delegate has not taken.
    pub resend: Option<HarvestDelegateRequest>,
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
    /// Upcoming addresses whose address contract to read: its id, the
    /// address's script, and the token the read runs under.
    pub vets: Vec<([u8; 32], Vec<u8>, u64)>,
    /// Ask the delegate for an address with the used scripts among the
    /// published ones, so its counter moves past them.
    pub raise: bool,
    /// The request id that raise goes under, once queued.
    pub raise_request: Option<u64>,
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
    /// and counter the delegate now reports, and every one of them has been
    /// read and found to hold no payment ([`AddressVet`], harvest#183).
    ///
    /// Everything this tab does to put an upcoming address in play goes
    /// through this: the prewatch, the arm and the watch delegation. So until
    /// the whole window is clear none of them is sent. The whole window, not
    /// the clear addresses before the first used one: a delegation would let
    /// the delegate watch from its counter by itself, used address included.
    ///
    /// What it cannot do is withdraw what the delegate already holds. A
    /// delegate with a live arm or delegation keeps invoicing on its own
    /// watches, so an address found used there is safe only once the raise
    /// has moved the counter past it, seconds later; an invoice in between
    /// can land on it. A delegate that lost its counter lost its arm and
    /// delegation with it (a re-key or a new device), so the case #183 hit
    /// has nothing to withdraw at first.
    ///
    /// The delegate does not reach past the window (harvest#198): its own
    /// delegated watches count only for scripts an arm names, and it renews
    /// only those, so with the tab closed instant checkout stops at the end
    /// of the window read here (its heartbeat then says not taking orders)
    /// rather than invoicing an address nobody read.
    fn current_upcoming(&self) -> Option<(BitcoinNetwork, &[DerivedAddress])> {
        let (network, upcoming) = self.upcoming_unvetted()?;
        // Read under the address contract an order would name NOW: a verdict
        // reached under an earlier build is no verdict on this one.
        let ids = self.window_contract_ids()?;
        upcoming
            .iter()
            .zip(ids)
            .all(|(a, id)| {
                self.auto_invoice
                    .vets
                    .get(&a.script_pubkey)
                    .is_some_and(|v| v.is_clear() && v.contract_id == id)
            })
            .then_some((network, upcoming))
    }

    /// The address contract ids of the current window, under the address
    /// generation and bridges an order would name now; `None` until the
    /// generation has resolved.
    pub(crate) fn window_contract_ids(&self) -> Option<Vec<[u8; 32]>> {
        let (network, upcoming) = self.upcoming_unvetted()?;
        let code_hash = self.bitcoin.address_generation.code_hash()?;
        let bridges = crate::gateway::bitcoin_config::default_trusted_bridges(network).ok()?;
        Some(
            upcoming
                .iter()
                .map(|a| address_instance_id(network, &a.script_pubkey, &bridges, code_hash))
                .collect(),
        )
    }

    /// The part of the window an arm may name (harvest#198): from the
    /// counter, every address read clear under the build an order would
    /// name now, up to the first found used. `None` while the reads have not
    /// settled (an address unread, being read, unreadable, or read under
    /// another build before any used one): the delegate then keeps the arm
    /// it has, rather than being told the window shrank to what has been
    /// read so far. A window found used part-way is armed up to that
    /// address, so the delegate stops renewing and invoicing on it.
    fn vetted_window(&self) -> Option<(BitcoinNetwork, &[DerivedAddress])> {
        let (network, upcoming) = self.upcoming_unvetted()?;
        let ids = self.window_contract_ids()?;
        for (i, (a, id)) in upcoming.iter().zip(ids).enumerate() {
            match self.auto_invoice.vets.get(&a.script_pubkey) {
                Some(v) if v.is_clear() && v.contract_id == id => {}
                Some(v) if v.verdict == VetVerdict::Used => {
                    return Some((network, &upcoming[..i]));
                }
                _ => return None,
            }
        }
        Some((network, upcoming))
    }

    /// [`Self::current_upcoming`] before the address-contract reads.
    fn upcoming_unvetted(&self) -> Option<(BitcoinNetwork, &[DerivedAddress])> {
        let xpub = self.bitcoin.payment_xpub.as_ref()?;
        let (key, _) = self.auto_invoice.upcoming_for.as_ref()?;
        let first = self.auto_invoice.upcoming.first()?;
        (*key == xpub.xpub && first.index >= xpub.next_index)
            .then_some((xpub.network, self.auto_invoice.upcoming.as_slice()))
    }

    /// The upcoming addresses whose address contract is to be read now (never
    /// read, or clear for [`VET_REFRESH_MS`]), with the id to read and the
    /// token each read runs under. Empty until the address generation has
    /// resolved: the id depends on it.
    fn vets_due(&self, now_ms: u64) -> Vec<([u8; 32], Vec<u8>, u64)> {
        let Some((_, upcoming)) = self.upcoming_unvetted() else {
            return Vec::new();
        };
        let Some(ids) = self.window_contract_ids() else {
            return Vec::new();
        };
        upcoming
            .iter()
            .zip(ids)
            .filter(
                |(a, id)| match self.auto_invoice.vets.get(&a.script_pubkey) {
                    None => true,
                    // Read under another build: read again under this one. Not a
                    // used one: a payment recorded under any build stands, and the
                    // new build's contract would not show it (the bridge does not
                    // look back).
                    Some(vet) if vet.contract_id != *id && vet.verdict != VetVerdict::Used => true,
                    Some(vet) => match vet.verdict {
                        VetVerdict::Clear => now_ms.saturating_sub(vet.at_ms) >= VET_REFRESH_MS,
                        VetVerdict::Unreadable => now_ms.saturating_sub(vet.at_ms) >= PEEK_RETRY_MS,
                        _ => false,
                    },
                },
            )
            .enumerate()
            .map(|(i, (a, id))| {
                (
                    id,
                    a.script_pubkey.clone(),
                    self.auto_invoice.next_vet_token + i as u64,
                )
            })
            .collect()
    }

    /// Whether to ask the delegate to move past used addresses now: one is
    /// in the window, and it was not asked at this counter in the last
    /// [`RAISE_RETRY_MS`]. No limit on how many: a paid address must never go
    /// on an invoice, and only a trusted bridge's claim makes one used.
    fn raise_due(&self, now_ms: u64) -> bool {
        let Some(xpub) = self.bitcoin.payment_xpub.as_ref() else {
            return false;
        };
        let Some((_, upcoming)) = self.upcoming_unvetted() else {
            return false;
        };
        let used_ahead = upcoming.iter().any(|a| {
            self.auto_invoice
                .vets
                .get(&a.script_pubkey)
                .is_some_and(|v| v.verdict == VetVerdict::Used)
        });
        let recent = self.auto_invoice.raise_sent.is_some_and(|(counter, at)| {
            counter == xpub.next_index && now_ms.saturating_sub(at) < RAISE_RETRY_MS
        });
        // Not while the delegate does not hold this tab's scripts, used
        // addresses included (they are sent as additions, #206), nor while a
        // raise that could not finish is held off.
        let held = self
            .auto_invoice
            .raise_held_until_ms
            .is_some_and(|until| now_ms < until);
        used_ahead && !recent && !held && self.scripts_synced()
    }

    /// The scripts of addresses found used by [`AddressVet`]: published as
    /// far as the counter is concerned (`AppState::published_payment_scripts`).
    pub(crate) fn vetted_used_scripts(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.auto_invoice
            .vets
            .iter()
            .filter(|(_, v)| v.verdict == VetVerdict::Used)
            .map(|(script, _)| script)
    }

    /// Keep only the reads of the current window: an address that leaves it
    /// (spent, or moved past) and comes back after a counter fell is read
    /// afresh. A used one below the counter has done its work: the counter is
    /// past it.
    fn prune_vets(&mut self) {
        let window: std::collections::HashSet<Vec<u8>> = self
            .auto_invoice
            .upcoming
            .iter()
            .map(|a| a.script_pubkey.clone())
            .collect();
        self.auto_invoice
            .vets
            .retain(|script, _| window.contains(script));
        self.auto_invoice
            .retired_reads
            .retain(|_, script| window.contains(script));
    }

    /// A state arrived for `contract_id`. It settles a read that is out: used
    /// when it shows a payment, clear when not, unreadable when it does not
    /// decode. A payment on an address already read clear (a late answer, or
    /// a payment since) turns it used too. Any address newly found used makes
    /// the window stale, so the window and counter are read again, by a peek
    /// sent after the verdict, before any raise: it may be an address the
    /// delegate has since handed out and a buyer paid (see [`AddressVet`]).
    /// Returns whether `contract_id` is an upcoming address's contract.
    pub(crate) fn on_address_vet_state(
        &mut self,
        contract_id: &[u8],
        state_bytes: &[u8],
        now_ms: u64,
    ) -> bool {
        if let Ok(id) = <[u8; 32]>::try_from(contract_id) {
            if let Some(script) = self.auto_invoice.retired_reads.remove(&id) {
                if address_state_payments(state_bytes) == Some(true) {
                    // Its current read may be gone (a send that failed):
                    // recorded used whatever is held.
                    let held = self.auto_invoice.vets.get(&script);
                    if held.is_none_or(|v| v.verdict != VetVerdict::Used) {
                        dioxus::logger::tracing::warn!(
                            "An upcoming payment address (script {}) was paid under an \
                             earlier address-contract build; moving the delegate's counter \
                             past it",
                            hex::encode(&script)
                        );
                        let contract_id = held.map_or(id, |v| v.contract_id);
                        self.auto_invoice.vets.insert(
                            script,
                            AddressVet {
                                contract_id,
                                verdict: VetVerdict::Used,
                                at_ms: now_ms,
                            },
                        );
                        self.auto_invoice.upcoming_for = None;
                        self.auto_invoice.paid_since_read = true;
                        self.auto_invoice.stale_from_peek = Some(self.bitcoin.next_request_id + 1);
                    }
                }
                if !self
                    .auto_invoice
                    .vets
                    .values()
                    .any(|v| v.contract_id.as_slice() == contract_id)
                {
                    return true;
                }
            }
        }
        if !self
            .auto_invoice
            .vets
            .values()
            .any(|v| v.contract_id.as_slice() == contract_id)
        {
            return false;
        }
        match address_state_payments(state_bytes) {
            Some(true) => {
                let newly_used = self.auto_invoice.vets.values().any(|v| {
                    v.contract_id.as_slice() == contract_id && v.verdict != VetVerdict::Used
                });
                self.settle_vet(contract_id, None, true, VetVerdict::Used, now_ms);
                if newly_used {
                    // Read the window again, by a peek sent from now on,
                    // before believing it.
                    self.auto_invoice.upcoming_for = None;
                    self.auto_invoice.paid_since_read = true;
                    self.auto_invoice.stale_from_peek = Some(self.bitcoin.next_request_id + 1);
                }
            }
            Some(false) => {
                self.settle_vet(contract_id, None, false, VetVerdict::Clear, now_ms);
            }
            None => {
                dioxus::logger::tracing::warn!(
                    "An upcoming payment address's contract state did not decode; reading it \
                     again later before it may be used"
                );
                self.settle_vet(contract_id, None, false, VetVerdict::Unreadable, now_ms);
            }
        }
        true
    }

    /// The node answered `NotFound`: nothing was ever published there, as
    /// far as it can tell. Clear, like silence.
    pub(crate) fn on_address_vet_absent(&mut self, contract_id: &[u8], now_ms: u64) -> bool {
        let retired = <[u8; 32]>::try_from(contract_id)
            .ok()
            .and_then(|id| self.auto_invoice.retired_reads.remove(&id))
            .is_some();
        self.settle_vet(contract_id, None, false, VetVerdict::Clear, now_ms) || retired
    }

    /// No answer in [`ADDRESS_VET_TIMEOUT_MS`] to the read started under
    /// `token`: clear (see [`AddressVet`] on why silence is).
    pub(crate) fn on_address_vet_timeout(
        &mut self,
        contract_id: &[u8],
        token: u64,
        now_ms: u64,
    ) -> bool {
        self.settle_vet(contract_id, Some(token), false, VetVerdict::Clear, now_ms)
    }

    /// The read under `token` could not even be sent: forget it, so it is
    /// asked again rather than timing out into "clear" having asked nothing.
    pub(crate) fn on_address_vet_unsent(&mut self, contract_id: &[u8], token: u64) {
        self.auto_invoice.vets.retain(|_, v| {
            !(v.contract_id.as_slice() == contract_id
                && v.token() == Some(token)
                && matches!(v.verdict, VetVerdict::Asking { .. }))
        });
        // A refresh that could not be sent stays clear, due again.
        for v in self.auto_invoice.vets.values_mut() {
            if v.contract_id.as_slice() == contract_id
                && v.verdict == (VetVerdict::Rechecking { token })
            {
                v.verdict = VetVerdict::Clear;
            }
        }
    }

    /// Settle the reads of `contract_id`: those still out (under `token`, if
    /// given), or, when `any_phase`, every one whatever it was.
    fn settle_vet(
        &mut self,
        contract_id: &[u8],
        token: Option<u64>,
        any_phase: bool,
        verdict: VetVerdict,
        now_ms: u64,
    ) -> bool {
        let mut settled = false;
        for (script, vet) in self.auto_invoice.vets.iter_mut() {
            if vet.contract_id.as_slice() != contract_id {
                continue;
            }
            let out = vet.token();
            if !any_phase && (out.is_none() || token.is_some_and(|t| Some(t) != out)) {
                continue;
            }
            if verdict == VetVerdict::Used && vet.verdict != VetVerdict::Used {
                dioxus::logger::tracing::warn!(
                    "An upcoming payment address (script {}) has been paid before; moving the \
                     delegate's counter past it",
                    hex::encode(script)
                );
            }
            if vet.verdict != VetVerdict::Used {
                vet.verdict = verdict.clone();
                vet.at_ms = now_ms;
            }
            settled = true;
        }
        settled
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
        // A window made stale by a payment is read again at once, unless a
        // peek has gone since.
        let asked_since_stale = match self.auto_invoice.stale_from_peek {
            Some(first) => self.auto_invoice.last_peek_id.is_some_and(|id| id >= first),
            None => true,
        };
        stale
            && (!asked_since_stale
                || self
                    .auto_invoice
                    .peek_sent_ms
                    .is_none_or(|at| now_ms.saturating_sub(at) >= PEEK_RETRY_MS))
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
        // After a newly paid address in the window, the arm names nothing
        // until the window is read again (`paid_since_read`).
        let (network, upcoming) = if self.auto_invoice.paid_since_read {
            (self.bitcoin.payment_xpub.as_ref()?.network, &[][..])
        } else {
            self.vetted_window()?
        };
        let vetted_scripts: Vec<Vec<u8>> =
            upcoming.iter().map(|a| a.script_pubkey.clone()).collect();
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
            // Kept whatever the tab's own watch is: what the delegation
            // renews must not vanish on a tab load before this tab knows its
            // own watches again (review round 1 of batch 2).
            vetted_scripts,
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
        work.vets = self.vets_due(now_ms);
        work.raise = self.raise_due(now_ms);
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
        // Only for the bridge this tab uses now: a delegation for another
        // was prepared against an inbox the tab no longer reads.
        let bridge = self.bitcoin.inbox.as_ref().map(|inbox| inbox.bridge);
        // And only while the window is clear, like the first send.
        work.delegation.resend = bridge
            .filter(|_| self.current_upcoming().is_some())
            .and_then(|bridge| self.auto_invoice.delegation_in_flight.get(&bridge))
            .filter(|f| {
                f.attempts < DELEGATION_SEND_ATTEMPTS
                    && now_ms.saturating_sub(f.sent_ms) >= DELEGATION_RESEND_MS
            })
            .map(|f| f.request.clone());
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
        // Asked once this session: again only once the delegate says the
        // delegation asked for (or a later one) has stalled, never while it
        // may still be on its way or was refused.
        let stalled_since_asked = |asked: u32| {
            held.is_some_and(|d| {
                d.ghostkey == ghostkey.0 && d.stalled && d.issued_mainnet_height >= asked
            })
        };
        if self
            .auto_invoice
            .delegation_asked
            .get(&(ghostkey, bridge))
            .is_some_and(|asked| !stalled_since_asked(*asked))
        {
            return work;
        }
        if self
            .auto_invoice
            .delegation_unanswered
            .get(&(ghostkey, bridge))
            .is_some_and(|(_, until)| now_ms < *until)
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
            issued_mainnet_height: issued,
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
        now_ms: u64,
    ) -> Option<HarvestDelegateRequest> {
        // Prepared for an inbox this tab has since stopped using: its bridge
        // may be another, and the next plan asks again against the current one.
        let inbox = self
            .bitcoin
            .inbox
            .as_ref()
            .filter(|inbox| inbox.bridge == pending.bridge)?;
        let request = HarvestDelegateRequest::SetWatchDelegation {
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
        };
        // Only while the window is clear (harvest#183): it may have closed
        // while the vault signed. Held, unsent, for the resend to carry once
        // it opens again.
        let open = self.current_upcoming().is_some();
        self.auto_invoice.delegation_in_flight.insert(
            pending.bridge,
            InFlightDelegation {
                request: request.clone(),
                ghostkey: pending.ghostkey.0,
                issued_mainnet_height: pending.issued_mainnet_height,
                sent_ms: if open {
                    now_ms
                } else {
                    now_ms.saturating_sub(DELEGATION_RESEND_MS)
                },
                attempts: u32::from(open),
            },
        );
        open.then_some(request)
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
            Ok(status) => {
                // Taken once the delegate holds it, or a later one for the
                // same Ghost Key (an update's answer for an older one does
                // not count).
                if self
                    .auto_invoice
                    .delegation_in_flight
                    .get(&bridge)
                    .is_some_and(|f| {
                        status.ghostkey == f.ghostkey
                            && status.issued_mainnet_height >= f.issued_mainnet_height
                    })
                {
                    self.auto_invoice.delegation_in_flight.remove(&bridge);
                    self.auto_invoice
                        .delegation_unanswered
                        .remove(&(GhostkeyId(status.ghostkey), bridge));
                }
                self.note_watch_delegation(status)
            }
            Err(e) => {
                dioxus::logger::tracing::warn!(
                    "the delegate did not take the watch delegation for bridge {}: {e}",
                    bs58::encode(bridge.0).into_string()
                );
                // Due again at once, until the attempts run out.
                if let Some(f) = self.auto_invoice.delegation_in_flight.get_mut(&bridge) {
                    if f.attempts >= DELEGATION_SEND_ATTEMPTS {
                        self.auto_invoice.delegation_in_flight.remove(&bridge);
                    } else {
                        f.sent_ms = 0;
                    }
                }
            }
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
        let mut work = self.plan_auto_invoice(now_ms);
        if work.peek {
            self.auto_invoice.peek_sent_ms = Some(now_ms);
        }
        for (contract_id, script, token) in &work.vets {
            let verdict = match self.auto_invoice.vets.get(script) {
                Some(held) if held.is_clear() && held.contract_id == *contract_id => {
                    VetVerdict::Rechecking { token: *token }
                }
                _ => VetVerdict::Asking { token: *token },
            };
            let at_ms = self.auto_invoice.vets.get(script).map_or(0, |v| v.at_ms);
            if let Some(held) = self
                .auto_invoice
                .vets
                .get(script)
                .filter(|held| held.contract_id != *contract_id && held.token().is_some())
            {
                self.auto_invoice
                    .retired_reads
                    .insert(held.contract_id, script.clone());
            }
            self.auto_invoice.vets.insert(
                script.clone(),
                AddressVet {
                    contract_id: *contract_id,
                    verdict,
                    at_ms,
                },
            );
            self.auto_invoice.next_vet_token = self.auto_invoice.next_vet_token.max(token + 1);
        }
        if work.raise {
            let counter = self
                .bitcoin
                .payment_xpub
                .as_ref()
                .map_or(0, |x| x.next_index);
            self.auto_invoice.raise_sent = Some((counter, now_ms));
            let used_ahead: Vec<Vec<u8>> = self
                .auto_invoice
                .upcoming
                .iter()
                .filter(|a| {
                    self.auto_invoice
                        .vets
                        .get(&a.script_pubkey)
                        .is_some_and(|v| v.verdict == VetVerdict::Used)
                })
                .map(|a| a.script_pubkey.clone())
                .collect();
            self.auto_invoice.moved_past.extend(used_ahead);
            let moved = self.auto_invoice.moved_past.len();
            if moved > MANY_VETTED_USED && !self.auto_invoice.vets_many_used_told {
                self.auto_invoice.vets_many_used_told = true;
                self.notifications.push(format!(
                    "Harvest skipped {moved} payment addresses from your key because they had \
                     already been paid. If another device issues invoices from this key, stop it. \
                     Set your wallet's gap limit to at least 100 so it still sees your payments."
                ));
            }
            let request_id = self.bitcoin.next_request_id();
            self.bitcoin.in_flight.insert(request_id);
            self.auto_invoice.raise_requests.insert(request_id);
            work.raise_request = Some(request_id);
        }
        if work.delegation.get_watch_key {
            self.auto_invoice.watch_key_asked_ms = Some(now_ms);
        }
        if let Some(pending) = &work.delegation.delegate {
            self.auto_invoice.delegation_asked.insert(
                (pending.ghostkey, pending.bridge),
                pending.issued_mainnet_height,
            );
            self.pending_signatures
                .push_back(crate::state::PendingSignature::WatchDelegation(Box::new(
                    pending.clone(),
                )));
        }
        // Sent every time and never answered: nothing will report it
        // stalled, so it is given up and the vault may be asked afresh (a
        // refusal that keeps coming is handled in `on_watch_delegation`,
        // where it is the delegate's verdict and is not re-asked).
        let unanswered: Vec<(GhostkeyId, BridgeId)> = self
            .auto_invoice
            .delegation_in_flight
            .iter()
            .filter(|(_, f)| {
                f.attempts >= DELEGATION_SEND_ATTEMPTS
                    && now_ms.saturating_sub(f.sent_ms) >= DELEGATION_RESEND_MS
            })
            .map(|(bridge, f)| (GhostkeyId(f.ghostkey), *bridge))
            .collect();
        for (ghostkey, bridge) in unanswered {
            self.auto_invoice.delegation_in_flight.remove(&bridge);
            let times = self
                .auto_invoice
                .delegation_unanswered
                .get(&(ghostkey, bridge))
                .map_or(1, |(n, _)| n.saturating_add(1));
            let wait = unanswered_wait(times);
            self.auto_invoice
                .delegation_unanswered
                .insert((ghostkey, bridge), (times, now_ms.saturating_add(wait)));
            self.auto_invoice
                .delegation_asked
                .remove(&(ghostkey, bridge));
        }
        if let Some(HarvestDelegateRequest::SetWatchDelegation { grant }) = &work.delegation.resend
        {
            if let Some(f) = self
                .auto_invoice
                .delegation_in_flight
                .get_mut(&grant.bridge)
            {
                f.sent_ms = now_ms;
                f.attempts = f.attempts.saturating_add(1);
            }
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
            if let Some(resend) = work.delegation.resend.clone() {
                crate::state::spawn_harvest_request(resend, "the watch delegation (again)");
            }
            if let Some(pending) = work.delegation.delegate.clone() {
                spawn_delegation_signature(pending);
            }
            for (contract_id, _, token) in work.vets.iter().cloned() {
                spawn_address_vet(contract_id, token);
            }
            if let Some(request_id) = work.raise_request {
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) =
                        crate::gateway::bitcoin_ops::derive_order_address(request_id).await
                    {
                        dioxus::logger::tracing::warn!(
                            "could not move the payment counter past used addresses: {e}"
                        );
                        use dioxus::prelude::WritableExt;
                        crate::gateway::APP_STATE
                            .write()
                            .abandon_raise_request(request_id);
                    }
                });
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

    /// The payment key the delegate reports is about to become `new`: when it
    /// is another key (or the first), peeks sent before now list the wrong
    /// key's addresses, so their answers are dropped and the window is read
    /// again.
    pub(crate) fn note_payment_key(&mut self, new: Option<&harvest_common::PaymentXpubStatus>) {
        let changed = match (self.bitcoin.payment_xpub.as_ref(), new) {
            (Some(old), Some(new)) => old.xpub != new.xpub,
            (None, Some(_)) => true,
            _ => false,
        };
        if changed {
            let floor = self.bitcoin.next_request_id + 1;
            self.auto_invoice.key_floor_peek = Some(floor);
            // Read the new key's window at once, not after the retry minute.
            self.auto_invoice.stale_from_peek = Some(floor);
            self.auto_invoice.upcoming_for = None;
            self.auto_invoice.paid_since_read = false;
        }
    }

    /// A `PeekOrderAddresses` went out under `request_id`.
    pub(crate) fn note_peek_sent(&mut self, request_id: u64) {
        self.auto_invoice.last_peek_id = Some(request_id);
    }

    /// The delegate's answer to the peek sent under `request_id`. One sent
    /// before a payment made the window stale can predate the sale that
    /// payment was for: dropped, and the next peek brings a window read after
    /// it. Matched by request id, so a later peek cannot vouch for it.
    pub(crate) fn on_upcoming_answer(
        &mut self,
        request_id: u64,
        result: Result<Vec<DerivedAddress>, String>,
        now_ms: u64,
    ) {
        // An id this tab never issued would hold every later answer out.
        if request_id > self.bitcoin.next_request_id
            || self
                .auto_invoice
                .stale_from_peek
                .is_some_and(|first| request_id < first)
            || self
                .auto_invoice
                .last_answered_peek
                .is_some_and(|newest| request_id < newest)
            || self
                .auto_invoice
                .key_floor_peek
                .is_some_and(|floor| request_id < floor)
        {
            return;
        }
        if result.is_ok() {
            self.auto_invoice.last_answered_peek = Some(request_id);
        }
        self.on_upcoming_addresses(result, now_ms);
    }

    /// The delegate's answer to `PeekOrderAddresses`, taken as current.
    pub(crate) fn on_upcoming_addresses(
        &mut self,
        result: Result<Vec<DerivedAddress>, String>,
        now_ms: u64,
    ) {
        match (result, self.bitcoin.payment_xpub.as_ref()) {
            (Ok(upcoming), Some(xpub)) => {
                self.auto_invoice.stale_from_peek = None;
                self.auto_invoice.upcoming_for = Some((xpub.xpub.clone(), now_ms));
                self.auto_invoice.paid_since_read = false;
                self.auto_invoice.upcoming = upcoming;
                self.prune_vets();
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
            // The state line alone: the alerts (oversold, capped) are said
            // separately, in "Needs you", whether or not the store is open.
            Some(Ok(status)) if status.paused.as_deref() == Some(NOT_VETTED_REASON) => {
                format!(
                    "{NOT_VETTED_LINE} {}",
                    self.rearm_progress(store_contract_id, now_ms)
                )
            }
            Some(Ok(status)) => instant_checkout_state_line(status, now_ms),
        })
    }

    /// What re-arming a store paused for a lapsed week still waits for,
    /// from what this tab holds: the delegate's next addresses and their
    /// reads, what an arm needs, and whether that arm has gone out. The
    /// delegate's answer to the arm replaces the paused status, so this is
    /// not asked once the store is re-armed and accepted.
    pub fn rearm_progress(&self, store_contract_id: &[u8], now_ms: u64) -> &'static str {
        let Some((_, window)) = self.vetted_window() else {
            return "Harvest is checking your next payment addresses before it can renew it.";
        };
        if window.is_empty() {
            return "Your next payment address has been paid before, so Harvest is moving past it \
                    first.";
        }
        let arm = self
            .instant_checkout_stores()
            .into_iter()
            .find(|(_, r)| r.store_contract_id == store_contract_id)
            .and_then(|(fingerprint, r)| self.auto_invoice_arm(&fingerprint, &r, now_ms));
        let Some((arm, _)) = arm else {
            return "Harvest is still connecting to the Bitcoin bridge before it can renew it.";
        };
        let sent = self
            .auto_invoice
            .sent
            .get(store_contract_id)
            .is_some_and(|(held, _, _)| held.vetted_scripts == arm.vetted_scripts);
        if sent {
            "Harvest has renewed it and is waiting for this device\u{2019}s Freenet to confirm."
        } else {
            "Harvest is about to renew it."
        }
    }

    /// Whether this device answers buyers' orders for one of our stores, for
    /// the seller's one status (`presence_flow::seller_status`). `None` for a
    /// store that is not selling here.
    pub fn instant_checkout_local(
        &self,
        store_contract_id: &[u8],
        now_ms: u64,
    ) -> Option<crate::presence_flow::LocalSelling> {
        use crate::presence_flow::LocalSelling;
        let notice = self.instant_checkout_notice(store_contract_id, now_ms)?;
        if !self.bitcoin.payment_xpub_loaded {
            // Not answered yet: nothing to say against the store.
            return Some(LocalSelling::Starting);
        }
        if self.bitcoin.payment_xpub.is_none() {
            return Some(LocalSelling::Blocked(notice));
        }
        Some(match self.auto_invoice.status.get(store_contract_id) {
            None => LocalSelling::Starting,
            Some(Err(_)) => LocalSelling::Blocked(notice),
            Some(Ok(status)) => {
                let hosted = status.last_background_run_ms.is_none()
                    && now_ms.saturating_sub(status.armed_at_ms) >= NO_BACKGROUND_RUN_AFTER_MS;
                if status.paused.is_some() {
                    LocalSelling::Blocked(notice)
                } else if hosted {
                    // Only a guess (a quiet half hour on a real node looks
                    // the same, round 2 of #190), so a warning, not closed.
                    LocalSelling::Unconfirmed(notice)
                } else if status.last_background_run_ms.is_none() {
                    LocalSelling::Starting
                } else {
                    LocalSelling::Ready {
                        delegated: status
                            .watch_delegation
                            .as_ref()
                            .is_some_and(|delegation| !delegation.stalled),
                    }
                }
            }
        })
    }

    /// [`instant_checkout_alerts`] for one of our stores; empty when it has
    /// no status yet.
    pub fn instant_checkout_alerts(&self, store_contract_id: &[u8]) -> Vec<String> {
        match self.auto_invoice.status.get(store_contract_id) {
            Some(Ok(status)) => instant_checkout_alerts(status),
            _ => Vec::new(),
        }
    }
}

/// Read an upcoming address's contract ([`AddressVet`]), and count it clear
/// if nothing answers in time.
#[cfg(target_arch = "wasm32")]
fn spawn_address_vet(contract_id: [u8; 32], token: u64) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::WritableExt;
        let id = freenet_stdlib::prelude::ContractInstanceId::new(contract_id);
        if let Err(e) = crate::gateway::get_contract(&id, false).await {
            dioxus::logger::tracing::warn!("could not ask about an upcoming payment address: {e}");
            crate::gateway::APP_STATE
                .write()
                .on_address_vet_unsent(&contract_id, token);
            return;
        }
        gloo_timers::future::TimeoutFuture::new(ADDRESS_VET_TIMEOUT_MS).await;
        let mut state = crate::gateway::APP_STATE.write();
        if state.on_address_vet_timeout(&contract_id, token, crate::state::now_ms()) {
            state.send_due_auto_invoice();
            state.send_due_watch_requests();
        }
    });
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

/// What the seller must know about orders even while the store is open:
/// paid orders the listing's count no longer covered (to refund or send by
/// hand), and a buyer turned away by a cap in the last hour. Empty for none.
pub fn instant_checkout_alerts(status: &AutoInvoiceStatus) -> Vec<String> {
    let mut alerts = Vec::new();
    if !status.oversold.is_empty() {
        let orders: Vec<String> = status.oversold.iter().map(|id| id.short()).collect();
        alerts.push(format!(
            "Paid when the listing's count no longer covered them (the item went to another \
             buyer, or you marked it sold out or took it down): {}. Refund or send these by \
             hand.",
            orders.join(", ")
        ));
    }
    if let Some(why) = &status.capped {
        alerts.push(format!(
            "In the last hour a buyer couldn't order because {why}; they were told to try again \
             later."
        ));
    }
    alerts
}

/// The harvest delegate's reason for a lapsed watch (`Refusal::WatchLapsed`
/// in `delegates/harvest-delegate/src/auto_invoice.rs`), exactly as it sends
/// it. The status carries only the text, so this is matched on; a delegate
/// that rewords it falls back to showing its words as they are.
pub(crate) const WATCH_LAPSED_REASON: &str =
    "the watch on its payment addresses would lapse before a buyer could pay; open Harvest to \
     renew it";

/// The harvest delegate's reason for a store paused because Harvest has not
/// been opened on this device for a week (`Refusal::NotVettedRecently` in
/// `delegates/harvest-delegate/src/auto_invoice.rs`, `VETTED_FOR_MS`),
/// exactly as it sends it. Matched like [`WATCH_LAPSED_REASON`].
pub(crate) const NOT_VETTED_REASON: &str =
    "paused: Harvest has not been opened on this device for 7 days; open Harvest to keep taking \
     orders";

/// What the store page says for [`NOT_VETTED_REASON`] on its own; the store
/// page adds what re-arming still waits for
/// (`AppState::rearm_progress`), and promises nothing about when orders
/// start again (review round 3 of batch 2).
pub(crate) const NOT_VETTED_LINE: &str = "Your store paused because Harvest hadn\u{2019}t been \
     opened on this device for 7 days. Open Harvest at least once a week to keep taking orders.";

/// This device's line about taking orders: the reason buyers can't buy,
/// said under the store's status while they can't (`presence_flow::
/// seller_status`). The alerts that stand whether or not the store is open
/// are [`instant_checkout_alerts`].
pub fn instant_checkout_state_line(status: &AutoInvoiceStatus, now_ms: u64) -> String {
    // A pause is certain and says what to do, so it comes before the guess
    // below (round 3 of #190).
    if let Some(why) = &status.paused {
        // The delegate's own words for a lapsed watch end "open Harvest to
        // renew it", said here to someone who has Harvest open (the
        // 2026-09-30 critique). This tab renews it (module doc), so say that.
        // Said to someone who has just opened Harvest: this tab re-arms at
        // once, which lifts the pause (review round 2 of batch 2).
        if why == NOT_VETTED_REASON {
            return NOT_VETTED_LINE.into();
        }
        if why == WATCH_LAPSED_REASON {
            return "Your store isn't taking orders right now: the watch on its payment \
                    addresses has lapsed. Harvest renews it while it\u{2019}s open here, and \
                    orders start again once it\u{2019}s renewed."
                .into();
        }
        return format!("Your store isn't taking orders right now: {why}.");
    }
    if status.last_background_run_ms.is_none()
        && now_ms.saturating_sub(status.armed_at_ms) >= NO_BACKGROUND_RUN_AFTER_MS
    {
        // A guess, and worded as one: a quiet half hour on a real node looks
        // the same as a hosted service (round 3 of #190).
        return "This device hasn\u{2019}t been seen running your store in the background yet. \
                If you use Harvest through a hosted service such as try.freenet.org, orders stop \
                when you close Harvest: run Harvest on your own Freenet node to stay open."
            .into();
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
