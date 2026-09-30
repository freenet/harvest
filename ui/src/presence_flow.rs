//! Whether a store is open, and keeping one's own store open (Ian,
//! 2026-09-26).
//!
//! A store is OPEN when its seller's node sent a heartbeat at most ten
//! minutes ago saying it can issue payment details; otherwise CLOSED, and
//! nothing in it can be bought. The heartbeats live in the store's own small
//! presence contract (`harvest_common::presence`), addressed by the store
//! key, so every reader derives where to look with no lookup.
//!
//! # Where heartbeats come from
//!
//! The seller's Harvest delegate signs them with the store key. On a node
//! that wakes delegates on a schedule (freenet-core#5747) it sends one every
//! five minutes with no tab open. On a node that does not (every release up
//! to v0.2.138), the seller's open tab asks the delegate for one every five
//! minutes instead, so a store is open while its seller has Harvest open and
//! closed within about ten minutes of their closing it. Which of the two this
//! node does is read from the delegate at run time
//! (`AutoInvoiceStatus::last_wakeup_ms`), never from a version number: the
//! tab stops asking once it sees recent wake-ups, and starts again if they
//! stop.
//!
//! # What a reader trusts
//!
//! Nothing a node served. A presence state is used only once its heartbeat
//! verifies against the store key the presence contract is addressed by, as
//! every other contract state this app reads (`index_flow`).

use std::collections::{HashMap, HashSet};

use harvest_common::presence::{
    presence_verdict, ClosedWhy, Presence, PresenceParameters, PresenceStateV1, SignedHeartbeat,
    HEARTBEAT_EVERY_MS, HEARTBEAT_MIN_GAP_MS, PRESENCE_FRESH_MS,
};

use crate::state::AppState;

/// How long after this tab starts following a store's presence it says
/// "checking" rather than "closed" while nothing has arrived. A node that
/// holds nothing at the address never answers with a state.
/// A GET for a contract this node has never seen can take tens of seconds,
/// and "closed" said before it answers is a false "the seller isn't online".
pub const PRESENCE_CHECKING_MS: u64 = 60 * 1000;

/// How soon this tab reads a store's presence again while it does not read
/// open. Presence arrives by subscription, and a GET that found nothing yet
/// (the seller's first heartbeat not out) or a subscription that died would
/// otherwise leave an open store reading closed for the whole session.
/// Doubled after each read that still leaves it not open, up to
/// [`PRESENCE_REFRESH_MAX_MS`], so a buyer who browsed many stores whose
/// sellers are away does not re-read all of them every two minutes.
pub const PRESENCE_REFRESH_MS: u64 = 2 * 60 * 1000;

/// The longest the re-read interval grows to.
pub const PRESENCE_REFRESH_MAX_MS: u64 = 32 * 60 * 1000;

/// The wait before the next read of a presence after `misses` reads that did
/// not find it open.
pub fn presence_refresh_after(misses: u32) -> u64 {
    (PRESENCE_REFRESH_MS << misses.min(4)).min(PRESENCE_REFRESH_MAX_MS)
}

/// How recent the delegate's last wake-up must be for the tab to leave the
/// heartbeats to the node: one period and a half minute. Once wake-ups stop,
/// the tab takes over while the last heartbeat sent is still fresh (see the
/// bound below), so the store does not read closed in the handover. A late
/// wake-up that brings the tab in early costs nothing: the delegate signs at
/// most one heartbeat per [`HEARTBEAT_MIN_GAP_MS`] whoever asks.
pub const WAKEUPS_FRESH_MS: u64 = HEARTBEAT_EVERY_MS + 30 * 1000;

/// How recent a wake-up has to be for the seller to be TOLD the store stays
/// open without Harvest open ([`AppState::wakeups_seen_recently`]).
pub const WAKEUPS_SEEN_MS: u64 = 3 * HEARTBEAT_EVERY_MS;

// The handover. The last heartbeat SENT may predate the last wake-up by up to
// the gap (that wake-up was held back by it); the tab takes over
// `WAKEUPS_FRESH_MS` after the wake-up, at its next minute tick. All of that
// must fall inside the heartbeat's freshness.
const _: () = assert!(HEARTBEAT_MIN_GAP_MS + WAKEUPS_FRESH_MS + 60 * 1000 < PRESENCE_FRESH_MS);

/// What this tab holds about stores' presence.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PresenceUi {
    /// Presence contract instance id -> (store key, when this tab started
    /// following it). Keyed by the presence contract, not the store: two
    /// generations of one store (one key) share it.
    pub following: HashMap<Vec<u8>, ([u8; 32], u64)>,
    /// When this tab last read each presence contract, and how many reads in
    /// a row have not found it open (see [`presence_refresh_after`]).
    pub reads: HashMap<Vec<u8>, (u64, u32)>,
    /// The latest verified presence state, per presence contract id.
    pub states: HashMap<Vec<u8>, PresenceStateV1>,
    /// When this tab last asked the delegate for a heartbeat, per store.
    pub heartbeat_asked_ms: HashMap<Vec<u8>, u64>,
    /// Our stores whose presence contract this tab has created (or merged
    /// into) this session.
    pub published: HashSet<Vec<u8>>,
    /// The delegate's last wake-up, by the node's clock, as it last said.
    pub last_wakeup_ms: Option<u64>,
}

/// A store's presence, as a buyer is shown it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorePresence {
    /// Nothing has arrived yet, and it is too soon to say closed.
    Checking,
    Open,
    Closed(ClosedWhy),
}

impl StorePresence {
    pub fn is_open(self) -> bool {
        self == StorePresence::Open
    }

    /// Sorted last, greyed, and not offered Buy now.
    pub fn is_closed(self) -> bool {
        matches!(self, StorePresence::Closed(_))
    }

    /// The line a buyer reads about a store that is not open, or `None`.
    pub fn buyer_line(self) -> Option<&'static str> {
        match self {
            StorePresence::Open => None,
            StorePresence::Checking => Some("Checking whether this store is open\u{2026}"),
            StorePresence::Closed(ClosedWhy::NotTakingOrders) => Some(
                "This store is closed: it isn\u{2019}t taking orders right now. You can look, \
                 but not buy.",
            ),
            StorePresence::Closed(_) => Some(
                "This store is closed: the seller\u{2019}s computer isn\u{2019}t online right \
                 now. You can look, but not buy. Try again later.",
            ),
        }
    }
}

/// The presence of a store from what the tab holds: `state` verified, and
/// `following_since_ms` when this tab started asking (`None`: not asked).
pub fn store_presence(
    state: Option<&PresenceStateV1>,
    following_since_ms: Option<u64>,
    now_ms: u64,
) -> StorePresence {
    if state.is_none()
        && following_since_ms
            .is_none_or(|since| now_ms.saturating_sub(since) < PRESENCE_CHECKING_MS)
    {
        return StorePresence::Checking;
    }
    match presence_verdict(state, now_ms) {
        Presence::Open => StorePresence::Open,
        Presence::Closed(why) => StorePresence::Closed(why),
    }
}

impl AppState {
    /// This store's presence, now.
    pub fn store_presence(&self, store_contract_id: &[u8], now_ms: u64) -> StorePresence {
        let presence = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.owner)
            .and_then(|key| crate::auto_invoice_flow::presence_instance_bytes(&key));
        self.presence_of(presence.as_ref().map(|p| p.as_slice()), now_ms)
    }

    fn presence_of(&self, presence: Option<&[u8]>, now_ms: u64) -> StorePresence {
        let since = presence
            .and_then(|p| self.presence.following.get(p))
            .map(|(_, since)| *since);
        let state = presence.and_then(|p| self.presence.states.get(p));
        store_presence(state, since, now_ms)
    }

    /// The presence contracts to GET (and subscribe to) now, each once:
    /// every loaded store's whose key is known and that this tab has not
    /// followed yet, and again each one that does not read open, spaced by
    /// [`presence_refresh_after`]. Changes nothing.
    pub fn presence_reads_due(&self, now_ms: u64) -> Vec<([u8; 32], [u8; 32])> {
        let keys: std::collections::BTreeSet<[u8; 32]> = self
            .browsing_stores
            .values()
            .filter_map(|s| s.owner)
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                let presence = crate::auto_invoice_flow::presence_instance_bytes(&key)?;
                let due = match self.presence.reads.get(presence.as_slice()) {
                    None => true,
                    Some((at, misses)) => {
                        now_ms.saturating_sub(*at) >= presence_refresh_after(*misses)
                            && !self.presence_of(Some(&presence), now_ms).is_open()
                    }
                };
                due.then_some((key, presence))
            })
            .collect()
    }

    /// [`Self::presence_reads_due`], recorded as read and followed. A read
    /// again is one more miss, until a state finds the store open.
    pub fn follow_due_presence(&mut self, now_ms: u64) -> Vec<[u8; 32]> {
        let due = self.presence_reads_due(now_ms);
        let mut out = Vec::with_capacity(due.len());
        for (key, presence) in due {
            self.presence
                .following
                .entry(presence.to_vec())
                .or_insert((key, now_ms));
            let misses = self
                .presence
                .reads
                .get(presence.as_slice())
                .map_or(0, |(_, misses)| misses.saturating_add(1));
            self.presence
                .reads
                .insert(presence.to_vec(), (now_ms, misses));
            out.push(presence);
        }
        out
    }

    /// If `contract_id` is a presence contract this tab follows, take its
    /// state and return `true`; otherwise `false`. Routed by id, like an
    /// index: a presence state is a small map a store decode could misread.
    pub(crate) fn on_presence_state(&mut self, contract_id: &[u8], state_bytes: &[u8]) -> bool {
        let Some((key, _)) = self.presence.following.get(contract_id).cloned() else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key) else {
            return true;
        };
        let state = match harvest_common::presence::decode_state(state_bytes) {
            Ok(state) => state,
            Err(e) => {
                dioxus::logger::tracing::warn!("a store's presence did not decode: {e}");
                return true;
            }
        };
        if let Err(e) = state.verify(&PresenceParameters::new(vk)) {
            dioxus::logger::tracing::warn!("a store's presence did not verify: {e}");
            return true;
        }
        self.keep_presence(contract_id, state);
        true
    }

    /// Keep `state` for the presence contract `presence` unless what is held
    /// is newer; one that reads open resets the re-read spacing.
    fn keep_presence(&mut self, presence: &[u8], state: PresenceStateV1) {
        let newer = |s: &PresenceStateV1| s.heartbeat.as_ref().map(|h| h.heartbeat.seq);
        let held = self.presence.states.get(presence).and_then(newer);
        if newer(&state) >= held {
            self.presence.states.insert(presence.to_vec(), state);
        }
        if self
            .presence_of(Some(presence), crate::state::now_ms())
            .is_open()
        {
            if let Some((_, misses)) = self.presence.reads.get_mut(presence) {
                *misses = 0;
            }
        }
    }

    /// Whether the delegate has woken on its own recently enough to say the
    /// store stays open with Harvest closed. For what the seller READS only:
    /// three heartbeat intervals, so one late wake-up does not flip the
    /// wording back and forth (the 2026-09-27 friction report saw it flip
    /// between two contradictory lines). What the tab DOES still follows
    /// [`Self::wakeups_live`], whose shorter window decides whether the tab
    /// sends heartbeats itself.
    pub fn wakeups_seen_recently(&self, now_ms: u64) -> bool {
        self.presence
            .last_wakeup_ms
            .is_some_and(|at| now_ms.saturating_sub(at) < WAKEUPS_SEEN_MS)
    }

    /// Whether this node wakes the delegate on its own, as far as the tab
    /// knows: a wake-up within [`WAKEUPS_FRESH_MS`].
    pub fn wakeups_live(&self, now_ms: u64) -> bool {
        self.presence
            .last_wakeup_ms
            .is_some_and(|at| now_ms.saturating_sub(at) < WAKEUPS_FRESH_MS)
    }

    /// Our stores that are due a heartbeat from this tab, and whether to
    /// force one (the first of a session, which the tab creates the presence
    /// contract with). Only stores the delegate has answered an arm for
    /// this session: it heartbeats armed stores only, and a heartbeat asked
    /// for before the arm is stored would be refused and not asked again for
    /// a whole interval. Changes nothing.
    pub fn heartbeats_due(&self, now_ms: u64) -> Vec<(Vec<u8>, bool)> {
        let wakeups = self.wakeups_live(now_ms);
        self.instant_checkout_stores()
            .into_iter()
            .map(|(_, registration)| registration.store_contract_id)
            .filter(|id| self.auto_invoice.sent.contains_key(id))
            .filter(|id| matches!(self.auto_invoice.status.get(id), Some(Ok(_))))
            .filter_map(|id| {
                let force = !self.presence.published.contains(&id);
                if !force && wakeups {
                    return None;
                }
                let due = self
                    .presence
                    .heartbeat_asked_ms
                    .get(&id)
                    .is_none_or(|at| now_ms.saturating_sub(*at) >= HEARTBEAT_EVERY_MS);
                due.then_some((id, force))
            })
            .collect()
    }

    /// [`Self::heartbeats_due`], noted as asked.
    pub fn queue_heartbeats(&mut self, now_ms: u64) -> Vec<(Vec<u8>, bool)> {
        let due = self.heartbeats_due(now_ms);
        for (id, _) in &due {
            self.presence.heartbeat_asked_ms.insert(id.clone(), now_ms);
        }
        due
    }

    /// The delegate's answer to a heartbeat request. Returns the heartbeat
    /// to create the store's presence contract with, when this tab has not
    /// yet this session.
    pub(crate) fn on_heartbeat_answer(
        &mut self,
        store_contract_id: Vec<u8>,
        result: Result<harvest_common::delegate::HeartbeatAnswer, String>,
    ) -> Option<(Vec<u8>, [u8; 32], SignedHeartbeat)> {
        let answer = match result {
            Ok(answer) => answer,
            Err(why) => {
                dioxus::logger::tracing::warn!("the delegate sent no heartbeat: {why}");
                return None;
            }
        };
        if answer.last_wakeup_ms.is_some() {
            self.presence.last_wakeup_ms = answer.last_wakeup_ms;
        }
        let heartbeat = answer.heartbeat?;
        let key = self.browsing_stores.get(&store_contract_id)?.owner?;
        let presence = crate::auto_invoice_flow::presence_instance_bytes(&key)?;
        // Our own store reads open from our own heartbeat at once, rather
        // than after the network's copy comes back.
        self.keep_presence(
            &presence,
            PresenceStateV1 {
                heartbeat: Some(heartbeat.clone()),
            },
        );
        if self.presence.published.insert(store_contract_id.clone()) {
            Some((store_contract_id, key, heartbeat))
        } else {
            None
        }
    }

    /// The PUT that creates a store's presence contract did not go out: the
    /// next heartbeat this tab asks for is forced, and creates it again.
    pub(crate) fn on_presence_publish_failed(&mut self, store_contract_id: &[u8]) {
        self.presence.published.remove(store_contract_id);
        self.presence.heartbeat_asked_ms.remove(store_contract_id);
    }

    /// A heartbeat the delegate may send with no tab open, as the status
    /// answer says: `last_wakeup_ms` rides on every arm's status too.
    pub(crate) fn note_wakeup_status(&mut self, last_wakeup_ms: Option<u64>) {
        if last_wakeup_ms.is_some() {
            self.presence.last_wakeup_ms = last_wakeup_ms;
        }
    }

    /// Send what is due: follow presence contracts, and ask the delegate
    /// for heartbeats.
    pub fn send_due_presence(&mut self) {
        let now_ms = crate::state::now_ms();
        let follow = self.follow_due_presence(now_ms);
        let heartbeats = self.queue_heartbeats(now_ms);
        #[cfg(target_arch = "wasm32")]
        {
            if !follow.is_empty() || !heartbeats.is_empty() {
                wasm_bindgen_futures::spawn_local(async move {
                    for id in follow {
                        if let Err(e) = crate::gateway::get_contract_by_id(&id).await {
                            dioxus::logger::tracing::warn!(
                                "could not follow a store's presence: {e}"
                            );
                        }
                    }
                    for (store, force) in heartbeats {
                        crate::state::spawn_harvest_request(
                            harvest_common::HarvestDelegateRequest::Heartbeat {
                                store_contract_id: store,
                                force,
                            },
                            "a heartbeat request",
                        );
                    }
                });
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (follow, heartbeats);
    }

    /// Whether [`Self::send_due_presence`] would send anything.
    pub fn presence_due(&self, now_ms: u64) -> bool {
        !self.presence_reads_due(now_ms).is_empty() || !self.heartbeats_due(now_ms).is_empty()
    }
}

/// Whether this device can answer buyers' orders for one of our stores, as
/// the seller's status needs it ([`AppState::instant_checkout_local`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSelling {
    /// It answers them. `delegated`: the delegate keeps its own payment
    /// watches going with no tab (harvest#179), so the store stays open with
    /// Harvest closed if the node also wakes it.
    Ready { delegated: bool },
    /// Just armed, not yet shown to run in the background here. Orders are
    /// answered while Harvest is open.
    Starting,
    /// Armed a while ago and never seen to run in the background: a hosted
    /// node such as try.freenet.org, where orders go unanswered once the tab
    /// closes, looks like this, and so does a quiet stretch on a real node.
    /// Said as a warning, not as closed.
    Unconfirmed(String),
    /// It cannot, and this is why (no payout wallet, paused, a hosted node
    /// where nothing runs while the seller is away, ...).
    Blocked(String),
}

/// The one status the seller reads about their own store (the friction
/// report found "Buyers see your store as open" above "Your store is
/// starting to take orders"). It says what happens to a buyer: open only
/// when buyers see the store open AND this device answers their orders, and
/// otherwise the one reason that matters (review of #190: a hosted node read
/// "Open" while no order would ever be answered).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SellerStatus {
    /// "Open", "Closed", "Checking" or "Not taking orders".
    pub pill: &'static str,
    pub open: bool,
    /// The line itself.
    pub line: String,
    /// The reason buyers can't buy, when there is one to give.
    pub why_not: Option<String>,
}

/// See [`SellerStatus`]. `wakeups`: the node has been waking the delegate on
/// its own ([`AppState::wakeups_seen_recently`]).
pub fn seller_status(presence: StorePresence, wakeups: bool, local: &LocalSelling) -> SellerStatus {
    let blocked = match local {
        LocalSelling::Blocked(why) => Some(why.clone()),
        _ => None,
    };
    let caution = match local {
        LocalSelling::Unconfirmed(why) => Some(why.clone()),
        _ => None,
    };
    match presence {
        StorePresence::Open => match blocked {
            Some(why) => SellerStatus {
                pill: "Not taking orders",
                open: false,
                line: "Buyers see your store as open, but this device can\u{2019}t answer their \
                       orders."
                    .to_string(),
                why_not: Some(why),
            },
            None => SellerStatus {
                pill: "Open",
                open: true,
                // "With Harvest open or not" only when both halves hold: the
                // node wakes the delegate, and the delegate keeps its own
                // watches (otherwise the watches lapse with the tab closed).
                line: if wakeups && matches!(local, LocalSelling::Ready { delegated: true }) {
                    "Buyers can buy now. Your store stays open while this computer is on and \
                     Freenet is running, with Harvest open or not."
                        .to_string()
                } else {
                    "Buyers can buy now. Your store stays open while Harvest is open here."
                        .to_string()
                },
                // Starting: nothing to add (the line already says "while
                // Harvest is open here"). Unconfirmed: the warning.
                why_not: caution,
            },
        },
        StorePresence::Checking => SellerStatus {
            pill: "Checking",
            open: false,
            line: "Checking whether buyers can reach your store\u{2026}".to_string(),
            why_not: None,
        },
        StorePresence::Closed(why_closed) => {
            let line = if why_closed == ClosedWhy::NotTakingOrders || blocked.is_some() {
                "Buyers can\u{2019}t buy from your store right now."
            } else {
                "Buyers can\u{2019}t reach your store right now."
            };
            // This device's own reason when it has one; otherwise why buyers
            // see it closed. Never this device's "taking orders" line under
            // a closed pill (codex and review round 1 of #190).
            // A clock ahead of the buyers' is why they see it closed,
            // whatever else is true here, so it wins.
            let why_not = (why_closed != ClosedWhy::FromTheFuture)
                .then_some(())
                .and(blocked.or(caution))
                .or_else(|| {
                    Some(
                    match why_closed {
                        ClosedWhy::FromTheFuture => {
                            "This computer\u{2019}s clock is ahead of the buyers\u{2019}. Check \
                             that its date and time are set correctly."
                        }
                        ClosedWhy::NotTakingOrders => {
                            "Your store told buyers it can\u{2019}t take orders yet. This \
                             usually clears within a few minutes."
                        }
                        ClosedWhy::NoHeartbeat | ClosedWhy::Stale { .. } => {
                            "Your store\u{2019}s signal isn\u{2019}t reaching buyers. It is sent \
                             while Freenet runs here, or, on a Freenet that can\u{2019}t run \
                             Harvest in the background, only while Harvest is open."
                        }
                    }
                    .to_string(),
                )
                });
            SellerStatus {
                pill: "Closed",
                open: false,
                line: line.to_string(),
                why_not,
            }
        }
    }
}

/// The age past which a heartbeat no longer opens a store, for display.
pub const FRESH_MINUTES: u64 = PRESENCE_FRESH_MS / 60_000;

#[cfg(test)]
mod tests {
    use super::*;
    use harvest_common::presence::Heartbeat;

    fn signed(at_ms: u64, taking: bool) -> SignedHeartbeat {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
        SignedHeartbeat::sign(&sk, Heartbeat::new(at_ms, at_ms, taking)).unwrap()
    }

    const NOW: u64 = 1_800_000_000_000;

    /// Checking only briefly, then the heartbeat decides. Mutated red by
    /// dropping the checking window, and by never leaving it.
    #[test]
    fn a_store_is_checking_then_open_or_closed() {
        assert_eq!(store_presence(None, None, NOW), StorePresence::Checking);
        assert_eq!(
            store_presence(None, Some(NOW - 1_000), NOW),
            StorePresence::Checking
        );
        assert_eq!(
            store_presence(None, Some(NOW - PRESENCE_CHECKING_MS), NOW),
            StorePresence::Closed(ClosedWhy::NoHeartbeat)
        );
        let fresh = PresenceStateV1 {
            heartbeat: Some(signed(NOW - 60_000, true)),
        };
        assert_eq!(
            store_presence(Some(&fresh), Some(NOW), NOW),
            StorePresence::Open
        );
        let stale = PresenceStateV1 {
            heartbeat: Some(signed(NOW - PRESENCE_FRESH_MS - 1, true)),
        };
        assert!(store_presence(Some(&stale), Some(NOW), NOW).is_closed());
        let not_taking = PresenceStateV1 {
            heartbeat: Some(signed(NOW, false)),
        };
        assert_eq!(
            store_presence(Some(&not_taking), Some(NOW), NOW),
            StorePresence::Closed(ClosedWhy::NotTakingOrders)
        );
    }

    /// ONE status, saying what happens to a buyer. Open only when buyers
    /// see it open and this device answers orders; a blocked device says so
    /// even while buyers see it open (a hosted node, review of #190); a
    /// closed store never carries the device's "taking orders" line; "with
    /// Harvest open or not" only with wake-ups AND delegated watches. Red if
    /// a blocked device reads Open, if the closed reason is dropped, or if
    /// the "open or not" wording ignores the delegation.
    #[test]
    fn the_seller_reads_one_status_driven_by_what_buyers_see() {
        let ready = LocalSelling::Ready { delegated: true };
        let open = seller_status(StorePresence::Open, true, &ready);
        assert_eq!((open.pill, open.open), ("Open", true));
        assert!(
            open.line.contains("with Harvest open or not"),
            "{}",
            open.line
        );
        assert_eq!(open.why_not, None);
        let undelegated = seller_status(
            StorePresence::Open,
            true,
            &LocalSelling::Ready { delegated: false },
        );
        assert!(
            undelegated.line.contains("while Harvest is open here"),
            "{}",
            undelegated.line
        );
        let tab = seller_status(StorePresence::Open, false, &ready);
        assert!(
            tab.line.contains("while Harvest is open here"),
            "{}",
            tab.line
        );

        let hosted = LocalSelling::Blocked("nothing runs here while you are away".into());
        let false_open = seller_status(StorePresence::Open, true, &hosted);
        assert!(!false_open.open);
        assert_eq!(false_open.pill, "Not taking orders");
        assert_eq!(
            false_open.why_not.as_deref(),
            Some("nothing runs here while you are away")
        );

        let closed = seller_status(
            StorePresence::Closed(ClosedWhy::NotTakingOrders),
            true,
            &hosted,
        );
        assert_eq!((closed.pill, closed.open), ("Closed", false));
        assert_eq!(
            closed.why_not.as_deref(),
            Some("nothing runs here while you are away")
        );
        let offline = seller_status(StorePresence::Closed(ClosedWhy::NoHeartbeat), true, &ready);
        assert!(
            offline.line.contains("can\u{2019}t reach"),
            "{}",
            offline.line
        );
        let reason = offline.why_not.expect("a closed store says why");
        assert!(reason.contains("signal"), "{reason}");
        assert!(!reason.contains("taking orders"), "{reason}");
        let clock = seller_status(
            StorePresence::Closed(ClosedWhy::FromTheFuture),
            true,
            &ready,
        );
        assert!(clock.why_not.unwrap().contains("clock"));
        // A guess that the node never runs in the background: a warning
        // under the Open pill, not closed (round 2 of #190).
        let guess = LocalSelling::Unconfirmed("maybe a hosted node".into());
        let warned = seller_status(StorePresence::Open, false, &guess);
        assert_eq!((warned.pill, warned.open), ("Open", true));
        assert_eq!(warned.why_not.as_deref(), Some("maybe a hosted node"));
        // A clock ahead of the buyers' wins over the device's reason.
        let clock_blocked = seller_status(
            StorePresence::Closed(ClosedWhy::FromTheFuture),
            true,
            &hosted,
        );
        assert!(clock_blocked.why_not.unwrap().contains("clock"));
        let checking = seller_status(StorePresence::Checking, false, &hosted);
        assert_eq!(checking.pill, "Checking");
        assert_eq!(checking.why_not, None);
    }

    #[test]
    fn a_buyer_is_told_why_a_store_is_not_open() {
        assert_eq!(StorePresence::Open.buyer_line(), None);
        assert!(StorePresence::Closed(ClosedWhy::NoHeartbeat)
            .buyer_line()
            .unwrap()
            .contains("isn\u{2019}t online"));
        assert!(StorePresence::Closed(ClosedWhy::NotTakingOrders)
            .buyer_line()
            .unwrap()
            .contains("isn\u{2019}t taking orders"));
    }
}
