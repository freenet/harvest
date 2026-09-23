//! Asking a bridge to watch an order's payment address (#59).
//!
//! A bridge scans only the scripts it has been asked to watch, and it takes
//! those requests through its request inbox: a contract to which a sender
//! appends an entry signed by a Ghost Key and sealed so that only the bridge
//! can read it. Until an order's address is on that list, a payment to it is
//! never seen and the order never reaches `Paid`.
//!
//! This module builds the entries and does no I/O, so what it builds is tested
//! against the real inbox contract and the real bridge key rather than against
//! a stand-in for either.
//!
//! # Dating an entry
//!
//! Every entry carries a Bitcoin mainnet height, and the inbox admits one only
//! within `WINDOW_BLOCKS` above the floor the bridge last signed. A sender
//! dates against that floor, with [`sender_height`], and NOT against the chain
//! tip: the floor trails the tip, so a tip-dated entry lands above the window
//! and the contract drops it without any error. Harvest#59 as first written
//! said to date by the tip. That predates the inbox, and followed literally it
//! would have sent every request somewhere nothing reads.
//!
//! # Locating the inbox
//!
//! Nothing here names the inbox's code hash. It comes from the bridge's
//! generation pointer at runtime, because a hash written into this build goes
//! stale on the bridge's next deploy and then names a contract the bridge no
//! longer reads. That is exactly what happened to the address contract's
//! (#30).

use freenet_bitcoin_common::{to_cbor, BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::{
    sender_height, Action, ByteBuf, EntryKey, GhostkeyId, InboxDelta, InboxEntryBody,
    InboxParameters, InboxRequest, InboxStateV1, SignedFloor, WireEntry, MAX_ENTRIES_PER_GHOSTKEY,
    MAX_SCRIPTS_PER_REQUEST,
};
use freenet_stdlib::prelude::{CodeHash, ContractKey, Parameters};

/// `bridge`'s production inbox parameters, encoded as the bridge encodes them.
///
/// Deliberately the bridge's own encoder and not Harvest's: the contract id is
/// a hash over these bytes, so two encoders that merely agree on the value
/// would still address two different contracts if their bytes ever differed.
pub fn inbox_params_bytes(bridge: BridgeId) -> Result<Vec<u8>, String> {
    to_cbor(&InboxParameters::production(bridge))
}

/// The key of `bridge`'s inbox, given the inbox code hash its generation
/// pointer names.
pub fn inbox_contract_key(bridge: BridgeId, code_hash: CodeHash) -> Result<ContractKey, String> {
    let params = Parameters::from(inbox_params_bytes(bridge)?);
    Ok(ContractKey::from_id_and_code(
        crate::migrate::current_id(&code_hash, &params),
        code_hash,
    ))
}

/// The timestamp for a sender's next request.
///
/// A bridge applies one sender's requests about a script in the order they
/// were made, and ignores one that is not strictly later than the last, a
/// renewal included. So this is the clock, unless the clock has not yet moved
/// past the last request sent, in which case it is one millisecond after it.
pub fn next_made_at_ms(now_ms: u64, last_sent_ms: Option<u64>) -> u64 {
    match last_sent_ms {
        Some(last) if last >= now_ms => last + 1,
        _ => now_ms,
    }
}

/// Watch requests for `scripts` on `network`.
///
/// A script named twice is asked for once. The scripts are split so no request
/// names more than the inbox allows, and each request is dated one millisecond
/// after the one before it, starting at `made_at_ms`, so they stay strictly
/// ordered for the bridge.
pub fn watch_requests(
    network: BitcoinNetwork,
    scripts: &[Vec<u8>],
    made_at_ms: u64,
    scan_from_height: Option<u32>,
) -> Vec<InboxRequest> {
    let mut unique: Vec<&Vec<u8>> = Vec::new();
    for s in scripts {
        if !unique.contains(&s) {
            unique.push(s);
        }
    }
    unique
        .chunks(MAX_SCRIPTS_PER_REQUEST)
        .enumerate()
        .map(|(i, batch)| InboxRequest {
            action: Action::Watch,
            network,
            scripts: batch.iter().map(|s| ByteBuf((*s).clone())).collect(),
            scan_from_height,
            made_at_ms: made_at_ms + i as u64,
        })
        .collect()
}

/// An entry laid out for the Ghost Key to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedEntry {
    /// The mainnet height the entry is dated at.
    pub mainnet_height: u32,
    /// The exact bytes to ask the ghostkey delegate to sign.
    pub signing_payload: Vec<u8>,
}

/// Seal `request` to `bridge` and lay out the entry that carries it, dated
/// against the inbox's current `floor`.
///
/// The seal is bound both to the Ghost Key that will sign the entry and to the
/// height it is dated at, so both are fixed here, before anything is signed:
/// an entry signed by another key or re-dated afterwards does not open.
pub fn prepare_entry(
    bridge: BridgeId,
    ghostkey: GhostkeyId,
    floor: &SignedFloor,
    request: &InboxRequest,
) -> Result<PreparedEntry, String> {
    let mainnet_height = sender_height(floor.height);
    let sealed = freenet_bitcoin_inbox::seal::seal(&bridge, &ghostkey, mainnet_height, request)?;
    let body = InboxEntryBody {
        bridge,
        mainnet_height,
        sealed,
    };
    Ok(PreparedEntry {
        mainnet_height,
        signing_payload: body.signing_payload()?,
    })
}

/// The contract update that appends a signed entry to the inbox.
///
/// It carries the floor the entry was dated against, since the inbox admits an
/// entry only alongside a floor it can check the date against.
pub fn submission_bytes(floor: &SignedFloor, entry: WireEntry) -> Result<Vec<u8>, String> {
    to_cbor(&InboxDelta::submission(Some(floor.clone()), entry))
}

/// How long after a watch request is sent before it is renewed. A bridge lets
/// a watch lapse about a day after the request that last asked for it, so this
/// renews with half a day to spare.
pub const RENEW_AFTER_MS: u64 = 12 * 60 * 60 * 1000;

/// How long a just-sent request is given to land in the inbox before its
/// absence is read as its having been dropped.
pub const LAND_GRACE_MS: u64 = 2 * 60 * 1000;

/// What this tab has sent the bridge about one script, and what it has seen
/// happen to that request since.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentWatch {
    /// When it was sent, by this tab's clock.
    pub sent_at_ms: u64,
    /// The entry that carried it and the height it was dated at, which is what
    /// its fate in the inbox is read back by.
    pub entry_key: EntryKey,
    pub mainnet_height: u32,
    /// The Ghost Key that sent it, whose allowance of unread entries it uses.
    pub ghostkey: GhostkeyId,
    /// Whether this tab has seen the bridge remove the entry, which it does
    /// when it reads it.
    ///
    /// Remembered because the evidence does not last. About half an hour after
    /// the bridge reads an entry, the inbox floor passes its height, and the
    /// entry and the record of its removal are both pruned. From then on a
    /// request the bridge read looks exactly like one that was dropped unread,
    /// and without this every order would be re-requested every half hour.
    pub read: bool,
    /// Since when this script has been asked for without the bridge being seen
    /// to read it: the first of a run of requests that each went unread. See
    /// [`InboxTracker::request_long_unread`].
    pub unread_since_ms: u64,
}

impl SentWatch {
    /// A request just sent in `entry`.
    pub fn sent(entry: &WireEntry, now_ms: u64) -> Self {
        SentWatch {
            sent_at_ms: now_ms,
            entry_key: entry.entry.key(),
            mainnet_height: entry.entry.mainnet_height,
            ghostkey: entry.entry.ghostkey,
            read: false,
            unread_since_ms: now_ms,
        }
    }

    /// Record it if `inbox` shows the bridge has read this request.
    pub fn observe(&mut self, inbox: &InboxStateV1) {
        if inbox.is_removed(&self.entry_key, self.mainnet_height) {
            self.read = true;
        }
    }
}

/// Whether a watch request for a script should be sent now, given what this
/// tab last sent about it (`None` if nothing), the inbox as the node serves it,
/// and when that state arrived.
///
/// Due when it was never sent, when the last request is old enough to renew,
/// or when the last request left the inbox without the bridge having read it.
/// Not due while a request is still waiting in the inbox, once the bridge is
/// seen to have read it, or while a just-sent request may still be landing.
///
/// "Still landing" is judged by the state, not the clock: a request is taken
/// to have left unread only when a state that arrived [`LAND_GRACE_MS`] or more
/// after it was sent does not hold it. Judged by the clock, a quiet inbox whose
/// state has not changed since before the send would read every new request
/// as dropped, and it would be sent again into the Ghost Key's second place.
pub fn watch_due(
    sent: Option<&SentWatch>,
    inbox: &InboxStateV1,
    state_received_ms: u64,
    now_ms: u64,
) -> bool {
    let Some(sent) = sent else {
        return true;
    };
    let age = now_ms.saturating_sub(sent.sent_at_ms);
    if age >= RENEW_AFTER_MS {
        return true;
    }
    if sent.read || inbox.is_removed(&sent.entry_key, sent.mainnet_height) {
        return false;
    }
    if state_received_ms < sent.sent_at_ms.saturating_add(LAND_GRACE_MS) {
        return false;
    }
    !inbox.entries.contains_key(&sent.entry_key)
}

/// A script a seller wants the bridge to watch, because an unpaid order of
/// theirs pays to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchWanted {
    pub network: BitcoinNetwork,
    pub script: Vec<u8>,
    /// The height the order was anchored at (for a script several orders pay
    /// to, the earliest of their anchors: see `AppState::watches_wanted`). No
    /// payment to a freshly derived address can predate it, so it is sent as
    /// the height the bridge may start scanning from.
    ///
    /// Only a hint. The bridge this was written against ignores it and starts a
    /// new watch at its next scan (freenet-bitcoin#7), so a payment mined
    /// before the bridge reads the request is not found.
    pub anchor_height: Option<u32>,
}

/// A request prepared and handed to the ghostkey delegate, waiting on its
/// signature before it can be submitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInboxEntry {
    pub fingerprint: String,
    pub ghostkey: GhostkeyId,
    /// The inbox it goes to, fixed when it was prepared: the entry is sealed
    /// to that inbox's bridge and dated against its floor.
    pub contract_key: ContractKey,
    /// The floor it was dated against, sent with it so a peer whose floor lags
    /// takes the floor first (see [`InboxDelta::submission`]).
    pub floor: SignedFloor,
    pub network: BitcoinNetwork,
    pub scripts: Vec<Vec<u8>>,
    /// What the delegate is asked to sign, and so what its answer is matched by.
    pub signing_payload: Vec<u8>,
    /// When it was queued, so a signature that never comes back does not hold
    /// one of the Ghost Key's places for ever. See [`SIGNATURE_TIMEOUT_MS`].
    pub queued_at_ms: u64,
}

/// How long a request may wait on the delegate's signature before it is given
/// up. Longer than a person takes to answer a prompt. A signature with a grant
/// in place comes back at once, so a wait this long means the vault is showing
/// a prompt or the answer was lost, and the key is not asked again this session
/// (see `AppState::stop_watch_requests_for`).
pub const SIGNATURE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// How old the inbox state may be and still be planned against. The floor
/// advances about once a mainnet block, and an entry dated against a floor
/// three blocks behind is dropped on arrival, so a state not heard from in this
/// long may be one the entry would be dropped against.
pub const INBOX_STATE_FRESH_MS: u64 = 15 * 60 * 1000;

/// How often the inbox is fetched again even with its subscription apparently
/// live. A subscription can end without a word, and a fetch re-subscribes.
pub const INBOX_REFETCH_MS: u64 = 10 * 60 * 1000;

/// How soon a fetch that brought nothing back may be tried again, doubled on
/// each further fetch without a state up to [`INBOX_REFETCH_MS`].
pub const INBOX_FETCH_RETRY_MS: u64 = 60 * 1000;

/// How long a Ghost Key's requests may go unread before the seller is told
/// something is wrong.
///
/// Unread in either of two ways, and both count: a request of this tab's that
/// was sent, went unread, was passed by the floor and sent again, over and
/// over; or any entry of the key's, whoever sent it, sitting in this node's
/// copy of the inbox. The first is a request that never reaches the bridge's
/// node, or that the bridge will not read; the second is a node serving a copy
/// it has stopped following, or a bridge that is not running. In a working
/// system an entry is read within a minute, so two hours is well past the
/// bridge's legitimate deferrals (a sender past its share of a read budget, a
/// few blocks before the floor passes an entry).
///
/// Nothing is done about it but telling the seller. Resending sooner cannot
/// help any of these, and against a stale copy it could only fill the key's
/// places with its own earlier entries.
/// A run of this tab's own requests counts only for scripts still wanted, so an
/// order paid or expired mid-fault does not leave a run that never ends. An
/// entry sitting in the inbox counts whatever it asked for: see
/// [`InboxTracker::request_long_unread`]. After this tab has not looked for longer
/// than [`CHECK_GAP_MS`] (a laptop asleep), every clock restarts: what could not
/// be observed meanwhile is not evidence of anything.
pub const UNREAD_NOTICE_MS: u64 = 2 * 60 * 60 * 1000;

/// A gap between checks this long means the tab was not running (asleep,
/// suspended) rather than that nothing was due: checks come about once a
/// minute while anything is wanted.
pub const CHECK_GAP_MS: u64 = 5 * 60 * 1000;

/// How long the seller's own signing may hold watch requests back.
///
/// Watch requests wait while the seller signs something, because most of the
/// delegate's refusals name no request. But some of the seller's pending
/// states have no expiry, and one that never clears would otherwise stop every
/// watch for the session without a word. The hold is continuous: it restarts
/// whenever a check finds nothing of the seller's under way.
pub const MAX_HOLD_FOR_USER_MS: u64 = 10 * 60 * 1000;

/// One bridge inbox as this tab sees it, and what this tab has sent to it.
///
/// In memory only. After a reload nothing is remembered, so every wanted
/// script is sent once more: a renewal early, which costs the bridge one read
/// and the seller nothing. The same happens if this tab misses every state in
/// which the bridge's removal of an entry was visible, even while connected:
/// the read is not seen, and the request is sent again after its grace.
///
/// Two limits of what this tab can see, both residual:
///
/// * A removal means the bridge READ the request, not that it acted on it. It
///   removes a request past its per-sender limit of watched scripts, or for a
///   network it does not observe, the same way. Such a request is not sent
///   again until its renewal.
/// * The bridge applies only a request whose `made_at_ms` is newer than the
///   last it applied from this Ghost Key, and `made_at_ms` is this tab's
///   clock. A reload after the clock stepped back by more than the renewal
///   interval, or a second device with a clock running ahead, makes renewals
///   the bridge ignores, and the watch lapses unannounced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxTracker {
    pub bridge: BridgeId,
    pub contract_key: ContractKey,
    /// The inbox's latest state, once the node has served it.
    pub state: Option<InboxStateV1>,
    /// Keyed by network and script: one address on two networks is two watches.
    pub sent: std::collections::HashMap<(BitcoinNetwork, Vec<u8>), SentWatch>,
    last_made_at_ms: Option<u64>,
    /// When `state` last arrived.
    state_received_ms: Option<u64>,
    /// When the inbox was last asked for, and how many times since a state
    /// last arrived.
    last_fetch_ms: Option<u64>,
    fetches_without_state: u32,
    /// Since when the seller's own signing has been holding requests back.
    pub held_since_ms: Option<u64>,
    /// When each entry now in the inbox was first seen here, and whose it is.
    first_seen: std::collections::BTreeMap<EntryKey, (GhostkeyId, u64)>,
    /// Whether the seller has been told requests are going unread, so they are
    /// told once for as long as it lasts.
    pub unread_notified: bool,
    /// When the watch-request loop last looked.
    last_check_ms: Option<u64>,
}

impl InboxTracker {
    pub fn new(bridge: BridgeId, contract_key: ContractKey) -> Self {
        InboxTracker {
            bridge,
            contract_key,
            state: None,
            sent: Default::default(),
            last_made_at_ms: None,
            state_received_ms: None,
            last_fetch_ms: None,
            fetches_without_state: 0,
            held_since_ms: None,
            first_seen: Default::default(),
            unread_notified: false,
            last_check_ms: None,
        }
    }

    /// Take a newly served state, noting any request it shows the bridge read.
    pub fn on_state(&mut self, state: InboxStateV1, now_ms: u64) {
        for sent in self.sent.values_mut() {
            sent.observe(&state);
        }
        self.fetches_without_state = 0;
        self.first_seen
            .retain(|key, _| state.entries.contains_key(key));
        for (key, entry) in &state.entries {
            self.first_seen
                .entry(*key)
                .or_insert((entry.ghostkey, now_ms));
        }
        self.state = Some(state);
        self.state_received_ms = Some(now_ms);
    }

    /// Note that the watch-request loop is looking now. After a gap longer than
    /// [`CHECK_GAP_MS`] every unread clock restarts, since reads that happened
    /// while the tab was not running may have left no trace by now.
    pub fn note_check(&mut self, now_ms: u64) {
        if self
            .last_check_ms
            .is_some_and(|at| now_ms.saturating_sub(at) > CHECK_GAP_MS)
        {
            for sent in self.sent.values_mut().filter(|s| !s.read) {
                sent.unread_since_ms = now_ms;
            }
            for (_, seen) in self.first_seen.values_mut() {
                *seen = now_ms;
            }
        }
        self.last_check_ms = Some(now_ms);
    }

    /// Whether any of `ghostkeys`' requests has gone unread past
    /// [`UNREAD_NOTICE_MS`], in either of the ways described there.
    ///
    /// A run of this tab's requests counts only for a script in `wanted`. An
    /// entry sitting in the inbox counts whatever it asked for: its scripts are
    /// sealed to the bridge, and one unread for that long means the inbox is not
    /// being read, which matters to every script the key still wants.
    pub fn request_long_unread(
        &self,
        ghostkeys: &[GhostkeyId],
        wanted: &std::collections::HashSet<(BitcoinNetwork, Vec<u8>)>,
        now_ms: u64,
    ) -> bool {
        let old = |since: u64| now_ms.saturating_sub(since) >= UNREAD_NOTICE_MS;
        self.sent.iter().any(|(key, s)| {
            !s.read
                && ghostkeys.contains(&s.ghostkey)
                && wanted.contains(key)
                && old(s.unread_since_ms)
        }) || self
            .first_seen
            .values()
            .any(|(ghostkey, seen)| ghostkeys.contains(ghostkey) && old(*seen))
    }

    /// Whether to fetch the inbox now: never served, or not heard from in
    /// [`INBOX_REFETCH_MS`], and not already asked within
    /// [`INBOX_FETCH_RETRY_MS`]. A fetch that fails, or a node that has not
    /// found the inbox yet, is simply asked again.
    ///
    /// Fetches that bring nothing back are spaced further apart each time, up
    /// to [`INBOX_REFETCH_MS`], so an inbox the network cannot find yet is not
    /// asked for every minute.
    pub fn fetch_due(&self, now_ms: u64) -> bool {
        let unheard = self
            .state_received_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= INBOX_REFETCH_MS);
        let spacing = INBOX_FETCH_RETRY_MS
            .saturating_mul(1u64 << self.fetches_without_state.min(8))
            .min(INBOX_REFETCH_MS);
        let asked_recently = self
            .last_fetch_ms
            .is_some_and(|at| now_ms.saturating_sub(at) < spacing);
        unheard && !asked_recently
    }

    pub fn note_fetch(&mut self, now_ms: u64) {
        if self
            .last_fetch_ms
            .is_some_and(|at| self.state_received_ms.is_none_or(|got| got < at))
        {
            self.fetches_without_state = self.fetches_without_state.saturating_add(1);
        }
        self.last_fetch_ms = Some(now_ms);
    }

    /// The requests `ghostkey` should send now for `wanted`, most urgent first.
    ///
    /// `wanted` is taken in the caller's order, so a caller puts the newest
    /// orders first: when the allowance is short those are the ones a buyer is
    /// most likely paying now. `awaiting` is what this Ghost Key already has
    /// waiting on the delegate, which is neither due again nor free to use the
    /// allowance.
    ///
    /// Empty until the inbox has been served with a floor, and again whenever
    /// the served state is older than [`INBOX_STATE_FRESH_MS`]: an entry is
    /// dated against the floor, and one dated against a floor that has moved on
    /// is dropped at once.
    pub fn plan(
        &mut self,
        ghostkey: GhostkeyId,
        wanted: &[WatchWanted],
        awaiting: &[&PendingInboxEntry],
        now_ms: u64,
    ) -> Vec<InboxRequest> {
        let Some(received_ms) = self
            .state_received_ms
            .filter(|at| now_ms.saturating_sub(*at) < INBOX_STATE_FRESH_MS)
        else {
            return Vec::new();
        };
        let Some(state) = self.state.as_ref() else {
            return Vec::new();
        };
        if state.floor.is_none() {
            return Vec::new();
        }

        // A Ghost Key's third unread entry is dropped on arrival, so count
        // what already holds its places: unread entries in the inbox, entries
        // sent but not yet seen landing, and entries not yet signed.
        let in_inbox: std::collections::BTreeSet<EntryKey> = state
            .entries
            .iter()
            .filter(|(_, e)| e.ghostkey == ghostkey)
            .map(|(k, _)| *k)
            .collect();
        let landing: std::collections::BTreeSet<EntryKey> = self
            .sent
            .values()
            .filter(|s| {
                s.ghostkey == ghostkey
                    && !s.read
                    && received_ms < s.sent_at_ms.saturating_add(LAND_GRACE_MS)
                    && !in_inbox.contains(&s.entry_key)
                    && !state.is_removed(&s.entry_key, s.mainnet_height)
            })
            .map(|s| s.entry_key)
            .collect();
        let held = in_inbox.len() + landing.len() + awaiting.len();
        let slots = MAX_ENTRIES_PER_GHOSTKEY.saturating_sub(held);
        if slots == 0 {
            return Vec::new();
        }

        let mut due: Vec<&WatchWanted> = Vec::new();
        for w in wanted {
            let key = (w.network, w.script.clone());
            let signing = awaiting
                .iter()
                .any(|p| p.network == w.network && p.scripts.contains(&w.script));
            let repeated = due
                .iter()
                .any(|d| d.network == w.network && d.script == w.script);
            if !signing && !repeated && watch_due(self.sent.get(&key), state, received_ms, now_ms) {
                due.push(w);
            }
        }

        // One request per network, up to a request's worth of scripts each,
        // networks in the order their first script was wanted.
        let mut networks: Vec<BitcoinNetwork> = Vec::new();
        for w in &due {
            if !networks.contains(&w.network) {
                networks.push(w.network);
            }
        }
        let mut requests = Vec::new();
        for network in networks {
            let scripts: Vec<&WatchWanted> = due
                .iter()
                .copied()
                .filter(|w| w.network == network)
                .collect();
            for batch in scripts.chunks(MAX_SCRIPTS_PER_REQUEST) {
                if requests.len() == slots {
                    return requests;
                }
                let made_at_ms = next_made_at_ms(now_ms, self.last_made_at_ms);
                self.last_made_at_ms = Some(made_at_ms);
                requests.push(InboxRequest {
                    action: Action::Watch,
                    network,
                    scripts: batch.iter().map(|w| ByteBuf(w.script.clone())).collect(),
                    scan_from_height: batch.iter().filter_map(|w| w.anchor_height).min(),
                    made_at_ms,
                });
            }
        }
        requests
    }

    /// Record that `entry`, signed for `pending`, has been sent.
    pub fn record_sent(&mut self, pending: &PendingInboxEntry, entry: &WireEntry, now_ms: u64) {
        let sent = SentWatch::sent(entry, now_ms);
        for script in &pending.scripts {
            let key = (pending.network, script.clone());
            let mut this = sent.clone();
            // A request sent while the last is still not seen read continues
            // the run; one sent after a read starts afresh.
            if let Some(previous) = self.sent.get(&key).filter(|p| !p.read) {
                this.unread_since_ms = previous.unread_since_ms;
            }
            self.sent.insert(key, this);
        }
    }
}

/// Real inbox pieces under a throwaway Ghost Key authority, shared with the
/// app state tests so they drive the same contract logic these do.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_inbox::test_support::{TestAuthority, TestGhostkey};
    use freenet_stdlib::prelude::ContractInstanceId;
    use ghostkey_common::{ScopedPayload, SignatureRequestor};
    use std::sync::OnceLock;

    pub const FLOOR: u32 = 900_000;

    /// Minting a notary key costs an RSA key generation, so once per binary.
    pub fn authority() -> &'static TestAuthority {
        static A: OnceLock<TestAuthority> = OnceLock::new();
        A.get_or_init(TestAuthority::new)
    }

    pub fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    pub fn bridge() -> BridgeId {
        BridgeId(bridge_key().verifying_key().to_bytes())
    }

    /// An inbox the test bridge has opened at `FLOOR`, under the test authority.
    pub fn open_inbox() -> InboxStateV1 {
        let mut s = InboxStateV1::default();
        s.apply_delta(
            &authority().params(bridge()),
            &InboxDelta {
                floor: Some(SignedFloor::sign(&bridge_key(), FLOOR)),
                entries: vec![],
                removals: vec![],
            },
        )
        .expect("the bridge opens its inbox");
        s
    }

    /// What the ghostkey delegate returns for `signing_payload`: the payload
    /// wrapped in a scoped payload naming the web app that asked, and a
    /// signature over that.
    pub fn sign_result(gk: &TestGhostkey, signing_payload: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let scoped = to_cbor(&ScopedPayload {
            requestor: SignatureRequestor::WebApp(ContractInstanceId::new([7u8; 32])),
            payload: signing_payload,
        })
        .expect("scoped payload encodes");
        let sig = gk.sk.sign(&scoped).to_bytes().to_vec();
        (scoped, sig)
    }

    /// [`sign_result`], formed into the entry the UI submits.
    pub fn signed(gk: &TestGhostkey, signing_payload: Vec<u8>) -> WireEntry {
        let (scoped, sig) = sign_result(gk, signing_payload);
        WireEntry::from_sign_result(gk.pem.clone(), scoped, sig).expect("a signed entry forms")
    }

    /// Submit through the same bytes the UI would send, as the contract would
    /// receive them.
    pub fn submit(state: &mut InboxStateV1, floor: &SignedFloor, entry: WireEntry) {
        let bytes = submission_bytes(floor, entry).expect("submission encodes");
        let delta: InboxDelta =
            freenet_bitcoin_common::from_cbor(&bytes).expect("submission decodes");
        state
            .apply_delta(&authority().params(bridge()), &delta)
            .expect("the inbox accepts the update");
    }

    /// The bridge moving its floor up to `height`, as it does each mainnet
    /// block.
    pub fn raise_floor(state: &mut InboxStateV1, height: u32) {
        state
            .apply_delta(
                &authority().params(bridge()),
                &InboxDelta {
                    floor: Some(SignedFloor::sign(&bridge_key(), height)),
                    entries: vec![],
                    removals: vec![],
                },
            )
            .expect("the bridge raises its floor");
    }

    /// A contract key for the test inbox. Its code hash is arbitrary: nothing
    /// in these tests fetches the contract.
    pub fn inbox_key() -> ContractKey {
        inbox_contract_key(bridge(), CodeHash::new([0x38; 32])).expect("the inbox key derives")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use freenet_bitcoin_common::from_cbor;
    use freenet_bitcoin_inbox::test_support::TestGhostkey;
    use freenet_bitcoin_inbox::{InboxStateV1, WINDOW_BLOCKS};
    use freenet_stdlib::prelude::ContractCode;

    fn watch_one() -> InboxRequest {
        watch_requests(
            BitcoinNetwork::Signet,
            &[vec![0x00, 0x14, 0xab]],
            1_000,
            None,
        )
        .pop()
        .expect("one request")
    }

    /// The whole path, end to end on real pieces: prepared here, signed as the
    /// ghostkey delegate signs, submitted as the UI submits, admitted by the
    /// real inbox contract logic, and opened by the real bridge key.
    #[test]
    fn a_prepared_entry_is_admitted_by_the_inbox_and_opened_by_the_bridge() {
        let gk = authority().mint();
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let request = watch_one();
        let prepared = prepare_entry(bridge(), gk.id(), &floor, &request).expect("prepares");

        let mut inbox = open_inbox();
        submit(&mut inbox, &floor, signed(&gk, prepared.signing_payload));
        assert_eq!(inbox.entries.len(), 1, "the inbox admits the entry");

        let entry = inbox.entries.values().next().expect("the admitted entry");
        let body = entry.body().expect("the body decodes");
        let opened = freenet_bitcoin_inbox::seal::unseal(
            &bridge_key(),
            &gk.id(),
            entry.mainnet_height,
            &body.sealed,
        )
        .expect("the bridge opens it");
        assert_eq!(
            opened, request,
            "and reads exactly the request that was sent"
        );

        let stranger = authority().mint();
        assert!(
            freenet_bitcoin_inbox::seal::unseal(
                &bridge_key(),
                &stranger.id(),
                entry.mainnet_height,
                &body.sealed
            )
            .is_err(),
            "a request sealed for one Ghost Key does not open as another's"
        );
    }

    /// The trap in the issue as first written: dating by the chain tip. The
    /// floor trails the tip, so a tip-dated entry falls above the window, and
    /// the inbox drops it with no error. Only the floor-dated one gets in.
    #[test]
    fn an_entry_is_dated_against_the_floor_and_one_dated_by_the_tip_goes_nowhere() {
        let gk = authority().mint();
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let request = watch_one();

        let prepared = prepare_entry(bridge(), gk.id(), &floor, &request).expect("prepares");
        assert!(
            (FLOOR..=FLOOR + WINDOW_BLOCKS).contains(&prepared.mainnet_height),
            "dated inside the window above the floor"
        );

        // Built the same way, but dated as a tip a little ahead of the floor.
        let tip = FLOOR + WINDOW_BLOCKS + 26;
        let sealed =
            freenet_bitcoin_inbox::seal::seal(&bridge(), &gk.id(), tip, &request).expect("seals");
        let tip_payload = InboxEntryBody {
            bridge: bridge(),
            mainnet_height: tip,
            sealed,
        }
        .signing_payload()
        .expect("lays out");

        let mut inbox = open_inbox();
        submit(&mut inbox, &floor, signed(&gk, tip_payload));
        assert!(
            inbox.entries.is_empty(),
            "a tip-dated entry is dropped, and the update still reports success"
        );
        submit(&mut inbox, &floor, signed(&gk, prepared.signing_payload));
        assert_eq!(inbox.entries.len(), 1, "the floor-dated one is admitted");
    }

    #[test]
    fn watch_requests_split_at_the_script_limit_and_each_is_dated_later() {
        let scripts: Vec<Vec<u8>> = (0..=MAX_SCRIPTS_PER_REQUEST as u8)
            .map(|i| vec![0x00, 0x14, i])
            .collect();
        let requests = watch_requests(BitcoinNetwork::Bitcoin, &scripts, 5_000, Some(12));

        assert_eq!(
            requests.len(),
            2,
            "one past the limit makes a second request"
        );
        assert_eq!(requests[0].scripts.len(), MAX_SCRIPTS_PER_REQUEST);
        assert_eq!(requests[1].scripts.len(), 1);
        assert!(
            requests[0].made_at_ms < requests[1].made_at_ms,
            "strictly later, so the bridge applies both"
        );
        for r in &requests {
            assert_eq!(r.action, Action::Watch);
            assert_eq!(r.network, BitcoinNetwork::Bitcoin);
            assert_eq!(r.scan_from_height, Some(12));
            r.check().expect("every request is one the inbox accepts");
        }
    }

    #[test]
    fn a_script_named_twice_is_asked_for_once() {
        let s = vec![0x00, 0x14, 0x01];
        let requests = watch_requests(BitcoinNetwork::Signet, &[s.clone(), s], 1, None);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].scripts.len(), 1);
    }

    #[test]
    fn the_next_timestamp_never_goes_back() {
        assert_eq!(
            next_made_at_ms(100, None),
            100,
            "the clock, with no history"
        );
        assert_eq!(next_made_at_ms(100, Some(50)), 100, "the clock, once past");
        assert_eq!(
            next_made_at_ms(100, Some(100)),
            101,
            "never equal to the last"
        );
        assert_eq!(
            next_made_at_ms(100, Some(200)),
            201,
            "past a clock that ran ahead and came back"
        );
    }

    /// The key built from a generation pointer's code hash must be the very
    /// contract the bridge serves, or every request goes to a contract nobody
    /// reads. The bridge side is built here the way the bridge's own
    /// `InboxWorker::contract_key` builds it, independently of this module:
    /// derived from the parameters through its own encoder, so a mistake in
    /// `inbox_params_bytes` cannot appear on both sides and cancel out.
    #[test]
    fn the_inbox_key_is_the_one_the_bridge_serves() {
        let code = ContractCode::from(b"stands in for the inbox wasm".to_vec());
        let bridge_params = freenet_bitcoin_common::to_cbor(&InboxParameters::production(bridge()))
            .expect("the bridge's parameters encode");
        let the_bridges = ContractKey::from_params_and_code(Parameters::from(bridge_params), &code);

        let ours = inbox_contract_key(bridge(), *code.hash()).expect("key builds");
        assert_eq!(ours.id(), the_bridges.id(), "same instance id");
        assert_eq!(ours.code_hash(), the_bridges.code_hash(), "same code hash");
    }

    const T0: u64 = 1_700_000_000_000;

    /// A signed entry for one watch, as sent, and the bridge's floor it was
    /// dated against.
    fn a_sent_entry() -> WireEntry {
        let gk = authority().mint();
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let prepared = prepare_entry(bridge(), gk.id(), &floor, &watch_one()).expect("prepares");
        signed(&gk, prepared.signing_payload)
    }

    fn apply(inbox: &mut InboxStateV1, delta: InboxDelta) {
        inbox
            .apply_delta(&authority().params(bridge()), &delta)
            .expect("the inbox accepts the update");
    }

    /// The bridge reading `entry`: it signs a batch removing it.
    fn bridge_reads(inbox: &mut InboxStateV1, entry: &WireEntry) {
        let mut removed = std::collections::BTreeSet::new();
        removed.insert(entry.entry.key().removal_prefix());
        apply(
            inbox,
            InboxDelta {
                floor: Some(SignedFloor::sign(&bridge_key(), FLOOR)),
                entries: vec![],
                removals: vec![freenet_bitcoin_inbox::RemovalBatch::sign(
                    &bridge_key(),
                    entry.entry.mainnet_height,
                    &removed,
                )],
            },
        );
    }

    /// The bridge's floor moving past `entry`, which prunes it and any record
    /// of its removal.
    fn floor_passes(inbox: &mut InboxStateV1, entry: &WireEntry) {
        apply(
            inbox,
            InboxDelta {
                floor: Some(SignedFloor::sign(
                    &bridge_key(),
                    entry.entry.mainnet_height + 1,
                )),
                entries: vec![],
                removals: vec![],
            },
        );
    }

    #[test]
    fn a_script_never_asked_for_is_due() {
        assert!(watch_due(None, &open_inbox(), T0, T0));
    }

    #[test]
    fn a_request_still_waiting_in_the_inbox_is_not_due() {
        let entry = a_sent_entry();
        let mut inbox = open_inbox();
        submit(
            &mut inbox,
            &SignedFloor::sign(&bridge_key(), FLOOR),
            entry.clone(),
        );
        let sent = SentWatch::sent(&entry, T0);
        assert!(!watch_due(
            Some(&sent),
            &inbox,
            T0 + 10 * 60 * 1000,
            T0 + 10 * 60 * 1000
        ));
    }

    #[test]
    fn a_just_sent_request_is_given_time_to_land() {
        let entry = a_sent_entry();
        let sent = SentWatch::sent(&entry, T0);
        assert!(
            !watch_due(Some(&sent), &open_inbox(), T0 + 1_000, T0 + 1_000),
            "not in the inbox yet, but only a second old"
        );
    }

    #[test]
    fn a_request_the_bridge_read_is_not_due() {
        let entry = a_sent_entry();
        let mut inbox = open_inbox();
        submit(
            &mut inbox,
            &SignedFloor::sign(&bridge_key(), FLOOR),
            entry.clone(),
        );
        bridge_reads(&mut inbox, &entry);
        let sent = SentWatch::sent(&entry, T0);
        assert!(!watch_due(
            Some(&sent),
            &inbox,
            T0 + 10 * 60 * 1000,
            T0 + 10 * 60 * 1000
        ));
    }

    #[test]
    fn a_request_that_left_the_inbox_unread_is_due_again() {
        let entry = a_sent_entry();
        let sent = SentWatch::sent(&entry, T0);
        assert!(
            watch_due(
                Some(&sent),
                &open_inbox(),
                T0 + 10 * 60 * 1000,
                T0 + 10 * 60 * 1000
            ),
            "past the grace period, not in the inbox, never seen read"
        );
    }

    /// The trap this type exists for. Once the bridge has read a request, the
    /// floor passing it erases both the entry and the record that it was read,
    /// so read and dropped look the same. A watch whose read was observed is
    /// not asked for again; the same history unobserved would be, every half
    /// hour, for every order.
    #[test]
    fn a_request_seen_read_is_not_resent_once_the_floor_erases_the_evidence() {
        let entry = a_sent_entry();
        let mut inbox = open_inbox();
        submit(
            &mut inbox,
            &SignedFloor::sign(&bridge_key(), FLOOR),
            entry.clone(),
        );
        bridge_reads(&mut inbox, &entry);

        let mut observed = SentWatch::sent(&entry, T0);
        observed.observe(&inbox);
        assert!(observed.read, "the removal was seen");
        let unobserved = SentWatch::sent(&entry, T0);

        floor_passes(&mut inbox, &entry);
        let later = T0 + 40 * 60 * 1000;
        assert!(
            !inbox.is_removed(&entry.entry.key(), entry.entry.mainnet_height)
                && !inbox.entries.contains_key(&entry.entry.key()),
            "the floor has erased every trace of it"
        );
        assert!(
            !watch_due(Some(&observed), &inbox, later, later),
            "seen read: not resent"
        );
        assert!(
            watch_due(Some(&unobserved), &inbox, later, later),
            "the same history, unobserved, would be resent"
        );
    }

    #[test]
    fn a_watch_is_renewed_before_the_bridge_lets_it_lapse() {
        let entry = a_sent_entry();
        let mut sent = SentWatch::sent(&entry, T0);
        sent.read = true;
        assert!(!watch_due(
            Some(&sent),
            &open_inbox(),
            T0 + RENEW_AFTER_MS - 1,
            T0 + RENEW_AFTER_MS - 1
        ));
        assert!(watch_due(
            Some(&sent),
            &open_inbox(),
            T0 + RENEW_AFTER_MS,
            T0 + RENEW_AFTER_MS
        ));
    }

    fn wanted(network: BitcoinNetwork, n: u8, anchor: u32) -> WatchWanted {
        WatchWanted {
            network,
            script: vec![0x00, 0x14, n],
            anchor_height: Some(anchor),
        }
    }

    fn wanted_set(w: &[WatchWanted]) -> std::collections::HashSet<(BitcoinNetwork, Vec<u8>)> {
        w.iter().map(|w| (w.network, w.script.clone())).collect()
    }

    fn tracker_on(inbox: InboxStateV1) -> InboxTracker {
        let mut t = InboxTracker::new(bridge(), inbox_key());
        t.on_state(inbox, T0);
        t
    }

    /// Sign and send `request` as `gk`, landing it in `inbox`, and record it
    /// in `tracker` as the UI does.
    fn send(
        tracker: &mut InboxTracker,
        inbox: &mut InboxStateV1,
        gk: &TestGhostkey,
        request: &InboxRequest,
        now_ms: u64,
    ) -> WireEntry {
        let floor = inbox.floor.clone().expect("an open inbox");
        let prepared = prepare_entry(bridge(), gk.id(), &floor, request).expect("prepares");
        let entry = signed(gk, prepared.signing_payload.clone());
        let pending = PendingInboxEntry {
            fingerprint: "seller".into(),
            ghostkey: gk.id(),
            contract_key: inbox_key(),
            floor: floor.clone(),
            network: request.network,
            scripts: request.scripts.iter().map(|s| s.0.clone()).collect(),
            signing_payload: prepared.signing_payload,
            queued_at_ms: T0,
        };
        tracker.record_sent(&pending, &entry, now_ms);
        submit(inbox, &floor, entry.clone());
        tracker.on_state(inbox.clone(), now_ms);
        entry
    }

    #[test]
    fn nothing_is_planned_before_the_inbox_is_served() {
        let gk = authority().mint();
        let mut t = InboxTracker::new(bridge(), inbox_key());
        let w = [wanted(BitcoinNetwork::Signet, 1, 10)];
        assert!(t.plan(gk.id(), &w, &[], T0).is_empty());
        t.on_state(InboxStateV1::default(), T0);
        assert!(
            t.plan(gk.id(), &w, &[], T0).is_empty(),
            "an inbox with no floor cannot date an entry"
        );
    }

    #[test]
    fn a_first_plan_asks_for_every_wanted_script_scanning_from_the_oldest_anchor() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let w = [
            wanted(BitcoinNetwork::Signet, 1, 120),
            wanted(BitcoinNetwork::Signet, 2, 100),
            wanted(BitcoinNetwork::Signet, 1, 120),
        ];
        let plan = t.plan(gk.id(), &w, &[], T0);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].action, Action::Watch);
        assert_eq!(
            plan[0].scripts,
            vec![ByteBuf(w[0].script.clone()), ByteBuf(w[1].script.clone())],
            "each script once"
        );
        assert_eq!(plan[0].scan_from_height, Some(100));
        plan[0].check().expect("a well-formed request");
    }

    #[test]
    fn made_at_strictly_increases_across_plans_in_one_millisecond() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let a = t.plan(gk.id(), &[wanted(BitcoinNetwork::Signet, 1, 1)], &[], T0);
        let b = t.plan(gk.id(), &[wanted(BitcoinNetwork::Signet, 2, 1)], &[], T0);
        assert!(b[0].made_at_ms > a[0].made_at_ms);
    }

    #[test]
    fn each_network_gets_its_own_request() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let plan = t.plan(
            gk.id(),
            &[
                wanted(BitcoinNetwork::Signet, 1, 1),
                wanted(BitcoinNetwork::Testnet4, 1, 1),
            ],
            &[],
            T0,
        );
        let networks: Vec<_> = plan.iter().map(|r| r.network).collect();
        assert_eq!(
            networks,
            vec![BitcoinNetwork::Signet, BitcoinNetwork::Testnet4]
        );
    }

    /// More than two requests' worth of scripts: the inbox would drop a
    /// third entry from one Ghost Key, so only two are sent now, newest
    /// orders first, and the rest wait for the bridge to read those.
    #[test]
    fn a_ghost_key_never_sends_more_entries_than_the_inbox_keeps() {
        let gk = authority().mint();
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let w: Vec<WatchWanted> = (0..70u8)
            .map(|n| wanted(BitcoinNetwork::Signet, n, 1))
            .collect();

        let plan = t.plan(gk.id(), &w, &[], T0);
        assert_eq!(plan.len(), MAX_ENTRIES_PER_GHOSTKEY);
        assert_eq!(plan[0].scripts[0], ByteBuf(w[0].script.clone()));
        assert_eq!(plan[0].scripts.len(), MAX_SCRIPTS_PER_REQUEST);

        for r in &plan {
            send(&mut t, &mut inbox, &gk, r, T0);
        }
        assert_eq!(
            inbox.entries.len(),
            MAX_ENTRIES_PER_GHOSTKEY,
            "both admitted"
        );
        assert!(
            t.plan(gk.id(), &w, &[], T0 + 60_000).is_empty(),
            "both places are held by unread entries"
        );

        let other = authority().mint();
        let others: Vec<WatchWanted> = (100..170u8)
            .map(|n| wanted(BitcoinNetwork::Signet, n, 1))
            .collect();
        assert_eq!(
            t.plan(other.id(), &others, &[], T0 + 60_000).len(),
            MAX_ENTRIES_PER_GHOSTKEY,
            "another Ghost Key's allowance is its own"
        );
    }

    #[test]
    fn a_request_still_landing_holds_its_place() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let w = [
            wanted(BitcoinNetwork::Signet, 1, 1),
            wanted(BitcoinNetwork::Signet, 2, 1),
        ];
        let first = t.plan(gk.id(), &w[..1], &[], T0);
        // Sent, but the node has not yet served a state that includes it.
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let prepared = prepare_entry(bridge(), gk.id(), &floor, &first[0]).expect("prepares");
        let entry = signed(&gk, prepared.signing_payload.clone());
        let pending = PendingInboxEntry {
            fingerprint: "seller".into(),
            ghostkey: gk.id(),
            contract_key: inbox_key(),
            floor,
            network: BitcoinNetwork::Signet,
            scripts: vec![w[0].script.clone()],
            signing_payload: prepared.signing_payload,
            queued_at_ms: T0,
        };
        t.record_sent(&pending, &entry, T0);

        let now = T0 + 1_000;
        let plan = t.plan(gk.id(), &w, &[&pending, &pending], now);
        assert!(
            plan.is_empty(),
            "one landing and two awaiting a signature is over the allowance"
        );
        // Enough still wanted to fill both places, so only the allowance
        // limits what is sent.
        let mut more = w.to_vec();
        more.extend((10..80u8).map(|n| wanted(BitcoinNetwork::Signet, n, 1)));
        let plan = t.plan(gk.id(), &more, &[], now);
        assert_eq!(plan.len(), 1, "one place is left while the first lands");
        assert_eq!(plan[0].scripts[0], ByteBuf(w[1].script.clone()));
        assert!(
            !plan[0].scripts.contains(&ByteBuf(w[0].script.clone())),
            "the landing script is not asked for again"
        );
    }

    #[test]
    fn a_script_awaiting_its_signature_is_not_asked_for_again() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let w = [
            wanted(BitcoinNetwork::Signet, 1, 1),
            wanted(BitcoinNetwork::Signet, 2, 1),
        ];
        let awaiting = PendingInboxEntry {
            fingerprint: "seller".into(),
            ghostkey: gk.id(),
            contract_key: inbox_key(),
            floor: SignedFloor::sign(&bridge_key(), FLOOR),
            network: BitcoinNetwork::Signet,
            scripts: vec![w[0].script.clone()],
            signing_payload: vec![],
            queued_at_ms: T0,
        };
        let plan = t.plan(gk.id(), &w, &[&awaiting], T0);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].scripts, vec![ByteBuf(w[1].script.clone())]);
    }

    /// The lifecycle on real pieces: sent, admitted, read by the bridge, the
    /// evidence pruned by the floor, and renewed when the watch needs it.
    #[test]
    fn a_watch_is_sent_once_and_renewed_only_when_due() {
        let gk = authority().mint();
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let w = [wanted(BitcoinNetwork::Signet, 1, 1)];

        let plan = t.plan(gk.id(), &w, &[], T0);
        let entry = send(&mut t, &mut inbox, &gk, &plan[0], T0);
        assert!(
            t.plan(gk.id(), &w, &[], T0 + 10 * 60_000).is_empty(),
            "waiting"
        );

        bridge_reads(&mut inbox, &entry);
        t.on_state(inbox.clone(), T0 + 30 * 60_000);
        floor_passes(&mut inbox, &entry);
        t.on_state(inbox.clone(), T0 + 60 * 60_000);
        assert!(
            t.plan(gk.id(), &w, &[], T0 + 60 * 60_000).is_empty(),
            "read, so not sent again once the evidence is pruned"
        );
        raise_floor(&mut inbox, FLOOR + 72);
        t.on_state(inbox.clone(), T0 + RENEW_AFTER_MS);
        let renewal = t.plan(gk.id(), &w, &[], T0 + RENEW_AFTER_MS);
        assert_eq!(renewal.len(), 1, "renewed before the watch lapses");
        assert!(renewal[0].made_at_ms > plan[0].made_at_ms);
    }

    /// **Nothing is dated against a state not heard from lately.** An entry
    /// dated against a floor that has since moved on is dropped on arrival.
    #[test]
    fn nothing_is_planned_against_a_stale_inbox_state() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let w = [wanted(BitcoinNetwork::Signet, 1, 1)];
        assert!(t
            .plan(gk.id(), &w, &[], T0 + INBOX_STATE_FRESH_MS)
            .is_empty());
        assert_eq!(
            t.plan(gk.id(), &w, &[], T0 + INBOX_STATE_FRESH_MS - 1)
                .len(),
            1
        );
    }

    #[test]
    fn the_inbox_is_fetched_when_unheard_from_and_not_asked_twice_at_once() {
        let mut t = InboxTracker::new(bridge(), inbox_key());
        assert!(t.fetch_due(T0), "never served");
        t.note_fetch(T0);
        assert!(!t.fetch_due(T0 + INBOX_FETCH_RETRY_MS - 1));
        assert!(t.fetch_due(T0 + INBOX_FETCH_RETRY_MS), "nothing came back");

        t.on_state(open_inbox(), T0 + 1);
        assert!(!t.fetch_due(T0 + INBOX_FETCH_RETRY_MS), "served");
        assert!(
            t.fetch_due(T0 + 1 + INBOX_REFETCH_MS),
            "fetched again in case the subscription ended quietly"
        );
    }

    /// **An entry that has landed holds one place, not two**, though it is
    /// also still within its landing grace.
    #[test]
    fn an_entry_seen_landing_is_counted_once() {
        let gk = authority().mint();
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let w: Vec<WatchWanted> = (0..70u8)
            .map(|n| wanted(BitcoinNetwork::Signet, n, 1))
            .collect();
        let first = t.plan(gk.id(), &w[..1], &[], T0);
        send(&mut t, &mut inbox, &gk, &first[0], T0);

        let plan = t.plan(gk.id(), &w, &[], T0 + 1_000);
        assert_eq!(plan.len(), 1, "one place left, not none");
    }

    /// **Absence is judged by a state that arrived after the send had time to
    /// land**, not by the clock. A quiet inbox whose last state predates the
    /// send says nothing about whether the request arrived.
    #[test]
    fn a_request_is_not_taken_as_dropped_on_a_state_older_than_its_landing() {
        let entry = a_sent_entry();
        let sent = SentWatch::sent(&entry, T0);
        let later = T0 + 30 * 60 * 1000;
        assert!(
            !watch_due(Some(&sent), &open_inbox(), T0 + LAND_GRACE_MS - 1, later),
            "the only state seen could not have held it yet"
        );
        assert!(
            watch_due(Some(&sent), &open_inbox(), T0 + LAND_GRACE_MS, later),
            "a state that should hold it and does not"
        );
    }

    #[test]
    fn fetches_that_bring_nothing_back_are_spaced_further_apart() {
        let mut t = InboxTracker::new(bridge(), inbox_key());
        t.note_fetch(T0);
        let second = T0 + INBOX_FETCH_RETRY_MS;
        assert!(t.fetch_due(second));
        t.note_fetch(second);
        assert!(
            !t.fetch_due(second + INBOX_FETCH_RETRY_MS),
            "the second wait is longer than the first"
        );
        assert!(t.fetch_due(second + 2 * INBOX_FETCH_RETRY_MS));

        let mut at = second;
        for _ in 0..20 {
            at += INBOX_REFETCH_MS;
            assert!(t.fetch_due(at), "never spaced past the refetch interval");
            t.note_fetch(at);
        }
        t.on_state(open_inbox(), at + 1);
        assert!(!t.fetch_due(at + INBOX_FETCH_RETRY_MS), "served");
        let unheard = at + 1 + INBOX_REFETCH_MS;
        assert!(t.fetch_due(unheard));
        t.note_fetch(unheard);
        assert!(
            t.fetch_due(unheard + INBOX_FETCH_RETRY_MS),
            "a state resets the spacing, so a new silence is retried promptly"
        );
    }

    /// **A request sitting unread holds its place, is not sent again however
    /// long it sits, and is noticed after long enough.**
    #[test]
    fn a_request_left_unread_holds_its_place_and_is_noticed() {
        let gk = authority().mint();
        let other = authority().mint();
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let w: Vec<WatchWanted> = (0..70u8)
            .map(|n| wanted(BitcoinNetwork::Signet, n, 1))
            .collect();
        let plan = t.plan(gk.id(), &w, &[], T0);
        for r in &plan {
            send(&mut t, &mut inbox, &gk, r, T0);
        }
        let hours = T0 + UNREAD_NOTICE_MS;
        for at in [hours - 1, hours, hours + 60 * 60 * 1000] {
            t.on_state(inbox.clone(), at);
            assert!(
                t.plan(gk.id(), &w, &[], at).is_empty(),
                "not resent at {at}"
            );
        }
        t.on_state(inbox.clone(), hours - 1);
        assert!(!t.request_long_unread(&[gk.id()], &wanted_set(&w), hours - 1));
        assert!(t.request_long_unread(&[gk.id()], &wanted_set(&w), hours));
        assert!(
            !t.request_long_unread(&[other.id()], &wanted_set(&w), hours),
            "only the keys asked about"
        );
    }

    /// **A request that keeps expiring unread is noticed**, though each one is
    /// pruned by the floor before it has sat for long. A read ends the run.
    #[test]
    fn a_request_that_keeps_expiring_unread_is_noticed() {
        let gk = authority().mint();
        let w = [wanted(BitcoinNetwork::Signet, 1, 1)];
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let mut at = T0;
        let mut floor = FLOOR;
        while at < T0 + UNREAD_NOTICE_MS {
            let plan = t.plan(gk.id(), &w, &[], at);
            assert_eq!(plan.len(), 1, "sent again once the last expired");
            send(&mut t, &mut inbox, &gk, &plan[0], at);
            assert!(!t.request_long_unread(&[gk.id()], &wanted_set(&w), at));
            // Three blocks pass; the entry, unread, falls below the floor.
            at += 30 * 60 * 1000;
            floor += 3;
            raise_floor(&mut inbox, floor);
            t.on_state(inbox.clone(), at);
        }
        assert!(t.request_long_unread(&[gk.id()], &wanted_set(&w), at));

        let plan = t.plan(gk.id(), &w, &[], at);
        let entry = send(&mut t, &mut inbox, &gk, &plan[0], at);
        bridge_reads(&mut inbox, &entry);
        t.on_state(inbox.clone(), at + 1);
        assert!(
            !t.request_long_unread(&[gk.id()], &wanted_set(&w), at + 1),
            "read"
        );
    }

    /// **Entries left from before a reload are noticed too.** A new tracker
    /// knows nothing it sent, but a stale copy still holds the key's places.
    #[test]
    fn entries_this_tab_did_not_send_are_noticed_when_they_sit_unread() {
        let gk = authority().mint();
        let w: Vec<WatchWanted> = (0..70u8)
            .map(|n| wanted(BitcoinNetwork::Signet, n, 1))
            .collect();
        let mut inbox = open_inbox();
        let mut before_reload = tracker_on(inbox.clone());
        for r in &before_reload.plan(gk.id(), &w, &[], T0) {
            send(&mut before_reload, &mut inbox, &gk, r, T0);
        }

        let mut t = tracker_on(inbox.clone());
        assert!(
            t.plan(gk.id(), &w, &[], T0).is_empty(),
            "the places are held"
        );
        assert!(!t.request_long_unread(&[gk.id()], &wanted_set(&w), T0 + 1));
        let later = T0 + UNREAD_NOTICE_MS;
        t.on_state(inbox, later);
        assert!(t.request_long_unread(&[gk.id()], &wanted_set(&w), later));
    }

    /// **A floor that stands still does not stop requests.** The bridge still
    /// reads entries dated against its floor while its mainnet node is down.
    #[test]
    fn a_floor_that_stands_still_does_not_stop_requests() {
        let gk = authority().mint();
        let mut t = tracker_on(open_inbox());
        let hours_later = T0 + 6 * 60 * 60 * 1000;
        t.on_state(open_inbox(), hours_later);
        assert_eq!(
            t.plan(
                gk.id(),
                &[wanted(BitcoinNetwork::Signet, 1, 1)],
                &[],
                hours_later
            )
            .len(),
            1
        );
    }

    /// **A renewal after a read starts a new run**, so a healthy watch renewed
    /// every twelve hours is not reported as unread.
    #[test]
    fn a_renewal_after_a_read_starts_a_fresh_unread_run() {
        let gk = authority().mint();
        let w = [wanted(BitcoinNetwork::Signet, 1, 1)];
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let plan = t.plan(gk.id(), &w, &[], T0);
        let entry = send(&mut t, &mut inbox, &gk, &plan[0], T0);
        bridge_reads(&mut inbox, &entry);
        t.on_state(inbox.clone(), T0 + 1);

        let renew = T0 + RENEW_AFTER_MS;
        raise_floor(&mut inbox, FLOOR + 72);
        t.on_state(inbox.clone(), renew);
        let plan = t.plan(gk.id(), &w, &[], renew);
        assert_eq!(plan.len(), 1, "renewed");
        send(&mut t, &mut inbox, &gk, &plan[0], renew);
        assert!(
            !t.request_long_unread(&[gk.id()], &wanted_set(&w), renew + 60_000),
            "the run starts at the renewal, not at the first request"
        );
    }

    /// **A script no longer wanted does not count**, so an order paid or
    /// expired while its request was going unread leaves no run behind.
    #[test]
    fn a_script_no_longer_wanted_is_not_reported_unread() {
        let gk = authority().mint();
        let w = [wanted(BitcoinNetwork::Signet, 1, 1)];
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        let plan = t.plan(gk.id(), &w, &[], T0);
        send(&mut t, &mut inbox, &gk, &plan[0], T0);
        // The entry expires unread, and the order stops being wanted.
        raise_floor(&mut inbox, FLOOR + 3);
        let later = T0 + UNREAD_NOTICE_MS;
        t.on_state(inbox, later);
        assert!(t.request_long_unread(&[gk.id()], &wanted_set(&w), later));
        assert!(!t.request_long_unread(&[gk.id()], &Default::default(), later));
    }

    /// **After the tab has not been running, the clocks restart**: reads that
    /// happened meanwhile may have left no trace.
    #[test]
    fn a_gap_in_checking_restarts_the_unread_clocks() {
        let gk = authority().mint();
        let w = [wanted(BitcoinNetwork::Signet, 1, 1)];
        let mut inbox = open_inbox();
        let mut t = tracker_on(inbox.clone());
        t.note_check(T0);
        let plan = t.plan(gk.id(), &w, &[], T0);
        send(&mut t, &mut inbox, &gk, &plan[0], T0);

        let woke = T0 + 8 * 60 * 60 * 1000;
        t.note_check(woke);
        t.on_state(inbox, woke);
        assert!(
            !t.request_long_unread(&[gk.id()], &wanted_set(&w), woke),
            "neither the send nor the entry is taken as hours unread"
        );
        assert!(t.request_long_unread(&[gk.id()], &wanted_set(&w), woke + UNREAD_NOTICE_MS));

        let mut steady = tracker_on(open_inbox());
        steady.note_check(T0);
        let mut inbox = open_inbox();
        let plan = steady.plan(gk.id(), &w, &[], T0);
        send(&mut steady, &mut inbox, &gk, &plan[0], T0);
        let mut at = T0;
        while at < T0 + UNREAD_NOTICE_MS {
            at += 60_000;
            steady.note_check(at);
        }
        assert!(
            steady.request_long_unread(&[gk.id()], &wanted_set(&w), at),
            "checking every minute restarts nothing"
        );
    }
}
