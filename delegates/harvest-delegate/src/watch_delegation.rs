//! Keeping instant checkout's next payment addresses watched with no tab open,
//! through a watch key the seller's Ghost Key delegated to this delegate
//! (freenet-bitcoin#30).
//!
//! # Why
//!
//! The delegate invoices only on an address the bridge is watching (I7 in
//! [`crate::auto_invoice`]), and a watch request must come from the seller's
//! Ghost Key. A background run cannot reach the Ghost Key vault, so until now
//! only an open seller tab could ask, and the store stopped taking orders once
//! the ten addresses the tab had watched were used or their horizon neared.
//! Here the tab asks the Ghost Key to delegate watch requests for one bridge
//! to a key this delegate holds (the watch key), and the delegate then signs
//! its own requests with it. The bridge acts on them as the Ghost Key's own.
//!
//! # The one rule: never credit a horizon the bridge may not have applied
//!
//! The bridge answers nothing. It reads and removes, without acting, a request
//! under a delegation it no longer honours (revoked, superseded, conflicting),
//! one whose `made_at_ms` is behind, and the scripts past the Ghost Key's cap;
//! it leaves unread, and lets the floor drop, a request to an inbox it no
//! longer reads. A removal proves nothing, and a script's scan watermark
//! proves only that SOMEONE has it watched: the tab watches the same
//! addresses.
//!
//! So every request ends with a **canary**: an address that is unscanned BY
//! CONSTRUCTION. It lies past the tab's pool (the next
//! [`MAX_UPCOMING_ADDRESSES`], exactly what the tab asks for) by
//! [`CANARY_MARGIN`] more, past every canary this delegate has used, and is
//! not one an arm names. Nobody else asks for it, so its address contract
//! normally does not exist at all: the bridge creates one only when it
//! publishes for a watched script. The bridge applies a request's scripts in
//! order and counts the rest refused once the Ghost Key's cap is reached; the
//! count only grows within a request, so the canary (last) scanned means
//! every script before it was applied too. The request's scripts are credited
//! only once the canary's watermark, signed by this bridge, reaches the tip
//! the request left the inbox at, and only while the canary is still outside
//! the tab's pool and the tab's watches.
//!
//! # One request's life
//!
//! 1. **Canary.** When the first [`REFILL_BELOW`] addresses from the counter
//!    are not all watched with [`RENEW_MARGIN_BLOCKS`] to spare, a wake-up
//!    reads the next canary candidate's address contract (a GET only). No
//!    state, or no fresh watermark: go on to the inbox in the same run. A
//!    fresh watermark (someone has it watched): skip it, at most
//!    [`MAX_CANARY_TRIES`] a round.
//! 2. **Sent.** ONE delegated Watch for every next address not so watched,
//!    then the canary, through `tip + REQUEST_AHEAD_BLOCKS`. A node that
//!    refuses the UPDATE means it was never sent: forgotten, not a failure.
//! 3. **Left the inbox.** On a removal the bridge signed, on the floor
//!    passing its height, or after [`OUTSTANDING_MAX_MS`].
//! 4. **Confirmed** by the canary's watermark reaching the tip it left at.
//!    Still short [`CONFIRM_BLOCKS`] later, with a fresh tip, is a failure:
//!    a canary nobody asks for has no contract until the bridge publishes,
//!    so an absent state is the evidence. A canary the counter or the tab has
//!    reached since proves nothing either way: dropped, uncredited.
//! 5. **Kept honest.** Every [`PROBE_EVERY_MS`] the canary of the next
//!    address's request is read again; a settled copy more than
//!    [`LIVE_LAG_BLOCKS`] behind a fresh tip withdraws every watch of the
//!    delegation (a revocation withdraws them at the bridge too).
//!
//! # Settled copies
//!
//! A delegate's GET is answered from the node's LOCAL copy when it holds one,
//! with no freshness check (freenet-core `contract.rs`, the delegate GET
//! path). So every inbox and confirm/probe read is also SUBSCRIBED to, which
//! keeps the local copy following the network, and a copy counts as settled
//! only [`SETTLE_MS`] after the node answered that SUBSCRIBE Ok in this node
//! run. A probe withdraws only on a settled copy; a request is dated only from
//! a settled inbox copy. A read with no state is no evidence for a probe.
//! Nothing is judged without a fresh tip (a bridge that is down stops its tip
//! too).
//!
//! # Stalls
//!
//! [`MAX_FAILURES`] requests in a row whose canary never showed (with a
//! doubling [`FAILURE_BACKOFF_MS`] between them) stall the delegation: it
//! sends nothing until the open tab delegates again, and the tab is told
//! ([`WatchDelegationStatus::stalled`]). Watches already confirmed keep
//! counting while the probe keeps finding them scanned.
//!
//! # The watch key is not exported
//!
//! It lives under `harvest:auto:`, which a migration export leaves behind
//! (`migration::is_store_key`), like everything here but the ledgers. A
//! successor generation has no watch key until the tab delegates to it, and
//! that newer delegation supersedes this generation's at the bridge.
//!
//! # Residuals
//!
//! - **Another device, same store and payment key.** A second device armed
//!   for the same store derives the same addresses, and could watch the same
//!   canary index; its watch would then confirm this delegate's canary.
//! - **Probe latency.** A revocation or a watch ending is noticed at the
//!   next probe, up to [`PROBE_EVERY_MS`] (plus [`SETTLE_MS`] after a node
//!   restart) late.
//! - **Two devices, one Ghost Key.** The bridge honours one delegation per
//!   Ghost Key; the other device's requests are read and ignored. Its canary
//!   never shows, so it credits nothing and stalls, and each device's tab
//!   re-delegates at a later height when it opens, taking the bridge back.
//! - **The horizon credited is the one asked.** A bridge that knows no
//!   reference height for the network keeps a plain day's watch while the
//!   delegate credits nine days; the watermark does not carry the horizon.
//!   The live bridge always knows one (it clamps from its own tip).
//! - **A read outage is a failure.** A canary the bridge did apply, whose
//!   contract the node cannot fetch for the whole confirmation window, counts
//!   as not applied: a backoff, and after three a stall, which only stops
//!   sending.
//! - **Pointers.** The inbox and the address contract's code hash are the
//!   ones the tab last named; the delegate does not resolve the bridge's
//!   generation pointers itself. After a re-key with no tab open, requests
//!   go unread or unapplied, their canaries never show, and the delegation
//!   stalls; the tab re-names both when it opens. Fail closed.
//! - **The tip is the network's, not the bridge's.** Horizons and freshness
//!   are judged against the tip contract the arm names for the network: with
//!   one bridge per network (every network Harvest runs on) the bridge's own.
//! - **Revocation.** The tab never restates `revoke_watch_keys_through`
//!   (the API recommends it on every Ghost Key request); nothing Harvest does
//!   revokes.
//! - **Subscriptions.** Every inbox, confirm and probe read is subscribed to,
//!   a few a week, never unsubscribed (stdlib 0.8.5 has no unsubscribe); their
//!   notifications are dropped (up to [`EVER_SUBSCRIBED_CAP`] per delegation).

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_bitcoin_common::{BitcoinAddressParameters, BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::{
    sender_height, Action, ByteBuf, Delegation, EntryKey, EphemeralKey, GhostkeyId, InboxDelta,
    InboxEntryBody, InboxRequest, InboxStateV1, Sealed, SignedFloor, WireEntry,
    MAX_DELEGATION_BYTES, MAX_SCRIPTS_PER_REQUEST, MAX_WATCH_AHEAD_BLOCKS,
};
use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::{
    ContractInstanceId, DelegateContext, GetContractRequest, OutboundDelegateMsg, StateDelta,
    SubscribeContractRequest, UpdateContractRequest, UpdateData,
};
use serde::{Deserialize, Serialize};

use harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES;
use harvest_common::delegate::{
    AutoInvoiceArm, HarvestDelegateRequest, HarvestDelegateResponse, WatchDelegationGrant,
    WatchDelegationStatus,
};
use harvest_common::{from_cbor, to_cbor};

use crate::auto_invoice::{
    arms, load, save, tip_key, ArmRecord, TipCache, AUTO_PREFIX, EXPORTED_KEY, TIP_MAX_AGE_MS,
    WATCH_NEEDED_BLOCKS, WATCH_NEEDED_MS,
};

/// The watch key's 32-byte Ed25519 seed. Not exported (see the module docs).
pub(crate) const WATCH_KEY: &[u8] = b"harvest:auto:watchkey";

/// One delegation per bridge.
pub(crate) fn delegation_key(bridge: &BridgeId) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}watchdeleg:{}",
        bs58::encode(bridge.0).into_string()
    )
    .into_bytes()
}

fn delegation_prefix() -> Vec<u8> {
    format!("{AUTO_PREFIX}watchdeleg:").into_bytes()
}

/// The first this many addresses from the counter must all be watched with
/// [`RENEW_MARGIN_BLOCKS`] to spare, or a request goes out. A contiguous
/// prefix, because I7 only ever invoices the NEXT address.
pub(crate) const REFILL_BELOW: usize = (MAX_UPCOMING_ADDRESSES / 2) as usize;

/// How far past what an invoice needs a watch must reach to count as fresh
/// when deciding whether to ask again: a day of blocks.
pub(crate) const RENEW_MARGIN_BLOCKS: u32 = 144;

/// How far past the tip a request asks the bridge to watch: nine days, so a
/// pool is renewed about weekly. Not the bridge's six-week maximum: every
/// watched script holds one of the Ghost Key's 1000 places at the bridge until
/// its height passes, and a store selling tens of orders a day would fill
/// them (review round 2 of freenet/harvest#179).
pub(crate) const REQUEST_AHEAD_BLOCKS: u32 = 9 * 144;

/// A request still in the inbox this long is taken to have left it: an inbox
/// whose floor stopped moving would otherwise hold it for ever.
pub(crate) const OUTSTANDING_MAX_MS: u64 = 2 * 60 * 60 * 1000;

/// Blocks after a request left the inbox within which its canary's watermark
/// must reach the tip it left at.
pub(crate) const CONFIRM_BLOCKS: u32 = 6;

/// How far past the tab's pool a canary is chosen, so the counter moving
/// while a request waits does not bring its canary into the tab's watches.
pub(crate) const CANARY_MARGIN: u32 = MAX_UPCOMING_ADDRESSES;

/// How often a watched request's canary is read again, and how far behind a
/// fresh tip it may be.
pub(crate) const PROBE_EVERY_MS: u64 = 60 * 60 * 1000;
pub(crate) const LIVE_LAG_BLOCKS: u32 = 6;

/// How long a contract must have been subscribed to, in this node run,
/// before a copy of it can show that something is NOT happening.
pub(crate) const SETTLE_MS: u64 = 20 * 60 * 1000;

/// How long a canary found unscanned may wait for its request.
pub(crate) const CANARY_VALID_MS: u64 = 10 * 60 * 1000;

/// Canary candidates found scanned in a row before the delegation waits
/// [`CANARY_DEFER_MS`] and starts again.
pub(crate) const MAX_CANARY_TRIES: u32 = 8;
pub(crate) const CANARY_DEFER_MS: u64 = 60 * 60 * 1000;

/// Requests in a row whose canary never showed before the delegation stalls.
pub(crate) const MAX_FAILURES: u32 = 3;

/// The wait after a failed request before the next, doubled per further
/// failure.
pub(crate) const FAILURE_BACKOFF_MS: u64 = 30 * 60 * 1000;

/// Bridges one delegate holds a delegation for.
pub(crate) const MAX_DELEGATIONS: usize = 8;

/// Scripts recorded as watched, per delegation: a bound, not a working
/// limit. Expired ones go first.
pub(crate) const WATCHED_CAP: usize = 64;

/// Contracts recorded as subscribed, per delegation.
pub(crate) const SUBSCRIBED_CAP: usize = 64;

/// Contracts ever subscribed to, per delegation, whose notifications are
/// dropped rather than forwarded.
pub(crate) const EVER_SUBSCRIBED_CAP: usize = 256;

const READ_MAGIC: [u8; 8] = *b"hvwinb04";

/// A delegation as this delegate holds it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Held {
    pub network: BitcoinNetwork,
    pub bridge: BridgeId,
    pub ghostkey: [u8; 32],
    /// Canonical, as every entry carries it.
    pub certificate_pem: String,
    pub delegation: Delegation,
    pub issued_mainnet_height: u32,
    pub inbox_contract_id: [u8; 32],
    /// The latest `made_at_ms` the tab reported, and the latest this
    /// delegate sent.
    pub ui_made_at_ms: u64,
    pub own_made_at_ms: u64,
    #[serde(default)]
    pub outstanding: Option<Outstanding>,
    #[serde(default)]
    pub unconfirmed: Option<Unconfirmed>,
    /// Confirmed: the request's canary showed.
    #[serde(default)]
    pub watched: Vec<Watched>,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_failure_ms: Option<u64>,
    /// When this delegation last read anything, for taking turns.
    #[serde(default)]
    pub last_read_ms: u64,
    #[serde(default)]
    pub last_probe_ms: Option<u64>,
    /// A canary found unscanned, waiting for its request.
    #[serde(default)]
    pub canary: Option<Canary>,
    /// The lowest address index not yet tried as a canary.
    #[serde(default)]
    pub canary_next: u32,
    #[serde(default)]
    pub canary_tries: u32,
    #[serde(default)]
    pub defer_until_ms: Option<u64>,
    /// Contracts whose SUBSCRIBE the node confirmed in this node run, and
    /// since when: what a verdict that something is NOT happening rests on.
    #[serde(default)]
    pub subscribed: Vec<([u8; 32], u64)>,
    /// Contracts a SUBSCRIBE was sent for and not yet answered.
    #[serde(default)]
    pub subscribing: Vec<[u8; 32]>,
    /// Every contract ever subscribed to (bounded), whose notifications
    /// need no handling.
    #[serde(default)]
    pub ever_subscribed: Vec<[u8; 32]>,
}

impl Held {
    pub(crate) fn stalled(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    fn fail(&mut self, now_ms: u64) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure_ms = Some(now_ms);
    }

    /// Past the backoff a failure imposes on the next request.
    fn may_send(&self, now_ms: u64) -> bool {
        !self.stalled()
            && self.last_failure_ms.is_none_or(|at| {
                let wait = FAILURE_BACKOFF_MS
                    .saturating_mul(1u64 << self.failures.saturating_sub(1).min(8));
                now_ms.saturating_sub(at) >= wait
            })
    }

    /// Whether a copy of `contract` can show that something is not happening.
    fn settled(&self, contract: &[u8; 32], now_ms: u64) -> bool {
        self.subscribed
            .iter()
            .any(|(id, since)| id == contract && now_ms.saturating_sub(*since) >= SETTLE_MS)
    }

    /// The node confirmed a SUBSCRIBE: settled from now, unless it already
    /// was (a repeat keeps its first time).
    fn note_subscribed(&mut self, contract: [u8; 32], now_ms: u64) {
        if self.subscribed.iter().any(|(id, _)| *id == contract) {
            return;
        }
        self.subscribed.push((contract, now_ms));
        while self.subscribed.len() > SUBSCRIBED_CAP {
            // The oldest one nothing here reads any more; the oldest of all
            // only if every one is in use.
            let at = self
                .subscribed
                .iter()
                .position(|(id, _)| !self.in_use(id))
                .unwrap_or(0);
            self.subscribed.remove(at);
        }
    }

    /// Whether a read of this delegation may still need `contract` settled.
    fn in_use(&self, contract: &[u8; 32]) -> bool {
        *contract == self.inbox_contract_id
            || self
                .unconfirmed
                .as_ref()
                .is_some_and(|u| u.canary_contract == *contract)
            || self.watched.iter().any(|w| w.canary_contract == *contract)
    }

    fn note_subscribing(&mut self, contract: [u8; 32]) {
        if !self.subscribing.contains(&contract) {
            self.subscribing.push(contract);
            while self.subscribing.len() > SUBSCRIBED_CAP {
                self.subscribing.remove(0);
            }
        }
        if !self.ever_subscribed.contains(&contract) {
            self.ever_subscribed.push(contract);
            while self.ever_subscribed.len() > EVER_SUBSCRIBED_CAP {
                self.ever_subscribed.remove(0);
            }
        }
    }
}

/// A canary found unscanned.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Canary {
    pub script: Vec<u8>,
    pub index: u32,
    pub at_ms: u64,
}

/// A request sent and not yet seen to leave the inbox. `scripts` ends with
/// `canary`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Outstanding {
    pub entry_key: EntryKey,
    pub mainnet_height: u32,
    pub scripts: Vec<Vec<u8>>,
    pub canary: Vec<u8>,
    #[serde(default)]
    pub canary_index: u32,
    pub until_height: u32,
    pub sent_at_ms: u64,
}

/// A request that left the inbox, waiting for its canary.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Unconfirmed {
    pub scripts: Vec<Vec<u8>>,
    pub canary: Vec<u8>,
    #[serde(default)]
    pub canary_index: u32,
    /// The canary's address contract.
    #[serde(default)]
    pub canary_contract: [u8; 32],
    pub until_height: u32,
    /// The tip when it was seen to leave: the watermark must reach it.
    pub since_tip: u32,
    /// Whether a removal was seen (read), or it merely left.
    pub removed: bool,
    pub left_at_ms: u64,
}

/// A script the bridge is watching for this delegate, the height asked, and
/// the canary that showed it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Watched {
    pub script: Vec<u8>,
    pub until_height: u32,
    pub canary: Vec<u8>,
    #[serde(default)]
    pub canary_contract: [u8; 32],
}

/// What a read this module sent is for.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
enum ReadKind {
    Inbox,
    /// The canary of the unconfirmed request.
    Confirm,
    /// The canary of the next watched address's request.
    Probe,
    /// A canary candidate, before a request.
    Canary,
    /// The inbox UPDATE that submits a request.
    Sent,
}

/// Carried through a GET this module sent.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct ReadContext {
    magic: [u8; 8],
    bridge: BridgeId,
    kind: ReadKind,
    /// For an address read: whose address contract it is.
    #[serde(default)]
    script: Vec<u8>,
    /// For a canary read: its address index.
    #[serde(default)]
    index: u32,
}

pub(crate) fn watch_key<S: SecretStore>(secrets: &S) -> Option<SigningKey> {
    let seed: [u8; 32] = secrets.get_secret(WATCH_KEY)?.try_into().ok()?;
    Some(SigningKey::from_bytes(&seed))
}

fn load_held<S: SecretStore>(secrets: &S, bridge: &BridgeId) -> Option<Held> {
    load(secrets, &delegation_key(bridge))
}

fn all_held<S: SecretStore>(secrets: &S) -> Vec<Held> {
    secrets
        .list_secrets(&delegation_prefix())
        .iter()
        .filter_map(|key| load(secrets, key))
        .collect()
}

fn store_held<S: SecretStore>(secrets: &mut S, held: &Held) -> bool {
    save(secrets, &delegation_key(&held.bridge), held)
}

const EXPORTED: &str = "this generation of the Harvest delegate has handed its keys to a newer \
                        one; reload Harvest to use it";

/// Answer one of the three watch-key requests. The caller has checked the
/// origin; anything else is answered with an error.
pub(crate) fn handle_request<S: SecretStore>(
    secrets: &mut S,
    request: HarvestDelegateRequest,
    now_ms: u64,
) -> HarvestDelegateResponse {
    match request {
        HarvestDelegateRequest::GetWatchKey => HarvestDelegateResponse::WatchKey {
            result: get_watch_key(secrets),
        },
        HarvestDelegateRequest::SetWatchDelegation { grant } => {
            let bridge = grant.bridge;
            HarvestDelegateResponse::WatchDelegation {
                bridge,
                result: set_delegation(secrets, *grant, now_ms),
            }
        }
        HarvestDelegateRequest::UpdateWatchDelegation {
            bridge,
            inbox_contract_id,
            last_made_at_ms,
        } => HarvestDelegateResponse::WatchDelegation {
            bridge,
            result: update_delegation(secrets, bridge, inbox_contract_id, last_made_at_ms, now_ms),
        },
        _ => HarvestDelegateResponse::Error {
            message: "not a watch-key request".into(),
        },
    }
}

/// [`harvest_common::HarvestDelegateRequest::GetWatchKey`]: the watch key's
/// public half, the key made and kept on first asking.
pub(crate) fn get_watch_key<S: SecretStore>(secrets: &mut S) -> Result<[u8; 32], String> {
    if secrets.has_secret(EXPORTED_KEY) {
        return Err(EXPORTED.into());
    }
    if let Some(key) = watch_key(secrets) {
        return Ok(key.verifying_key().to_bytes());
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("no randomness for a watch key: {e}"))?;
    if !secrets.set_secret(WATCH_KEY, &seed) {
        return Err("the node refused to store the watch key".into());
    }
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

/// [`harvest_common::HarvestDelegateRequest::SetWatchDelegation`]: check the
/// grant and keep it.
///
/// Checked here: the delegation names this delegate's watch key and the
/// bridge, the Ghost Key signed it as a web app's or a delegate's request (as
/// the inbox contract requires), and the certificate certifies that Ghost Key
/// (every entry is sealed to it). Not checked: the certificate's chain to
/// Freenet's master key, which the inbox contract checks on every entry.
pub(crate) fn set_delegation<S: SecretStore>(
    secrets: &mut S,
    grant: WatchDelegationGrant,
    now_ms: u64,
) -> Result<WatchDelegationStatus, String> {
    if secrets.has_secret(EXPORTED_KEY) {
        return Err(EXPORTED.into());
    }
    let sk = watch_key(secrets).ok_or("this delegate has no watch key yet; ask for it first")?;
    if grant.delegation_scoped_payload.len() > MAX_DELEGATION_BYTES {
        return Err("the delegation is too large".into());
    }
    let scoped: ghostkey_common::ScopedPayload = from_cbor(&grant.delegation_scoped_payload)
        .map_err(|_| "the delegation does not decode".to_string())?;
    match scoped.requestor {
        ghostkey_common::SignatureRequestor::WebApp(_)
        | ghostkey_common::SignatureRequestor::Delegate(_) => {}
        _ => return Err("the delegation was requested by an unknown kind of caller".into()),
    }
    let delegation =
        Delegation::from_sign_result(grant.delegation_scoped_payload, grant.delegation_signature);
    let body = delegation
        .body()
        .map_err(|_| "the delegation does not decode".to_string())?;
    if body.bridge != grant.bridge {
        return Err("the delegation is for another bridge".into());
    }
    if body.watch_key.0 != sk.verifying_key().to_bytes() {
        return Err("the delegation names another watch key".into());
    }
    // Harvest's tab issues delegations that do not expire; one that does
    // would stop being honoured with nothing here noticing until its requests
    // failed.
    if body.expires_mainnet_height.is_some() {
        return Err("a watch delegation for Harvest must not expire".into());
    }
    let ghostkey = VerifyingKey::from_bytes(&grant.ghostkey)
        .map_err(|_| "the Ghost Key is not a valid key".to_string())?;
    let signature: [u8; 64] = delegation
        .signature
        .as_ref()
        .try_into()
        .map_err(|_| "the delegation's signature is not 64 bytes".to_string())?;
    ghostkey
        .verify_strict(
            &delegation.scoped_payload,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "the Ghost Key did not sign this delegation".to_string())?;
    // Built exactly as a real entry is, which canonicalises the certificate
    // and reads the Ghost Key it certifies.
    let probe = WireEntry::delegated(
        grant.certificate_pem,
        delegation.clone(),
        &sk,
        &InboxEntryBody {
            bridge: grant.bridge,
            mainnet_height: body.issued_mainnet_height,
            sealed: Sealed {
                ephemeral: EphemeralKey::default(),
                nonce: ByteBuf(vec![0; 12]),
                ciphertext: ByteBuf(Vec::new()),
            },
        },
    )?;
    if probe.entry.ghostkey.0 != grant.ghostkey {
        return Err("the certificate is for another Ghost Key".into());
    }

    let held = load_held(secrets, &grant.bridge);
    if held.is_none() && all_held(secrets).len() >= MAX_DELEGATIONS {
        return Err(format!(
            "this delegate holds watch delegations for at most {MAX_DELEGATIONS} bridges"
        ));
    }
    // The same Ghost Key's earlier work carries over; another's does not.
    let same = held.filter(|h| h.ghostkey == grant.ghostkey);
    if same
        .as_ref()
        .is_some_and(|h| h.issued_mainnet_height > body.issued_mainnet_height)
    {
        return Err("a newer delegation is already held for this bridge".into());
    }
    // Only a LATER delegation clears the record of failures: the bridge
    // prefers it. One at the same height is the same standing, and clearing
    // a stall for it would put a superseded delegation back to work.
    let later = same
        .as_ref()
        .is_none_or(|h| body.issued_mainnet_height > h.issued_mainnet_height);
    let same_inbox = same
        .as_ref()
        .is_some_and(|h| h.inbox_contract_id == grant.inbox_contract_id);
    let record = Held {
        network: grant.network,
        bridge: grant.bridge,
        ghostkey: grant.ghostkey,
        certificate_pem: probe.certificate_pem,
        delegation,
        issued_mainnet_height: body.issued_mainnet_height,
        inbox_contract_id: grant.inbox_contract_id,
        ui_made_at_ms: same
            .as_ref()
            .map_or(0, |h| h.ui_made_at_ms)
            .max(grant.last_made_at_ms),
        own_made_at_ms: same.as_ref().map_or(0, |h| h.own_made_at_ms),
        // A request sent to another inbox cannot be read back.
        outstanding: same
            .as_ref()
            .filter(|_| same_inbox)
            .and_then(|h| h.outstanding.clone()),
        unconfirmed: same.as_ref().and_then(|h| h.unconfirmed.clone()),
        watched: same.as_ref().map(|h| h.watched.clone()).unwrap_or_default(),
        failures: if later {
            0
        } else {
            same.as_ref().map_or(0, |h| h.failures)
        },
        last_failure_ms: if later {
            None
        } else {
            same.as_ref().and_then(|h| h.last_failure_ms)
        },
        last_read_ms: same.as_ref().map_or(0, |h| h.last_read_ms),
        last_probe_ms: same.as_ref().and_then(|h| h.last_probe_ms),
        canary: None,
        canary_next: same.as_ref().map_or(0, |h| h.canary_next),
        canary_tries: 0,
        defer_until_ms: None,
        subscribed: same
            .as_ref()
            .map(|h| h.subscribed.clone())
            .unwrap_or_default(),
        subscribing: same
            .as_ref()
            .map(|h| h.subscribing.clone())
            .unwrap_or_default(),
        ever_subscribed: same
            .as_ref()
            .map(|h| h.ever_subscribed.clone())
            .unwrap_or_default(),
    };
    if !store_held(secrets, &record) {
        return Err("the node refused to store the delegation".into());
    }
    Ok(status_of(secrets, &record, now_ms))
}

/// [`harvest_common::HarvestDelegateRequest::UpdateWatchDelegation`].
pub(crate) fn update_delegation<S: SecretStore>(
    secrets: &mut S,
    bridge: BridgeId,
    inbox_contract_id: [u8; 32],
    last_made_at_ms: u64,
    now_ms: u64,
) -> Result<WatchDelegationStatus, String> {
    if secrets.has_secret(EXPORTED_KEY) {
        return Err(EXPORTED.into());
    }
    let mut held =
        load_held(secrets, &bridge).ok_or("no watch delegation is held for this bridge")?;
    if held.inbox_contract_id != inbox_contract_id {
        held.inbox_contract_id = inbox_contract_id;
        // Sent to the old inbox, it cannot be read back from the new one,
        // and its failure to show is not the delegation's.
        held.outstanding = None;
        held.canary = None;
    }
    held.ui_made_at_ms = held.ui_made_at_ms.max(last_made_at_ms);
    if !store_held(secrets, &held) {
        return Err("the node refused to store the delegation".into());
    }
    Ok(status_of(secrets, &held, now_ms))
}

/// The delegation this store's arm can use, as the tab is told it.
pub(crate) fn status_for_arm<S: SecretStore>(
    secrets: &S,
    arm: &AutoInvoiceArm,
    now_ms: u64,
) -> Option<WatchDelegationStatus> {
    all_held(secrets)
        .into_iter()
        .find(|h| h.network == arm.network && arm.trusted_bridges.contains(&h.bridge))
        .map(|h| status_of(secrets, &h, now_ms))
}

fn status_of<S: SecretStore>(secrets: &S, held: &Held, now_ms: u64) -> WatchDelegationStatus {
    let watched = fresh_tip(secrets, held.network, now_ms).map_or(0, |tip| {
        pool(secrets, held.network)
            .iter()
            .take_while(|s| covers(held, s, tip.anchor.height))
            .count() as u32
    });
    WatchDelegationStatus {
        bridge: held.bridge,
        ghostkey: held.ghostkey,
        issued_mainnet_height: held.issued_mainnet_height,
        inbox_contract_id: held.inbox_contract_id,
        made_at_ms: held.ui_made_at_ms.max(held.own_made_at_ms),
        watched,
        outstanding: held.outstanding.is_some() || held.unconfirmed.is_some(),
        stalled: held.stalled(),
    }
}

/// Whether the bridge is confirmed watching `script` for this delegation
/// through a horizon an invoice issued at `tip_height` can rely on.
fn covers(held: &Held, script: &[u8], tip_height: u32) -> bool {
    held.watched.iter().any(|w| {
        w.script == script && tip_height.saturating_add(WATCH_NEEDED_BLOCKS) <= w.until_height
    })
}

/// I7's second source: the scripts this delegate's own confirmed requests
/// have the bridge watching far enough past `tip_height`, each with the
/// horizon asked, for a store on `network` trusting `bridges`: the union
/// across every delegation it holds for them. A stalled delegation still
/// counts what its probes keep finding scanned; a probe that finds it not
/// scanned clears it.
pub(crate) fn delegated_watched<S: SecretStore>(
    secrets: &S,
    network: BitcoinNetwork,
    bridges: &[BridgeId],
    tip_height: u32,
) -> Vec<(Vec<u8>, u32)> {
    all_held(secrets)
        .iter()
        .filter(|h| h.network == network && bridges.contains(&h.bridge))
        .flat_map(|h| {
            h.watched
                .iter()
                .filter(|w| covers(h, &w.script, tip_height))
                .map(|w| (w.script.clone(), w.until_height))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The delegate's next addresses, as scripts, from the counter on.
fn pool<S: SecretStore>(secrets: &S, network: BitcoinNetwork) -> Vec<Vec<u8>> {
    let Some(xpub) = crate::bitcoin::load_payment_xpub(secrets) else {
        return Vec::new();
    };
    if xpub.network != network {
        return Vec::new();
    }
    crate::bitcoin::upcoming_addresses(&xpub, MAX_UPCOMING_ADDRESSES)
        .map(|upcoming| upcoming.into_iter().map(|a| a.script_pubkey).collect())
        .unwrap_or_default()
}

/// The next canary candidate, and its index: unscanned BY CONSTRUCTION.
/// Past the tab's pool (the next `MAX_UPCOMING_ADDRESSES` from the counter,
/// exactly what the tab prewatches) by [`CANARY_MARGIN`] more, so the counter
/// moving while a request waits leaves it outside; past every canary this
/// delegate has used; and not one an arm names as the tab's. Nobody else asks
/// for such an address, so its address contract normally does not even exist
/// yet: the bridge creates one only when it publishes for a watched script.
fn next_canary<S: SecretStore>(secrets: &S, held: &Held) -> Option<(u32, Vec<u8>)> {
    let xpub = crate::bitcoin::load_payment_xpub(secrets)?;
    if xpub.network != held.network {
        return None;
    }
    let chain = crate::bip32::AccountXpub::parse(&xpub.xpub)
        .and_then(|a| a.external_chain())
        .ok()?;
    let tabs: Vec<Vec<u8>> = armed_for(secrets, held)
        .into_iter()
        .flat_map(|r| r.arm.watched_scripts)
        .collect();
    let first = canary_floor(xpub.next_index).max(held.canary_next);
    (first..first.saturating_add(64)).find_map(|index| {
        let script = chain.script_at(index).ok()?;
        (!tabs.contains(&script)).then_some((index, script))
    })
}

/// The lowest index a canary may have with the counter at `next_index`.
fn canary_floor(next_index: u32) -> u32 {
    next_index
        .saturating_add(MAX_UPCOMING_ADDRESSES)
        .saturating_add(CANARY_MARGIN)
}

/// Whether a canary could by now be one the tab watches: the counter moved it
/// into the tab's pool, or an arm names it. Its watermark then shows nothing
/// about this delegate's request.
fn canary_compromised<S: SecretStore>(secrets: &S, held: &Held, index: u32, script: &[u8]) -> bool {
    let in_pool = crate::bitcoin::load_payment_xpub(secrets)
        .is_none_or(|xpub| index < xpub.next_index.saturating_add(MAX_UPCOMING_ADDRESSES));
    in_pool
        || armed_for(secrets, held)
            .iter()
            .any(|r| r.arm.watched_scripts.iter().any(|s| s == script))
}

fn fresh_tip<S: SecretStore>(
    secrets: &S,
    network: BitcoinNetwork,
    now_ms: u64,
) -> Option<TipCache> {
    let tip: TipCache = load(secrets, &tip_key(network))?;
    (now_ms.saturating_sub(u64::from(tip.block_time) * 1000) <= TIP_MAX_AGE_MS).then_some(tip)
}

/// The armed stores this delegation serves.
fn armed_for<S: SecretStore>(secrets: &S, held: &Held) -> Vec<ArmRecord> {
    arms(secrets)
        .into_iter()
        .filter(|r| r.arm.network == held.network && r.arm.trusted_bridges.contains(&held.bridge))
        .collect()
}

/// The next addresses to ask the bridge to watch now, or none: none unless a
/// store armed here uses this delegation, and none while the first
/// [`REFILL_BELOW`] from the counter are all watched with
/// [`RENEW_MARGIN_BLOCKS`] to spare, by this delegate's confirmed requests or
/// by the tab's (the arm's).
fn refill_scripts<S: SecretStore>(
    secrets: &S,
    held: &Held,
    tip_height: u32,
    now_ms: u64,
) -> Vec<Vec<u8>> {
    let armed = armed_for(secrets, held);
    if armed.is_empty() {
        return Vec::new();
    }
    let threshold = tip_height
        .saturating_add(WATCH_NEEDED_BLOCKS)
        .saturating_add(RENEW_MARGIN_BLOCKS);
    let fresh = |script: &Vec<u8>| {
        held.watched
            .iter()
            .any(|w| w.script == *script && w.until_height >= threshold)
            || armed.iter().any(|r| {
                now_ms.saturating_add(WATCH_NEEDED_MS) < r.watched_until_ms
                    && r.arm.watched_until_height.is_some_and(|h| h >= threshold)
                    && r.arm.watched_scripts.contains(script)
            })
    };
    let pool = pool(secrets, held.network);
    if pool.iter().take(REFILL_BELOW).all(fresh) {
        return Vec::new();
    }
    pool.into_iter()
        .filter(|s| !fresh(s))
        // Room for the canary.
        .take(MAX_SCRIPTS_PER_REQUEST - 1)
        .collect()
}

/// The address contract the bridge publishes `script`'s watermark to: the
/// arm's generation, with this delegation's bridge as the one trusted, as the
/// bridge writes it.
fn address_contract(held: &Held, arm: &AutoInvoiceArm, script: &[u8]) -> Option<[u8; 32]> {
    let params = freenet_bitcoin_common::to_cbor(&address_params(held, arm, script)).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&arm.address_code_hash);
    hasher.update(&params);
    Some(*hasher.finalize().as_bytes())
}

pub(crate) fn address_params(
    held: &Held,
    arm: &AutoInvoiceArm,
    script: &[u8],
) -> BitcoinAddressParameters {
    BitcoinAddressParameters {
        network: arm.network,
        script_pubkey: script.to_vec(),
        trusted_bridges: vec![held.bridge],
        pow_floor: arm.network.default_pow_floor(),
    }
}

/// What this delegation should read now, if anything.
fn due_read<S: SecretStore>(
    secrets: &S,
    held: &Held,
    now_ms: u64,
) -> Option<([u8; 32], ReadContext)> {
    let context = |kind, script: Vec<u8>, index| ReadContext {
        magic: READ_MAGIC,
        bridge: held.bridge,
        kind,
        script,
        index,
    };
    let arm = armed_for(secrets, held).into_iter().next().map(|r| r.arm)?;
    let address = |script: &Vec<u8>| address_contract(held, &arm, script);
    if let Some(unconfirmed) = &held.unconfirmed {
        let script = unconfirmed.canary.clone();
        return Some((address(&script)?, context(ReadKind::Confirm, script, 0)));
    }
    if held.outstanding.is_some() {
        return Some((
            held.inbox_contract_id,
            context(ReadKind::Inbox, Vec::new(), 0),
        ));
    }
    let tip = fresh_tip(secrets, held.network, now_ms)?;
    // The probe runs stalled or not: it is what withdraws the watches.
    let next = pool(secrets, held.network).into_iter().next();
    let probe = next.and_then(|next| {
        held.watched
            .iter()
            .find(|w| w.script == next && covers(held, &w.script, tip.anchor.height))
            .map(|w| w.canary.clone())
    });
    if let Some(canary) = probe {
        if held
            .last_probe_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= PROBE_EVERY_MS)
        {
            return Some((address(&canary)?, context(ReadKind::Probe, canary, 0)));
        }
    }
    if !held.may_send(now_ms)
        || held.defer_until_ms.is_some_and(|until| now_ms < until)
        || refill_scripts(secrets, held, tip.anchor.height, now_ms).is_empty()
    {
        return None;
    }
    if held
        .canary
        .as_ref()
        .is_some_and(|c| now_ms.saturating_sub(c.at_ms) < CANARY_VALID_MS)
    {
        return Some((
            held.inbox_contract_id,
            context(ReadKind::Inbox, Vec::new(), 0),
        ));
    }
    let (index, script) = next_canary(secrets, held)?;
    Some((address(&script)?, context(ReadKind::Canary, script, index)))
}

/// A GET of `id` carrying `context`, and a SUBSCRIBE to it: the subscription
/// keeps the node's local copy, which later GETs are answered from, following
/// the network, and the node's Ok to it is what makes a copy settled
/// ([`on_subscribed`]). On a contract the node already holds it costs no
/// network operation. A canary candidate is read without one: most likely it
/// is a contract nobody has created, and one found scanned is skipped for
/// good.
fn read_msgs(
    held: &mut Held,
    id: [u8; 32],
    context: &ReadContext,
    _now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    let Ok(bytes) = to_cbor(context) else {
        return Vec::new();
    };
    let mut get = GetContractRequest::new(ContractInstanceId::new(id));
    get.context = DelegateContext::new(bytes);
    let mut out = vec![OutboundDelegateMsg::GetContractRequest(get)];
    if context.kind != ReadKind::Canary {
        held.note_subscribing(id);
        out.push(OutboundDelegateMsg::SubscribeContractRequest(
            SubscribeContractRequest::new(ContractInstanceId::new(id)),
        ));
    }
    out
}

/// The node answered a SUBSCRIBE. `true` when it was one this module sent:
/// only an Ok makes the contract settled, from now.
pub(crate) fn on_subscribed<S: SecretStore>(
    secrets: &mut S,
    contract: &[u8; 32],
    result: &Result<(), String>,
    now_ms: u64,
) -> bool {
    let mut ours = false;
    for mut held in all_held(secrets) {
        if !held.subscribing.contains(contract) {
            continue;
        }
        ours = true;
        held.subscribing.retain(|id| id != contract);
        if result.is_ok() {
            held.note_subscribed(*contract, now_ms);
        }
        store_held(secrets, &held);
    }
    ours
}

/// A wake-up's work: one read, for the delegation that has gone longest
/// without one among those that have something to read.
pub(crate) fn on_wakeup<S: SecretStore>(secrets: &mut S, now_ms: u64) -> Vec<OutboundDelegateMsg> {
    if secrets.has_secret(EXPORTED_KEY) || watch_key(secrets).is_none() {
        return Vec::new();
    }
    let mut due: Vec<(Held, [u8; 32], ReadContext)> = Vec::new();
    for mut held in all_held(secrets) {
        // A store unarmed since: what was waiting cannot be read or credited
        // any more. Dropped, not counted as a failure.
        if armed_for(secrets, &held).is_empty()
            && (held.unconfirmed.is_some() || held.outstanding.is_some())
        {
            held.unconfirmed = None;
            held.outstanding = None;
            store_held(secrets, &held);
            continue;
        }
        if let Some((id, context)) = due_read(secrets, &held, now_ms) {
            due.push((held, id, context));
        }
    }
    due.sort_by_key(|(held, _, _)| held.last_read_ms);
    let Some((mut held, id, context)) = due.into_iter().next() else {
        return Vec::new();
    };
    held.last_read_ms = now_ms;
    let out = read_msgs(&mut held, id, &context, now_ms);
    if !store_held(secrets, &held) {
        return Vec::new();
    }
    out
}

/// The node started, or this delegate was installed: subscriptions made in
/// an earlier run may be gone, so none counts as settled any more.
pub(crate) fn on_node_started<S: SecretStore>(secrets: &mut S) {
    for mut held in all_held(secrets) {
        if !held.subscribed.is_empty() || !held.subscribing.is_empty() {
            held.subscribed.clear();
            held.subscribing.clear();
            store_held(secrets, &held);
        }
    }
}

/// Whether `contract` is one this module ever subscribed to (within
/// [`EVER_SUBSCRIBED_CAP`]): its notifications need no handling, since every
/// verdict comes from a GET, and are not forwarded as a `ContractUpdate`.
pub(crate) fn subscribed_to<S: SecretStore>(secrets: &S, contract: &[u8; 32]) -> bool {
    all_held(secrets)
        .iter()
        .any(|h| h.ever_subscribed.contains(contract))
}

/// A GET [`on_wakeup`] (or a canary read) sent has answered. `None` when the
/// context is not this module's.
pub(crate) fn on_inbox_read<S: SecretStore>(
    secrets: &mut S,
    contract_id: &[u8; 32],
    state: Option<&[u8]>,
    context: &[u8],
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    let read: ReadContext = from_cbor(context).ok()?;
    if read.magic != READ_MAGIC {
        return None;
    }
    if secrets.has_secret(EXPORTED_KEY) {
        return Some(Vec::new());
    }
    let Some(held) = load_held(secrets, &read.bridge) else {
        return Some(Vec::new());
    };
    let out = match read.kind {
        ReadKind::Inbox if held.inbox_contract_id == *contract_id => {
            on_inbox(secrets, held, state, now_ms)
        }
        ReadKind::Inbox => None,
        ReadKind::Confirm | ReadKind::Probe | ReadKind::Canary => {
            on_address(secrets, held, &read, contract_id, state, now_ms)
        }
        ReadKind::Sent => None,
    };
    Some(out.unwrap_or_default())
}

/// `script`'s watermark by this delegation's bridge, as the bridge signed it.
fn watermark(held: &Held, arm: &AutoInvoiceArm, script: &[u8], state: &[u8]) -> Option<u32> {
    let state: freenet_bitcoin_common::BitcoinAddressStateV1 =
        freenet_bitcoin_common::from_cbor(state).ok()?;
    let claim = state.claims.scanned.get(&held.bridge)?;
    if claim.bridge != held.bridge {
        return None;
    }
    let body = claim.verify(&address_params(held, arm, script)).ok()?;
    matches!(body.claim, freenet_bitcoin_common::Claim::ScannedTo).then_some(body.as_of.height)
}

fn on_address<S: SecretStore>(
    secrets: &mut S,
    mut held: Held,
    read: &ReadContext,
    contract_id: &[u8; 32],
    state: Option<&[u8]>,
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    // Judged only against a fresh tip: a bridge that is down stops its tip
    // contract too, and nothing is counted against the delegation then.
    let tip = fresh_tip(secrets, held.network, now_ms)?;
    let arm = armed_for(secrets, &held)
        .into_iter()
        .next()
        .map(|r| r.arm)?;
    if address_contract(&held, &arm, &read.script) != Some(*contract_id) {
        return None;
    }
    let before = held.clone();
    let seen = state.and_then(|state| watermark(&held, &arm, &read.script, state));
    // What this copy can show: that the script IS scanned (at `seen`), from
    // any copy; that it is NOT, only from a settled one with a state.
    let settled = state.is_some() && held.settled(contract_id, now_ms);
    let scanned_now = seen.is_some_and(|h| h.saturating_add(LIVE_LAG_BLOCKS) >= tip.anchor.height);
    let mut out = Vec::new();
    match read.kind {
        ReadKind::Confirm => {
            let pending = held.unconfirmed.clone()?;
            if pending.canary != read.script {
                return None;
            }
            if canary_compromised(secrets, &held, pending.canary_index, &pending.canary) {
                // The tab may be what scans it now: no evidence either way.
                // Dropped uncredited, not a failure; the next request gets a
                // new canary.
                held.unconfirmed = None;
            } else if seen.is_some_and(|h| h >= pending.since_tip) {
                for script in pending.scripts {
                    match held.watched.iter_mut().find(|w| w.script == script) {
                        Some(w) => {
                            w.until_height = w.until_height.max(pending.until_height);
                            w.canary = pending.canary.clone();
                            w.canary_contract = pending.canary_contract;
                        }
                        None => held.watched.push(Watched {
                            script,
                            until_height: pending.until_height,
                            canary: pending.canary.clone(),
                            canary_contract: pending.canary_contract,
                        }),
                    }
                }
                prune_watched(&mut held, tip.anchor.height);
                held.unconfirmed = None;
                held.failures = 0;
                held.last_failure_ms = None;
                held.last_probe_ms = Some(now_ms);
            } else if tip.anchor.height >= pending.since_tip.saturating_add(CONFIRM_BLOCKS) {
                // The request left the inbox, a fresh tip is past the window,
                // and its canary shows nothing: the bridge did not apply it.
                // A canary nobody else asks for has no address contract until
                // the bridge publishes for it, so an absent state IS the
                // evidence here. A read outage looks the same; it costs a
                // backoff, and a stall only stops sending.
                held.unconfirmed = None;
                held.fail(now_ms);
            }
        }
        ReadKind::Probe => {
            if settled && !scanned_now {
                // The bridge stopped scanning what this delegation asked for:
                // revoked, or lost. Nothing asked through it counts any more.
                held.watched.clear();
                held.fail(now_ms);
                held.last_probe_ms = Some(now_ms);
            } else if scanned_now {
                held.last_probe_ms = Some(now_ms);
            }
            // Otherwise no evidence: asked again at the next wake-up.
        }
        ReadKind::Canary => {
            if scanned_now {
                // Someone has it watched: it cannot show this request.
                held.canary_next = read.index.saturating_add(1);
                held.canary_tries = held.canary_tries.saturating_add(1);
                if held.canary_tries >= MAX_CANARY_TRIES {
                    held.canary_tries = 0;
                    held.defer_until_ms = Some(now_ms.saturating_add(CANARY_DEFER_MS));
                }
            } else {
                // Unscanned by construction (see `next_canary`); a read that
                // finds no contract, or no fresh watermark in one, agrees.
                held.canary = Some(Canary {
                    script: read.script.clone(),
                    index: read.index,
                    at_ms: now_ms,
                });
                held.canary_tries = 0;
                // Straight on to the inbox, in this run.
                let context = ReadContext {
                    magic: READ_MAGIC,
                    bridge: held.bridge,
                    kind: ReadKind::Inbox,
                    script: Vec::new(),
                    index: 0,
                };
                let inbox = held.inbox_contract_id;
                out = read_msgs(&mut held, inbox, &context, now_ms);
            }
        }
        ReadKind::Sent => {}
        ReadKind::Inbox => {}
    }
    if held != before && !store_held(secrets, &held) {
        return None;
    }
    Some(out)
}

/// Keep the watched list bounded: expired entries go, then the nearest
/// horizons.
fn prune_watched(held: &mut Held, tip_height: u32) {
    held.watched.retain(|w| w.until_height >= tip_height);
    if held.watched.len() > WATCHED_CAP {
        held.watched
            .sort_by_key(|w| std::cmp::Reverse(w.until_height));
        held.watched.truncate(WATCHED_CAP);
    }
}

/// Whether the bridge signed a removal naming `key`, dated `height`.
fn removed_by_bridge(state: &InboxStateV1, bridge: &BridgeId, key: &EntryKey, height: u32) -> bool {
    let prefix = key.removal_prefix();
    state.removals.values().any(|batch| {
        batch.height == height
            && batch.prefixes().any(|p| p == prefix)
            && batch.verify(bridge).is_ok()
    })
}

fn on_inbox<S: SecretStore>(
    secrets: &mut S,
    mut held: Held,
    state: Option<&[u8]>,
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    let before = held.clone();
    let tip = fresh_tip(secrets, held.network, now_ms);
    // Only a floor this bridge signed dates anything.
    let state = state
        .and_then(|s| InboxStateV1::decode_canonical(s).ok())
        .filter(|s| {
            s.floor
                .as_ref()
                .is_some_and(|f| f.verify(&held.bridge).is_ok())
        });

    if let Some(sent) = held.outstanding.clone() {
        let floor = state
            .as_ref()
            .and_then(|s| s.floor.as_ref())
            .map(|f| f.height);
        let removed = state.as_ref().is_some_and(|s| {
            removed_by_bridge(s, &held.bridge, &sent.entry_key, sent.mainnet_height)
        });
        let passed = floor.is_some_and(|f| f > sent.mainnet_height);
        let timed_out = now_ms.saturating_sub(sent.sent_at_ms) >= OUTSTANDING_MAX_MS;
        if removed || passed || timed_out {
            let Some(tip) = tip else {
                // Without a fresh tip there is no height to confirm against:
                // leave it outstanding.
                return save_if_changed(secrets, &before, &held).then(Vec::new);
            };
            held.outstanding = None;
            let canary_contract = armed_for(secrets, &held)
                .first()
                .and_then(|r| address_contract(&held, &r.arm, &sent.canary))
                .unwrap_or_default();
            held.unconfirmed = Some(Unconfirmed {
                scripts: sent.scripts,
                canary: sent.canary,
                canary_index: sent.canary_index,
                canary_contract,
                until_height: sent.until_height,
                since_tip: tip.anchor.height,
                removed,
                left_at_ms: now_ms,
            });
        }
        // Either way nothing is sent until it is confirmed or failed.
        return save_if_changed(secrets, &before, &held).then(Vec::new);
    }
    let inbox = held.inbox_contract_id;
    let canary = held
        .canary
        .clone()
        .filter(|c| now_ms.saturating_sub(c.at_ms) < CANARY_VALID_MS);
    // A request needs: nothing waiting, no backoff, a canary just found
    // unscanned, a fresh tip, and a settled copy of the inbox, so its date is
    // the live floor's rather than an old copy's (a misdated entry is dropped
    // unread, and would count as a failure).
    let ready = held.unconfirmed.is_none()
        && held.may_send(now_ms)
        && canary.is_some()
        && held.settled(&inbox, now_ms);
    let (Some(state), Some(tip), Some(canary), true) = (state, tip, canary, ready) else {
        return save_if_changed(secrets, &before, &held).then(Vec::new);
    };
    let floor = state.floor.clone()?;
    let mut out = Vec::new();
    let mut scripts = refill_scripts(secrets, &held, tip.anchor.height, now_ms);
    if !scripts.is_empty() {
        // The canary goes LAST: the bridge applies a request's scripts in
        // order and counts the rest refused once the Ghost Key's cap is
        // reached (the count only grows within a request), so the canary
        // scanned means every script before it was applied too.
        scripts.retain(|s| *s != canary.script);
        scripts.push(canary.script.clone());
        if let Some((mut sent, delta)) =
            build_request(secrets, &held, &floor, &tip, scripts, now_ms)
        {
            sent.outstanding.canary_index = canary.index;
            held.own_made_at_ms = sent.made_at_ms;
            held.outstanding = Some(sent.outstanding);
            held.canary = None;
            held.canary_next = canary.index.saturating_add(1);
            let mut update = UpdateContractRequest::new(
                ContractInstanceId::new(inbox),
                UpdateData::Delta(StateDelta::from(delta)),
            );
            if let Ok(context) = to_cbor(&ReadContext {
                magic: READ_MAGIC,
                bridge: held.bridge,
                kind: ReadKind::Sent,
                script: Vec::new(),
                index: 0,
            }) {
                update.context = DelegateContext::new(context);
            }
            out.push(OutboundDelegateMsg::UpdateContractRequest(update));
        }
    }
    // Recorded before anything is sent: a request sent but not recorded
    // would be followed by a second one into the watch key's one place.
    if !save_if_changed(secrets, &before, &held) {
        return None;
    }
    Some(out)
}

/// The node answered the inbox UPDATE that submitted a request. `None` when
/// the context is not this module's. Refused (the contract would not take the
/// entry): the request was never sent, so it is forgotten, not counted as a
/// failure, and the next wake-up tries again with a new canary.
pub(crate) fn on_update_answer<S: SecretStore>(
    secrets: &mut S,
    result: &Result<(), String>,
    context: &[u8],
) -> Option<Vec<OutboundDelegateMsg>> {
    let read: ReadContext = from_cbor(context).ok()?;
    if read.magic != READ_MAGIC || read.kind != ReadKind::Sent {
        return None;
    }
    if result.is_err() {
        if let Some(mut held) = load_held(secrets, &read.bridge) {
            if held.outstanding.take().is_some() {
                store_held(secrets, &held);
            }
        }
    }
    Some(Vec::new())
}

fn save_if_changed<S: SecretStore>(secrets: &mut S, before: &Held, now: &Held) -> bool {
    before == now || store_held(secrets, now)
}

struct Built {
    outstanding: Outstanding,
    made_at_ms: u64,
}

/// One delegated Watch for `scripts` (the canary last): sealed to the bridge
/// under the seller's Ghost Key, dated against `floor`, signed by the watch
/// key, and wrapped as the inbox update that submits it.
fn build_request<S: SecretStore>(
    secrets: &S,
    held: &Held,
    floor: &SignedFloor,
    tip: &TipCache,
    scripts: Vec<Vec<u8>>,
    now_ms: u64,
) -> Option<(Built, Vec<u8>)> {
    let sk = watch_key(secrets)?;
    let canary = scripts.last()?.clone();
    let mainnet_height = sender_height(floor.height);
    // The inbox refuses an entry dated before its delegation.
    if mainnet_height < held.issued_mainnet_height {
        return None;
    }
    let made_at_ms = now_ms
        .max(held.ui_made_at_ms.saturating_add(1))
        .max(held.own_made_at_ms.saturating_add(1));
    let until_height = tip
        .anchor
        .height
        .saturating_add(REQUEST_AHEAD_BLOCKS.min(MAX_WATCH_AHEAD_BLOCKS));
    let request = InboxRequest {
        action: Action::Watch,
        network: held.network,
        scripts: scripts.iter().cloned().map(ByteBuf).collect(),
        // Fresh addresses: nothing before the tip pays to them.
        scan_from_height: Some(tip.anchor.height),
        made_at_ms,
        watch_until_height: Some(until_height),
        // Ignored from a watch key: only the Ghost Key revokes.
        revoke_watch_keys_through: None,
    };
    let sealed = freenet_bitcoin_inbox::seal::seal(
        &held.bridge,
        &GhostkeyId(held.ghostkey),
        mainnet_height,
        &request,
    )
    .ok()?;
    let entry = WireEntry::delegated(
        held.certificate_pem.clone(),
        held.delegation.clone(),
        &sk,
        &InboxEntryBody {
            bridge: held.bridge,
            mainnet_height,
            sealed,
        },
    )
    .ok()?;
    let entry_key = entry.entry.key();
    let delta =
        freenet_bitcoin_common::to_cbor(&InboxDelta::submission(Some(floor.clone()), entry))
            .ok()?;
    Some((
        Built {
            outstanding: Outstanding {
                entry_key,
                mainnet_height,
                scripts,
                canary,
                canary_index: 0,
                until_height,
                sent_at_ms: now_ms,
            },
            made_at_ms,
        },
        delta,
    ))
}

/// A real inbox, a test Ghost Key authority and a delegate set up to use
/// them, shared with `auto_invoice`'s tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::auto_invoice::{arm_key, ArmRecord};
    use crate::secrets::MemSecrets;
    use freenet_bitcoin_common::{BlockAnchor, BlockHash};
    use freenet_bitcoin_inbox::test_support::{TestAuthority, TestGhostkey};
    use freenet_bitcoin_inbox::{InboxParameters, RemovalBatch};
    use std::sync::OnceLock;

    pub const NOW: u64 = 1_800_000_000_000;
    pub const FLOOR: u32 = 900_000;
    pub const TIP: u32 = 1_000;
    pub const INBOX: [u8; 32] = [0x1b; 32];
    pub const MINUTE: u64 = 60 * 1000;

    /// An RSA notary key per test binary, not per test.
    pub fn authority() -> &'static TestAuthority {
        static A: OnceLock<TestAuthority> = OnceLock::new();
        A.get_or_init(TestAuthority::new)
    }

    /// The seller's Ghost Key.
    pub fn seller() -> &'static TestGhostkey {
        static G: OnceLock<TestGhostkey> = OnceLock::new();
        G.get_or_init(|| authority().mint())
    }

    pub fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    pub fn bridge() -> BridgeId {
        BridgeId(bridge_key().verifying_key().to_bytes())
    }

    pub fn params() -> InboxParameters {
        authority().params(bridge())
    }

    pub fn open_inbox() -> InboxStateV1 {
        open_inbox_at(FLOOR)
    }

    pub fn open_inbox_at(floor: u32) -> InboxStateV1 {
        let mut s = InboxStateV1::default();
        s.apply_delta(
            &params(),
            &InboxDelta {
                floor: Some(SignedFloor::sign(&bridge_key(), floor)),
                entries: vec![],
                removals: vec![],
            },
        )
        .expect("the bridge opens its inbox");
        s
    }

    pub fn state_bytes(state: &InboxStateV1) -> Vec<u8> {
        freenet_bitcoin_common::to_cbor(state).expect("state encodes")
    }

    /// The bridge reading `key`, dated `height`: a signed removal.
    pub fn bridge_reads(state: &mut InboxStateV1, key: &EntryKey, height: u32) {
        let mut removed = std::collections::BTreeSet::new();
        removed.insert(key.removal_prefix());
        state
            .apply_delta(
                &params(),
                &InboxDelta {
                    floor: state.floor.clone(),
                    entries: vec![],
                    removals: vec![RemovalBatch::sign(&bridge_key(), height, &removed)],
                },
            )
            .expect("the bridge removes what it read");
    }

    pub fn signet_vpub() -> String {
        let mut bytes = bs58::decode(
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        )
        .with_check(None)
        .into_vec()
        .expect("the BIP-84 vector must decode");
        bytes[..4].copy_from_slice(&0x045f_1cf6u32.to_be_bytes());
        bs58::encode(bytes).with_check().into_string()
    }

    pub fn script_at(index: u32) -> Vec<u8> {
        crate::bip32::AccountXpub::parse(&signet_vpub())
            .unwrap()
            .external_chain()
            .unwrap()
            .script_at(index)
            .unwrap()
    }

    /// A tip `height`, a block ten minutes old at [`NOW`].
    pub fn set_tip(secrets: &mut MemSecrets, height: u32) {
        set_tip_at(secrets, height, NOW);
    }

    /// A tip `height`, a block ten minutes old at `now_ms`.
    pub fn set_tip_at(secrets: &mut MemSecrets, height: u32, now_ms: u64) {
        save(
            secrets,
            &tip_key(BitcoinNetwork::Signet),
            &TipCache {
                anchor: BlockAnchor {
                    height,
                    hash: BlockHash([7; 32]),
                },
                block_time: (now_ms / 1000) as u32 - 600,
            },
        );
    }

    pub fn set_counter(secrets: &mut MemSecrets, next_index: u32) {
        crate::bitcoin::save_payment_xpub(
            secrets,
            &harvest_common::PaymentXpubStatus {
                xpub: signet_vpub(),
                network: BitcoinNetwork::Signet,
                next_index,
            },
        )
        .unwrap();
    }

    /// A delegate with a payment key at index 0, a tip at [`TIP`], and one
    /// store armed on the test bridge whose tab watches nothing.
    pub fn armed() -> MemSecrets {
        let mut secrets = MemSecrets::default();
        let store_sk = SigningKey::from_bytes(&[0x51; 32]);
        crate::store_keys::keep(&mut secrets, &store_sk);
        set_counter(&mut secrets, 0);
        set_tip(&mut secrets, TIP);
        let record = ArmRecord {
            arm: AutoInvoiceArm {
                store_contract_id: vec![1; 32],
                store_verifying_key: store_sk.verifying_key().to_bytes(),
                mailbox_contract_id: [2; 32],
                seller_fingerprint: "seller".into(),
                network: BitcoinNetwork::Signet,
                tip_contract_id: [3; 32],
                trusted_bridges: vec![bridge()],
                address_code_hash: [5; 32],
                watched_scripts: Vec::new(),
                watch_left_ms: 0,
                watched_until_height: None,
                presence_contract_id: None,
            },
            armed_at_ms: NOW - 1_000,
            watched_until_ms: NOW,
        };
        save(
            &mut secrets,
            &arm_key(&record.arm.store_contract_id),
            &record,
        );
        secrets
    }

    pub fn arm_record(secrets: &MemSecrets) -> ArmRecord {
        load(secrets, &arm_key(&[1; 32])).expect("armed")
    }

    /// The seller's Ghost Key delegating to `watch_key` for `bridge`,
    /// issued at `issued`, as the tab hands it over.
    pub fn grant_on(
        bridge: BridgeId,
        watch_key: [u8; 32],
        issued: u32,
        ui_made_at_ms: u64,
    ) -> WatchDelegationGrant {
        let body = freenet_bitcoin_inbox::DelegationBody {
            bridge,
            watch_key: freenet_bitcoin_inbox::WatchKeyId(watch_key),
            issued_mainnet_height: issued,
            expires_mainnet_height: None,
        };
        let (scoped, signature) = sign_as(seller(), body.signing_payload().unwrap());
        WatchDelegationGrant {
            network: BitcoinNetwork::Signet,
            bridge,
            ghostkey: seller().id().0,
            certificate_pem: seller().pem.clone(),
            delegation_scoped_payload: scoped,
            delegation_signature: signature,
            inbox_contract_id: INBOX,
            last_made_at_ms: ui_made_at_ms,
        }
    }

    pub fn grant_for(watch_key: [u8; 32], issued: u32, ui_made_at_ms: u64) -> WatchDelegationGrant {
        grant_on(bridge(), watch_key, issued, ui_made_at_ms)
    }

    /// What the vault's `SignResult` carries for `payload`.
    pub fn sign_as(gk: &TestGhostkey, payload: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer;
        let scoped = freenet_bitcoin_common::to_cbor(&ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(ContractInstanceId::new(
                [7u8; 32],
            )),
            payload,
        })
        .unwrap();
        let sig = gk.sk.sign(&scoped).to_bytes().to_vec();
        (scoped, sig)
    }

    /// [`armed`], with the seller's delegation to this delegate's watch key
    /// held, the tab having last sent at `NOW + 500`.
    pub fn delegated() -> MemSecrets {
        let mut secrets = armed();
        let key = get_watch_key(&mut secrets).unwrap();
        set_delegation(
            &mut secrets,
            grant_for(key, freenet_bitcoin_inbox::sender_height(FLOOR), NOW + 500),
            NOW,
        )
        .expect("the delegation is kept");
        settle_all(&mut secrets);
        secrets
    }

    /// Every contract these tests read, subscribed long enough ago that a
    /// copy of it counts as evidence.
    pub fn settle_all(secrets: &mut MemSecrets) {
        let arm = arm_record(secrets).arm;
        let mut h = held(secrets);
        h.subscribed.clear();
        h.note_subscribed(INBOX, 0);
        for index in 0..48 {
            h.note_subscribed(
                address_contract(&h.clone(), &arm, &script_at(index)).unwrap(),
                0,
            );
        }
        put_held(secrets, &h);
    }

    pub fn address_id(secrets: &MemSecrets, script: &[u8]) -> [u8; 32] {
        address_contract(&held(secrets), &arm_record(secrets).arm, script).unwrap()
    }

    pub fn held(secrets: &MemSecrets) -> Held {
        load_held(secrets, &bridge()).expect("a delegation is held")
    }

    pub fn put_held(secrets: &mut MemSecrets, held: &Held) {
        assert!(store_held(secrets, held));
    }

    /// The inbox update in `out`, decoded, and the entry it submits.
    pub fn submitted(out: &[OutboundDelegateMsg]) -> (InboxDelta, WireEntry) {
        assert_eq!(out.len(), 1, "exactly one message: {out:?}");
        let OutboundDelegateMsg::UpdateContractRequest(update) = &out[0] else {
            panic!("expected an inbox update, got {:?}", out[0]);
        };
        assert_eq!(
            update.contract_id.as_bytes(),
            INBOX.as_slice(),
            "sent to the inbox"
        );
        let UpdateData::Delta(delta) = &update.update else {
            panic!("expected a delta");
        };
        let delta: InboxDelta = freenet_bitcoin_common::from_cbor(delta.as_ref()).unwrap();
        let entry = delta.entries[0].clone();
        (delta, entry)
    }

    /// The one read a wake-up sends, which must come first: a GET, and a
    /// SUBSCRIBE of the same contract unless it is a canary candidate.
    pub fn wake(secrets: &mut MemSecrets, now_ms: u64) -> GetContractRequest {
        let out = on_wakeup(secrets, now_ms);
        got_read(&out)
    }

    /// `out` is exactly one read.
    pub fn got_read(out: &[OutboundDelegateMsg]) -> GetContractRequest {
        let Some(OutboundDelegateMsg::GetContractRequest(get)) = out.first() else {
            panic!("expected a GET first, got {out:?}");
        };
        match out.get(1) {
            Some(OutboundDelegateMsg::SubscribeContractRequest(sub)) => {
                assert_eq!(out.len(), 2, "one read: {out:?}");
                assert_eq!(
                    sub.contract_id, get.contract_id,
                    "subscribed to what is read"
                );
            }
            None => {}
            Some(other) => panic!("expected only a read, got {other:?}"),
        }
        get.clone()
    }

    pub fn answer(
        secrets: &mut MemSecrets,
        get: &GetContractRequest,
        state: Option<Vec<u8>>,
        now_ms: u64,
    ) -> Vec<OutboundDelegateMsg> {
        let id: [u8; 32] = get.contract_id.as_bytes().try_into().unwrap();
        on_inbox_read(secrets, &id, state.as_deref(), get.context.as_ref(), now_ms)
            .expect("the answer is this module's")
    }

    /// A wake-up, answered: a canary read first, if that is what it asks
    /// (answered as live, with no state), then the inbox read, answered with
    /// `state`.
    pub fn wake_and_read(
        secrets: &mut MemSecrets,
        state: &InboxStateV1,
        now_ms: u64,
    ) -> Vec<OutboundDelegateMsg> {
        let mut get = wake(secrets, now_ms);
        if get.contract_id.as_bytes() != INBOX.as_slice() {
            let canary = next_canary(secrets, &held(secrets)).unwrap().1;
            assert_eq!(
                get.contract_id.as_bytes(),
                address_id(secrets, &canary).as_slice(),
                "a canary is read before a request"
            );
            // As live: nobody has created a canary's address contract.
            get = got_read(&answer(secrets, &get, None, now_ms));
        }
        assert_eq!(
            get.contract_id.as_bytes(),
            INBOX.as_slice(),
            "the inbox is read"
        );
        answer(secrets, &get, Some(state_bytes(state)), now_ms)
    }

    /// `script`'s address contract with the bridge's watermark at
    /// `scanned`, as the bridge publishes it.
    pub fn address_state(secrets: &MemSecrets, script: &[u8], scanned: Option<u32>) -> Vec<u8> {
        let arm = arm_record(secrets).arm;
        let params = address_params(&held(secrets), &arm, script);
        let mut state = freenet_bitcoin_common::BitcoinAddressStateV1::default();
        if let Some(height) = scanned {
            let body = freenet_bitcoin_common::address_state::scanned_to_body(
                &params,
                BlockAnchor {
                    height,
                    hash: BlockHash([9; 32]),
                },
            );
            let claim = freenet_bitcoin_common::SignedClaim::sign(&bridge_key(), &body).unwrap();
            state.claims.scanned.insert(bridge(), claim);
        }
        freenet_bitcoin_common::to_cbor(&state).unwrap()
    }

    /// A wake-up's GET, which must be `script`'s address contract, answered
    /// with the bridge's watermark at `scanned`: what the answer sends.
    pub fn wake_and_scan(
        secrets: &mut MemSecrets,
        script: &[u8],
        scanned: Option<u32>,
        now_ms: u64,
    ) -> Vec<OutboundDelegateMsg> {
        let get = wake(secrets, now_ms);
        assert_eq!(
            get.contract_id.as_bytes(),
            address_id(secrets, script).as_slice(),
            "the address contract is read"
        );
        let state = address_state(secrets, script, scanned);
        answer(secrets, &get, Some(state), now_ms)
    }

    /// One request sent, read by the bridge, and confirmed by its canary's
    /// watermark at `tip`: the entry that carried it.
    pub fn send_read_confirm(secrets: &mut MemSecrets, tip: u32, now_ms: u64) -> WireEntry {
        let mut inbox = open_inbox();
        let (delta, entry) = submitted(&wake_and_read(secrets, &inbox, now_ms));
        inbox.apply_delta(&params(), &delta).unwrap();
        bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wake_and_read(secrets, &inbox, now_ms + 5 * MINUTE).is_empty());
        let canary = held(secrets).unconfirmed.expect("left the inbox").canary;
        assert!(wake_and_scan(secrets, &canary, Some(tip), now_ms + 10 * MINUTE).is_empty());
        assert!(held(secrets).unconfirmed.is_none(), "confirmed");
        entry
    }

    /// Record `scripts` as confirmed watched through `until`, shown by the
    /// canary at index 40.
    pub fn confirm_watched(secrets: &mut MemSecrets, scripts: &[Vec<u8>], until: u32) {
        let mut h = held(secrets);
        for script in scripts {
            h.watched.retain(|w| w.script != *script);
            h.watched.push(Watched {
                script: script.clone(),
                until_height: until,
                canary: script_at(40),
                canary_contract: address_id(secrets, &script_at(40)),
            });
        }
        put_held(secrets, &h);
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::secrets::MemSecrets;

    /// The request `entry` carries, as the bridge opens it.
    fn opened(entry: &WireEntry) -> InboxRequest {
        freenet_bitcoin_inbox::seal::unseal(
            &bridge_key(),
            &seller().id(),
            entry.entry.mainnet_height,
            &entry.entry.body().unwrap().sealed,
        )
        .expect("the bridge opens it")
    }

    fn scripts(entry: &WireEntry) -> Vec<Vec<u8>> {
        opened(entry).scripts.iter().map(|s| s.0.clone()).collect()
    }

    fn watched_now(secrets: &MemSecrets, tip: u32) -> Vec<Vec<u8>> {
        delegated_watched(secrets, BitcoinNetwork::Signet, &[bridge()], tip)
            .into_iter()
            .map(|(s, _)| s)
            .collect()
    }

    fn with_canary(pool: std::ops::Range<u32>, canary: u32) -> Vec<Vec<u8>> {
        pool.map(script_at).chain([script_at(canary)]).collect()
    }

    /// Made on first asking and the same ever after, and stored under
    /// `harvest:auto:`, which the migration export leaves behind. Mutated red
    /// by generating a fresh key on every call.
    #[test]
    fn the_watch_key_is_made_once_and_kept() {
        let mut secrets = MemSecrets::default();
        let first = get_watch_key(&mut secrets).unwrap();
        assert_eq!(get_watch_key(&mut secrets).unwrap(), first);
        assert_eq!(
            watch_key(&secrets).unwrap().verifying_key().to_bytes(),
            first
        );
        assert!(WATCH_KEY.starts_with(AUTO_PREFIX.as_bytes()));
        assert!(!crate::auto_invoice::is_ledger_key(WATCH_KEY));
        // A host that refuses the write gets no key it would lose.
        assert!(get_watch_key(&mut MemSecrets::refusing_writes()).is_err());
    }

    /// A good grant is kept; one naming another watch key, signed by another
    /// Ghost Key, carrying another key's certificate, for another bridge,
    /// that expires, or older than the one held, is refused. Each check
    /// mutated red by removing it.
    #[test]
    fn a_delegation_is_checked_before_it_is_kept() {
        let mut secrets = armed();
        let key = get_watch_key(&mut secrets).unwrap();
        let issued = sender_height(FLOOR);

        let other_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        assert!(set_delegation(&mut secrets, grant_for(other_key, issued, 0), NOW).is_err());

        let mut forged = grant_for(key, issued, 0);
        let stranger = authority().mint();
        forged.ghostkey = stranger.id().0;
        forged.certificate_pem = stranger.pem.clone();
        let err = set_delegation(&mut secrets, forged, NOW).unwrap_err();
        assert!(err.contains("did not sign"), "{err}");

        let mut wrong_cert = grant_for(key, issued, 0);
        wrong_cert.certificate_pem = stranger.pem.clone();
        let err = set_delegation(&mut secrets, wrong_cert, NOW).unwrap_err();
        assert!(err.contains("another Ghost Key"), "{err}");

        let mut other_bridge = grant_for(key, issued, 0);
        other_bridge.bridge = BridgeId(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes());
        assert!(set_delegation(&mut secrets, other_bridge, NOW).is_err());

        let body = freenet_bitcoin_inbox::DelegationBody {
            bridge: bridge(),
            watch_key: freenet_bitcoin_inbox::WatchKeyId(key),
            issued_mainnet_height: issued,
            expires_mainnet_height: Some(issued + 1_000),
        };
        let (scoped, signature) = sign_as(seller(), body.signing_payload().unwrap());
        let mut expiring = grant_for(key, issued, 0);
        expiring.delegation_scoped_payload = scoped;
        expiring.delegation_signature = signature;
        let err = set_delegation(&mut secrets, expiring, NOW).unwrap_err();
        assert!(err.contains("expire"), "{err}");
        assert!(load_held(&secrets, &bridge()).is_none(), "nothing kept yet");

        let status = set_delegation(&mut secrets, grant_for(key, issued + 5, 7), NOW).unwrap();
        assert_eq!(status.issued_mainnet_height, issued + 5);
        assert_eq!(status.ghostkey, seller().id().0);
        assert_eq!(status.made_at_ms, 7);
        let err = set_delegation(&mut secrets, grant_for(key, issued, 0), NOW).unwrap_err();
        assert!(err.contains("newer"), "{err}");
        assert_eq!(held(&secrets).issued_mainnet_height, issued + 5);
    }

    /// Only a LATER delegation clears a stall: the same one handed over again
    /// is the same standing at the bridge. Mutated red by clearing failures
    /// on any grant.
    #[test]
    fn only_a_later_delegation_clears_a_stall() {
        let mut secrets = delegated();
        let mut h = held(&secrets);
        h.failures = MAX_FAILURES;
        put_held(&mut secrets, &h);
        let key = get_watch_key(&mut secrets).unwrap();
        let same = set_delegation(&mut secrets, grant_for(key, sender_height(FLOOR), 0), NOW);
        assert!(same.unwrap().stalled, "the same height is still stalled");
        let later = set_delegation(
            &mut secrets,
            grant_for(key, sender_height(FLOOR) + 1, 0),
            NOW,
        );
        assert!(!later.unwrap().stalled);
    }

    /// At most `MAX_DELEGATIONS` bridges; replacing one held is always
    /// allowed. Mutated red by dropping the cap.
    #[test]
    fn delegations_are_capped_per_delegate() {
        let mut secrets = armed();
        let key = get_watch_key(&mut secrets).unwrap();
        let bridge_n =
            |n: u8| BridgeId(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes());
        for n in 0..MAX_DELEGATIONS as u8 {
            set_delegation(&mut secrets, grant_on(bridge_n(40 + n), key, 10, 0), NOW).unwrap();
        }
        let err =
            set_delegation(&mut secrets, grant_on(bridge_n(90), key, 10, 0), NOW).unwrap_err();
        assert!(err.contains("at most"), "{err}");
        assert!(set_delegation(&mut secrets, grant_on(bridge_n(40), key, 11, 0), NOW).is_ok());
    }

    /// The whole request, against the real inbox and the real bridge key: a
    /// wake-up with too few watched addresses reads a canary past the pool,
    /// finds it unscanned, reads the inbox in the same run, and sends exactly
    /// one delegated Watch that the inbox contract admits and the bridge
    /// opens: the next addresses, then the canary LAST, the horizon asked
    /// from the tip, and a `made_at_ms` above the tab's. Mutated red by:
    /// sealing to the watch key instead of the Ghost Key, dating beyond the
    /// window, dropping the `ui_made_at + 1` floor, and putting the canary
    /// first.
    #[test]
    fn a_low_pool_sends_one_delegated_watch_the_inbox_admits() {
        let mut secrets = delegated();
        let mut inbox = open_inbox();
        let out = wake_and_read(&mut secrets, &inbox, NOW);
        let (delta, entry) = submitted(&out);

        inbox.apply_delta(&params(), &delta).unwrap();
        assert!(
            inbox.entries.contains_key(&entry.entry.key()),
            "the inbox admits it"
        );
        inbox
            .verify(&params())
            .expect("and the state verifies whole");
        assert!(entry.entry.delegation.is_some(), "signed by the watch key");
        assert_eq!(entry.entry.ghostkey, seller().id(), "as the seller's");

        let request = opened(&entry);
        assert_eq!(request.action, Action::Watch);
        assert_eq!(request.network, BitcoinNetwork::Signet);
        assert_eq!(scripts(&entry), with_canary(0..10, 20));
        assert_eq!(request.watch_until_height, Some(TIP + REQUEST_AHEAD_BLOCKS));
        assert_eq!(request.made_at_ms, NOW + 501, "above the tab's last");
        assert_eq!(request.revoke_watch_keys_through, None);

        let held = held(&secrets);
        assert_eq!(held.own_made_at_ms, NOW + 501);
        let sent = held.outstanding.expect("recorded as outstanding");
        assert_eq!(sent.entry_key, entry.entry.key());
        assert_eq!(sent.canary, script_at(20));
        assert_eq!(sent.canary_index, 20);
        assert_eq!(sent.until_height, TIP + REQUEST_AHEAD_BLOCKS);
        assert_eq!(held.canary_next, 21, "a canary is used once");
    }

    /// Review round 2 of #179, P1: a request the bridge IGNORED credits
    /// nothing, although the tab has every one of its pool addresses watched
    /// (so their watermarks advance). The tab's watch named no height, so the
    /// refill fires; the request is read and dropped without effect; the pool
    /// scripts show fresh watermarks, the canary none. After `CONFIRM_BLOCKS`
    /// on a settled copy it is a failure. Mutated red by confirming on the
    /// first script instead of the canary.
    #[test]
    fn a_request_the_bridge_ignored_credits_nothing_though_the_tab_watches_it() {
        let mut secrets = delegated();
        let key = crate::auto_invoice::arm_key(&[1; 32]);
        let mut record = arm_record(&secrets);
        record.arm.watched_scripts = (0..10).map(script_at).collect();
        record.watched_until_ms = NOW + 30 * 24 * 60 * 60 * 1000;
        save(&mut secrets, &key, &record);

        let mut inbox = open_inbox();
        let (delta, entry) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        assert_eq!(scripts(&entry).last(), Some(&script_at(20)), "the canary");
        inbox.apply_delta(&params(), &delta).unwrap();
        // Read and removed, with no effect.
        bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wake_and_read(&mut secrets, &inbox, NOW + 5 * MINUTE).is_empty());
        // The tab's watch keeps the first script scanned; the canary is not.
        let get = wake(&mut secrets, NOW + 10 * MINUTE);
        assert_eq!(
            get.contract_id.as_bytes(),
            address_id(&secrets, &script_at(20)).as_slice(),
            "the canary is what is read, not the first script"
        );
        // As live: the canary's address contract was never created.
        answer(&mut secrets, &get, None, NOW + 10 * MINUTE);
        assert!(watched_now(&secrets, TIP).is_empty(), "nothing credited");
        set_tip_at(&mut secrets, TIP + CONFIRM_BLOCKS, NOW + 60 * MINUTE);
        let get = wake(&mut secrets, NOW + 60 * MINUTE);
        answer(&mut secrets, &get, None, NOW + 60 * MINUTE);
        let h = held(&secrets);
        assert!(h.unconfirmed.is_none() && h.watched.is_empty());
        assert_eq!(h.failures, 1);
    }

    /// Review round 3 of #179, P1: a canary is unscanned BY CONSTRUCTION
    /// (past the tab's pool by a margin, past every canary used, not one the
    /// tab names), so the read that finds NO state (as it does live: nobody
    /// has created its address contract) goes straight on to the request. A
    /// candidate someone has scanned is skipped for the next; after
    /// `MAX_CANARY_TRIES` the delegation waits. Mutated red by requiring a
    /// state, taking a scanned candidate, dropping the margin, and never
    /// deferring.
    #[test]
    fn a_canary_is_unscanned_by_construction() {
        let mut secrets = delegated();
        // Live: the canary read answers None, and the inbox is read at once.
        let get = wake(&mut secrets, NOW);
        assert_eq!(
            get.contract_id.as_bytes(),
            address_id(&secrets, &script_at(20)).as_slice(),
            "past the pool of ten by a margin of ten"
        );
        let out = answer(&mut secrets, &get, None, NOW);
        assert_eq!(got_read(&out).contract_id.as_bytes(), INBOX.as_slice());

        let mut secrets = delegated();
        let out = wake_and_scan(&mut secrets, &script_at(20), Some(TIP), NOW);
        assert!(out.is_empty(), "no inbox read for a scanned canary");
        assert_eq!(held(&secrets).canary_next, 21);
        assert!(held(&secrets).canary.is_none());

        // One the tab names is never a canary.
        let key = crate::auto_invoice::arm_key(&[1; 32]);
        let mut record = arm_record(&secrets);
        record.arm.watched_scripts = vec![script_at(21)];
        save(&mut secrets, &key, &record);
        let get = wake(&mut secrets, NOW + MINUTE);
        assert_eq!(
            get.contract_id.as_bytes(),
            address_id(&secrets, &script_at(22)).as_slice()
        );

        let mut secrets = delegated();
        for i in 0..MAX_CANARY_TRIES {
            wake_and_scan(
                &mut secrets,
                &script_at(20 + i),
                Some(TIP),
                NOW + u64::from(i),
            );
        }
        assert!(
            on_wakeup(&mut secrets, NOW + 10 * MINUTE).is_empty(),
            "waits"
        );
        assert!(!on_wakeup(&mut secrets, NOW + CANARY_DEFER_MS + 10).is_empty());
    }

    /// A canary the counter has since brought into the tab's pool, or that
    /// the tab now names, shows nothing about the request: dropped without
    /// credit and without a failure, even with a watermark. Mutated red by
    /// dropping the check.
    #[test]
    fn a_canary_that_reached_the_tabs_pool_proves_nothing() {
        let mut secrets = delegated();
        let mut inbox = open_inbox();
        let (delta, entry) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        inbox.apply_delta(&params(), &delta).unwrap();
        bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wake_and_read(&mut secrets, &inbox, NOW + 5 * MINUTE).is_empty());
        set_counter(&mut secrets, 11);
        wake_and_scan(&mut secrets, &script_at(20), Some(TIP), NOW + 10 * MINUTE);
        let h = held(&secrets);
        assert!(h.unconfirmed.is_none() && h.watched.is_empty() && h.failures == 0);
    }

    /// The node refusing the inbox UPDATE means the request was never sent:
    /// forgotten, not a failure, and not waited on for two hours. Mutated red
    /// by ignoring the answer.
    #[test]
    fn a_refused_inbox_update_is_not_waited_on() {
        let mut secrets = delegated();
        let out = wake_and_read(&mut secrets, &open_inbox(), NOW);
        let OutboundDelegateMsg::UpdateContractRequest(update) = &out[0] else {
            panic!("{out:?}");
        };
        assert!(
            on_update_answer(&mut secrets, &Ok(()), update.context.as_ref())
                .is_some_and(|out| out.is_empty())
        );
        assert!(
            held(&secrets).outstanding.is_some(),
            "taken: still waited on"
        );
        on_update_answer(
            &mut secrets,
            &Err("refused".into()),
            update.context.as_ref(),
        );
        let h = held(&secrets);
        assert!(h.outstanding.is_none() && h.failures == 0);
        assert!(on_update_answer(&mut secrets, &Ok(()), b"not ours").is_none());
    }

    /// One request at a time: while it sits unread in the inbox, may still be
    /// landing, or has left but is not yet confirmed, nothing else is sent.
    /// Mutated red by sending while unconfirmed.
    #[test]
    fn no_second_request_while_one_is_outstanding_or_unconfirmed() {
        let mut secrets = delegated();
        let mut inbox = open_inbox();
        let (delta, entry) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        // Landing: this node's copy does not hold it yet.
        assert!(wake_and_read(&mut secrets, &inbox, NOW + MINUTE).is_empty());
        inbox.apply_delta(&params(), &delta).unwrap();
        // Waiting, unread.
        assert!(wake_and_read(&mut secrets, &inbox, NOW + 10 * MINUTE).is_empty());
        assert!(held(&secrets).outstanding.is_some());
        // Read: left the inbox, but nothing is sent until it is confirmed.
        bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wake_and_read(&mut secrets, &inbox, NOW + 15 * MINUTE).is_empty());
        let h = held(&secrets);
        assert!(h.outstanding.is_none());
        assert!(h.unconfirmed.as_ref().is_some_and(|u| u.removed));
        // The next wake-up reads the canary, not the inbox.
        let get = wake(&mut secrets, NOW + 20 * MINUTE);
        assert_ne!(get.contract_id.as_bytes(), INBOX.as_slice());
        // And an inbox read answered meanwhile, with a fresh canary on hand,
        // sends nothing either.
        let mut h = held(&secrets);
        h.canary = Some(Canary {
            script: script_at(30),
            index: 30,
            at_ms: NOW + 20 * MINUTE,
        });
        put_held(&mut secrets, &h);
        let late_inbox_read = to_cbor(&ReadContext {
            magic: READ_MAGIC,
            bridge: bridge(),
            kind: ReadKind::Inbox,
            script: Vec::new(),
            index: 0,
        })
        .unwrap();
        let out = on_inbox_read(
            &mut secrets,
            &INBOX,
            Some(&state_bytes(&open_inbox())),
            &late_inbox_read,
            NOW + 20 * MINUTE,
        )
        .unwrap();
        assert!(out.is_empty(), "{out:?}");
    }

    /// A removal is not a watch: the scripts count for I7 only once the
    /// canary's watermark by this bridge reaches the tip the request left at;
    /// one from before it, one signed by another key, none, or no state at
    /// all, does not confirm, and one still short `CONFIRM_BLOCKS` past it
    /// fails. Mutated red by: confirming on the removal alone, dropping the
    /// `since_tip` comparison, not verifying the claim's signature, not
    /// failing at `CONFIRM_BLOCKS`, and failing before it.
    #[test]
    fn a_read_request_counts_only_once_its_canary_shows() {
        let mut secrets = delegated();
        let mut inbox = open_inbox();
        let (delta, entry) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        inbox.apply_delta(&params(), &delta).unwrap();
        bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wake_and_read(&mut secrets, &inbox, NOW + 5 * MINUTE).is_empty());
        assert!(
            watched_now(&secrets, TIP).is_empty(),
            "read, not yet watched"
        );

        let canary = script_at(20);
        wake_and_scan(&mut secrets, &canary, None, NOW + 10 * MINUTE);
        wake_and_scan(&mut secrets, &canary, Some(TIP - 1), NOW + 15 * MINUTE);
        // Signed by someone other than the bridge.
        let get = wake(&mut secrets, NOW + 20 * MINUTE);
        let arm = arm_record(&secrets).arm;
        let mut forged = freenet_bitcoin_common::BitcoinAddressStateV1::default();
        let body = freenet_bitcoin_common::address_state::scanned_to_body(
            &address_params(&held(&secrets), &arm, &canary),
            freenet_bitcoin_common::BlockAnchor {
                height: TIP + 5,
                hash: freenet_bitcoin_common::BlockHash([9; 32]),
            },
        );
        let mut claim =
            freenet_bitcoin_common::SignedClaim::sign(&SigningKey::from_bytes(&[8; 32]), &body)
                .unwrap();
        claim.bridge = bridge();
        forged.claims.scanned.insert(bridge(), claim);
        answer(
            &mut secrets,
            &get,
            Some(freenet_bitcoin_common::to_cbor(&forged).unwrap()),
            NOW + 20 * MINUTE,
        );
        assert!(held(&secrets).unconfirmed.is_some());
        assert!(watched_now(&secrets, TIP).is_empty());

        wake_and_scan(&mut secrets, &canary, Some(TIP), NOW + 25 * MINUTE);
        assert_eq!(watched_now(&secrets, TIP), with_canary(0..10, 20));
        let h = held(&secrets);
        assert!(h.unconfirmed.is_none() && h.failures == 0);
        let status = status_of(&secrets, &h, NOW);
        assert_eq!((status.watched, status.outstanding), (10, false));

        // Another request whose canary never shows: its address contract
        // is never created, so every read answers None. Inside the window,
        // no verdict; at `CONFIRM_BLOCKS` past the tip it left at (review
        // round 3, P2-a: stalls must be reachable), a failure.
        let mut h = held(&secrets);
        h.unconfirmed = Some(Unconfirmed {
            scripts: vec![script_at(0), script_at(30)],
            canary: script_at(30),
            canary_index: 30,
            canary_contract: address_id(&secrets, &script_at(30)),
            until_height: TIP + 1,
            since_tip: TIP,
            removed: true,
            left_at_ms: NOW + 30 * MINUTE,
        });
        put_held(&mut secrets, &h);
        set_tip_at(&mut secrets, TIP + CONFIRM_BLOCKS - 1, NOW + 30 * MINUTE);
        let get = wake(&mut secrets, NOW + 30 * MINUTE);
        answer(&mut secrets, &get, None, NOW + 30 * MINUTE);
        assert_eq!(held(&secrets).failures, 0, "not yet");
        assert!(held(&secrets).unconfirmed.is_some());
        set_tip_at(&mut secrets, TIP + CONFIRM_BLOCKS, NOW + 35 * MINUTE);
        let get = wake(&mut secrets, NOW + 35 * MINUTE);
        answer(&mut secrets, &get, None, NOW + 35 * MINUTE);
        let h = held(&secrets);
        assert!(h.unconfirmed.is_none());
        assert_eq!(h.failures, 1);
    }

    /// A request gone from the inbox without a removal seen (the floor passed
    /// it while this node slept) is not a failure by itself: its canary
    /// decides. Mutated red by counting it failed on the spot.
    #[test]
    fn a_request_the_floor_passed_is_judged_by_its_canary() {
        let mut secrets = delegated();
        let inbox = open_inbox();
        let (_, entry) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        let moved = open_inbox_at(entry.entry.mainnet_height + 1);
        assert!(wake_and_read(&mut secrets, &moved, NOW + 40 * MINUTE).is_empty());
        let h = held(&secrets);
        assert!(h.unconfirmed.as_ref().is_some_and(|u| !u.removed));
        assert_eq!(h.failures, 0);
        wake_and_scan(&mut secrets, &script_at(20), Some(TIP), NOW + 45 * MINUTE);
        assert_eq!(watched_now(&secrets, TIP).len(), 11);
    }

    /// An inbox that stops moving (re-keyed, say) holds the entry for ever;
    /// after `OUTSTANDING_MAX_MS` it is taken to have left. Mutated red by
    /// dropping the timeout.
    #[test]
    fn a_frozen_inbox_does_not_hold_a_request_for_ever() {
        let mut secrets = delegated();
        let mut inbox = open_inbox();
        let (delta, _) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        inbox.apply_delta(&params(), &delta).unwrap();
        let late = NOW + OUTSTANDING_MAX_MS - MINUTE;
        set_tip_at(&mut secrets, TIP, late);
        assert!(wake_and_read(&mut secrets, &inbox, late).is_empty());
        assert!(held(&secrets).outstanding.is_some());
        let later = NOW + OUTSTANDING_MAX_MS;
        set_tip_at(&mut secrets, TIP, later);
        assert!(wake_and_read(&mut secrets, &inbox, later).is_empty());
        let h = held(&secrets);
        assert!(h.outstanding.is_none() && h.unconfirmed.is_some());
    }

    /// Only a floor the bridge signed is read, and only a settled copy of the
    /// inbox dates a request. Mutated red by dropping the floor's signature
    /// check, and the inbox's settle check.
    #[test]
    fn a_request_is_dated_only_from_a_settled_floor_the_bridge_signed() {
        let mut secrets = delegated();
        let mut forged = open_inbox();
        forged.floor = Some(SignedFloor::sign(&SigningKey::from_bytes(&[8; 32]), FLOOR));
        assert!(wake_and_read(&mut secrets, &forged, NOW).is_empty());
        assert!(held(&secrets).outstanding.is_none());

        let mut secrets = delegated();
        let mut h = held(&secrets);
        h.subscribed.retain(|(id, _)| *id != INBOX);
        put_held(&mut secrets, &h);
        assert!(wake_and_read(&mut secrets, &open_inbox(), NOW).is_empty());
        assert!(
            held(&secrets).outstanding.is_none(),
            "an unsettled inbox copy"
        );
    }

    /// The hourly probe reads the canary of the next address's request: a
    /// settled copy behind a fresh tip withdraws every watch of the
    /// delegation; no state, or an unsettled copy, is no evidence and
    /// withdraws nothing. Mutated red by dropping the clear, and by clearing
    /// on no evidence.
    #[test]
    fn a_stale_canary_withdraws_the_delegations_watches() {
        let mut secrets = delegated();
        send_read_confirm(&mut secrets, TIP, NOW);
        assert_eq!(watched_now(&secrets, TIP).len(), 11);
        // Probed within the hour of confirming: nothing to read.
        assert!(on_wakeup(&mut secrets, NOW + 30 * MINUTE).is_empty());
        let at = NOW + 10 * MINUTE + PROBE_EVERY_MS;
        set_tip_at(&mut secrets, TIP + 6, at);
        wake_and_scan(&mut secrets, &script_at(20), Some(TIP + 6), at);
        assert_eq!(watched_now(&secrets, TIP + 6).len(), 11, "live");
        let at = at + PROBE_EVERY_MS;
        set_tip_at(&mut secrets, TIP + 20, at);
        // No state: nothing withdrawn.
        let get = wake(&mut secrets, at);
        answer(&mut secrets, &get, None, at);
        assert_eq!(watched_now(&secrets, TIP + 20).len(), 11);
        // Unsettled (the SUBSCRIBE not yet answered Ok): nothing withdrawn.
        on_node_started(&mut secrets);
        wake_and_scan(&mut secrets, &script_at(20), Some(TIP + 13), at + MINUTE);
        assert_eq!(watched_now(&secrets, TIP + 20).len(), 11);
        settle_all(&mut secrets);
        wake_and_scan(
            &mut secrets,
            &script_at(20),
            Some(TIP + 13),
            at + 2 * MINUTE,
        );
        assert!(watched_now(&secrets, TIP + 20).is_empty(), "withdrawn");
        assert_eq!(held(&secrets).failures, 1);
    }

    /// A horizon is relied on only while it covers an invoice's window, and
    /// renewed a day before, with a new canary. Mutated red by an off-by-one
    /// in `covers` and by dropping the margin.
    #[test]
    fn a_horizon_near_the_tip_is_not_relied_on_and_is_renewed() {
        let mut secrets = delegated();
        send_read_confirm(&mut secrets, TIP, NOW);
        let until = TIP + REQUEST_AHEAD_BLOCKS;
        let last_ok = until - WATCH_NEEDED_BLOCKS;
        assert_eq!(watched_now(&secrets, last_ok).len(), 11);
        assert!(watched_now(&secrets, last_ok + 1).is_empty());

        let mut h = held(&secrets);
        h.last_probe_ms = Some(NOW + 20 * MINUTE);
        put_held(&mut secrets, &h);
        set_tip(&mut secrets, last_ok - RENEW_MARGIN_BLOCKS);
        assert!(on_wakeup(&mut secrets, NOW + 25 * MINUTE).is_empty());
        set_tip(&mut secrets, last_ok - RENEW_MARGIN_BLOCKS + 1);
        let (_, renewal) = submitted(&wake_and_read(
            &mut secrets,
            &open_inbox(),
            NOW + 30 * MINUTE,
        ));
        assert_eq!(scripts(&renewal), with_canary(0..10, 21));
        assert!(
            opened(&renewal).made_at_ms > NOW + 501,
            "above its own last"
        );
    }

    /// The refill looks at the NEXT addresses, not anywhere in the pool:
    /// with 6-9 watched through an older horizon and 10-15 through a newer
    /// one, the older one nearing sends a renewal for 6-9 though six fresh
    /// addresses sit further on. Mutated red by counting fresh addresses
    /// anywhere in the pool.
    #[test]
    fn the_refill_follows_the_next_addresses() {
        let mut secrets = delegated();
        let u1 = TIP + 3_000;
        let u2 = TIP + MAX_WATCH_AHEAD_BLOCKS;
        confirm_watched(
            &mut secrets,
            &(6..10).map(script_at).collect::<Vec<_>>(),
            u1,
        );
        confirm_watched(
            &mut secrets,
            &(10..16).map(script_at).collect::<Vec<_>>(),
            u2,
        );
        set_counter(&mut secrets, 6);
        let mut h = held(&secrets);
        h.last_probe_ms = Some(NOW);
        put_held(&mut secrets, &h);
        assert!(on_wakeup(&mut secrets, NOW).is_empty(), "all fresh yet");
        set_tip(
            &mut secrets,
            u1 - WATCH_NEEDED_BLOCKS - RENEW_MARGIN_BLOCKS + 1,
        );
        let (_, renewal) = submitted(&wake_and_read(&mut secrets, &open_inbox(), NOW));
        assert_eq!(scripts(&renewal), with_canary(6..10, 26));
    }

    /// Requests whose canary never shows: each failure waits a doubling
    /// backoff before the next send, and after `MAX_FAILURES` the delegation
    /// stalls and sends nothing, while what it has confirmed still counts as
    /// long as its probes find it scanned; a later delegation starts it
    /// afresh. Mutated red by: ignoring the backoff, and dropping the stall
    /// from `may_send`.
    #[test]
    fn requests_whose_canary_never_shows_stall_the_delegation() {
        let mut secrets = delegated();
        send_read_confirm(&mut secrets, TIP, NOW);
        let mut h = held(&secrets);
        h.failures = 1;
        h.last_failure_ms = Some(NOW);
        h.last_probe_ms = Some(NOW);
        put_held(&mut secrets, &h);
        // Two of the first five from the counter past what was confirmed.
        set_counter(&mut secrets, 8);
        assert!(on_wakeup(&mut secrets, NOW + FAILURE_BACKOFF_MS - 1).is_empty());
        let at = NOW + FAILURE_BACKOFF_MS;
        set_tip_at(&mut secrets, TIP, at);
        submitted(&wake_and_read(&mut secrets, &open_inbox(), at));

        let mut h = held(&secrets);
        h.outstanding = None;
        h.failures = MAX_FAILURES;
        h.last_probe_ms = Some(at + 10 * FAILURE_BACKOFF_MS);
        put_held(&mut secrets, &h);
        assert!(status_of(&secrets, &h, NOW).stalled);
        assert_eq!(
            watched_now(&secrets, TIP).len(),
            11,
            "what probes confirm still counts"
        );
        set_tip_at(&mut secrets, TIP, at + 10 * FAILURE_BACKOFF_MS);
        assert!(on_wakeup(&mut secrets, at + 10 * FAILURE_BACKOFF_MS).is_empty());

        let key = get_watch_key(&mut secrets).unwrap();
        set_delegation(
            &mut secrets,
            grant_for(key, sender_height(FLOOR) + 1, 0),
            NOW,
        )
        .unwrap();
        assert!(!held(&secrets).stalled());
    }

    /// The five-minute wake-up is what runs it, and its read goes first, so
    /// the node's cap on network operations falls on heartbeats instead.
    /// Mutated red by dropping the call from `background`, and by putting it
    /// after the heartbeats.
    #[test]
    fn the_wakeup_reads_first() {
        use crate::node_glue::{BackgroundRun, HEARTBEAT_TAG};
        let mut secrets = delegated();
        let key = crate::auto_invoice::arm_key(&[1; 32]);
        let mut record = arm_record(&secrets);
        record.arm.presence_contract_id = Some([9; 32]);
        save(&mut secrets, &key, &record);
        let out = crate::background::on_background(
            &mut secrets,
            &BackgroundRun::Wakeup {
                tag: HEARTBEAT_TAG.to_vec(),
            },
            NOW,
        );
        assert!(out.len() >= 2, "{out:?}");
        let get = got_read(&out[..1]);
        assert_eq!(
            get.contract_id.as_bytes(),
            address_id(&secrets, &script_at(20)).as_slice()
        );
    }

    /// Two delegations with work take turns, the least recently read first.
    /// Mutated red by always taking the first.
    #[test]
    fn delegations_take_turns() {
        let mut secrets = delegated();
        let other = BridgeId(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes());
        let key = crate::auto_invoice::arm_key(&[1; 32]);
        let mut record = arm_record(&secrets);
        record.arm.trusted_bridges.push(other);
        save(&mut secrets, &key, &record);
        let watch = get_watch_key(&mut secrets).unwrap();
        let mut grant = grant_on(other, watch, sender_height(FLOOR), 0);
        grant.inbox_contract_id = [0x2d; 32];
        set_delegation(&mut secrets, grant, NOW).unwrap();
        let a = wake(&mut secrets, NOW);
        let b = wake(&mut secrets, NOW + 5 * MINUTE);
        let c = wake(&mut secrets, NOW + 10 * MINUTE);
        assert_ne!(a.contract_id, b.contract_id);
        assert_eq!(a.contract_id, c.contract_id);
    }

    /// Testing lens, round 2: I7's delegated source is the union over every
    /// delegation serving the store's bridges, each read at its own bridge's
    /// address contract (`trusted_bridges` of that bridge alone, as the bridge
    /// writes it); one whose probe withdrew its watches adds nothing.
    /// Mutated red by addressing with the arm's whole `trusted_bridges`.
    #[test]
    fn two_bridges_feed_one_union_and_each_is_read_at_its_own_address() {
        let mut secrets = delegated();
        let other = BridgeId(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes());
        let key = crate::auto_invoice::arm_key(&[1; 32]);
        let mut record = arm_record(&secrets);
        record.arm.trusted_bridges.push(other);
        save(&mut secrets, &key, &record);
        let watch = get_watch_key(&mut secrets).unwrap();
        let mut grant = grant_on(other, watch, sender_height(FLOOR), 0);
        grant.inbox_contract_id = [0x2d; 32];
        set_delegation(&mut secrets, grant, NOW).unwrap();
        confirm_watched(&mut secrets, &[script_at(0)], TIP + 500);
        let mut second = load_held(&secrets, &other).unwrap();
        second.watched.push(Watched {
            script: script_at(1),
            until_height: TIP + 500,
            canary: script_at(90),
            canary_contract: [0; 32],
        });
        store_held(&mut secrets, &second);
        let both = [bridge(), other];
        let mut union: Vec<Vec<u8>> =
            delegated_watched(&secrets, BitcoinNetwork::Signet, &both, TIP)
                .into_iter()
                .map(|(s, _)| s)
                .collect();
        union.sort();
        let mut expected = vec![script_at(0), script_at(1)];
        expected.sort();
        assert_eq!(union, expected);
        second.watched.clear();
        second.failures = MAX_FAILURES;
        store_held(&mut secrets, &second);
        assert_eq!(
            delegated_watched(&secrets, BitcoinNetwork::Signet, &both, TIP).len(),
            1,
            "a withdrawn delegation adds nothing"
        );
        // Addressed as the bridge writes it: itself alone trusted.
        let arm = arm_record(&secrets).arm;
        let only_it = BitcoinAddressParameters {
            network: BitcoinNetwork::Signet,
            script_pubkey: script_at(0),
            trusted_bridges: vec![bridge()],
            pow_floor: BitcoinNetwork::Signet.default_pow_floor(),
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&arm.address_code_hash);
        hasher.update(&freenet_bitcoin_common::to_cbor(&only_it).unwrap());
        assert_eq!(
            address_contract(&held(&secrets), &arm, &script_at(0)),
            Some(*hasher.finalize().as_bytes())
        );
    }

    /// A store unarmed while a request waits: what waited is dropped, not
    /// counted as a failure, and an address answer for it changes nothing.
    /// Mutated red by keeping it.
    #[test]
    fn an_unarmed_store_drops_what_waited() {
        let mut secrets = delegated();
        submitted(&wake_and_read(&mut secrets, &open_inbox(), NOW));
        let get = wake(&mut secrets, NOW + MINUTE);
        for key in secrets.list_secrets(format!("{AUTO_PREFIX}arm:").as_bytes()) {
            crate::secrets::RemovableSecrets::remove_secret(&mut secrets, &key);
        }
        let before = held(&secrets);
        answer(
            &mut secrets,
            &get,
            Some(state_bytes(&open_inbox_at(FLOOR + 10))),
            NOW + MINUTE,
        );
        assert!(on_wakeup(&mut secrets, NOW + 2 * MINUTE).is_empty());
        let h = held(&secrets);
        assert!(h.outstanding.is_none() && h.unconfirmed.is_none());
        assert_eq!(h.failures, before.failures);
    }

    /// The watched list stays bounded: expired entries go, then the nearest
    /// horizons. Mutated red by dropping the truncation.
    #[test]
    fn the_watched_list_is_bounded() {
        let mut h = held(&delegated());
        for i in 0..(WATCHED_CAP as u32 + 10) {
            h.watched.push(Watched {
                script: script_at(i),
                until_height: TIP + i,
                canary: Vec::new(),
                canary_contract: [0; 32],
            });
        }
        h.watched.push(Watched {
            script: vec![1],
            until_height: TIP - 1,
            canary: Vec::new(),
            canary_contract: [0; 32],
        });
        prune_watched(&mut h, TIP);
        assert_eq!(h.watched.len(), WATCHED_CAP);
        assert!(h.watched.iter().all(|w| w.until_height >= TIP + 10));
    }

    /// Review round 3, P2-b: a copy is settled only once the node answered
    /// its SUBSCRIBE Ok, `SETTLE_MS` ago; an Err, no answer, or a node start
    /// leaves it unsettled. A notification for any contract ever subscribed
    /// to is this module's, even once its record is evicted. Mutated red by
    /// settling on the send, settling on an Err, not clearing on start, and
    /// forgetting evicted contracts.
    #[test]
    fn a_copy_is_settled_only_by_an_ok_to_its_subscribe() {
        let mut secrets = delegated();
        on_node_started(&mut secrets);
        assert!(!held(&secrets).settled(&INBOX, NOW));
        // An inbox read subscribes; nothing is settled until the node says Ok.
        let mut h = held(&secrets);
        let context = ReadContext {
            magic: READ_MAGIC,
            bridge: bridge(),
            kind: ReadKind::Inbox,
            script: Vec::new(),
            index: 0,
        };
        let out = read_msgs(&mut h, INBOX, &context, NOW);
        put_held(&mut secrets, &h);
        got_read(&out);
        assert!(!held(&secrets).settled(&INBOX, NOW + SETTLE_MS));
        assert!(on_subscribed(&mut secrets, &INBOX, &Err("no".into()), NOW));
        assert!(!held(&secrets).settled(&INBOX, NOW + SETTLE_MS));
        assert!(
            !on_subscribed(&mut secrets, &INBOX, &Ok(()), NOW),
            "not asked any more"
        );
        let mut h = held(&secrets);
        read_msgs(&mut h, INBOX, &context, NOW);
        put_held(&mut secrets, &h);
        assert!(on_subscribed(&mut secrets, &INBOX, &Ok(()), NOW));
        assert!(!held(&secrets).settled(&INBOX, NOW + SETTLE_MS - 1));
        assert!(held(&secrets).settled(&INBOX, NOW + SETTLE_MS));
        assert!(
            !on_subscribed(&mut secrets, &[0x77; 32], &Ok(()), NOW),
            "not ours"
        );
        on_node_started(&mut secrets);
        assert!(!held(&secrets).settled(&INBOX, NOW + SETTLE_MS));
        assert!(subscribed_to(&secrets, &INBOX), "still dropped as ours");
    }

    /// `SUBSCRIBED_CAP`: past it, the oldest record nothing reads any more is
    /// evicted, never the inbox or a canary in use while another could go.
    /// Mutated red by evicting the oldest regardless.
    #[test]
    fn the_subscribed_record_evicts_what_is_not_in_use() {
        let mut h = held(&delegated());
        h.subscribed.clear();
        h.note_subscribed(INBOX, 0);
        for n in 0..SUBSCRIBED_CAP as u8 {
            h.note_subscribed([n.wrapping_add(100); 32], 1);
        }
        assert_eq!(h.subscribed.len(), SUBSCRIBED_CAP);
        assert!(h.settled(&INBOX, SETTLE_MS), "the inbox stays");
        assert!(!h.subscribed.iter().any(|(id, _)| *id == [100; 32]));
    }

    /// Nothing is sent without a delegation, without an armed store on its
    /// bridge, without a fresh tip, or once this generation is exported.
    #[test]
    fn nothing_is_sent_without_everything_it_needs() {
        let mut none = armed();
        get_watch_key(&mut none).unwrap();
        assert!(on_wakeup(&mut none, NOW).is_empty(), "no delegation");

        let mut unarmed = delegated();
        for key in unarmed.list_secrets(format!("{AUTO_PREFIX}arm:").as_bytes()) {
            crate::secrets::RemovableSecrets::remove_secret(&mut unarmed, &key);
        }
        assert!(on_wakeup(&mut unarmed, NOW).is_empty(), "no store armed");

        let mut stale = delegated();
        assert!(
            on_wakeup(&mut stale, NOW + TIP_MAX_AGE_MS + 600_001).is_empty(),
            "no fresh tip"
        );

        let mut exported = delegated();
        exported.set_secret(EXPORTED_KEY, b"1");
        assert!(on_wakeup(&mut exported, NOW).is_empty(), "exported");
        assert!(get_watch_key(&mut exported).is_err());
        assert!(update_delegation(&mut exported, bridge(), INBOX, 0, NOW).is_err());
    }

    /// An arm whose tab already watches the next addresses far enough ahead
    /// needs nothing from the delegate. Mutated red by ignoring the arm's
    /// watches.
    #[test]
    fn the_tabs_own_watches_count() {
        let mut secrets = delegated();
        let key = crate::auto_invoice::arm_key(&[1; 32]);
        let mut record = arm_record(&secrets);
        record.arm.watched_scripts = (0..10).map(script_at).collect();
        record.arm.watched_until_height = Some(TIP + MAX_WATCH_AHEAD_BLOCKS);
        record.watched_until_ms = NOW + 30 * 24 * 60 * 60 * 1000;
        save(&mut secrets, &key, &record);
        assert!(on_wakeup(&mut secrets, NOW).is_empty());
    }

    /// The tab naming a new inbox drops what was sent to the old one, and
    /// its `made_at_ms` raises the floor the delegate dates above.
    #[test]
    fn an_update_moves_the_inbox_and_raises_the_timeline() {
        let mut secrets = delegated();
        submitted(&wake_and_read(&mut secrets, &open_inbox(), NOW));
        let status =
            update_delegation(&mut secrets, bridge(), [0x2c; 32], NOW + 9_000, NOW).unwrap();
        assert_eq!(status.inbox_contract_id, [0x2c; 32]);
        assert!(!status.outstanding);
        assert_eq!(held(&secrets).ui_made_at_ms, NOW + 9_000);
        assert!(update_delegation(&mut secrets, BridgeId([8; 32]), [0; 32], 0, NOW).is_err());
    }
}
