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
//! # One request's life
//!
//! 1. **Sent.** When the first [`REFILL_BELOW`] addresses from the counter are
//!    not all watched with [`RENEW_MARGIN_BLOCKS`] to spare past what an
//!    invoice needs, ONE delegated Watch goes to the inbox for every next
//!    address that is not (up to `MAX_SCRIPTS_PER_REQUEST`), asking for
//!    `tip + MAX_WATCH_AHEAD_BLOCKS`.
//! 2. **Left the inbox.** The inbox is read on later wake-ups. A removal
//!    signed by the bridge means it was read. The floor passing its height, or
//!    [`OUTSTANDING_MAX_MS`] going by (an inbox that stopped moving), means it
//!    is gone either way: a removal lasts only until the floor passes, so a
//!    node asleep for half an hour cannot tell read from dropped.
//! 3. **Confirmed.** Neither is evidence the bridge WATCHES the scripts: it
//!    removes, unapplied, a request past the Ghost Key's cap, one under a
//!    delegation it no longer honours (a conflicting one of the same height,
//!    say), or one whose `made_at_ms` is behind. What is evidence is the
//!    bridge's scan watermark in the first script's address contract reaching
//!    the tip the request left the inbox at. Only then does I7 count the
//!    scripts. No watermark within [`CONFIRM_BLOCKS`] and the request failed.
//! 4. **Kept honest.** Every [`PROBE_EVERY_MS`] the next address's watermark is
//!    read again; one [`LIVE_LAG_BLOCKS`] behind a fresh tip means the bridge
//!    stopped (a revocation, a newer delegation elsewhere), and every watch of
//!    the delegation is dropped from I7 at once.
//!
//! A tip is judged only while it is fresh: the bridge's tip contract follows
//! its scan, so a bridge that is down stops the tip, and nothing is counted
//! against the delegation meanwhile.
//!
//! # The rules this keeps
//!
//! - **One request at a time.** A watch key holds one of its Ghost Key's two
//!   places in the inbox, and a second entry sent before the first is read
//!   replaces one of the two at random. Nothing is sent while one is
//!   outstanding or unconfirmed.
//! - **One timeline.** The tab and the delegate date their requests on one
//!   `made_at_ms` timeline per Ghost Key. The delegate dates above both its
//!   own last and the tab's (which the tab reports), and tells the tab its own
//!   ([`WatchDelegationStatus::made_at_ms`]).
//! - **Stop when refused, and say so.** After [`MAX_FAILURES`] requests in a
//!   row whose watch never showed (with [`FAILURE_BACKOFF_MS`], doubling,
//!   between them) the delegation is `stalled`: it sends nothing, counts for
//!   nothing in I7, and the open tab delegates again.
//! - **One inbox read or address read per wake-up**, across all delegations,
//!   the least recently read first, and before anything else the wake-up
//!   sends (see `background`).
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
//! - **One script stands for its request.** Only the first script's
//!   watermark is read, so a request the bridge applied only in part (the
//!   Ghost Key's 1000-script cap reached mid-request) counts whole. The cap
//!   is far above what this delegate and the tab use.
//! - **A watermark does not show the horizon.** A script the tab also has
//!   watched confirms even if the bridge dropped this delegate's request; the
//!   horizon counted is then the one asked for, not the tab's. The hourly
//!   probe catches the watch ending, up to [`PROBE_EVERY_MS`] late.
//! - **Two devices, one Ghost Key.** The bridge honours one delegation per
//!   Ghost Key. Two devices that delegate in one floor window get the same
//!   issued height, and the bridge takes whichever it saw used first; the
//!   other's requests are read and ignored. Confirmation keeps that loser from
//!   invoicing unwatched addresses, and it stalls, but each device's tab
//!   re-delegates at a later height when it opens, taking the bridge back from
//!   the other. Share one device per seller, or one Ghost Key per device.
//! - **`made_at_ms` clamp.** The bridge counts a delegated request as made at
//!   most an hour past its own clock. A tab whose clock runs more than an hour
//!   fast pushes the shared timeline past that, and the delegate's requests
//!   are then stale at the bridge; confirmation fails them, and the delegation
//!   stalls until the clocks agree.
//! - **The tip is the network's, not the bridge's.** Horizons and freshness
//!   are judged against the tip contract the arm names for the network. With
//!   one bridge per network (every network Harvest runs on today) that is the
//!   delegation bridge's own.
//! - **The inbox is the one the tab last named.** A bridge that re-keys its
//!   inbox while no tab is open leaves the delegate's requests unread: each
//!   times out ([`OUTSTANDING_MAX_MS`]), fails confirmation, and after
//!   [`MAX_FAILURES`] the delegation stalls until the tab names the new inbox.

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
    UpdateContractRequest, UpdateData,
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
/// prefix, because I7 only ever invoices the NEXT address: fresh addresses
/// further on do not help a buyer now (review round 1 of freenet/harvest#179).
pub(crate) const REFILL_BELOW: usize = (MAX_UPCOMING_ADDRESSES / 2) as usize;

/// How far past what an invoice needs a watch must reach to count as fresh
/// when deciding whether to ask again: a day of blocks, so a pool watched in
/// one go is renewed about a day before it would stop invoicing.
pub(crate) const RENEW_MARGIN_BLOCKS: u32 = 144;

/// A request still in the inbox this long is taken to have left it: an inbox
/// whose floor stopped moving (the bridge re-keyed it, say) would otherwise
/// hold it for ever.
pub(crate) const OUTSTANDING_MAX_MS: u64 = 2 * 60 * 60 * 1000;

/// Blocks after a request left the inbox within which the first script's
/// watermark must reach the tip it left at.
pub(crate) const CONFIRM_BLOCKS: u32 = 6;

/// How often the next watched address's watermark is read again, and how far
/// behind a fresh tip it may be before the delegation's watches stop counting.
pub(crate) const PROBE_EVERY_MS: u64 = 60 * 60 * 1000;
pub(crate) const LIVE_LAG_BLOCKS: u32 = 6;

/// Requests in a row whose watch never showed before the delegation stalls.
pub(crate) const MAX_FAILURES: u32 = 3;

/// The wait after a failed request before the next, doubled per further
/// failure.
pub(crate) const FAILURE_BACKOFF_MS: u64 = 30 * 60 * 1000;

/// Bridges one delegate holds a delegation for.
pub(crate) const MAX_DELEGATIONS: usize = 8;

/// Scripts recorded as watched, per delegation. Only the next addresses
/// matter, so this is pruned to them; the cap is a bound, not a working
/// limit.
const WATCHED_CAP: usize = 64;

const READ_MAGIC: [u8; 8] = *b"hvwinb02";

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
    /// Confirmed: the bridge's watermark showed.
    #[serde(default)]
    pub watched: Vec<Watched>,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_failure_ms: Option<u64>,
    /// When this delegation's inbox or address was last read, for taking
    /// turns between delegations.
    #[serde(default)]
    pub last_read_ms: u64,
    #[serde(default)]
    pub last_probe_ms: Option<u64>,
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
}

/// A request sent and not yet seen to leave the inbox.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Outstanding {
    pub entry_key: EntryKey,
    pub mainnet_height: u32,
    pub scripts: Vec<Vec<u8>>,
    pub until_height: u32,
    pub sent_at_ms: u64,
}

/// A request that left the inbox, waiting for its watermark.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Unconfirmed {
    pub scripts: Vec<Vec<u8>>,
    pub until_height: u32,
    /// The tip when it was seen to leave: the watermark must reach it.
    pub since_tip: u32,
    /// Whether a removal was seen (read), or it merely left.
    pub removed: bool,
}

/// A script the bridge is watching for this delegate, and the height asked.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Watched {
    pub script: Vec<u8>,
    pub until_height: u32,
}

/// What a read this module sent is for.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
enum ReadKind {
    Inbox,
    /// The first script of the unconfirmed request.
    Confirm,
    /// The next watched address.
    Probe,
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
    let watched = match fresh_tip(secrets, held.network, now_ms) {
        Some(tip) if !held.stalled() => pool(secrets, held.network)
            .iter()
            .take_while(|s| covers(held, s, tip.anchor.height))
            .count() as u32,
        _ => 0,
    };
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
/// horizon asked, for a store on `network` trusting `bridges`. A stalled
/// delegation counts for nothing: what stalls it is the bridge not watching.
pub(crate) fn delegated_watched<S: SecretStore>(
    secrets: &S,
    network: BitcoinNetwork,
    bridges: &[BridgeId],
    tip_height: u32,
) -> Vec<(Vec<u8>, u32)> {
    all_held(secrets)
        .iter()
        .filter(|h| h.network == network && bridges.contains(&h.bridge) && !h.stalled())
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
        .take(MAX_SCRIPTS_PER_REQUEST)
        .collect()
}

/// The address contract the bridge publishes `script`'s watermark to, as the
/// orders this store issues name it (`Order::bitcoin_address_instance_id_under`).
fn address_contract(arm: &AutoInvoiceArm, script: &[u8]) -> Option<[u8; 32]> {
    let params = to_cbor(&address_params(arm, script)).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&arm.address_code_hash);
    hasher.update(&params);
    Some(*hasher.finalize().as_bytes())
}

pub(crate) fn address_params(arm: &AutoInvoiceArm, script: &[u8]) -> BitcoinAddressParameters {
    BitcoinAddressParameters {
        network: arm.network,
        script_pubkey: script.to_vec(),
        trusted_bridges: arm.trusted_bridges.clone(),
        pow_floor: arm.network.default_pow_floor(),
    }
}

/// What this delegation should read now, if anything.
fn due_read<S: SecretStore>(
    secrets: &S,
    held: &Held,
    now_ms: u64,
) -> Option<(ContractInstanceId, ReadContext)> {
    let context = |kind, script: Vec<u8>| ReadContext {
        magic: READ_MAGIC,
        bridge: held.bridge,
        kind,
        script,
    };
    let inbox = || ContractInstanceId::new(held.inbox_contract_id);
    let arm = armed_for(secrets, held).into_iter().next().map(|r| r.arm);
    let address = |script: &Vec<u8>| {
        arm.as_ref()
            .and_then(|arm| address_contract(arm, script))
            .map(ContractInstanceId::new)
    };
    if let Some(unconfirmed) = &held.unconfirmed {
        let script = unconfirmed.scripts.first()?.clone();
        return Some((address(&script)?, context(ReadKind::Confirm, script)));
    }
    if held.outstanding.is_some() {
        return Some((inbox(), context(ReadKind::Inbox, Vec::new())));
    }
    if held.stalled() {
        return None;
    }
    let tip = fresh_tip(secrets, held.network, now_ms)?;
    // The next address, if this delegation is what watches it.
    let next = pool(secrets, held.network).into_iter().next();
    if let Some(next) = next.filter(|s| covers(held, s, tip.anchor.height)) {
        if held
            .last_probe_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= PROBE_EVERY_MS)
        {
            let id = address(&next)?;
            return Some((id, context(ReadKind::Probe, next)));
        }
    }
    (held.may_send(now_ms) && !refill_scripts(secrets, held, tip.anchor.height, now_ms).is_empty())
        .then(|| (inbox(), context(ReadKind::Inbox, Vec::new())))
}

/// A wake-up's work: one read, for the delegation that has gone longest
/// without one among those that have something to read.
pub(crate) fn on_wakeup<S: SecretStore>(secrets: &mut S, now_ms: u64) -> Vec<OutboundDelegateMsg> {
    if secrets.has_secret(EXPORTED_KEY) || watch_key(secrets).is_none() {
        return Vec::new();
    }
    let mut due: Vec<(Held, ContractInstanceId, ReadContext)> = all_held(secrets)
        .into_iter()
        .filter_map(|held| {
            due_read(secrets, &held, now_ms).map(|(id, context)| (held, id, context))
        })
        .collect();
    due.sort_by_key(|(held, _, _)| held.last_read_ms);
    let Some((mut held, id, context)) = due.into_iter().next() else {
        return Vec::new();
    };
    let Ok(context) = to_cbor(&context) else {
        return Vec::new();
    };
    held.last_read_ms = now_ms;
    if !store_held(secrets, &held) {
        return Vec::new();
    }
    let mut get = GetContractRequest::new(id);
    get.context = DelegateContext::new(context);
    vec![OutboundDelegateMsg::GetContractRequest(get)]
}

/// A GET [`on_wakeup`] sent has answered. `None` when the context is not this
/// module's.
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
        ReadKind::Confirm | ReadKind::Probe => {
            on_address(secrets, held, read.kind, &read.script, state, now_ms);
            None
        }
    };
    Some(out.unwrap_or_default())
}

/// The first script's watermark by this delegation's bridge, as signed.
fn watermark(held: &Held, arm: &AutoInvoiceArm, script: &[u8], state: &[u8]) -> Option<u32> {
    let state: freenet_bitcoin_common::BitcoinAddressStateV1 =
        freenet_bitcoin_common::from_cbor(state).ok()?;
    let claim = state.claims.scanned.get(&held.bridge)?;
    let body = claim.verify(&address_params(arm, script)).ok()?;
    matches!(body.claim, freenet_bitcoin_common::Claim::ScannedTo).then_some(body.as_of.height)
}

fn on_address<S: SecretStore>(
    secrets: &mut S,
    mut held: Held,
    kind: ReadKind,
    script: &[u8],
    state: Option<&[u8]>,
    now_ms: u64,
) {
    // Judged only against a fresh tip: a bridge that is down stops its tip
    // contract too, and nothing is counted against the delegation then.
    let Some(tip) = fresh_tip(secrets, held.network, now_ms) else {
        return;
    };
    let Some(arm) = armed_for(secrets, &held).into_iter().next().map(|r| r.arm) else {
        return;
    };
    let seen = state.and_then(|state| watermark(&held, &arm, script, state));
    let before = held.clone();
    match kind {
        ReadKind::Confirm => {
            let Some(pending) = held.unconfirmed.clone() else {
                return;
            };
            if pending.scripts.first().map(Vec::as_slice) != Some(script) {
                return;
            }
            if seen.is_some_and(|h| h >= pending.since_tip) {
                for script in pending.scripts {
                    match held.watched.iter_mut().find(|w| w.script == script) {
                        Some(w) => w.until_height = w.until_height.max(pending.until_height),
                        None => held.watched.push(Watched {
                            script,
                            until_height: pending.until_height,
                        }),
                    }
                }
                held.unconfirmed = None;
                held.failures = 0;
                held.last_failure_ms = None;
                held.last_probe_ms = Some(now_ms);
            } else if tip.anchor.height >= pending.since_tip.saturating_add(CONFIRM_BLOCKS) {
                // Read or not, the bridge is not scanning it.
                held.unconfirmed = None;
                held.fail(now_ms);
            }
        }
        ReadKind::Probe => {
            held.last_probe_ms = Some(now_ms);
            let live = seen.is_some_and(|h| h.saturating_add(LIVE_LAG_BLOCKS) >= tip.anchor.height);
            if !live {
                // The bridge stopped: revoked, superseded, or lost its
                // records. Nothing it was asked for through this delegation
                // counts any more; what is still wanted is asked for again.
                held.watched.clear();
                held.fail(now_ms);
            }
        }
        ReadKind::Inbox => {}
    }
    if held != before {
        store_held(secrets, &held);
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
            held.unconfirmed = Some(Unconfirmed {
                scripts: sent.scripts,
                until_height: sent.until_height,
                since_tip: tip.anchor.height,
                removed,
            });
        }
        // Either way nothing is sent until it is confirmed or failed.
        return save_if_changed(secrets, &before, &held).then(Vec::new);
    }
    if held.unconfirmed.is_some() || !held.may_send(now_ms) {
        return save_if_changed(secrets, &before, &held).then(Vec::new);
    }
    let (Some(state), Some(tip)) = (state, tip) else {
        return save_if_changed(secrets, &before, &held).then(Vec::new);
    };
    let floor = state.floor.clone()?;
    // Only the next addresses matter to I7.
    let pool = pool(secrets, held.network);
    held.watched.retain(|w| pool.contains(&w.script));
    if held.watched.len() > WATCHED_CAP {
        held.watched
            .sort_by_key(|w| std::cmp::Reverse(w.until_height));
        held.watched.truncate(WATCHED_CAP);
    }
    let mut out = Vec::new();
    let scripts = refill_scripts(secrets, &held, tip.anchor.height, now_ms);
    if !scripts.is_empty() {
        if let Some((sent, delta)) = build_request(secrets, &held, &floor, &tip, scripts, now_ms) {
            held.own_made_at_ms = sent.made_at_ms;
            held.outstanding = Some(sent.outstanding);
            out.push(OutboundDelegateMsg::UpdateContractRequest(
                UpdateContractRequest::new(
                    ContractInstanceId::new(held.inbox_contract_id),
                    UpdateData::Delta(StateDelta::from(delta)),
                ),
            ));
        }
    }
    // Recorded before anything is sent: a request sent but not recorded
    // would be followed by a second one into the watch key's one place.
    if !save_if_changed(secrets, &before, &held) {
        return None;
    }
    Some(out)
}

fn save_if_changed<S: SecretStore>(secrets: &mut S, before: &Held, now: &Held) -> bool {
    before == now || store_held(secrets, now)
}

struct Built {
    outstanding: Outstanding,
    made_at_ms: u64,
}

/// One delegated Watch for `scripts`: sealed to the bridge under the seller's
/// Ghost Key, dated against `floor`, signed by the watch key, and wrapped as
/// the inbox update that submits it.
fn build_request<S: SecretStore>(
    secrets: &S,
    held: &Held,
    floor: &SignedFloor,
    tip: &TipCache,
    scripts: Vec<Vec<u8>>,
    now_ms: u64,
) -> Option<(Built, Vec<u8>)> {
    let sk = watch_key(secrets)?;
    let mainnet_height = sender_height(floor.height);
    // The inbox refuses an entry dated before its delegation.
    if mainnet_height < held.issued_mainnet_height {
        return None;
    }
    let made_at_ms = now_ms
        .max(held.ui_made_at_ms.saturating_add(1))
        .max(held.own_made_at_ms.saturating_add(1));
    let until_height = tip.anchor.height.saturating_add(MAX_WATCH_AHEAD_BLOCKS);
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
        secrets
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

    /// The one GET a wake-up sends, which must come first.
    pub fn wake(secrets: &mut MemSecrets, now_ms: u64) -> GetContractRequest {
        let out = on_wakeup(secrets, now_ms);
        assert_eq!(out.len(), 1, "one read: {out:?}");
        let OutboundDelegateMsg::GetContractRequest(get) = &out[0] else {
            panic!("expected a GET, got {:?}", out[0]);
        };
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

    /// A wake-up's GET, which must be the inbox's, answered with `state`.
    pub fn wake_and_read(
        secrets: &mut MemSecrets,
        state: &InboxStateV1,
        now_ms: u64,
    ) -> Vec<OutboundDelegateMsg> {
        let get = wake(secrets, now_ms);
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
        let params = address_params(&arm, script);
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
    /// with the bridge's watermark at `scanned`.
    pub fn wake_and_scan(
        secrets: &mut MemSecrets,
        script: &[u8],
        scanned: Option<u32>,
        now_ms: u64,
    ) {
        let get = wake(secrets, now_ms);
        let arm = arm_record(secrets).arm;
        assert_eq!(
            get.contract_id.as_bytes(),
            address_contract(&arm, script).unwrap().as_slice(),
            "the address contract is read"
        );
        let state = address_state(secrets, script, scanned);
        assert!(answer(secrets, &get, Some(state), now_ms).is_empty());
    }

    /// One request sent, read by the bridge, and confirmed by its first
    /// script's watermark at the tip: the entry that carried it.
    pub fn send_read_confirm(secrets: &mut MemSecrets, tip: u32, now_ms: u64) -> WireEntry {
        let mut inbox = open_inbox();
        let (delta, entry) = submitted(&wake_and_read(secrets, &inbox, now_ms));
        inbox.apply_delta(&params(), &delta).unwrap();
        bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wake_and_read(secrets, &inbox, now_ms + 5 * MINUTE).is_empty());
        let first = held(secrets).unconfirmed.expect("left the inbox").scripts[0].clone();
        wake_and_scan(secrets, &first, Some(tip), now_ms + 10 * MINUTE);
        assert!(held(secrets).unconfirmed.is_none(), "confirmed");
        entry
    }

    /// Record `scripts` as confirmed watched through `until`.
    pub fn confirm_watched(secrets: &mut MemSecrets, scripts: &[Vec<u8>], until: u32) {
        let mut h = held(secrets);
        for script in scripts {
            h.watched.retain(|w| w.script != *script);
            h.watched.push(Watched {
                script: script.clone(),
                until_height: until,
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
    /// Ghost Key, carrying another key's certificate, for another bridge, or
    /// older than the one held, is refused. Each check mutated red by
    /// removing it.
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
    /// wake-up with too few watched addresses reads the inbox, and the answer
    /// sends exactly one delegated Watch that the inbox contract admits and
    /// the bridge opens, naming the next addresses, the horizon asked from
    /// the tip, and a `made_at_ms` above the tab's. Mutated red by: sealing to
    /// the watch key instead of the Ghost Key, dating beyond the window, and
    /// dropping the `ui_made_at + 1` floor.
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
        assert_eq!(scripts(&entry), (0..10).map(script_at).collect::<Vec<_>>());
        assert_eq!(
            request.watch_until_height,
            Some(TIP + MAX_WATCH_AHEAD_BLOCKS)
        );
        assert_eq!(request.made_at_ms, NOW + 501, "above the tab's last");
        assert_eq!(request.revoke_watch_keys_through, None);

        let held = held(&secrets);
        assert_eq!(held.own_made_at_ms, NOW + 501);
        let sent = held.outstanding.expect("recorded as outstanding");
        assert_eq!(sent.entry_key, entry.entry.key());
        assert_eq!(sent.until_height, TIP + MAX_WATCH_AHEAD_BLOCKS);
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
        // The next wake-up reads the watermark, not the inbox.
        let get = wake(&mut secrets, NOW + 20 * MINUTE);
        assert_ne!(get.contract_id.as_bytes(), INBOX.as_slice());
        // And an inbox read answered meanwhile (sent before it left) sends
        // nothing either.
        let late_inbox_read = to_cbor(&ReadContext {
            magic: READ_MAGIC,
            bridge: bridge(),
            kind: ReadKind::Inbox,
            script: Vec::new(),
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

    /// A removal is not a watch: the scripts count for I7 only once the first
    /// one's watermark by this bridge reaches the tip the request left at; a
    /// watermark from before it, one signed by another key, or none, does
    /// not confirm, and past `CONFIRM_BLOCKS` the request has failed.
    /// Mutated red by: confirming on the removal alone, dropping the
    /// `since_tip` comparison, and not verifying the claim's signature.
    #[test]
    fn a_read_request_counts_only_once_its_watermark_shows() {
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

        let first = script_at(0);
        wake_and_scan(&mut secrets, &first, None, NOW + 10 * MINUTE);
        wake_and_scan(&mut secrets, &first, Some(TIP - 1), NOW + 15 * MINUTE);
        // Signed by someone other than the bridge.
        let get = wake(&mut secrets, NOW + 20 * MINUTE);
        let arm = arm_record(&secrets).arm;
        let mut forged = freenet_bitcoin_common::BitcoinAddressStateV1::default();
        let body = freenet_bitcoin_common::address_state::scanned_to_body(
            &address_params(&arm, &first),
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

        wake_and_scan(&mut secrets, &first, Some(TIP), NOW + 25 * MINUTE);
        assert_eq!(
            watched_now(&secrets, TIP),
            (0..10).map(script_at).collect::<Vec<_>>()
        );
        let h = held(&secrets);
        assert!(h.unconfirmed.is_none() && h.failures == 0);
        let status = status_of(&secrets, &h, NOW);
        assert_eq!((status.watched, status.outstanding), (10, false));

        // Another request that never shows: failed after CONFIRM_BLOCKS.
        let mut h = held(&secrets);
        h.unconfirmed = Some(Unconfirmed {
            scripts: vec![script_at(0)],
            until_height: TIP + 1,
            since_tip: TIP,
            removed: true,
        });
        put_held(&mut secrets, &h);
        set_tip_at(&mut secrets, TIP + CONFIRM_BLOCKS - 1, NOW + 30 * MINUTE);
        wake_and_scan(&mut secrets, &first, None, NOW + 30 * MINUTE);
        assert_eq!(held(&secrets).failures, 0, "not yet");
        set_tip_at(&mut secrets, TIP + CONFIRM_BLOCKS, NOW + 35 * MINUTE);
        wake_and_scan(&mut secrets, &first, None, NOW + 35 * MINUTE);
        let h = held(&secrets);
        assert!(h.unconfirmed.is_none());
        assert_eq!(h.failures, 1);
    }

    /// A request gone from the inbox without a removal seen (the floor passed
    /// it while this node slept) is not a failure by itself: its watermark
    /// decides. Mutated red by counting it failed on the spot.
    #[test]
    fn a_request_the_floor_passed_is_judged_by_its_watermark() {
        let mut secrets = delegated();
        let inbox = open_inbox();
        let (_, entry) = submitted(&wake_and_read(&mut secrets, &inbox, NOW));
        let moved = open_inbox_at(entry.entry.mainnet_height + 1);
        assert!(wake_and_read(&mut secrets, &moved, NOW + 40 * MINUTE).is_empty());
        let h = held(&secrets);
        assert!(h.unconfirmed.as_ref().is_some_and(|u| !u.removed));
        assert_eq!(h.failures, 0);
        wake_and_scan(&mut secrets, &script_at(0), Some(TIP), NOW + 45 * MINUTE);
        assert_eq!(watched_now(&secrets, TIP).len(), 10);
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

    /// Only a floor the bridge signed is read: a copy carrying another key's
    /// floor dates nothing and sends nothing. Mutated red by dropping the
    /// floor's signature check.
    #[test]
    fn an_inbox_floor_the_bridge_did_not_sign_is_ignored() {
        let mut secrets = delegated();
        let mut forged = open_inbox();
        forged.floor = Some(SignedFloor::sign(&SigningKey::from_bytes(&[8; 32]), FLOOR));
        assert!(wake_and_read(&mut secrets, &forged, NOW).is_empty());
        assert!(held(&secrets).outstanding.is_none());
    }

    /// The hourly probe: the next address's watermark falling behind a fresh
    /// tip (a revocation, a newer delegation elsewhere) drops every watch of
    /// the delegation from I7 at once. Mutated red by dropping the clear.
    #[test]
    fn a_stale_watermark_withdraws_the_delegations_watches() {
        let mut secrets = delegated();
        send_read_confirm(&mut secrets, TIP, NOW);
        assert_eq!(watched_now(&secrets, TIP).len(), 10);
        // Probed within the hour of confirming: nothing to read.
        assert!(on_wakeup(&mut secrets, NOW + 30 * MINUTE).is_empty());
        let at = NOW + 10 * MINUTE + PROBE_EVERY_MS;
        set_tip_at(&mut secrets, TIP + 6, at);
        wake_and_scan(&mut secrets, &script_at(0), Some(TIP + 6), at);
        assert_eq!(watched_now(&secrets, TIP + 6).len(), 10, "live");
        let at = at + PROBE_EVERY_MS;
        set_tip_at(&mut secrets, TIP + 20, at);
        wake_and_scan(&mut secrets, &script_at(0), Some(TIP + 13), at);
        assert!(watched_now(&secrets, TIP + 20).is_empty(), "withdrawn");
        assert_eq!(held(&secrets).failures, 1);
    }

    /// A horizon is relied on only while it covers an invoice's window, and
    /// renewed a day before: at the margin a new request goes out. Mutated
    /// red by an off-by-one in `covers` and by dropping the margin.
    #[test]
    fn a_horizon_near_the_tip_is_not_relied_on_and_is_renewed() {
        let mut secrets = delegated();
        send_read_confirm(&mut secrets, TIP, NOW);
        let until = TIP + MAX_WATCH_AHEAD_BLOCKS;
        let last_ok = until - WATCH_NEEDED_BLOCKS;
        assert_eq!(watched_now(&secrets, last_ok).len(), 10);
        assert!(watched_now(&secrets, last_ok + 1).is_empty());

        // A day of blocks before that, still quiet; one block later, renewed.
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
        assert_eq!(scripts(&renewal).len(), 10);
        assert!(
            opened(&renewal).made_at_ms > NOW + 501,
            "above its own last"
        );
    }

    /// The refill looks at the NEXT addresses, not anywhere in the pool
    /// (review round 1 of #179): with 6-9 watched through an older horizon
    /// and 10-15 through a newer one, the older one nearing sends a renewal
    /// for 6-9 though six fresh addresses sit further on. Mutated red by
    /// counting fresh addresses anywhere in the pool.
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
        assert_eq!(
            scripts(&renewal),
            (6..10).map(script_at).collect::<Vec<_>>()
        );
    }

    /// Requests whose watch never shows: each failure waits a doubling
    /// backoff before the next send, and after `MAX_FAILURES` the delegation
    /// stalls, sends nothing and counts for nothing in I7 (a revoked Ghost
    /// Key's withdrawn watches with it); a later delegation starts it afresh.
    /// Mutated red by: ignoring the backoff, dropping the stall from
    /// `delegated_watched`, and dropping it from `due_read`.
    #[test]
    fn requests_whose_watch_never_shows_stall_the_delegation() {
        let mut secrets = delegated();
        send_read_confirm(&mut secrets, TIP, NOW);
        let mut h = held(&secrets);
        h.failures = 1;
        h.last_failure_ms = Some(NOW);
        h.last_probe_ms = Some(NOW);
        put_held(&mut secrets, &h);
        set_counter(&mut secrets, 6);
        // Backoff: no send before FAILURE_BACKOFF_MS.
        assert!(on_wakeup(&mut secrets, NOW + FAILURE_BACKOFF_MS - 1).is_empty());
        let at = NOW + FAILURE_BACKOFF_MS;
        set_tip_at(&mut secrets, TIP, at);
        submitted(&wake_and_read(&mut secrets, &open_inbox(), at));

        let mut h = held(&secrets);
        h.outstanding = None;
        h.failures = MAX_FAILURES;
        put_held(&mut secrets, &h);
        assert!(status_of(&secrets, &h, NOW).stalled);
        assert!(
            watched_now(&secrets, TIP).is_empty(),
            "stalled counts for nothing"
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
        assert_eq!(
            watched_now(&secrets, TIP).len(),
            4,
            "a later one counts again"
        );
    }

    /// The five-minute wake-up is what runs it, and its read goes first, so
    /// the node's cap on network operations falls on heartbeats instead.
    /// Mutated red by dropping the call from `background`, and by putting it
    /// after the heartbeats.
    #[test]
    fn the_wakeup_reads_the_inbox_first() {
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
        assert!(
            matches!(out.first(), Some(OutboundDelegateMsg::GetContractRequest(get))
                if get.contract_id.as_bytes() == INBOX.as_slice()),
            "{out:?}"
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
