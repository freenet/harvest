//! Keeping instant checkout's next payment addresses watched with no tab open,
//! through a watch key the seller's Ghost Key delegated to this delegate
//! (freenet-bitcoin#30).
//!
//! # Why
//!
//! The delegate invoices only on an address the bridge was asked to watch
//! (I7 in [`crate::auto_invoice`]), and a watch request must come from the
//! seller's Ghost Key. A background run cannot reach the Ghost Key vault, so
//! until now only an open seller tab could ask, and the store stopped taking
//! orders once the ten addresses the tab had watched were used or their
//! horizon neared. Here the tab asks the Ghost Key, once, to delegate watch
//! requests for one bridge to a key this delegate holds (the watch key), and
//! the delegate then signs its own requests with it. The bridge acts on them
//! as the Ghost Key's own.
//!
//! # What runs when
//!
//! - **A wake-up** ([`on_wakeup`], every five minutes) reads the bridge's
//!   inbox when this delegate has a request waiting there, or when fewer than
//!   [`REFILL_BELOW`] of its next addresses are watched with a horizon at
//!   least [`RENEW_MARGIN_BLOCKS`] past what an invoice needs. One GET, and
//!   nothing else, per run.
//! - **The inbox read** ([`on_inbox_read`]) settles the waiting request, if
//!   any: removed by the bridge means read, so its scripts are recorded as
//!   watched through the height asked for; gone without a removal means
//!   dropped unread. Then, with nothing waiting, it sends ONE request (an
//!   inbox UPDATE) for every next address not watched far enough ahead.
//!
//! # The rules this keeps
//!
//! - **One request waiting at a time.** A watch key holds one of its Ghost
//!   Key's two places in the inbox, and a second entry sent before the first
//!   is read replaces one of the two at random. The next is sent only once
//!   the last was seen removed, or gone.
//! - **One timeline.** The tab and the delegate date their requests on one
//!   `made_at_ms` timeline per Ghost Key, and the bridge ignores a request
//!   dated at or below the last it applied. The delegate dates above both its
//!   own last and the tab's (which the tab reports), and tells the tab its own
//!   ([`WatchDelegationStatus::made_at_ms`]).
//! - **The horizon asked for is the one relied on.** A request asks for
//!   `tip + MAX_WATCH_AHEAD_BLOCKS`, with `tip` this delegate's copy of the
//!   bridge's own tip contract, which is what the bridge clamps above. A
//!   script counts for I7 only while that horizon is at least
//!   `WATCH_NEEDED_BLOCKS` past the tip.
//! - **Stop when refused.** A bridge refusing the delegation (revoked, or
//!   superseded by another device's) leaves its requests unread. After
//!   [`MAX_UNREAD_SENDS`] in a row the delegate stops, and the tab delegates
//!   again on its next open ([`WatchDelegationStatus::stalled`]).
//!
//! # The watch key is not exported
//!
//! It lives under `harvest:auto:`, which a migration export leaves behind
//! (`migration::is_store_key`), like everything here but the ledgers. A
//! successor generation has no watch key until the tab delegates to it, and
//! that newer delegation supersedes this generation's at the bridge, so an
//! old generation left running cannot go on asking in the seller's name.
//!
//! # Residuals
//!
//! - A removal means the bridge READ the request, not that it acted on it: it
//!   removes a request over its per-Ghost-Key limit of watched scripts the
//!   same way. What would show the watch running is the script's scan
//!   watermark in its address contract, which this delegate does not read.
//! - The inbox contract is the one the tab last named. A bridge that re-keys
//!   its inbox while no tab is open leaves the delegate sending to the old
//!   one until the tab next opens and names the new one; the delegate then
//!   stops after two unread sends rather than sending for ever.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_bitcoin_common::{BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::{
    sender_height, Action, ByteBuf, Delegation, EntryKey, EphemeralKey, GhostkeyId, InboxDelta,
    InboxEntryBody, InboxRequest, InboxStateV1, Sealed, WireEntry, MAX_DELEGATION_BYTES,
    MAX_SCRIPTS_PER_REQUEST, MAX_WATCH_AHEAD_BLOCKS,
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
    arms, load, save, tip_key, TipCache, AUTO_PREFIX, EXPORTED_KEY, TIP_MAX_AGE_MS,
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

/// Fewer of the next addresses than this watched far enough ahead, and a
/// request goes out for the rest: half the pool, so a buyer rush finds
/// addresses left while the request is read.
pub(crate) const REFILL_BELOW: usize = (MAX_UPCOMING_ADDRESSES / 2) as usize;

/// How far past what an invoice needs a watch must reach to count as fresh
/// when deciding whether to ask again: a day of blocks, so a pool watched in
/// one go is renewed about a day before it would stop invoicing.
pub(crate) const RENEW_MARGIN_BLOCKS: u32 = 144;

/// How long a request is given to appear in this node's copy of the inbox
/// before its absence means it was dropped.
pub(crate) const LAND_GRACE_MS: u64 = 2 * 60 * 1000;

/// Requests left unread in a row before the delegate stops sending. The
/// bridge leaves a revoked or superseded delegation's requests unread.
pub(crate) const MAX_UNREAD_SENDS: u32 = 2;

/// Bridges one delegate holds a delegation for.
pub(crate) const MAX_DELEGATIONS: usize = 8;

/// Scripts recorded as watched, per delegation. Only the next addresses
/// matter, so this is pruned to them; the cap is a bound, not a working
/// limit.
const WATCHED_CAP: usize = 64;

const INBOX_READ_MAGIC: [u8; 8] = *b"hvwinb01";

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
    pub watched: Vec<Watched>,
    #[serde(default)]
    pub unread_drops: u32,
}

/// A request sent and not yet seen read or gone.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Outstanding {
    pub entry_key: EntryKey,
    pub mainnet_height: u32,
    pub scripts: Vec<Vec<u8>>,
    pub until_height: u32,
    pub sent_at_ms: u64,
}

/// A script the bridge read this delegate's Watch for, and the height asked.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Watched {
    pub script: Vec<u8>,
    pub until_height: u32,
}

/// Carried through the inbox GET.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct InboxRead {
    magic: [u8; 8],
    bridge: BridgeId,
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
/// bridge, the Ghost Key signed it, and the certificate certifies that Ghost
/// Key (every entry is sealed to it). Not checked: the certificate's chain to
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

    let key = delegation_key(&grant.bridge);
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
        outstanding: same.as_ref().and_then(|h| {
            // A request sent to another inbox cannot be read back.
            (h.inbox_contract_id == grant.inbox_contract_id)
                .then(|| h.outstanding.clone())
                .flatten()
        }),
        watched: same.map(|h| h.watched).unwrap_or_default(),
        unread_drops: 0,
    };
    if !save(secrets, &key, &record) {
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
    let mut held =
        load_held(secrets, &bridge).ok_or("no watch delegation is held for this bridge")?;
    if held.inbox_contract_id != inbox_contract_id {
        held.inbox_contract_id = inbox_contract_id;
        // Sent to the old inbox, it cannot be read back from the new one.
        held.outstanding = None;
        held.unread_drops = 0;
    }
    held.ui_made_at_ms = held.ui_made_at_ms.max(last_made_at_ms);
    if !save(secrets, &delegation_key(&bridge), &held) {
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
        let pool = pool(secrets, held.network);
        pool.iter()
            .filter(|s| covers(held, s, tip.anchor.height))
            .count() as u32
    });
    WatchDelegationStatus {
        bridge: held.bridge,
        ghostkey: held.ghostkey,
        issued_mainnet_height: held.issued_mainnet_height,
        inbox_contract_id: held.inbox_contract_id,
        made_at_ms: held.ui_made_at_ms.max(held.own_made_at_ms),
        watched,
        outstanding: held.outstanding.is_some(),
        stalled: held.unread_drops >= MAX_UNREAD_SENDS,
    }
}

/// Whether the bridge read this delegate's Watch for `script` asking for a
/// horizon an invoice issued at `tip_height` can rely on.
fn covers(held: &Held, script: &[u8], tip_height: u32) -> bool {
    held.watched.iter().any(|w| {
        w.script == script && tip_height.saturating_add(WATCH_NEEDED_BLOCKS) <= w.until_height
    })
}

/// I7's second source: the scripts this delegate's own requests have the
/// bridge watching far enough past `tip_height`, for a store on `network`
/// trusting `bridges`.
pub(crate) fn delegated_watched<S: SecretStore>(
    secrets: &S,
    network: BitcoinNetwork,
    bridges: &[BridgeId],
    tip_height: u32,
) -> Vec<Vec<u8>> {
    all_held(secrets)
        .iter()
        .filter(|h| h.network == network && bridges.contains(&h.bridge))
        .flat_map(|h| {
            h.watched
                .iter()
                .filter(|w| covers(h, &w.script, tip_height))
                .map(|w| w.script.clone())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The nearest horizon among the scripts [`delegated_watched`] returns.
pub(crate) fn nearest_delegated_horizon<S: SecretStore>(
    secrets: &S,
    network: BitcoinNetwork,
    bridges: &[BridgeId],
    tip_height: u32,
) -> Option<u32> {
    all_held(secrets)
        .iter()
        .filter(|h| h.network == network && bridges.contains(&h.bridge))
        .flat_map(|h| {
            h.watched
                .iter()
                .filter(|w| covers(h, &w.script, tip_height))
                .map(|w| w.until_height)
                .collect::<Vec<_>>()
        })
        .min()
}

/// The delegate's next addresses, as scripts.
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

/// The next addresses to ask the bridge to watch now, or none: none unless a
/// store armed here uses this delegation, and none while at least
/// [`REFILL_BELOW`] of them are watched with [`RENEW_MARGIN_BLOCKS`] to
/// spare, by this delegate's requests or by the tab's (the arm's).
fn refill_scripts<S: SecretStore>(
    secrets: &S,
    held: &Held,
    tip_height: u32,
    now_ms: u64,
) -> Vec<Vec<u8>> {
    let armed: Vec<_> = arms(secrets)
        .into_iter()
        .filter(|r| r.arm.network == held.network && r.arm.trusted_bridges.contains(&held.bridge))
        .collect();
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
    if pool.iter().filter(|s| fresh(s)).count() >= REFILL_BELOW {
        return Vec::new();
    }
    pool.into_iter()
        .filter(|s| !fresh(s))
        .take(MAX_SCRIPTS_PER_REQUEST)
        .collect()
}

/// A wake-up's work: read the inbox of the first delegation that has a
/// request waiting, or whose next addresses need watching. At most one GET.
pub(crate) fn on_wakeup<S: SecretStore>(secrets: &S, now_ms: u64) -> Vec<OutboundDelegateMsg> {
    if secrets.has_secret(EXPORTED_KEY) || watch_key(secrets).is_none() {
        return Vec::new();
    }
    for held in all_held(secrets) {
        if held.unread_drops >= MAX_UNREAD_SENDS {
            continue;
        }
        let due = held.outstanding.is_some()
            || fresh_tip(secrets, held.network, now_ms).is_some_and(|tip| {
                !refill_scripts(secrets, &held, tip.anchor.height, now_ms).is_empty()
            });
        if !due {
            continue;
        }
        let Ok(context) = to_cbor(&InboxRead {
            magic: INBOX_READ_MAGIC,
            bridge: held.bridge,
        }) else {
            continue;
        };
        let mut get = GetContractRequest::new(ContractInstanceId::new(held.inbox_contract_id));
        get.context = DelegateContext::new(context);
        return vec![OutboundDelegateMsg::GetContractRequest(get)];
    }
    Vec::new()
}

/// The inbox GET [`on_wakeup`] sent has answered. `None` when the context is
/// not this module's.
pub(crate) fn on_inbox_read<S: SecretStore>(
    secrets: &mut S,
    contract_id: &[u8; 32],
    state: Option<&[u8]>,
    context: &[u8],
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    let read: InboxRead = from_cbor(context).ok()?;
    if read.magic != INBOX_READ_MAGIC {
        return None;
    }
    Some(settle_and_send(secrets, read.bridge, contract_id, state, now_ms).unwrap_or_default())
}

fn settle_and_send<S: SecretStore>(
    secrets: &mut S,
    bridge: BridgeId,
    contract_id: &[u8; 32],
    state: Option<&[u8]>,
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    if secrets.has_secret(EXPORTED_KEY) {
        return None;
    }
    let mut held = load_held(secrets, &bridge)?;
    // The tab named another inbox meanwhile.
    if held.inbox_contract_id != *contract_id {
        return None;
    }
    let state = InboxStateV1::decode_canonical(state?).ok()?;
    let floor = state.floor.clone()?;
    let before = held.clone();
    let tip = fresh_tip(secrets, held.network, now_ms);

    if let Some(sent) = held.outstanding.clone() {
        if state.is_removed(&sent.entry_key, sent.mainnet_height) {
            // Read. The scripts are watched through the height asked for.
            for script in sent.scripts {
                match held.watched.iter_mut().find(|w| w.script == script) {
                    Some(w) => w.until_height = w.until_height.max(sent.until_height),
                    None => held.watched.push(Watched {
                        script,
                        until_height: sent.until_height,
                    }),
                }
            }
            held.outstanding = None;
            held.unread_drops = 0;
        } else if state.entries.contains_key(&sent.entry_key)
            || now_ms.saturating_sub(sent.sent_at_ms) < LAND_GRACE_MS
        {
            // Still waiting to be read, or still landing.
            return save_if_changed(secrets, &before, &held).then(Vec::new);
        } else {
            // Gone unread: the floor passed it, or the caps pushed it out.
            held.outstanding = None;
            held.unread_drops = held.unread_drops.saturating_add(1);
        }
    }
    // Only the next addresses matter to I7.
    let pool = pool(secrets, held.network);
    held.watched.retain(|w| pool.contains(&w.script));
    if held.watched.len() > WATCHED_CAP {
        held.watched
            .sort_by_key(|w| std::cmp::Reverse(w.until_height));
        held.watched.truncate(WATCHED_CAP);
    }

    let mut out = Vec::new();
    if held.unread_drops < MAX_UNREAD_SENDS {
        if let Some(tip) = tip {
            let scripts = refill_scripts(secrets, &held, tip.anchor.height, now_ms);
            if !scripts.is_empty() {
                if let Some((sent, delta)) =
                    build_request(secrets, &held, &floor, &tip, scripts, now_ms)
                {
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
    before == now || save(secrets, &delegation_key(&now.bridge), now)
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
    floor: &freenet_bitcoin_inbox::SignedFloor,
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
