//! Bound the work each Harvest delegate handler does in one call.
//!
//! A Freenet node stops a delegate call after 5 s of wall clock
//! (`RuntimeConfig::max_execution_seconds`). A handler that needs longer does
//! not fail loudly: the node answers the web app with an unattributable error
//! and the flow waiting on the answer hangs (harvest#203, harvest#204). Native
//! unit tests cannot see this -- they run about 7x faster than the delegate
//! WASM and have no limit at all.
//!
//! This runs the COMMITTED delegate WASM under wasmtime with fuel metering,
//! drives it through what the Harvest web app and the node send it, and fails
//! if any single call consumes more than [`BUDGET_FUEL`]. Fuel counts WASM
//! instructions executed, so the result is identical on every machine and
//! every run: this is not a timing test and cannot flake. See README.md for
//! how the budget was calibrated against wall-clock time.
//!
//! Usage:
//!   harvest-delegate-budget [--wasm PATH] [--calibrate [REPS]]

/// The delegate's own BIP-32 code, compiled in: the published-script
/// fixtures are what the configured account key derives, by the code that
/// derives them in the delegate. Only the derivation is used here.
#[allow(dead_code)]
#[path = "../../../delegates/harvest-delegate/src/bip32.rs"]
mod bip32;
mod fixtures;
mod host;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ciborium::Value;
use ed25519_dalek::SigningKey;
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractInstanceId, ContractNotification, DelegateContext,
    GetContractResponse, InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, WrappedState,
};
use harvest_common::bitcoin_delegate::BitcoinDelegateRequest;
use harvest_common::delegate::{
    AutoInvoiceArm, ConversationSecret, HarvestDelegateRequest, KeptPurchase, PurchaseToKeep,
    WrapSignature,
};
use harvest_common::migration::HarvestMigrationRequest;
use x25519_dalek::{PublicKey, StaticSecret};

use host::{Host, HostState};

/// The most fuel one delegate call may consume.
///
/// Roughly ONE SECOND of this delegate's work on the reference machine (nova),
/// a fifth of the node's 5 s per-call limit: one second at the SLOWEST rate
/// measured there with the node's engine, memory layout included
/// (copy-heavy code, about 3.1 billion fuel/s; crypto runs at about 7
/// billion, so for crypto this is about 0.4 s). The margin is for everything
/// fuel does not see: a slower CPU than the reference, a node under load (the
/// limit is wall clock, and nova at load 9-18 turned 1/30 timeouts into 7/30
/// in the #203 investigation), and host-function time (the node's encrypted
/// secret store). Calibration, and how to redo it: README.md.
const BUDGET_FUEL: u64 = 3_000_000_000;

/// The seconds of work [`BUDGET_FUEL`] stands for, for the report only.
const BUDGET_SECONDS: f64 = 1.0;

/// The most secret writes and removals one call may make. Fuel does not
/// see them, and on a node each is an encrypted file write with an fsync
/// (`secrets_store/store.rs`): 5-30 ms on slow storage, so 64 is up to about
/// two seconds there. The most measured today is 18 (the wake-up with watch
/// delegations: one write per arm, and the delegation it reads for).
const BUDGET_WRITES: u64 = 64;

/// How many store keys to derive subkeys for. `GetStoreSubkeys` cost used to
/// depend on the store key (a seeded RSA prime search), so one key proves
/// nothing either way; the #203 probe saw 0.85-5 s across keys.
const STORE_KEYS: usize = 8;

/// The delegate's caps this scenario fills, read from its source so a raised
/// cap raises the fixture with it ([`delegate_cap`]).
fn caps() -> Result<Caps> {
    Ok(Caps {
        store_keys: delegate_cap("store_keys.rs", "MAX_STORE_KEYS")?,
        arms: delegate_cap("auto_invoice.rs", "MAX_ARMS")?,
        known_stores: delegate_cap("known_stores.rs", "MAX_KNOWN_STORES")?,
        buyer_conversations: delegate_cap("messaging.rs", "MAX_BUYER_CONVERSATIONS")?,
    })
}

/// The ledger caps a seeded ledger is filled to.
pub struct LedgerCaps {
    pub seen: usize,
    pub answered: usize,
    /// `STATUSES_CAP`, which bounds both `statuses` and `oversold`.
    pub statuses: usize,
    pub sales: usize,
    pub gap_orders: usize,
}

struct Caps {
    store_keys: usize,
    arms: usize,
    known_stores: usize,
    buyer_conversations: usize,
}

/// `pub(crate) const {name}: usize = N;` in the delegate's `src/{file}`.
/// The constants are crate-private, so they are read from the source; a
/// renamed or reshaped constant fails the run rather than leaving a stale
/// fixture size.
fn delegate_cap(file: &str, name: &str) -> Result<usize> {
    Ok(usize::try_from(delegate_const(file, name, "usize")?)?)
}

/// [`delegate_cap`] for a `u32` constant.
fn delegate_u32(file: &str, name: &str) -> Result<u32> {
    Ok(u32::try_from(delegate_const(file, name, "u32")?)?)
}

/// `const {name}: {ty} = ...;` in the delegate's `src/{file}`, evaluated: a
/// sum of products of literals and the public constants named in
/// [`known_const`]. Anything else fails the run.
fn delegate_const(file: &str, name: &str, ty: &str) -> Result<u64> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../delegates/harvest-delegate/src")
        .join(file);
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let needle = format!("const {name}: {ty} = ");
    let found = src.matches(&needle).count();
    if found != 1 {
        bail!("{name} occurs {found} times in {file}, expected once: update the harness");
    }
    let rest = src.split(&needle).nth(1).unwrap_or_default();
    let expr = rest.split(';').next().unwrap_or_default();
    expr.split('+')
        .map(|term| {
            term.split('*').try_fold(1u64, |acc, factor| {
                let factor = factor.trim();
                let value = match known_const(factor) {
                    Some(v) => v,
                    None => factor.replace('_', "").parse().with_context(|| {
                        format!("{name} in {file} is not a sum of known terms: {factor}")
                    })?,
                };
                Ok::<_, anyhow::Error>(acc * value)
            })
        })
        .sum()
}

/// The constants a delegate constant may be written in terms of.
fn known_const(name: &str) -> Option<u64> {
    match name {
        "MAX_ANCHOR_AGE_BLOCKS" => Some(harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS.into()),
        _ => None,
    }
}

/// The height of the tip the bridge publishes in this scenario.
const TIP_HEIGHT: u32 = 250_000;

/// The mailbox cap (`harvest_common::mailbox::MAX_MESSAGES`): the most
/// distinct senders one `DeriveConversationKeys` can name.
const MAILBOX_PEERS: usize = harvest_common::mailbox::MAX_MESSAGES;

/// `harvest_common::delegate::MAX_KEPT_PURCHASES`: purchases a buyer keeps.
const KEPT_PURCHASES: usize = harvest_common::delegate::MAX_KEPT_PURCHASES;

struct Measured {
    name: String,
    fuel: Option<u64>,
    /// Host-function calls the metered run made (deterministic, reported
    /// only: fuel does not count host time, so this shows how much of a call
    /// happens outside it).
    host_calls: u64,
    /// Secret writes and removals the call made (each an fsync'd file write
    /// on a node; see [`BUDGET_WRITES`]).
    host_writes: u64,
    /// `--calibrate` only: the best unmetered, node-like wall time of
    /// `process`, and the part of it spent in host functions.
    timing: Option<(Duration, Duration)>,
}

struct Runner {
    host: Host,
    origin: MessageOrigin,
    calibrate_reps: usize,
    measured: Vec<Measured>,
    /// Whether this is the committed delegate (no `--wasm`): it must take
    /// every request the harness sends, so no step may be skipped for it.
    committed: bool,
}

impl Runner {
    /// Send one application message as the Harvest web app. The handler must
    /// ANSWER: a refusal or an error means the harness is not exercising the
    /// handler's real work, so it is a harness failure, not a pass.
    fn app(&mut self, name: &str, payload: Vec<u8>, expect: &str) -> Result<Value> {
        let outbound = self.send(name, payload)?;
        let response = first_app_payload(&outbound)
            .ok_or_else(|| anyhow!("{name}: no application message in the answer"))?;
        let value: Value = ciborium::from_reader(response.as_slice())
            .with_context(|| format!("{name}: the answer is not CBOR"))?;
        check_answer(name, &value, expect)?;
        Ok(value)
    }

    /// [`Self::app`] for a call made only to read the delegate's state:
    /// not measured, and not in the report.
    fn quiet_app(&mut self, payload: Vec<u8>, expect: &str) -> Result<Value> {
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload));
        let origin = self.origin.clone();
        let outbound = self
            .host
            .call(Some(&origin), &msg)?
            .result
            .map_err(|e| anyhow!("{expect}: the delegate returned an error: {e}"))?;
        let response = first_app_payload(&outbound)
            .ok_or_else(|| anyhow!("{expect}: no application message in the answer"))?;
        let value: Value = ciborium::from_reader(response.as_slice())
            .with_context(|| format!("{expect}: the answer is not CBOR"))?;
        check_answer(expect, &value, expect)?;
        Ok(value)
    }

    /// Send an application message unmeasured, ignoring the answer.
    fn quiet_send(&mut self, payload: &[u8]) -> Result<()> {
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload.to_vec()));
        let origin = self.origin.clone();
        self.host
            .call(Some(&origin), &msg)?
            .result
            .map_err(|e| anyhow!("the delegate returned an error: {e}"))?;
        Ok(())
    }

    fn send(&mut self, name: &str, payload: Vec<u8>) -> Result<Vec<OutboundDelegateMsg>> {
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload));
        let origin = self.origin.clone();
        let timing = self.time(Some(&origin), &msg)?;
        let outcome = self.host.call(Some(&origin), &msg)?;
        self.record(name, &outcome, timing);
        outcome
            .result
            .map_err(|e| anyhow!("{name}: the delegate returned an error: {e}"))
    }

    /// A state change of a contract the delegate subscribed to. The node
    /// delivers these with no origin.
    fn notify(
        &mut self,
        name: &str,
        contract: [u8; 32],
        state: Vec<u8>,
    ) -> Result<Vec<OutboundDelegateMsg>> {
        let msg = InboundDelegateMsg::ContractNotification(ContractNotification {
            contract_id: ContractInstanceId::new(contract),
            new_state: WrappedState::new(state),
            context: DelegateContext::default(),
        });
        let timing = self.time(None, &msg)?;
        let outcome = self.host.call(None, &msg)?;
        self.record(name, &outcome, timing);
        outcome
            .result
            .map_err(|e| anyhow!("{name}: the delegate returned an error: {e}"))
    }

    /// The answer to a GET the delegate sent, carrying the context the GET
    /// carried (empty for an arm's own tip read). Delivered with no origin,
    /// like a notification.
    fn get_answer(
        &mut self,
        name: &str,
        contract: [u8; 32],
        state: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<Vec<OutboundDelegateMsg>> {
        let msg = InboundDelegateMsg::GetContractResponse(GetContractResponse {
            contract_id: ContractInstanceId::new(contract),
            state: Some(WrappedState::new(state)),
            context: DelegateContext::new(context),
        });
        let timing = self.time(None, &msg)?;
        let outcome = self.host.call(None, &msg)?;
        self.record(name, &outcome, timing);
        outcome
            .result
            .map_err(|e| anyhow!("{name}: the delegate returned an error: {e}"))
    }

    /// A run the node starts on its own (stdlib 0.12 tags 9 and 10, which
    /// the delegate decodes by hand in `node_glue`). The node sends these
    /// with no origin.
    fn background(&mut self, name: &str, raw: &[u8]) -> Result<Vec<OutboundDelegateMsg>> {
        let outcome = self.host.call_raw(None, raw)?;
        self.record(name, &outcome, None);
        outcome
            .result
            .map_err(|e| anyhow!("{name}: the delegate returned an error: {e}"))
    }

    fn time(
        &mut self,
        origin: Option<&MessageOrigin>,
        msg: &InboundDelegateMsg<'_>,
    ) -> Result<Option<(Duration, Duration)>> {
        if self.calibrate_reps == 0 {
            return Ok(None);
        }
        let mut best: Option<(Duration, Duration)> = None;
        for _ in 0..self.calibrate_reps {
            let t = self.host.time_unmetered(origin, msg)?;
            if best.is_none_or(|b| t.0 < b.0) {
                best = Some(t);
            }
        }
        Ok(best)
    }

    fn record(
        &mut self,
        name: &str,
        outcome: &host::CallOutcome,
        timing: Option<(Duration, Duration)>,
    ) {
        let shown = outcome.fuel.map_or("past the ceiling".to_string(), group);
        println!("  {name:<52} {shown:>18} {:>6} writes", outcome.host_writes);
        self.measured.push(Measured {
            name: name.to_string(),
            fuel: outcome.fuel,
            host_calls: outcome.host_calls,
            host_writes: outcome.host_writes,
            timing,
        });
    }
}

fn first_app_payload(outbound: &[OutboundDelegateMsg]) -> Option<Vec<u8>> {
    outbound.iter().find_map(|m| match m {
        OutboundDelegateMsg::ApplicationMessage(a) => Some(a.payload.clone()),
        _ => None,
    })
}

/// The answer is the expected variant and is not a refusal. Checked
/// structurally rather than by decoding into `HarvestDelegateResponse`, so the
/// same harness reads the answers of an older or newer delegate whose response
/// structs have gained or lost a field (#203 dropped one from
/// `StoreSubkeyInfo`).
fn check_answer(name: &str, value: &Value, expect: &str) -> Result<()> {
    let (variant, body) = match value {
        Value::Text(t) => (t.as_str(), None),
        Value::Map(entries) if entries.len() == 1 => match &entries[0] {
            (Value::Text(t), body) => (t.as_str(), Some(body)),
            _ => bail!("{name}: unexpected answer shape {value:?}"),
        },
        _ => bail!("{name}: unexpected answer shape {value:?}"),
    };
    if variant != expect {
        let why = body
            .and_then(|b| {
                field(b, &["reason"])
                    .ok()
                    .or_else(|| field(b, &["message"]).ok())
            })
            .map_or_else(|| brief(value), |w| format!("{w:?}"));
        bail!("{name}: expected {expect}, got {variant}: {why}");
    }
    if let Some(Value::Map(fields)) = body {
        for (k, v) in fields {
            if matches!(k, Value::Text(t) if t == "result") {
                if let Value::Map(r) = v {
                    if matches!(r.first(), Some((Value::Text(t), _)) if t == "Err") {
                        bail!("{name}: refused: {}", brief(v));
                    }
                }
            }
        }
    }
    Ok(())
}

fn brief(v: &Value) -> String {
    let s = format!("{v:?}");
    if s.len() > 300 {
        format!("{}...", &s[..300])
    } else {
        s
    }
}

fn field<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut cur = value;
    for key in path {
        cur = match cur {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v)
                .ok_or_else(|| anyhow!("no field {key} in {}", brief(cur)))?,
            _ => bail!("not a map at {key}: {}", brief(cur)),
        };
    }
    Ok(cur)
}

fn bytes32(value: &Value) -> Result<[u8; 32]> {
    match value {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| anyhow!("not 32 bytes")),
        Value::Array(items) => {
            let v: Vec<u8> = items
                .iter()
                .map(|i| match i {
                    Value::Integer(n) => u8::try_from(i128::from(*n)).map_err(|_| anyhow!("byte")),
                    _ => bail!("not a byte"),
                })
                .collect::<Result<_>>()?;
            v.as_slice().try_into().map_err(|_| anyhow!("not 32 bytes"))
        }
        _ => bail!("not bytes: {}", brief(value)),
    }
}

fn cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    harvest_common::to_cbor(v).expect("encode request")
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// What the Harvest web app and the node send the delegate, in the order a
/// seller (and then a buyer) would. Crypto-heavy handlers first.
fn scenario(r: &mut Runner) -> Result<()> {
    let caps = caps()?;
    let buyer_conversations = caps.buyer_conversations;
    let ghost = SigningKey::from_bytes(&[0x42; 32]);
    let fingerprint = "budget-seller-fp".to_string();

    // --- store keys (harvest#93 phase 1b) --------------------------------
    // Every store key the delegate will hold: export and the per-key walks
    // read them all.
    let mut stores = Vec::new();
    for i in 0..caps.store_keys {
        let name = if i < STORE_KEYS || i == caps.store_keys - 1 {
            format!("CreateStoreKey #{i}")
        } else {
            "CreateStoreKey (filling to the cap)".to_string()
        };
        let answer = r.app(
            &name,
            cbor(&HarvestDelegateRequest::CreateStoreKey {
                request_id: i as u64,
                ghostkey_fingerprint: None,
                another_store: true,
            }),
            "StoreKeyCreated",
        )?;
        stores.push(bytes32(field(
            &answer,
            &["StoreKeyCreated", "result", "Ok"],
        )?)?);
    }
    // The call that tripped the node's limit in #203: the UI sends it right
    // after a store key arrives, and it gates store creation.
    let mut inbox_keys = Vec::new();
    for (i, store) in stores.iter().take(STORE_KEYS).enumerate() {
        let answer = r.app(
            &format!("GetStoreSubkeys #{i}"),
            cbor(&HarvestDelegateRequest::GetStoreSubkeys {
                request_id: 100 + i as u64,
                store_verifying_key: *store,
            }),
            "StoreSubkeys",
        )?;
        inbox_keys.push(bytes32(field(
            &answer,
            &["StoreSubkeys", "result", "Ok", "inbox_public_key"],
        )?)?);
    }
    let inbox = inbox_keys[0];
    let store = stores[0];
    let store_vk = ed25519_dalek::VerifyingKey::from_bytes(&store)?;

    r.app(
        "SignStoreUpdate (store closure)",
        cbor(&HarvestDelegateRequest::SignStoreUpdate {
            request_id: 200,
            store_verifying_key: store,
            payload: cbor(&harvest_common::backing::StoreClosure { store: store_vk }),
        }),
        "StoreUpdateSigned",
    )?;

    let (scoped, sig) =
        fixtures::vault_sign(&ghost, harvest_common::custody::wrap_message(&store_vk));
    let wrapped = r.app(
        "WrapStoreKeyFor",
        cbor(&HarvestDelegateRequest::WrapStoreKeyFor {
            request_id: 201,
            store_verifying_key: store,
            backer_verifying_key: ghost.verifying_key().to_bytes(),
            scoped_payload: scoped.clone(),
            signature: WrapSignature(sig.clone()),
        }),
        "StoreKeyWrapped",
    )?;
    let copy: harvest_common::custody::AuthorizedCopy = {
        let v = field(&wrapped, &["StoreKeyWrapped", "result", "Ok"])?;
        v.deserialized().context("decode the wrapped copy")?
    };
    r.app(
        "UnwrapStoreKey",
        cbor(&HarvestDelegateRequest::UnwrapStoreKey {
            request_id: 202,
            store_verifying_key: store,
            backer_verifying_key: ghost.verifying_key().to_bytes(),
            scoped_payload: scoped,
            signature: WrapSignature(sig),
            wrapped: copy.copy.wrapped,
        }),
        "StoreKeyRecovered",
    )?;

    // --- seller messaging ------------------------------------------------
    r.app(
        "InitEncryptionKey",
        cbor(&HarvestDelegateRequest::InitEncryptionKey {
            ghostkey_fingerprint: fingerprint.clone(),
            recall_only: false,
        }),
        "EncryptionKeyReady",
    )?;
    let peers: Vec<Vec<u8>> = (0..MAILBOX_PEERS)
        .map(|i| {
            // Not byte 0 or 31: X25519 clamps their low/high bits, so seeds
            // differing only there are the same key.
            let mut seed = [7u8; 32];
            seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            PublicKey::from(&StaticSecret::from(seed))
                .as_bytes()
                .to_vec()
        })
        .collect();
    r.app(
        &format!("DeriveConversationKeys ({MAILBOX_PEERS} peers, store key)"),
        cbor(&HarvestDelegateRequest::DeriveConversationKeys {
            request_id: 300,
            ghostkey_fingerprint: fingerprint.clone(),
            peer_public_keys: peers.clone(),
            store_verifying_key: Some(store),
        }),
        "ConversationKeys",
    )?;
    r.app(
        &format!("DeriveConversationKeys ({MAILBOX_PEERS} peers, ghost key)"),
        cbor(&HarvestDelegateRequest::DeriveConversationKeys {
            request_id: 301,
            ghostkey_fingerprint: fingerprint.clone(),
            peer_public_keys: peers,
            store_verifying_key: None,
        }),
        "ConversationKeys",
    )?;

    // --- store registry ----------------------------------------------------
    let store_contract = [0x51u8; 32];
    r.app(
        "RegisterStore",
        cbor(&HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint: fingerprint.clone(),
            store_contract_id: store_contract.to_vec(),
            reputation_contract_id: vec![0x52; 32],
            mailbox_contract_id: vec![0x53; 32],
            store_verifying_key: Some(store),
        }),
        "StoreRegistered",
    )?;
    r.app(
        "ListStores",
        cbor(&HarvestDelegateRequest::ListStores {
            ghostkey_fingerprint: fingerprint.clone(),
        }),
        "StoreList",
    )?;

    // --- Bitcoin payments --------------------------------------------------
    use freenet_bitcoin_common::BitcoinNetwork;
    r.app(
        "SetPaymentXpub",
        cbor(&BitcoinDelegateRequest::SetPaymentXpub {
            request_id: 400,
            xpub: fixtures::signet_vpub(0),
            network: BitcoinNetwork::Signet,
            published_scripts: Vec::new(),
            resume: false,
        }),
        "PaymentXpubSet",
    )?;
    r.app(
        "DeriveOrderAddress",
        cbor(&BitcoinDelegateRequest::DeriveOrderAddress {
            request_id: 401,
            published_scripts: Vec::new(),
        }),
        "OrderAddress",
    )?;
    let upcoming = r.app(
        "PeekOrderAddresses (10)",
        cbor(&BitcoinDelegateRequest::PeekOrderAddresses {
            request_id: 402,
            count: harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES,
        }),
        "UpcomingAddresses",
    )?;
    // A published script this key never derived: the floor scan walks the
    // full `PUBLISHED_INDEX_GAP` (100 derivations) before giving up -- the
    // most one call does short of a crafted chain of matches.
    r.app(
        "DeriveOrderAddress (foreign script, full gap scan)",
        cbor(&BitcoinDelegateRequest::DeriveOrderAddress {
            request_id: 403,
            published_scripts: vec![vec![0x00, 0x14, 0xde, 0xad]],
        }),
        "OrderAddress",
    )?;
    let watched: Vec<Vec<u8>> = match field(&upcoming, &["UpcomingAddresses", "result", "Ok"])? {
        Value::Array(items) => items
            .iter()
            .map(|a| {
                field(a, &["script_pubkey"])?
                    .deserialized::<serde_bytes_vec::ByteVec>()
                    .map(|b| b.0)
                    .context("script_pubkey")
            })
            .collect::<Result<_>>()?,
        other => bail!("upcoming addresses: {}", brief(other)),
    };

    // --- instant checkout (auto-invoice) -----------------------------------
    let bridge = SigningKey::from_bytes(&[22u8; 32]);
    let bridge_id = freenet_bitcoin_common::BridgeId(bridge.verifying_key().to_bytes());
    let (mailbox_contract, tip_contract) = ([0x53u8; 32], [0x54u8; 32]);
    // Every store trusts as many bridges as the delegate holds watch
    // delegations for, so each delegation seeded below serves every store
    // (`watch_delegation::armed_for`) and every walk of them does its work.
    let max_delegations = delegate_cap("watch_delegation.rs", "MAX_DELEGATIONS")?;
    let trusted: Vec<freenet_bitcoin_common::BridgeId> = std::iter::once(bridge_id)
        .chain((1..max_delegations).map(|i| {
            freenet_bitcoin_common::BridgeId(
                SigningKey::from_bytes(&[22u8 + i as u8; 32])
                    .verifying_key()
                    .to_bytes(),
            )
        }))
        .collect();
    r.app(
        "ArmAutoInvoice",
        cbor(&HarvestDelegateRequest::ArmAutoInvoice {
            arm: Box::new(AutoInvoiceArm {
                store_contract_id: store_contract.to_vec(),
                store_verifying_key: store,
                mailbox_contract_id: mailbox_contract,
                seller_fingerprint: fingerprint.clone(),
                network: BitcoinNetwork::Signet,
                tip_contract_id: tip_contract,
                trusted_bridges: trusted.clone(),
                address_code_hash: [0x56; 32],
                watched_scripts: watched.clone(),
                watch_left_ms: 24 * 3600 * 1000,
                watched_until_height: None,
                presence_contract_id: Some([0x57; 32]),
            }),
        }),
        "AutoInvoice",
    )?;
    r.app(
        "Heartbeat (forced)",
        cbor(&HarvestDelegateRequest::Heartbeat {
            store_contract_id: store_contract.to_vec(),
            force: true,
        }),
        "Heartbeat",
    )?;
    // Every arm the delegate takes: the wake-up and resubscribe walk them all.
    if caps.arms > stores.len() {
        bail!(
            "MAX_ARMS ({}) is above the store keys created ({})",
            caps.arms,
            stores.len()
        );
    }
    let mut extra_arms = Vec::new();
    for (i, store_key) in stores.iter().enumerate().take(caps.arms).skip(1) {
        let mut contract = [0x51u8; 32];
        contract[1] = i as u8;
        // Its own mailbox: the scan below is of the first store's.
        let mut mailbox = [0x53u8; 32];
        mailbox[1] = i as u8;
        extra_arms.push((contract, *store_key, mailbox));
        r.app(
            "ArmAutoInvoice (filling to the cap)",
            cbor(&HarvestDelegateRequest::ArmAutoInvoice {
                arm: Box::new(AutoInvoiceArm {
                    store_contract_id: contract.to_vec(),
                    store_verifying_key: *store_key,
                    mailbox_contract_id: mailbox,
                    seller_fingerprint: fingerprint.clone(),
                    network: BitcoinNetwork::Signet,
                    tip_contract_id: tip_contract,
                    trusted_bridges: trusted.clone(),
                    address_code_hash: [0x56; 32],
                    watched_scripts: watched.clone(),
                    watch_left_ms: 24 * 3600 * 1000,
                    watched_until_height: None,
                    presence_contract_id: Some([0x57; 32]),
                }),
            }),
            "AutoInvoice",
        )?;
    }
    let watch_key = bytes32(field(
        &r.app(
            "GetWatchKey",
            cbor(&HarvestDelegateRequest::GetWatchKey),
            "WatchKey",
        )?,
        &["WatchKey", "result", "Ok"],
    )?)?;

    // The bridge's tip contract changes: instant checkout caches the tip it
    // needs before it will issue anything (`auto_invoice::note_tip`).
    let now_s = r.host.state.now.timestamp();
    let tip = freenet_bitcoin_common::SignedTipEntry::sign(
        &bridge,
        &freenet_bitcoin_common::TipEntryBody {
            network: BitcoinNetwork::Signet,
            anchor: freenet_bitcoin_common::BlockAnchor {
                height: TIP_HEIGHT,
                hash: freenet_bitcoin_common::BlockHash([0x61; 32]),
            },
            prev_hash: freenet_bitcoin_common::BlockHash([0x60; 32]),
            block_time: (now_s - 60) as u32,
            tx_count: 1,
            median_time: (now_s - 600) as u32,
        },
    )
    .map_err(|e| anyhow!("sign tip: {e}"))?;
    let tip_state = freenet_bitcoin_common::BitcoinTipStateV1::from_entries(
        &freenet_bitcoin_common::BitcoinTipParameters {
            network: BitcoinNetwork::Signet,
            trusted_bridges: vec![bridge_id],
        },
        [tip],
    )
    .map_err(|e| anyhow!("tip state: {e}"))?;
    let tip_bytes = freenet_bitcoin_common::to_cbor(&tip_state).map_err(|e| anyhow!("{e}"))?;
    r.notify(
        "ContractNotification: bridge tip",
        tip_contract,
        tip_bytes.clone(),
    )?;
    if !r
        .host
        .state
        .secrets
        .contains_key(b"harvest:auto:tip:signet".as_slice())
    {
        bail!("the tip notification did not cache a tip: the mailbox scan below would be a no-op");
    }

    // The store's mailbox changes with a full mailbox of messages this
    // device has never read, each from a different buyer: instant checkout
    // opens every one to see whether it is an instant order
    // (`auto_invoice::on_mailbox`). The first notification after arming pays
    // for all of them.
    let messages: Vec<harvest_common::mailbox::EncryptedMessage> = (0..MAILBOX_PEERS)
        .map(|i| {
            let mut seed = [0x70u8; 32];
            seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            let buyer = StaticSecret::from(seed);
            let tag = *PublicKey::from(&buyer).as_bytes();
            let shared = buyer.diffie_hellman(&PublicKey::from(inbox)).to_bytes();
            let key = harvest_common::mailbox::conversation_key_from_dh(
                &shared,
                harvest_common::mailbox::MessageDirection::BuyerToSeller,
            );
            Ok(fixtures::encrypt_message_seeded(
                &harvest_common::sealed::PlaintextMessage {
                    conversation_id: harvest_common::mailbox::ConversationId([i as u8; 32]),
                    content: harvest_common::sealed::MessageContent::Text(format!(
                        "Is item {i} still available?"
                    )),
                },
                &tag,
                &key,
                r.host.state.now - chrono::Duration::minutes(i as i64),
                i as u64,
            ))
        })
        .collect::<Result<_>>()?;
    drain_mailbox(
        r,
        &format!("ContractNotification: mailbox ({MAILBOX_PEERS} unread)"),
        mailbox_contract,
        store_contract,
        cbor(&mailbox_state(messages)?),
    )?;
    let ledger = format!(
        "harvest:auto:ledger:{}",
        bs58::encode(store_contract).into_string()
    );
    let seen = ledger_seen(r, &ledger)?;
    if seen < MAILBOX_PEERS {
        bail!(
            "the mailbox notification recorded {seen} of the {MAILBOX_PEERS} messages as read: \
             the scan was refused or skipped, so its cost was not measured"
        );
    }

    // The same mailbox at its BYTE cap rather than its count cap: every size
    // class as full as `SIZE_CLASS_CAPS` lets it be, each message from a new
    // buyer. Decrypting and hashing grow with bytes, not with count.
    let class_caps = harvest_common::mailbox::SIZE_CLASS_CAPS;
    let buckets = harvest_common::mailbox::SIZE_BUCKETS;
    let mut sizes = Vec::new();
    for class in (0..buckets.len()).rev() {
        let room = class_caps[class].min(MAILBOX_PEERS - sizes.len());
        // A text that pads into this bucket and no further.
        let len = buckets[class] - 200;
        sizes.extend(std::iter::repeat_n(len, room));
    }
    let big: Vec<harvest_common::mailbox::EncryptedMessage> = sizes
        .iter()
        .enumerate()
        .map(|(i, &len)| {
            let mut seed = [0x90u8; 32];
            seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            let buyer = StaticSecret::from(seed);
            let tag = *PublicKey::from(&buyer).as_bytes();
            let shared = buyer.diffie_hellman(&PublicKey::from(inbox)).to_bytes();
            let key = harvest_common::mailbox::conversation_key_from_dh(
                &shared,
                harvest_common::mailbox::MessageDirection::BuyerToSeller,
            );
            fixtures::encrypt_message_seeded(
                &harvest_common::sealed::PlaintextMessage {
                    conversation_id: harvest_common::mailbox::ConversationId([(i % 251) as u8; 32]),
                    content: harvest_common::sealed::MessageContent::Text("x".repeat(len)),
                },
                &tag,
                &key,
                r.host.state.now - chrono::Duration::seconds(i as i64),
                10_000 + i as u64,
            )
        })
        .collect();
    let big_state = mailbox_state(big)?;
    let big_bytes = cbor(&big_state);
    println!(
        "  (byte-cap mailbox: {} messages, {} KiB)",
        big_state.messages.len(),
        big_bytes.len() / 1024
    );
    drain_mailbox(
        r,
        "ContractNotification: mailbox (byte cap, unread)",
        mailbox_contract,
        store_contract,
        big_bytes,
    )?;
    let seen_after = ledger_seen(r, &ledger)?;
    let seen_cap = delegate_cap("auto_invoice.rs", "SEEN_CAP")?;
    let new = big_state.messages.len();
    if seen_cap < seen + new {
        bail!(
            "SEEN_CAP ({seen_cap}) is below the {} messages this scenario records",
            seen + new
        );
    }
    if seen_after != seen + new {
        bail!(
            "the byte-cap mailbox scan recorded {} of its {new} messages as read",
            seen_after.saturating_sub(seen)
        );
    }

    // The byte cap again, each message's plaintext written to cost the most
    // to decode rather than a text ([`hostile_mailbox`]).
    let hostile_state = mailbox_state(hostile_mailbox(
        &sizes,
        inbox,
        0xA0,
        20_000,
        r.host.state.now,
    )?)?;
    if hostile_state.messages.len() != big_state.messages.len() {
        bail!("the hostile mailbox is not the byte-cap mailbox's shape");
    }
    // The ledger's seen list is already at `SEEN_CAP` here, so its length
    // cannot show whether this scan recorded anything (eviction is FIFO and
    // keeps it at the cap). Its contents can: every hostile message's digest
    // must be in it afterwards, and none was before.
    let seen_before = ledger_seen_digests(r, &ledger)?;
    let hostile_digests: Vec<[u8; 32]> = hostile_state
        .messages
        .iter()
        .map(harvest_common::mailbox::entry_digest)
        .collect();
    if hostile_digests.iter().any(|d| seen_before.contains(d)) {
        bail!("a hostile message was recorded as read before it was sent: update the harness");
    }
    drain_mailbox(
        r,
        "ContractNotification: mailbox (byte cap, plaintexts built to be slow)",
        mailbox_contract,
        store_contract,
        cbor(&hostile_state),
    )?;
    let seen_hostile = ledger_seen_digests(r, &ledger)?;
    let recorded = hostile_digests
        .iter()
        .filter(|d| seen_hostile.contains(d))
        .count();
    if recorded != new {
        bail!("the hostile mailbox scan recorded {recorded} of its {new} messages as read");
    }

    // Every other arm's ledger at its caps, in the delegate's own encoding
    // (`auto_invoice::Ledger`, mirrored in `fixtures::ledger`): the wake-up
    // and the export decode each arm's ledger.
    let now_ms = r.host.state.now.timestamp_millis() as u64;
    let issued = delegate_cap("auto_invoice.rs", "MAX_PER_DAY")? - 1;
    let ledger_caps = LedgerCaps {
        seen: seen_cap,
        answered: delegate_cap("auto_invoice.rs", "ANSWERED_CAP")?,
        statuses: delegate_cap("auto_invoice.rs", "STATUSES_CAP")?,
        sales: delegate_cap("auto_invoice.rs", "SALES_CAP")?,
        gap_orders: delegate_cap("auto_invoice.rs", "GAP_ORDERS_CAP")?,
    };
    // The first store's ledger is the delegate's own writing (the scans
    // above): the mirror must have exactly its fields.
    let mirror_ledger: Value = ciborium::from_reader(
        cbor(&fixtures::full_ledger(0, now_ms, issued, &ledger_caps)).as_slice(),
    )
    .context("the mirrored ledger is not CBOR")?;
    same_fields(
        "instant-checkout ledger",
        &secret_value(r, ledger.as_bytes())?,
        &mirror_ledger,
    )?;
    for (n, (contract, _, _)) in extra_arms.iter().enumerate() {
        r.host.state.secrets.insert(
            format!(
                "harvest:auto:ledger:{}",
                bs58::encode(contract).into_string()
            )
            .into_bytes(),
            cbor(&fixtures::full_ledger(
                n as u32,
                now_ms,
                issued,
                &ledger_caps,
            )),
        );
    }
    // A re-arm answers the status read from that ledger: the issued count
    // proves the seeded ledger decodes, rather than being read as empty.
    if let Some((contract, store_key, mailbox)) = extra_arms.first() {
        let status = r.app(
            "ArmAutoInvoice (re-arm, full ledger)",
            cbor(&HarvestDelegateRequest::ArmAutoInvoice {
                arm: Box::new(AutoInvoiceArm {
                    store_contract_id: contract.to_vec(),
                    store_verifying_key: *store_key,
                    mailbox_contract_id: *mailbox,
                    seller_fingerprint: fingerprint.clone(),
                    network: BitcoinNetwork::Signet,
                    tip_contract_id: tip_contract,
                    trusted_bridges: trusted.clone(),
                    address_code_hash: [0x56; 32],
                    watched_scripts: watched.clone(),
                    watch_left_ms: 24 * 3600 * 1000,
                    watched_until_height: None,
                    presence_contract_id: Some([0x57; 32]),
                }),
            }),
            "AutoInvoice",
        )?;
        let got = field(&status, &["AutoInvoice", "result", "Ok", "issued_last_day"])?;
        if !matches!(got, Value::Integer(i) if i128::from(*i) == issued as i128) {
            bail!(
                "a seeded ledger read back {} issued invoices, expected {issued}: the delegate did \
                 not decode it, so the full-ledger walks below would measure empty ledgers",
                brief(got)
            );
        }
    }

    // --- runs the node starts on its own ------------------------------------
    // Byte layouts pinned in `node_glue`'s tests against stdlib 0.12.0.
    // Both resubscribe every arm (`auto_invoice::resubscribe_all`): with
    // arms taken, an empty answer means an early return.
    for (name, raw) in [
        ("Background: Installed", vec![0x0a, 0, 0, 0, 0, 0, 0, 0]),
        (
            "Background: NodeStarted",
            vec![0x0a, 0, 0, 0, 1, 0, 0, 0, 0],
        ),
    ] {
        if r.background(name, &raw)?.is_empty() {
            bail!("{name} resubscribed nothing: it returned early, so its cost was not measured");
        }
    }
    let mut wakeup = vec![0x09, 0, 0, 0];
    wakeup.extend_from_slice(&9u64.to_le_bytes());
    wakeup.extend_from_slice(b"heartbeat");
    r.host.state.now += chrono::Duration::minutes(5);
    let woke = r.background("Background: heartbeat wake-up", &wakeup)?;
    if woke.is_empty() {
        bail!(
            "the heartbeat wake-up sent nothing: it returned early, so its cost was not measured"
        );
    }
    // The same with every store's mailbox waiting to be re-read (the flag
    // beside each ledger, `auto_invoice::retry_key`), which anyone can bring
    // about by filling a mailbox: each flagged store is checked for whether
    // it can take orders before its mailbox is asked for.
    let gets = |out: &[OutboundDelegateMsg]| {
        out.iter()
            .filter(|m| matches!(m, OutboundDelegateMsg::GetContractRequest(_)))
            .count()
    };
    let all_arms: Vec<[u8; 32]> = std::iter::once(store_contract)
        .chain(extra_arms.iter().map(|(contract, _, _)| *contract))
        .collect();
    set_retry(r, &all_arms, true)?;
    r.host.state.now += chrono::Duration::minutes(5);
    let woke_waiting = r.background(
        "Background: heartbeat wake-up (every mailbox waiting)",
        &wakeup,
    )?;
    if gets(&woke_waiting) < gets(&woke) + all_arms.len() {
        bail!(
            "the wake-up with every mailbox waiting asked for {} more reads, not {}: some stores \
             were not checked, so the cost was not measured",
            gets(&woke_waiting).saturating_sub(gets(&woke)),
            all_arms.len()
        );
    }
    // One of those reads answered, carrying the context the wake-up gave it
    // (`auto_invoice::mailbox_retries`): the first store's mailbox at the
    // byte cap, every plaintext built to be slow and none of it read yet.
    // The answer is decided as a mailbox change is (`on_mailbox_retry`).
    let retry_read = woke_waiting
        .iter()
        .find_map(|m| match m {
            OutboundDelegateMsg::GetContractRequest(get)
                if get.contract_id == ContractInstanceId::new(mailbox_contract) =>
            {
                Some(get.context.as_ref().to_vec())
            }
            _ => None,
        })
        .ok_or_else(|| {
            anyhow!(
                "the wake-up with every mailbox waiting asked nothing of the first store's mailbox"
            )
        })?;
    let retry_state = mailbox_state(hostile_mailbox(
        &sizes,
        inbox,
        0xC0,
        30_000,
        r.host.state.now,
    )?)?;
    let retry_digests: Vec<[u8; 32]> = retry_state
        .messages
        .iter()
        .map(harvest_common::mailbox::entry_digest)
        .collect();
    r.get_answer(
        "GetContractResponse: mailbox retry read (byte cap, slow plaintexts)",
        mailbox_contract,
        cbor(&retry_state),
        retry_read,
    )?;
    let seen_now = ledger_seen_digests(r, &ledger)?;
    if !retry_digests.iter().any(|d| seen_now.contains(d)) {
        bail!(
            "the answered mailbox retry read recorded none of its messages as read: it was \
             refused or ignored, so its cost was not measured"
        );
    }
    set_retry(r, &all_arms, false)?;

    // --- delegated watches (`watch_delegation`) -------------------------------
    // Every delegation the delegate holds, each for a bridge every store
    // trusts and full: `WATCHED_CAP` confirmed watches that all count, in the
    // delegate's own encoding (`watch_delegation::Held`, mirrored in
    // `fixtures::full_delegation`). Each store's status and heartbeat walks
    // every delegation's watches (`auto_invoice::watch_set`,
    // `watch_delegation::delegated_watched`), and the wake-up looks at each
    // delegation for a read (`watch_delegation::on_wakeup`).
    let pool: Vec<Vec<u8>> = match field(
        &r.app(
            "PeekOrderAddresses (10, for the delegations)",
            cbor(&BitcoinDelegateRequest::PeekOrderAddresses {
                request_id: 404,
                count: harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES,
            }),
            "UpcomingAddresses",
        )?,
        &["UpcomingAddresses", "result", "Ok"],
    )? {
        Value::Array(items) => items
            .iter()
            .map(|a| {
                field(a, &["script_pubkey"])?
                    .deserialized::<serde_bytes_vec::ByteVec>()
                    .map(|b| b.0)
                    .context("script_pubkey")
            })
            .collect::<Result<_>>()?,
        other => bail!("upcoming addresses: {}", brief(other)),
    };
    let delegation_caps = fixtures::DelegationCaps {
        watched: delegate_cap("watch_delegation.rs", "WATCHED_CAP")?,
        subscribed: delegate_cap("watch_delegation.rs", "SUBSCRIBED_CAP")?,
        ever_subscribed: delegate_cap("watch_delegation.rs", "EVER_SUBSCRIBED_CAP")?,
    };
    if delegation_caps.watched < pool.len() {
        bail!("WATCHED_CAP is below the delegate's next addresses: update the harness");
    }
    // Every watch counts for an invoice issued now (at least
    // `WATCH_NEEDED_BLOCKS` past the tip) and is due renewal (inside
    // `RENEW_MARGIN_BLOCKS` of that), so the wake-up goes on to choose a
    // canary for a refill.
    let until_height = TIP_HEIGHT
        + delegate_u32("auto_invoice.rs", "WATCH_NEEDED_BLOCKS")?
        + delegate_u32("watch_delegation.rs", "RENEW_MARGIN_BLOCKS")?
        - 1;
    let now_ms = r.host.state.now.timestamp_millis() as u64;
    let delegation_key = |bridge: &freenet_bitcoin_common::BridgeId| {
        format!(
            "harvest:auto:watchdeleg:{}",
            bs58::encode(bridge.0).into_string()
        )
        .into_bytes()
    };
    let mut mirror_delegation = None;
    for (n, bridge) in trusted.iter().enumerate() {
        let seeded = cbor(&fixtures::full_delegation(
            n as u32,
            *bridge,
            &ghost,
            watch_key,
            &pool,
            until_height,
            now_ms,
            &delegation_caps,
        ));
        if mirror_delegation.is_none() {
            mirror_delegation = Some(
                ciborium::from_reader::<Value, _>(seeded.as_slice())
                    .context("the mirrored delegation is not CBOR")?,
            );
        }
        r.host.state.secrets.insert(delegation_key(bridge), seeded);
    }
    let mirror_delegation =
        mirror_delegation.ok_or_else(|| anyhow!("MAX_DELEGATIONS is 0: update the harness"))?;
    let delegations = format!(
        "{max_delegations} delegations x {} watches",
        delegation_caps.watched
    );

    // The tip read an arm asks for is answered: every store naming that tip
    // contract is told its status again, each with its delegation's
    // (`auto_invoice::on_tip_read`).
    let statuses = r.get_answer(
        &format!("GetContractResponse: bridge tip ({delegations})"),
        tip_contract,
        tip_bytes,
        Vec::new(),
    )?;
    let mut counted = 0;
    for m in &statuses {
        if let OutboundDelegateMsg::ApplicationMessage(a) = m {
            let status: Value = ciborium::from_reader(a.payload.as_slice())
                .context("a status sent on the tip read is not CBOR")?;
            if status_watched(&status)? == pool.len() as i128 {
                counted += 1;
            }
        }
    }
    if counted != all_arms.len() {
        bail!(
            "{counted} of the {} store statuses sent on the tip read counted the delegation's watches: \
             the seeded delegations were not read, so their cost was not measured",
            all_arms.len()
        );
    }
    // A re-arm answers one store's status.
    if let Some((contract, store_key, mailbox)) = extra_arms.first() {
        let status = r.app(
            &format!("ArmAutoInvoice (re-arm, {delegations})"),
            cbor(&HarvestDelegateRequest::ArmAutoInvoice {
                arm: Box::new(AutoInvoiceArm {
                    store_contract_id: contract.to_vec(),
                    store_verifying_key: *store_key,
                    mailbox_contract_id: *mailbox,
                    seller_fingerprint: fingerprint.clone(),
                    network: BitcoinNetwork::Signet,
                    tip_contract_id: tip_contract,
                    trusted_bridges: trusted.clone(),
                    address_code_hash: [0x56; 32],
                    watched_scripts: watched.clone(),
                    watch_left_ms: 24 * 3600 * 1000,
                    watched_until_height: None,
                    presence_contract_id: Some([0x57; 32]),
                }),
            }),
            "AutoInvoice",
        )?;
        if status_watched(&status)? != pool.len() as i128 {
            bail!(
                "the re-arm's status counted {} delegated watches, not {}",
                status_watched(&status)?,
                pool.len()
            );
        }
    }
    r.app(
        &format!("Heartbeat (forced, {delegations})"),
        cbor(&HarvestDelegateRequest::Heartbeat {
            store_contract_id: store_contract.to_vec(),
            force: true,
        }),
        "Heartbeat",
    )?;
    // The wake-up's own read goes first: a canary candidate's GET, which only
    // a delegation found due a refill gets (`watch_delegation::due_read`).
    let canary_read = |out: &[OutboundDelegateMsg]| {
        out.first().is_some_and(|m| match m {
            OutboundDelegateMsg::GetContractRequest(get) => {
                ciborium::from_reader::<Value, _>(get.context.as_ref())
                    .ok()
                    .and_then(|c| field(&c, &["kind"]).ok().cloned())
                    == Some(Value::Text("Canary".into()))
            }
            _ => false,
        })
    };
    r.host.state.now += chrono::Duration::minutes(5);
    let woke_deleg = r.background(
        &format!("Background: heartbeat wake-up ({delegations})"),
        &wakeup,
    )?;
    if !canary_read(&woke_deleg) {
        bail!(
            "the wake-up with {delegations} sent no canary read: it did not walk the \
             delegations to a read, so its cost was not measured"
        );
    }
    set_retry(r, &all_arms, true)?;
    r.host.state.now += chrono::Duration::minutes(5);
    let woke_deleg_waiting = r.background(
        &format!("Background: heartbeat wake-up ({delegations}, every mailbox waiting)"),
        &wakeup,
    )?;
    if !canary_read(&woke_deleg_waiting)
        || gets(&woke_deleg_waiting) < gets(&woke_deleg) + all_arms.len()
    {
        bail!(
            "the wake-up with {delegations} and every mailbox waiting did not read for a \
             delegation and check every store, so its cost was not measured"
        );
    }
    set_retry(r, &all_arms, false)?;
    wakeup_catch_up(r, &wakeup, &all_arms)?;
    // A node start forgets every delegation's subscriptions, rewriting each.
    r.background(
        &format!("Background: NodeStarted ({delegations})"),
        &[0x0a, 0, 0, 0, 1, 0, 0, 0, 0],
    )?;
    let rewritten = r.measured.last().map_or(0, |m| m.host_writes);
    if rewritten < max_delegations as u64 {
        bail!(
            "the node start rewrote {rewritten} secrets, fewer than the {max_delegations} \
             delegations: it did not walk them, so its cost was not measured"
        );
    }
    // The node start rewrote each delegation in the delegate's own encoding
    // (`watch_delegation::store_held`): the mirror must have exactly its
    // fields, down to a watch's, and the lists the start keeps are still at
    // their caps (it clears only the subscriptions).
    let rewritten_held = secret_value(r, &delegation_key(&trusted[0]))?;
    same_fields("watch delegation", &rewritten_held, &mirror_delegation)?;
    let first_watch = |v: &Value| -> Result<Value> {
        match field(v, &["watched"])? {
            Value::Array(w) => w
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("a delegation with no watches")),
            other => bail!("a delegation's watches are not a list: {}", brief(other)),
        }
    };
    same_fields(
        "delegated watch",
        &first_watch(&rewritten_held)?,
        &first_watch(&mirror_delegation)?,
    )?;
    for (list, cap) in [
        ("watched", delegation_caps.watched),
        ("ever_subscribed", delegation_caps.ever_subscribed),
    ] {
        let got = list_len(&rewritten_held, &[list])?;
        if got != cap {
            bail!("the rewritten delegation holds {got} {list}, not the cap {cap}");
        }
    }

    // --- the buyer's half ---------------------------------------------------
    let orders = fixtures::OrderFx {
        seller: SigningKey::from_bytes(&[11u8; 32]),
        bridge,
    };
    let seller_store_key = orders.seller.verifying_key().to_bytes();
    let mut first_secret = None;
    for i in 0..buyer_conversations {
        let mut secret = [0x60u8; 32];
        secret[1..9].copy_from_slice(&(i as u64).to_le_bytes());
        first_secret.get_or_insert(secret);
        let conversation = *PublicKey::from(&StaticSecret::from(secret)).as_bytes();
        let name = if i == 0 || i == buyer_conversations - 1 {
            format!("StoreBuyerConversation #{i}")
        } else {
            // Measured like every other call; named alike so the report
            // groups them.
            "StoreBuyerConversation (filling to the cap)".to_string()
        };
        r.app(
            &name,
            cbor(&HarvestDelegateRequest::StoreBuyerConversation {
                request_id: 500 + i as u64,
                store_contract_id: store_contract.to_vec(),
                secret: ConversationSecret(secret),
                seller_public_key: seller_store_key,
                conversation_id: conversation,
                created_at: 1_700_000_000,
            }),
            "BuyerConversationStored",
        )?;
    }
    let listed = r.app(
        &format!("ListBuyerConversations ({buyer_conversations})"),
        cbor(&HarvestDelegateRequest::ListBuyerConversations {
            request_id: 900,
            store_contract_id: store_contract.to_vec(),
        }),
        "BuyerConversationList",
    )?;
    let n = count_array_somewhere(&listed);
    if n != buyer_conversations {
        bail!("ListBuyerConversations answered {n} conversations, expected {buyer_conversations}");
    }

    let secret = first_secret.expect("at least one conversation");
    let conversation = *PublicKey::from(&StaticSecret::from(secret)).as_bytes();
    let receipt_seed = harvest_common::mailbox::buyer_receipt_seed_from_secret(&secret);
    let receipt_key = SigningKey::from_bytes(&receipt_seed)
        .verifying_key()
        .to_bytes();
    let paid = orders.paid(orders.order(0, receipt_key));
    r.app(
        "KeepPurchase (paid, SPV proof)",
        cbor(&HarvestDelegateRequest::KeepPurchase {
            keep: Box::new(PurchaseToKeep {
                store_key: seller_store_key,
                conversation,
                order: paid,
                complaint: None,
            }),
        }),
        "KeptPurchases",
    )?;
    // Fill to the cap directly in the secret store, in the delegate's own
    // encoding and key scheme (`kept_purchases::kept_purchase_key`); keeping
    // 1024 through the handler would only measure the handler 1024 times.
    for n in 1..(KEPT_PURCHASES - 1) as u32 {
        let record = KeptPurchase {
            store_key: seller_store_key,
            conversation,
            receipt_seed,
            order: orders.paid(orders.order(n, receipt_key)),
            complaint: None,
        };
        let id: String = record
            .order
            .order
            .id
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        r.host.state.secrets.insert(
            format!("harvest:kept_purchase:{id}").into_bytes(),
            cbor(&record),
        );
    }
    // The last slot through the handler, at the conversation found last: a
    // keep ends by listing every kept purchase and looks its conversation's
    // seed up among all of them, so the full store is its worst case.
    // `conversation_seed` walks the conversations in secret-key order,
    // `harvest:buyer_conv:{store}:{bs58(public key)}`, with an X25519 per
    // step: the worst case is the conversation whose bs58 sorts last.
    let last_secret = (0..buyer_conversations)
        .map(|i| {
            let mut secret = [0x60u8; 32];
            secret[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            secret
        })
        .max_by_key(|secret| {
            bs58::encode(PublicKey::from(&StaticSecret::from(*secret)).as_bytes()).into_string()
        })
        .expect("at least one conversation");
    let last_conversation = *PublicKey::from(&StaticSecret::from(last_secret)).as_bytes();
    let last_receipt = SigningKey::from_bytes(
        &harvest_common::mailbox::buyer_receipt_seed_from_secret(&last_secret),
    )
    .verifying_key()
    .to_bytes();
    r.app(
        &format!("KeepPurchase (the {KEPT_PURCHASES}th, store full)"),
        cbor(&HarvestDelegateRequest::KeepPurchase {
            keep: Box::new(PurchaseToKeep {
                store_key: seller_store_key,
                conversation: last_conversation,
                order: orders.paid(orders.order(KEPT_PURCHASES as u32, last_receipt)),
                complaint: None,
            }),
        }),
        "KeptPurchases",
    )?;
    // A keep naming a conversation this node does not hold: the lookup by
    // tag misses and the scan of every conversation runs to the end before
    // the keep is refused.
    let stranger = *PublicKey::from(&StaticSecret::from([0x5Au8; 32])).as_bytes();
    let stranger_answer = r.app(
        "KeepPurchase (a conversation not held, store full)",
        cbor(&HarvestDelegateRequest::KeepPurchase {
            keep: Box::new(PurchaseToKeep {
                store_key: seller_store_key,
                conversation: stranger,
                order: orders.paid(orders.order(KEPT_PURCHASES as u32 + 1, last_receipt)),
                complaint: None,
            }),
        }),
        "KeepPurchaseRefused",
    )?;
    // Refused for the reason this step is here for (the scan of every
    // conversation came up empty), not an earlier, cheaper check.
    match field(&stranger_answer, &["KeepPurchaseRefused", "reason"])? {
        Value::Text(why) if why.contains("does not hold the conversation") => {}
        other => bail!(
            "the stranger's keep was refused for another reason ({}), so the scan of every \
             conversation was not measured",
            brief(other)
        ),
    }
    let kept = r.app(
        &format!("ListKeptPurchases ({KEPT_PURCHASES})"),
        cbor(&HarvestDelegateRequest::ListKeptPurchases),
        "KeptPurchases",
    )?;
    match field(&kept, &["KeptPurchases", "purchases"])? {
        Value::Array(p) if p.len() == KEPT_PURCHASES => {}
        other => bail!(
            "ListKeptPurchases answered {} purchases, expected {KEPT_PURCHASES}: the seeded \
             records do not match the delegate's key scheme",
            match other {
                Value::Array(p) => p.len().to_string(),
                _ => brief(other),
            }
        ),
    }

    // --- the buyer's remembered stores, to the cap --------------------------
    for i in 0..caps.known_stores {
        let mut seed = [0x33u8; 32];
        seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
        let code =
            harvest_common::store::store_code(&SigningKey::from_bytes(&seed).verifying_key());
        let name = if i + 1 == caps.known_stores {
            format!("RememberStore (the {}th)", caps.known_stores)
        } else {
            "RememberStore (filling to the cap)".to_string()
        };
        r.app(
            &name,
            cbor(&HarvestDelegateRequest::RememberStore { store_code: code }),
            "RememberedStores",
        )?;
    }
    let remembered = r.app(
        &format!("ListRememberedStores ({})", caps.known_stores),
        cbor(&HarvestDelegateRequest::ListRememberedStores),
        "RememberedStores",
    )?;
    let n = count_array_somewhere(&remembered);
    if n != caps.known_stores {
        bail!(
            "ListRememberedStores answered {n} stores, expected {}",
            caps.known_stores
        );
    }

    instant_decide(
        r,
        &InstantStore {
            contract: store_contract,
            verifying_key: store,
            mailbox: mailbox_contract,
            inbox,
            fingerprint: &fingerprint,
            tip_contract,
            trusted: &trusted,
        },
    )?;

    // --- a migration import of a full ledger into a full ledger --------------
    // What a successor does with each ledger a predecessor exports: decode
    // both, merge, encode. The largest secret this delegate imports.
    if let (Some((a, _, _)), Some((b, _, _))) = (extra_arms.first(), extra_arms.get(1)) {
        let key = |c: &[u8; 32]| {
            format!("harvest:auto:ledger:{}", bs58::encode(c).into_string()).into_bytes()
        };
        let incoming = r
            .host
            .state
            .secrets
            .get(&key(b))
            .cloned()
            .ok_or_else(|| anyhow!("no seeded ledger to import"))?;
        let incoming_value: Value =
            ciborium::from_reader(incoming.as_slice()).context("a seeded ledger is not CBOR")?;
        let answer = r.app(
            "ImportMigratedSecret (full ledger into a full ledger)",
            cbor(&HarvestDelegateRequest::ImportMigratedSecret {
                predecessor: [0x29; 32],
                key: key(a),
                value: harvest_common::delegate::MigratedSecretValue(incoming),
            }),
            "MigratedSecretImported",
        )?;
        // The answer carries an outcome, not a `result`, so `check_answer`
        // cannot see a refusal: a ledger refused (or found already merged)
        // costs a decode at most, not the merge.
        let outcome = field(&answer, &["MigratedSecretImported", "outcome"])?;
        if *outcome != Value::Text("Written".into()) {
            bail!(
                "the ledger import answered {}, not Written: the merge was not done, so its \
                 cost was not measured",
                brief(outcome)
            );
        }
        // And what it wrote is the merge: the delegate's encoding with the
        // mirror's fields, every capped list at its cap, and the incoming
        // ledger's newest sale in it.
        let merged = secret_value(r, &key(a))?;
        same_fields("merged instant-checkout ledger", &merged, &mirror_ledger)?;
        for (list, cap) in [
            ("sales", ledger_caps.sales),
            ("gap_orders", ledger_caps.gap_orders),
            ("statuses", ledger_caps.statuses),
            ("oversold", ledger_caps.statuses),
        ] {
            let got = list_len(&merged, &[list])?;
            if got != cap {
                bail!("the merged ledger holds {got} {list}, not the cap {cap}");
            }
        }
        let order_of = |sale: &Value| field(sale, &["order"]).cloned();
        let newest = match field(&incoming_value, &["sales"])? {
            Value::Array(sales) => sales
                .last()
                .map(order_of)
                .ok_or_else(|| anyhow!("the incoming ledger has no sales"))??,
            other => bail!(
                "the incoming ledger's sales are not a list: {}",
                brief(other)
            ),
        };
        let found = match field(&merged, &["sales"])? {
            Value::Array(sales) => sales.iter().any(|s| order_of(s).is_ok_and(|o| o == newest)),
            _ => false,
        };
        if !found {
            bail!(
                "the merged ledger holds none of the incoming ledger's sales: nothing was merged"
            );
        }
    }

    // --- the migration export, last: it disarms instant checkout -----------
    let out = r.send(
        "ExportSecrets (migration)",
        cbor(&HarvestMigrationRequest::ExportSecrets {
            source_generation: 0,
        }),
    )?;
    let exported = first_app_payload(&out).ok_or_else(|| anyhow!("export answered nothing"))?;
    // Every instant-checkout ledger: the export's largest entries, and the
    // ones a cut-short export would drop first.
    let ledgers: Vec<Vec<u8>> = all_arms
        .iter()
        .map(|c| format!("harvest:auto:ledger:{}", bs58::encode(c).into_string()).into_bytes())
        .collect();
    freenet_migrate_check(
        &exported,
        KEPT_PURCHASES + buyer_conversations + caps.known_stores,
        &ledgers,
    )?;

    // --- a seller's published orders, after the export ---------------------
    // The payment-key handlers do not look at the export marker. Last
    // because the spaced run is past the harness's fuel ceiling on a
    // delegate without a per-call bound, which stops the scenario.
    published_scripts(r, &caps)?;

    Ok(())
}

/// The first store's instant-checkout arm, as [`instant_decide`] needs it.
struct InstantStore<'a> {
    contract: [u8; 32],
    verifying_key: [u8; 32],
    mailbox: [u8; 32],
    inbox: [u8; 32],
    fingerprint: &'a str,
    tip_contract: [u8; 32],
    trusted: &'a [freenet_bitcoin_common::BridgeId],
}

impl InstantStore<'_> {
    fn arm(&self, watched_scripts: Vec<Vec<u8>>) -> Vec<u8> {
        cbor(&HarvestDelegateRequest::ArmAutoInvoice {
            arm: Box::new(AutoInvoiceArm {
                store_contract_id: self.contract.to_vec(),
                store_verifying_key: self.verifying_key,
                mailbox_contract_id: self.mailbox,
                seller_fingerprint: self.fingerprint.to_string(),
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                tip_contract_id: self.tip_contract,
                trusted_bridges: self.trusted.to_vec(),
                address_code_hash: [0x56; 32],
                watched_scripts,
                watch_left_ms: 24 * 3600 * 1000,
                watched_until_height: None,
                presence_contract_id: Some([0x57; 32]),
            }),
        })
    }
}

/// Instant checkout deciding a buyer's request against a full store
/// (`auto_invoice::on_store_state`, `decide`): the store's `MAX_ORDERS`
/// orders, all paid, on addresses contiguous from this device's counter, as
/// a busy store's are on a device that has not seen them. `decide` raises the
/// counter past every one before it invoices (`published_floor_scan`); since
/// #216 a run that cannot finish the scan refuses the batch
/// (`Refusal::CatchingUp`), keeps the count, and the request waits for the
/// next run.
///
/// Driven as on a node: the request arrives in the store's mailbox, the
/// delegate asks for the store, and the answer (with the context the GET
/// carried) is the full store, repeated while the delegate is catching up.
/// Every run before the last must have refused for that reason, and the last
/// must publish one order on the address one past the store's last.
///
/// The orders are paid, so no store limit turns the request away once the
/// counter has caught up. `decide` does not check an order's signature, so
/// each is signed by a fixture key at its real size, with a genuine SPV
/// payment proof.
fn instant_decide(r: &mut Runner, at: &InstantStore) -> Result<()> {
    use harvest_common::listing::{
        AuthorizedListing, ChoiceGroup, DeliveryPrice, FixedCheckout, Listing, ListingId,
        ListingKind, RegionPrice,
    };
    use harvest_common::sealed::{InstantSelection, MessageContent, PlaintextMessage};

    // Put back after: the run changes the counter, the store's arm and
    // ledger, and (since #216) the published scripts the delegate holds,
    // which the published-script runs below must start without.
    let snapshot = r.host.state.secrets.clone();
    let chain = fixture_chain()?;
    let start = counter_now(r, &chain)?;
    let n = harvest_common::store::MAX_ORDERS as u32;
    let next = start + n;
    // The seller's tab watches the address the invoice will use, and the
    // ten after it.
    r.quiet_app(at.arm(scripts_at(&chain, next..next + 10)?), "AutoInvoice")?;

    let listing = Listing {
        id: ListingId([0; 32]),
        title: "Jam".into(),
        description: String::new(),
        kind: ListingKind::Sale,
        price: None,
        created_at: fixtures::ts(1_700_000_000),
        checkout: Some(FixedCheckout {
            unit_sats: 10_000,
            delivery: DeliveryPrice::ByRegion(vec![RegionPrice {
                region: "UK".into(),
                sats: 2_000,
            }]),
        }),
        choices: vec![ChoiceGroup {
            name: "Flavour".into(),
            options: vec!["Plum".into(), "Fig".into()],
        }],
    }
    .with_derived_id();
    let owner = ed25519_dalek::VerifyingKey::from_bytes(&at.verifying_key)?;
    let fx = fixtures::OrderFx {
        seller: SigningKey::from_bytes(&[12u8; 32]),
        bridge: SigningKey::from_bytes(&[22u8; 32]),
    };
    let mut store = harvest_common::store::StoreStateV1 {
        owner: Some(owner),
        listings: harvest_common::store::ListingsV1 {
            listings: vec![AuthorizedListing {
                listing: listing.clone(),
                scoped_payload: Vec::new(),
                signature: Vec::new(),
                certificate_pem: String::new(),
            }],
        },
        ..Default::default()
    };
    for (k, script) in scripts_at(&chain, start..next)?.into_iter().enumerate() {
        let order = fx.paid(fx.order_on(k as u32, script));
        store.orders.orders.insert(order.order.id.clone(), order);
    }
    if store.orders.orders.len() != n as usize {
        bail!(
            "the full store holds {} orders, not {n}",
            store.orders.orders.len()
        );
    }
    let store_bytes = cbor(&store);
    println!(
        "  (full store: {} paid orders, {} KiB)",
        store.orders.orders.len(),
        store_bytes.len() / 1024
    );

    // The buyer's instant request, sealed to the store's inbox.
    let buyer = StaticSecret::from([0xD0u8; 32]);
    let tag = *PublicKey::from(&buyer).as_bytes();
    let key = harvest_common::mailbox::conversation_key_from_dh(
        &buyer.diffie_hellman(&PublicKey::from(at.inbox)).to_bytes(),
        harvest_common::mailbox::MessageDirection::BuyerToSeller,
    );
    let now = r.host.state.now;
    let conversation = harvest_common::mailbox::ConversationId([0xD0; 32]);
    let request = fixtures::encrypt_message_seeded(
        &PlaintextMessage {
            conversation_id: conversation.clone(),
            content: MessageContent::OrderRequest {
                listing_id: listing.id.clone(),
                quantity: 1,
                shipping: "1 Lane".into(),
                note: String::new(),
                order_binding: [0xD1; 32],
                buyer_receipt_key: Some([0xD2; 32]),
                instant: Some(InstantSelection {
                    nonce: [0xD3; 16],
                    region: Some("UK".into()),
                    choices: vec!["Fig".into()],
                    expected_total_sats: 12_000,
                    requested_at_ms: (now - chrono::Duration::seconds(5)).timestamp_millis(),
                }),
            },
        },
        &tag,
        &key,
        now - chrono::Duration::seconds(5),
        40_000,
    );
    let out = r.notify(
        "ContractNotification: mailbox (an instant request)",
        at.mailbox,
        cbor(&mailbox_state(vec![request])?),
    )?;
    let context = out
        .iter()
        .find_map(|m| match m {
            OutboundDelegateMsg::GetContractRequest(get)
                if get.contract_id == ContractInstanceId::new(at.contract) =>
            {
                Some(get.context.as_ref().to_vec())
            }
            _ => None,
        })
        .ok_or_else(|| {
            anyhow!("the instant request asked nothing of the store: it was not batched")
        })?;

    let name = format!("GetContractResponse: store, {n} paid orders (instant decide)");
    let counter = |r: &Runner| -> Result<u64> {
        let v = secret_value(r, XPUB_KEY)?;
        match field(&v, &["next_index"])? {
            Value::Integer(i) => Ok(u64::try_from(i128::from(*i))?),
            other => bail!("the payment counter is not a number: {}", brief(other)),
        }
    };
    let mut count = counter(r)?;
    let mut cursor = active_cursor(r)?.unwrap_or(count);
    let want = chain.script_at(next).map_err(|e| anyhow!("{e}"))?;
    for _ in 0..=n {
        let out = r.get_answer(&name, at.contract, store_bytes.clone(), context.clone())?;
        let published: Vec<Vec<u8>> = out
            .iter()
            .filter_map(|m| match m {
                OutboundDelegateMsg::UpdateContractRequest(u)
                    if u.contract_id == ContractInstanceId::new(at.contract) =>
                {
                    Some(update_bytes(&u.update))
                }
                _ => None,
            })
            .flatten()
            .collect();
        if published.is_empty() {
            // Nothing published: the run must have refused for the catch-up
            // (`Refusal::CatchingUp`). Since #216 the store's status says so
            // (`paused`); before it, the refusal was the one that kept a
            // higher counter, up to the store's end (a scan whose budget ran
            // out on the last match has not yet looked `PUBLISHED_INDEX_GAP`
            // past it, so the next run finishes).
            let now_at = counter(r)?;
            let status =
                r.quiet_app(at.arm(scripts_at(&chain, next..next + 10)?), "AutoInvoice")?;
            let paused = field(&status, &["AutoInvoice", "result", "Ok", "paused"])
                .ok()
                .cloned();
            let said = matches!(&paused, Some(Value::Text(why)) if why == CATCHING_UP_SHOWN);
            if !said && (now_at <= count || now_at > u64::from(next)) {
                bail!(
                    "{name}: published nothing, its status is paused for {paused:?}, and the \
                     counter went from {count} to {now_at} \
                     (the store ends at {next}): the request was refused for another reason, so \
                     the decide was not measured"
                );
            }
            // And every refused run moved the scan on (the counter, or the
            // cursor past it), so a delegate stuck catching up fails here
            // rather than running out the loop.
            let now_cursor = active_cursor(r)?.unwrap_or(now_at);
            if now_at < count || (now_at, now_cursor) <= (count, cursor) || now_at > u64::from(next)
            {
                bail!(
                    "{name}: a refused run took the scan from {count}/{cursor} to \
                     {now_at}/{now_cursor}: it made no progress"
                );
            }
            count = now_at;
            cursor = now_cursor;
            continue;
        }
        let scripts = published
            .iter()
            .filter_map(|bytes| ciborium::from_reader::<Value, _>(bytes.as_slice()).ok())
            .flat_map(|v| byte_fields(&v, "payment_script_pubkey"))
            .collect::<Vec<_>>();
        if scripts != vec![want.clone()] {
            bail!(
                "{name}: published orders paying {} script(s), not one order at index {next} \
                 (one past the store's last)",
                scripts.len()
            );
        }
        // Back as it was for the rest of the scenario.
        r.host.state.secrets = snapshot;
        return Ok(());
    }
    bail!("{name}: still catching up after {} runs", n + 1)
}

/// The bytes an update carries.
fn update_bytes(data: &freenet_stdlib::prelude::UpdateData<'_>) -> Option<Vec<u8>> {
    use freenet_stdlib::prelude::UpdateData;
    match data {
        UpdateData::Delta(d) => Some(d.as_ref().to_vec()),
        UpdateData::State(s) => Some(s.as_ref().to_vec()),
        _ => None,
    }
}

/// Every value of a field named `name` anywhere in `v`, as bytes.
fn byte_fields(v: &Value, name: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match v {
        Value::Map(entries) => {
            for (k, val) in entries {
                if matches!(k, Value::Text(t) if t == name) {
                    if let Ok(b) = val.deserialized::<serde_bytes_vec::ByteVec>() {
                        out.push(b.0);
                        continue;
                    }
                }
                out.extend(byte_fields(val, name));
            }
        }
        Value::Array(items) => items.iter().for_each(|i| out.extend(byte_fields(i, name))),
        Value::Tag(_, inner) => out.extend(byte_fields(inner, name)),
        _ => {}
    }
    out
}

/// How a store's status names `Refusal::CatchingUp` (`Refusal::explain`).
const CATCHING_UP_SHOWN: &str =
    "the payment counter is still catching up with this store's published orders";

/// The payment-key record's secret key (`bitcoin::BITCOIN_PAYMENT_XPUB_KEY`).
const XPUB_KEY: &[u8] = b"harvest:bitcoin:payment-xpub:v1";

/// The fixture key's receiving chain, derived natively by the delegate's own
/// code ([`bip32`]).
fn fixture_chain() -> Result<bip32::ExternalChain> {
    bip32::AccountXpub::parse(&fixtures::signet_vpub(0))
        .and_then(|a| a.external_chain())
        .map_err(|e| anyhow!("derive the fixture key's chain: {e}"))
}

/// Where the delegate's address counter is now, with the native chain
/// checked against the next addresses the delegate itself reports, so a
/// fixture script is the address the delegate would derive.
fn counter_now(r: &mut Runner, chain: &bip32::ExternalChain) -> Result<u32> {
    let peeked = r.quiet_app(
        cbor(&BitcoinDelegateRequest::PeekOrderAddresses {
            request_id: 410,
            count: harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES,
        }),
        "UpcomingAddresses",
    )?;
    let upcoming = match field(&peeked, &["UpcomingAddresses", "result", "Ok"])? {
        Value::Array(items) => items.clone(),
        other => bail!("upcoming addresses: {}", brief(other)),
    };
    let start = match upcoming.first().map(|a| field(a, &["index"])) {
        Some(Ok(Value::Integer(i))) => u32::try_from(i128::from(*i))?,
        _ => bail!("the next address carries no index: update the harness"),
    };
    for (k, a) in upcoming.iter().enumerate() {
        let script = field(a, &["script_pubkey"])?
            .deserialized::<serde_bytes_vec::ByteVec>()
            .context("script_pubkey")?
            .0;
        if chain
            .script_at(start + k as u32)
            .map_err(|e| anyhow!("{e}"))?
            != script
        {
            bail!("the natively derived address {k} is not the delegate's: update the harness");
        }
    }
    Ok(start)
}

/// The scripts at `indexes` on the fixture key's receiving chain.
fn scripts_at(
    chain: &bip32::ExternalChain,
    indexes: impl Iterator<Item = u32>,
) -> Result<Vec<Vec<u8>>> {
    indexes
        .map(|i| chain.script_at(i).map_err(|e| anyhow!("{e}")))
        .collect()
}

/// A seller's published orders, which the delegate's address counter must be
/// raised past before it hands out an address (harvest#77).
///
/// Since #216 the delegate holds every script it is sent: the web app sends
/// them as `AddPublishedScripts`, at most `MAX_SCRIPTS_PER_REQUEST` a
/// request, then the key (`SetPaymentXpub`), and asks again (`resume`) while
/// the delegate answers that its scan is still catching up; every address
/// request (`DeriveOrderAddress`) goes through the same scan. A delegate that
/// does not take `AddPublishedScripts` (V29) is sent the scripts with the
/// request itself, as its web app did.
///
/// * One full store (`MAX_ORDERS`), contiguous from the counter: fed, then
///   driven to the end, which must put the count one past the last script.
/// * Every store full (64 x `MAX_ORDERS`), contiguous: the web app sends
///   every owned store's scripts (`published_payment_scripts`), and one
///   delegate holds one payment key for every store. Fed in 64 requests, each
///   measured, then ONE scan call, to show its cost is bounded per call.
/// * One full store with every script `PUBLISHED_INDEX_GAP - 1` unused
///   indices after the last (abandoned invoices burn indices): the longest
///   scan a store's scripts allow. Capped at [`SPACED_CALLS`] calls.
///
/// Each of `SetPaymentXpub` and `DeriveOrderAddress` starts from the same
/// secrets (the key active, its counter where the scenario left it, nothing
/// published held); the feeding is measured once a run, before
/// `SetPaymentXpub`. The secrets are put back after, so the rest of the
/// scenario sees the delegate as it was.
fn published_scripts(r: &mut Runner, caps: &Caps) -> Result<()> {
    let snapshot = r.host.state.secrets.clone();
    let chain = fixture_chain()?;
    let start = counter_now(r, &chain)?;
    let additions = takes_additions(
        r,
        "the published-script steps send the scripts with each request instead",
    )?;
    r.host.state.secrets = snapshot.clone();
    let per_store = harvest_common::store::MAX_ORDERS;
    let gap = harvest_common::bitcoin_delegate::PUBLISHED_INDEX_GAP;
    let all = caps.store_keys * per_store;
    let contiguous = scripts_at(&chain, start..start + all as u32)?;
    // The first match may be `gap - 1` past the counter, and each next one
    // `gap` past the last.
    let spaced = scripts_at(
        &chain,
        (0..per_store as u32).map(|k| start + gap - 1 + k * gap),
    )?;
    // (what, the scripts, one past the last of them, at most this many calls)
    type Run = (String, Vec<Vec<u8>>, u32, Option<usize>);
    let runs: [Run; 3] = [
        (
            format!("{per_store} published scripts, one full store"),
            contiguous[..per_store].to_vec(),
            start + per_store as u32,
            None,
        ),
        (
            format!("{all} published scripts, {} full stores", caps.store_keys),
            contiguous,
            start + all as u32,
            Some(1),
        ),
        (
            format!("{per_store} published scripts {gap} apart, one full store"),
            spaced,
            start + gap - 1 + (per_store as u32 - 1) * gap + 1,
            Some(SPACED_CALLS),
        ),
    ];
    for (label, published, past_every, cap) in runs {
        let n = published.len();
        let past_every_v = Value::Integer(u64::from(past_every).into());
        // Inline only for a delegate without `AddPublishedScripts`.
        let inline = if additions {
            Vec::new()
        } else {
            published.clone()
        };

        r.host.state.secrets = snapshot.clone();
        if additions {
            feed(r, &label, &published, true)?;
        }
        let set = |resume: bool| {
            cbor(&BitcoinDelegateRequest::SetPaymentXpub {
                request_id: 411,
                xpub: fixtures::signet_vpub(0),
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                published_scripts: inline.clone(),
                resume,
            })
        };
        let answer = catch_up(
            r,
            &format!("SetPaymentXpub ({label})"),
            &set(false),
            &set(true),
            "PaymentXpubSet",
            n,
            cap,
            &mut (u64::from(start), u64::from(start)),
        )?;
        if let Some(answer) = answer {
            let count = field(&answer, &["PaymentXpubSet", "result", "Ok", "next_index"])?;
            if *count != past_every_v {
                bail!(
                    "SetPaymentXpub ({label}) finished at count {}, not {past_every}: the \
                     scan stopped short",
                    brief(count)
                );
            }
        }

        r.host.state.secrets = snapshot.clone();
        if additions {
            feed(r, &label, &published, false)?;
        }
        let derive = cbor(&BitcoinDelegateRequest::DeriveOrderAddress {
            request_id: 412,
            published_scripts: inline,
        });
        let answer = catch_up(
            r,
            &format!("DeriveOrderAddress ({label})"),
            &derive,
            &derive,
            "OrderAddress",
            n,
            cap,
            &mut (u64::from(start), u64::from(start)),
        )?;
        // One past the last published script: neither an address a
        // published order already uses nor one beyond it.
        if let Some(answer) = answer {
            let index = field(&answer, &["OrderAddress", "result", "Ok", "index"])?;
            if *index != past_every_v {
                bail!(
                    "DeriveOrderAddress ({label}) handed out index {}, not {past_every} (one \
                     past the last published script)",
                    brief(index)
                );
            }
        }
    }
    r.host.state.secrets = snapshot;
    pending_key(r)?;
    Ok(())
}

/// Whether the delegate takes `AddPublishedScripts` (#216 on); asked with
/// none, so nothing is held. The caller puts the secrets back.
///
/// Only one answer means "no": the delegate's own refusal of a request it
/// cannot decode (V29's `payload is neither a HarvestDelegateRequest nor a
/// BitcoinDelegateRequest`). Anything else that is not a clean
/// `PublishedScriptsAdded` fails the run, and so does "no" from the
/// committed delegate, so a step is never skipped for a delegate that
/// should have run it. A skip is printed.
fn takes_additions(r: &mut Runner, step: &str) -> Result<bool> {
    let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(cbor(
        &BitcoinDelegateRequest::AddPublishedScripts {
            request_id: 413,
            scripts: Vec::new(),
        },
    )));
    let origin = r.origin.clone();
    match r.host.call(Some(&origin), &msg)?.result {
        Err(e) if e.contains("neither a HarvestDelegateRequest nor a BitcoinDelegateRequest") => {
            if r.committed {
                bail!(
                    "the committed delegate does not take AddPublishedScripts ({e}): {step} \
                     cannot be skipped for it"
                );
            }
            println!("  ({step}: this delegate does not take AddPublishedScripts)");
            Ok(false)
        }
        Err(e) => bail!("AddPublishedScripts: the delegate returned an error: {e}"),
        Ok(outbound) => {
            let answer = first_app_payload(&outbound)
                .ok_or_else(|| anyhow!("AddPublishedScripts: no application message"))?;
            let value: Value = ciborium::from_reader(answer.as_slice())
                .context("AddPublishedScripts: not CBOR")?;
            check_answer("AddPublishedScripts", &value, "PublishedScriptsAdded")?;
            Ok(true)
        }
    }
}

/// Send `scripts` as `AddPublishedScripts` requests of at most
/// `MAX_SCRIPTS_PER_REQUEST`, each measured when `measured`.
fn feed(r: &mut Runner, label: &str, scripts: &[Vec<u8>], measured: bool) -> Result<()> {
    let chunk = harvest_common::bitcoin_delegate::MAX_SCRIPTS_PER_REQUEST;
    for part in scripts.chunks(chunk) {
        let payload = cbor(&BitcoinDelegateRequest::AddPublishedScripts {
            request_id: 414,
            scripts: part.to_vec(),
        });
        if measured {
            r.app(
                &format!("AddPublishedScripts ({} of {label})", part.len()),
                payload,
                "PublishedScriptsAdded",
            )?;
        } else {
            r.quiet_app(payload, "PublishedScriptsAdded")?;
        }
    }
    Ok(())
}

/// The active payment key's counter, as the delegate holds it.
fn active_counter(r: &Runner) -> Result<u64> {
    let v = secret_value(r, XPUB_KEY)?;
    match field(&v, &["next_index"])? {
        Value::Integer(i) => Ok(u64::try_from(i128::from(*i))?),
        other => bail!("the payment counter is not a number: {}", brief(other)),
    }
}

/// A scheduled wake-up moves the active key's catch-up on by itself
/// (`bitcoin::advance_on_wakeup`, `WAKEUP_SCAN_BUDGET`), on top of all the
/// wake-up's other work: measured with one full store's scripts held and
/// none of them scanned. The counter must move on. Skipped for a delegate
/// without `AddPublishedScripts`, which holds no scripts. The secrets are put
/// back after.
fn wakeup_catch_up(r: &mut Runner, wakeup: &[u8], stores: &[[u8; 32]]) -> Result<()> {
    let snapshot = r.host.state.secrets.clone();
    let chain = fixture_chain()?;
    let start = counter_now(r, &chain)?;
    if !takes_additions(r, "SKIPPED the wake-up catch-up")? {
        r.host.state.secrets = snapshot;
        return Ok(());
    }
    r.host.state.secrets = snapshot.clone();
    let began = r.host.state.now;
    let per_store = harvest_common::store::MAX_ORDERS as u32;
    feed(
        r,
        "one full store",
        &scripts_at(&chain, start..start + per_store)?,
        false,
    )?;
    let catching = "Background: heartbeat wake-up (payment counter catching up)";
    let gap = harvest_common::bitcoin_delegate::PUBLISHED_INDEX_GAP;
    let end = u64::from(start + per_store);
    // Each wake-up moves the scan on by `WAKEUP_SCAN_BUDGET`; bounded well
    // past what that needs.
    let wakeups = (per_store + gap) as usize + 2;
    let mut last = (u64::from(start), u64::from(start));
    let mut done = None;
    for n in 1..=wakeups {
        r.host.state.now += chrono::Duration::minutes(5);
        if n == 1 {
            // The first with every store's mailbox waiting too: its reads
            // and the catch-up in one wake-up.
            set_retry(r, stores, true)?;
            r.background(
                "Background: heartbeat wake-up (payment counter catching up, every mailbox waiting)",
                wakeup,
            )?;
            set_retry(r, stores, false)?;
        } else {
            r.background(catching, wakeup)?;
        }
        let counter = active_counter(r)?;
        let at = active_cursor(r)?.unwrap_or(counter);
        if (counter, at) <= last || counter > end {
            bail!(
                "wake-up {n} took the catch-up from {}/{} to {counter}/{at}: it did not move \
                 it on, so its cost was not measured",
                last.0,
                last.1
            );
        }
        last = (counter, at);
        if counter == end && at >= end + u64::from(gap) {
            done = Some(n);
            break;
        }
    }
    let Some(n) = done else {
        bail!("{wakeups} wake-ups did not finish one store's catch-up");
    };
    println!("  (the wake-ups finished one store's catch-up in {n})");
    // And once it is complete, a wake-up's share is a check of the cursor.
    r.host.state.now += chrono::Duration::minutes(5);
    r.background(
        "Background: heartbeat wake-up (payment counter caught up)",
        wakeup,
    )?;
    let counter = active_counter(r)?;
    let after = (counter, active_cursor(r)?.unwrap_or(counter));
    if after != last {
        bail!("a wake-up after the catch-up was complete moved it from {last:?} to {after:?}");
    }
    r.host.state.secrets = snapshot;
    // The scenario's clock as one wake-up left it, as before this step.
    r.host.state.now = began + chrono::Duration::minutes(5);
    Ok(())
}

/// The active key's scan cursor (`published_set::Cursor`, stored as
/// `[tag_len u16][tag][generation u32][base u32][at u32]`): how far its scan
/// has derived. `None` when none is saved; a cursor of another shape fails
/// the run.
fn active_cursor(r: &Runner) -> Result<Option<u64>> {
    let Some(bytes) = r.host.state.secrets.get(CURSOR_ACTIVE_KEY) else {
        return Ok(None);
    };
    let tag_len = bytes
        .get(..2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        .ok_or_else(|| anyhow!("the scan cursor is too short: update the harness"))?;
    match bytes.get(2 + tag_len..) {
        Some(rest) if rest.len() == 12 => {
            Ok(Some(u64::from(u32::from_le_bytes(rest[8..12].try_into()?))))
        }
        _ => {
            bail!("the scan cursor is not [tag_len][tag][generation][base][at]: update the harness")
        }
    }
}

/// `published_set::CURSOR_ACTIVE_KEY`.
const CURSOR_ACTIVE_KEY: &[u8] = b"harvest:bitcoin:cursor-active:v1";

/// `bitcoin::BITCOIN_PAYMENT_XPUB_PENDING_KEY`.
const XPUB_PENDING_KEY: &[u8] = b"harvest:bitcoin:payment-xpub-pending:v1";

/// The account key a payment-key record holds (`None` for no record, or the
/// emptied pending slot).
fn held_key(r: &Runner, key: &[u8]) -> Result<Option<String>> {
    match r.host.state.secrets.get(key) {
        None => Ok(None),
        Some(b) if b.is_empty() => Ok(None),
        Some(_) => match secret_value(r, key)? {
            Value::Null => Ok(None),
            v => match field(&v, &["xpub"])? {
                Value::Text(t) => Ok(Some(t.clone())),
                other => bail!("a payment key record's xpub: {}", brief(other)),
            },
        },
    }
}

/// A new device: a key that is not the active one, entered with a store's
/// published scripts held. Its scan runs in the pending slot, the active
/// key going on handing out addresses meanwhile, and only once complete is
/// it made active (#216). Then the stale case: a tab resuming a key's
/// catch-up after another key was entered since is refused with
/// `KEY_SUPERSEDED_PREFIX`, and writes nothing. Skipped for a delegate
/// without `AddPublishedScripts`, which has no pending slot. The secrets are
/// put back after.
fn pending_key(r: &mut Runner) -> Result<()> {
    let snapshot = r.host.state.secrets.clone();
    if !takes_additions(r, "SKIPPED the new-device (pending key) steps")? {
        r.host.state.secrets = snapshot;
        return Ok(());
    }
    r.host.state.secrets = snapshot.clone();
    let (old, new, newer) = (
        fixtures::signet_vpub(0),
        fixtures::signet_vpub(1),
        fixtures::signet_vpub(2),
    );
    let chain = bip32::AccountXpub::parse(&new)
        .and_then(|a| a.external_chain())
        .map_err(|e| anyhow!("derive the new key's chain: {e}"))?;
    let per_store = harvest_common::store::MAX_ORDERS;
    let label = format!("{per_store} published scripts, a new key");
    feed(r, &label, &scripts_at(&chain, 0..per_store as u32)?, true)?;
    let set = |xpub: &str, resume: bool| {
        cbor(&BitcoinDelegateRequest::SetPaymentXpub {
            request_id: 415,
            xpub: xpub.to_string(),
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            published_scripts: Vec::new(),
            resume,
        })
    };
    let name = format!("SetPaymentXpub ({label})");
    // A new key's scan starts at 0.
    let mut stood = (0, 0);
    // One call: still catching up, the new key held pending and the old one
    // still active.
    if catch_up(
        r,
        &name,
        &set(&new, false),
        &set(&new, true),
        "PaymentXpubSet",
        per_store,
        Some(1),
        &mut stood,
    )?
    .is_some()
    {
        bail!("{name}: done in one call, so the pending slot was not exercised");
    }
    if held_key(r, XPUB_KEY)?.as_deref() != Some(old.as_str())
        || held_key(r, XPUB_PENDING_KEY)?.as_deref() != Some(new.as_str())
    {
        bail!("{name}: part-way, the new key is not held pending beside the active one");
    }
    // Resumed to the end: promoted, past every script, the slot emptied.
    let done = catch_up(
        r,
        &name,
        &set(&new, true),
        &set(&new, true),
        "PaymentXpubSet",
        per_store,
        None,
        &mut stood,
    )?
    .ok_or_else(|| anyhow!("{name}: never finished"))?;
    let count = field(&done, &["PaymentXpubSet", "result", "Ok", "next_index"])?;
    if *count != Value::Integer((per_store as u64).into())
        || held_key(r, XPUB_KEY)?.as_deref() != Some(new.as_str())
        || held_key(r, XPUB_PENDING_KEY)?.is_some()
    {
        bail!(
            "{name}: finished at count {} without the new key made active and the pending \
             slot emptied",
            brief(count)
        );
    }

    // The stale resume: tab A's new key part-way, tab B enters another (it
    // has no published scripts, so it is made active at once), then tab A
    // asks again.
    r.host.state.secrets = snapshot.clone();
    feed(r, &label, &scripts_at(&chain, 0..per_store as u32)?, false)?;
    r.quiet_send(&set(&new, false))?;
    r.app(
        "SetPaymentXpub (another new key, entered in another tab)",
        set(&newer, false),
        "PaymentXpubSet",
    )?;
    let out = r.send("SetPaymentXpub (a stale resume)", set(&new, true))?;
    let wrote = r.measured.last().map_or(u64::MAX, |m| m.host_writes);
    if wrote != 0 {
        bail!("a stale resume wrote {wrote} secrets: it must write nothing");
    }
    let answer: Value = ciborium::from_reader(
        first_app_payload(&out)
            .ok_or_else(|| anyhow!("a stale resume answered nothing"))?
            .as_slice(),
    )?;
    let prefix = harvest_common::bitcoin_delegate::KEY_SUPERSEDED_PREFIX;
    match field(&answer, &["PaymentXpubSet", "result", "Err"]) {
        Ok(Value::Text(why)) if why.starts_with(prefix) => {}
        _ => bail!(
            "a stale resume was not refused as superseded: {}",
            brief(&answer)
        ),
    }
    if held_key(r, XPUB_KEY)?.as_deref() != Some(newer.as_str())
        || held_key(r, XPUB_PENDING_KEY)?.is_some()
    {
        bail!("a stale resume changed which key is active or pending");
    }
    r.host.state.secrets = snapshot;
    Ok(())
}

/// How many calls of each request the spaced published-script run makes.
/// Driven to the end it is about 1,400 calls each (409,600 indices, about
/// 300 of them a call): minutes of CI for no more information than a few
/// dozen calls give, since each call's cost is bounded the same way.
const SPACED_CALLS: usize = 32;

/// Send `first`, then `again` for as long as the answer is the delegate's
/// catch-up refusal, every call measured under `name`, and return the first
/// other answer; or `None` when `max_calls` were made and it was still
/// catching up.
///
/// Since #216 a scan of published scripts derives at most
/// `FLOOR_SCAN_BUDGET` indices a call, keeps how far it got, and answers an
/// `Err` starting `CATCHING_UP_PREFIX` and the count; the web app asks again.
/// The refusal names the counter and the scan's cursor: the cursor must move
/// on every call, past `last` on the first (the caller seeds it with where
/// the scan stood, so a single call is checked too), the counter only when
/// the scan matched; with no
/// `max_calls` the requests are bounded by `bound` + 2, far more than a scan
/// budget of a single index needs, so a delegate that never finishes fails
/// the run. A delegate without the bound answers at once.
#[allow(clippy::too_many_arguments)]
fn catch_up(
    r: &mut Runner,
    name: &str,
    first: &[u8],
    again: &[u8],
    expect: &str,
    bound: usize,
    max_calls: Option<usize>,
    last: &mut (u64, u64),
) -> Result<Option<Value>> {
    let limit = max_calls.unwrap_or(bound.saturating_add(2)).max(1);
    let prefix = harvest_common::bitcoin_delegate::CATCHING_UP_PREFIX;
    for call in 0..limit {
        let payload = if call == 0 { first } else { again };
        let outbound = r.send(name, payload.to_vec())?;
        let response = first_app_payload(&outbound)
            .ok_or_else(|| anyhow!("{name}: no application message in the answer"))?;
        let value: Value = ciborium::from_reader(response.as_slice())
            .with_context(|| format!("{name}: the answer is not CBOR"))?;
        // `CATCHING_UP_PREFIX`, `{counter}/{cursor}`, `;`, a sentence.
        let refusal = match field(&value, &[expect, "result", "Err"]) {
            Ok(Value::Text(why)) if why.starts_with(prefix) => why.clone(),
            _ => {
                check_answer(name, &value, expect)?;
                return Ok(Some(value));
            }
        };
        let figures: Vec<u64> = refusal[prefix.len()..]
            .split(';')
            .next()
            .unwrap_or_default()
            .split('/')
            .map(|n| n.trim().parse())
            .collect::<Result<_, _>>()
            .map_err(|_| anyhow!("{name}: a catch-up refusal names no count: {refusal}"))?;
        let [counter, cursor] = figures[..] else {
            bail!("{name}: a catch-up refusal is not counter/cursor: {refusal}");
        };
        // The cursor moves on every call, the first included (past the
        // caller's baseline: where the scan stood before); the counter only
        // on a match.
        let (last_counter, last_cursor) = *last;
        if cursor <= last_cursor || counter < last_counter {
            bail!(
                "{name}: the catch-up went from {last_counter}/{last_cursor} to \
                 {counter}/{cursor}: it makes no progress"
            );
        }
        *last = (counter, cursor);
    }
    if max_calls.is_some() {
        return Ok(None);
    }
    bail!("{name}: still catching up after {limit} requests")
}

/// The export answers `freenet_migrate::ExportedSecrets`, not a Harvest
/// response. Checked for carrying at least `at_least` entries and every key
/// in `required`: its encoding is `freenet-migrate`'s business and tested
/// there.
fn freenet_migrate_check(bytes: &[u8], at_least: usize, required: &[Vec<u8>]) -> Result<()> {
    let v: Value = ciborium::from_reader(bytes).context("export is not CBOR")?;
    // `freenet_migrate::ExportedSecrets { secrets: Vec<(key, value)>, .. }`.
    let entries = match field(&v, &["secrets"])? {
        Value::Array(items) => items,
        other => bail!("the export's secrets are not a list: {}", brief(other)),
    };
    let n = entries.len();
    let keys: std::collections::HashSet<Vec<u8>> = entries
        .iter()
        .map(|e| match e {
            Value::Array(pair) if pair.len() == 2 => pair[0]
                .deserialized::<serde_bytes_vec::ByteVec>()
                .map(|k| k.0)
                .context("an exported key is not bytes"),
            other => bail!(
                "an exported entry is not a (key, value) pair: {}",
                brief(other)
            ),
        })
        .collect::<Result<_>>()?;
    let missing: Vec<_> = required
        .iter()
        .filter(|k| !keys.contains(*k))
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect();
    if !missing.is_empty() {
        bail!(
            "the export left out {} of the {} seeded ledgers ({missing:?}): it was cut short, \
             so its cost was not measured",
            missing.len(),
            required.len()
        );
    }
    if n < at_least {
        bail!(
            "the export carried {n} entries, fewer than the {at_least} secrets seeded: it was \
             refused or cut short, so its cost was not measured ({})",
            brief(&v)
        );
    }
    Ok(())
}

/// Deliver a mailbox state, and again for as long as the delegate says a run
/// left messages for the next one (its retry flag,
/// `harvest:auto:retry:{store}` = "1"): on a node the next mailbox change or
/// the wake-up's re-read delivers it. Every run is measured under `name`. A
/// delegate without the flag (one that opens everything in one run) gets one
/// delivery.
fn drain_mailbox(
    r: &mut Runner,
    name: &str,
    mailbox: [u8; 32],
    store: [u8; 32],
    state: Vec<u8>,
) -> Result<()> {
    let flag = format!("harvest:auto:retry:{}", bs58::encode(store).into_string());
    for _ in 0..32 {
        r.notify(name, mailbox, state.clone())?;
        if r.host.state.secrets.get(flag.as_bytes()).map(Vec::as_slice) != Some(b"1") {
            return Ok(());
        }
    }
    bail!("{name}: still not done after 32 runs; the delegate's per-run bound makes no progress")
}

/// A byte-cap mailbox whose plaintexts are written to cost the most to
/// decode rather than a text: a valid message with an extra field of
/// one-byte integers, which the decoder walks one by one. Anyone can encrypt
/// their own plaintext to a store's inbox. `sizes` gives each message's
/// length (as the byte-cap mailbox's), `tag` and `nonce_base` keep its
/// senders and nonces apart from any other mailbox's.
///
/// Each message is decrypted here, natively, with the key and associated
/// data the delegate will use, and must decode as a `PlaintextMessage`: a
/// fixture the delegate cannot open (or opens and cannot decode) is refused
/// cheaply, and the scan would pass the budget for the wrong reason.
fn hostile_mailbox(
    sizes: &[usize],
    inbox: [u8; 32],
    tag: u8,
    nonce_base: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<harvest_common::mailbox::EncryptedMessage>> {
    sizes
        .iter()
        .enumerate()
        .map(|(i, &len)| {
            let mut seed = [tag; 32];
            seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            let buyer = StaticSecret::from(seed);
            let sender = *PublicKey::from(&buyer).as_bytes();
            let shared = buyer.diffie_hellman(&PublicKey::from(inbox)).to_bytes();
            let key = harvest_common::mailbox::conversation_key_from_dh(
                &shared,
                harvest_common::mailbox::MessageDirection::BuyerToSeller,
            );
            let id = harvest_common::mailbox::ConversationId([(i % 251) as u8; 32]);
            let plaintext = Value::Map(vec![
                (
                    Value::Text("conversation_id".into()),
                    Value::Array(id.0.iter().map(|b| Value::Integer((*b).into())).collect()),
                ),
                (
                    Value::Text("content".into()),
                    Value::Map(vec![(
                        Value::Text("Text".into()),
                        Value::Text(String::new()),
                    )]),
                ),
                (
                    Value::Text("pad".into()),
                    Value::Array(vec![Value::Integer(0.into()); len.saturating_sub(64)]),
                ),
            ]);
            let message = fixtures::encrypt_bytes_seeded(
                &cbor(&plaintext),
                &id,
                &sender,
                &key,
                now - chrono::Duration::seconds(i as i64),
                nonce_base + i as u64,
            );
            let opened = harvest_common::sealed::decrypt_message(&message, &key)
                .map_err(|e| anyhow!("hostile message {i} does not open with its own key: {e}"))?;
            if opened.conversation_id != id {
                bail!("hostile message {i} decodes to another conversation: update the harness");
            }
            Ok(message)
        })
        .collect()
}

/// A mailbox state as a node delivers it: in the contract's canonical order
/// (by nonce, so effectively random in time) and passing its own `verify`.
/// The delegate sorts what it is given, and a fixture already in time order
/// would be its cheapest input, not a real one.
fn mailbox_state(
    mut messages: Vec<harvest_common::mailbox::EncryptedMessage>,
) -> Result<harvest_common::mailbox::MailboxStateV1> {
    messages.sort_by(harvest_common::mailbox::canonical_order);
    let state = harvest_common::mailbox::MailboxStateV1 { messages };
    state
        .verify()
        .map_err(|e| anyhow!("the mailbox fixture is not a state the contract accepts: {e}"))?;
    Ok(state)
}

/// The length of the longest array anywhere in `v`: the list an answer
/// carries, whatever its envelope.
fn count_array_somewhere(v: &Value) -> usize {
    match v {
        Value::Array(items) => items
            .len()
            .max(items.iter().map(count_array_somewhere).max().unwrap_or(0)),
        Value::Map(entries) => entries
            .iter()
            .map(|(_, v)| count_array_somewhere(v))
            .max()
            .unwrap_or(0),
        Value::Tag(_, inner) => count_array_somewhere(inner),
        _ => 0,
    }
}

/// Flag every store's mailbox as waiting to be re-read, or clear the flag:
/// in the ledger (`Ledger::retry_pending`, which every generation keeps and
/// main's wake-up reads) and beside it (`auto_invoice::retry_key`, which a
/// generation since #206 reads instead of decoding every ledger), so the
/// state is the one the delegate itself writes and either generation sees it.
fn set_retry(r: &mut Runner, stores: &[[u8; 32]], waiting: bool) -> Result<()> {
    for contract in stores {
        let id = bs58::encode(contract).into_string();
        let ledger_key = format!("harvest:auto:ledger:{id}").into_bytes();
        let bytes = r
            .host
            .state
            .secrets
            .get(&ledger_key)
            .ok_or_else(|| anyhow!("store {id} has no ledger to flag"))?;
        let mut ledger: Value =
            ciborium::from_reader(bytes.as_slice()).context("a ledger is not CBOR")?;
        let Value::Map(fields) = &mut ledger else {
            bail!("a ledger is not a map: update the harness");
        };
        let flag = fields
            .iter_mut()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "retry_pending"))
            .ok_or_else(|| anyhow!("a ledger has no retry_pending: update the harness"))?;
        flag.1 = Value::Bool(waiting);
        r.host.state.secrets.insert(ledger_key, cbor(&ledger));
        r.host.state.secrets.insert(
            format!("harvest:auto:retry:{id}").into_bytes(),
            if waiting { b"1" } else { b"0" }.to_vec(),
        );
    }
    Ok(())
}

/// The `watched` count of the watch delegation an `AutoInvoice` status
/// reports: the delegation's watches that cover the delegate's next
/// addresses (`watch_delegation::status_of`).
fn status_watched(status: &Value) -> Result<i128> {
    match field(
        status,
        &["AutoInvoice", "result", "Ok", "watch_delegation", "watched"],
    )? {
        Value::Integer(i) => Ok(i128::from(*i)),
        other => bail!("the status reports no delegated watches: {}", brief(other)),
    }
}

/// How many message digests the instant-checkout ledger records as read.
fn ledger_seen(r: &Runner, key: &str) -> Result<usize> {
    Ok(ledger_seen_digests(r, key)?.len())
}

/// The message digests the instant-checkout ledger records as read
/// (`Ledger::seen`, each `harvest_common::mailbox::entry_digest`).
fn ledger_seen_digests(r: &Runner, key: &str) -> Result<Vec<[u8; 32]>> {
    let v = secret_value(r, key.as_bytes())?;
    match field(&v, &["seen"])? {
        Value::Array(items) => items.iter().map(bytes32).collect(),
        other => bail!("ledger seen is not a list: {}", brief(other)),
    }
}

/// A secret the delegate holds, decoded as CBOR.
fn secret_value(r: &Runner, key: &[u8]) -> Result<Value> {
    let bytes = r.host.state.secrets.get(key).ok_or_else(|| {
        anyhow!(
            "the delegate holds no secret {}",
            String::from_utf8_lossy(key)
        )
    })?;
    ciborium::from_reader(bytes.as_slice())
        .with_context(|| format!("secret {} is not CBOR", String::from_utf8_lossy(key)))
}

/// The field names of a CBOR map, sorted.
fn map_keys(v: &Value) -> Result<Vec<String>> {
    let Value::Map(entries) = v else {
        bail!("not a map: {}", brief(v));
    };
    let mut keys = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(t) => Ok(t.clone()),
            other => bail!("a non-text field name: {}", brief(other)),
        })
        .collect::<Result<Vec<_>>>()?;
    keys.sort();
    Ok(keys)
}

/// The length of the list at `path` in `v`.
fn list_len(v: &Value, path: &[&str]) -> Result<usize> {
    match field(v, path)? {
        Value::Array(items) => Ok(items.len()),
        other => bail!("{} is not a list: {}", path.join("."), brief(other)),
    }
}

/// The delegate's own encoding of a crate-private type has exactly the
/// fields the harness's mirror has. Most of the delegate's fields are
/// `serde(default)`, so a mirror missing one still decodes, and a field the
/// delegate added would never be filled: a fixture that silently no longer
/// reaches the delegate's worst case.
fn same_fields(what: &str, delegate: &Value, mirror: &Value) -> Result<()> {
    let (d, m) = (map_keys(delegate)?, map_keys(mirror)?);
    if d != m {
        let only_d: Vec<_> = d.iter().filter(|k| !m.contains(k)).collect();
        let only_m: Vec<_> = m.iter().filter(|k| !d.contains(k)).collect();
        bail!(
            "the delegate's {what} has fields the harness's mirror lacks ({only_d:?}) or the \
             mirror has fields the delegate does not write ({only_m:?}): update `fixtures.rs`"
        );
    }
    Ok(())
}

/// `Vec<u8>` from either a CBOR byte string or an array of integers.
mod serde_bytes_vec {
    pub struct ByteVec(pub Vec<u8>);
    impl<'de> serde::Deserialize<'de> for ByteVec {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = ByteVec;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<ByteVec, E> {
                    Ok(ByteVec(v.to_vec()))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<ByteVec, A::Error> {
                    let mut out = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(ByteVec(out))
                }
            }
            d.deserialize_any(V)
        }
    }
}

fn default_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../ui/public/contracts/harvest_delegate.wasm")
}

fn run() -> Result<bool> {
    let mut args = std::env::args().skip(1);
    let mut wasm_path = default_wasm();
    let mut committed = true;
    let mut calibrate_reps = 0usize;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wasm" => {
                wasm_path = args.next().ok_or_else(|| anyhow!("--wasm PATH"))?.into();
                committed = false;
            }
            "--calibrate" => calibrate_reps = 3,
            n if calibrate_reps > 0 && n.parse::<usize>().is_ok() => {
                calibrate_reps = n.parse().unwrap()
            }
            other => bail!("unknown argument {other}; usage: [--wasm PATH] [--calibrate [REPS]]"),
        }
    }
    let wasm =
        std::fs::read(&wasm_path).with_context(|| format!("read {}", wasm_path.display()))?;
    let hash = blake3_hex(&wasm);
    println!(
        "delegate: {} ({} bytes, blake3 {hash})",
        wasm_path.display(),
        wasm.len()
    );
    println!(
        "budget:   {} fuel per call (~{BUDGET_SECONDS} s of work on the reference machine; \
         the node's limit is 5 s)",
        group(BUDGET_FUEL)
    );
    println!();

    let origin = MessageOrigin::WebApp(
        harvest_common::HARVEST_WEBAPP_CONTRACT_ID
            .parse::<ContractInstanceId>()
            .map_err(|e| anyhow!("webapp id: {e}"))?,
    );
    let state = HostState::new(0x4841_5256_4553_5421, fixtures::ts(1_790_000_000));
    let mut runner = Runner {
        host: Host::new(&wasm, state, calibrate_reps > 0)?,
        origin,
        calibrate_reps,
        measured: Vec::new(),
        committed,
    };
    let scenario_result = scenario(&mut runner);

    let ok = report(&runner.measured, &hash, scenario_result.as_ref().err())?;
    // A call past the fuel ceiling also stops the scenario; that is an
    // over-budget result (exit 1), not a harness failure (exit 2).
    if !ok {
        if let Err(e) = &scenario_result {
            eprintln!("(the scenario also stopped early: {e:#})");
        }
        return Ok(false);
    }
    scenario_result.context("the scenario did not complete")?;
    Ok(ok)
}

/// BLAKE3, as `scripts/check-code-hashes.sh` and the staleness job print it,
/// so a reader can match the measured file to the committed one.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// One report row: every call of that name, keeping the most expensive.
struct Row {
    name: String,
    calls: usize,
    fuel: Option<u64>,
    host_calls: u64,
    /// The most writes any call of this name made.
    host_writes: u64,
    timing: Option<(Duration, Duration)>,
}

fn over_budget(fuel: Option<u64>) -> bool {
    fuel.is_none_or(|f| f > BUDGET_FUEL)
}

/// Print the table, write the GitHub step summary, and say whether every
/// call fit the budget.
fn report(measured: &[Measured], hash: &str, failure: Option<&anyhow::Error>) -> Result<bool> {
    let mut rows: Vec<Row> = Vec::new();
    for m in measured {
        match rows.iter_mut().find(|r| r.name == m.name) {
            Some(row) => {
                row.calls += 1;
                row.host_writes = row.host_writes.max(m.host_writes);
                if over_budget(m.fuel) || (!over_budget(row.fuel) && m.fuel > row.fuel) {
                    row.fuel = m.fuel;
                    row.host_calls = m.host_calls;
                    row.timing = m.timing;
                }
            }
            None => rows.push(Row {
                name: m.name.clone(),
                calls: 1,
                fuel: m.fuel,
                host_calls: m.host_calls,
                host_writes: m.host_writes,
                timing: m.timing,
            }),
        }
    }
    let over: Vec<&str> = rows
        .iter()
        .filter(|r| over_budget(r.fuel) || r.host_writes > BUDGET_WRITES)
        .map(|r| r.name.as_str())
        .collect();

    let mut md = String::new();
    writeln!(md, "## Harvest delegate: work per call").ok();
    writeln!(md).ok();
    writeln!(
        md,
        "Delegate `{}`, budget **{}** fuel per call (about {BUDGET_SECONDS} s of work; the \
         node stops a call at 5 s). Fuel is deterministic: these numbers are the same on every \
         run and every machine.",
        &hash[..16.min(hash.len())],
        group(BUDGET_FUEL)
    )
    .ok();
    writeln!(md).ok();
    writeln!(
        md,
        "| call | calls | fuel (max) | of budget | host calls | writes | |"
    )
    .ok();
    writeln!(md, "|---|---:|---:|---:|---:|---:|---|").ok();
    println!();
    println!(
        "{:<52} {:>5} {:>18} {:>9} {:>10} {:>6}",
        "call", "calls", "fuel (max)", "budget", "host calls", "writes"
    );
    for r in &rows {
        let pct = r.fuel.map_or("-".into(), |f| {
            format!("{:.1}%", f as f64 * 100.0 / BUDGET_FUEL as f64)
        });
        let fuel = r.fuel.map_or("past the ceiling".into(), group);
        let flag = if over_budget(r.fuel) || r.host_writes > BUDGET_WRITES {
            "OVER"
        } else {
            ""
        };
        println!(
            "{:<52} {:>5} {fuel:>18} {pct:>9} {:>10} {:>6} {flag}",
            r.name, r.calls, r.host_calls, r.host_writes
        );
        writeln!(
            md,
            "| {} | {} | {fuel} | {pct} | {} | {} | {} |",
            r.name,
            r.calls,
            r.host_calls,
            r.host_writes,
            if flag.is_empty() {
                ""
            } else {
                ":x: **over budget**"
            }
        )
        .ok();
    }

    if rows.iter().any(|r| r.timing.is_some()) {
        println!();
        println!("calibration (best unmetered run, node-like engine: Cranelift OptLevel::None, epoch interruption)");
        println!(
            "{:<52} {:>18} {:>10} {:>9} {:>16} {:>16}",
            "call", "fuel", "wall ms", "host ms", "fuel/s (wall)", "fuel/s (guest)"
        );
        for r in rows.iter().filter(|r| r.timing.is_some()) {
            let (wall, host) = r.timing.unwrap();
            let fuel = r.fuel.unwrap_or(0) as f64;
            let guest = wall.saturating_sub(host).as_secs_f64();
            println!(
                "{:<52} {:>18} {:>10.1} {:>9.1} {:>16} {:>16}",
                r.name,
                r.fuel.map_or("-".into(), group),
                wall.as_secs_f64() * 1e3,
                host.as_secs_f64() * 1e3,
                group((fuel / wall.as_secs_f64()) as u64),
                if guest > 0.0 {
                    group((fuel / guest) as u64)
                } else {
                    "-".into()
                },
            );
        }
    }

    writeln!(md).ok();
    if let Some(e) = failure {
        writeln!(md, ":x: The scenario stopped early: `{e:#}`").ok();
    } else if over.is_empty() {
        writeln!(md, "Every call is within budget.").ok();
    } else {
        writeln!(
            md,
            ":x: Over budget: {}. On a node such a call risks running past the 5 s wall-clock \
             limit, and the web app never learns why it got no answer. See \
             `tests/delegate-budget/README.md`.",
            over.join(", ")
        )
        .ok();
    }
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(md.as_bytes())?;
    }

    println!();
    if over.is_empty() {
        println!("every call is within {} fuel", group(BUDGET_FUEL));
    } else {
        for name in &over {
            eprintln!(
                "::error::{name} exceeds the per-call budget of {} fuel or {BUDGET_WRITES} \
                 secret writes",
                group(BUDGET_FUEL)
            );
        }
    }
    Ok(over.is_empty())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("::error::delegate budget harness failed: {e:#}");
            ExitCode::from(2)
        }
    }
}
