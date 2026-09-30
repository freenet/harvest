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
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, WrappedState,
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
/// measured there (copy-heavy code, about 4.1 billion fuel/s; crypto runs at
/// 9.5-11 billion, so for crypto this is about 0.4 s). The margin is for everything
/// fuel does not see: a slower CPU than the reference, a node under load (the
/// limit is wall clock, and nova at load 9-18 turned 1/30 timeouts into 7/30
/// in the #203 investigation), and host-function time (the node's encrypted
/// secret store). Calibration, and how to redo it: README.md.
const BUDGET_FUEL: u64 = 4_000_000_000;

/// The seconds of work [`BUDGET_FUEL`] stands for, for the report only.
const BUDGET_SECONDS: f64 = 1.0;

/// How many store keys to derive subkeys for. `GetStoreSubkeys` cost used to
/// depend on the store key (a seeded RSA prime search), so one key proves
/// nothing either way; the #203 probe saw 0.85-5 s across keys.
const STORE_KEYS: usize = 8;

/// The mailbox cap (`harvest_common::mailbox::MAX_MESSAGES`): the most
/// distinct senders one `DeriveConversationKeys` can name.
const MAILBOX_PEERS: usize = harvest_common::mailbox::MAX_MESSAGES;

/// `messaging::MAX_BUYER_CONVERSATIONS`: conversations a buyer keeps.
const BUYER_CONVERSATIONS: usize = 256;

/// `harvest_common::delegate::MAX_KEPT_PURCHASES`: purchases a buyer keeps.
const KEPT_PURCHASES: usize = harvest_common::delegate::MAX_KEPT_PURCHASES;

struct Measured {
    name: String,
    fuel: Option<u64>,
    /// Host-function calls the metered run made (deterministic, reported
    /// only: fuel does not count host time, so this shows how much of a call
    /// happens outside it).
    host_calls: u64,
    /// `--calibrate` only: the best unmetered, node-like wall time of
    /// `process`, and the part of it spent in host functions.
    timing: Option<(Duration, Duration)>,
}

struct Runner {
    host: Host,
    origin: MessageOrigin,
    calibrate_reps: usize,
    measured: Vec<Measured>,
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

    fn send(&mut self, name: &str, payload: Vec<u8>) -> Result<Vec<OutboundDelegateMsg>> {
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload));
        let origin = self.origin.clone();
        let timing = self.time(Some(&origin), &msg)?;
        let outcome = self.host.call(Some(&origin), &msg)?;
        self.record(name, outcome.fuel, outcome.host_calls, timing);
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
        self.record(name, outcome.fuel, outcome.host_calls, timing);
        outcome
            .result
            .map_err(|e| anyhow!("{name}: the delegate returned an error: {e}"))
    }

    /// A run the node starts on its own (stdlib 0.12 tags 9 and 10, which
    /// the delegate decodes by hand in `node_glue`). The node sends these
    /// with no origin.
    fn background(&mut self, name: &str, raw: &[u8]) -> Result<Vec<OutboundDelegateMsg>> {
        let outcome = self.host.call_raw(None, raw)?;
        self.record(name, outcome.fuel, outcome.host_calls, None);
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
        fuel: Option<u64>,
        host_calls: u64,
        timing: Option<(Duration, Duration)>,
    ) {
        let shown = fuel.map_or("past the ceiling".to_string(), group);
        println!("  {name:<52} {shown:>18}");
        self.measured.push(Measured {
            name: name.to_string(),
            fuel,
            host_calls,
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
    let ghost = SigningKey::from_bytes(&[0x42; 32]);
    let fingerprint = "budget-seller-fp".to_string();

    // --- store keys (harvest#93 phase 1b) --------------------------------
    let mut stores = Vec::new();
    for i in 0..STORE_KEYS {
        let answer = r.app(
            &format!("CreateStoreKey #{i}"),
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
    for (i, store) in stores.iter().enumerate() {
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
                trusted_bridges: vec![bridge_id],
                address_code_hash: [0x56; 32],
                watched_scripts: watched,
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
    r.app(
        "GetWatchKey",
        cbor(&HarvestDelegateRequest::GetWatchKey),
        "WatchKey",
    )?;

    // The bridge's tip contract changes: instant checkout caches the tip it
    // needs before it will issue anything (`auto_invoice::note_tip`).
    let now_s = r.host.state.now.timestamp();
    let tip = freenet_bitcoin_common::SignedTipEntry::sign(
        &bridge,
        &freenet_bitcoin_common::TipEntryBody {
            network: BitcoinNetwork::Signet,
            anchor: freenet_bitcoin_common::BlockAnchor {
                height: 250_000,
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
    r.notify(
        "ContractNotification: bridge tip",
        tip_contract,
        freenet_bitcoin_common::to_cbor(&tip_state).map_err(|e| anyhow!("{e}"))?,
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
    r.notify(
        &format!("ContractNotification: mailbox ({MAILBOX_PEERS} unread)"),
        mailbox_contract,
        cbor(&harvest_common::mailbox::MailboxStateV1 { messages }),
    )?;
    let ledger = format!(
        "harvest:auto:ledger:{}",
        bs58::encode(store_contract).into_string()
    );
    match r.host.state.secrets.get(ledger.as_bytes()) {
        Some(l) if l.len() >= MAILBOX_PEERS * 32 => {}
        other => bail!(
            "the mailbox notification did not record the {MAILBOX_PEERS} messages as read \
             (ledger {} bytes): the scan was refused or skipped, so its cost was not measured",
            other.map_or(0, Vec::len)
        ),
    }

    // --- runs the node starts on its own ------------------------------------
    // Byte layouts pinned in `node_glue`'s tests against stdlib 0.12.0.
    r.background("Background: Installed", &[0x0a, 0, 0, 0, 0, 0, 0, 0])?;
    r.background("Background: NodeStarted", &[0x0a, 0, 0, 0, 1, 0, 0, 0, 0])?;
    let mut wakeup = vec![0x09, 0, 0, 0];
    wakeup.extend_from_slice(&9u64.to_le_bytes());
    wakeup.extend_from_slice(b"heartbeat");
    r.host.state.now += chrono::Duration::minutes(5);
    r.background("Background: heartbeat wake-up", &wakeup)?;

    // --- the buyer's half ---------------------------------------------------
    let orders = fixtures::OrderFx {
        seller: SigningKey::from_bytes(&[11u8; 32]),
        bridge,
    };
    let seller_store_key = orders.seller.verifying_key().to_bytes();
    let mut first_secret = None;
    for i in 0..BUYER_CONVERSATIONS {
        let mut secret = [0x60u8; 32];
        secret[1..9].copy_from_slice(&(i as u64).to_le_bytes());
        first_secret.get_or_insert(secret);
        let conversation = *PublicKey::from(&StaticSecret::from(secret)).as_bytes();
        let name = if i == 0 || i == BUYER_CONVERSATIONS - 1 {
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
    r.app(
        &format!("ListBuyerConversations ({BUYER_CONVERSATIONS})"),
        cbor(&HarvestDelegateRequest::ListBuyerConversations {
            request_id: 900,
            store_contract_id: store_contract.to_vec(),
        }),
        "BuyerConversationList",
    )?;

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
    for n in 1..KEPT_PURCHASES as u32 {
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

    // --- the migration export, last: it disarms instant checkout -----------
    let out = r.send(
        "ExportSecrets (migration)",
        cbor(&HarvestMigrationRequest::ExportSecrets {
            source_generation: 0,
        }),
    )?;
    let exported = first_app_payload(&out).ok_or_else(|| anyhow!("export answered nothing"))?;
    freenet_migrate_check(&exported)?;

    Ok(())
}

/// The export answers `freenet_migrate::ExportedSecrets`, not a Harvest
/// response. Checked only for being a non-empty CBOR value: its contents are
/// `freenet-migrate`'s business and tested there.
fn freenet_migrate_check(bytes: &[u8]) -> Result<()> {
    let v: Value = ciborium::from_reader(bytes).context("export is not CBOR")?;
    if matches!(v, Value::Null) {
        bail!("export answered null");
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
    let mut calibrate_reps = 0usize;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wasm" => wasm_path = args.next().ok_or_else(|| anyhow!("--wasm PATH"))?.into(),
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
    };
    let scenario_result = scenario(&mut runner);

    let ok = report(&runner.measured, &hash, scenario_result.as_ref().err())?;
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
                timing: m.timing,
            }),
        }
    }
    let over: Vec<&str> = rows
        .iter()
        .filter(|r| over_budget(r.fuel))
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
        "| call | calls | fuel (max) | of budget | host calls | |"
    )
    .ok();
    writeln!(md, "|---|---:|---:|---:|---:|---|").ok();
    println!();
    println!(
        "{:<52} {:>5} {:>18} {:>9} {:>10}",
        "call", "calls", "fuel (max)", "budget", "host calls"
    );
    for r in &rows {
        let pct = r.fuel.map_or("-".into(), |f| {
            format!("{:.1}%", f as f64 * 100.0 / BUDGET_FUEL as f64)
        });
        let fuel = r.fuel.map_or("past the ceiling".into(), group);
        let flag = if over_budget(r.fuel) { "OVER" } else { "" };
        println!(
            "{:<52} {:>5} {fuel:>18} {pct:>9} {:>10} {flag}",
            r.name, r.calls, r.host_calls
        );
        writeln!(
            md,
            "| {} | {} | {fuel} | {pct} | {} | {} |",
            r.name,
            r.calls,
            r.host_calls,
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
                "::error::{name} exceeds the per-call budget of {} fuel",
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
