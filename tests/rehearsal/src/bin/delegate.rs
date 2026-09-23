//! Rehearsal of the harvest delegate's secret migration (harvest#123)
//! against a live node.
//!
//! The walk itself runs in the browser (`ui/src/delegate_migrate.rs` over
//! `ui/src/gateway/delegate_migrate_ops.rs`), because that is the code that
//! ships. This binary does the two things around it that a browser cannot be
//! scripted to do cheaply:
//!
//! * `seed`: register a delegate generation and put one secret of every
//!   family into it, through that generation's own request handlers, then
//!   write down what it answered;
//! * `check`: register the current generation and ask it for every one of
//!   those secrets, comparing value for value -- never a count.
//!
//! Both talk to the node AS the Harvest web app: the delegate refuses anyone
//! else (`delegates/harvest-delegate/src/origin.rs`), and the node attests the
//! caller from the `authToken` it issued when it served the web app's page.
//! So the URL passed here must carry that token.
//!
//! Usage:
//!   delegate seed  <ws-url-with-authToken> <delegate.wasm> <out.json>
//!   delegate check <ws-url-with-authToken> <delegate.wasm> <seeded.json> <predecessor-key-hex>
//!   delegate touch <ws-url-with-authToken> <delegate.wasm>
//!     (touch: register the delegate and give it a remembered store and a
//!      store registration of its own, for the populated-successor scenario)
//!   delegate seed-store  <ws-url-with-authToken> <delegate.wasm> <out.json>
//!   delegate check-store <ws-url-with-authToken> <delegate.wasm> <seeded-store.json>
//!     (a REAL store key, minted by that generation, registered, and shown to
//!      sign; then whether the successor still holds it -- the migration
//!      carries the registration but never the key, harvest#138 F1)
//!   delegate recover-store <ws-url-with-authToken> <delegate.wasm> <seeded-store.json>
//!     (what custody's Recover does: unwrap the seeded copy with the stand-in
//!      backer's wrap signature, then check the successor signs again)
//!   delegate seed-convo <ws-url-with-authToken> <delegate.wasm> <store-code-hash-hex> <out-dir>
//!     (keep a buyer conversation under the store's id at an EARLIER store
//!      generation, and write the store code plus the current generation's
//!      parameters and empty state for `fdev publish`, harvest#138 F2)

use std::time::Duration;

use freenet_stdlib::client_api::{ClientRequest, DelegateRequest, HostResponse, WebApi};
use freenet_stdlib::prelude::*;
use harvest_common::bitcoin_delegate::{BitcoinDelegateRequest, BitcoinDelegateResponse};
use harvest_common::delegate::{
    ConversationSecret, HarvestDelegateRequest, HarvestDelegateResponse, PredecessorMarkerState,
    StoreRegistration,
};
use serde::{Deserialize, Serialize};

const FP: &str = "rehearsal-fp";
const STORE_CODE: &str = "3Bn8xWqLd6Tz9Kf2";
const SUCCESSOR_STORE_CODE: &str = "7SvqFBjw5vGE5JYG";
const CONV_STORE: [u8; 32] = [0x51; 32];
const CONV_SECRET: [u8; 32] = [0x77; 32];
const MARKER: &str = "v1.store.rehearsal.marker";

/// What the seeded generation answered, and so what the successor must
/// answer too.
#[derive(Serialize, Deserialize, Debug)]
struct Seeded {
    rsa_public_key_der: Vec<u8>,
    x25519_public_key: Vec<u8>,
    stores: Vec<StoreRegistration>,
    remembered: Vec<String>,
    xpub: String,
    /// `RecalledConversation::buyer_public_key`, a function of the secret.
    conversation_buyer_public_key: [u8; 32],
}

struct Node {
    api: WebApi,
}

impl Node {
    async fn connect(url: &str) -> Node {
        let (stream, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect to node websocket");
        Node {
            api: WebApi::start(stream),
        }
    }

    async fn register(&mut self, wasm: &[u8]) -> DelegateKey {
        let code = DelegateCode::from(wasm.to_vec());
        let params = Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS);
        let delegate = Delegate::from((&code, &params));
        let container = DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate));
        let key = container.key().clone();
        self.api
            .send(ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
                delegate: container,
                cipher: [0u8; 32],
                nonce: [0u8; 24],
            }))
            .await
            .expect("send RegisterDelegate");
        // The node answers a registration; drain it so it is not read as the
        // answer to the first request.
        let _ = tokio::time::timeout(Duration::from_secs(10), self.api.recv()).await;
        println!("registered delegate {key}");
        key
    }

    async fn ask(&mut self, key: &DelegateKey, payload: Vec<u8>) -> Vec<u8> {
        self.api
            .send(ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
                key: key.clone(),
                params: Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS),
                inbound: vec![InboundDelegateMsg::ApplicationMessage(
                    ApplicationMessage::new(payload),
                )],
            }))
            .await
            .expect("send delegate message");
        loop {
            match tokio::time::timeout(Duration::from_secs(20), self.api.recv()).await {
                Err(_) => panic!("no delegate answer within 20s"),
                Ok(Ok(HostResponse::DelegateResponse { values, .. })) => {
                    for value in values {
                        if let OutboundDelegateMsg::ApplicationMessage(msg) = value {
                            return msg.payload;
                        }
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => panic!("node error: {e}"),
            }
        }
    }

    async fn harvest(&mut self, key: &DelegateKey, request: HarvestDelegateRequest) -> HarvestDelegateResponse {
        let bytes = self.ask(key, harvest_common::to_cbor(&request).unwrap()).await;
        let response: HarvestDelegateResponse = harvest_common::from_cbor(&bytes).expect("a harvest response");
        if let HarvestDelegateResponse::Error { message } = &response {
            panic!("the delegate refused: {message}");
        }
        response
    }

    async fn bitcoin(&mut self, key: &DelegateKey, request: BitcoinDelegateRequest) -> BitcoinDelegateResponse {
        let bytes = self.ask(key, harvest_common::to_cbor(&request).unwrap()).await;
        harvest_common::from_cbor(&bytes).expect("a bitcoin response")
    }
}

/// A signet account key: the BIP-84 test vector's bytes under the vpub
/// version prefix, as the delegate's own tests build one.
fn signet_vpub() -> String {
    let mut bytes = bs58::decode(
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    )
    .with_check(None)
    .into_vec()
    .expect("the BIP-84 vector decodes");
    bytes[..4].copy_from_slice(&0x045f_1cf6u32.to_be_bytes());
    bs58::encode(bytes).with_check().into_string()
}

async fn read_back(node: &mut Node, key: &DelegateKey) -> Seeded {
    let rsa = match node
        .harvest(key, HarvestDelegateRequest::GetRsaPublicKey { ghostkey_fingerprint: FP.into() })
        .await
    {
        HarvestDelegateResponse::RsaPublicKey { rsa_public_key_der, .. } => rsa_public_key_der,
        other => panic!("GetRsaPublicKey: {other:?}"),
    };
    // Mints if absent -- which is exactly the check: after a migration it
    // must answer the PREDECESSOR's key, not a new one.
    let x25519 = match node
        .harvest(key, HarvestDelegateRequest::InitEncryptionKey { ghostkey_fingerprint: FP.into(), recall_only: false })
        .await
    {
        HarvestDelegateResponse::EncryptionKeyReady { x25519_public_key, .. } => x25519_public_key,
        other => panic!("InitEncryptionKey: {other:?}"),
    };
    let stores = match node
        .harvest(key, HarvestDelegateRequest::ListStores { ghostkey_fingerprint: FP.into() })
        .await
    {
        HarvestDelegateResponse::StoreList { stores, .. } => stores,
        other => panic!("ListStores: {other:?}"),
    };
    let remembered = match node.harvest(key, HarvestDelegateRequest::ListRememberedStores).await {
        HarvestDelegateResponse::RememberedStores { stores } => stores.into_iter().map(|s| s.store_code).collect(),
        other => panic!("ListRememberedStores: {other:?}"),
    };
    let xpub = match node.bitcoin(key, BitcoinDelegateRequest::GetPaymentXpub).await {
        BitcoinDelegateResponse::PaymentXpub { status } => status.map(|s| s.xpub).unwrap_or_default(),
        other => panic!("GetPaymentXpub: {other:?}"),
    };
    let conversation_buyer_public_key = match node
        .harvest(
            key,
            HarvestDelegateRequest::ListBuyerConversations { request_id: 2, store_contract_id: CONV_STORE.to_vec() },
        )
        .await
    {
        HarvestDelegateResponse::BuyerConversationList { conversations, .. } => {
            conversations.first().map(|c| c.buyer_public_key).unwrap_or([0; 32])
        }
        other => panic!("ListBuyerConversations: {other:?}"),
    };
    Seeded {
        rsa_public_key_der: rsa,
        x25519_public_key: x25519,
        stores,
        remembered,
        xpub,
        conversation_buyer_public_key,
    }
}

async fn seed(url: &str, wasm: &[u8], out: &str) {
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    node.harvest(&key, HarvestDelegateRequest::InitReputationKeys { ghostkey_fingerprint: FP.into() }).await;
    node.harvest(
        &key,
        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint: FP.into(),
            store_contract_id: vec![0x11; 32],
            reputation_contract_id: vec![0x12; 32],
            mailbox_contract_id: vec![0x13; 32],
            store_verifying_key: Some([0x14; 32]),
        },
    )
    .await;
    node.harvest(&key, HarvestDelegateRequest::RememberStore { store_code: STORE_CODE.into() }).await;
    node.harvest(
        &key,
        HarvestDelegateRequest::StoreBuyerConversation {
            request_id: 1,
            store_contract_id: CONV_STORE.to_vec(),
            secret: ConversationSecret(CONV_SECRET),
            seller_public_key: [0x33; 32],
            conversation_id: [0x34; 32],
            created_at: 1_700_000_000,
        },
    )
    .await;
    node.harvest(&key, HarvestDelegateRequest::SetMigrationMarker { marker: MARKER.into(), note: "seeded".into() })
        .await;
    match node
        .bitcoin(
            &key,
            BitcoinDelegateRequest::SetPaymentXpub {
                request_id: 3,
                xpub: signet_vpub(),
                network: freenet_bitcoin_common_network(),
                published_scripts: Vec::new(),
            },
        )
        .await
    {
        BitcoinDelegateResponse::PaymentXpubSet { result: Ok(_), .. } => {}
        other => panic!("SetPaymentXpub: {other:?}"),
    }
    let seeded = read_back(&mut node, &key).await;
    assert!(!seeded.rsa_public_key_der.is_empty() && !seeded.stores.is_empty() && !seeded.xpub.is_empty());
    std::fs::write(out, serde_json::to_vec_pretty(&seeded).unwrap()).unwrap();
    println!("seeded {key}: {seeded:#?}");
}

fn freenet_bitcoin_common_network() -> freenet_bitcoin_common::BitcoinNetwork {
    freenet_bitcoin_common::BitcoinNetwork::Signet
}

async fn touch(url: &str, wasm: &[u8]) {
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    node.harvest(&key, HarvestDelegateRequest::RememberStore { store_code: SUCCESSOR_STORE_CODE.into() }).await;
    node.harvest(
        &key,
        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint: FP.into(),
            store_contract_id: vec![0x21; 32],
            reputation_contract_id: vec![0x22; 32],
            mailbox_contract_id: vec![0x23; 32],
            store_verifying_key: None,
        },
    )
    .await;
    println!("touched {key}: it now holds a store and a remembered store of its own");
}

async fn check(url: &str, wasm: &[u8], seeded: &str, predecessor_hex: &str) {
    let expected: Seeded = serde_json::from_slice(&std::fs::read(seeded).unwrap()).unwrap();
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    let predecessor: [u8; 32] = hex::decode(predecessor_hex).unwrap().try_into().unwrap();
    match node.harvest(&key, HarvestDelegateRequest::GetPredecessorMarker { predecessor }).await {
        HarvestDelegateResponse::PredecessorMarker { marker, .. } => {
            println!("predecessor marker: {marker:?}");
            assert_eq!(marker, Some(PredecessorMarkerState::Done { had_data: true }), "the predecessor is sealed done");
        }
        other => panic!("GetPredecessorMarker: {other:?}"),
    }
    match node.harvest(&key, HarvestDelegateRequest::GetMigrationMarker { marker: MARKER.into() }).await {
        HarvestDelegateResponse::MigrationMarker { present, .. } => assert!(present, "the contract marker travelled"),
        other => panic!("GetMigrationMarker: {other:?}"),
    }
    let got = read_back(&mut node, &key).await;
    let mut failures = Vec::new();
    let mut compare = |what: &str, ok: bool, detail: String| {
        println!("{} {what}: {detail}", if ok { "OK  " } else { "FAIL" });
        if !ok {
            failures.push(what.to_string());
        }
    };
    compare("RSA public key", got.rsa_public_key_der == expected.rsa_public_key_der, format!("{} bytes", got.rsa_public_key_der.len()));
    compare(
        "X25519 public key (the predecessor's, not a new one)",
        got.x25519_public_key == expected.x25519_public_key,
        hex::encode(&got.x25519_public_key),
    );
    compare("payment xpub", got.xpub == expected.xpub, got.xpub.clone());
    compare(
        "buyer conversation",
        got.conversation_buyer_public_key == expected.conversation_buyer_public_key && got.conversation_buyer_public_key != [0; 32],
        hex::encode(got.conversation_buyer_public_key),
    );
    for store in &expected.stores {
        compare(
            "store registration",
            got.stores.iter().any(|s| s.store_contract_id == store.store_contract_id && s.store_verifying_key == store.store_verifying_key),
            format!("{} registration(s) held", got.stores.len()),
        );
    }
    for code in &expected.remembered {
        compare("remembered store", got.remembered.contains(code), format!("{:?}", got.remembered));
    }
    println!("full read-back of the successor: {got:#?}");
    if failures.is_empty() {
        println!("REHEARSAL PASSED: every seeded secret is answered by the successor");
    } else {
        println!("REHEARSAL FAILED: {failures:?}");
        std::process::exit(1);
    }
}

const STORE_FP: &str = "rehearsal-store-fp";

/// A store key the seeded generation minted and signed with, and the custody
/// copy it wrapped to the rehearsal's stand-in backing Ghost Key.
#[derive(Serialize, Deserialize, Debug)]
struct SeededStore {
    store_verifying_key: [u8; 32],
    copy: harvest_common::custody::AuthorizedCopy,
}

/// The stand-in for a backing Ghost Key: the vault's signature over the wrap
/// message is all custody needs from it. A throwaway key, never a real one.
fn backer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x4b; 32])
}

/// What the vault answers a wrap request with: the scoped payload and the
/// backer's signature over it.
fn wrap_signature(store: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use ed25519_dalek::Signer;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&store).expect("a store key");
    let scoped = ghostkey_common::ScopedPayload {
        requestor: harvest_common::expected_harvest_requestor(),
        payload: harvest_common::custody::wrap_message(&vk),
    };
    let bytes = ghostkey_common::to_cbor(&scoped).expect("encode");
    let signature = backer().sign(&bytes).to_bytes().to_vec();
    (bytes, signature)
}

/// Whether `key` answers for the store key: a registration naming it, its
/// subkeys (derived only from a key the delegate HOLDS), and a signature.
async fn store_key_report(node: &mut Node, key: &DelegateKey, store: [u8; 32]) -> (bool, Result<(), String>, Result<(), String>) {
    let registered = match node
        .harvest(key, HarvestDelegateRequest::ListStores { ghostkey_fingerprint: STORE_FP.into() })
        .await
    {
        HarvestDelegateResponse::StoreList { stores, held_store_keys, .. } => {
            // `None` from a generation older than the field (V18, V19).
            println!("  StoreList held_store_keys: {:?}", held_store_keys.map(|keys| keys.contains(&store)));
            stores.iter().any(|s| s.store_verifying_key == Some(store))
        }
        other => panic!("ListStores: {other:?}"),
    };
    let subkeys = match node
        .harvest(key, HarvestDelegateRequest::GetStoreSubkeys { request_id: 41, store_verifying_key: store })
        .await
    {
        HarvestDelegateResponse::StoreSubkeys { result, .. } => result.map(|_| ()),
        other => panic!("GetStoreSubkeys: {other:?}"),
    };
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&store).expect("a store key");
    let closure = harvest_common::to_cbor(&harvest_common::backing::StoreClosure { store: vk }).unwrap();
    let signed = match node
        .harvest(key, HarvestDelegateRequest::SignStoreUpdate { request_id: 42, store_verifying_key: store, payload: closure })
        .await
    {
        HarvestDelegateResponse::StoreUpdateSigned { result, .. } => result.map(|_| ()),
        other => panic!("SignStoreUpdate: {other:?}"),
    };
    (registered, subkeys, signed)
}

async fn seed_store(url: &str, wasm: &[u8], out: &str) {
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    let store = match node
        .harvest(
            &key,
            HarvestDelegateRequest::CreateStoreKey { request_id: 40, ghostkey_fingerprint: Some(STORE_FP.into()), another_store: false },
        )
        .await
    {
        HarvestDelegateResponse::StoreKeyCreated { result: Ok(store), .. } => store,
        other => panic!("CreateStoreKey: {other:?}"),
    };
    node.harvest(
        &key,
        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint: STORE_FP.into(),
            store_contract_id: vec![0x61; 32],
            reputation_contract_id: vec![0x62; 32],
            mailbox_contract_id: vec![0x63; 32],
            store_verifying_key: Some(store),
        },
    )
    .await;
    let (registered, subkeys, signed) = store_key_report(&mut node, &key, store).await;
    println!("seeded store key {} in {key}: registered={registered} subkeys={subkeys:?} sign={signed:?}", hex::encode(store));
    assert!(registered && subkeys.is_ok() && signed.is_ok(), "the seeding generation must hold and use its own key");
    let (scoped_payload, signature) = wrap_signature(store);
    let copy = match node
        .harvest(
            &key,
            HarvestDelegateRequest::WrapStoreKeyFor {
                request_id: 43,
                store_verifying_key: store,
                backer_verifying_key: backer().verifying_key().to_bytes(),
                scoped_payload,
                signature: harvest_common::delegate::WrapSignature(signature),
            },
        )
        .await
    {
        HarvestDelegateResponse::StoreKeyWrapped { result: Ok(copy), .. } => *copy,
        other => panic!("WrapStoreKeyFor: {other:?}"),
    };
    println!("wrapped the store key to the stand-in backer {}", hex::encode(backer().verifying_key().to_bytes()));
    std::fs::write(out, serde_json::to_vec_pretty(&SeededStore { store_verifying_key: store, copy }).unwrap()).unwrap();
}

async fn check_store(url: &str, wasm: &[u8], seeded: &str) {
    let seeded: SeededStore = serde_json::from_slice(&std::fs::read(seeded).unwrap()).unwrap();
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    let (registered, subkeys, signed) = store_key_report(&mut node, &key, seeded.store_verifying_key).await;
    println!("successor {key}: registration naming the store key: {registered}");
    println!("successor {key}: GetStoreSubkeys: {subkeys:?}");
    println!("successor {key}: SignStoreUpdate: {signed:?}");
    match (registered, subkeys.is_ok(), signed.is_ok()) {
        (true, false, false) => println!("F1 STATE: the registration came across and the key did not; the delegate cannot sign for this store"),
        (true, true, true) => println!("KEY HELD: the successor signs for the store"),
        other => println!("OTHER: {other:?}"),
    }
}

/// Recover the store key into `wasm`'s delegate from the seeded custody copy,
/// exactly as the UI's `CustodyPurpose::Recover` does, then check it signs.
async fn recover_store(url: &str, wasm: &[u8], seeded: &str) {
    let seeded: SeededStore = serde_json::from_slice(&std::fs::read(seeded).unwrap()).unwrap();
    let store = seeded.store_verifying_key;
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    let (scoped_payload, signature) = wrap_signature(store);
    match node
        .harvest(
            &key,
            HarvestDelegateRequest::UnwrapStoreKey {
                request_id: 44,
                store_verifying_key: store,
                backer_verifying_key: backer().verifying_key().to_bytes(),
                scoped_payload,
                signature: harvest_common::delegate::WrapSignature(signature),
                wrapped: seeded.copy.copy.wrapped.clone(),
            },
        )
        .await
    {
        HarvestDelegateResponse::StoreKeyRecovered { result, .. } => println!("UnwrapStoreKey: {result:?}"),
        other => panic!("UnwrapStoreKey: {other:?}"),
    }
    let (registered, subkeys, signed) = store_key_report(&mut node, &key, store).await;
    println!("after recovery: registered={registered} subkeys={subkeys:?} sign={signed:?}");
    if subkeys.is_ok() && signed.is_ok() {
        println!("RECOVERED: the successor signs for the store again");
    } else {
        println!("NOT RECOVERED");
        std::process::exit(1);
    }
}

async fn seed_convo(url: &str, wasm: &[u8], earlier_code_hash_hex: &str, out_dir: &str) {
    let vk = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]).verifying_key();
    let params = harvest_common::store::StoreParameters::new(vk);
    let params_bytes = harvest_common::to_cbor(&params).unwrap();
    let earlier_hash: [u8; 32] = hex::decode(earlier_code_hash_hex).unwrap().try_into().unwrap();
    let earlier = freenet_migrate::contract_id_from_code_hash(&earlier_hash, &Parameters::from(params_bytes.clone()));
    let mut node = Node::connect(url).await;
    let key = node.register(wasm).await;
    node.harvest(
        &key,
        HarvestDelegateRequest::StoreBuyerConversation {
            request_id: 50,
            store_contract_id: earlier.as_bytes().to_vec(),
            secret: ConversationSecret([0x66; 32]),
            seller_public_key: [0x67; 32],
            conversation_id: [0x68; 32],
            created_at: 1_700_000_100,
        },
    )
    .await;
    let kept = match node
        .harvest(&key, HarvestDelegateRequest::ListBuyerConversations { request_id: 51, store_contract_id: earlier.as_bytes().to_vec() })
        .await
    {
        HarvestDelegateResponse::BuyerConversationList { conversations, .. } => conversations,
        other => panic!("ListBuyerConversations: {other:?}"),
    };
    assert_eq!(kept.len(), 1, "the conversation is kept under the earlier id");
    std::fs::create_dir_all(out_dir).unwrap();
    std::fs::write(format!("{out_dir}/store.parameters"), &params_bytes).unwrap();
    std::fs::write(
        format!("{out_dir}/store.state"),
        harvest_common::to_cbor(&harvest_common::store::StoreStateV1::default()).unwrap(),
    )
    .unwrap();
    std::fs::write(format!("{out_dir}/store.code"), params.code()).unwrap();
    println!(
        "kept conversation {} under the earlier store id {earlier}; store code {}",
        hex::encode(kept[0].buyer_public_key),
        params.code()
    );
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seed") => seed(&args[2], &std::fs::read(&args[3]).unwrap(), &args[4]).await,
        Some("touch") => touch(&args[2], &std::fs::read(&args[3]).unwrap()).await,
        Some("check") => check(&args[2], &std::fs::read(&args[3]).unwrap(), &args[4], &args[5]).await,
        Some("seed-store") => seed_store(&args[2], &std::fs::read(&args[3]).unwrap(), &args[4]).await,
        Some("check-store") => check_store(&args[2], &std::fs::read(&args[3]).unwrap(), &args[4]).await,
        Some("recover-store") => recover_store(&args[2], &std::fs::read(&args[3]).unwrap(), &args[4]).await,
        Some("seed-convo") => seed_convo(&args[2], &std::fs::read(&args[3]).unwrap(), &args[4], &args[5]).await,
        _ => {
            eprintln!("usage: delegate seed|touch|check ... (see the module docs)");
            std::process::exit(2);
        }
    }
}
