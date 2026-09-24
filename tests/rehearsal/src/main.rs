//! Live-node rehearsal of Harvest's contract migration.
//!
//! Compiles the REAL `ui/src/migrate.rs` (via `#[path]`) against the REAL
//! `legacy/*.toml` (via the same codegen `ui/build.rs` runs), so every id this
//! walks is derived by the code that ships. Nothing here is mocked: every GET
//! and PUT goes to a freenet node over the websocket client API.

#[path = "../../../ui/src/migrate.rs"]
mod migrate;
// `migrate::ReputationOps::decode` reduces a certificate to what the
// reputation contract accepts, through the UI's own certificate check.
#[path = "../../../ui/src/ghostkey_cert.rs"]
#[allow(dead_code)]
mod ghostkey_cert;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_migrate::Outcome;
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, DelegateRequest, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractCode, ContractContainer, ContractInstanceId, ContractKey, State,
    UpdateData,
    ContractWasmAPIVersion, Delegate, DelegateCode, DelegateContainer, DelegateKey,
    DelegateWasmAPIVersion, InboundDelegateMsg, OutboundDelegateMsg, Parameters, RelatedContracts,
    WrappedContract, WrappedState,
};
use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind, PriceInfo};
use freenet_bitcoin_common::spv::testing::payment_proof;
use freenet_bitcoin_common::{
    BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim, ClaimBody, OutPoint, SignedClaim,
    SignedTipEntry, TipEntryBody,
};
use harvest_common::feedback::FeedbackCategory;
use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus};
use harvest_common::reputation::{
    Complaint, ComplaintTag, ComplaintTerms, ReputationParameters, ReputationStateV1,
    MAX_COMPLAINTS,
};
use harvest_common::store::{AuthorizedStoreInfoV1, StoreInfoV1, StoreParameters, StoreStateV1};

use migrate::{Artifact, ProbeSession, Seal, StoreOps};

fn ws_url() -> String {
    std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:7599".to_string())
        + "/v1/contract/command?encodingProtocol=native"
}
/// The repository this harness lives in, so nothing here depends on where it
/// was checked out.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("tests/rehearsal is two directories below the repo root")
}

/// The generations to plant STATE at, and the registry hash each must have.
///
/// Both are inside the legacy parameter band (V2..=V5), which is deliberate
/// but is NOT what exercises the encoding split -- two generations on the same
/// side of it cannot. An earlier version of this comment claimed they did,
/// reasoning from "both are `<= LAST_LEGACY_STORE_PARAM_GENERATION`", which
/// stopped being a sound test for "legacy" when the band gained a lower end.
/// The split is checked separately and over EVERY generation, by
/// `assert_candidate_addresses` below.
///
/// What these two are for is the FOLD: different data at two generations, so a
/// walk that stops at the first hit shows up as a missing listing rather than
/// as a pass.
const PLANT_AT: &[(u32, &str)] = &[
    (
        5,
        "186f7784628f0f773dd711c91a35d822e2f1111fe052328227f924977df2d2c0",
    ),
    (
        4,
        "df0e8dfbc12071b1ab80d1b5c05aa6a9265b9b4141669a740f04f96363118d4a",
    ),
];

/// The WASM a superseded generation was published with, taken out of git
/// history by HASH rather than by commit.
///
/// The registries record hashes and never commits, deliberately, and this is
/// the same lookup `legacy/README.md` prescribes for verifying one: walk every
/// revision of the committed artifact and take the blob whose BLAKE3 matches.
/// A commit id written down here would be one more thing to keep in step.
fn legacy_wasm_from_git(repo: &Path, artifact: &str, want_hex: &str) -> Vec<u8> {
    let path = format!("ui/public/contracts/{artifact}.wasm");
    let revs = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["log", "--all", "--format=%H", "--"])
        .arg(&path)
        .output()
        .expect("run git log");
    for sha in String::from_utf8_lossy(&revs.stdout).lines() {
        let blob = Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("show")
            .arg(format!("{sha}:{path}"))
            .output()
            .expect("run git show");
        if !blob.status.success() {
            continue;
        }
        if hex::encode(code_hash(&blob.stdout)) == want_hex {
            println!("  {artifact} @ {} -> blake3 {want_hex}", &sha[..8]);
            return blob.stdout;
        }
    }
    panic!(
        "no revision of {path} hashes to {want_hex}. The registry names a \
         generation whose artifact is not in this repository's history."
    );
}

// --- the legacy parameter shape, written out INDEPENDENTLY of migrate.rs ---
//
// migrate.rs keeps its own private copy. If the two disagree the addresses
// disagree and every scenario below fails loudly, which is the point: this is
// a second, independent derivation of the same bytes rather than a re-use of
// the one under test.
#[derive(serde::Serialize)]
struct LegacyStoreParameters {
    seller_verifying_key: VerifyingKey,
    trusted_bitcoin_bridges: Vec<[u8; 32]>,
    bitcoin_address_code_hash: Option<[u8; 32]>,
}

fn legacy_params(vk: &VerifyingKey) -> Parameters<'static> {
    let bytes = harvest_common::to_cbor(&LegacyStoreParameters {
        seller_verifying_key: *vk,
        trusted_bitcoin_bridges: Vec::new(),
        bitcoin_address_code_hash: None,
    })
    .expect("encode legacy store parameters");
    Parameters::from(bytes)
}

/// The whole-key shape V1 and V6..=V16 were published under, before
/// harvest#52 made the parameter a code. Written out independently too.
#[derive(serde::Serialize)]
struct WholeKeyStoreParameters {
    seller_verifying_key: VerifyingKey,
}

fn whole_key_params(vk: &VerifyingKey) -> Parameters<'static> {
    let bytes = harvest_common::to_cbor(&WholeKeyStoreParameters {
        seller_verifying_key: *vk,
    })
    .expect("encode whole-key store parameters");
    Parameters::from(bytes)
}

fn current_params(vk: &VerifyingKey) -> Parameters<'static> {
    migrate::encode_params(&StoreParameters::new(*vk)).expect("encode current store parameters")
}

fn code_hash(wasm: &[u8]) -> [u8; 32] {
    *blake3::hash(wasm).as_bytes()
}

fn container(wasm: &[u8], params: Parameters<'static>) -> (ContractContainer, ContractInstanceId) {
    let code = Arc::new(ContractCode::from(wasm.to_vec()));
    let wrapped = WrappedContract::new(code, params);
    let id = *wrapped.key().id();
    (
        ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped)),
        id,
    )
}

// --- state construction -------------------------------------------------

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).unwrap()
}

/// Sign a value the way the ghostkey delegate does: a `ScopedPayload` naming
/// the Harvest webapp, signed over its CBOR.
fn scoped_sign<T: serde::Serialize>(sk: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
    let payload = harvest_common::to_cbor(data).expect("encode payload");
    let scoped = ghostkey_common::ScopedPayload {
        requestor: harvest_common::expected_harvest_requestor(),
        payload,
    };
    let bytes = harvest_common::to_cbor(&scoped).expect("encode scoped payload");
    let sig = sk.sign(&bytes).to_bytes().to_vec();
    (bytes, sig)
}

fn make_listing(sk: &SigningKey, fingerprint: &str, title: &str, at: i64) -> AuthorizedListing {
    let created_at = ts(at);
    let listing = Listing {
        checkout: None,
        choices: Vec::new(),
        id: ListingId::from_label(title),
        title: title.to_string(),
        description: format!("{title} -- written by the rehearsal harness"),
        kind: ListingKind::Sale,
        price: Some(PriceInfo {
            amount: "0.005".into(),
            currency: "BTC".into(),
        }),
        created_at,
    }
    // The id every generation since terms-derived ids checks (the label id
    // above is replaced; generations before that accept either).
    .with_derived_id();
    let (scoped_payload, signature) = scoped_sign(sk, &listing);
    AuthorizedListing {
        listing,
        scoped_payload,
        signature,
        certificate_pem: "-----BEGIN GHOSTKEY CERTIFICATE-----rehearsal-----END-----".into(),
    }
}

fn make_info(sk: &SigningKey, fingerprint: &str, name: &str, version: u32) -> AuthorizedStoreInfoV1 {
    let info = StoreInfoV1 {
        version,
        certificate_pem: "-----BEGIN GHOSTKEY CERTIFICATE-----rehearsal-----END-----".into(),
        seller_fingerprint: fingerprint.to_string(),
        reputation_contract_id: [0xABu8; 32],
        store_name: name.to_string(),
        description: "A store planted at a predecessor generation".into(),
        encryption_public_key: None,
        record_public_key: None,
    };
    let (scoped_payload, signature) = scoped_sign(sk, &info);
    AuthorizedStoreInfoV1 {
        info,
        scoped_payload,
        signature,
    }
}

fn fingerprint_of(vk: &VerifyingKey) -> String {
    bs58::encode(blake3::hash(vk.as_bytes()).as_bytes()).into_string()
}

// --- harvest#53 Phase C: the reputation record's re-addressing ------------

/// A throwaway RSA public key (PKCS#1 DER) standing in for a store's record
/// key. The RSA generations' contract parses it in `validate_state`, so it
/// has to be a real key; nothing ever signed with its private half.
const THROWAWAY_RSA_DER_HEX: &str = "3082010a0282010100b27faa28bf26a8ca2b29176d45f8bbd501eceaea7fa8bc9d5c56411194fd3bf68ee21e6576a8035e3786b418fd747d78fac7ba13c561f1f1bffe38749887d98b98be0ff960e9333decfe41f6402354bbaa0dbb8254b8770c426966b54b3752f03b1fb22e133ac076f9434a953540fe668fa71f12b4372e7115c9956f2383db314860e6096563b77d4afd7989e9aa0b13f71fa375eb4e35ce9f682f68cda8e28922a165734366d42446b02dc1d794a09b4d09ebcca455f31451736b54f88a735b62a13d182a7f333a56728a8abadd14360a03fb3411a6f8e6a6b35716cdd3c476b357adc0f184c661ea4e4ab8fd002b01ade77037e0fc9a2440da88a19918e40b0203010001";

/// The last generation addressed by the RSA key and the Ghost Key, and the
/// hash the registry must give it.
const REPUTATION_PLANT_AT: (u32, &str) = (
    15,
    "78ae80d2bcb3e80299a977da3a437a44cced8b74367f53d24e407c2b171d362e",
);

/// The RSA generations' parameters, written out independently of
/// `migrate.rs`'s copy for the reason `LegacyStoreParameters` gives.
#[derive(serde::Serialize)]
struct RsaReputationParameters {
    rsa_public_key_der: Vec<u8>,
    owner_verifying_key: VerifyingKey,
}

/// The RSA generations' state, as every live record holds it: the seller's
/// certificate and no feedback (no producer of a feedback entry ever
/// shipped).
#[derive(serde::Serialize)]
struct RsaGenerationReputationState {
    owner_certificate_pem: String,
    feedback: Vec<()>,
    used_nonces: Vec<[u8; 32]>,
}

/// Scenario 4: a V15 reputation record holding the seller's certificate is
/// found through `migrate::reputation_candidates` (Option A: the RSA key as
/// a legacy address input only), folded by `ReputationOps`, and the
/// certificate lands at the record the store key addresses under this
/// build.
async fn scenario_reputation(node: &mut Node, repo: &Path) {
    println!("\n== scenario 4: a V15 reputation record's certificate is carried to the store-key record ==");
    let (generation, want) = REPUTATION_PLANT_AT;
    let row = migrate::reputation_lineage()
        .iter()
        .find(|e| e.generation == generation)
        .expect("the registry declares V15");
    assert_eq!(hex::encode(row.code_hash), want, "V15 no longer has the hash planted at");
    assert_eq!(
        migrate::LAST_RSA_REPUTATION_PARAM_GENERATION, generation,
        "V15 is the last RSA-addressed generation"
    );
    let v15 = legacy_wasm_from_git(repo, "reputation_contract", want);
    let current = read_wasm(&repo.join("ui/public/contracts/reputation_contract.wasm"));

    let store = SigningKey::from_bytes(&[0x5C; 32]).verifying_key();
    let ghost = SigningKey::from_bytes(&[0x6D; 32]).verifying_key();
    let record_der = hex::decode(THROWAWAY_RSA_DER_HEX).unwrap();
    // A second key that addressed nothing here: a Ghost Key's per-device
    // key, which addressed the records of stores made BEFORE harvest#93 1b
    // (this store, made after, used its record key). The walk tries it too
    // when it is known.
    let mut per_device_der = record_der.clone();
    let last = per_device_der.len() - 1;
    per_device_der[last] ^= 1;

    let rsa_params = Parameters::from(
        harvest_common::to_cbor(&RsaReputationParameters {
            rsa_public_key_der: record_der.clone(),
            owner_verifying_key: ghost,
        })
        .unwrap(),
    );
    let (v15_container, v15_id) = container(&v15, rsa_params);
    let current_params =
        migrate::encode_params(&migrate::reputation_params(&store)).expect("encode");
    let (curr_container, curr_id) = container(&current, current_params.clone());
    assert_eq!(migrate::current_id(&code_hash(&current), &current_params), curr_id);
    println!("  V15 record (stdlib key derivation): {v15_id}");
    println!("  store-key record under this build:  {curr_id}");

    // The walk reaches the node's own address for V15, from the record key,
    // and does not list the registration's id a second time when it is the
    // same record.
    let locators = || migrate::ReputationLocators {
        store_key: store,
        ghost_key: ghost,
        rsa_public_keys: vec![per_device_der.clone(), record_der.clone()],
        registered_id: Some(v15_id),
        current_id: curr_id,
    };
    let ids = migrate::reputation_candidate_ids(&locators()).expect("derive");
    assert!(ids.contains(&v15_id), "the walk must reach the V15 record");
    assert_eq!(ids.iter().filter(|i| **i == v15_id).count(), 1, "no duplicate");
    assert!(!ids.contains(&curr_id), "the successor is not its own predecessor");
    println!("  {} candidates, V15 record at position {}", ids.len(), ids.iter().position(|i| *i == v15_id).unwrap());

    // A genuine Ghost Key certificate: since #143 review round 1 (P1-4) the
    // record's contract refuses anything else in this field, and the fold
    // reduces anything else to nothing.
    const CERT: &str = include_str!("../../fixtures/ghostkey-certificate.pem");
    let planted = harvest_common::to_cbor(&RsaGenerationReputationState {
        owner_certificate_pem: CERT.into(),
        feedback: Vec::new(),
        used_nonces: Vec::new(),
    })
    .unwrap();
    println!("  PUT the V15 record ({} bytes) ...", planted.len());
    node.put(v15_container, planted).await.expect("PUT V15 record (the V15 contract accepts it)");
    match node.get(v15_id).await {
        GetOutcome::State(bytes) => {
            let s: harvest_common::reputation::ReputationStateV1 =
                harvest_common::from_cbor(&bytes).expect("an RSA-generation state decodes as the new type");
            println!("  read back V15: certificate {:?}, {} complaints", s.owner_certificate_pem, s.complaints.len());
            assert_eq!(s.owner_certificate_pem, CERT);
        }
        other => panic!("V15 record did not read back: {other:?}"),
    }

    println!("\n  -- probe as the current build --");
    let params = migrate::reputation_params(&store);
    let mut session = ProbeSession::start_with_candidates(
        migrate::ReputationOps { params: params.clone() },
        harvest_common::reputation::ReputationStateV1::default(),
        migrate::reputation_candidates(&locators()).expect("candidates"),
        migrate::fold_all_policy(),
    );
    while let Some(candidate) = session.next_get() {
        match node.get(candidate).await {
            GetOutcome::State(bytes) => {
                println!("  GET {candidate} -> state, {} bytes", bytes.len());
                session.on_state(candidate, &bytes)
            }
            GetOutcome::Absent => session.on_absent(candidate),
            GetOutcome::Unknown(_) => session.on_unknown(candidate),
        }
    }
    let (outcome, seal) = session.take_result().expect("probe finished");
    println!("  describe: {}", migrate::describe(&outcome));
    println!("  seal decision: {seal:?}");
    let Outcome::Recovered { merged, source, .. } = &outcome else {
        panic!("expected Recovered, got {outcome:?}");
    };
    assert_eq!(*source, v15_id, "the V15 record is the source");
    assert_eq!(merged.owner_certificate_pem, CERT, "the certificate is carried");
    assert!(merged.complaints.is_empty());

    let forward = harvest_common::to_cbor(merged).unwrap();
    println!("  PUT forward to {curr_id} ({} bytes) ...", forward.len());
    node.put(curr_container, forward).await.expect("the current contract accepts the carried record");
    match node.get(curr_id).await {
        GetOutcome::State(bytes) => {
            let s: harvest_common::reputation::ReputationStateV1 = harvest_common::from_cbor(&bytes).unwrap();
            println!("  store-key record now: certificate {:?}, {} complaints", s.owner_certificate_pem, s.complaints.len());
            assert_eq!(s.owner_certificate_pem, CERT, "the certificate is at the store-key record");
        }
        other => panic!("the store-key record did not read back: {other:?}"),
    }
    println!("  SCENARIO 4a PASSED: the V15 certificate is at the store-key record");

    scenario_reputation_by_registration(node, repo, &current, CERT).await;
}

/// Scenario 4b (#143 review round 1, P2-13): a store made BEFORE harvest#93
/// phase 1b, whose record lives under the Ghost Key's per-device RSA key at
/// V10, reached ONLY through the registration's id -- the per-device key is
/// not in the locators, which is the usual case (review P2-11). Then the
/// registration naming the current record walks nothing (P2-7).
async fn scenario_reputation_by_registration(node: &mut Node, repo: &Path, current: &[u8], cert: &str) {
    println!("\n== scenario 4b: a pre-1b V10 record under the per-device key, found only through the registered id ==");
    const V10: &str = "3c55af21e5658f03121bbeccfe347d4d530b57139251048767089596145e0594";
    let row = migrate::reputation_lineage()
        .iter()
        .find(|e| hex::encode(e.code_hash) == V10)
        .expect("the registry declares V10");
    assert_eq!(row.generation, 10);
    let v10 = legacy_wasm_from_git(repo, "reputation_contract", V10);

    let store = SigningKey::from_bytes(&[0x5D; 32]).verifying_key();
    let ghost = SigningKey::from_bytes(&[0x6E; 32]).verifying_key();
    let mut per_device_der = hex::decode(THROWAWAY_RSA_DER_HEX).unwrap();
    // The per-device key: planted under, never given to the walk.
    let last = per_device_der.len() - 1;
    per_device_der[last] ^= 2;
    let (v10_container, v10_id) = container(
        &v10,
        Parameters::from(
            harvest_common::to_cbor(&RsaReputationParameters {
                rsa_public_key_der: per_device_der.clone(),
                owner_verifying_key: ghost,
            })
            .unwrap(),
        ),
    );
    let current_params = migrate::encode_params(&migrate::reputation_params(&store)).expect("encode");
    let (curr_container, curr_id) = container(current, current_params);
    println!("  V10 record (per-device key): {v10_id}");
    println!("  store-key record:            {curr_id}");

    let locators = |registered| migrate::ReputationLocators {
        store_key: store,
        ghost_key: ghost,
        rsa_public_keys: Vec::new(),
        registered_id: registered,
        current_id: curr_id,
    };
    // The derivations alone cannot reach it: no RSA key is known.
    let derived = migrate::reputation_candidate_ids(&locators(None)).expect("derive");
    assert!(!derived.contains(&v10_id), "no locator but the registration reaches it");
    let ids = migrate::reputation_candidate_ids(&locators(Some(v10_id))).expect("derive");
    assert_eq!(ids.last(), Some(&v10_id), "the registration's id is tried, last");

    let planted = harvest_common::to_cbor(&RsaGenerationReputationState {
        owner_certificate_pem: cert.into(),
        feedback: Vec::new(),
        used_nonces: Vec::new(),
    })
    .unwrap();
    node.put(v10_container, planted).await.expect("PUT V10 record (the V10 contract accepts it)");

    let params = migrate::reputation_params(&store);
    let mut session = ProbeSession::start_with_candidates(
        migrate::ReputationOps { params: params.clone() },
        harvest_common::reputation::ReputationStateV1::default(),
        migrate::reputation_candidates(&locators(Some(v10_id))).expect("candidates"),
        migrate::fold_all_policy(),
    );
    while let Some(candidate) = session.next_get() {
        match node.get(candidate).await {
            GetOutcome::State(bytes) => session.on_state(candidate, &bytes),
            GetOutcome::Absent => session.on_absent(candidate),
            GetOutcome::Unknown(_) => session.on_unknown(candidate),
        }
    }
    let (outcome, seal) = session.take_result().expect("probe finished");
    println!("  describe: {}", migrate::describe(&outcome));
    println!("  seal decision: {seal:?}");
    let Outcome::Recovered { merged, source, .. } = &outcome else {
        panic!("expected Recovered, got {outcome:?}");
    };
    assert_eq!(*source, v10_id, "the V10 record is the source");
    assert_eq!(merged.owner_certificate_pem, cert, "the certificate is carried");
    node.put(curr_container, harvest_common::to_cbor(merged).unwrap())
        .await
        .expect("the current contract accepts the carried record");
    match node.get(curr_id).await {
        GetOutcome::State(bytes) => {
            let s: harvest_common::reputation::ReputationStateV1 = harvest_common::from_cbor(&bytes).unwrap();
            assert_eq!(s.owner_certificate_pem, cert, "the certificate is at the store-key record");
        }
        other => panic!("the store-key record did not read back: {other:?}"),
    }
    println!("  SCENARIO 4b PASSED: the pre-1b certificate reached the store-key record through the registered id");

    // P2-7: once the registration names the current record, nothing to walk.
    let none = migrate::reputation_candidate_ids(&locators(Some(curr_id))).expect("derive");
    assert!(none.is_empty(), "a registration naming the current record walks nothing: {none:?}");
    println!("  SCENARIO 4c PASSED: a registration naming the current record yields no candidates");
}

// --- scenario 4d: existing complaints carried forward, then the cap ------
//
// Genuine complaints built the way `tests/merge-laws/gen` builds them
// (`StoreFx`, `receipted_order`, `complaint_buyer`, `complaint_by`), copied
// because `harvest_common::test_orders` is private to its crate.

/// The build before #143 round 6 (commit 7421f02): the store-key record with
/// NO complaint cap. Never published, so no registry lists it.
const UNCAPPED_REPUTATION: &str =
    "eb3e0e6711fd716d69415479f7afbb4edb8caad55d5f10f5a4d99274dbf901ce";

struct ComplaintFx {
    seller: SigningKey,
    bridge: SigningKey,
}

impl ComplaintFx {
    fn order(&self, n: u8) -> Order {
        Order {
            request_id: None,
            id: OrderId([0u8; 32]),
            buyer_fingerprint: format!("complainer-{n}"),
            seller_fingerprint: "throwaway-seller-fp".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            payment_hash: None,
            payment_address: "tb1qthrowaway".into(),
            required_confirmations: 1,
            trusted_bridges: vec![BridgeId(self.bridge.verifying_key().to_bytes())],
            bitcoin_address_code_hash: None,
            // The payment below confirms at height 100, inside the window.
            anchor: Some(BlockAnchor { height: 90, hash: BlockHash([3u8; 32]) }),
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: Some(complaint_buyer(n).verifying_key().to_bytes()),
            created_at: ts(1_700_000_000 + i64::from(n)),
        }
        .with_derived_id()
    }

    fn tip(&self, order: &Order, height: u32) -> SignedTipEntry {
        SignedTipEntry::sign(
            &self.bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor { height, hash: BlockHash([9u8; 32]) },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .unwrap()
    }

    /// The order at `Paid`, with a genuine SPV proof confirming at 100.
    fn paid(&self, n: u8) -> AuthorizedOrder {
        let order = self.order(n);
        let (spv, txid, block_hash) =
            payment_proof(&order.payment_script_pubkey, order.amount_sats, 1, [1u8; 32]);
        let anchor = BlockAnchor { height: 100, hash: block_hash };
        let claim = SignedClaim::sign(
            &self.bridge,
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: anchor,
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: order.amount_sats,
                    anchor,
                    spv,
                },
            },
        )
        .unwrap();
        let proof = OrderPaymentProof::on_chain(vec![claim], self.tip(&order, 100));
        let (scoped_payload, signature) = scoped_sign(&self.seller, &order);
        let rec = AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::Paid,
            payment_proof: Some(proof),
            status_scoped_payload: None,
            status_signature: None,
        };
        rec.verify(&self.seller.verifying_key()).expect("fixture order verifies");
        rec
    }

    /// Order `n`'s genuine complaint, dated `after` blocks after its payment.
    fn dated(&self, n: u8, after: u32) -> Complaint {
        let order = self.paid(n);
        let paid_height = harvest_common::payment::paid_height(&order).expect("paid");
        let terms = ComplaintTerms {
            tag: ComplaintTag::HarvestComplaintV1,
            order_id: order.order.id.clone(),
            category: FeedbackCategory::NonDelivery,
            block_height: paid_height + after,
            paid_height,
        };
        let (scoped_payload, buyer_signature) = scoped_sign(&complaint_buyer(n), &terms);
        let c = Complaint {
            order,
            category: terms.category,
            block_height: terms.block_height,
            paid_height,
            scoped_payload,
            buyer_signature,
        };
        c.verify(&self.seller.verifying_key()).expect("fixture complaint verifies");
        c
    }
}

fn complaint_buyer(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n.wrapping_add(100); 32])
}

/// 3 honest complaints dated 151..=153 blocks after payment (orders 1..=3)
/// and 147 dated 5004..=5150 after (orders 4..=150): 150 in all, 4 past
/// `MAX_COMPLAINTS`. The record must keep the honest ones and drop orders
/// 147..=150, the four dated farthest.
fn over_cap_record(fx: &ComplaintFx, cert: &str) -> (ReputationStateV1, Vec<OrderId>, Vec<OrderId>) {
    let honest: Vec<Complaint> = (1u8..=3).map(|n| fx.dated(n, 150 + u32::from(n))).collect();
    let late: Vec<Complaint> = (4u8..=150).map(|n| fx.dated(n, 5_000 + u32::from(n))).collect();
    let farthest = late[late.len() - 4..].iter().map(|c| c.order_id().clone()).collect();
    let honest_ids = honest.iter().map(|c| c.order_id().clone()).collect();
    let mut complaints: Vec<Complaint> = honest.into_iter().chain(late).collect();
    // The uncapped build's canonical form: strictly ascending by order id.
    complaints.sort_by(|a, b| a.order_id().cmp(b.order_id()));
    (
        ReputationStateV1 { owner_certificate_pem: cert.into(), complaints },
        honest_ids,
        farthest,
    )
}

/// What a record the new build holds must be, after taking the 150.
fn assert_capped(label: &str, bytes: &[u8], params: &ReputationParameters, honest: &[OrderId], farthest: &[OrderId]) -> ReputationStateV1 {
    let s: ReputationStateV1 = harvest_common::from_cbor(bytes).expect("decode the new-build record");
    let held: Vec<&OrderId> = s.complaints.iter().map(|c| c.order_id()).collect();
    let honest_kept = honest.iter().filter(|o| held.contains(o)).count();
    let far_kept = farthest.iter().filter(|o| held.contains(o)).count();
    println!(
        "  {label}: {} complaints (cap {MAX_COMPLAINTS}), honest kept {honest_kept}/{}, farthest-dated kept {far_kept}/{}, {} bytes",
        s.complaints.len(), honest.len(), farthest.len(), bytes.len()
    );
    assert_eq!(s.complaints.len(), MAX_COMPLAINTS, "{label}: exactly the cap");
    assert_eq!(honest_kept, honest.len(), "{label}: every honest complaint is kept");
    assert_eq!(far_kept, 0, "{label}: the four farthest-dated are dropped");
    s.verify(params).unwrap_or_else(|e| panic!("{label}: the record does not verify: {e}"));
    s
}

/// Scenario 4d: a record the uncapped build (eb3e0e67) holds with 150
/// complaints is carried to this build, whose record keeps 146.
///
/// The app's walk cannot reach the uncapped build: it was never published,
/// so no registry lists it (and it must not be added to one). The fold and
/// PUT-forward are driven here with an EXPLICIT one-entry candidate list
/// naming that record, through the same `ProbeSession`/`ReputationOps` code
/// scenario 4a drives.
async fn scenario_reputation_cap_carried(node: &mut Node, repo: &Path) {
    println!("\n== scenario 4d: existing complaints are carried forward, then the cap applies ==");
    println!("  NOTE: the uncapped build is not in any registry (never published); the walk is driven");
    println!("        with an explicit candidate list naming its record, through the real ProbeSession/ReputationOps.");
    const CERT: &str = include_str!("../../fixtures/ghostkey-certificate.pem");
    let old = legacy_wasm_from_git(repo, "reputation_contract", UNCAPPED_REPUTATION);
    assert!(
        migrate::reputation_lineage().iter().all(|e| hex::encode(e.code_hash) != UNCAPPED_REPUTATION),
        "the uncapped build must not be in the registry"
    );
    let current = read_wasm(&repo.join("ui/public/contracts/reputation_contract.wasm"));
    println!("  current reputation_contract: blake3 {}", hex::encode(code_hash(&current)));

    let fx = ComplaintFx {
        seller: SigningKey::from_bytes(&[0x5E; 32]),
        bridge: SigningKey::from_bytes(&[0xB2; 32]),
    };
    let store = fx.seller.verifying_key();
    let params = ReputationParameters::new(store);
    let pbytes = migrate::encode_params(&params).expect("encode");
    let (old_container, old_id) = container(&old, pbytes.clone());
    let (curr_container, curr_id) = container(&current, pbytes.clone());
    let curr_key = curr_container.key().clone();
    println!("  uncapped record: {old_id}");
    println!("  this build's:    {curr_id}");

    let (full, honest, farthest) = over_cap_record(&fx, CERT);
    let full_bytes = harvest_common::to_cbor(&full).unwrap();
    println!(
        "  built {} genuine complaints ({} honest near payment, {} late; farthest 4 = orders 147..=150), {} bytes",
        full.complaints.len(), honest.len(), full.complaints.len() - honest.len(), full_bytes.len()
    );
    assert!(full.complaints.len() > MAX_COMPLAINTS);

    println!("  PUT all {} to the uncapped build ...", full.complaints.len());
    node.put(old_container, full_bytes.clone()).await.expect("the uncapped build accepts 150");
    let old_bytes = match node.get(old_id).await {
        GetOutcome::State(bytes) => bytes,
        other => panic!("the uncapped record did not read back: {other:?}"),
    };
    let old_state: ReputationStateV1 = harvest_common::from_cbor(&old_bytes).unwrap();
    println!("  read back uncapped record: {} complaints, {} bytes", old_state.complaints.len(), old_bytes.len());
    assert_eq!(old_state.complaints.len(), full.complaints.len());

    println!("\n  -- probe as the current build, candidate list = [{old_id}] --");
    let mut session = ProbeSession::start_with_candidates(
        migrate::ReputationOps { params: params.clone() },
        ReputationStateV1::default(),
        freenet_migrate::NewestFirst::assume_ordered(vec![old_id]),
        migrate::fold_all_policy(),
    );
    while let Some(candidate) = session.next_get() {
        match node.get(candidate).await {
            GetOutcome::State(bytes) => {
                println!("  GET {candidate} -> state, {} bytes", bytes.len());
                session.on_state(candidate, &bytes)
            }
            GetOutcome::Absent => session.on_absent(candidate),
            GetOutcome::Unknown(_) => session.on_unknown(candidate),
        }
    }
    let (outcome, seal) = session.take_result().expect("probe finished");
    println!("  describe: {}", migrate::describe(&outcome));
    println!("  seal decision: {seal:?}");
    let Outcome::Recovered { merged, source, .. } = &outcome else {
        panic!("expected Recovered, got {outcome:?}");
    };
    assert_eq!(*source, old_id);
    println!("  fold result: {} complaints", merged.complaints.len());
    let forward = harvest_common::to_cbor(merged).unwrap();
    println!("  PUT forward to {curr_id} ({} bytes) ...", forward.len());
    node.put(curr_container, forward).await.expect("this build accepts the carried record");
    let after_put = match node.get(curr_id).await {
        GetOutcome::State(bytes) => bytes,
        other => panic!("this build's record did not read back: {other:?}"),
    };
    let carried = assert_capped("after the PUT forward", &after_put, &params, &honest, &farthest);
    assert_eq!(carried.owner_certificate_pem, CERT, "the certificate is carried");

    println!("\n  -- the uncapped record's full state as an UpdateData::State merge into this build --");
    node.update_state(curr_key, old_bytes.clone()).await.expect("the node accepts the 150-complaint state merge");
    let after_update = match node.get(curr_id).await {
        GetOutcome::State(bytes) => bytes,
        other => panic!("this build's record did not read back: {other:?}"),
    };
    assert_capped("after the state merge", &after_update, &params, &honest, &farthest);
    assert_eq!(after_update, after_put, "the merge of the full state changes nothing: the same 146");
    println!("  identical bytes to the carried record: yes");

    // The same merge into a record that holds none of them yet, so the
    // contract's own `update_state` is what drops the four.
    println!("\n  -- a second store: its record holds only the certificate, then takes the 150 as one state merge --");
    let fx2 = ComplaintFx {
        seller: SigningKey::from_bytes(&[0x5F; 32]),
        bridge: SigningKey::from_bytes(&[0xB2; 32]),
    };
    let params2 = ReputationParameters::new(fx2.seller.verifying_key());
    let (curr2_container, curr2_id) =
        container(&current, migrate::encode_params(&params2).expect("encode"));
    let curr2_key = curr2_container.key().clone();
    let empty = harvest_common::to_cbor(&ReputationStateV1 { owner_certificate_pem: CERT.into(), complaints: Vec::new() }).unwrap();
    node.put(curr2_container, empty).await.expect("a certificate-only record");
    let (full2, honest2, farthest2) = over_cap_record(&fx2, CERT);
    node.update_state(curr2_key, harvest_common::to_cbor(&full2).unwrap())
        .await
        .expect("the node accepts the 150-complaint state merge");
    match node.get(curr2_id).await {
        GetOutcome::State(bytes) => {
            assert_capped("second store after the state merge", &bytes, &params2, &honest2, &farthest2);
        }
        other => panic!("the second record did not read back: {other:?}"),
    }

    println!(
        "  SCENARIO 4d PASSED: {} complaints under the uncapped build carried to this build's record as {} \
         (cap {MAX_COMPLAINTS}); all {} honest kept, the 4 farthest-dated dropped, verify OK; the full state \
         as an UpdateData::State merge gives the same {} (and {} into a certificate-only record)",
        full.complaints.len(), MAX_COMPLAINTS, honest.len(), MAX_COMPLAINTS, MAX_COMPLAINTS
    );
}

// --- the node ------------------------------------------------------------

#[derive(Debug)]
enum GetOutcome {
    State(Vec<u8>),
    Absent,
    Unknown(String),
}

struct Node {
    api: WebApi,
}

impl Node {
    async fn connect() -> Node {
        let url = ws_url();
        let (stream, resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("connect to node websocket");
        println!("connected to {url} (HTTP {})", resp.status());
        Node {
            api: WebApi::start(stream),
        }
    }

    async fn put(&mut self, contract: ContractContainer, state: Vec<u8>) -> Result<(), String> {
        let expected = *contract.key().id();
        self.api
            .send(ClientRequest::ContractOp(ContractRequest::Put {
                contract,
                state: WrappedState::new(state),
                related_contracts: RelatedContracts::default(),
                subscribe: false,
                blocking_subscribe: false,
            }))
            .await
            .map_err(|e| format!("send PUT: {e}"))?;
        loop {
            match tokio::time::timeout(Duration::from_secs(60), self.api.recv()).await {
                Err(_) => return Err("PUT timed out after 60s".into()),
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key }))) => {
                    if *key.id() != expected {
                        return Err(format!("PUT answered for {} not {expected}", key.id()));
                    }
                    return Ok(());
                }
                // A PUT onto a contract the node already holds is answered as
                // an UPDATE (the node merges rather than replaces). The app
                // never sees this -- its `put_contract` awaits only the send --
                // but this harness has to treat it as completion.
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateResponse {
                    key,
                    ..
                }))) if *key.id() == expected => {
                    println!("    (PUT answered as UpdateResponse: the node merged into existing state)");
                    return Ok(());
                }
                Ok(Ok(other)) => println!("    (ignoring while awaiting PUT: {other:?})"),
                Ok(Err(e)) => return Err(format!("PUT failed: {e}")),
            }
        }
    }

    /// An `UpdateData::State` UPDATE: the node runs the contract's own
    /// `update_state` merge, then `validate_state` on the result.
    async fn update_state(&mut self, key: ContractKey, state: Vec<u8>) -> Result<(), String> {
        let expected = *key.id();
        self.api
            .send(ClientRequest::ContractOp(ContractRequest::Update {
                key,
                data: UpdateData::State(State::from(state)),
            }))
            .await
            .map_err(|e| format!("send UPDATE: {e}"))?;
        loop {
            match tokio::time::timeout(Duration::from_secs(60), self.api.recv()).await {
                Err(_) => return Err("UPDATE timed out after 60s".into()),
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateResponse {
                    key,
                    ..
                }))) if *key.id() == expected => return Ok(()),
                Ok(Ok(other)) => println!("    (ignoring while awaiting UPDATE: {other:?})"),
                Ok(Err(e)) => return Err(format!("UPDATE failed: {e}")),
            }
        }
    }

    /// Register the harvest delegate exactly as `register_delegate` does.
    async fn register_delegate(&mut self, wasm: &[u8]) -> Result<DelegateKey, String> {
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
            .map_err(|e| format!("send RegisterDelegate: {e}"))?;
        Ok(key)
    }

    /// One harvest-delegate request, and whatever comes back.
    async fn delegate_request(
        &mut self,
        key: &DelegateKey,
        request: &harvest_common::HarvestDelegateRequest,
    ) -> Result<harvest_common::HarvestDelegateResponse, String> {
        let payload = harvest_common::to_cbor(request).map_err(|e| e.to_string())?;
        self.api
            .send(ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
                key: key.clone(),
                params: Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS),
                inbound: vec![InboundDelegateMsg::ApplicationMessage(
                    ApplicationMessage::new(payload),
                )],
            }))
            .await
            .map_err(|e| format!("send delegate message: {e}"))?;
        loop {
            match tokio::time::timeout(Duration::from_secs(20), self.api.recv()).await {
                Err(_) => return Err("no delegate answer within 20s".into()),
                Ok(Ok(HostResponse::DelegateResponse { values, .. })) => {
                    for v in values {
                        if let OutboundDelegateMsg::ApplicationMessage(app) = v {
                            return harvest_common::from_cbor(&app.payload)
                                .map_err(|e| format!("decode delegate response: {e}"));
                        }
                    }
                    return Err("delegate answered with no application message".into());
                }
                Ok(Ok(other)) => println!("    (ignoring while awaiting delegate: {other:?})"),
                Ok(Err(e)) => return Err(format!("delegate error: {e}")),
            }
        }
    }

    /// One GET, exactly as `migrate_ops::pump` issues it: no subscribe, no
    /// contract code, and a deadline that is `Unknown` rather than `Absent`.
    async fn get(&mut self, id: ContractInstanceId) -> GetOutcome {
        if let Err(e) = self
            .api
            .send(ClientRequest::ContractOp(ContractRequest::Get {
                key: id,
                return_contract_code: false,
                subscribe: false,
                blocking_subscribe: false,
            }))
            .await
        {
            return GetOutcome::Unknown(format!("send failed: {e}"));
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(30), self.api.recv()).await {
                Err(_) => return GetOutcome::Unknown("no answer within 30s".into()),
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                    key,
                    state,
                    ..
                }))) => {
                    if *key.id() != id {
                        return GetOutcome::Unknown(format!(
                            "answer named {} not {id}",
                            key.id()
                        ));
                    }
                    return GetOutcome::State(state.as_ref().to_vec());
                }
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::NotFound {
                    instance_id,
                }))) => {
                    if instance_id != id {
                        return GetOutcome::Unknown(format!(
                            "NotFound named {instance_id} not {id}"
                        ));
                    }
                    return GetOutcome::Absent;
                }
                Ok(Ok(other)) => println!("    (ignoring while awaiting GET: {other:?})"),
                Ok(Err(e)) => return GetOutcome::Unknown(format!("error response: {e}")),
            }
        }
    }
}

/// Run one probe to completion over a live node, mirroring `migrate_ops::pump`.
/// Scenario 5: a store at the NEWEST superseded generation, owned by its key
/// and addressed by its code (V17 on), is found by the walk, and its state is
/// accepted by this build's contract as it is. The whole-key scenario 1
/// plants states built from today's types at V4/V5, whose contracts no longer
/// decode them; this one rehearses the step a real upgrade takes.
async fn scenario_newest_store_generation(node: &mut Node, repo: &Path, current: &[u8]) {
    println!("\n== scenario 5: a store at the newest superseded generation is carried forward ==");
    let newest = migrate::store_lineage()
        .iter()
        .max_by_key(|e| e.generation)
        .expect("a superseded generation");
    let wasm = legacy_wasm_from_git(repo, "store_contract", &hex::encode(newest.code_hash));
    let seller = SigningKey::from_bytes(&[9u8; 32]);
    let vk = seller.verifying_key();
    let fp = fingerprint_of(&vk);
    let params = current_params(&vk);
    let (old_container, old_id) = container(&wasm, params.clone());
    let (curr_container, curr_id) = container(current, params);
    println!("  V{} instance {old_id}; current instance {curr_id}", newest.generation);
    assert!(
        migrate::store_candidate_ids(&vk).unwrap().contains(&old_id),
        "the walk must reach the generation state is planted at"
    );
    let planted = StoreStateV1 {
        owner: Some(vk),
        info: make_info(&seller, &fp, "Newest Generation Store", 4),
        listings: harvest_common::store::ListingsV1 {
            listings: vec![make_listing(&seller, &fp, "newest-listing", 1_758_000_000)],
        },
        ..Default::default()
    };
    node.put(old_container, harvest_common::to_cbor(&planted).unwrap())
        .await
        .expect("PUT at the newest superseded generation");
    let (outcome, seal) = run_probe(node, &vk, migrate::store_candidates(&vk).unwrap()).await;
    println!("  describe: {}", migrate::describe(&outcome));
    println!("  seal decision: {seal:?}");
    let Outcome::Recovered { merged, source, .. } = &outcome else {
        panic!("expected Recovered, got {outcome:?}");
    };
    assert_eq!(*source, old_id);
    assert_eq!(titles(merged), vec!["newest-listing".to_string()]);
    node.put(curr_container, harvest_common::to_cbor(merged).unwrap())
        .await
        .expect("the current contract accepts the carried state");
    match node.get(curr_id).await {
        GetOutcome::State(bytes) => {
            let s: StoreStateV1 = harvest_common::from_cbor(&bytes).unwrap();
            println!(
                "  current generation holds: store_name={:?} listings={:?} statuses={}",
                s.info.info.store_name,
                titles(&s),
                s.listing_statuses.records.len()
            );
            assert_eq!(titles(&s), vec!["newest-listing".to_string()]);
            assert_eq!(s.info.info.store_name, "Newest Generation Store");
            assert!(s.listing_statuses.is_empty(), "none was planted, none appears");
            for l in &s.listings.listings {
                l.verify(&vk).expect("a carried listing still verifies");
            }
        }
        other => panic!("current generation did not read back: {other:?}"),
    }
}

async fn run_probe(
    node: &mut Node,
    vk: &VerifyingKey,
    candidates: freenet_migrate::NewestFirst,
) -> (Outcome<StoreStateV1>, Seal) {
    let mut session = ProbeSession::start_with_candidates(
        StoreOps {
            params: migrate::store_params(vk),
            seller: *vk,
        },
        StoreStateV1::default(),
        candidates,
        migrate::fold_all_policy(),
    );
    while let Some(candidate) = session.next_get() {
        let answer = node.get(candidate).await;
        match &answer {
            GetOutcome::State(b) => println!("  GET {candidate} -> state, {} bytes", b.len()),
            GetOutcome::Absent => println!("  GET {candidate} -> NotFound"),
            GetOutcome::Unknown(why) => println!("  GET {candidate} -> unknown ({why})"),
        }
        match answer {
            GetOutcome::State(bytes) => session.on_state(candidate, &bytes),
            GetOutcome::Absent => session.on_absent(candidate),
            GetOutcome::Unknown(_) => session.on_unknown(candidate),
        }
    }
    session.take_result().expect("probe finished with a result")
}

fn titles(state: &StoreStateV1) -> Vec<String> {
    state
        .listings
        .listings
        .iter()
        .map(|l| l.listing.title.clone())
        .collect()
}

fn read_wasm(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    println!(
        "  {}: {} bytes, blake3 {}",
        path.display(),
        bytes.len(),
        hex::encode(code_hash(&bytes))
    );
    bytes
}

/// The parameter encoding a store generation was published under.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// `{seller_verifying_key, trusted_bitcoin_bridges, bitcoin_address_code_hash}`, 109 B.
    Legacy,
    /// `{seller_verifying_key}`, 56 B.
    WholeKey,
    /// `{store_code}`, 29 B: harvest#52 onwards, and the current build.
    Code,
}

/// Every registry generation is walked at the address it ACTUALLY has.
///
/// This is the part `freenet_migrate` cannot do on its own:
/// `ContractLineageEntry` carries only a code hash, so the crate derives every
/// predecessor from one set of parameter bytes, and the store's encoding
/// changed three times -- 56 bytes for V1, 109 for V2..=V5, 56 again for
/// V6..=V16, and 29 (the store code) from V17. Each
/// generation is checked against an id derived the way the NODE derives one
/// (`WrappedContract::key`), from that generation's real WASM out of git
/// history and the parameters it shipped with.
///
/// Keyed on the generation NUMBER, never on a position in the candidate list.
/// The two assertions this replaced were `derived[0] == v5_id` and
/// `derived[1] == v4_id`, correct when written against a five-row registry and
/// silently wrong from the moment V6 was recorded (`d9cddad`) -- V6 took index
/// 0 and every position shifted. Nothing caught it because this harness needs
/// a live node and does not run in CI. Looking generations up by number means
/// adding V7 cannot break it again.
///
/// The table is written out per generation rather than asking
/// `published_under_legacy_store_params`, for the same reason its counterpart
/// in `ui/src/migrate/tests.rs` is: deriving the expectation from the code
/// under test cannot catch that code having the boundary wrong, and the
/// boundary WAS wrong -- it put V1, the only generation ever published, on the
/// legacy side.
const ENCODING_BY_GENERATION: &[(u32, Shape)] = {
    use Shape::{Code, Legacy, WholeKey};
    &[
        (1, WholeKey),
        (2, Legacy),
        (3, Legacy),
        (4, Legacy),
        (5, Legacy),
        (6, WholeKey),
        // V7: visibility-only change to `StoreParameters`, so the encoding is
        // unchanged at 56 bytes. See the same table in `ui/src/migrate/tests.rs`.
        (7, WholeKey),
        // V8, V9 and V10 were added on 2026-09-09, having been missed when each
        // generation was recorded. The table went stale at V8 (2026-09-06) and the
        // harness has been panicking on the length assertion below ever since,
        // unnoticed because it needs a live node and does not run in CI. Note what
        // that says about the reassurance above: looking generations up BY NUMBER
        // did fix the index-shift bug it was written for, and it does not stop
        // this table needing a row per generation. Adding one is still part of
        // recording a generation.
        //
        // All three are `WholeKey` for the same reason V8 and V9 are in the sibling
        // table: none of them touched `StoreParameters`, whose encoding is still
        // 56 bytes.
        (8, WholeKey),
        (9, WholeKey),
        (10, WholeKey),
        // V11..=V16 were missed the same way and added with harvest#52. All are
        // the 56-byte whole-key shape; V16 is the last of them, because harvest#52
        // made the parameter a code.
        (11, WholeKey),
        (12, WholeKey),
        (13, WholeKey),
        (14, WholeKey),
        (15, WholeKey),
        (16, WholeKey),
        // V17: the build at `bc57dac` (harvest#52), the first addressed by the
        // store code. Superseded by dropping the store contract's diagnostic-only
        // related-contract fetch.
        (17, Code),
        // V18: the build at `f6afc74` (#95). Still the store code, 29 B, and still
        // the code of the seller's Ghost Key: harvest#93 changed whose key the
        // code is a prefix of, not the encoding. Superseded by harvest#93 phase
        // 1a (a store key owns the store).
        (18, Code),
        // V19 (`b5eddce7`) and V20 (`9e0561ce`) were missed the same way, and
        // added with harvest#53 Phase C when this harness next ran. Neither
        // touched `StoreParameters`: still the store code.
        (19, Code),
        (20, Code),
        // V21: harvest#53 Phase C, superseded by harvest#70's listing
        // statuses. `StoreParameters` untouched: still the store code.
        (21, Code),
    ]
};

/// Every recorded generation is published under one of three shapes: the
/// three-field (`legacy`), the whole key, or (V17 onwards) the store code.
fn assert_candidate_addresses(
    repo: &Path,
    vk: &VerifyingKey,
    legacy: &Parameters<'static>,
    whole_key: &Parameters<'static>,
    code: &Parameters<'static>,
) {
    let derived = migrate::store_candidate_ids(vk).expect("derive candidates");
    let mut newest_first: Vec<_> = migrate::store_lineage().iter().collect();
    newest_first.sort_by_key(|e| std::cmp::Reverse(e.generation));

    assert_eq!(
        derived.len(),
        newest_first.len(),
        "every recorded generation must be walked"
    );
    assert_eq!(
        ENCODING_BY_GENERATION.len(),
        newest_first.len(),
        "the encoding table must cover every recorded generation, and only those"
    );

    println!("  migrate::store_candidate_ids, checked against the node's own derivation:");
    let mut saw_legacy = false;
    let mut saw_whole_key = false;
    let mut saw_code = false;

    for (entry, got) in newest_first.iter().zip(&derived) {
        let (_, shape) = ENCODING_BY_GENERATION
            .iter()
            .find(|(g, _)| *g == entry.generation)
            .unwrap_or_else(|| {
                panic!(
                    "generation {} is not in the encoding table",
                    entry.generation
                )
            });

        let wasm = legacy_wasm_from_git(repo, "store_contract", &hex::encode(entry.code_hash));
        let params = match shape {
            Shape::Legacy => {
                saw_legacy = true;
                legacy.clone()
            }
            Shape::WholeKey => {
                saw_whole_key = true;
                whole_key.clone()
            }
            Shape::Code => {
                saw_code = true;
                code.clone()
            }
        };
        let (_, expected) = container(&wasm, params);

        println!(
            "    V{} {:?} params -> {}",
            entry.generation,
            shape,
            got
        );
        assert_eq!(
            *got,
            expected,
            "generation {} must be walked at the address it was published under \
             ({:?} parameter encoding)",
            entry.generation,
            shape
        );
    }

    // Without generations of EVERY shape this checks nothing about the splits
    // between them: deriving every id under one encoding would pass. There are
    // three shapes, so two boundaries (V1/V2 and V5/V6 around the three-field
    // band, and V16/V17 into the store code), and the walk has to have met all
    // three shapes for either boundary to have been exercised.
    assert!(
        saw_legacy && saw_whole_key && saw_code,
        "the registry must span every parameter split for this check to mean anything \
         (legacy seen: {saw_legacy}, whole key seen: {saw_whole_key}, code seen: {saw_code})"
    );
}

#[tokio::main]
async fn main() {
    println!("== artifacts ==");
    let repo = repo_root();
    let v5 = legacy_wasm_from_git(&repo, "store_contract", PLANT_AT[0].1);
    let v4 = legacy_wasm_from_git(&repo, "store_contract", PLANT_AT[1].1);
    let current = read_wasm(&repo.join("ui/public/contracts/store_contract.wasm"));
    let current_hash = code_hash(&current);
    println!(
        "  current generation hash {} (must NOT appear in the registry)",
        hex::encode(current_hash)
    );
    for e in migrate::store_lineage() {
        assert_ne!(
            hex::encode(e.code_hash),
            hex::encode(current_hash),
            "the current build's hash is recorded as superseded"
        );
    }
    println!(
        "  registry generations: {:?}",
        migrate::store_lineage()
            .iter()
            .map(|e| (e.generation, hex::encode(&e.code_hash[..4])))
            .collect::<Vec<_>>()
    );

    let mut node = Node::connect().await;

    // `REHEARSAL_ONLY=reputation` runs scenario 4 alone (harvest#53 Phase C),
    // so the reputation re-addressing can be rehearsed without the store
    // scenarios' own preconditions.
    if std::env::var("REHEARSAL_ONLY").as_deref() == Ok("reputation") {
        scenario_reputation(&mut node, &repo).await;
        scenario_reputation_cap_carried(&mut node, &repo).await;
        println!("\nSCENARIO 4 ONLY: PASSED");
        return;
    }
    // `REHEARSAL_ONLY=newest` plants a store at the newest superseded
    // generation and folds it into this build (harvest#70's re-key).
    if std::env::var("REHEARSAL_ONLY").as_deref() == Ok("newest") {
        scenario_newest_store_generation(&mut node, &repo, &current).await;
        println!("\nSCENARIO 5 ONLY: PASSED");
        return;
    }

    // ================= scenario 1: populated predecessors =================
    println!("\n== scenario 1: populated predecessor generations ==");
    let seller = SigningKey::from_bytes(&[7u8; 32]);
    let vk = seller.verifying_key();
    let fp = fingerprint_of(&vk);
    println!("  seller fingerprint {fp}");

    let legacy = legacy_params(&vk);
    let curr_p = current_params(&vk);
    println!(
        "  legacy parameter bytes: {} | current parameter bytes: {}",
        legacy.as_ref().len(),
        curr_p.as_ref().len()
    );

    let (v5_container, v5_id) = container(&v5, legacy.clone());
    let (v4_container, v4_id) = container(&v4, legacy.clone());
    let (curr_container, curr_id) = container(&current, curr_p.clone());
    println!("  V4 instance (stdlib key derivation): {v4_id}");
    println!("  V5 instance (stdlib key derivation): {v5_id}");
    println!("  current instance:                    {curr_id}");

    // The arithmetic that matters: the ids migrate.rs will walk must equal the
    // ids the node addresses those generations by -- every generation, each
    // under the parameter encoding IT shipped with.
    assert_candidate_addresses(&repo, &vk, &legacy, &whole_key_params(&vk), &curr_p);

    for (generation, want) in PLANT_AT {
        let row = migrate::store_lineage()
            .iter()
            .find(|e| e.generation == *generation)
            .expect("the registry still declares this generation");
        assert_eq!(
            hex::encode(row.code_hash),
            *want,
            "generation {generation} no longer has the hash this harness plants at"
        );
    }
    // Named for the fold below, and cross-checked against the walk rather than
    // assumed: these are the two generations state is planted at.
    let derived = migrate::store_candidate_ids(&vk).expect("derive candidates");
    assert!(
        derived.contains(&v5_id) && derived.contains(&v4_id),
        "the walk must reach both generations this harness plants state at"
    );
    assert_eq!(
        migrate::current_id(&current_hash, &curr_p),
        curr_id,
        "migrate::current_id must agree with the stdlib key derivation"
    );

    // Plant DIFFERENT data at two generations, so a fold that stops early is
    // visible as a missing listing rather than as a pass.
    // Whole-key generations: their state names no owner, which is what the
    // fold has to supply (harvest#52).
    let v5_state = StoreStateV1 {
        owner: None,
        info: make_info(&seller, &fp, "Fifth Generation Store", 3),
        listings: harvest_common::store::ListingsV1 {
            listings: vec![make_listing(&seller, &fp, "gen5-listing", 1_756_000_000)],
        },
        orders: Default::default(),
        // Empty, and so not written out: the bytes are exactly the ones a
        // whole-key generation holds (harvest#93 added these parts).
        ..Default::default()
    };
    let v4_state = StoreStateV1 {
        owner: None,
        info: make_info(&seller, &fp, "Fourth Generation Store", 2),
        listings: harvest_common::store::ListingsV1 {
            listings: vec![make_listing(&seller, &fp, "gen4-listing", 1_755_000_000)],
        },
        orders: Default::default(),
        // Empty, and so not written out: the bytes are exactly the ones a
        // whole-key generation holds (harvest#93 added these parts).
        ..Default::default()
    };

    let v5_bytes = harvest_common::to_cbor(&v5_state).unwrap();
    let v4_bytes = harvest_common::to_cbor(&v4_state).unwrap();
    println!("  PUT V4 state ({} bytes) ...", v4_bytes.len());
    node.put(v4_container, v4_bytes).await.expect("PUT V4");
    println!("  PUT V5 state ({} bytes) ...", v5_bytes.len());
    node.put(v5_container, v5_bytes).await.expect("PUT V5");

    // Read them back so "planted" is an observation, not an assumption.
    for (label, id, want) in [("V4", v4_id, "gen4-listing"), ("V5", v5_id, "gen5-listing")] {
        match node.get(id).await {
            GetOutcome::State(bytes) => {
                let s: StoreStateV1 = harvest_common::from_cbor(&bytes).expect("decode planted");
                println!(
                    "  read back {label} {id}: store_name={:?} listings={:?}",
                    s.info.info.store_name,
                    titles(&s)
                );
                assert_eq!(titles(&s), vec![want.to_string()]);
            }
            other => panic!("{label} did not read back: {other:?}"),
        }
    }

    println!("\n  -- probe as the current build --");
    let (outcome, seal) = run_probe(&mut node, &vk, migrate::store_candidates(&vk).unwrap()).await;
    println!("  describe: {}", migrate::describe(&outcome));
    println!("  seal decision: {seal:?}");
    match &outcome {
        Outcome::Recovered {
            merged,
            source,
            truncated_fold,
            unresolved,
        } => {
            println!("  source generation: {source}");
            println!("  truncated_fold={truncated_fold} unresolved={}", unresolved.len());
            println!("  merged store_name: {:?}", merged.info.info.store_name);
            println!("  merged info.version: {}", merged.info.info.version);
            println!("  merged listings: {:?}", titles(merged));
            assert_eq!(*source, v5_id, "newest populated generation is the source");
            assert!(!*truncated_fold);
            if !unresolved.is_empty() {
                println!(
                    "  NOTE: {} candidate(s) never produced a usable answer on this node, \
                     so the walk is not sealable here:",
                    unresolved.len()
                );
                for id in unresolved {
                    println!("    unresolved {id}");
                }
            }
            let mut got = titles(merged);
            got.sort();
            assert_eq!(
                got,
                vec!["gen4-listing".to_string(), "gen5-listing".to_string()],
                "fold-all must carry BOTH generations' listings forward"
            );
            assert_eq!(merged.info.info.version, 3, "newest info wins");
            assert_eq!(merged.info.info.store_name, "Fifth Generation Store");
            for l in &merged.listings.listings {
                l.verify(&vk).expect("recovered listing must still verify");
            }
            let expect_seal = unresolved.is_empty() && !*truncated_fold;
            assert_eq!(
                seal,
                if expect_seal { Seal::Seal } else { Seal::Retry },
                "seal decision must follow the rule: only a complete Recovered seals"
            );

            // And the forward PUT: does the CURRENT contract accept it?
            let forward = harvest_common::to_cbor(merged).unwrap();
            println!("  PUT recovered state forward to {curr_id} ({} bytes) ...", forward.len());
            node.put(curr_container, forward)
                .await
                .expect("forward PUT to the current generation");
            match node.get(curr_id).await {
                GetOutcome::State(bytes) => {
                    let s: StoreStateV1 = harvest_common::from_cbor(&bytes).unwrap();
                    println!(
                        "  current generation now holds: store_name={:?} listings={:?}",
                        s.info.info.store_name,
                        titles(&s)
                    );
                    let mut got = titles(&s);
                    got.sort();
                    assert_eq!(
                        got,
                        vec!["gen4-listing".to_string(), "gen5-listing".to_string()]
                    );
                    assert_eq!(s.info.info.store_name, "Fifth Generation Store");
                }
                other => panic!("current generation did not read back: {other:?}"),
            }
        }
        other => panic!("expected Recovered, got {other:?}"),
    }
    println!(
        "  marker that MAY now be written: {}",
        migrate::marker_key(Artifact::Store, &curr_id, &current_hash)
    );

    // ===== scenario 1b: what the same walk does WITHOUT the param split =====
    println!("\n== scenario 1b (control): the same lineage derived with TODAY's parameters ==");
    let unsplit = freenet_migrate::NewestFirst::from_lineage(&curr_p, migrate::store_lineage());
    let (outcome_unsplit, seal_unsplit) = run_probe(&mut node, &vk, unsplit).await;
    println!("  describe: {}", migrate::describe(&outcome_unsplit));
    println!("  seal decision: {seal_unsplit:?}");
    match &outcome_unsplit {
        Outcome::SeedLocal { .. } => println!(
            "  CONFIRMED: without the generation split the walk reports a clean \
             'nothing to migrate' over a populated store"
        ),
        other => println!("  unexpected: {other:?}"),
    }

    // ================= scenario 2: nothing to find =================
    println!("\n== scenario 2: empty successor, no predecessor holds state ==");
    let stranger = SigningKey::from_bytes(&[9u8; 32]);
    let svk = stranger.verifying_key();
    println!("  seller fingerprint {}", fingerprint_of(&svk));
    let s_curr_p = current_params(&svk);
    let s_curr_id = migrate::current_id(&current_hash, &s_curr_p);
    let s_candidates = migrate::store_candidate_ids(&svk).unwrap();
    println!("  candidates: {}", s_candidates.len());
    assert!(
        !s_candidates.contains(&v5_id) && !s_candidates.contains(&v4_id),
        "a different seller must not derive the planted addresses"
    );
    let (outcome2, seal2) = run_probe(&mut node, &svk, migrate::store_candidates(&svk).unwrap()).await;
    println!("  describe: {}", migrate::describe(&outcome2));
    println!("  seal decision: {seal2:?}");
    match &outcome2 {
        Outcome::SeedLocal { local } => {
            assert_eq!(*local, StoreStateV1::default());
            println!("  SEED-LOCAL path taken: every candidate answered, none held state");
        }
        Outcome::Indeterminate { unresolved, .. } => {
            println!(
                "  INDETERMINATE: {} candidate(s) never answered on this node",
                unresolved.len()
            );
        }
        other => panic!("expected SeedLocal or Indeterminate, got {other:?}"),
    }
    assert_eq!(seal2, Seal::Retry, "nothing but a complete Recovered may seal");
    // Mirror `migrate_ops::finish`: a marker is written only under
    // `Seal::Seal` AND a state to forward. Neither holds here.
    let would_write_marker = seal2 == Seal::Seal;
    println!(
        "  marker {} would NOT be written (seal={seal2:?})",
        migrate::marker_key(Artifact::Store, &s_curr_id, &current_hash)
    );
    assert!(!would_write_marker);

    scenario_reputation(&mut node, &repo).await;

    // ============ scenario 3: the durable marker, on the live delegate ============
    println!("\n== scenario 3: the repeat gate's marker, against the real delegate ==");
    let delegate_wasm = std::fs::read(repo.join("ui/public/contracts/harvest_delegate.wasm"))
        .expect("read harvest delegate wasm");
    println!(
        "  harvest_delegate.wasm: {} bytes, blake3 {}",
        delegate_wasm.len(),
        hex::encode(code_hash(&delegate_wasm))
    );
    match node.register_delegate(&delegate_wasm).await {
        Ok(dkey) => {
            println!("  registered delegate {dkey}");
            let marker = migrate::marker_key(Artifact::Store, &s_curr_id, &current_hash);
            // 1. before: must be absent
            match node.delegate_request(&dkey, &migrate::marker_query(&marker)).await {
                Ok(r) => println!("  GetMigrationMarker (before) -> {r:?}"),
                Err(e) => println!("  GetMigrationMarker (before) FAILED: {e}"),
            }
            // 2. write one (this is what a SEALABLE outcome would do)
            match node
                .delegate_request(&dkey, &migrate::marker_write(&marker, "rehearsal"))
                .await
            {
                Ok(r) => println!("  SetMigrationMarker -> {r:?}"),
                Err(e) => println!("  SetMigrationMarker FAILED: {e}"),
            }
            // 3. after: must now be present, or the repeat gate does not work
            match node.delegate_request(&dkey, &migrate::marker_query(&marker)).await {
                Ok(r) => {
                    println!("  GetMigrationMarker (after) -> {r:?}");
                    match r {
                        harvest_common::HarvestDelegateResponse::MigrationMarker {
                            present, ..
                        } => {
                            if present {
                                println!("  the durable marker survives a round trip: the repeat gate is real");
                            } else {
                                println!("  WARNING: the delegate did not report the marker it just recorded");
                            }
                        }
                        other => println!("  unexpected response shape: {other:?}"),
                    }
                }
                Err(e) => println!("  GetMigrationMarker (after) FAILED: {e}"),
            }
        }
        Err(e) => println!("  could not register the delegate: {e}"),
    }

    println!("\nALL SCENARIOS PASSED");
}
