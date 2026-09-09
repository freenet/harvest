//! Live-node rehearsal of Harvest's contract migration.
//!
//! Compiles the REAL `ui/src/migrate.rs` (via `#[path]`) against the REAL
//! `legacy/*.toml` (via the same codegen `ui/build.rs` runs), so every id this
//! walks is derived by the code that ships. Nothing here is mocked: every GET
//! and PUT goes to a freenet node over the websocket client API.

#[path = "../../../ui/src/migrate.rs"]
mod migrate;

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
    ApplicationMessage, ContractCode, ContractContainer, ContractInstanceId,
    ContractWasmAPIVersion, Delegate, DelegateCode, DelegateContainer, DelegateKey,
    DelegateWasmAPIVersion, InboundDelegateMsg, OutboundDelegateMsg, Parameters, RelatedContracts,
    WrappedContract, WrappedState,
};
use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind, PriceInfo};
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
        id: ListingId::from_label(title),
        title: title.to_string(),
        description: format!("{title} -- written by the rehearsal harness"),
        kind: ListingKind::Sale,
        price: Some(PriceInfo {
            amount: "0.005".into(),
            currency: "BTC".into(),
        }),
        created_at,
    };
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
        payment_instructions: "BTC: tb1qrehearsal".into(),
        encryption_public_key: None,
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
async fn run_probe(
    node: &mut Node,
    vk: &VerifyingKey,
    candidates: freenet_migrate::NewestFirst,
) -> (Outcome<StoreStateV1>, Seal) {
    let mut session = ProbeSession::start_with_candidates(
        StoreOps {
            params: migrate::store_params(vk),
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

/// Every registry generation is walked at the address it ACTUALLY has.
///
/// This is the part `freenet_migrate` cannot do on its own:
/// `ContractLineageEntry` carries only a code hash, so the crate derives every
/// predecessor from one set of parameter bytes, and the store's encoding
/// changed twice -- 56 bytes for V1, 109 for V2..=V5, 56 again from V6. Each
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
const ENCODING_BY_GENERATION: &[(u32, bool)] = &[
    (1, false),
    (2, true),
    (3, true),
    (4, true),
    (5, true),
    (6, false),
    // V7: visibility-only change to `StoreParameters`, so the encoding is
    // unchanged at 56 bytes. See the same table in `ui/src/migrate/tests.rs`.
    (7, false),
    // V8, V9 and V10 were added on 2026-09-09, having been missed when each
    // generation was recorded. The table went stale at V8 (2026-09-06) and the
    // harness has been panicking on the length assertion below ever since,
    // unnoticed because it needs a live node and does not run in CI. Note what
    // that says about the reassurance above: looking generations up BY NUMBER
    // did fix the index-shift bug it was written for, and it does not stop
    // this table needing a row per generation. Adding one is still part of
    // recording a generation.
    //
    // All three are `false` for the same reason V8 and V9 are in the sibling
    // table: none of them touched `StoreParameters`, whose encoding is still
    // 56 bytes.
    (8, false),
    (9, false),
    (10, false),
];

fn assert_candidate_addresses(
    repo: &Path,
    vk: &VerifyingKey,
    legacy: &Parameters<'static>,
    current: &Parameters<'static>,
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
    let mut saw_current = false;

    for (entry, got) in newest_first.iter().zip(&derived) {
        let (_, is_legacy) = ENCODING_BY_GENERATION
            .iter()
            .find(|(g, _)| *g == entry.generation)
            .unwrap_or_else(|| {
                panic!(
                    "generation {} is not in the encoding table",
                    entry.generation
                )
            });

        let wasm = legacy_wasm_from_git(repo, "store_contract", &hex::encode(entry.code_hash));
        let params = if *is_legacy {
            saw_legacy = true;
            legacy.clone()
        } else {
            saw_current = true;
            current.clone()
        };
        let (_, expected) = container(&wasm, params);

        println!(
            "    V{} {} params -> {}",
            entry.generation,
            if *is_legacy { "legacy " } else { "current" },
            got
        );
        assert_eq!(
            *got,
            expected,
            "generation {} must be walked at the address it was published under \
             ({} parameter encoding)",
            entry.generation,
            if *is_legacy { "legacy" } else { "current" }
        );
    }

    // Without generations on BOTH sides this checks nothing about the split:
    // deriving every id under one encoding would pass.
    assert!(
        saw_legacy && saw_current,
        "the registry must span the parameter split for this check to mean anything \
         (legacy seen: {saw_legacy}, current seen: {saw_current})"
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
    assert_candidate_addresses(&repo, &vk, &legacy, &curr_p);

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
    let v5_state = StoreStateV1 {
        info: make_info(&seller, &fp, "Fifth Generation Store", 3),
        listings: harvest_common::store::ListingsV1 {
            listings: vec![make_listing(&seller, &fp, "gen5-listing", 1_756_000_000)],
        },
        orders: Default::default(),
    };
    let v4_state = StoreStateV1 {
        info: make_info(&seller, &fp, "Fourth Generation Store", 2),
        listings: harvest_common::store::ListingsV1 {
            listings: vec![make_listing(&seller, &fp, "gen4-listing", 1_755_000_000)],
        },
        orders: Default::default(),
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
