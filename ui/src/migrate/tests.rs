//! Tests for the migration registries and the probe's decisions.
//!
//! Two halves, and the second is the one that matters most.
//!
//! The **registry** tests pin what is recorded: that every lineage is
//! non-empty and ordered, that the recorded hashes are the ones derived from
//! git history, that each delegate key really derives from its code hash, and
//! that no CURRENT hash has crept into a registry of superseded ones.
//!
//! The **probe** tests drive a real `ProbeDriver` through the answers the
//! network actually gives -- state, a positive `NotFound`, and silence -- and
//! assert what may be sealed. Every failure in this area is silent, so the
//! only useful assertions are the ones that fail when a guard is removed. Each
//! test below was confirmed to go red by applying the mutation it describes.

use std::collections::HashSet;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_migrate::Outcome;
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId};
use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};
use harvest_common::mailbox::{EncryptedMessage, MailboxStateV1};
use harvest_common::reputation::{Complaint, ReputationStateV1};
use harvest_common::store::StoreStateV1;

use super::*;

// --- fixtures -----------------------------------------------------------

fn seller() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn seller_vk() -> VerifyingKey {
    seller().verifying_key()
}

fn store_bytes(state: &StoreStateV1) -> Vec<u8> {
    harvest_common::to_cbor(state).expect("serialize store state")
}

/// A listing signed the way the ghostkey delegate signs one, so
/// `AuthorizedListing::verify` -- which the store contract's `apply_delta`
/// runs on every merged listing -- accepts it.
fn signed_listing(title: &str) -> AuthorizedListing {
    // The id is derived from the terms rather than passed in: a listing
    // carrying anything else is refused by `AuthorizedListing::verify`, which
    // the store contract runs on every merged listing -- so a hand-chosen id
    // would make every fixture here unmergeable. Distinct titles still give
    // distinct listings, which is all these tests identify them by.
    let listing = Listing {
        checkout: None,
        choices: Vec::new(),
        id: ListingId([0u8; 32]),
        title: title.to_string(),
        description: String::new(),
        kind: ListingKind::Sale,
        price: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp"),
    }
    .with_derived_id();
    let payload = harvest_common::to_cbor(&listing).expect("serialize listing");
    let scoped = ghostkey_common::ScopedPayload {
        requestor: ghostkey_common::SignatureRequestor::WebApp(
            harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                .parse::<ContractInstanceId>()
                .expect("canonical webapp id"),
        ),
        payload,
    };
    let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped payload");
    let signature = seller().sign(&scoped_payload).to_bytes().to_vec();
    AuthorizedListing {
        listing,
        scoped_payload,
        signature,
        certificate_pem: String::new(),
    }
}

fn store_with(listings: &[AuthorizedListing]) -> StoreStateV1 {
    let mut state = StoreStateV1::default();
    state.listings.listings = listings.to_vec();
    // Sorted by id, which is the order `ListingsV1::apply_delta` leaves
    // behind and therefore the only order a state reached through a merge is
    // ever in. Assigning an arbitrary vec here builds a state no peer could
    // hold, and the commutativity check then fails against a difference this
    // fixture invented rather than one the merge caused.
    //
    // It went unnoticed while ids were hand-chosen bytes that happened to
    // ascend with the fixture's own argument order; deriving ids from the
    // terms reordered them and made the assumption visible.
    state
        .listings
        .listings
        .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
    state
}

fn message(nonce: u8, secs: i64) -> EncryptedMessage {
    EncryptedMessage {
        conversation_id: harvest_common::mailbox::ConversationId([nonce; 32]),
        sender_public_key: vec![nonce; 32],
        ciphertext: vec![nonce; 8],
        timestamp: chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp"),
        nonce: [nonce; 24],
    }
}

fn mailbox_with(messages: Vec<EncryptedMessage>) -> MailboxStateV1 {
    MailboxStateV1 { messages }
}

fn store_ops() -> StoreOps {
    StoreOps {
        params: store_params(&seller_vk()),
        seller: seller_vk(),
    }
}

fn store_params_encoded() -> freenet_stdlib::prelude::Parameters<'static> {
    encode_params(&store_params(&seller_vk())).expect("encode store params")
}

/// Drive a probe to completion, answering each candidate from `answers`.
///
/// `answers` maps a candidate id to what the network says about it; anything
/// not listed is silence (`on_unknown`), which is how a real run behaves when
/// a deadline expires.
enum Answer {
    State(Vec<u8>),
    Absent,
    Silence,
}

fn run<O: ProbeStateOps>(
    mut session: ProbeSession<O>,
    mut answer: impl FnMut(ContractInstanceId) -> Answer,
) -> (Outcome<O::State>, Seal) {
    // Bounded so a driver bug cannot hang the test suite.
    for _ in 0..64 {
        match session.next_get() {
            Some(id) => match answer(id) {
                Answer::State(bytes) => session.on_state(id, &bytes),
                Answer::Absent => session.on_absent(id),
                Answer::Silence => session.on_unknown(id),
            },
            None => {
                return session
                    .take_result()
                    .expect("probe finished without a result")
            }
        }
    }
    panic!("probe did not terminate");
}

fn store_session(local: StoreStateV1) -> ProbeSession<StoreOps> {
    ProbeSession::start(
        store_ops(),
        local,
        &store_params_encoded(),
        store_lineage(),
        fold_all_policy(),
    )
}

// --- registry: what is recorded -----------------------------------------

/// Every lineage has rows. An empty lineage probes nothing, finds nothing, and
/// reports success -- the failure mode this whole mechanism exists to avoid,
/// and the one that looks healthiest.
///
/// `ui/build.rs` already fails the build on a registry with no `[[entry]]`
/// rows, and that guard fires FIRST -- so emptying a registry cannot make this
/// test red, it makes the build red. This asserts the same property one layer
/// down, against the generated consts rather than the TOML text, and covers
/// what the build guard cannot: a codegen change, or an accessor here, that
/// produced an empty lineage from a populated file.
///
/// Mutated red by stubbing `store_lineage()` to return `&[]`.
#[test]
fn every_lineage_has_predecessors() {
    for (name, len) in [
        ("store", store_lineage().len()),
        ("reputation", reputation_lineage().len()),
        ("mailbox", mailbox_lineage().len()),
        ("index", index_lineage().len()),
        ("delegate", delegate_lineage().len()),
    ] {
        assert!(
            len > 0,
            "the {name} lineage is empty: a probe over it would report a clean \
             migration having looked at nothing"
        );
    }
}

/// Generations are unique and strictly increasing.
///
/// The driver orders candidates by the `generation` FIELD, descending -- not
/// by slice order -- so the whole newest-first guarantee, and with it the
/// anti-rollback property, rests on these numbers being right. Two rows
/// sharing a generation makes the probe order between them arbitrary.
#[test]
fn generations_are_unique_and_ascending() {
    for (name, entries) in [
        ("store", store_lineage()),
        ("reputation", reputation_lineage()),
        ("mailbox", mailbox_lineage()),
        ("index", index_lineage()),
    ] {
        let generations: Vec<u32> = entries.iter().map(|e| e.generation).collect();
        let unique: HashSet<u32> = generations.iter().copied().collect();
        assert_eq!(
            unique.len(),
            generations.len(),
            "{name}: duplicate generation numbers {generations:?}"
        );
        let mut sorted = generations.clone();
        sorted.sort_unstable();
        assert_eq!(generations, sorted, "{name}: generations are out of order");
    }
    let delegate_generations: Vec<u32> = delegate_lineage().iter().map(|e| e.generation).collect();
    let mut sorted = delegate_generations.clone();
    sorted.sort_unstable();
    assert_eq!(
        delegate_generations, sorted,
        "delegate generations disorder"
    );
}

/// The recorded hashes, pinned.
///
/// Each was produced by hashing the committed artifact out of git history --
/// `git show <commit>:ui/public/contracts/<a>.wasm | b3sum --no-names` -- which
/// is meaningful because the UI embeds those files with `include_bytes!`, so
/// the committed bytes at a commit ARE what was deployed from it. The method
/// was checked first by confirming that HEAD's committed bytes reproduce
/// exactly under `scripts/build-contract-wasm.sh`.
///
/// This test is what makes deleting a row loud. A generation quietly dropped
/// from a registry is a generation nothing ever probes again, and no other
/// check in the repo would notice.
#[test]
fn the_recorded_hashes_are_the_ones_derived_from_git_history() {
    let expected: &[(&str, &[&str])] = &[
        (
            "store",
            &[
                "4d7ad3c31238a4b7a45095ae8722df52f9931a5362568ed2c63b3f36a96c711d",
                "0227238dccae77ef9f49d06b685fa3fed95fe63b292d7d7a4fa9d6ad3f42caa8",
                "ccc61113e758c463ab03a55612ac28a480c4733e9a82eb961566cf6496205233",
                "df0e8dfbc12071b1ab80d1b5c05aa6a9265b9b4141669a740f04f96363118d4a",
                "186f7784628f0f773dd711c91a35d822e2f1111fe052328227f924977df2d2c0",
                // V6, from `git show 94a3fd1:ui/public/contracts/store_contract.wasm`.
                // Superseded by the per-order Bitcoin payment address.
                "9add809b5af3b735114e0683fac23a459a1d3dde447cf4f921ced9a0719611cf",
                // V7, from `git show d9cddad:ui/public/contracts/store_contract.wasm`.
                // Superseded by the 2026-09-05 correctness review; see the
                // registry entry for the per-artifact causes.
                "c1bf133c0029553bee0e092332aac933851e28a1054cce3bf72e42f517bece30",
                // V8, from `git show 5c33d4f:ui/public/contracts/store_contract.wasm`.
                // Superseded by the buyer-to-seller messaging work; this
                // artifact's own change is `StoreInfoV1::encryption_public_key`.
                "c51cbcf2730b8d8511d48768c435462fa1ae37f0a4b513a96cf1d23d73f78370",
                // V9, from `git show baaff9d:ui/public/contracts/store_contract.wasm`.
                // Superseded by the buy flow. This artifact's own change is
                // that it now REJECTS a record whose id is not the one its
                // terms give, which is what makes the content-derived
                // `OrderId`/`ListingId` binding on the network rather than on
                // the issuer -- and it calls the shared address derivation
                // instead of holding a second copy of it.
                "8884c7258f9547743367a1b440f3803b216c09903148407c7f6f5a2af84ae785",
                // V10, from `git show 83521fc:ui/public/contracts/store_contract.wasm`.
                // Superseded by the canonical set-encoding fix; this artifact
                // moves only because `harvest-common` is compiled into it.
                "a758603acd00ecd1394c9d6d017bebfec7b3e0720511b1e56259154f9290ff36",
                // V11, from `git show bc99be7:ui/public/contracts/store_contract.wasm`.
                // Superseded by moving `freenet-bitcoin-common` 0e5b9d9 ->
                // a037181 with NO source change: the store WASM embeds the git
                // checkout path, whose commit segment the build does not remap
                // (harvest#60). See the registry row.
                "97db0a2e4b10de814b760459b2db611285a5b26f49e3db02282b3a8565751392",
                // V12, from `git show 8271d21:ui/public/contracts/store_contract.wasm`.
                // Superseded by removing `listing_id` from `Order` (harvest#57),
                // a real record change: order ids and signature preimages move.
                "52107dcfcc21b96990b8403a37408258f8349335bab42dea9d630672156d4f40",
                // V13, from `git show 5320beb:ui/public/contracts/store_contract.wasm`.
                // Superseded by removing `payment_instructions` from
                // `StoreInfoV1`, which changes what the store's signed details
                // re-encode to, so a predecessor's info no longer verifies.
                "ddac8dd508819052c3771d23aaff9078e52c84ca17e62ae7e68ce356770b3a67",
                // V14, from `git show 7fb733e:ui/public/contracts/store_contract.wasm`.
                // Superseded by settling an order only with a payment that
                // confirmed inside its window after the anchor (harvest#77),
                // which makes verification stricter, so a predecessor
                // holding such an order no longer verifies.
                "3f47ab79e985659f7c03728d907f05e9321037aa23c1ff7c7e569512a445489a",
                // V15, from `git show 1b0d3c3:ui/public/contracts/store_contract.wasm`.
                // Superseded by harvest#26 (canonical listings in `verify`)
                // and #55 (an empty summary or state is not a decode error).
                "c4e212924bc4547525a63c3ab13f6170b552224b32e9ae990b4a438abe890a98",
                // V16, from `git show 5110283:ui/public/contracts/store_contract.wasm`.
                // Superseded by harvest#52: the parameter became a store code
                // and the state gained its owner. The last generation
                // addressed by the whole key.
                "95f464c47796ec638185bb023a37e60dff3a63ecbe115824a3be1bb28c82067d",
                // V17, from `git show bc57dac:ui/public/contracts/store_contract.wasm`.
                // Superseded by removing the diagnostic-only related-contract
                // fetch from `validate_state`. The first generation addressed
                // by the store code; state and validity unchanged.
                "7c56e044b2f69825f209500c54c433038e1be5b3e5cc59b78a92bf4173175f68",
                // V18, from `git show f6afc74:ui/public/contracts/store_contract.wasm`.
                // Superseded by harvest#93 phase 1a: a store key owns the
                // store, and the state gained backings, retirements and the
                // closed flag. The last generation owned by a Ghost Key.
                "1e4eba431c84532ecc684d1d3d664f8d8cbde9156f7a4fcab2af0ca20fcbc79c",
                // V19, from `git show 3f95eff:ui/public/contracts/store_contract.wasm`.
                // Superseded by harvest#53 Phase B: the buyer's receipt key
                // on an order, the buyer's cancel, and the despatch part.
                "b5eddce776f5f38e47682e94ede5bbd7f4d12fb0acd23bc826dcbff81708737b",
                // V20, from `git show 3f3ef7b:ui/public/contracts/store_contract.wasm`.
                // Superseded by harvest#53 Phase C; this artifact moves only
                // because `harvest-common` is compiled into it.
                "9e0561ce17ef6e62dae5b3a75f70c9e00d742aa6afb5b813d369208f75efc16d",
                // V21, from `git show 52afb47:ui/public/contracts/store_contract.wasm`.
                // Superseded by harvest#70: the state gained listing statuses.
                "4aa47d75444431b8dcecd731aef0e88dd484be0805b2b7fb74798d003a23cca8",
                // V22, from `git show f9558cd:ui/public/contracts/store_contract.wasm`.
                // Superseded by instant checkout: listings and orders gained
                // their fixed terms and request id.
                "307332ee371b0ed7a21c696180a09e9b55d53cbd07e96b4e219abf9a5ac5ddf1",
            ],
        ),
        (
            "reputation",
            &[
                "b8577fa15470f4721ede1dfb677d03e263d6f59e6b2661d922aa5eb8d66ce3f9",
                "2d274a944701a37166b09c2a41d987738cd7b29a5f5b8b0179e400dace9ce1f5",
                "7f345c69a800288fe2eb649319cf9b34587953f8161976cc412ab4d308ad35da",
                "c9a939f9a93648f1571193228ccd2fd8331a9970f7c3d934b5b0d646f8cae2ca",
                "5c4d0eec19bf023c32c1723fc6676e43ecc1638922e952ab06c572b407350750",
                // V6, from `git show 94a3fd1:ui/public/contracts/reputation_contract.wasm`.
                "fd91d10d8100cec85ce5719290b57b2c56908352c31f5038fe0e78168eca9f35",
                // V7, from `git show d9cddad:ui/public/contracts/reputation_contract.wasm`.
                // Superseded by the 2026-09-05 correctness review; see the
                // registry entry for the per-artifact causes.
                "7163be62207ae9f77ee2ccb8e0249fe2d824cb52788732eb6fe60cca52b0f801",
                // V8, from `git show 5c33d4f:ui/public/contracts/\
                // reputation_contract.wasm`. This artifact took no behavioural
                // change of its own; `harvest-common` moved underneath it.
                "c47e6fc580e2ecdbc4f4e4330c926c1e2d3092070519f074366bf09964d0e826",
                // V9, from `git show baaff9d:ui/public/contracts/reputation_contract.wasm`.
                // Superseded by the buy flow; this artifact moves only
                // because `harvest-common` is compiled into it.
                "152a12dcf119e72d9b4a909033dcc367b0c9e57a1395c7fa02f5463131499dae",
                // V10, from `git show 83521fc:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by the canonical
                // set-encoding fix, and for THIS artifact the cause is its
                // own: `ReputationStateV1.used_nonces` is STATE and was a
                // `HashSet`, whose CBOR order follows a key bumped on every
                // `RandomState` construction. See the registry row for why
                // that is a counter rather than randomness on wasm32.
                "3c55af21e5658f03121bbeccfe347d4d530b57139251048767089596145e0594",
                // V11, from `git show f46bbf0:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by harvest#22: the
                // token's entry key now signs every field of an entry, which
                // changes what a record's signature covers.
                "eef8685c7a829a36fd95733b94a00a1581f377e734bd64765f0a8ed239709054",
                // V12, from `git show 5110283:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by harvest#52; this
                // artifact moves only because `harvest-common` is compiled
                // into it.
                "58c9632d415d46d333c25e6299878c736460854ca4cdd01e0162fda88ce1f22b",
                // V13, from `git show bc57dac:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by harvest#93 phase
                // 1a; this artifact moves only because `harvest-common` is
                // compiled into it.
                "bf1f3c47e6888c686ca9e6b74d9eee6692c94c9de6b3a7eed68a2a27e027a947",
                // V14, from `git show 3f95eff:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by harvest#53 Phase B;
                // this artifact moves only because `harvest-common` is
                // compiled into it.
                "57af8e42fb73260f5b38e9fc27116eaa9e4183b464c8b921e971adfb4dff72db",
                // V15, from `git show 3f3ef7b:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by harvest#53 Phase C,
                // which is this contract's own change: receipted complaints,
                // and the record addressed by the store key. The last
                // generation addressed by an RSA key and the Ghost Key.
                "78ae80d2bcb3e80299a977da3a437a44cced8b74367f53d24e407c2b171d362e",
                // V16, from `git show 52afb47:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by harvest#70; this
                // artifact moves only because `harvest-common` is compiled
                // into it. The first generation addressed by the store key.
                "68543c8c1e29a968046ffe3392fb767576aa6a950c6a835d6eb97e8d989e0230",
                // V17, from `git show f9558cd:ui/public/contracts/\
                // reputation_contract.wasm`. Superseded by instant checkout;
                // this artifact moves only because `harvest-common` is
                // compiled into it.
                "492c6e74953058477ec0cb736a1ae2f8d751b858e0df8c3176274599d9f1b8df",
            ],
        ),
        (
            "mailbox",
            &[
                "db0b1c286442209e76eb7f507d945803ae9ebf6582e9f1b2714d57d7b03703cc",
                "a2819d2967e92510d0e1b7a5ece5c2261fbd04f4ec8b4fbdabd6f58d2ff0ea9d",
                "99fc27fab5a87d274fb32a5772a4f670cad6821700a7e4c54eaec783c6aa1358",
                "61154e38ca91b5dbf0e4c1c3fa5ad36b4ed56f058dbc8418d20781213e613f4e",
                "a00fd23796d2d87c6652749ac2365a94bf060f27f5fbe5e70929cc6635c19433",
                // V6, from `git show 94a3fd1:ui/public/contracts/mailbox_contract.wasm`.
                "e49cb3038b321a895850adcf594e09b6a5a698b7ba469a991a529910493628dc",
                // V7, from `git show d9cddad:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by the 2026-09-05 correctness review; see the
                // registry entry for the per-artifact causes.
                "2eb1403aa35b94b8c6a0cbf252c7858e07b704740b0b76d4412871a643a78afa",
                // V8, from `git show 5c33d4f:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by the buyer-to-seller messaging work; for THIS
                // artifact the cause is its own, and it is a change of
                // identity -- see the registry entry.
                "b3bb6b0fd90c0918114e8068de1e1cc9ba6b08aa89fbbf018970ccfb1a6b0f14",
                // V9, from `git show baaff9d:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by the buy flow; for THIS artifact the cause
                // is `harvest-common` gaining `order_binding_from_secret`.
                "08d0e54aceaa2a5a40226f371d3d1fd9dfd85cbd3694a7afdddb40ad89becd8f",
                // V10, from `git show 83521fc:ui/public/contracts/\
                // mailbox_contract.wasm`. Superseded by the canonical
                // set-encoding fix; for THIS artifact the cause is
                // `MailboxSummaryV2`, which is a summary and not state, so
                // nothing stored at V9 changes shape.
                "29e874557b99730efb7a863d7d393ea8f5444d066144cf354582c23c60b11404",
                // V11, from `git show f46bbf0:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by harvest#85: size-class caps instead of a
                // byte budget, and a `verify` that requires canonical state.
                "5c0145d2421ebcae41ae8ee5591907c7f015502400b939e46dcbd8f128051854",
                // V12, from `git show 5110283:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by harvest#52; this artifact moves only because
                // `harvest-common` is compiled into it.
                "f78ff5a230a63904705059cc1cb8e67dd54ee9f7a02662fa882b1557455a3913",
                // V13, from `git show bc57dac:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by harvest#93 phase 1a; this artifact moves only
                // because `harvest-common` is compiled into it.
                "21b1bbedf8ce32df123a5b7af4b675654e47aceb017fee08c12d4e5c0fbedcc6",
                // V14, from `git show 3f95eff:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by harvest#53 Phase B; this artifact moves only
                // because `harvest-common` is compiled into it.
                "fad8339c66fe289d07a7b651fef92f55aa36444862c59151523d0e68dac93cf2",
                // V15, from `git show 3f3ef7b:ui/public/contracts/mailbox_contract.wasm`.
                // Superseded by harvest#53 Phase C; this artifact moves only
                // because `harvest-common` is compiled into it.
                "397f30059eea7a5d8cc4fa4a7f364c772cbfda15ce2b62bb65db1c048b0f1d43",
                // V16, from `git show f9558cd:ui/public/contracts/mailbox_contract.wasm`
                // (unchanged since 52afb47). Superseded by instant checkout;
                // this artifact moves only because `harvest-common` is
                // compiled into it.
                "4b02a3f41d494efa2570c75fc3044f091775858566569c115a219091346087d4",
            ],
        ),
        (
            "index",
            &[
                // V1, from `git show 3f95eff:ui/public/contracts/index_contract.wasm`.
                // The index's first generation (harvest#93 phase 1c),
                // superseded by harvest#53 Phase B; this artifact moves only
                // because `harvest-common` is compiled into it.
                "0df754b5c0066bf4ed02b800a293b8eb219ff3c4178af1a0239a8cf7eec7faec",
                // V2, from `git show 3f3ef7b:ui/public/contracts/index_contract.wasm`.
                // Superseded by harvest#53 Phase C; this artifact moves only
                // because `harvest-common` is compiled into it.
                "88fe938bc67b794a497a1e9c657d527c9d857cc394259c02bb7e594000729a29",
                // V3, from `git show 52afb47:ui/public/contracts/index_contract.wasm`.
                // Superseded by harvest#70; this artifact moves only because
                // `harvest-common` is compiled into it.
                "0a21fecfdd702dea40d5ccd51d6b7ecc095e101d1c8a8801a5594c4368d60361",
                // V4, from `git show f9558cd:ui/public/contracts/index_contract.wasm`.
                // Superseded by instant checkout; this artifact moves only
                // because `harvest-common` is compiled into it.
                "e23c43c86fa12acfbed7778b8c15b22d4af87c8c0d6c673f47a5d606d9cca9e5",
            ],
        ),
    ];

    for ((name, hashes), entries) in expected.iter().zip([
        store_lineage(),
        reputation_lineage(),
        mailbox_lineage(),
        index_lineage(),
    ]) {
        let recorded: Vec<String> = entries.iter().map(|e| hex::encode(e.code_hash)).collect();
        assert_eq!(
            recorded,
            hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "{name}: the recorded generations are not the ones derived from git history"
        );
    }

    let delegate: Vec<String> = delegate_lineage()
        .iter()
        .map(|e| hex::encode(e.code_hash))
        .collect();
    assert_eq!(
        delegate,
        vec![
            "1fa5776b332464a22a99ca80d0079cf82120cfc57b195023af8bd6ec8dfd0bfd".to_string(),
            "2f805880b45c83ab25271e0da1e9528ab6a3f7e96dae730e4b5465227654877d".to_string(),
            "ddcecc5b3f1abd49194f103fec424ce6ad38f0ac8359a4bad92d9125ae43085e".to_string(),
            "57b467532105613f28829c0fac8a4d72d0a146593d6d64430892f5ce7009027a".to_string(),
            "230c2b581c4fa44de16cd9705413d099dfc5bff0634130907c1b81e0cee05c42".to_string(),
            // V6, from `git show ea94a33:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by moving the migration marker into this delegate's
            // own secret store.
            "d6a387917599b8ae3746dd41f7ad45d2cc008adb7f4f98b26156ed66032e4aec".to_string(),
            // V7, from `git show 94a3fd1:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by the per-order Bitcoin payment address, which added
            // the BIP-84 derivation module and the payment-xpub secret.
            "f6d6543524d359f54379bd9b0d79f5106a72d1d205b44b04f6375db74fde7e91".to_string(),
            // V8, from `git show d9cddad:ui/public/contracts/harvest_delegate.wasm`.
            // The first build of the payment-address work, superseded by its
            // own review fixes before it left the branch.
            "f563abc42391938ad99ea47202177acbeddd1e41d517a1b92a49a6aa03a3a6eb".to_string(),
            // V9, from `git show 4b8894b:ui/public/contracts/harvest_delegate.wasm`.
            // Note the provenance commit differs from the contracts' above: the
            // delegate was rebuilt again at 4b8894b after d9cddad, so its outgoing
            // bytes are not the ones d9cddad committed.
            // Superseded by the 2026-09-05 correctness review, principally the
            // origin gate on every request.
            "c11c732fce7c00344739cf94ec0934c45fd2fbb152d24fe7de1d353b9ee207a4".to_string(),
            // V10, from `git show 5c33d4f:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by the buyer-to-seller messaging work, which put the
            // seller's X25519 secret and the buyer's per-conversation store in
            // this delegate and added `x25519-dalek` as a real dependency.
            "907c2219b12938d45ce302e82818ca6edad0f6706affafc8da14efe65f0f3ad7".to_string(),
            // V11, from `git show baaff9d:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by the buy flow. This delegate's own change is one
            // field on an answer it already sent: `RecalledConversation`
            // gained `order_binding`, derived in `recall()` from the STORED
            // conversation secret and deliberately not from the
            // Diffie-Hellman shared secret, which the seller also holds.
            "73f5761fc6dfa2602d3b683473209a44b1f649d507c3187a05e7dcef02e051e8".to_string(),
            // V12, from `git show 84ac54e:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by removing `listing_id` from `Order` (harvest#57).
            // Codegen only: this delegate's source and wire types did not
            // change.
            "4739e01954ab57d866840f9542fe87bb35910057bcee793c0a6a27a8c9536397".to_string(),
            // V13, from `git show 5320beb:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by recovering the payment-address counter from the
            // store's published orders (harvest#77): `SetPaymentXpub` and
            // `DeriveOrderAddress` gained `published_scripts`.
            "08eac64a49dd1ca2f97421db0f022843b631b8c3b45fcd7f296f231bf9d0bd7e".to_string(),
            // V14, from `git show 1b0d3c3:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#22: `FeedbackToken` gained `entry_key`, a
            // wire type this delegate stores.
            "a1118c09466362b8b7b9edba06087126b71b08ddbd048287d04064af0e56e413".to_string(),
            // V15, from `git show 5110283:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#52: the remembered-store requests and the
            // `harvest:known_store:` secret family.
            "da3c9ca1819663314512aa08378374a88be9701a83f0034c37af9cbc81e1c7a0".to_string(),
            // V16, from `git show bc57dac:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#94: the protocol types that hold keys,
            // backup strings, the xpub and the private half of a feedback
            // token redact themselves under `Debug`. Wire unchanged.
            "4fae20e120a968fe6651529ed8eb36fa04bd98a8fcc6c52f69206cdb6fae1444".to_string(),
            // V17, from `git show 0173527:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#93 phase 1a: the store-key requests and
            // the `harvest:store_sk:` secret family.
            "4d36b2a41c7f77d99ea39d0b5bbf565d8b62b22552aeda6249d6626b70392dea".to_string(),
            // V18, from `git show 4dec675:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#123, whose successor (not V18) gained the
            // import side of the export handshake; V18 only answers exports.
            "09507e3f4f1432dd746cf4644aaa81678e25314798dc6069ce38409d1499fddd".to_string(),
            // V19, from `git show 7bc8a69:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#138: `StoreList` gained `held_store_keys`,
            // so the UI can tell a carried registration from a held key.
            "29b781b43ee9ad30a0b151fd2db719cf909179994bb6ac577bdca6608005560d".to_string(),
            // V20, from `git show 99bbd59:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#53 Phase B: it signs a despatch, and a
            // recalled conversation carries the buyer's receipt seed.
            "9917c1fbad0ed1754d25f318b8c3384db327d389219c2ed715bc5f7e4343b6c1".to_string(),
            // V21, from `git show 3f3ef7b:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#53 Phase C: the blind-signature and
            // transaction requests are gone, and nothing mints an RSA key.
            "0ab16ff67f87e11da81e179ab75481791b165d631af0a86966e2421255da3b62".to_string(),
            // V22, from `git show 52afb47:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by harvest#70: the store key also signs a listing
            // status.
            "225214b7d88fcc8e769f50f51279703f11fd5aef13f64657b4646c2af978ef19".to_string(),
            // V23, from `git show f9558cd:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by instant checkout: the delegate answers instant
            // requests in the background.
            "9463b53b02e72c444935a024ad8b05268d21eb5c6a5ead049ad88ee456a24ea1".to_string(),
        ],
    );
}

/// Every recorded delegate key is `BLAKE3(code_hash || params)` with Harvest's
/// empty parameters.
///
/// `freenet-migrate-build` already cross-checks this at build time. Re-deriving
/// it here independently is the point: the build-time check is only as good as
/// the build crate's own derivation agreeing with what the node does, and this
/// asserts the same property from the app's side of that boundary.
#[test]
fn delegate_keys_derive_from_their_code_hashes() {
    for entry in delegate_lineage() {
        assert!(
            !entry.irregular_key,
            "generation {} claims a pre-standard key; Harvest has never had one",
            entry.generation
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entry.code_hash);
        // The derivation is `blake3(code_hash || params)`, and reading it as
        // `blake3(code_hash)` is only accidentally right. Read the parameters
        // from the constant the app registers with rather than writing `&[]`
        // here: a hardcoded empty slice would keep this test passing after a
        // change that re-keyed the real delegate.
        hasher.update(harvest_common::delegate::DELEGATE_PARAMETERS);
        assert_eq!(
            *hasher.finalize().as_bytes(),
            entry.delegate_key,
            "generation {}'s recorded delegate key is not the one its code hash derives",
            entry.generation
        );
    }
}

/// The bundled artifacts' code hashes are NOT in the registries.
///
/// The registries list superseded generations only; the live one is derived
/// from the WASM the build ships. A current hash appearing in one means either
/// the entry was appended and the artifact never rebuilt, or the change that
/// moved it was reverted -- and in both cases the probe would walk to its own
/// instance, find its own state, and report a successful migration having
/// moved nothing.
///
/// `scripts/check-code-hashes.sh` asserts the same thing in CI against a fresh
/// build. This asserts it against the COMMITTED artifacts, which are what
/// `include_bytes!` actually ships, so the two cover different failures: CI's
/// catches a source change without a rebuild, this catches a committed file
/// that names a generation already retired.
///
/// Mutated red by appending the live store hash to `legacy/store_contract.toml`.
#[test]
fn no_bundled_artifact_is_recorded_as_superseded() {
    /// (artifact name, the bytes `include_bytes!` ships, its superseded hashes)
    type Bundled<'a> = (&'a str, &'a [u8], Vec<[u8; 32]>);

    let bundled: &[Bundled<'_>] = &[
        (
            "store",
            include_bytes!("../../public/contracts/store_contract.wasm"),
            store_lineage().iter().map(|e| e.code_hash).collect(),
        ),
        (
            "reputation",
            include_bytes!("../../public/contracts/reputation_contract.wasm"),
            reputation_lineage().iter().map(|e| e.code_hash).collect(),
        ),
        (
            "mailbox",
            include_bytes!("../../public/contracts/mailbox_contract.wasm"),
            mailbox_lineage().iter().map(|e| e.code_hash).collect(),
        ),
        (
            "delegate",
            include_bytes!("../../public/contracts/harvest_delegate.wasm"),
            delegate_lineage().iter().map(|e| e.code_hash).collect(),
        ),
    ];

    for (name, wasm, superseded) in bundled {
        let hash: [u8; 32] = *blake3::hash(wasm).as_bytes();
        assert!(
            !superseded.contains(&hash),
            "the bundled {name} artifact's code hash {} is recorded as SUPERSEDED. \
             Either it was never rebuilt after the entry was added, or the change \
             that moved it was reverted.",
            hex::encode(hash)
        );
    }
}

/// The contract code hash the migration derives ids from is the one the rest
/// of the app publishes under.
///
/// `store_ops` builds a `ContractCode` and takes its hash; the migration
/// hashes the same bytes with blake3 directly. If those two ever disagreed,
/// every id the probe derives would name a contract nobody else uses -- and
/// nothing else in the repo compares them.
#[test]
fn the_migrations_code_hash_matches_the_one_contracts_are_published_under() {
    for wasm in [
        include_bytes!("../../public/contracts/store_contract.wasm").as_slice(),
        include_bytes!("../../public/contracts/reputation_contract.wasm").as_slice(),
        include_bytes!("../../public/contracts/mailbox_contract.wasm").as_slice(),
    ] {
        let via_stdlib = *ContractCode::from(wasm.to_vec()).hash();
        let via_blake3: [u8; 32] = *blake3::hash(wasm).as_bytes();
        assert_eq!(
            AsRef::<[u8]>::as_ref(&via_stdlib),
            &via_blake3[..],
            "stdlib's contract code hash and blake3 of the same bytes disagree"
        );
    }
}

/// Each generation derives a DIFFERENT instance id, and none of them collides
/// with the current one.
///
/// This is the property that makes the whole exercise necessary: the same
/// seller, the same parameters, four addresses. It also catches a registry
/// with a duplicated hash, which would otherwise waste a probe hop on an id
/// already asked for.
#[test]
fn each_generation_is_a_different_instance() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let unique: HashSet<_> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "two generations derive the same id"
    );

    let current_hash: [u8; 32] =
        *blake3::hash(include_bytes!("../../public/contracts/store_contract.wasm")).as_bytes();
    let current = current_id(&current_hash, &params);
    assert!(
        !ids.contains(&current),
        "a predecessor derives the current instance id"
    );
}

// --- reputation: the RSA generations (harvest#53 Phase C) ----------------

fn store_vk() -> VerifyingKey {
    SigningKey::from_bytes(&[61u8; 32]).verifying_key()
}

fn locators(rsa: Vec<Vec<u8>>, registered: Option<ContractInstanceId>) -> ReputationLocators {
    ReputationLocators {
        store_key: store_vk(),
        ghost_key: seller_vk(),
        rsa_public_keys: rsa,
        registered_id: registered,
        current_id: current_reputation_id(),
    }
}

/// The store-key record under this build's reputation code.
fn current_reputation_id() -> ContractInstanceId {
    crate::gateway::store_ops::reputation_instance_id(&store_vk()).expect("derive")
}

/// **A registration naming the current record has no predecessor** (review
/// round 1, P2-7): every store this build creates registers the current id,
/// and probing it as a predecessor GETs our own record and reports a false
/// recovery. Red if the early return is removed.
#[test]
fn a_registration_naming_the_current_record_walks_nothing() {
    let ids = reputation_candidate_ids(&locators(
        vec![vec![1u8; 40]],
        Some(current_reputation_id()),
    ))
    .expect("derive");
    assert!(ids.is_empty(), "no predecessor to probe: {ids:?}");
    // And a registration naming something else still walks.
    let other = ContractInstanceId::new([9u8; 32]);
    let ids = reputation_candidate_ids(&locators(vec![], Some(other))).expect("derive");
    assert!(ids.contains(&other));
    assert!(!ids.contains(&current_reputation_id()));
}

/// The id an RSA generation's record was published at, derived here with the
/// field set the RSA generations' `ReputationParameters` had.
fn rsa_generation_id(code_hash: &[u8; 32], der: &[u8]) -> ContractInstanceId {
    #[derive(serde::Serialize)]
    struct Old {
        rsa_public_key_der: Vec<u8>,
        owner_verifying_key: VerifyingKey,
    }
    let params = encode_params(&Old {
        rsa_public_key_der: der.to_vec(),
        owner_verifying_key: seller_vk(),
    })
    .expect("encode");
    current_id(code_hash, &params)
}

/// The superseded store-key generations (V16 on), newest first, each at the
/// address it was published at for `store_vk()`: derived here with the field
/// set V16 shipped with, independently of `reputation_params`, so a change to
/// `ReputationParameters` that the migration does not split for turns these
/// tests red rather than agreeing with itself (harvest#125 review).
fn store_key_generation_ids() -> Vec<ContractInstanceId> {
    #[derive(serde::Serialize)]
    struct V16 {
        store_key: VerifyingKey,
    }
    let params = encode_params(&V16 {
        store_key: store_vk(),
    })
    .unwrap();
    let mut rows: Vec<_> = reputation_lineage()
        .iter()
        .filter(|e| e.generation > LAST_RSA_REPUTATION_PARAM_GENERATION)
        .collect();
    rows.sort_by_key(|e| core::cmp::Reverse(e.generation));
    rows.iter()
        .map(|e| current_id(&e.code_hash, &params))
        .collect()
}

/// **Every RSA generation is probed at the address it was published at,
/// for every RSA key known, and at no store-key address.** Deriving them from
/// today's parameters would probe addresses that never existed and report a
/// clean "nothing to migrate" -- the silent failure the store split exists
/// for. Red if the RSA generations are derived from `reputation_params`.
#[test]
fn rsa_generations_are_probed_under_their_own_encoding() {
    let record = vec![1u8; 40];
    let per_device = vec![2u8; 40];
    let ids = reputation_candidate_ids(&locators(vec![record.clone(), per_device.clone()], None))
        .expect("derive");
    let rsa_rows: Vec<_> = reputation_lineage()
        .iter()
        .filter(|e| e.generation <= LAST_RSA_REPUTATION_PARAM_GENERATION)
        .collect();
    assert!(
        !rsa_rows.is_empty(),
        "precondition: the registry has RSA rows"
    );
    for row in &rsa_rows {
        for der in [&record, &per_device] {
            assert!(
                ids.contains(&rsa_generation_id(&row.code_hash, der)),
                "V{} under one of the RSA keys is missing",
                row.generation
            );
        }
        let store_key_id = current_id(
            &row.code_hash,
            &encode_params(&reputation_params(&store_vk())).unwrap(),
        );
        assert!(
            !ids.contains(&store_key_id),
            "V{} was derived under the store key, where it never lived",
            row.generation
        );
    }
    // Newest first, as `NewestFirst` asks: the store-key generations, then
    // the newest RSA generation.
    let store_key_ids = store_key_generation_ids();
    assert_eq!(ids[..store_key_ids.len()], store_key_ids[..]);
    let newest = rsa_rows.iter().max_by_key(|e| e.generation).unwrap();
    assert_eq!(
        ids[store_key_ids.len()],
        rsa_generation_id(&newest.code_hash, &record)
    );
}

/// With no RSA key known, the RSA generations contribute nothing (the
/// store-key generations still do, derived from the store key alone), and
/// the registered id -- the exact record this seller made -- is still
/// tried, once, and last.
#[test]
fn the_registered_reputation_id_is_tried_once_and_last() {
    let registered = ContractInstanceId::new([77u8; 32]);
    let ids = reputation_candidate_ids(&locators(Vec::new(), Some(registered))).expect("derive");
    let mut expected = store_key_generation_ids();
    expected.push(registered);
    assert_eq!(
        ids, expected,
        "no RSA key, so only the store-key generations and the registered id"
    );

    let der = vec![3u8; 40];
    let newest = reputation_lineage()
        .iter()
        .filter(|e| e.generation <= LAST_RSA_REPUTATION_PARAM_GENERATION)
        .max_by_key(|e| e.generation)
        .unwrap();
    let derived = rsa_generation_id(&newest.code_hash, &der);
    let ids =
        reputation_candidate_ids(&locators(vec![der.clone()], Some(derived))).expect("derive");
    assert_eq!(
        ids.iter().filter(|id| **id == derived).count(),
        1,
        "a registered id the derivation already produced is not probed twice"
    );
    let ids = reputation_candidate_ids(&locators(vec![der], Some(registered))).expect("derive");
    assert_eq!(ids.last(), Some(&registered));
}

/// The current record is the store key's, and no candidate is it.
#[test]
fn no_reputation_candidate_is_the_current_record() {
    let current_hash: [u8; 32] = *blake3::hash(include_bytes!(
        "../../public/contracts/reputation_contract.wasm"
    ))
    .as_bytes();
    let current = current_id(
        &current_hash,
        &encode_params(&reputation_params(&store_vk())).unwrap(),
    );
    let ids = reputation_candidate_ids(&locators(vec![vec![1u8; 40]], None)).expect("derive");
    assert!(!ids.contains(&current));
}

// --- the store's parameter-encoding splits ------------------------------

/// The bytes generations V2..=V5 were published under, reconstructed here
/// independently of `migrate.rs` so the two have to agree.
fn legacy_store_param_bytes(vk: &VerifyingKey) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Old {
        seller_verifying_key: VerifyingKey,
        trusted_bitcoin_bridges: Vec<[u8; 32]>,
        bitcoin_address_code_hash: Option<[u8; 32]>,
    }
    harvest_common::to_cbor(&Old {
        seller_verifying_key: *vk,
        trusted_bitcoin_bridges: Vec::new(),
        bitcoin_address_code_hash: None,
    })
    .expect("encode legacy store parameters")
}

/// The bytes V1 and V6..=V16 were published under: the whole key, before
/// harvest#52. Reconstructed independently of `migrate.rs`, likewise.
fn whole_key_store_param_bytes(vk: &VerifyingKey) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct WholeKey {
        seller_verifying_key: VerifyingKey,
    }
    harvest_common::to_cbor(&WholeKey {
        seller_verifying_key: *vk,
    })
    .expect("encode whole-key store parameters")
}

/// The parameters each shape addresses `vk`'s store under.
fn store_params_for_shape(vk: &VerifyingKey, shape: StoreParamShape) -> Parameters<'static> {
    match shape {
        StoreParamShape::WholeKeyWithBitcoinFields => {
            Parameters::from(legacy_store_param_bytes(vk))
        }
        StoreParamShape::WholeKey => Parameters::from(whole_key_store_param_bytes(vk)),
        StoreParamShape::Code => encode_params(&store_params(vk)).expect("encode"),
    }
}

const SHAPES: [StoreParamShape; 3] = [
    StoreParamShape::WholeKey,
    StoreParamShape::WholeKeyWithBitcoinFields,
    StoreParamShape::Code,
];

/// The premise: the three encodings really are different, so probing an old
/// generation with today's parameters is a search of the wrong address rather
/// than a harmless re-encoding.
///
/// Without this the tests below could pass vacuously.
#[test]
fn the_store_parameter_encodings_actually_differ() {
    let vk = seller_vk();
    let encodings: Vec<Vec<u8>> = SHAPES
        .iter()
        .map(|shape| store_params_for_shape(&vk, *shape).as_ref().to_vec())
        .collect();
    for i in 0..encodings.len() {
        for j in 0..i {
            assert_ne!(
                encodings[i], encodings[j],
                "{:?} and {:?} must be different bytes, or there is nothing to split on",
                SHAPES[i], SHAPES[j]
            );
        }
    }
}

/// Every already-published store generation must be probed at the address it
/// actually has.
///
/// `freenet_migrate::ContractLineageEntry` carries only a code hash, so the
/// crate derives every predecessor id from the CURRENT parameters. That is
/// right until the parameter encoding changes, and then it fails silently:
/// the probe walks addresses that never existed, every one comes back
/// `NotFound`, and the sweep reports a clean "nothing to migrate" over a
/// seller's whole store.
///
/// Mutated red by deriving the lineage with `NewestFirst::from_lineage` and
/// today's parameters -- i.e. by not making the split at all, which is what
/// the code did before `store_candidates` existed.
#[test]
fn superseded_store_generations_are_probed_under_their_own_parameter_encoding() {
    let vk = seller_vk();
    let candidates = store_candidate_ids(&vk).expect("candidates");
    assert_eq!(
        candidates.len(),
        store_lineage().len(),
        "every recorded generation must be probed"
    );

    // Newest-first, each generation derived under the encoding IT was
    // published with. Which shape each generation has is asserted against
    // the artifacts in
    // `each_store_generation_is_derived_under_the_encoding_it_shipped_with`;
    // this test is about the ordering and completeness of the walk, so it is
    // entitled to ask the predicate.
    let mut newest_first: Vec<_> = store_lineage().iter().collect();
    newest_first.sort_by_key(|e| std::cmp::Reverse(e.generation));

    let mut seen = HashSet::new();
    for (entry, got) in newest_first.iter().zip(&candidates) {
        let shape = store_param_shape(entry.generation);
        seen.insert(format!("{shape:?}"));
        let expected = current_id(&entry.code_hash, &store_params_for_shape(&vk, shape));
        for other in SHAPES.iter().filter(|s| **s != shape) {
            assert_ne!(
                expected,
                current_id(&entry.code_hash, &store_params_for_shape(&vk, *other))
            );
        }
        assert_eq!(
            *got, expected,
            "generation {} must be probed at its real address, under the {shape:?} encoding",
            entry.generation,
        );
    }

    // Both recorded shapes have to be exercised, or this test stops being
    // about the split at all. (No recorded generation is on the code shape
    // yet: the current build is the first, and it is never recorded.)
    assert!(
        seen.contains("WholeKey") && seen.contains("WholeKeyWithBitcoinFields"),
        "the lineage must span the parameter splits for this test to mean anything: {seen:?}"
    );
}

/// Which encoding each store generation was ACTUALLY published under, taken
/// from the artifacts rather than from the code under test.
///
/// | generation | built at  | `StoreParameters`      | cbor  |
/// |------------|-----------|------------------------|-------|
/// | V1         | `ded0e3a` | whole key              | 56 B  |
/// | V2..=V5    | `78d1020`..`9e3e1fb` | + 2 Bitcoin fields | 109 B |
/// | V6..=V16   | `ea94a33`..`5110283` | whole key   | 56 B  |
/// | current    | this build | code (harvest#52)     | 29 B  |
///
/// The two Bitcoin fields were added by `7c192d2` (first shipped in the V2
/// artifact) and removed again by `fc760ed` (first shipped in the V6
/// artifact). Each "built at" commit is the one whose committed
/// `ui/public/contracts/store_contract.wasm` hashes to that generation's
/// `code_hash` in `legacy/store_contract.toml`, so the mapping is checkable
/// with `git show <commit>:ui/public/contracts/store_contract.wasm | b3sum`.
///
/// Written out per generation on purpose. Deriving the expectation from
/// `store_param_shape` -- as the test above does, for the ordering property
/// it is actually about -- cannot catch the boundary being wrong, because it
/// asks the code under test what the answer is. V1 once sat on the wrong
/// side of a boundary for exactly that reason.
const PUBLISHED_UNDER: &[(u32, StoreParamShape)] = {
    use StoreParamShape::{Code, WholeKey, WholeKeyWithBitcoinFields};
    &[
        (1, WholeKey),
        (2, WholeKeyWithBitcoinFields),
        (3, WholeKeyWithBitcoinFields),
        (4, WholeKeyWithBitcoinFields),
        (5, WholeKeyWithBitcoinFields),
        (6, WholeKey),
        // V7: the 2026-09-05 review. `StoreParameters` changed VISIBILITY
        // only -- `pub` to `pub(crate)` plus a constructor -- which moves the
        // code hash like any `common` edit but leaves the encoding at 56
        // bytes.
        (7, WholeKey),
        // V8: `StoreInfoV1` gained a field, which is STATE and not
        // parameters; verified against V7 rather than assumed.
        (8, WholeKey),
        // V9: the buy flow. Record identities changed, all STATE.
        (9, WholeKey),
        // V10: the canonical set-encoding fix, `reputation.rs` and
        // `mailbox.rs` only; `cargo make code-hashes` still reported 56B.
        (10, WholeKey),
        // V11: a `freenet-bitcoin-common` bump with no source change; 56B.
        (11, WholeKey),
        // V12: `listing_id` removed from `Order` (harvest#57); 56B.
        (12, WholeKey),
        // V13: `payment_instructions` removed from `StoreInfoV1`; 56B.
        (13, WholeKey),
        // V14: the payment-window rule (harvest#77); 56B.
        (14, WholeKey),
        // V15: harvest#26 and #55; 56B.
        (15, WholeKey),
        // V16: the build at `5110283`, the last before harvest#52 made the
        // parameter a code. Still the whole key, 56B per
        // `scripts/check-code-hashes.sh` on that commit.
        (16, WholeKey),
        // V17: the build at `bc57dac` (harvest#52), the first addressed by
        // the store code, 29B.
        (17, Code),
        // V18: the build at `f6afc74` (#95). Still the code, 29B, and still
        // the code of the seller's GHOST KEY: harvest#93 changed whose key
        // the code is a prefix of, not the parameter encoding, so a Ghost
        // Key's own probe derives it exactly as it derives V17.
        (18, Code),
        // V19: the phase-1 build published 2026-09-21 (through `3f95eff`),
        // the first owned by a store key. Still the code, 29B; the code is
        // now the store key's, and the probe derives it from that key.
        (19, Code),
        // V20: harvest#53 Phase B (`3f3ef7b`). Still the store key's code,
        // 29B.
        (20, Code),
        // V21: harvest#53 Phase C (`52afb47`). Still the store key's code,
        // 29B.
        (21, Code),
        // V22: harvest#70 (`f9558cd`). Still the store key's code, 29B.
        (22, Code),
    ]
};

/// V1 is derived under the whole-key encoding, not the three-field one, and
/// V16 is the last generation that is.
///
/// V1 is the first generation ever published to the network (`4d7ad3c3...`,
/// the registry's first row), so getting it wrong means the migration probe
/// cannot find the store that exists -- and reports a clean "nothing to
/// migrate" while doing it. Mutated red by restoring the single threshold the
/// band replaced (`generation <= LAST_LEGACY_STORE_PARAM_GENERATION`), which
/// buckets V1 as three-field because generations are 1-based.
#[test]
fn each_store_generation_is_derived_under_the_encoding_it_shipped_with() {
    let vk = seller_vk();

    // The sizes named in `legacy/store_contract.toml` and in
    // `harvest_common::address`. If any moves, the table above is about
    // something else.
    let size = |shape| store_params_for_shape(&vk, shape).as_ref().len();
    assert_eq!(size(StoreParamShape::WholeKeyWithBitcoinFields), 109);
    assert_eq!(size(StoreParamShape::WholeKey), 56);
    assert_eq!(
        size(StoreParamShape::Code),
        29,
        "current StoreParameters cbor"
    );

    assert_eq!(
        PUBLISHED_UNDER.len(),
        store_lineage().len(),
        "the table must cover every recorded generation, and only those"
    );

    let candidates = store_candidate_ids(&vk).expect("candidates");
    let mut newest_first: Vec<_> = store_lineage().iter().collect();
    newest_first.sort_by_key(|e| std::cmp::Reverse(e.generation));

    for (entry, got) in newest_first.iter().zip(&candidates) {
        let (_, shape) = PUBLISHED_UNDER
            .iter()
            .find(|(g, _)| *g == entry.generation)
            .unwrap_or_else(|| panic!("generation {} is not in the table", entry.generation));

        assert_eq!(
            *got,
            current_id(&entry.code_hash, &store_params_for_shape(&vk, *shape)),
            "generation {} was published under the {shape:?} encoding",
            entry.generation,
        );

        // And the predicate the derivation actually consults has to agree
        // with the table, so a future edit to one of them cannot drift from
        // the other unnoticed.
        assert_eq!(
            store_param_shape(entry.generation),
            *shape,
            "the generation bands disagree with the artifacts for V{}",
            entry.generation
        );
    }

    // A generation recorded after V16 was published under the code.
    assert_eq!(
        store_param_shape(LAST_WHOLE_KEY_STORE_PARAM_GENERATION + 1),
        StoreParamShape::Code
    );
}

/// **The whole-key encoding, as literal bytes.** V1 and V6..=V16 live at
/// addresses derived from exactly these bytes for the key of seed `[1; 32]`,
/// taken from `main` before harvest#52 (the parameters `main`'s
/// `StoreParameters::new` produced). Every other test here rebuilds the
/// bytes through the same serde path as the code under test, so a
/// dependency change to how a `VerifyingKey` or a struct encodes would move
/// both sides together and pass; this one would not.
#[test]
fn the_whole_key_encoding_is_the_bytes_main_published_under() {
    const MAIN_SEED_1_PARAMS: &str = "a17473656c6c65725f766572696679696e675f6b657958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    let vk = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
    assert_eq!(
        hex::encode(whole_key_store_params_cbor(&vk).expect("encode").as_ref()),
        MAIN_SEED_1_PARAMS
    );
    assert_eq!(
        hex::encode(whole_key_store_param_bytes(&vk)),
        MAIN_SEED_1_PARAMS
    );
}

/// `migrate`'s address arithmetic agrees with the one the NODE uses.
///
/// Everything in this module derives instance ids with
/// `freenet_migrate::contract_id_from_code_hash`. The node derives them by
/// building a `WrappedContract` and taking its key. If those two ever
/// disagreed, every id the probe walks would be wrong -- and wrong in the
/// silent direction, since a walk to an address that was never written just
/// reports "nothing to migrate".
///
/// Every parameter encoding is checked, because the whole point of
/// `store_candidate_ids` is that it addresses generations under different
/// ones; and so is the address a store code resolves to from a link
/// (`store_ops::store_instance_id`), which is the one a buyer reaches.
#[test]
fn migrate_addresses_agree_with_the_stdlib_key_derivation() {
    use freenet_stdlib::prelude::WrappedContract;
    use std::sync::Arc;

    let wasm = crate::gateway::store_ops::STORE_CONTRACT_WASM;
    let code_hash: [u8; 32] = {
        let hash = *ContractCode::from(wasm.to_vec()).hash();
        let bytes: &[u8] = hash.as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    };

    let vk = seller_vk();
    let mut ids = Vec::new();
    for shape in SHAPES {
        let params = store_params_for_shape(&vk, shape);
        let ours = current_id(&code_hash, &params);
        let theirs = *WrappedContract::new(Arc::new(ContractCode::from(wasm.to_vec())), params)
            .key()
            .id();
        assert_eq!(
            ours, theirs,
            "under the {shape:?} parameter encoding, migrate's derivation and the node's \
             must name the same instance"
        );
        ids.push(ours);
    }
    assert_eq!(
        crate::gateway::store_ops::store_instance_id(&store_params(&vk)).expect("derive"),
        ids[2],
        "a store code read from a link resolves to the address the seller's PUT uses"
    );

    // Non-vacuous: the encodings must actually produce different addresses,
    // or the assertions above would hold for a derivation that ignored its
    // parameters entirely.
    let distinct: HashSet<_> = ids.iter().collect();
    assert_eq!(
        distinct.len(),
        ids.len(),
        "each encoding must address a different instance"
    );
}

/// The parameter structs keep their fields crate-private.
///
/// # What holds the invariant, and what this adds
///
/// "Contract parameters are derived in exactly one place" is enforced by the
/// COMPILER, not by this test: the fields are `pub(crate)` and the only way to
/// build one of these structs outside `harvest-common` is its `new`. A second
/// derivation does not compile, whatever it is spelled.
///
/// This test guards the one step that would silently give that up -- making a
/// field `pub` again. It exists because the check it replaces tried to hold
/// the whole invariant by scraping source, and was beaten by
/// `use StoreParameters as SP`, which is an ordinary refactor rather than an
/// exotic evasion.
///
/// # Be precise about what a green result here means
///
/// It means these three files do not contain the exact strings below. It is a
/// substring match: unusual spacing, a field rename, or a fourth parameter
/// struct added elsewhere all slip past it. It is a cheap guard on a change
/// that would otherwise be easy to miss in review, NOT the thing that makes
/// the invariant true. Reading a scrape as more than it is, is what put this
/// comment here.
#[test]
fn contract_parameter_fields_stay_crate_private() {
    for (file, source, fields) in [
        (
            "common/src/store.rs",
            include_str!("../../../common/src/store.rs"),
            &["pub seller_verifying_key"][..],
        ),
        (
            "common/src/mailbox.rs",
            include_str!("../../../common/src/mailbox.rs"),
            &["pub owner_verifying_key"][..],
        ),
        (
            "common/src/reputation.rs",
            include_str!("../../../common/src/reputation.rs"),
            &["pub rsa_public_key_der", "pub owner_verifying_key"][..],
        ),
    ] {
        for field in fields {
            assert!(
                !source.contains(field),
                "{file} declares `{field}` public. These fields are hashed into a \
                 contract's address, and a public field lets a second derivation be \
                 written outside `harvest-common` -- which is how the probe came to \
                 look for V1 at an address it never had. Construct through `new`."
            );
        }
    }
}

// --- sealing ------------------------------------------------------------

/// Only a complete recovery may seal.
///
/// Mutated red five ways: `Recovered`-with-truncation, `Recovered`-with-
/// unresolved, `SeedLocal`, `Indeterminate` and `NoLegacy` each turned into a
/// `Seal` in `seal_decision` and each caught here.
///
/// The wildcard arm is NOT among them, and cannot be: `Outcome` is
/// `#[non_exhaustive]`, so today every variant is named and the wildcard is
/// unreachable. Inverting it to `Seal::Seal` leaves this test green -- which
/// is exactly the defence-in-depth guard that nothing exercises, so
/// `the_wildcard_outcome_arm_retries` pins it by reading the source instead.
#[test]
fn only_a_complete_recovery_seals() {
    let src = ContractInstanceId::new([1u8; 32]);
    let other = ContractInstanceId::new([2u8; 32]);
    let local = StoreStateV1::default();

    assert_eq!(
        seal_decision(&Outcome::Recovered {
            merged: local.clone(),
            source: src,
            truncated_fold: false,
            unresolved: Vec::new(),
        }),
        Seal::Seal
    );

    // A fold cut short by the hop cap is missing the oldest generations.
    assert_eq!(
        seal_decision(&Outcome::Recovered {
            merged: local.clone(),
            source: src,
            truncated_fold: true,
            unresolved: Vec::new(),
        }),
        Seal::Retry
    );

    // A generation that never answered may hold anything.
    assert_eq!(
        seal_decision(&Outcome::Recovered {
            merged: local.clone(),
            source: src,
            truncated_fold: false,
            unresolved: vec![other],
        }),
        Seal::Retry
    );

    assert_eq!(
        seal_decision(&Outcome::SeedLocal {
            local: local.clone()
        }),
        Seal::Retry,
        "an all-absent walk must never seal: absence on Freenet is unauthenticated"
    );

    assert_eq!(
        seal_decision(&Outcome::Indeterminate {
            local: local.clone(),
            unresolved: vec![other],
        }),
        Seal::Retry
    );

    assert_eq!(seal_decision(&Outcome::NoLegacy { local }), Seal::Retry);
}

// --- the probe, end to end ----------------------------------------------

/// A populated newest generation is recovered, and that recovery seals.
///
/// The candidate answered from is the NEWEST, which is what the newest-first
/// ordering is for.
#[test]
fn a_populated_predecessor_is_recovered_and_seals() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("a lineage with rows");
    let populated = store_with(&[signed_listing("Coffee")]);
    let bytes = store_bytes(&populated);

    let (outcome, seal) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(bytes.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { merged, source, .. } => {
            assert_eq!(source, newest, "recovered from the wrong generation");
            assert_eq!(merged.listings.listings.len(), 1);
            assert_eq!(merged.listings.listings[0].listing.title, "Coffee");
        }
        other => panic!("expected a recovery, got {}", describe(&other)),
    }
    assert_eq!(seal, Seal::Seal);
}

/// **The owner fill-in never reassigns a store.** A local snapshot owned by
/// a DIFFERENT key (the case where another key holds the seller's address)
/// is merged with the seller's whole-key predecessor. The fill-in names the
/// seller only where a state names nobody, so the snapshot stays the other
/// key's: its records are not re-attributed to the seller, and the merge
/// decides between the two owners by the contract's own rule.
///
/// Mutated red by dropping the `is_none()` guard in `name_whole_key_owner`,
/// which the review found survived every other test. It is the FIRST
/// assertion, the direct call, that kills that mutation. The merge half below
/// passes either way (with the guard gone the snapshot is renamed to the
/// seller and then refused by its signatures instead of by its owner), and
/// is kept because it pins what the fold does with such a snapshot, not
/// because it guards the fill-in. Do not trim the first assertion as
/// redundant with it.
#[test]
fn the_owner_fill_in_does_not_reassign_a_store_another_key_owns() {
    let other = SigningKey::from_bytes(&[0x3cu8; 32]);
    let mut foreign = StoreStateV1 {
        owner: Some(other.verifying_key()),
        ..Default::default()
    };
    foreign.listings.listings = vec![{
        let listing = Listing {
            checkout: None,
            choices: Vec::new(),
            id: ListingId([0u8; 32]),
            title: "Not the seller's".to_string(),
            description: String::new(),
            kind: ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("ts"),
        }
        .with_derived_id();
        let scoped = ghostkey_common::ScopedPayload {
            requestor: harvest_common::expected_harvest_requestor(),
            payload: harvest_common::to_cbor(&listing).expect("encode"),
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("encode");
        AuthorizedListing {
            signature: other.sign(&scoped_payload).to_bytes().to_vec(),
            listing,
            scoped_payload,
            certificate_pem: String::new(),
        }
    }];

    assert_eq!(
        crate::migrate::name_whole_key_owner(foreign.clone(), &seller_vk()).owner,
        Some(other.verifying_key()),
        "a state that names an owner keeps it"
    );

    // Precondition for the refusal asserted below: the other key outranks
    // the seller, so its snapshot is SENT and refused. The other way round
    // it would simply lose the merge and send nothing, which is also right
    // (its records are not the seller's) but reports nothing.
    assert!(other.verifying_key().as_bytes() < seller_vk().as_bytes());

    take_uncarried();
    let recovered = store_with(&[signed_listing("Coffee")]);
    let merged = store_ops().merge_with_local(recovered, &foreign);
    assert_eq!(
        merged.owner,
        Some(seller_vk()),
        "the seller's recovered store"
    );
    assert!(
        merged
            .listings
            .listings
            .iter()
            .all(|l| l.listing.title != "Not the seller's"),
        "no record of the other key's is carried as the seller's"
    );
    assert!(
        merged
            .listings
            .listings
            .iter()
            .all(|l| l.verify(&seller_vk()).is_ok()),
        "every carried record verifies against the owner it is carried under"
    );
    // The other key does not share the seller's code, so the contract's own
    // rule refuses its snapshot, and the fold says so rather than dropping it
    // quietly.
    let lost = take_uncarried();
    assert_eq!(lost.len(), 1, "{lost:?}");
    assert!(lost[0].contains("could not be merged"), "{}", lost[0]);
}

/// **harvest#52, end to end.** A seller's store at V16 -- addressed by the
/// whole key, its state naming no owner -- is found at the address the
/// whole-key encoding derives, and carried into a state the CODE-addressed
/// contract accepts, owned by that seller.
///
/// Both halves are needed, and each fails silently without the other: probed
/// under today's code parameters the V16 address is one it never had, and
/// carried without an owner every record is refused by the new contract.
#[test]
fn a_whole_key_store_is_found_and_carried_into_the_code_addressed_contract() {
    use freenet_scaffold::ComposableState;
    let vk = seller_vk();
    let v16 = store_lineage()
        .iter()
        .find(|e| e.generation == LAST_WHOLE_KEY_STORE_PARAM_GENERATION)
        .expect("V16 is recorded");
    let v16_address = current_id(
        &v16.code_hash,
        &Parameters::from(whole_key_store_param_bytes(&vk)),
    );
    let mut predecessor = store_with(&[signed_listing("Coffee")]);
    predecessor.info = signed_store_info(1);
    assert_eq!(predecessor.owner, None, "a whole-key state names no owner");
    let bytes = store_bytes(&predecessor);

    let session = ProbeSession::start_with_candidates(
        store_ops(),
        StoreStateV1::default(),
        store_candidates(&vk).expect("candidates"),
        fold_all_policy(),
    );
    let (outcome, _) = run(session, |id| {
        if id == v16_address {
            Answer::State(bytes.clone())
        } else {
            Answer::Absent
        }
    });
    let Outcome::Recovered { merged, source, .. } = outcome else {
        panic!("expected a recovery, got {}", describe(&outcome));
    };
    assert_eq!(source, v16_address);
    assert_eq!(
        merged.owner,
        Some(vk),
        "the fold names the seller as the owner"
    );
    assert_eq!(merged.listings.listings.len(), 1);
    merged
        .verify(&merged, &store_params(&vk))
        .expect("the carried store is one the code-addressed contract accepts");
}

/// **A code-addressed generation carries forward as it is.** V17 is the
/// first store generation addressed by the store code, and the change that
/// superseded it (dropping the diagnostic-only related-contract fetch) left
/// state, validity and parameters alone. So a seller's V17 store, which
/// already names its owner, is found at the address today's CODE parameters
/// derive and verifies against the current contract unchanged.
///
/// Mutated red by deriving V17 under the whole-key encoding (moving
/// `LAST_WHOLE_KEY_STORE_PARAM_GENERATION` to 17): the probe then asks for an
/// address V17 never had and recovers nothing.
#[test]
fn a_code_addressed_store_is_carried_into_the_next_generation() {
    use freenet_scaffold::ComposableState;
    let vk = seller_vk();
    let v17 = store_lineage()
        .iter()
        .find(|e| e.generation == 17)
        .expect("V17 is recorded");
    let v17_address = current_id(&v17.code_hash, &store_params_encoded());
    let mut predecessor = store_with(&[signed_listing("Coffee")]);
    predecessor.info = signed_store_info(1);
    predecessor.owner = Some(vk);
    predecessor
        .verify(&predecessor, &store_params(&vk))
        .expect("the fixture is a state V17 accepted");
    let bytes = store_bytes(&predecessor);

    let session = ProbeSession::start_with_candidates(
        store_ops(),
        StoreStateV1::default(),
        store_candidates(&vk).expect("candidates"),
        fold_all_policy(),
    );
    let (outcome, _) = run(session, |id| {
        if id == v17_address {
            Answer::State(bytes.clone())
        } else {
            Answer::Absent
        }
    });
    let Outcome::Recovered { merged, source, .. } = outcome else {
        panic!("expected a recovery, got {}", describe(&outcome));
    };
    assert_eq!(source, v17_address);
    assert_eq!(merged.owner, Some(vk));
    assert_eq!(merged.listings.listings.len(), 1);
    assert_eq!(
        merged.info, predecessor.info,
        "the store's details carry over"
    );
    merged
        .verify(&merged, &store_params(&vk))
        .expect("the carried store is one the current contract accepts");
}

/// **The last Ghost-Key-owned generation carries forward as it is, and
/// arrives unbacked** (harvest#93). Every store up to V18 was owned by the
/// seller's Ghost Key. The current contract still accepts such a state -- its
/// owner is a key, and every record verifies against it -- so the probe
/// carries it forward by data transfer alone. But it has no backing, so every
/// reader finds no current backing, and that is what sends its seller to the
/// move in `backing_flow` rather than leaving them a store buyers cannot pay.
///
/// Mutated red by deriving V18 under the whole-key encoding
/// (`LAST_WHOLE_KEY_STORE_PARAM_GENERATION` = 18): the probe then asks for an
/// address V18 never had.
#[test]
fn a_ghost_key_owned_store_is_carried_forward_and_arrives_unbacked() {
    use freenet_scaffold::ComposableState;
    let vk = seller_vk();
    let v18 = store_lineage()
        .iter()
        .find(|e| e.generation == 18)
        .expect("V18 is recorded");
    let v18_address = current_id(&v18.code_hash, &store_params_encoded());
    let mut predecessor = store_with(&[signed_listing("Coffee")]);
    predecessor.info = signed_store_info(1);
    predecessor.owner = Some(vk);
    let bytes = store_bytes(&predecessor);

    let session = ProbeSession::start_with_candidates(
        store_ops(),
        StoreStateV1::default(),
        store_candidates(&vk).expect("candidates"),
        fold_all_policy(),
    );
    let (outcome, _) = run(session, |id| {
        if id == v18_address {
            Answer::State(bytes.clone())
        } else {
            Answer::Absent
        }
    });
    let Outcome::Recovered { merged, source, .. } = outcome else {
        panic!("expected a recovery, got {}", describe(&outcome));
    };
    assert_eq!(source, v18_address);
    assert_eq!(merged.owner, Some(vk), "still owned by the Ghost Key");
    merged
        .verify(&merged, &store_params(&vk))
        .expect("the current contract accepts a Ghost-Key-owned state as it is");
    assert!(
        harvest_common::backing::current_backing(&merged, |_| None).is_none(),
        "and it arrives with no backing, so readers treat it as unbacked"
    );
}

/// A store owned by a store key is probed at the addresses that key derives,
/// which a Ghost Key's own probe cannot reach (harvest#93). So the next
/// re-key finds it; see `migrate_ops::start_store_key_migration`.
#[test]
fn a_store_keys_candidates_are_its_own_and_not_its_ghost_keys() {
    let ghost = seller_vk();
    let store = ed25519_dalek::SigningKey::from_bytes(&[0x62; 32]).verifying_key();
    let by_store_key = store_candidate_ids(&store).expect("candidates");
    let by_ghost_key = store_candidate_ids(&ghost).expect("candidates");
    assert_eq!(by_store_key.len(), store_lineage().len());
    assert!(by_store_key.iter().all(|id| !by_ghost_key.contains(id)));
}

/// Fold-all reaches past the newest populated generation.
///
/// Harvest re-keyed four times, so a seller's listings can be spread across
/// several instances, none of which was ever carried forward.
/// `NewestFirstWins` would stop at the first hit and leave the rest behind --
/// which is why the policy is `FoldAll` and why the ack is earned in
/// `fold_all_preconditions_hold` below.
///
/// Mutated red by switching `fold_all_policy` to `NewestFirstWins`: the
/// recovered store then holds one listing instead of two.
#[test]
fn fold_all_recovers_listings_spread_across_generations() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    assert!(ids.len() >= 2, "this test needs at least two generations");
    let newest = ids[ids.len() - 1];
    let older = ids[0];

    let from_newest = store_bytes(&store_with(&[signed_listing("Beans")]));
    let from_older = store_bytes(&store_with(&[signed_listing("Coffee")]));

    let (outcome, _) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(from_newest.clone())
        } else if id == older {
            Answer::State(from_older.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { merged, .. } => {
            let titles: HashSet<&str> = merged
                .listings
                .listings
                .iter()
                .map(|l| l.listing.title.as_str())
                .collect();
            assert_eq!(
                titles,
                HashSet::from(["Coffee", "Beans"]),
                "fold-all must reach past the newest populated generation"
            );
        }
        other => panic!("expected a recovery, got {}", describe(&other)),
    }
}

/// A recovery seeded from a local snapshot keeps the local state too.
///
/// The probe is seeded from the client's own snapshot precisely so a recovery
/// can never drop local-only writes.
#[test]
fn a_recovery_never_drops_the_local_snapshot() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let recovered = store_bytes(&store_with(&[signed_listing("Coffee")]));
    let local = store_with(&[signed_listing("Local only")]);

    let (outcome, _) = run(store_session(local), |id| {
        if id == newest {
            Answer::State(recovered.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { merged, .. } => {
            let titles: HashSet<&str> = merged
                .listings
                .listings
                .iter()
                .map(|l| l.listing.title.as_str())
                .collect();
            assert!(
                titles.contains("Local only"),
                "the local snapshot was dropped by the merge"
            );
            assert!(titles.contains("Coffee"));
        }
        other => panic!("expected a recovery, got {}", describe(&other)),
    }
}

/// Every candidate answering `NotFound` produces `SeedLocal`, and `SeedLocal`
/// does not seal.
///
/// This is the single most important assertion in the file. An all-absent walk
/// is the case that LOOKS conclusive -- everyone was asked, nobody had
/// anything -- and sealing it is what marks a live predecessor permanently
/// empty. Absence on Freenet is unauthenticated, and a contract that exists
/// answers `NotFound` while it is momentarily unfindable.
///
/// Mutated red by making `seal_decision` seal on `SeedLocal`.
#[test]
fn an_all_absent_walk_does_not_seal() {
    let (outcome, seal) = run(store_session(StoreStateV1::default()), |_| Answer::Absent);
    assert!(
        matches!(outcome, Outcome::SeedLocal { .. }),
        "expected SeedLocal, got {}",
        describe(&outcome)
    );
    assert_eq!(
        seal,
        Seal::Retry,
        "an all-absent walk must be retried, never sealed"
    );
}

/// One candidate that never answers keeps the walk open, even when another
/// generation was recovered.
///
/// Under fold-all the probe continues past silence and reports the
/// unanswered candidates, so the recovery is real but partial -- the silent
/// generation may hold listings this fold is missing.
///
/// Mutated red by dropping the `unresolved.is_empty()` condition from
/// `seal_decision`.
#[test]
fn silence_anywhere_keeps_the_migration_open() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let silent = ids[0];
    let bytes = store_bytes(&store_with(&[signed_listing("Coffee")]));

    let (outcome, seal) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(bytes.clone())
        } else if id == silent {
            Answer::Silence
        } else {
            Answer::Absent
        }
    });

    match &outcome {
        Outcome::Recovered { unresolved, .. } => {
            assert!(
                unresolved.contains(&silent),
                "the silent candidate must be reported as unresolved"
            );
        }
        other => panic!("expected a partial recovery, got {}", describe(other)),
    }
    assert_eq!(seal, Seal::Retry, "a partial recovery must not seal");
    assert!(
        describe(&outcome).contains("not the whole story"),
        "the description must say the result is incomplete: {}",
        describe(&outcome)
    );
}

/// A walk where nothing answers at all is indeterminate, and indeterminate
/// never seals.
#[test]
fn total_silence_is_indeterminate_and_never_seals() {
    let (outcome, seal) = run(store_session(StoreStateV1::default()), |_| Answer::Silence);
    match &outcome {
        Outcome::Indeterminate { unresolved, .. } => {
            assert_eq!(unresolved.len(), store_lineage().len());
        }
        other => panic!("expected Indeterminate, got {}", describe(other)),
    }
    assert_eq!(seal, Seal::Retry);
}

/// An empty predecessor is a miss, not a hit.
///
/// A store PUT at creation time holds `StoreStateV1::default()`. Adopting one
/// would report a successful migration having recovered nothing -- and under a
/// stop-at-first-hit policy would prevent an older, populated generation from
/// ever being reached.
///
/// Mutated red by making `StoreOps::is_real` return `true` unconditionally.
#[test]
fn an_empty_predecessor_is_a_miss() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let empty = store_bytes(&StoreStateV1::default());
    let populated = store_bytes(&store_with(&[signed_listing("Coffee")]));

    let (outcome, _) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(empty.clone())
        } else if id == ids[0] {
            Answer::State(populated.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { source, merged, .. } => {
            assert_eq!(source, ids[0], "the empty generation was adopted as a hit");
            assert_eq!(merged.listings.listings.len(), 1);
        }
        other => panic!(
            "expected the older generation to be recovered, got {}",
            describe(&other)
        ),
    }
}

/// Undecodable bytes are a miss, and never a panic.
///
/// A predecessor whose state cannot be parsed is skipped defensively; the walk
/// continues to older generations rather than aborting.
#[test]
fn undecodable_state_is_a_miss_not_a_crash() {
    let ops = store_ops();
    assert!(ops.decode(b"not cbor at all").is_none());
    assert!(ops
        .decode(&harvest_common::to_cbor(&"a string").expect("cbor"))
        .is_none());

    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let populated = store_bytes(&store_with(&[signed_listing("Coffee")]));
    let (outcome, _) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(b"garbage".to_vec())
        } else if id == ids[0] {
            Answer::State(populated.clone())
        } else {
            Answer::Absent
        }
    });
    assert!(matches!(outcome, Outcome::Recovered { .. }));
}

// --- fold-all preconditions ---------------------------------------------

/// The properties `FoldAllAck` asks a caller to establish BEFORE opting in,
/// asserted on real states rather than argued in prose. That is the whole
/// point of the ack being a token.
#[test]
fn fold_all_preconditions_hold_for_the_store_state() {
    let ops = store_ops();
    // As the fold holds them: `StoreOps::decode` has already named the
    // seller as the owner of a whole-key generation's state (harvest#52).
    let samples: Vec<StoreStateV1> = [
        store_with(&[signed_listing("Alpha")]),
        store_with(&[signed_listing("Beta")]),
        store_with(&[signed_listing("Alpha"), signed_listing("Gamma")]),
    ]
    .into_iter()
    .map(|s| crate::migrate::name_whole_key_owner(s, &seller_vk()))
    .collect();
    let merge = |x: StoreStateV1, y: StoreStateV1| ops.merge_generations(x, y);
    freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
    freenet_migrate::driver::policy_check::assert_merge_idempotent(&samples, merge);
    freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);
}

/// Same, for the mailbox -- the one Harvest state with a real pruning rule.
///
/// Folding an older generation can re-admit a message the successor pruned.
/// That is sound only because the prune is deterministic and re-run on every
/// merge, so the fold result is pruned again identically. If it were not, the
/// order-invariance assertion here would fail.
///
/// **These three samples are all small in every dimension, and that is a
/// limitation of this test rather than a property of the merge.** The
/// mailbox merge NORMALISES -- it prunes to `MAX_MESSAGES`, to
/// `MAX_MAILBOX_BYTES`, and (since the fold fix) refuses messages over
/// `MAX_MESSAGE_BYTES` -- so `merge(a, a) == a` is simply false for any `a`
/// that is not already normalised, and `assert_merge_idempotent` asserts
/// exactly that strict form. Passing here means "these samples are already
/// normalised", not "the merge is idempotent".
///
/// `fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising` is the
/// test that faces that, on samples that cross all three bounds.
#[test]
fn fold_all_preconditions_hold_for_the_mailbox_state() {
    let ops = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    let base = 1_700_000_000;
    let samples = vec![
        mailbox_with(vec![message(1, base)]),
        mailbox_with(vec![message(2, base + 10)]),
        mailbox_with(vec![message(1, base), message(3, base + 20)]),
    ];
    let merge = |x: MailboxStateV1, y: MailboxStateV1| ops.merge_generations(x, y);
    freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
    freenet_migrate::driver::policy_check::assert_merge_idempotent(&samples, merge);
    freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);
}

/// **The `FoldAllAck` preconditions, on states that actually need
/// normalising.**
///
/// The test above earns the ack token against three samples that are small in
/// every dimension, so nothing in it exercises a prune or a refusal. That was
/// found when the size bound made the fold non-commutative and the existing
/// precondition test stayed green.
///
/// **This test then made the same mistake one bound over**, and it is worth
/// saying so here rather than only in the commit that fixed it. Its samples
/// crossed `MAX_MESSAGE_BYTES` and `MAX_MESSAGES` and reached 2.86% of
/// `MAX_MAILBOX_BYTES`; adding a sample that actually filled the byte budget
/// turned `assert_fold_order_invariant` red, because `enforce_message_cap`'s
/// prefix walk made the survivors depend on which large message blocked it.
/// Three fixtures, three times too small, all for the same reason: the sizes
/// were written as numbers while the bounds were constants. **Every sample
/// here is now derived from the constant it is tested against** -- see
/// `sized_message` and `fills_the_byte_budget` -- which is the only version of
/// this fix that does not need doing again.
///
/// # Strict idempotence is the wrong statement here, and always was
///
/// `assert_merge_idempotent` asserts `merge(a, a) == a`. A normalising merge
/// cannot satisfy that for a non-normalised `a`, and the mailbox merge has
/// normalised since long before the size bound: hand it 517 messages and
/// `merge(a, a)` returns 512, because `enforce_message_cap` runs on every
/// `apply_delta`. So this is not a new weakness introduced by the size
/// refusal -- it is a property the original sample set was too small to
/// reveal.
///
/// What `FoldAll` actually needs, and what is asserted here instead:
///
/// * **commutativity**, on raw un-normalised samples -- the property that
///   broke, and the only one of the three that was ever really at risk;
/// * **order-invariance** of the fold across those same samples;
/// * **idempotence on the merge's own output**, which is the honest form: the
///   fold's result is a fixed point, so re-running the migration or meeting
///   the same generation twice changes nothing;
/// * **absorption**, `merge(merge(a, b), b) == merge(a, b)` -- folding a
///   generation that has already been folded in is a no-op. This is the
///   property a re-run of the migration actually depends on, and neither the
///   crate's helpers nor the test above check it.
#[test]
fn fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising() {
    let ops = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    let merge = |x: MailboxStateV1, y: MailboxStateV1| ops.merge_generations(x, y);
    let base = 1_700_000_000;

    // One sample over each bound, all three derived from the constants.
    let over_cap: Vec<_> = (0..harvest_common::mailbox::MAX_MESSAGES + 5)
        .map(|i| message((i % 250) as u8, base + 1_000 + i as i64))
        .collect();
    let samples = vec![
        mailbox_with(vec![message(1, base)]),
        mailbox_with(vec![oversized_message(2, base + 10)]),
        mailbox_with(vec![message(1, base), oversized_message(3, base + 20)]),
        mailbox_with(over_cap),
        // MAX_MAILBOX_BYTES. This one was missing, and it is the bound where
        // the property actually fails.
        mailbox_with(fills_the_byte_budget(60, base + 100_000)),
    ];

    freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
    freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);

    // Idempotence on the merge's own output. `merge(a, a)` normalises; doing
    // it again must change nothing.
    let normalised: Vec<_> = samples
        .iter()
        .map(|s| merge(s.clone(), s.clone()))
        .collect();
    freenet_migrate::driver::policy_check::assert_merge_idempotent(&normalised, merge);

    // Absorption: re-folding a generation already folded in is a no-op.
    for (i, a) in samples.iter().enumerate() {
        for (j, b) in samples.iter().enumerate() {
            let once = merge(a.clone(), b.clone());
            let twice = merge(once.clone(), b.clone());
            assert_eq!(
                once, twice,
                "re-folding generation #{j} into the result of folding it with #{i} \
                 changed the state, so re-running the migration is not safe"
            );
        }
    }
}

/// A message the successor contract will not accept in a delta: one byte over
/// `MAX_MESSAGE_BYTES`.
///
/// No published generation ever enforced a size limit -- `MAX_MESSAGE_BYTES`
/// and the UI's send-side refusal both arrive on this branch, after the commit
/// recording V7 -- so a V1..V7 mailbox may hold one, either from a plaintext
/// over `LARGEST_BUCKET` (`pad_to_bucket` returned it unpadded rather than
/// refusing) or from an oversized `sender_public_key`, which was an unbounded
/// `Vec<u8>` any third party could plant in an open-write mailbox.
fn oversized_message(nonce: u8, secs: i64) -> EncryptedMessage {
    sized_message(nonce, secs, harvest_common::mailbox::MAX_MESSAGE_BYTES + 1)
}

/// A message of exactly `target` encoded bytes.
///
/// **Every size in these fixtures is DERIVED from the constant it is tested
/// against, never written as a number.** Three times now a precondition test
/// has been too small to observe the property it attests: the samples were
/// hard-coded, the bounds are constants, and the two drifted. A sample that is
/// `MAX_MESSAGE_BYTES` because it is written as `MAX_MESSAGE_BYTES` cannot
/// fall behind a retuned constant.
fn sized_message(nonce: u8, secs: i64, target: usize) -> EncryptedMessage {
    let mut message = message(nonce, secs);
    let headroom = target - harvest_common::mailbox::message_bytes(&message);
    message.ciphertext = vec![nonce; message.ciphertext.len() + headroom];
    assert_eq!(
        harvest_common::mailbox::message_bytes(&message),
        target,
        "the fixture must be the size it claims, or it cannot observe anything"
    );
    message
}

/// As few maximum-size messages as it takes to fill `MAX_MAILBOX_BYTES`.
///
/// Derived, not counted: the number is whatever the ratio of the two constants
/// makes it.
fn fills_the_byte_budget(first_nonce: u8, base: i64) -> Vec<EncryptedMessage> {
    let mut messages = vec![];
    let mut total = 0usize;
    let mut i = 0i64;
    while total < harvest_common::mailbox::MAX_MAILBOX_BYTES {
        let m = sized_message(
            first_nonce.wrapping_add((i % 200) as u8),
            base + i,
            harvest_common::mailbox::MAX_MESSAGE_BYTES,
        );
        total += harvest_common::mailbox::message_bytes(&m);
        messages.push(m);
        i += 1;
    }
    messages
}

/// **The fold is commutative even when a message crosses the size bound.**
///
/// This is the `FoldAllAck` precondition, on the sample the existing
/// precondition test could not contain. `apply_delta` refuses an oversized
/// message on the INCOMING side only, and `merge_generations(newer, older)`
/// puts the older generation on that side -- so before the fix,
/// `merge(big, small)` kept the oversized message and `merge(small, big)`
/// dropped it, which is a fold whose result depends on which side a message
/// arrived on rather than on the bytes.
///
/// Asserting commutativity rather than the message count is deliberate: the
/// count is the symptom, and the property the ack token is minted against is
/// this one.
///
/// Strict idempotence is deliberately NOT asserted here -- the merge
/// normalises, so `merge(a, a) == a` is false for any un-normalised `a`, which
/// has been true since long before the size bound. See
/// `fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising`, which
/// asserts the honest forms.
#[test]
fn folding_is_commutative_across_the_message_size_bound() {
    let ops = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    let base = 1_700_000_000;
    let samples = vec![
        mailbox_with(vec![message(1, base)]),
        mailbox_with(vec![oversized_message(2, base + 10)]),
        mailbox_with(vec![message(1, base), oversized_message(3, base + 20)]),
    ];
    let merge = |x: MailboxStateV1, y: MailboxStateV1| ops.merge_generations(x, y);
    freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
    freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);
}

/// **What the fold cannot carry, it drops from BOTH sides.**
///
/// The direction matters and is the reason commutativity is restored by
/// dropping rather than by keeping. Until harvest#85 `verify` tolerated an
/// oversized message, so a folded state carrying one would have been accepted
/// by `validate_state` and PUT successfully -- and then every peer that merged
/// it would run `apply_delta` and drop the message, leaving this node holding
/// an entry no other peer has, permanently. Since harvest#85 `verify` refuses
/// it, so keeping it would fail the fold's own PUT instead. Dropping it here moves the node
/// toward what the network holds; keeping it would be a silent permanent
/// divergence dressed up as data preservation.
#[test]
fn an_oversized_message_is_dropped_from_whichever_side_it_is_on() {
    let ops = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    let base = 1_700_000_000;
    let big = oversized_message(9, base + 5);
    let small = message(1, base);

    let from_older = ops.merge_generations(
        mailbox_with(vec![small.clone()]),
        mailbox_with(vec![big.clone()]),
    );
    let from_newer = ops.merge_generations(
        mailbox_with(vec![big.clone()]),
        mailbox_with(vec![small.clone()]),
    );

    for (which, folded) in [("older", &from_older), ("newer", &from_newer)] {
        assert!(
            !folded.messages.contains(&big),
            "an oversized message on the {which} side survived the fold; the successor's \
             own apply_delta would refuse it, so this node would hold an entry no peer has"
        );
        assert!(
            folded.messages.contains(&small),
            "the honest message was lost too"
        );
    }
}

/// **An unfoldable message is reported, not swallowed.**
///
/// The migration exists to preserve messages, so the one thing it must never
/// do is fail to carry one without saying so. `probe_warn` is the same channel
/// `decode_probed_state` uses for the neighbouring failure ("this is how a
/// recoverable generation goes missing silently"), which is the register this
/// belongs in.
///
/// Asserted on the returned report rather than on captured stderr, because a
/// test that greps a log is a test of the logger.
#[test]
fn the_fold_says_what_it_could_not_carry() {
    let base = 1_700_000_000;
    let report = merge_mailbox_reporting_drops(
        mailbox_with(vec![message(1, base), oversized_message(9, base + 5)]),
        &mailbox_with(vec![oversized_message(8, base + 6)]),
    );
    assert_eq!(
        report.dropped_oversized, 2,
        "the fold must count what it could not carry, from both sides"
    );
    assert_eq!(report.state.messages.len(), 1);

    let warning = report
        .unfoldable_warning()
        .expect("a fold that dropped messages must have something to say");
    assert!(
        warning.contains("2 message(s)")
            && warning.contains(&harvest_common::mailbox::MAX_MESSAGE_BYTES.to_string()),
        "the warning must name how many and against what bound, so an operator can \
         tell what was lost: {warning}"
    );

    // And says nothing when there is nothing to say, so the warning is
    // evidence rather than noise.
    let clean = merge_mailbox_reporting_drops(
        mailbox_with(vec![message(1, base)]),
        &mailbox_with(vec![message(2, base + 1)]),
    );
    assert_eq!(clean.dropped_oversized, 0);
    assert!(clean.unfoldable_warning().is_none());
}

/// **Absorption for the reputation and store folds, which nothing pinned.**
///
/// `fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising` asserts
/// absorption for the mailbox only. Both of the others hold -- reputation is a
/// grow-only nonce-keyed union with no cap and a monotone certificate
/// back-fill; `enforce_order_cap` keeps a strict top-k, so anything it drops
/// ranks below everything it keeps and re-offering it changes nothing -- but
/// "holds by argument" and "holds" are the distinction this whole file exists
/// to keep.
///
/// Absorption is the property a RE-RUN of the migration depends on: folding a
/// generation that has already been folded in must be a no-op, or the state
/// flaps and each flap is a PUT.
#[test]
fn re_folding_a_generation_is_a_no_op_for_reputation_and_store() {
    let rep_params = reputation_params(&store_vk());
    let rep_ops = ReputationOps {
        params: rep_params.clone(),
    };
    let with_cert = ReputationStateV1 {
        owner_certificate_pem: "CERT-FROM-OLDER".to_string(),
        ..Default::default()
    };

    let once = rep_ops.merge_generations(ReputationStateV1::default(), with_cert.clone());
    let twice = rep_ops.merge_generations(once.clone(), with_cert);
    assert_eq!(
        once, twice,
        "re-folding a reputation generation changed the state, so a re-run of the \
         migration is not a fixed point"
    );

    let store_ops = store_ops();
    let older = store_with(&[signed_listing("Alpha"), signed_listing("Beta")]);
    let once = store_ops.merge_generations(store_with(&[signed_listing("Gamma")]), older.clone());
    let twice = store_ops.merge_generations(once.clone(), older);
    assert_eq!(
        once, twice,
        "re-folding a store generation changed the state, so a re-run of the migration \
         is not a fixed point"
    );
}

/// **A predecessor's certificate is carried forward only as the successor
/// contract accepts it** (review round 1, P1-4): a genuine one in canonical
/// armour, anything else as nothing -- and a state whose only content was a
/// certificate that does not hold up is then a miss, not a recovery the
/// successor would refuse. Red if `ReputationOps::decode` stops reducing
/// the certificate.
#[test]
fn a_predecessor_certificate_is_carried_only_as_the_contract_accepts_it() {
    let ops = ReputationOps {
        params: reputation_params(&store_vk()),
    };
    let fixture = include_str!("../../../tests/fixtures/ghostkey-certificate.pem");
    let encode = |pem: &str| {
        harvest_common::to_cbor(&ReputationStateV1 {
            owner_certificate_pem: pem.to_string(),
            ..Default::default()
        })
        .unwrap()
    };
    let genuine = ops
        .decode(&encode(&fixture.replace('\n', "\r\n")))
        .expect("decodes");
    assert_eq!(
        genuine.owner_certificate_pem, fixture,
        "re-armoured canonically"
    );
    assert!(ops.is_real(&genuine));
    let junk = ops
        .decode(&encode("-----BEGIN CERT-----"))
        .expect("decodes");
    assert_eq!(junk.owner_certificate_pem, "");
    assert!(!ops.is_real(&junk), "nothing the successor would take");
}

/// An empty mailbox or reputation state is a miss.
#[test]
fn empty_states_are_not_real() {
    let mailbox = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    assert!(!mailbox.is_real(&MailboxStateV1::default()));
    assert!(mailbox.is_real(&mailbox_with(vec![message(1, 1_700_000_000)])));

    let reputation = ReputationOps {
        params: reputation_params(&store_vk()),
    };
    assert!(!reputation.is_real(&ReputationStateV1::default()));
    let mut with_complaint = ReputationStateV1::default();
    with_complaint.complaints.push(dummy_complaint());
    assert!(reputation.is_real(&with_complaint));
    // A certificate alone is real (harvest#53 Phase C, Option A): it is all
    // an RSA generation's record holds, and what the walk carries forward.
    // Red against the old rule, which counted only feedback.
    let cert_only = ReputationStateV1 {
        owner_certificate_pem: "CERT".to_string(),
        ..Default::default()
    };
    assert!(reputation.is_real(&cert_only));
}

/// A complaint that exists but does not verify. Used only where the
/// signatures are not the property under test.
fn dummy_complaint() -> Complaint {
    use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
    Complaint {
        order: AuthorizedOrder {
            order: Order {
                request_id: None,
                id: OrderId([4u8; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: String::new(),
                amount_sats: 1,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: vec![0u8; 22],
                payment_hash: None,
                payment_address: String::new(),
                required_confirmations: 1,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: None,
                listing_tag: None,
                buyer_receipt_key: Some([4u8; 32]),
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            },
            scoped_payload: vec![0u8; 8],
            signature: vec![0u8; 64],
            status: OrderStatus::Paid,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        },
        category: harvest_common::feedback::FeedbackCategory::NonDelivery,
        block_height: 100,
        paid_height: 90,
        scoped_payload: vec![0u8; 8],
        buyer_signature: vec![0u8; 64],
    }
}

/// A merge that cannot be applied keeps the primary rather than losing it.
///
/// `ReputationStateV1::apply_delta` rejects the whole delta if any complaint
/// does not verify. The documented `ProbeStateOps` behaviour is
/// keep-primary, and getting that backwards would let one bad entry from an
/// old generation erase a good newer one.
#[test]
fn an_unverifiable_merge_keeps_the_primary() {
    let params = reputation_params(&store_vk());
    let ops = ReputationOps {
        params: params.clone(),
    };
    let primary = ReputationStateV1 {
        owner_certificate_pem: "PRIMARY".to_string(),
        ..Default::default()
    };

    let mut bad = ReputationStateV1::default();
    bad.complaints.push(dummy_complaint());

    let merged = ops.merge_generations(primary.clone(), bad);
    assert_eq!(
        merged, primary,
        "an unverifiable delta must leave the primary untouched"
    );
}

/// **All three folds report a wholly-discarded predecessor generation.**
///
/// The blocking finding of the fold gate: `merge_mailbox` warned, `merge_store`
/// never had a warning at all, and the reputation fold's report covered token
/// collisions but not this path -- measured at 0 of 3 predecessor entries
/// carried, 2 of them verifiable, with nothing said. The refusal is
/// deterministic, so it repeats on every walk and nothing ever recovers the
/// generation: the person affected has to be told.
///
/// Asserted through one shared helper (`fold_or_keep_primary`) rather than
/// three arms, so there is one place to forget instead of three. The mailbox
/// arm is unreachable today (`apply_delta` is infallible), which is why this
/// drives the two that are reachable; the mailbox is covered structurally by
/// going through the same helper.
#[test]
fn a_wholly_discarded_predecessor_generation_is_reported() {
    // Reputation: one unverifiable complaint rejects the whole delta.
    let rep_params = reputation_params(&store_vk());
    let mut unverifiable = ReputationStateV1::default();
    unverifiable.complaints.push(dummy_complaint());

    let rep = merge_reputation_reporting_discard(
        ReputationStateV1::default(),
        &unverifiable,
        &rep_params,
    );
    assert!(
        rep.discarded,
        "a reputation generation refused in full must be reported, not kept quiet"
    );
    assert!(
        rep.state.complaints.is_empty(),
        "keep-primary is still the behaviour"
    );

    // And a fold that succeeds does NOT claim a discard, so the flag is
    // evidence rather than noise.
    let quiet = merge_reputation_reporting_discard(
        ReputationStateV1::default(),
        &ReputationStateV1::default(),
        &rep_params,
    );
    assert!(!quiet.discarded);

    // Store: a listing whose signature does not verify against these
    // parameters.
    let other_seller = SigningKey::from_bytes(&[77u8; 32]).verifying_key();
    let store = merge_store_reporting_discard(
        StoreStateV1::default(),
        &store_with(&[signed_listing("Alpha")]),
        &store_params(&other_seller),
        &other_seller,
        DiscardedSide::Predecessor,
    );
    assert!(
        store.discarded,
        "a store generation refused in full must be reported: it takes every VERIFIED \
         listing with it, measured at 0 of 2 carried with 1 verifiable"
    );

    let ok = merge_store_reporting_discard(
        StoreStateV1::default(),
        &store_with(&[signed_listing("Beta")]),
        &store_params(&seller_vk()),
        &seller_vk(),
        DiscardedSide::Predecessor,
    );
    assert!(!ok.discarded, "a successful store fold claims no discard");
}

/// **A fold that prunes to the caps says how many it pruned** (PR #82 review,
/// Should Fix 7). Two generations of top-size messages meet for the first time
/// in the fold and together exceed the top size class's cap; the lowest-ranked
/// go, and the report counts them once each, even where a message is on both
/// sides.
#[test]
fn a_fold_that_prunes_to_the_caps_reports_it() {
    let cap = harvest_common::mailbox::SIZE_CLASS_CAPS[3];
    let top = harvest_common::mailbox::MAX_MESSAGE_BYTES;
    let base = 1_700_000_000;
    let newer: Vec<_> = (0..cap as u8)
        .map(|i| sized_message(i, base + 100 + i as i64, top))
        .collect();
    // Older than every message above, so these are the ones pruned; one of
    // them is on both sides.
    let older: Vec<_> = (0..3u8)
        .map(|i| sized_message(200 + i, base + i as i64, top))
        .collect();
    let successor = {
        let mut s = MailboxStateV1::default();
        s.apply_delta(&Some(newer)).expect("apply");
        s.messages.push(older[0].clone());
        s
    };
    let report = merge_mailbox_reporting_drops(successor, &mailbox_with(older.clone()));
    assert_eq!(report.state.messages.len(), cap);
    assert_eq!(
        report.pruned_by_cap, 3,
        "three distinct older messages were pruned"
    );
    let warning = report
        .unfoldable_warning()
        .expect("a prune must be reported");
    assert!(
        warning.contains("3 message(s) were pruned"),
        "got: {warning}"
    );

    let clean = merge_mailbox_reporting_drops(mailbox_with(vec![]), &mailbox_with(older));
    assert_eq!(clean.pruned_by_cap, 0);
    assert!(
        clean.unfoldable_warning().is_none(),
        "nothing pruned, nothing said"
    );
}

/// An oversized message present on BOTH sides is one message that could not be
/// carried, not two.
///
/// A migration report that overstates a loss is as untrustworthy as one that
/// understates it, and this one is read by a person deciding whether the
/// migration went well.
#[test]
fn an_oversized_message_on_both_sides_is_counted_once() {
    let base = 1_700_000_000;
    let shared = oversized_message(9, base + 5);
    let report = merge_mailbox_reporting_drops(
        mailbox_with(vec![message(1, base), shared.clone()]),
        &mailbox_with(vec![shared]),
    );
    assert_eq!(
        report.dropped_oversized, 1,
        "the same message on both sides was counted twice"
    );
}

/// **A fold does not carry unsigned version-0 details forward** (PR #82
/// round-3 review). Before the re-review the contract accepted any content at
/// version 0, so a predecessor can hold an injected name and key at version 0
/// beside real listings. The scaffold's merge never touches a version-0 base,
/// so the fold carried the junk forward, the new contract refused the PUT,
/// and the listings never moved. The fold resets it to the default instead.
#[test]
fn a_fold_drops_unsigned_version_zero_details() {
    use freenet_scaffold::ComposableState;
    let mut junk = store_with(&[signed_listing("Alpha")]);
    junk.info.info.store_name = "Totally Legit Farm".into();
    junk.info.info.encryption_public_key = Some([0xAA; 32]);
    let params = store_params(&seller_vk());

    let folded = merge_store_reporting_discard(
        junk,
        &StoreStateV1::default(),
        &params,
        &seller_vk(),
        DiscardedSide::Predecessor,
    );
    assert!(!folded.discarded);
    assert_eq!(
        folded.state.info,
        harvest_common::store::AuthorizedStoreInfoV1::default()
    );
    assert_eq!(
        folded.state.listings.listings.len(),
        1,
        "the listing is carried"
    );
    folded
        .state
        .verify(&folded.state, &params)
        .expect("the folded state is one the new contract accepts");
}

/// Store details at `version`, signed by the test seller the way the ghostkey
/// delegate would.
fn signed_store_info(version: u32) -> harvest_common::store::AuthorizedStoreInfoV1 {
    let info = harvest_common::store::StoreInfoV1 {
        version,
        certificate_pem: String::new(),
        seller_fingerprint: "fp".into(),
        reputation_contract_id: [7u8; 32],
        store_name: format!("Shop v{version}"),
        description: String::new(),
        encryption_public_key: None,
        record_public_key: None,
    };
    let scoped = ghostkey_common::ScopedPayload {
        requestor: ghostkey_common::SignatureRequestor::WebApp(
            harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                .parse::<ContractInstanceId>()
                .expect("canonical webapp id"),
        ),
        payload: harvest_common::to_cbor(&info).expect("serialize info"),
    };
    let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped payload");
    let signature = seller().sign(&scoped_payload).to_bytes().to_vec();
    harvest_common::store::AuthorizedStoreInfoV1 {
        info,
        scoped_payload,
        signature,
    }
}

/// **The four fold orders the round-3 review reproduced, through the real
/// fold.** Each is a sequence of generations, newest first, folded the way
/// `merge_generations` folds them and then merged with an empty local state.
/// Every forward state must be one the new contract accepts, with the listing
/// carried; where a signed predecessor exists its details win.
#[test]
fn every_fold_order_with_injected_version_zero_details_moves_the_listings() {
    use freenet_scaffold::ComposableState;
    let params = store_params(&seller_vk());
    let mut junk = store_with(&[signed_listing("Alpha")]);
    junk.info.info.store_name = "Totally Legit Farm".into();
    junk.info.info.encryption_public_key = Some([0xAA; 32]);
    let signed = StoreStateV1 {
        info: signed_store_info(1),
        ..Default::default()
    };
    let plain = store_with(&[signed_listing("Alpha")]);

    let fold = |base: StoreStateV1, other: &StoreStateV1| {
        merge_store_reporting_discard(
            base,
            other,
            &params,
            &seller_vk(),
            DiscardedSide::Predecessor,
        )
        .state
    };
    let cases: [(&str, Vec<&StoreStateV1>, u32); 4] = [
        ("junk only", vec![&junk], 0),
        ("junk newest, signed older", vec![&junk, &signed], 1),
        ("signed newest, junk older", vec![&signed, &junk], 1),
        ("plain newest, junk older", vec![&plain, &junk], 0),
    ];
    for (name, generations, version) in cases {
        let mut acc = generations[0].clone();
        for older in &generations[1..] {
            acc = fold(acc, older);
        }
        let forward = fold(acc, &StoreStateV1::default());
        forward
            .verify(&forward, &params)
            .unwrap_or_else(|e| panic!("{name}: the new contract refuses the forward state: {e}"));
        assert_eq!(
            forward.listings.listings.len(),
            1,
            "{name}: the listing moved"
        );
        assert_eq!(forward.info.info.version, version, "{name}: details");
        assert!(
            forward.info.info.encryption_public_key.is_none(),
            "{name}: the injected key did not move"
        );
    }
}

/// **A fold whose base is not canonical writes canonical state (harvest#26).**
///
/// The current contract refuses unsorted listings or a listing held twice,
/// and the old one accepted both, so a predecessor generation can hold either.
/// When the other side of the fold brings nothing new the scaffold never calls
/// `ListingsV1::apply_delta`, so only the fold's own normalise stands between
/// that base and a PUT the new contract would refuse.
#[test]
fn a_fold_normalises_a_non_canonical_base() {
    let mut listings = vec![signed_listing("Alpha"), signed_listing("Beta")];
    listings.sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
    let mut messy = StoreStateV1::default();
    messy.listings.listings = vec![
        listings[1].clone(),
        listings[0].clone(),
        listings[1].clone(),
    ];

    let folded = merge_store_reporting_discard(
        messy,
        &StoreStateV1::default(),
        &store_params(&seller_vk()),
        &seller_vk(),
        DiscardedSide::Predecessor,
    );
    assert!(!folded.discarded);
    assert_eq!(
        folded.state.listings.listings, listings,
        "the fold must write the listings sorted and once each"
    );
}

// --- markers ------------------------------------------------------------

/// Marker keys are hex, and two distinct instances never share one.
///
/// Raw bytes in a storage key alias: anything that runs a key through a lossy
/// UTF-8 conversion maps every invalid byte to U+FFFD, so two distinct 32-byte
/// ids collapse onto one slot and one of them is sealed having never been
/// migrated. River hit exactly that.
///
/// Mutated red by encoding the ids with `String::from_utf8_lossy` instead of
/// hex: the two ids below then produce the same key.
#[test]
fn marker_keys_are_hex_and_do_not_alias() {
    // Two ids that differ only in bytes that are invalid UTF-8, so a lossy
    // conversion maps both to the same replacement character.
    let a = ContractInstanceId::new([0xF8u8; 32]);
    let b = ContractInstanceId::new([0xF9u8; 32]);
    let hash = [1u8; 32];

    let key_a = marker_key(Artifact::Store, &a, &hash);
    let key_b = marker_key(Artifact::Store, &b, &hash);
    assert_ne!(key_a, key_b, "two distinct instances share a marker slot");
    assert!(
        key_a.is_ascii(),
        "a marker key must be plain ASCII: {key_a}"
    );
    assert!(key_a.contains(&hex::encode(a.as_bytes())));
}

/// The marker is keyed by the CURRENT code hash, so the next re-key starts a
/// fresh walk rather than inheriting a "done" from the generation before.
///
/// Mutated red by dropping the code hash from `marker_key`.
#[test]
fn a_new_generation_gets_a_new_marker() {
    let id = ContractInstanceId::new([3u8; 32]);
    assert_ne!(
        marker_key(Artifact::Store, &id, &[1u8; 32]),
        marker_key(Artifact::Store, &id, &[2u8; 32]),
        "a re-key must not inherit the previous generation's completion marker"
    );
}

/// **The fail-safe direction, which is the whole reason the marker moved.**
///
/// The gate used to be a `localStorage` read. In the deployed gateway
/// `localStorage` throws -- Freenet's webapp iframe has no
/// `allow-same-origin`, so the frame's origin is opaque -- and the only reason
/// that was a performance bug rather than a data-loss one is that an
/// unreadable marker reads as "not migrated". The marker now lives in the
/// delegate, where the ways to get no usable answer are different (not
/// registered, send failed, no reply) and the direction has to be the same.
///
/// Mutated red by having `probe_gate` skip on `Unavailable`.
#[test]
fn an_unavailable_marker_runs_the_probe() {
    assert_eq!(probe_gate(MarkerLookup::Unavailable), Gate::Run);
}

/// Only a definite `Present` skips.
///
/// Mutated red by having `probe_gate` skip on `Absent`, which is the shape
/// that would suppress every first-run migration.
#[test]
fn only_a_recorded_marker_skips_the_probe() {
    assert_eq!(probe_gate(MarkerLookup::Present), Gate::Skip);
    assert_eq!(probe_gate(MarkerLookup::Absent), Gate::Run);
}

/// A marker id is something the harvest delegate will store.
///
/// The delegate refuses an empty or non-ASCII marker id (`markers::
/// is_valid_marker`), because a key that survives a lossy UTF-8 conversion is
/// a key that cannot alias with another. A minting side that produced one of
/// those would have every write silently refused and every walk repeat
/// forever, with nothing but a log line to say so.
///
/// Mutated red by having `marker_key` emit the raw id bytes rather than hex.
#[test]
fn a_marker_id_is_one_the_delegate_will_store() {
    let key = marker_key(
        Artifact::Mailbox,
        &ContractInstanceId::new([0xF8u8; 32]),
        &[0xF9u8; 32],
    );
    assert!(!key.is_empty());
    assert!(key.is_ascii(), "the delegate refuses a non-ASCII marker id");
}

/// The two delegate requests carry the marker id unchanged.
///
/// They are built in `migrate` rather than at the wasm-only call site so this
/// is assertable at all; a query that named a different marker than the write
/// would seal one slot and read another forever.
#[test]
fn the_delegate_requests_name_the_same_marker() {
    use harvest_common::HarvestDelegateRequest;

    let id = marker_key(
        Artifact::Store,
        &ContractInstanceId::new([3u8; 32]),
        &[1u8; 32],
    );

    match (marker_query(&id), marker_write(&id, "note")) {
        (
            HarvestDelegateRequest::GetMigrationMarker { marker: queried },
            HarvestDelegateRequest::SetMigrationMarker {
                marker: written,
                note,
            },
        ) => {
            assert_eq!(queried, id);
            assert_eq!(written, id);
            assert_eq!(note, "note");
        }
        (q, w) => panic!("wrong request variants: {q:?} / {w:?}"),
    }
}

/// Two artifacts never share a marker.
#[test]
fn artifacts_have_separate_markers() {
    let id = ContractInstanceId::new([3u8; 32]);
    let hash = [1u8; 32];
    let keys: HashSet<String> = [Artifact::Store, Artifact::Reputation, Artifact::Mailbox]
        .into_iter()
        .map(|a| marker_key(a, &id, &hash))
        .collect();
    assert_eq!(keys.len(), 3);
}

/// The wildcard arm of `seal_decision` retries.
///
/// A source scrape, which is an unusual thing to assert and is the right tool
/// here. `Outcome` is `#[non_exhaustive]`: every variant that exists today is
/// named explicitly, so the wildcard is unreachable and no behavioural test
/// can reach it. It exists for the variant a future `freenet-migrate` release
/// adds -- and if that arm said `Seal`, that variant would silently write a
/// permanent "this predecessor had nothing" marker the first time it occurred,
/// for a case this code has never seen.
///
/// The crate's own docs make the same point about `#[non_exhaustive]`: it
/// "protects exhaustive matches only", so it forces the arm to exist without
/// saying anything about what it does. This says what it must do.
///
/// Anchored on the `Seal::` values rather than on surrounding prose so
/// reformatting or re-commenting the function does not break it.
///
/// Mutated red by changing the arm to `_ => Seal::Seal`.
#[test]
fn the_wildcard_outcome_arm_retries() {
    let source = include_str!("../migrate.rs");
    let body = source
        .split("pub fn seal_decision")
        .nth(1)
        .expect("seal_decision must exist");
    let body = body.split("\n}\n").next().expect("a function body");

    assert!(
        body.contains("_ => Seal::Retry"),
        "seal_decision has no wildcard arm returning Retry; a future Outcome \
         variant would fall through to whatever is there instead"
    );
    assert!(
        !body.contains("_ => Seal::Seal"),
        "seal_decision's wildcard arm SEALS. A variant added by a future \
         freenet-migrate release would write a permanent marker for a case \
         this code has never seen."
    );
}

/// **The fold must not drop a message because something in the newer
/// generation shares its nonce.**
///
/// Found by the source scrape added with the contract's identity re-key, not
/// by review: this was a FOURTH site deciding "already held" by nonce, after
/// `dedupe_by_nonce`, `summarize` and the contract's state-merge arm. It is
/// the one with the sharpest consequence, because it runs during a re-key --
/// the buyer's messages are being carried forward from a superseded
/// generation, and a message dropped here is dropped at the moment the whole
/// migration exists to preserve it.
///
/// The fix is the same as the contract's: no comparison at all.
/// `apply_delta` decides, and it decides by `entry_digest`.
#[test]
fn folding_keeps_a_message_whose_nonce_the_newer_generation_shares() {
    let mut confession = message(7, 1_700_000_000);
    confession.ciphertext = b"I confess".to_vec();
    let mut retraction = message(7, 1_700_000_001);
    retraction.ciphertext = b"I said no such thing".to_vec();
    assert_eq!(
        confession.nonce, retraction.nonce,
        "precondition: the two share a nonce"
    );

    let folded = super::merge_mailbox(
        mailbox_with(vec![retraction.clone()]),
        &mailbox_with(vec![confession.clone()]),
    );

    assert!(
        folded.messages.contains(&confession),
        "the fold dropped a message from the older generation because the newer one held \
         something sharing its nonce"
    );
    assert!(folded.messages.contains(&retraction));
    folded
        .verify()
        .expect("the fold must produce a valid state");
}

/// Folding a generation this one already holds entirely changes nothing.
#[test]
fn folding_an_identical_generation_changes_nothing() {
    let held = mailbox_with(vec![message(1, 1_700_000_000), message(2, 1_700_000_001)]);
    let folded = super::merge_mailbox(held.clone(), &held);
    assert_eq!(folded.messages.len(), 2);
    folded.verify().expect("valid");
}

// --- harvest#121: telling the seller once --------------------------------

/// A notice's id is a valid delegate marker id, stable for the same notice
/// about the same lineage, and different when the text or the lineage changes
/// -- including the lineage's own code hash, so this artifact's next re-key
/// is news again. So a repeated walk re-finds the same id, while a second
/// store's identical "Recovered your store" is still shown. Mutated red by
/// leaving the text, and then the lineage, out of the hash.
#[test]
fn a_notice_id_is_stable_for_the_same_notice_and_new_for_a_different_one() {
    let lineage = marker_key(
        Artifact::Store,
        &ContractInstanceId::new([1u8; 32]),
        &[2u8; 32],
    );
    let other_store = marker_key(
        Artifact::Store,
        &ContractInstanceId::new([9u8; 32]),
        &[2u8; 32],
    );
    let rekeyed = marker_key(
        Artifact::Store,
        &ContractInstanceId::new([1u8; 32]),
        &[3u8; 32],
    );
    let text = "Recovered your store from an earlier version of Harvest.";
    let id = notice_marker(&lineage, text);
    assert_eq!(id, notice_marker(&lineage, text));
    assert!(id.starts_with(NOTICE_MARKER_PREFIX), "{id}");
    assert!(
        id.is_ascii() && !id.is_empty(),
        "the delegate refuses non-ASCII ids: {id}"
    );
    assert_ne!(
        id,
        notice_marker(
            &lineage,
            "Recovered your mailbox from an earlier version of Harvest."
        )
    );
    assert_ne!(
        id,
        notice_marker(&other_store, text),
        "a second store's identical words are a different notice"
    );
    assert_ne!(
        id,
        notice_marker(&rekeyed, text),
        "this artifact's re-key is news"
    );
    assert!(
        !lineage.starts_with(NOTICE_MARKER_PREFIX),
        "a lineage marker and a notice id must never collide: {lineage}"
    );
}

/// Only a definite `Present` suppresses a notice. Mutated red by suppressing
/// on `Unavailable`.
#[test]
fn only_a_definite_present_suppresses_a_notice() {
    assert_eq!(notice_gate(MarkerLookup::Present), NoticeGate::Suppress);
    assert_eq!(notice_gate(MarkerLookup::Absent), NoticeGate::Show);
    assert_eq!(notice_gate(MarkerLookup::Unavailable), NoticeGate::Show);
}

/// **The RSA generations' parameter bytes, pinned as hex** (review round 1
/// of #143, nit). `rsa_reputation_params_cbor` is a frozen record of bytes
/// already on the network, written out as a local struct; a serde or
/// ed25519-dalek upgrade that changed how `Vec<u8>` or `VerifyingKey`
/// encode would silently move every RSA-generation address, and every
/// other test here derives its expectation through the same encoder. This
/// one does not.
#[test]
fn rsa_generation_parameter_bytes_are_pinned() {
    let key = SigningKey::from_bytes(&[61u8; 32]).verifying_key();
    let params = rsa_reputation_params_cbor(&[1, 2, 3], &key).expect("encode");
    let hex: String = params.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    // map(2) { "rsa_public_key_der": [1, 2, 3] (a CBOR array of u8, serde's
    // default for Vec<u8>), "owner_verifying_key": bytes(32) }.
    assert_eq!(
        hex,
        "a2727273615f7075626c69635f6b65795f64657283010203736f776e65725f766572696679696e675f6b6579\
         582070df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae"
    );
}
