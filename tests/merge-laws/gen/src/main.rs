//! Generates `fdev verify-merge` corpora for the three Harvest contracts.
//!
//! Every state is built with the repo's own `harvest-common` types and merged
//! with the contracts' own `apply_delta` / `merge` code, and every state is
//! checked natively with the same `verify` the contract's `validate_state`
//! calls before it is written. Keys are fixed throwaway seeds (ed25519) or a
//! fresh throwaway RSA key; nothing here touches a real key.
//!
//! Output layout, one directory per corpus under the output root:
//!   <corpus>/params.bin
//!   <corpus>/states/<name>.cbor
//!   <corpus>/transitions.txt    "<base> <result>" per line (state names)
//!
//! Corpora:
//!   store, reputation, mailbox          -- HONEST: every state is reachable by
//!                                          the contract's own update path
//!                                          (built from empty via apply_delta)
//!   store-adv, reputation-adv, mailbox-adv
//!                                       -- ADVERSARIAL-VALID: states that pass
//!                                          validate_state but are NOT produced
//!                                          by the contract's update path
//!                                          (unsorted vectors, unsigned-field
//!                                          variants, equivocations)
//!   store-cap, mailbox-cap              -- honest states at the caps
//!                                          (MAX_ORDERS, MAX_MAILBOX_BYTES)
//!   *-empty                             -- the honest corpus plus a zero-byte
//!                                          state (#55)

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::spv::testing::payment_proof;
use freenet_bitcoin_common::{
    BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim, ClaimBody, OutPoint, SignedClaim,
    SignedTipEntry, TipEntryBody,
};
use freenet_scaffold::ComposableState;
use harvest_common::feedback::{FeedbackCategory, FeedbackToken};
use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind, PriceInfo};
use harvest_common::mailbox::{
    ConversationId, EncryptedMessage, MailboxParameters, MailboxStateV1, MAX_MESSAGE_BYTES,
    MAX_MAILBOX_BYTES,
};
use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus};
use harvest_common::reputation::{FeedbackEntry, ReputationParameters, ReputationStateV1};
use harvest_common::store::{
    AuthorizedStoreInfoV1, ListingsV1, OrdersV1, StoreInfoV1, StoreParameters, StoreStateV1,
    StoreStateV1Delta, MAX_ORDERS,
};
use serde::Serialize;

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    harvest_common::to_cbor(v).expect("encode")
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

// ---------------------------------------------------------------------------
// Corpus writer
// ---------------------------------------------------------------------------

struct Corpus {
    dir: PathBuf,
    code: Vec<u8>,
    params: Vec<u8>,
    names: Vec<String>,
    bytes: Vec<Vec<u8>>,
    transitions: Vec<(String, String)>,
    /// Transitions that carry the DELTA the contract received, the base's
    /// summary it was computed against, and the result. Only reachable through
    /// a bundle (the CLI has no --delta flag); these feed the delta_* laws.
    delta_steps: Vec<BundleTransition>,
}

/// Mirror of `freenet::conformance::bundle::Transition` (bincode field order).
#[derive(Serialize)]
struct BundleTransition {
    base_state: Vec<u8>,
    delta: Option<Vec<u8>>,
    incoming_state: Option<Vec<u8>>,
    summary: Option<Vec<u8>>,
    result_state: Vec<u8>,
}

/// Mirror of `freenet::conformance::bundle::ReplayBundle` (schema 1).
/// `instance` and `related` are always None/empty here, so the placeholder
/// id type does not affect the encoding.
#[derive(Serialize)]
struct ReplayBundle {
    schema_version: u16,
    code: Option<Vec<u8>>,
    code_hash: Option<[u8; 32]>,
    parameters: Vec<u8>,
    instance: Option<[u8; 32]>,
    states: Vec<Vec<u8>>,
    deltas: Vec<Vec<u8>>,
    summaries: Vec<Vec<u8>>,
    transitions: Vec<BundleTransition>,
    related: Vec<([u8; 32], Vec<u8>)>,
    note: Option<String>,
}

fn wasm(contract: &str) -> Vec<u8> {
    // Defaults to THIS worktree's build, so a bundle names the WASM of the
    // tree it was generated in. It used to default to one machine's fixed
    // path, which silently bundled another checkout's bytes.
    let dir = std::env::var("HARVEST_WASM_DIR").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/wasm32-unknown-unknown/release")
            .into()
    });
    fs::read(format!("{dir}/{contract}.wasm")).expect("contract wasm (build it first)")
}

impl Corpus {
    fn new(root: &Path, name: &str, params: &[u8]) -> Self {
        let contract = format!("{}_contract", name.split('-').next().unwrap());
        let code = wasm(&contract);
        let dir = root.join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("states")).unwrap();
        fs::write(dir.join("params.bin"), params).unwrap();
        Self {
            dir,
            code,
            params: params.to_vec(),
            names: vec![],
            bytes: vec![],
            transitions: vec![],
            delta_steps: vec![],
        }
    }

    fn delta_step(&mut self, base: &[u8], summary: &[u8], delta: &[u8], result: &[u8]) {
        self.delta_steps.push(BundleTransition {
            base_state: base.to_vec(),
            delta: Some(delta.to_vec()),
            incoming_state: None,
            summary: Some(summary.to_vec()),
            result_state: result.to_vec(),
        });
    }

    fn state(&mut self, name: &str, bytes: &[u8]) {
        assert!(!self.names.iter().any(|n| n == name), "duplicate {name}");
        fs::write(self.dir.join("states").join(format!("{name}.cbor")), bytes).unwrap();
        self.names.push(name.to_string());
        self.bytes.push(bytes.to_vec());
    }

    fn transition(&mut self, base: &str, result: &str) {
        self.transitions.push((base.into(), result.into()));
    }

    fn finish(self) {
        let t: String = self
            .transitions
            .iter()
            .map(|(b, r)| format!("{b} {r}\n"))
            .collect();
        fs::write(self.dir.join("transitions.txt"), t).unwrap();
        // A bundle with everything the CLI run has, plus the delta steps.
        let by_name = |n: &str| self.bytes[self.names.iter().position(|m| m == n).unwrap()].clone();
        let mut transitions: Vec<BundleTransition> = self
            .transitions
            .iter()
            .map(|(b, r)| BundleTransition {
                base_state: by_name(b),
                delta: None,
                incoming_state: None,
                summary: None,
                result_state: by_name(r),
            })
            .collect();
        let n_delta = self.delta_steps.len();
        transitions.extend(self.delta_steps);
        let bundle = ReplayBundle {
            schema_version: 1,
            code_hash: Some(*blake3::hash(&self.code).as_bytes()),
            code: Some(self.code),
            parameters: self.params,
            instance: None,
            states: self.bytes,
            deltas: vec![],
            summaries: vec![],
            transitions,
            related: vec![],
            note: Some("harvest merge-law baseline corpus (harvest-merge-corpus)".into()),
        };
        let mut out = b"FRNTCNF1".to_vec();
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend(bincode::serialize(&bundle).unwrap());
        fs::write(self.dir.join("bundle-in.bin"), out).unwrap();
        println!(
            "{}: {} states, {} transitions, {} delta steps",
            self.dir.display(),
            self.names.len(),
            self.transitions.len(),
            n_delta
        );
    }
}

// ---------------------------------------------------------------------------
// Signing, exactly as the ghostkey delegate's SignResult shapes it
// ---------------------------------------------------------------------------

fn sign_scoped<T: Serialize>(sk: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
    let scoped = ghostkey_common::ScopedPayload {
        requestor: harvest_common::expected_harvest_requestor(),
        payload: cbor(data),
    };
    let bytes = cbor(&scoped);
    let sig = sk.sign(&bytes).to_bytes().to_vec();
    (bytes, sig)
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

struct StoreFx {
    seller: SigningKey,
    bridge: SigningKey,
    params: StoreParameters,
}

impl StoreFx {
    fn new() -> Self {
        let seller = SigningKey::from_bytes(&[0xA1; 32]);
        let params = StoreParameters::new(seller.verifying_key());
        Self::with(seller, params)
    }

    /// A fixture for `seller` at a store whose parameters are `params` --
    /// the two-owner corpus uses one short code for two sellers (harvest#52).
    fn with(seller: SigningKey, params: StoreParameters) -> Self {
        let bridge = SigningKey::from_bytes(&[0xB2; 32]);
        Self {
            seller,
            bridge,
            params,
        }
    }

    fn info(&self, version: u32, name: &str) -> AuthorizedStoreInfoV1 {
        let info = StoreInfoV1 {
            version,
            certificate_pem: "-----BEGIN THROWAWAY CERT-----".into(),
            seller_fingerprint: "throwaway-seller-fp".into(),
            reputation_contract_id: [7u8; 32],
            store_name: name.into(),
            description: format!("**{name}** sells vegetables"),
            encryption_public_key: Some([9u8; 32]),
            record_public_key: None,
        };
        let (scoped_payload, signature) = sign_scoped(&self.seller, &info);
        AuthorizedStoreInfoV1 {
            info,
            scoped_payload,
            signature,
        }
    }

    fn listing(&self, i: u32) -> AuthorizedListing {
        let listing = Listing {
            id: ListingId([0u8; 32]),
            title: format!("Item {i}"),
            description: format!("Fresh item number {i}"),
            kind: if i % 3 == 0 {
                ListingKind::Gift
            } else {
                ListingKind::Sale
            },
            price: Some(PriceInfo {
                amount: format!("0.00{i}"),
                currency: "BTC".into(),
            }),
            created_at: ts(1_700_000_000 + i as i64 * 60),
        }
        .with_derived_id();
        let (scoped_payload, signature) = sign_scoped(&self.seller, &listing);
        AuthorizedListing {
            listing,
            scoped_payload,
            signature,
            certificate_pem: "-----BEGIN THROWAWAY CERT-----".into(),
        }
    }

    fn order(&self, buyer: &str, created: i64) -> Order {
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: buyer.into(),
            seller_fingerprint: "throwaway-seller-fp".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            payment_hash: None,
            payment_address: "tb1qthrowaway".into(),
            required_confirmations: 1,
            trusted_bridges: vec![BridgeId(self.bridge.verifying_key().to_bytes())],
            bitcoin_address_code_hash: None,
            // #83: a payment settles an order only if it confirmed inside the
            // order's window after its anchor. The fixture payments confirm
            // at height 100.
            anchor: Some(BlockAnchor { height: 90, hash: BlockHash([3u8; 32]) }),
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            created_at: ts(created),
        }
        .with_derived_id()
    }

    fn paid_proof(&self, order: &Order, seed: u8) -> OrderPaymentProof {
        let addr = order.bitcoin_params();
        let (spv, txid, block_hash) =
            payment_proof(&order.payment_script_pubkey, order.amount_sats, 1, [seed; 32]);
        let anchor = BlockAnchor {
            height: 100,
            hash: block_hash,
        };
        let claim = SignedClaim::sign(
            &self.bridge,
            &ClaimBody {
                script_id: addr.script_id(),
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
        OrderPaymentProof::on_chain(vec![claim], self.tip(order, 100))
    }

    fn reversed_proof(&self, order: &Order) -> OrderPaymentProof {
        let addr = order.bitcoin_params();
        let (spv, txid, block_hash) =
            payment_proof(&order.payment_script_pubkey, order.amount_sats, 1, [1u8; 32]);
        let outpoint = OutPoint { txid, vout: 0 };
        let anchor = BlockAnchor {
            height: 100,
            hash: block_hash,
        };
        let confirmed = SignedClaim::sign(
            &self.bridge,
            &ClaimBody {
                script_id: addr.script_id(),
                network: order.network,
                as_of: anchor,
                claim: Claim::ConfirmedOutput {
                    outpoint,
                    value_sats: order.amount_sats,
                    anchor,
                    spv,
                },
            },
        )
        .unwrap();
        let retracted = SignedClaim::sign(
            &self.bridge,
            &ClaimBody {
                script_id: addr.script_id(),
                network: order.network,
                as_of: BlockAnchor {
                    height: 101,
                    hash: BlockHash([7u8; 32]),
                },
                claim: Claim::Retracted { outpoint },
            },
        )
        .unwrap();
        OrderPaymentProof::on_chain(vec![confirmed, retracted], self.tip(order, 101))
    }

    fn tip(&self, order: &Order, height: u32) -> SignedTipEntry {
        SignedTipEntry::sign(
            &self.bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height,
                    hash: BlockHash([9u8; 32]),
                },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .unwrap()
    }

    fn authorized(&self, order: &Order, status: OrderStatus, seed: u8) -> AuthorizedOrder {
        let (scoped_payload, signature) = sign_scoped(&self.seller, order);
        let (sp, ss) = match status {
            OrderStatus::Cancelled => {
                let (a, b) = sign_scoped(&self.seller, &(order.id.clone(), status));
                (Some(a), Some(b))
            }
            _ => (None, None),
        };
        let proof = match status {
            OrderStatus::Paid => Some(self.paid_proof(order, seed)),
            OrderStatus::PaymentReversed => Some(self.reversed_proof(order)),
            _ => None,
        };
        let rec = AuthorizedOrder {
            order: order.clone(),
            scoped_payload,
            signature,
            status,
            payment_proof: proof,
            status_scoped_payload: sp,
            status_signature: ss,
        };
        rec.verify(&self.seller.verifying_key())
            .unwrap_or_else(|e| panic!("fixture order {status:?} does not verify: {e}"));
        rec
    }

    /// Build a state the way the contract's own update path would: from the
    /// default, via the store's own `apply_delta`, with a delta naming this
    /// fixture's seller as the owner (harvest#52).
    fn build(
        &self,
        info: Option<AuthorizedStoreInfoV1>,
        listings: Vec<AuthorizedListing>,
        orders: Vec<AuthorizedOrder>,
    ) -> StoreStateV1 {
        let mut s = StoreStateV1::default();
        let delta = StoreStateV1Delta {
            owner: Some(self.seller.verifying_key()),
            info,
            listings: (!listings.is_empty()).then_some(listings),
            orders: (!orders.is_empty()).then_some(orders),
            ..Default::default()
        };
        s.apply_delta(&StoreStateV1::default(), &self.params, &Some(delta))
            .unwrap();
        self.check(&s);
        s
    }

    fn check(&self, s: &StoreStateV1) {
        s.verify(s, &self.params)
            .unwrap_or_else(|e| panic!("fixture store state does not verify: {e}"));
    }

    /// What `update_state` does with `UpdateData::State(other)`.
    fn merged(&self, base: &StoreStateV1, other: &StoreStateV1) -> StoreStateV1 {
        let mut s = base.clone();
        s.merge(&base.clone(), &self.params, other).unwrap();
        self.check(&s);
        s
    }
}

trait SellerKey {
    fn seller_verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}
impl SellerKey for StoreParameters {
    fn seller_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        // `seller_verifying_key` is pub(crate); recover it through CBOR,
        // where the struct is a one-field map.
        #[derive(serde::Deserialize)]
        struct P {
            seller_verifying_key: ed25519_dalek::VerifyingKey,
        }
        let p: P = harvest_common::from_cbor(&cbor(self)).unwrap();
        p.seller_verifying_key
    }
}

fn gen_store(root: &Path) {
    let fx = StoreFx::new();
    let params = cbor(&fx.params);
    let l: Vec<AuthorizedListing> = (1..=6).map(|i| fx.listing(i)).collect();
    let o: Vec<Order> = (1..=6)
        .map(|i| fx.order(&format!("buyer-{i}"), 1_700_000_000 + i as i64 * 3600))
        .collect();
    let aw = |i: usize| fx.authorized(&o[i], OrderStatus::AwaitingPayment, 0);
    let cx = |i: usize| fx.authorized(&o[i], OrderStatus::Cancelled, 0);
    let pd = |i: usize, seed: u8| fx.authorized(&o[i], OrderStatus::Paid, seed);
    let rv = |i: usize| fx.authorized(&o[i], OrderStatus::PaymentReversed, 0);
    let i1 = fx.info(1, "Throwaway Farm");
    let i2 = fx.info(2, "Throwaway Farm (renamed)");

    let mut c = Corpus::new(root, "store", &params);
    let mut honest: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("info1", fx.build(Some(i1.clone()), vec![], vec![])),
        ("info2", fx.build(Some(i2.clone()), vec![], vec![])),
        ("info1_L1", fx.build(Some(i1.clone()), vec![l[0].clone()], vec![])),
        ("info1_L12", fx.build(Some(i1.clone()), vec![l[0].clone(), l[1].clone()], vec![])),
        ("info2_L23", fx.build(Some(i2.clone()), vec![l[1].clone(), l[2].clone()], vec![])),
        ("L145", fx.build(None, vec![l[0].clone(), l[3].clone(), l[4].clone()], vec![])),
        ("L6", fx.build(None, vec![l[5].clone()], vec![])),
        ("O1aw_O2aw", fx.build(Some(i1.clone()), vec![l[0].clone()], vec![aw(0), aw(1)])),
        ("O1paidA_O2aw_O3cx", fx.build(Some(i1.clone()), vec![], vec![pd(0, 1), aw(1), cx(2)])),
        ("O1paidB_O3aw", fx.build(None, vec![l[2].clone()], vec![pd(0, 2), aw(2)])),
        ("O1rev_O2cx", fx.build(Some(i2.clone()), vec![], vec![rv(0), cx(1)])),
        ("O2paidA_O4aw_O5cx", fx.build(None, vec![l[1].clone(), l[2].clone()], vec![pd(1, 3), aw(3), cx(4)])),
        ("O2cx_O6aw", fx.build(Some(i2.clone()), vec![l[4].clone()], vec![cx(1), aw(5)])),
        ("O1aw", fx.build(None, vec![], vec![aw(0)])),
        ("O1cx", fx.build(None, vec![], vec![cx(0)])),
        ("O1paidA", fx.build(None, vec![], vec![pd(0, 1)])),
        ("O1paidB", fx.build(None, vec![], vec![pd(0, 2)])),
    ];
    // Transitions: base, and base with one real update applied.
    let trans: Vec<(&str, &str, StoreStateV1)> = vec![
        ("info1", "t_info1_plus_L1", fx.build(Some(i1.clone()), vec![l[0].clone()], vec![])),
        ("info1", "t_info1_to_info2", fx.build(Some(i2.clone()), vec![], vec![])),
        ("O1aw_O2aw", "t_O1aw_O2aw_to_O1paid", fx.build(None, vec![], vec![pd(0, 1)])),
        ("O1aw_O2aw", "t_O1aw_O2aw_to_O2cx", fx.build(None, vec![], vec![cx(1)])),
        ("O1paidA_O2aw_O3cx", "t_paidA_to_rev", fx.build(None, vec![], vec![rv(0)])),
        ("O1paidB_O3aw", "t_paidB_meets_paidA", fx.build(None, vec![], vec![pd(0, 1)])),
        ("L145", "t_L145_plus_L23", fx.build(None, vec![l[1].clone(), l[2].clone()], vec![])),
    ];
    let mut extra = vec![];
    for (base, name, upd) in &trans {
        let b = &honest.iter().find(|(n, _)| n == base).unwrap().1;
        let r = fx.merged(b, upd);
        extra.push((*name, r));
        c.transition(base, name);
    }
    honest.extend(extra);
    for (n, s) in &honest {
        c.state(n, &cbor(s));
    }
    // Delta steps: what get_state_delta would send a peer holding `base`, and
    // what update_state(Delta) makes of it. Several per base so
    // delta_permutation_invariance has concurrent deltas to permute.
    let find = |n: &str| honest.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    for (base, targets) in [
        ("info1_L1", vec!["info1_L12", "O1aw_O2aw", "info2", "L145"]),
        ("O1aw_O2aw", vec!["O1paidA_O2aw_O3cx", "O1rev_O2cx", "O2cx_O6aw", "O1paidB_O3aw"]),
    ] {
        let b = find(base);
        let summ = b.summarize(&b, &fx.params);
        for t in targets {
            let tgt = find(t);
            let d = tgt.delta(&tgt, &fx.params, &summ).expect("non-empty delta");
            let mut r = b.clone();
            r.apply_delta(&b.clone(), &fx.params, &Some(d.clone())).unwrap();
            fx.check(&r);
            c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
        }
    }
    c.finish();

    // Honest + zero-byte state (#55).
    let mut c = Corpus::new(root, "store-empty", &params);
    c.state("zero_bytes", &[]);
    for (n, s) in &honest {
        c.state(n, &cbor(s));
    }
    c.finish();

    // Adversarial-valid: pass validate_state, not produced by update_state.
    let mut c = Corpus::new(root, "store-adv", &params);
    let base_hon = ["default", "info1_L12", "info2_L23", "L145", "O1paidA_O2aw_O3cx"];
    for n in base_hon {
        c.state(n, &cbor(&honest.iter().find(|(m, _)| *m == n).unwrap().1));
    }
    // #26: listings present but NOT in id order. Built directly because
    // apply_delta always sorts.
    let mut unsorted = vec![l[0].clone(), l[1].clone(), l[2].clone()];
    unsorted.sort_by(|a, b| b.listing.id.cmp(&a.listing.id));
    let s = StoreStateV1 {
        owner: Some(fx.seller.verifying_key()),
        info: i1.clone(),
        listings: ListingsV1 { listings: unsorted },
        orders: OrdersV1::default(),
        ..Default::default()
    };
    c.state("adv_unsorted_L123", &cbor(&s));
    // Duplicate listing entry: ListingsV1::verify has no uniqueness check.
    let s = StoreStateV1 {
        owner: Some(fx.seller.verifying_key()),
        info: i1.clone(),
        listings: ListingsV1 {
            listings: vec![l[0].clone(), l[0].clone()],
        },
        orders: OrdersV1::default(),
        ..Default::default()
    };
    c.state("adv_dup_L1", &cbor(&s));
    // certificate_pem is outside the listing signature.
    let mut l1_other_cert = l[0].clone();
    l1_other_cert.certificate_pem = "-----BEGIN SOME OTHER CERT-----".into();
    let s = fx.build(Some(i1.clone()), vec![l1_other_cert], vec![]);
    c.state("adv_L1_other_cert", &cbor(&s));
    // Seller equivocation: two different, validly-signed infos at version 2
    // (e.g. two tabs both bumping from 1).
    let i2b = fx.info(2, "Throwaway Farm (other tab)");
    let s = fx.build(Some(i2b), vec![], vec![]);
    c.state("adv_info2_other_tab", &cbor(&s));
    c.finish();

    // Cap corpus: MAX_ORDERS with a status whose eviction priority is not
    // monotone in rank (AwaitingPayment active, Cancelled terminal).
    let mut c = Corpus::new(root, "store-cap", &params);
    let x = fx.order("buyer-x-newest", 1_800_000_000);
    let p = fx.build(None, vec![], vec![fx.authorized(&x, OrderStatus::AwaitingPayment, 0)]);
    let q = fx.build(None, vec![], vec![fx.authorized(&x, OrderStatus::Cancelled, 0)]);
    let many: Vec<AuthorizedOrder> = (0..MAX_ORDERS)
        .map(|i| {
            let o = fx.order(&format!("bulk-{i}"), 1_700_000_000 + i as i64);
            fx.authorized(&o, OrderStatus::AwaitingPayment, 0)
        })
        .collect();
    let r = fx.build(None, vec![], many);
    assert_eq!(r.orders.orders.len(), MAX_ORDERS);
    c.state("cap_P_x_awaiting", &cbor(&p));
    c.state("cap_Q_x_cancelled", &cbor(&q));
    c.state("cap_R_full_awaiting", &cbor(&r));
    // Native reference computation of the two groupings.
    let pq_r = fx.merged(&fx.merged(&p, &q), &r);
    let p_qr = fx.merged(&p, &fx.merged(&q, &r));
    println!(
        "store-cap native: (P+Q)+R == P+(Q+R)? {}   [(P+Q)+R holds x: {:?}; P+(Q+R) holds x: {:?}]",
        cbor(&pq_r) == cbor(&p_qr),
        pq_r.orders.orders.get(&x.id).map(|r| r.status),
        p_qr.orders.orders.get(&x.id).map(|r| r.status)
    );
    c.finish();
}

// ---------------------------------------------------------------------------
// Reputation
// ---------------------------------------------------------------------------

fn gen_reputation(root: &Path) {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    let mut rng = rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let der = rsa::RsaPublicKey::from(&private)
        .to_pkcs1_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let owner = SigningKey::from_bytes(&[0xC3; 32]).verifying_key();
    let params = ReputationParameters::new(der, owner);
    let pbytes = cbor(&params);
    let signer = BlindedSigningKey::<sha2::Sha256>::new(private);

    // PR #82 (#22): the token carries a per-token Ed25519 key that signs the
    // whole entry.
    let entry_key = |n: u8| SigningKey::from_bytes(&[n.wrapping_add(1); 32]);
    let entry = |n: u8, cat: FeedbackCategory, comment: &str| {
        // PR #82 review Must Fix 1: the nonce is derived from the key.
        let token = FeedbackToken::new([5u8; 32], entry_key(n).verifying_key().to_bytes());
        let signature = signer.sign_with_rng(&mut rand_core::OsRng, &cbor(&token)).to_vec();
        FeedbackEntry::sign(
            token,
            signature,
            cat,
            comment.into(),
            ts(1_700_000_000 + n as i64 * 100),
            &entry_key(n),
        )
    };
    let f: Vec<FeedbackEntry> = (1u8..=6)
        .map(|n| {
            entry(
                n * 17,
                match n % 3 {
                    0 => FeedbackCategory::NonDelivery,
                    1 => FeedbackCategory::Misrepresented,
                    _ => FeedbackCategory::Other(format!("reason {n}")),
                },
                &format!("comment {n}"),
            )
        })
        .collect();

    let build = |cert: &str, entries: Vec<FeedbackEntry>| {
        let mut s = ReputationStateV1 {
            owner_certificate_pem: cert.into(),
            ..Default::default()
        };
        if !entries.is_empty() {
            s.apply_delta(&params, &Some(entries)).unwrap();
        }
        s.verify(&params).unwrap();
        s
    };
    let cert = "-----BEGIN THROWAWAY OWNER CERT-----";
    let merged = |base: &ReputationStateV1, other: &ReputationStateV1| {
        // Mirror of update_state's State arm.
        let mut s = base.clone();
        s.merge(&params, other).unwrap();
        s.verify(&params).unwrap();
        s
    };

    let mut honest: Vec<(&str, ReputationStateV1)> = vec![
        ("default", ReputationStateV1::default()),
        ("cert_only", build(cert, vec![])),
        ("F1", build(cert, vec![f[0].clone()])),
        ("F12", build(cert, vec![f[0].clone(), f[1].clone()])),
        ("F23", build(cert, vec![f[1].clone(), f[2].clone()])),
        ("F345", build(cert, vec![f[2].clone(), f[3].clone(), f[4].clone()])),
        ("F16_nocert", build("", vec![f[0].clone(), f[5].clone()])),
        ("F123456", build(cert, f.clone())),
    ];
    let trans = vec![
        ("F1", "t_F1_plus_F2", build("", vec![f[1].clone()])),
        ("cert_only", "t_cert_plus_F3", build("", vec![f[2].clone()])),
        ("F16_nocert", "t_F16_gets_cert_and_F4", build(cert, vec![f[3].clone()])),
    ];
    let mut c = Corpus::new(root, "reputation", &pbytes);
    let mut extra = vec![];
    for (base, name, upd) in &trans {
        let b = &honest.iter().find(|(n, _)| n == base).unwrap().1;
        extra.push((*name, merged(b, upd)));
        c.transition(base, name);
    }
    honest.extend(extra);
    for (n, s) in &honest {
        c.state(n, &cbor(s));
    }
    let find = |n: &str| honest.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    for (base, targets) in [("F1", vec!["F12", "F23", "F345"]), ("default", vec!["F1", "F23"])] {
        let b = find(base);
        let summ = b.summarize();
        for t in targets {
            let d = find(t).delta(&summ).expect("non-empty delta");
            let mut r = b.clone();
            r.apply_delta(&params, &Some(d.clone())).unwrap();
            r.verify(&params).unwrap();
            c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
        }
    }
    c.finish();

    let mut c = Corpus::new(root, "reputation-empty", &pbytes);
    c.state("zero_bytes", &[]);
    for (n, s) in &honest {
        c.state(n, &cbor(s));
    }
    c.finish();

    let mut c = Corpus::new(root, "reputation-adv", &pbytes);
    for n in ["default", "F1", "F12", "F23"] {
        c.state(n, &cbor(&honest.iter().find(|(m, _)| *m == n).unwrap().1));
    }
    // #22: same token + signature, different category/comment. A THIRD
    // PARTY's variant (entry signature not redone) no longer verifies, so it
    // is stored raw: the contract must refuse it.
    let mut f1v = f[0].clone();
    f1v.category = FeedbackCategory::Other("no complaint".into());
    f1v.comment = "actually it was fine".into();
    let raw = ReputationStateV1 {
        owner_certificate_pem: cert.into(),
        used_nonces: [f1v.token.nonce].into_iter().collect(),
        feedback: vec![f1v],
    };
    assert!(raw.verify(&params).is_err());
    c.state("adv_F1_variant", &cbor(&raw));
    // The BUYER's own second entry for the same token (validly signed).
    let f1b = entry(17, FeedbackCategory::Other("second thoughts".into()), "changed my mind");
    c.state("adv_F1_buyer_variant", &cbor(&build(cert, vec![f1b])));
    // PR #82 review Must Fix 1: the RSA key holder (the seller) mints a token
    // for the buyer's PUBLISHED slot with a key of its own. Refused now.
    let seller_key = SigningKey::from_bytes(&[0x77; 32]);
    let minted = FeedbackToken {
        target_reputation_contract: [5u8; 32],
        nonce: f[0].token.nonce,
        entry_key: seller_key.verifying_key().to_bytes(),
    };
    let minted_sig = signer.sign_with_rng(&mut rand_core::OsRng, &cbor(&minted)).to_vec();
    let minted = FeedbackEntry::sign(minted, minted_sig, FeedbackCategory::Other("fine".into()), "all good".into(), ts(1_700_000_050), &seller_key);
    let raw = ReputationStateV1 {
        owner_certificate_pem: cert.into(),
        used_nonces: [minted.token.nonce].into_iter().collect(),
        feedback: vec![minted],
    };
    assert!(raw.verify(&params).is_err());
    c.state("adv_seller_minted_slot", &cbor(&raw));
    // A different non-empty owner certificate (not covered by anything).
    c.state("adv_other_cert_F2", &cbor(&build("-----BEGIN OTHER CERT-----", vec![f[1].clone()])));
    // Unsorted feedback: verify does not require order.
    let mut s = build(cert, vec![f[0].clone(), f[1].clone(), f[2].clone()]);
    s.feedback.reverse();
    c.state("adv_unsorted_F123", &cbor(&s));
    c.finish();
}

// ---------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------

fn msg(conv: u8, nonce: u8, ct_len: usize, fill: u8, secs: i64) -> EncryptedMessage {
    EncryptedMessage {
        conversation_id: ConversationId([conv; 32]),
        sender_public_key: vec![0x5Au8; 32],
        ciphertext: vec![fill; ct_len],
        timestamp: ts(secs),
        nonce: [nonce; 24],
    }
}

fn gen_mailbox(root: &Path) {
    let owner = SigningKey::from_bytes(&[0xD4; 32]).verifying_key();
    let pbytes = cbor(&MailboxParameters::new(owner));
    let build = |msgs: Vec<EncryptedMessage>| {
        let mut s = MailboxStateV1::default();
        s.apply_delta(&Some(msgs)).unwrap();
        s.verify().unwrap();
        s
    };
    let merged = |base: &MailboxStateV1, other: &MailboxStateV1| {
        let mut s = base.clone();
        s.apply_delta(&Some(other.messages.clone())).unwrap();
        s.verify().unwrap();
        s
    };
    // 1024-byte bucket ciphertexts, as the UI would pad a short message.
    let m: Vec<EncryptedMessage> = (1u8..=6)
        .map(|i| msg(i % 2, i, 1024 + 16, i, 1_700_000_000 + i as i64 * 10))
        .collect();
    // Same nonce as m[5], different content: two distinct messages.
    let m6b = msg(0, 6, 1024 + 16, 0xEE, 1_700_000_061);

    let mut honest: Vec<(&str, MailboxStateV1)> = vec![
        ("default", MailboxStateV1::default()),
        ("M1", build(vec![m[0].clone()])),
        ("M12", build(vec![m[0].clone(), m[1].clone()])),
        ("M23", build(vec![m[1].clone(), m[2].clone()])),
        ("M345", build(vec![m[2].clone(), m[3].clone(), m[4].clone()])),
        ("M6", build(vec![m[5].clone()])),
        ("M6b", build(vec![m6b.clone()])),
        ("M1_6_6b", build(vec![m[0].clone(), m[5].clone(), m6b.clone()])),
    ];
    let trans = vec![
        ("M1", "t_M1_plus_M2", build(vec![m[1].clone()])),
        ("M6", "t_M6_plus_M6b", build(vec![m6b.clone()])),
        ("default", "t_default_plus_M4", build(vec![m[3].clone()])),
    ];
    let mut c = Corpus::new(root, "mailbox", &pbytes);
    let mut extra = vec![];
    for (base, name, upd) in &trans {
        let b = &honest.iter().find(|(n, _)| n == base).unwrap().1;
        extra.push((*name, merged(b, upd)));
        c.transition(base, name);
    }
    honest.extend(extra);
    for (n, s) in &honest {
        c.state(n, &cbor(s));
    }
    let find = |n: &str| honest.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    for (base, targets) in [("M1", vec!["M12", "M23", "M1_6_6b"]), ("M6", vec!["M6b", "M345"])] {
        let b = find(base);
        let summ = b.summarize();
        for t in targets {
            let d = find(t).delta(&summ).expect("non-empty delta");
            let mut r = b.clone();
            r.apply_delta(&Some(d.clone())).unwrap();
            r.verify().unwrap();
            c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
        }
    }
    c.finish();

    let mut c = Corpus::new(root, "mailbox-empty", &pbytes);
    c.state("zero_bytes", &[]);
    for (n, s) in &honest {
        c.state(n, &cbor(s));
    }
    c.finish();

    let mut c = Corpus::new(root, "mailbox-adv", &pbytes);
    for n in ["default", "M12", "M23"] {
        c.state(n, &cbor(&honest.iter().find(|(m, _)| *m == n).unwrap().1));
    }
    let mut s = build(vec![m[0].clone(), m[1].clone(), m[2].clone()]);
    s.messages.reverse();
    c.state("adv_unsorted_M123", &cbor(&s));
    // A message over MAX_MESSAGE_BYTES: verify accepts it, apply_delta refuses it.
    let big = msg(1, 99, MAX_MESSAGE_BYTES, 0x77, 1_700_000_500);
    let s = MailboxStateV1 {
        messages: vec![big],
    };
    c.state("adv_oversized_msg", &cbor(&s));
    c.finish();

    // Cap corpus: MAX_MAILBOX_BYTES greedy-with-skip.
    //
    // fdev skips any case whose inputs exceed 4 MiB (GeneratorConfig::
    // max_case_bytes, not settable from the CLI), and the counterexample needs
    // P+Q to exceed MAX_MAILBOX_BYTES (4 MiB of message_bytes). It still fits
    // because message_bytes charges a flat 192-byte envelope per message while
    // the CBOR costs less, so: many mid-size messages, and every byte value
    // below 24 so CBOR encodes each Vec<u8>/[u8; N] element in ONE byte.
    //   P = 500 messages of 8_300 bytes + y0, totalling budget - 500
    //   Q = x, 600 bytes, oldest
    //   R = r1, 600 bytes, newest
    // (P+Q)+R drops x (P+Q overflows, x ranks last), then r1 evicts y0.
    // P+(Q+R): r1 first, the 500 fit, y0 is skipped, and x now fits.
    let small = |i: u32, size: usize, secs: i64| {
        let env = 192 + 32;
        let mut nonce = [0u8; 24];
        nonce[0] = (i % 24) as u8;
        nonce[1] = ((i / 24) % 24) as u8;
        nonce[2] = (i / 576) as u8;
        EncryptedMessage {
            conversation_id: ConversationId([2u8; 32]),
            sender_public_key: vec![1u8; 32],
            ciphertext: vec![(i % 23) as u8 + 1; size - env],
            timestamp: ts(secs),
            nonce,
        }
    };
    let mut pm: Vec<EncryptedMessage> =
        (0..500u32).map(|i| small(i, 8_300, 1_700_002_000 + i as i64)).collect();
    let y0_size = MAX_MAILBOX_BYTES - 500 - 500 * 8_300;
    assert!(y0_size <= MAX_MESSAGE_BYTES);
    pm.push(small(500, y0_size, 1_700_001_500));
    let x = small(501, 600, 1_700_001_000);
    let r1 = small(502, 600, 1_700_003_000);
    let p = build(pm);
    let total: usize = p.messages.iter().map(harvest_common::mailbox::message_bytes).sum();
    // PR #82 (#85): P is now pruned by the size-class caps, so it no longer
    // holds all 501. The shape is kept; the laws must hold either way.
    println!("mailbox-cap: P holds {} messages, {} bytes", p.messages.len(), total);
    let q = build(vec![x.clone()]);
    let r = build(vec![r1]);
    let pq_r = merged(&merged(&p, &q), &r);
    let p_qr = merged(&p, &merged(&q, &r));
    println!(
        "mailbox-cap native: (P+Q)+R == P+(Q+R)? {}  [(P+Q)+R has x: {}; P+(Q+R) has x: {}]; encoded P+Q+R = {} bytes (fdev case cap 4194304)",
        cbor(&pq_r) == cbor(&p_qr),
        pq_r.messages.contains(&x),
        p_qr.messages.contains(&x),
        cbor(&p).len() + cbor(&q).len() + cbor(&r).len()
    );
    let mut c = Corpus::new(root, "mailbox-cap", &pbytes);
    c.state("cap_P_full", &cbor(&p));
    c.state("cap_Q_small_oldest", &cbor(&q));
    c.state("cap_R_newest", &cbor(&r));
    c.finish();
}

// ---------------------------------------------------------------------------
// Review additions (PR #82 review): boundary ties and non-canonical encodings
// ---------------------------------------------------------------------------

/// Same value, non-canonical bytes: a trailing byte, and an unknown map key.
fn noncanon(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut trailing = bytes.to_vec();
    trailing.push(0x00);
    let mut v: ciborium::Value = ciborium::from_reader(bytes).unwrap();
    if let ciborium::Value::Map(ref mut m) = v {
        m.push((ciborium::Value::Text("zz_unknown".into()), ciborium::Value::Integer(0.into())));
    } else {
        panic!("not a map");
    }
    let mut extra = vec![];
    ciborium::into_writer(&v, &mut extra).unwrap();
    (trailing, extra)
}

fn gen_review(root: &Path) {
    // ---- store: order cap boundary with created_at ties and same-rank variants
    let fx = StoreFx::new();
    let params = cbor(&fx.params);
    let t0 = 1_700_000_000;
    let orders: Vec<Order> = (0..MAX_ORDERS).map(|i| fx.order(&format!("tie-{i}"), t0)).collect();
    let x = fx.order("tie-x", t0);
    // The boundary key: the smallest id among R and x is the one cut when x arrives.
    let mut all: Vec<&Order> = orders.iter().collect();
    all.push(&x);
    all.sort_by(|a, b| a.id.cmp(&b.id));
    let lowest = all[0].clone();
    let second = all[1].clone();
    let r = fx.build(None, vec![], orders.iter().map(|o| fx.authorized(o, OrderStatus::AwaitingPayment, 0)).collect());
    let mut c = Corpus::new(root, "store-cap2", &params);
    c.state("R_full_tied", &cbor(&r));
    c.state("P_x_aw", &cbor(&fx.build(None, vec![], vec![fx.authorized(&x, OrderStatus::AwaitingPayment, 0)])));
    c.state("Q_x_paid1", &cbor(&fx.build(None, vec![], vec![fx.authorized(&x, OrderStatus::Paid, 1)])));
    c.state("Q_x_paid2", &cbor(&fx.build(None, vec![], vec![fx.authorized(&x, OrderStatus::Paid, 2)])));
    c.state("S_low_paid1", &cbor(&fx.build(None, vec![], vec![fx.authorized(&lowest, OrderStatus::Paid, 1)])));
    c.state("S_low_paid2_second_cx", &cbor(&fx.build(None, vec![], vec![
        fx.authorized(&lowest, OrderStatus::Paid, 2),
        fx.authorized(&second, OrderStatus::Cancelled, 0),
    ])));
    println!("store-cap2: x is lowest id? {}", lowest.id == x.id);
    c.finish();

    // ---- store: non-canonical encodings of a valid state
    let l1 = fx.listing(1);
    let honest = fx.build(Some(fx.info(1, "Throwaway Farm")), vec![l1.clone()], vec![]);
    let hb = cbor(&honest);
    let (trail, extra) = noncanon(&hb);
    let mut c = Corpus::new(root, "store-noncanon", &params);
    c.state("honest", &hb);
    c.state("honest_trailing_byte", &trail);
    c.state("honest_unknown_field", &extra);
    c.state("L2", &cbor(&fx.build(None, vec![fx.listing(2)], vec![])));
    c.finish();

    // ---- mailbox: class-3 cap boundary, total-cap boundary, and non-canonical
    let owner = SigningKey::from_bytes(&[0xD4; 32]).verifying_key();
    let pbytes = cbor(&MailboxParameters::new(owner));
    let build = |msgs: Vec<EncryptedMessage>| {
        let mut s = MailboxStateV1::default();
        s.apply_delta(&Some(msgs)).unwrap();
        s.verify().unwrap();
        s
    };
    let mk = |i: u32, ct: usize, fill: u8, secs: i64| {
        let mut nonce = [0u8; 24];
        nonce[0] = (i % 24) as u8;
        nonce[1] = ((i / 24) % 24) as u8;
        nonce[2] = (i / 576) as u8;
        EncryptedMessage {
            conversation_id: ConversationId([3u8; 32]),
            sender_public_key: vec![1u8; 32],
            ciphertext: vec![fill; ct],
            timestamp: ts(secs),
            nonce,
        }
    };
    let big = 65536 + 16; // class 3
    let p24: Vec<EncryptedMessage> = (0..24u32).map(|i| mk(i, big, 1, 1_700_002_000 + i as i64)).collect();
    let lowest = p24[0].clone();
    let mut tie = lowest.clone();
    tie.ciphertext = vec![2; big]; // same timestamp and nonce as the boundary msg, different digest
    let mut c = Corpus::new(root, "mailbox-cap2", &pbytes);
    c.state("P_class3_full", &cbor(&build(p24.clone())));
    c.state("Q_class3_oldest", &cbor(&build(vec![mk(100, big, 3, 1_700_001_000)])));
    c.state("R_class3_newest", &cbor(&build(vec![mk(101, big, 4, 1_700_003_000)])));
    c.state("T_class3_tie_at_boundary", &cbor(&build(vec![tie])));
    c.state("U_class0_small", &cbor(&build(vec![mk(102, 1040, 5, 1_700_000_500)])));
    c.finish();

    let t512: Vec<EncryptedMessage> = (0..512u32).map(|i| mk(i, 1040, (i % 20) as u8 + 1, 1_700_010_000 + i as i64)).collect();
    let mut c = Corpus::new(root, "mailbox-cap3", &pbytes);
    let full = build(t512);
    assert_eq!(full.messages.len(), 512);
    c.state("T_total_full", &cbor(&full));
    c.state("U_class1_mid", &cbor(&build(vec![mk(600, 4096 + 16, 7, 1_700_010_256)])));
    c.state("V_class0_oldest", &cbor(&build(vec![mk(601, 1040, 8, 1_700_000_001)])));
    c.state("W_class0_newest", &cbor(&build(vec![mk(602, 1040, 9, 1_800_000_000)])));
    c.finish();

    let hb = cbor(&build(vec![mk(1, 1040, 1, 1_700_000_000), mk(2, 1040, 2, 1_700_000_010)]));
    let (trail, extra) = noncanon(&hb);
    let mut c = Corpus::new(root, "mailbox-noncanon", &pbytes);
    c.state("honest", &hb);
    c.state("honest_trailing_byte", &trail);
    c.state("honest_unknown_field", &extra);
    c.state("M3", &cbor(&build(vec![mk(3, 1040, 3, 1_700_000_020)])));
    c.finish();
}

use harvest_common::custody::{AuthorizedCopy, StoreKeyCopy, WrapScope, WrappedStoreKey};

/// Store-key custody (harvest#93 phase 1b): wrapped copies, their tombstone
/// (the backer's retirement), the per-backer scope bound, and copies racing
/// the backings they depend on.
fn gen_copies(root: &Path) {
    let bx = BackingFx::new();
    let params = cbor(&bx.fx.params);
    let p = &bx.fx.params;
    let g1 = SigningKey::from_bytes(&[0xD1; 32]);
    let g2 = SigningKey::from_bytes(&[0xD2; 32]);
    let g9 = SigningKey::from_bytes(&[0xD9; 32]);
    let b1 = bx.backing(&g1, 100);
    let b2 = bx.backing(&g2, 200);
    let r1 = bx.retirement_by(&bx.store, &g1);
    let closed = bx.closure_by(&bx.store);
    let c1a = bx.copy(&g1, 0x10, 0xA1);
    let c1a_other = bx.copy(&g1, 0x10, 0xA2); // same slot, different bytes
    let c1b = bx.copy(&g1, 0x20, 0xB1);
    let c2a = bx.copy(&g2, 0x10, 0xC1);
    // Six scopes for g1, split across two sides of four: the union holds
    // six and the merge keeps the four smallest.
    let c1s: Vec<AuthorizedCopy> = (1..=6u8).map(|i| bx.copy(&g1, 0x30 + i, 0xD0 + i)).collect();
    let l3 = bx.fx.listing(3);

    let states: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("B1", bx.build(None, vec![], vec![b1.clone()], vec![], vec![])),
        ("B1_C1a", bx.build_c(None, vec![], vec![b1.clone()], vec![], vec![], vec![c1a.clone()])),
        ("B1_C1a_other", bx.build_c(None, vec![], vec![b1.clone()], vec![], vec![], vec![c1a_other.clone()])),
        ("B1_C1ab", bx.build_c(None, vec![], vec![b1.clone()], vec![], vec![], vec![c1a.clone(), c1b.clone()])),
        ("B12_C2a", bx.build_c(None, vec![], vec![b1.clone(), b2.clone()], vec![], vec![], vec![c2a.clone()])),
        ("B12_C1a_C2a", bx.build_c(None, vec![], vec![b1.clone(), b2.clone()], vec![], vec![], vec![c1a.clone(), c2a.clone()])),
        ("B1_R1", bx.build(None, vec![], vec![b1.clone()], vec![r1.clone()], vec![])),
        ("B12_R1_C2a", bx.build_c(None, vec![], vec![b1.clone(), b2.clone()], vec![r1.clone()], vec![], vec![c2a.clone()])),
        ("B1_C1low4", bx.build_c(None, vec![], vec![b1.clone()], vec![], vec![], c1s[0..4].to_vec())),
        ("B1_C1high4", bx.build_c(None, vec![], vec![b1.clone()], vec![], vec![], c1s[2..6].to_vec())),
        // A copy arriving before its backing (the #98 re-check, for custody).
        ("C1a_only", bx.build_c(None, vec![], vec![], vec![], vec![], vec![c1a.clone()])),
        ("R1_C2a", bx.build_c(None, vec![], vec![], vec![r1.clone()], vec![], vec![c2a.clone()])),
        ("B1_C1a_closed_L3", bx.build_c(None, vec![l3.clone()], vec![b1.clone()], vec![], vec![closed.clone()], vec![c1a.clone()])),
    ];
    native_laws_total("copies", p, &states);

    let pairs = [
        ("B1_C1a", "B1_R1"), ("B1_R1", "B1_C1a"),
        ("B1_C1a", "B1_C1a_other"), ("B1_C1a_other", "B1_C1a"),
        ("B1_C1low4", "B1_C1high4"), ("B1_C1high4", "B1_C1low4"),
        ("B12_C2a", "B1_C1ab"), ("B1_C1ab", "B12_R1_C2a"),
        ("B1", "B12_C1a_C2a"), ("default", "B1_C1a"),
        ("B1_C1a_closed_L3", "B1_R1"), ("B12_R1_C2a", "B1_C1a"),
        ("C1a_only", "B1"), ("B1", "C1a_only"), ("C1a_only", "B1_R1"), ("B1_R1", "C1a_only"), ("R1_C2a", "B12_C2a"), ("B12_C2a", "R1_C2a"),
    ];
    let mut c = Corpus::new(root, "store-copies", &params);
    let mut all = states.clone();
    let find = |all: &Vec<(&str, StoreStateV1)>, n: &str| all.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    let mut extra = vec![];
    for (a, b) in pairs {
        let r = bx.fx.merged(&find(&all, a), &find(&all, b));
        let name: &'static str = Box::leak(format!("m_{a}__{b}").into_boxed_str());
        extra.push((a, name, r));
    }
    for (_, n, s) in &extra { all.push((n, s.clone())); }
    // The facts the tests pin, checked here against the real merge.
    let tomb = find(&all, "m_B1_C1a__B1_R1");
    println!("copies: retirement tombstones the copy? {}", tomb.copies.records.is_empty());
    let six = find(&all, "m_B1_C1low4__B1_C1high4");
    println!("copies: 6 scopes -> kept {}", six.copies.records.len());
    for (n, s) in &all { c.state(n, &cbor(s)); }
    for (a, n, _) in &extra { c.transition(a, n); }
    for (a, b) in pairs {
        let base = find(&all, a);
        let tgt = find(&all, b);
        let summ = base.summarize(&base, p);
        let Some(d) = tgt.delta(&tgt, p, &summ) else { continue };
        let mut r = base.clone();
        r.apply_delta(&base.clone(), p, &Some(d.clone())).expect("a copies delta applies");
        bx.fx.check(&r);
        c.delta_step(&cbor(&base), &cbor(&summ), &cbor(&d), &cbor(&r));
    }
    c.finish();

    // States the contract must refuse.
    let base = bx.build(None, vec![], vec![b1.clone()], vec![], vec![]);
    let raw = |copy: AuthorizedCopy| {
        let mut s = base.clone();
        s.copies.records.insert(AuthorizedCopy::slot_for(&copy.copy.backer, &copy.copy.scope), copy);
        assert!(s.verify(&s, p).is_err(), "an invalid fixture must be one the contract refuses");
        s
    };
    let mut short = bx.copy(&g1, 0x10, 0xEE);
    short.copy.wrapped.ciphertext.truncate(40);
    let bad: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("B1", base.clone()),
        ("B1_C1a", find(&all, "B1_C1a")),
        ("bad_copy_by_stranger", raw(bx.copy_by(&g9, &g1, 0x10, 0xEE))),
        ("bad_copy_short", raw(short)),
    ];
    let mut c = Corpus::new(root, "store-copies-bad", &params);
    for (n, s) in &bad { c.state(n, &cbor(s)); }
    c.finish();
}


use harvest_common::ghostkey_index::{GhostKeyIndexV1, IndexEntry, IndexParameters, MAX_INDEX_ENTRIES};

/// The Ghost Key index (harvest#93 phase 1c): honest indexes, a same-slot
/// clash, unions past the bound with delta steps, and invalid states.
fn gen_index(root: &Path) {
    let ghost = SigningKey::from_bytes(&[0xE1; 32]);
    let params = IndexParameters::new(ghost.verifying_key());
    let pbytes = cbor(&params);
    let entry_by = |signer: &SigningKey, backer: &SigningKey, store: u32, height: u32| {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&(store + 9000).to_le_bytes());
        let statement = BackingStatement {
            store: SigningKey::from_bytes(&seed).verifying_key(),
            backer: backer.verifying_key(),
            certificate_pem: format!("CERT-{height}"),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor { height, hash: BlockHash([height as u8; 32]) },
        };
        let (scoped_payload, signature) = sign_scoped(signer, &statement);
        IndexEntry { statement, scoped_payload, signature }
    };
    let entry = |store: u32, height: u32| entry_by(&ghost, &ghost, store, height);
    let build = |es: Vec<IndexEntry>| {
        let mut i = GhostKeyIndexV1::default();
        i.apply_delta(&params, &es).unwrap();
        i.verify(&params).unwrap();
        i
    };
    let merge = |a: &GhostKeyIndexV1, b: &GhostKeyIndexV1| {
        let mut m = a.clone();
        m.merge(&params, b).unwrap();
        m
    };

    let write = |name: &str, states: Vec<(&str, GhostKeyIndexV1)>, pairs: &[(&str, &str)]| {
        let mut c = Corpus::new(root, name, &pbytes);
        let mut all = states.clone();
        let find = |all: &Vec<(&str, GhostKeyIndexV1)>, n: &str| all.iter().find(|(m, _)| *m == n).unwrap().1.clone();
        let mut extra = vec![];
        for (a, b) in pairs {
            let r = merge(&find(&all, a), &find(&all, b));
            let n: &'static str = Box::leak(format!("m_{a}__{b}").into_boxed_str());
            extra.push((*a, n, r));
        }
        for (_, n, s) in &extra { all.push((n, s.clone())); }
        // native laws (valid states only)
        let (mut comm, mut assoc, mut idem) = (0, 0, 0);
        for (_, a) in all.iter().filter(|_| !name.ends_with("-bad")) {
            if cbor(&merge(a, a)) != cbor(a) { idem += 1; }
            for (_, b) in &all {
                if cbor(&merge(a, b)) != cbor(&merge(b, a)) { comm += 1; }
                for (_, c3) in &all {
                    if cbor(&merge(&merge(a, b), c3)) != cbor(&merge(a, &merge(b, c3))) { assoc += 1; }
                }
            }
        }
        println!("{name} native: {} states; comm {comm} assoc {assoc} idem {idem}", all.len());
        for (n, s) in &all { c.state(n, &cbor(s)); }
        for (a, n, _) in &extra { c.transition(a, n); }
        for (a, b) in pairs {
            let base = find(&all, a);
            let tgt = find(&all, b);
            let summ = base.summarize();
            let Some(d) = tgt.delta(&summ) else { continue };
            let mut r = base.clone();
            r.apply_delta(&params, &d).unwrap();
            c.delta_step(&cbor(&base), &cbor(&summ), &cbor(&d), &cbor(&r));
        }
        c.finish();
    };

    let honest = vec![
        ("default", GhostKeyIndexV1::default()),
        ("E1", build(vec![entry(1, 10)])),
        ("E1b", build(vec![entry(1, 200)])), // same slot, different bytes
        ("E12", build(vec![entry(1, 10), entry(2, 10)])),
        ("E23", build(vec![entry(2, 10), entry(3, 10)])),
        ("E3", build(vec![entry(3, 10)])),
    ];
    write("index", honest, &[("E1", "E1b"), ("E1b", "E1"), ("E12", "E23"), ("E23", "E12"), ("default", "E12"), ("E3", "E1b"), ("E1", "E23"), ("E1", "E3"), ("E1", "E12")]);

    let n = MAX_INDEX_ENTRIES as u32;
    let cap = vec![
        ("default", GhostKeyIndexV1::default()),
        ("lowN", build((0..n).map(|i| entry(i, 10)).collect())),
        ("highN", build((8..n + 8).map(|i| entry(i, 10)).collect())),
        ("mid", build((4..n + 4).map(|i| entry(i, 300)).collect())),
        ("one", build(vec![entry(n + 7, 10)])),
    ];
    write("index-cap", cap, &[("lowN", "highN"), ("highN", "lowN"), ("mid", "lowN"), ("highN", "mid"), ("lowN", "one"), ("one", "highN")]);

    // Invalid: another key's statement, a bad signature, a wrong slot.
    let other = SigningKey::from_bytes(&[0xE2; 32]);
    let base = build(vec![entry(1, 10)]);
    let raw = |e: IndexEntry, slot: Option<[u8; 32]>| {
        let mut s = base.clone();
        let k = slot.map(harvest_common::store::Bytes32).unwrap_or(e.slot());
        s.entries.insert(k, e);
        assert!(s.verify(&params).is_err());
        s
    };
    let bad = vec![
        ("default", GhostKeyIndexV1::default()),
        ("E1", base.clone()),
        ("bad_other_key", raw(entry_by(&other, &other, 2, 10), None)),
        ("bad_signed_by_other", raw(entry_by(&other, &ghost, 3, 10), None)),
        ("bad_wrong_slot", raw(entry(4, 10), Some([7u8; 32]))),
    ];
    write("index-bad", bad, &[]);

    // ---- adversarial, added by the reviewer ----
    // Three-way same-slot clash on every slot, so the per-slot tie-break is
    // exercised from every side, plus a byte-identical duplicate.
    let clash = vec![
        ("default", GhostKeyIndexV1::default()),
        ("h10", build(vec![entry(1, 10), entry(2, 10), entry(3, 10)])),
        ("h200", build(vec![entry(1, 200), entry(2, 200), entry(3, 200)])),
        ("h300", build(vec![entry(1, 300), entry(2, 300), entry(3, 300)])),
        ("mixed", build(vec![entry(1, 300), entry(2, 10), entry(3, 200)])),
        ("dup10", build(vec![entry(1, 10), entry(1, 10), entry(2, 10)])),
        ("partial", build(vec![entry(2, 200), entry(4, 10)])),
    ];
    write("index-clash", clash, &[
        ("h10", "h200"), ("h200", "h10"), ("h300", "h10"), ("h10", "h300"),
        ("mixed", "h200"), ("h200", "mixed"), ("dup10", "h300"),
        ("partial", "h10"), ("h10", "partial"), ("default", "mixed"),
    ]);

    // Unions past the bound from several sides, with clashing entries at the
    // slots that straddle the cut, so truncation and the tie-break interact.
    let n = MAX_INDEX_ENTRIES as u32;
    let set = |lo: u32, hi: u32, h: u32| build((lo..hi).map(|i| entry(i, h)).collect::<Vec<_>>());
    let adv = vec![
        ("default", GhostKeyIndexV1::default()),
        ("A", set(0, 40, 10)),
        ("B", set(30, 70, 10)),
        ("C", set(55, n + 31, 10)),
        ("D", set(20, 60, 300)),
        ("E", set(0, n, 200)),
        ("F", build(vec![entry(n + 40, 10), entry(3, 300)])),
        ("full", set(0, n, 10)),
    ];
    write("index-adv", adv, &[
        ("A", "B"), ("B", "A"), ("B", "C"), ("C", "B"), ("A", "C"), ("C", "A"),
        ("D", "A"), ("A", "D"), ("E", "full"), ("full", "E"),
        ("F", "full"), ("full", "F"), ("D", "C"), ("C", "D"), ("default", "C"),
    ]);
}

fn main() {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: harvest-merge-corpus <output-root> [store|reputation|mailbox]..."),
    );
    let which: Vec<String> = std::env::args().skip(2).collect();
    let want = |n: &str| which.is_empty() || which.iter().any(|w| w == n);
    if want("store") {
        gen_store(&root);
    }
    if want("claim") {
        gen_claim(&root);
    }
    if want("triad") {
        gen_triad(&root);
    }
    if want("triadcap") {
        gen_triadcap(&root);
    }
    if want("reputation") {
        gen_reputation(&root);
    }
    if want("mailbox") {
        gen_mailbox(&root);
    }
    if want("review") {
        gen_review(&root);
    }
    if want("rr") {
        gen_rr(&root);
    }
    if want("backing") {
        gen_backing(&root);
    }
    if want("review98") {
        gen_review98(&root);
    }
    if want("index") {
        gen_index(&root);
    }
    if want("copies") {
        gen_copies(&root);
    }
    if want("retire98") {
        gen_retire98(&root);
    }
    if want("fulfilment") {
        gen_fulfilment(&root);
    }
}

use harvest_common::fulfilment::{AuthorizedDespatch, Despatch};

/// harvest#53 Phase B: the buyer's cancel (signed by the order's receipt key)
/// racing the seller's, a payment over both, the seller's despatches (two
/// anchors for one order, a clash in one slot), a despatch arriving with and
/// without its order, and a despatched order pushed out by the order cap.
fn gen_fulfilment(root: &Path) {
    let fx = StoreFx::new();
    let params = cbor(&fx.params);
    let p = &fx.params;
    let buyer = SigningKey::from_bytes(&[0xE7; 32]);
    let stranger = SigningKey::from_bytes(&[0xE9; 32]);
    let keyed = |who: &str, created: i64| {
        let mut o = fx.order(who, created);
        o.buyer_receipt_key = Some(buyer.verifying_key().to_bytes());
        o.with_derived_id()
    };
    let x = keyed("buyer-x", 1_750_000_000);
    let y = keyed("buyer-y", 1_750_000_100);
    let cancelled_by = |o: &Order, signer: &SigningKey| {
        let mut rec = fx.authorized(o, OrderStatus::AwaitingPayment, 0);
        let (sp, sig) = sign_scoped(signer, &(o.id.clone(), OrderStatus::Cancelled));
        rec.status = OrderStatus::Cancelled;
        rec.status_scoped_payload = Some(sp);
        rec.status_signature = Some(sig);
        rec.verify(&fx.seller.verifying_key()).expect("fixture cancel verifies");
        rec
    };
    let despatch_by = |o: &Order, height: u32, signer: &SigningKey| {
        let despatch = Despatch {
            order_id: o.id.clone(),
            anchor: BlockAnchor { height, hash: BlockHash([height as u8; 32]) },
        };
        let (scoped_payload, signature) = sign_scoped(signer, &despatch);
        AuthorizedDespatch { despatch, scoped_payload, signature }
    };
    let with = |orders: Vec<AuthorizedOrder>, ds: Vec<AuthorizedDespatch>| {
        let mut s = StoreStateV1::default();
        let delta = StoreStateV1Delta {
            owner: Some(fx.seller.verifying_key()),
            orders: (!orders.is_empty()).then_some(orders),
            fulfilment: (!ds.is_empty()).then_some(ds),
            ..Default::default()
        };
        s.apply_delta(&StoreStateV1::default(), p, &Some(delta)).unwrap();
        fx.check(&s);
        s
    };
    let xa = fx.authorized(&x, OrderStatus::AwaitingPayment, 0);
    let xc_seller = cancelled_by(&x, &fx.seller);
    let xc_buyer = cancelled_by(&x, &buyer);
    let xp = fx.authorized(&x, OrderStatus::Paid, 3);
    let ya = fx.authorized(&y, OrderStatus::AwaitingPayment, 0);
    let yp = fx.authorized(&y, OrderStatus::Paid, 5);
    let dx1 = despatch_by(&x, 150, &fx.seller);
    let dx2 = despatch_by(&x, 160, &fx.seller);
    let dy = despatch_by(&y, 151, &fx.seller);

    let states: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("Xa", with(vec![xa.clone()], vec![])),
        ("Xc_seller", with(vec![xc_seller.clone()], vec![])),
        ("Xc_buyer", with(vec![xc_buyer.clone()], vec![])),
        ("Xp", with(vec![xp.clone()], vec![])),
        ("Xp_D1", with(vec![xp.clone()], vec![dx1.clone()])),
        ("Xp_D2", with(vec![xp.clone()], vec![dx2.clone()])),
        ("Xa_D1", with(vec![xa.clone()], vec![dx1.clone()])),
        ("Xc_buyer_D2", with(vec![xc_buyer.clone()], vec![dx2.clone()])),
        ("Ya_Xp_D1", with(vec![ya.clone(), xp.clone()], vec![dx1.clone()])),
        ("Yp_Dy", with(vec![yp.clone()], vec![dy.clone()])),
        ("Yp_Dy_Xc_seller", with(vec![yp.clone(), xc_seller.clone()], vec![dy.clone()])),
    ];
    native_laws_total("fulfilment", p, &states);

    let pairs = [
        ("Xc_seller", "Xc_buyer"), ("Xc_buyer", "Xc_seller"),
        ("Xc_buyer", "Xp"), ("Xp", "Xc_buyer"),
        ("Xp_D1", "Xp_D2"), ("Xp_D2", "Xp_D1"),
        ("default", "Xp_D1"), ("Xa", "Xp_D1"), ("Xp_D1", "Xa"),
        ("Xa_D1", "Xc_buyer_D2"), ("Xc_buyer_D2", "Xp"),
        ("Ya_Xp_D1", "Yp_Dy"), ("Yp_Dy", "Ya_Xp_D1"),
        ("Yp_Dy_Xc_seller", "Xp_D2"), ("Xp_D2", "Yp_Dy_Xc_seller"),
    ];
    let mut c = Corpus::new(root, "store-fulfilment", &params);
    let mut all = states.clone();
    let find = |all: &Vec<(&str, StoreStateV1)>, n: &str| all.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    let mut extra = vec![];
    for (a, b) in pairs {
        let r = fx.merged(&find(&all, a), &find(&all, b));
        let name: &'static str = Box::leak(format!("m_{a}__{b}").into_boxed_str());
        extra.push((a, name, r));
    }
    for (_, n, s) in &extra { all.push((n, s.clone())); }
    let paid_over_cancels = find(&all, "m_Xc_buyer__Xp");
    println!(
        "fulfilment: a payment outranks the buyer's cancel? {}",
        paid_over_cancels.orders.orders[&x.id].status == OrderStatus::Paid
    );
    for (n, s) in &all { c.state(n, &cbor(s)); }
    for (a, n, _) in &extra { c.transition(a, n); }
    for (a, b) in pairs {
        let base = find(&all, a);
        let tgt = find(&all, b);
        let summ = base.summarize(&base, p);
        let Some(d) = tgt.delta(&tgt, p, &summ) else { continue };
        let mut r = base.clone();
        r.apply_delta(&base.clone(), p, &Some(d.clone())).expect("a fulfilment delta applies");
        fx.check(&r);
        c.delta_step(&cbor(&base), &cbor(&summ), &cbor(&d), &cbor(&r));
    }
    c.finish();

    // At the cap: an old despatched order pushed out by a full store of newer
    // ones takes its despatch with it, in either grouping.
    let old = keyed("buyer-old", 1_600_000_000);
    let old_paid = fx.authorized(&old, OrderStatus::Paid, 7);
    let d_old = despatch_by(&old, 140, &fx.seller);
    let small = with(vec![old_paid.clone()], vec![d_old.clone()]);
    let small_other = with(vec![old_paid.clone()], vec![despatch_by(&old, 141, &fx.seller)]);
    let many: Vec<AuthorizedOrder> = (0..MAX_ORDERS)
        .map(|i| {
            let o = fx.order(&format!("bulk-{i}"), 1_700_000_000 + i as i64);
            fx.authorized(&o, OrderStatus::AwaitingPayment, 0)
        })
        .collect();
    let full = with(many, vec![]);
    let mut c = Corpus::new(root, "store-fulfilment-cap", &params);
    c.state("cap_old_despatched", &cbor(&small));
    c.state("cap_old_despatched_other_anchor", &cbor(&small_other));
    c.state("cap_full_newer", &cbor(&full));
    let l = fx.merged(&fx.merged(&small, &small_other), &full);
    let r = fx.merged(&small, &fx.merged(&small_other, &full));
    println!(
        "store-fulfilment-cap native: groupings agree? {}   despatch kept: {} / {}",
        cbor(&l) == cbor(&r),
        !l.fulfilment.is_empty(),
        !r.fulfilment.is_empty()
    );
    c.finish();

    // States the contract must refuse.
    let base = with(vec![xp.clone()], vec![]);
    let raw = |d: AuthorizedDespatch| {
        let mut s = base.clone();
        s.fulfilment.records.insert(harvest_common::store::Bytes32(d.despatch.order_id.0), d);
        assert!(s.verify(&s, p).is_err(), "an invalid fixture must be one the contract refuses");
        s
    };
    let mut stranger_cancel = cancelled_by(&x, &fx.seller);
    let (sp, sig) = sign_scoped(&stranger, &(x.id.clone(), OrderStatus::Cancelled));
    stranger_cancel.status_scoped_payload = Some(sp);
    stranger_cancel.status_signature = Some(sig);
    let mut bad_cancel = StoreStateV1 {
        owner: Some(fx.seller.verifying_key()),
        ..Default::default()
    };
    bad_cancel.orders.orders.insert(x.id.clone(), stranger_cancel);
    assert!(bad_cancel.verify(&bad_cancel, p).is_err());
    let bad: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("Xp", base.clone()),
        ("Xp_D1", find(&all, "Xp_D1")),
        ("bad_despatch_orphan", raw(despatch_by(&y, 150, &fx.seller))),
        ("bad_despatch_by_stranger", raw(despatch_by(&x, 150, &stranger))),
        ("bad_despatch_by_buyer", raw(despatch_by(&x, 150, &buyer))),
        ("bad_cancel_by_stranger", bad_cancel),
    ];
    let mut c = Corpus::new(root, "store-fulfilment-bad", &params);
    for (n, s) in &bad { c.state(n, &cbor(s)); }
    c.finish();
}


// ---------------------------------------------------------------------------
// Re-review (round 2) additions: weak / non-canonical entry keys, non-minimal
// CBOR inside otherwise-valid states, the empty state vs non-minimal default,
// and a FULL store whose boundary order is Paid with differing proofs.
// ---------------------------------------------------------------------------

/// Replace the first occurrence of `key` text followed by `hdr` with `key` + `rep`.
fn nonminimal_after(bytes: &[u8], key: &str, hdr: &[u8], rep: &[u8]) -> Vec<u8> {
    let mut pat = vec![0x60 + key.len() as u8];
    pat.extend(key.as_bytes());
    pat.extend(hdr);
    let pos = bytes.windows(pat.len()).position(|w| w == pat.as_slice())
        .unwrap_or_else(|| panic!("pattern for {key} not found"));
    let mut out = bytes[..pos + 1 + key.len()].to_vec();
    out.extend(rep);
    out.extend(&bytes[pos + pat.len()..]);
    out
}

fn gen_rr(root: &Path) {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    // ---- reputation
    let mut rng = rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let der = rsa::RsaPublicKey::from(&private).to_pkcs1_der().unwrap().as_bytes().to_vec();
    let owner = SigningKey::from_bytes(&[0xC3; 32]).verifying_key();
    let params = ReputationParameters::new(der, owner);
    let pbytes = cbor(&params);
    let signer = BlindedSigningKey::<sha2::Sha256>::new(private);
    let rsa_sign = |t: &FeedbackToken| signer.sign_with_rng(&mut rand_core::OsRng, &cbor(t)).to_vec();
    let cert = "-----BEGIN THROWAWAY OWNER CERT-----";
    let honest = |entries: Vec<FeedbackEntry>| {
        let mut s = ReputationStateV1 { owner_certificate_pem: cert.into(), ..Default::default() };
        if !entries.is_empty() { s.apply_delta(&params, &Some(entries)).unwrap(); }
        s.verify(&params).unwrap();
        s
    };
    let buyer = SigningKey::from_bytes(&[0x42; 32]);
    let t1 = FeedbackToken::new([5u8; 32], buyer.verifying_key().to_bytes());
    let s1 = rsa_sign(&t1);
    let f1 = FeedbackEntry::sign(t1, s1, FeedbackCategory::NonDelivery, "never arrived".into(), ts(1_700_000_100), &buyer);
    let buyer2 = SigningKey::from_bytes(&[0x43; 32]);
    let t2 = FeedbackToken::new([5u8; 32], buyer2.verifying_key().to_bytes());
    let s2 = rsa_sign(&t2);
    let f2 = FeedbackEntry::sign(t2, s2, FeedbackCategory::Misrepresented, "not as shown".into(), ts(1_700_000_200), &buyer2);

    let mut c = Corpus::new(root, "reputation-rr", &pbytes);
    c.state("zero_bytes", &[]);
    let def = cbor(&ReputationStateV1::default());
    c.state("default", &def);
    // encoded default, map header non-minimal (0xA3 -> 0xB8 0x03)
    assert_eq!(def[0], 0xA3);
    let mut d2 = vec![0xB8, 0x03]; d2.extend(&def[1..]);
    c.state("adv_default_nonminimal_map", &d2);
    let st1 = honest(vec![f1.clone()]);
    c.state("F1", &cbor(&st1));
    c.state("F2", &cbor(&honest(vec![f2.clone()])));
    // F1 with its feedback array header non-minimal (0x81 -> 0x98 0x01)
    let nm = nonminimal_after(&cbor(&st1), "feedback", &[0x81], &[0x98, 0x01]);
    assert_eq!(harvest_common::from_cbor::<ReputationStateV1>(&nm).unwrap(), st1);
    c.state("adv_F1_nonminimal_array", &nm);
    // Weak / non-canonical entry keys with a forged (R = identity, s = 0) sig,
    // nonce correctly derived, token genuinely RSA-signed (a seller-minted slot).
    let mut ident_r = [0u8; 64]; ident_r[0] = 1; // R = identity (y = 1), s = 0
    let weak_keys: [(&str, [u8; 32]); 3] = [
        ("identity", { let mut k = [0u8; 32]; k[0] = 1; k }),
        ("identity_y_plus_p", { let mut k = [0xFFu8; 32]; k[0] = 0xEE; k[31] = 0x7F; k }),
        ("identity_signbit", { let mut k = [0u8; 32]; k[0] = 1; k[31] = 0x80; k }),
    ];
    for (name, k) in weak_keys {
        let tok = FeedbackToken::new([5u8; 32], k);
        let sig = rsa_sign(&tok);
        let e = FeedbackEntry { token: tok, signature: sig, category: FeedbackCategory::Other("forged".into()),
            comment: format!("third party via {name}"), submitted_at: ts(1_700_000_300), entry_signature: ident_r.to_vec() };
        // Also check: does NON-strict verify accept the forged signature? (would show verify_strict is load-bearing)
        let nonstrict = ed25519_dalek::VerifyingKey::from_bytes(&k).map(|vk| {
            use ed25519_dalek::Verifier;
            vk.verify(&e.signing_bytes(), &ed25519_dalek::Signature::from_bytes(&ident_r)).is_ok()
        });
        let probe = ReputationStateV1 { owner_certificate_pem: cert.into(), used_nonces: [e.token.nonce].into_iter().collect(), feedback: vec![e.clone()] };
        let r = probe.verify(&params);
        println!("reputation-rr weak key {name}: decompress={:?} nonstrict_forgery_ok={:?} contract verify={:?}",
            ed25519_dalek::VerifyingKey::from_bytes(&k).is_ok(), nonstrict.ok(), r);
        let raw = ReputationStateV1 { owner_certificate_pem: cert.into(), used_nonces: [e.token.nonce].into_iter().collect(), feedback: vec![e] };
        c.state(&format!("adv_weak_{name}"), &cbor(&raw));
    }
    // Delta steps: default <- F1, F1 <- F2
    for (b, t) in [(ReputationStateV1::default(), st1.clone()), (st1.clone(), honest(vec![f2.clone()]))] {
        let summ = b.summarize();
        let d = t.delta(&summ).unwrap();
        let mut r = b.clone();
        r.apply_delta(&params, &Some(d.clone())).unwrap();
        c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
    }
    c.finish();

    // ---- store: FULL cap, boundary (lowest-ranked) order Paid with differing proofs
    let fx = StoreFx::new();
    let sp = cbor(&fx.params);
    let orders: Vec<Order> = (0..MAX_ORDERS).map(|i| fx.order(&format!("rr-{i}"), 1_700_000_000 + i as i64)).collect();
    let boundary = orders[0].clone(); // oldest: cut first
    let rest: Vec<AuthorizedOrder> = orders[1..].iter().map(|o| fx.authorized(o, OrderStatus::AwaitingPayment, 0)).collect();
    let mk_full = |seed: u8| {
        let mut v = rest.clone();
        v.push(fx.authorized(&boundary, OrderStatus::Paid, seed));
        fx.build(None, vec![], v)
    };
    let full_a = mk_full(1);
    let full_b = mk_full(2);
    assert_eq!(full_a.orders.orders.len(), MAX_ORDERS);
    let y = fx.order("rr-newest", 1_900_000_000);
    let p_y = fx.build(None, vec![], vec![fx.authorized(&y, OrderStatus::AwaitingPayment, 0)]);
    let q_bnd_b = fx.build(None, vec![], vec![fx.authorized(&boundary, OrderStatus::Paid, 2)]);
    let q_bnd_rev = fx.build(None, vec![], vec![fx.authorized(&boundary, OrderStatus::PaymentReversed, 0)]);
    // second-oldest Paid variant + y Cancelled
    let q2 = fx.build(None, vec![], vec![fx.authorized(&orders[1], OrderStatus::Paid, 3), fx.authorized(&y, OrderStatus::Cancelled, 0)]);
    let mut c = Corpus::new(root, "store-rr", &sp);
    c.state("zero_bytes", &[]);
    let sdef = cbor(&StoreStateV1::default());
    c.state("default", &sdef);
    c.state("full_bnd_paidA", &cbor(&full_a));
    c.state("full_bnd_paidB", &cbor(&full_b));
    c.state("P_y_newest", &cbor(&p_y));
    c.state("Q_bnd_paidB", &cbor(&q_bnd_b));
    c.state("Q_bnd_reversed", &cbor(&q_bnd_rev));
    c.state("Q2_second_paid_y_cx", &cbor(&q2));
    // native reference
    let groupings = [
        ("full_a,full_b,p_y", &full_a, &full_b, &p_y),
        ("full_a,q_bnd_b,p_y", &full_a, &q_bnd_b, &p_y),
        ("p_y,full_b,q_bnd_rev", &p_y, &full_b, &q_bnd_rev),
        ("q2,full_a,p_y", &q2, &full_a, &p_y),
    ];
    for (n, a, b, cc) in groupings {
        let l = fx.merged(&fx.merged(a, b), cc);
        let r = fx.merged(a, &fx.merged(b, cc));
        let ba = fx.merged(b, a); let ab = fx.merged(a, b);
        println!("store-rr native {n}: assoc {} comm {}", cbor(&l) == cbor(&r), cbor(&ab) == cbor(&ba));
    }
    for (b, t) in [(&full_a, &full_b), (&full_a, &p_y), (&full_a, &q_bnd_rev), (&full_b, &q2), (&p_y, &full_a)] {
        let summ = b.summarize(b, &fx.params);
        let d = t.delta(t, &fx.params, &summ).expect("non-empty delta");
        let mut r = b.clone();
        r.apply_delta(&b.clone(), &fx.params, &Some(d.clone())).unwrap();
        fx.check(&r);
        c.delta_step(&cbor(b), &cbor(&summ), &cbor(&d), &cbor(&r));
    }
    c.finish();

    // ---- store: unsigned version-0 info (verify skips version 0 entirely)
    let v0 = |name: &str, key: u8| {
        let mut st = fx.build(None, vec![fx.listing(1)], vec![]);
        st.info.info.store_name = name.into();
        st.info.info.description = format!("injected by a third party ({name})");
        st.info.info.encryption_public_key = Some([key; 32]);
        // r3: the v0 rule now REFUSES this natively.
        let r = st.verify(&st, &fx.params);
        println!("store-v0 native verify of v0 junk ({name}): {:?}", r);
        assert!(r.is_err(), "v0 junk must not verify at this head");
        st
    };
    let l1 = fx.build(None, vec![fx.listing(1)], vec![]);
    let i1 = fx.build(Some(fx.info(1, "Throwaway Farm")), vec![], vec![]);
    let i2 = fx.build(Some(fx.info(2, "Throwaway Farm v2")), vec![fx.listing(2)], vec![]);
    let junk_a = v0("Totally Legit Farm", 0xAA);
    let mut c = Corpus::new(root, "store-v0", &sp);
    c.state("L1_default_info", &cbor(&l1));
    c.state("adv_v0_info_A", &cbor(&junk_a));
    c.state("adv_v0_info_B", &cbor(&v0("Other Farm", 0xBB)));
    c.state("info1_signed", &cbor(&i1));
    c.state("info2_signed_L2", &cbor(&i2));
    c.state("default", &cbor(&StoreStateV1::default()));
    // Q2: merge default-v0 with signed v1/v2 and back, natively.
    for (n, a, b) in [("l1,i1", &l1, &i1), ("i1,l1", &i1, &l1), ("i1,i2", &i1, &i2), ("i2,i1", &i2, &i1), ("l1,i2", &l1, &i2)] {
        let m = fx.merged(a, b);
        println!("store-v0 native merge {n}: info v{} verify {:?} comm {}", m.info.info.version, m.verify(&m, &fx.params).is_ok(), cbor(&m) == cbor(&fx.merged(b, a)));
    }
    let l1i1 = fx.merged(&l1, &i1);
    c.state("L1_merged_info1", &cbor(&l1i1));
    c.transition("L1_default_info", "L1_merged_info1");
    // Delta steps across the v0/v1 boundary, both directions, and v1 -> v2.
    for (b, t) in [(&l1, &i1), (&i1, &l1), (&i1, &i2), (&StoreStateV1::default(), &i1), (&l1, &i2)] {
        let summ = b.summarize(b, &fx.params);
        let Some(d) = t.delta(t, &fx.params, &summ) else { println!("store-v0 delta step: empty delta"); continue };
        let mut r = b.clone();
        r.apply_delta(&b.clone(), &fx.params, &Some(d.clone())).unwrap();
        fx.check(&r);
        c.delta_step(&cbor(b), &cbor(&summ), &cbor(&d), &cbor(&r));
    }
    c.finish();

    // Q3: migration fold, modelled exactly as freenet-migrate 0.6 FoldAll +
    // harvest StoreOps: acc = newest real predecessor, merge_generations(acc,
    // older) = acc.merge(acc, older) + normalize, then merge_with_local(folded,
    // Default) and PUT under the current contract.
    let fold = |mut base: StoreStateV1, other: &StoreStateV1| {
        let snap = base.clone();
        match base.merge(&snap, &fx.params, other) { Ok(()) => { base.listings.normalize(); base }, Err(e) => { println!("  fold refused: {e}"); snap } }
    };
    let pred_junk_listing = { let mut s = l1.clone(); s.info = junk_a.info.clone(); s };
    let cases: [(&str, Vec<&StoreStateV1>); 4] = [
        ("newest=junk+L1 only", vec![&pred_junk_listing]),
        ("newest=junk+L1, older=i1", vec![&pred_junk_listing, &i1]),
        ("newest=i1, older=junk+L1", vec![&i1, &pred_junk_listing]),
        ("newest=L1(default info), older=junk+L1", vec![&l1, &pred_junk_listing]),
    ];
    for (n, gens) in cases {
        let mut acc = gens[0].clone();
        for g in &gens[1..] { acc = fold(acc, g); }
        let fwd = fold(acc, &StoreStateV1::default());
        let v = fwd.verify(&fwd, &fx.params);
        println!("store-v0 migration {n}: forward info v{} name {:?} listings {} -> current verify {:?}", fwd.info.info.version, fwd.info.info.store_name, fwd.listings.listings.len(), v);
        fs::write(root.join(format!("fwd-{}.cbor", n.replace([' ', ',', '=', '+', '(', ')'], "_"))), cbor(&fwd)).unwrap();
    }

    // ---- mailbox: zero vs default vs non-minimal default
    let mo = SigningKey::from_bytes(&[0xD4; 32]).verifying_key();
    let mp = cbor(&MailboxParameters::new(mo));
    let mut c = Corpus::new(root, "mailbox-rr", &mp);
    let mdef = cbor(&MailboxStateV1::default());
    c.state("zero_bytes", &[]);
    c.state("default", &mdef);
    let mut m2 = mdef.clone();
    let h = m2[0]; assert!((0xA0..0xB8).contains(&h));
    m2[0] = 0xB8; m2.insert(1, h - 0xA0);
    c.state("adv_default_nonminimal_map", &m2);
    let mut s = MailboxStateV1::default();
    s.apply_delta(&Some(vec![msg(1, 1, 1040, 1, 1_700_000_000)])).unwrap();
    c.state("M1", &cbor(&s));
    c.finish();
}


// ---------------------------------------------------------------------------
// harvest#52: two owners that share a store code
// ---------------------------------------------------------------------------

/// Two signing keys whose verifying keys share their first two base58
/// characters, the one with the smaller key bytes first, and that code.
/// Twelve characters cannot be ground; the contract accepts a code of any
/// length, so two characters exercise the same merge on the production WASM.
fn two_keys_sharing_a_code() -> (SigningKey, SigningKey, String) {
    let mut seen: std::collections::HashMap<String, SigningKey> = Default::default();
    for i in 0u32..200_000 {
        let mut seed = [0xC7u8; 32];
        seed[..4].copy_from_slice(&i.to_le_bytes());
        let key = SigningKey::from_bytes(&seed);
        let code = bs58::encode(key.verifying_key().as_bytes()).into_string()[..2].to_string();
        if let Some(other) = seen.remove(&code) {
            return if other.verifying_key().as_bytes() < key.verifying_key().as_bytes() {
                (other, key, code)
            } else {
                (key, other, code)
            };
        }
        seen.insert(code, key);
    }
    panic!("no pair found");
}

fn gen_claim(root: &Path) {
    let (low, high, code) = two_keys_sharing_a_code();
    #[derive(Serialize)]
    struct CodeParams<'a> {
        store_code: &'a str,
    }
    let params_bytes = cbor(&CodeParams { store_code: &code });
    let params: StoreParameters = harvest_common::from_cbor(&params_bytes).unwrap();
    println!(
        "claim: code {code:?}, low {} high {}",
        bs58::encode(low.verifying_key().as_bytes()).into_string(),
        bs58::encode(high.verifying_key().as_bytes()).into_string()
    );
    let lo = StoreFx::with(low, params.clone());
    let hi = StoreFx::with(high, params.clone());

    // Same listing and order TERMS from both owners: their ids coincide
    // (ids are content-derived), so a delta across owners that were measured
    // against the other owner's summary would silently skip them.
    let ll: Vec<AuthorizedListing> = (1..=3).map(|i| lo.listing(i)).collect();
    let hl: Vec<AuthorizedListing> = (1..=3).map(|i| hi.listing(i)).collect();
    let lo_order = lo.order("buyer-1", 1_700_003_600);
    let hi_order = hi.order("buyer-1", 1_700_003_600);

    let mut c = Corpus::new(root, "store-claim", &params_bytes);
    let states: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("lo_info1", lo.build(Some(lo.info(1, "Low")), vec![], vec![])),
        ("lo_L1", lo.build(None, vec![ll[0].clone()], vec![])),
        ("lo_info2_L12", lo.build(Some(lo.info(2, "Low 2")), vec![ll[0].clone(), ll[1].clone()], vec![])),
        ("lo_O1aw", lo.build(None, vec![], vec![lo.authorized(&lo_order, OrderStatus::AwaitingPayment, 0)])),
        ("lo_O1paid_L3", lo.build(None, vec![ll[2].clone()], vec![lo.authorized(&lo_order, OrderStatus::Paid, 1)])),
        ("hi_info1", hi.build(Some(hi.info(1, "High")), vec![], vec![])),
        ("hi_L1", hi.build(None, vec![hl[0].clone()], vec![])),
        ("hi_info3_L123", hi.build(Some(hi.info(3, "High 3")), hl.clone(), vec![])),
        ("hi_O1aw_L2", hi.build(None, vec![hl[1].clone()], vec![hi.authorized(&hi_order, OrderStatus::AwaitingPayment, 0)])),
    ];
    let merged = |a: &StoreStateV1, b: &StoreStateV1| {
        let mut out = a.clone();
        out.merge(&a.clone(), &params, b).unwrap();
        out.verify(&out, &params).unwrap();
        out
    };
    for (n, s) in &states {
        c.state(n, &cbor(s));
    }
    // Transitions: a held store and what a real merge of another state makes
    // of it, across owners in both directions and within one owner.
    let find = |n: &str| states.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    for (base, other, name) in [
        ("hi_info3_L123", "lo_L1", "t_hi_taken_by_lo"),
        ("lo_info1", "hi_info3_L123", "t_lo_keeps_against_hi"),
        ("default", "hi_L1", "t_default_claimed_by_hi"),
        ("lo_L1", "lo_O1paid_L3", "t_lo_grows"),
        ("hi_L1", "hi_O1aw_L2", "t_hi_grows"),
    ] {
        let r = merged(&find(base), &find(other));
        c.state(name, &cbor(&r));
        c.transition(base, name);
    }
    // Delta steps: what get_state_delta sends a holder of `base`, and what
    // update_state(Delta) makes of it. Across owners the loser sends nothing,
    // so only the winning direction produces a step.
    for (base, targets) in [
        ("hi_info3_L123", vec!["lo_L1", "lo_info2_L12", "lo_O1paid_L3"]),
        ("hi_O1aw_L2", vec!["lo_O1aw", "lo_info1"]),
        ("default", vec!["hi_L1", "lo_L1", "hi_info3_L123"]),
        ("lo_L1", vec!["lo_info2_L12", "lo_O1paid_L3"]),
    ] {
        let b = find(base);
        let summ = b.summarize(&b, &params);
        for t in targets {
            let tgt = find(t);
            let d = tgt.delta(&tgt, &params, &summ).expect("non-empty delta");
            let mut r = b.clone();
            r.apply_delta(&b.clone(), &params, &Some(d.clone())).unwrap();
            r.verify(&r, &params).unwrap();
            c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
        }
    }
    // Native laws over every pair and triple, before the contract sees them.
    let all: Vec<StoreStateV1> = states.iter().map(|(_, s)| s.clone()).collect();
    let mut bad = 0;
    for a in &all {
        for b in &all {
            if cbor(&merged(a, b)) != cbor(&merged(b, a)) {
                bad += 1;
            }
            for c3 in &all {
                if cbor(&merged(&merged(a, b), c3)) != cbor(&merged(a, &merged(b, c3))) {
                    bad += 1;
                }
            }
        }
        if cbor(&merged(a, a)) != cbor(a) {
            bad += 1;
        }
    }
    println!("claim native: {} law violations over {} states", bad, all.len());
    c.finish();
}

// ---------------------------------------------------------------------------
// PR #91 review (independent lens): THREE owners sharing a code, losing-owner
// deltas, owner-less deltas, the default state, and the order cap under two
// owners.
// ---------------------------------------------------------------------------

fn three_keys_sharing_a_code() -> ([SigningKey; 3], String) {
    let mut seen: std::collections::HashMap<String, Vec<SigningKey>> = Default::default();
    for i in 0u32..2_000_000 {
        let mut seed = [0x3Du8; 32];
        seed[..4].copy_from_slice(&i.to_le_bytes());
        let key = SigningKey::from_bytes(&seed);
        let code = bs58::encode(key.verifying_key().as_bytes()).into_string()[..2].to_string();
        let v = seen.entry(code.clone()).or_default();
        v.push(key);
        if v.len() == 3 {
            let mut v = std::mem::take(v);
            v.sort_by(|a, b| a.verifying_key().as_bytes().cmp(b.verifying_key().as_bytes()));
            let [a, b, c]: [SigningKey; 3] = v.try_into().ok().unwrap();
            return ([a, b, c], code);
        }
    }
    panic!("no triple found");
}

fn code_params(code: &str) -> (Vec<u8>, StoreParameters) {
    #[derive(Serialize)]
    struct CodeParams<'a> {
        store_code: &'a str,
    }
    let bytes = cbor(&CodeParams { store_code: code });
    let p: StoreParameters = harvest_common::from_cbor(&bytes).unwrap();
    (bytes, p)
}

fn native_laws(name: &str, params: &StoreParameters, all: &[StoreStateV1]) {
    let merged = |a: &StoreStateV1, b: &StoreStateV1| {
        let mut out = a.clone();
        out.merge(&a.clone(), params, b).unwrap();
        out.listings.normalize();
        out.verify(&out, params).unwrap();
        out
    };
    let (mut comm, mut assoc, mut idem, mut n) = (0, 0, 0, 0);
    for a in all {
        if cbor(&merged(a, a)) != cbor(a) {
            idem += 1;
        }
        for b in all {
            if cbor(&merged(a, b)) != cbor(&merged(b, a)) {
                comm += 1;
            }
            for c3 in all {
                n += 1;
                if cbor(&merged(&merged(a, b), c3)) != cbor(&merged(a, &merged(b, c3))) {
                    assoc += 1;
                }
            }
        }
    }
    println!("{name} native: {} states, {n} triples; comm {comm} assoc {assoc} idem {idem}", all.len());
}

fn gen_triad(root: &Path) {
    let ([k1, k2, k3], code) = three_keys_sharing_a_code();
    let (params_bytes, params) = code_params(&code);
    for k in [&k1, &k2, &k3] {
        println!("triad: code {code:?} key {}", bs58::encode(k.verifying_key().as_bytes()).into_string());
    }
    let fx: Vec<StoreFx> = [k1, k2, k3].into_iter().map(|k| StoreFx::with(k, params.clone())).collect();
    let tag = ["a", "b", "c"]; // a < b < c by key bytes
    let mut states: Vec<(String, StoreStateV1)> = vec![("default".into(), StoreStateV1::default())];
    for (i, f) in fx.iter().enumerate() {
        let l: Vec<AuthorizedListing> = (1..=3).map(|n| f.listing(n)).collect();
        let o = f.order("buyer-1", 1_700_003_600);
        let o2 = f.order("buyer-2", 1_700_007_200);
        let t = tag[i];
        states.push((format!("{t}_info1"), f.build(Some(f.info(1, "One")), vec![], vec![])));
        states.push((format!("{t}_L1"), f.build(None, vec![l[0].clone()], vec![])));
        states.push((format!("{t}_info2_L12"), f.build(Some(f.info(2, "Two")), vec![l[0].clone(), l[1].clone()], vec![])));
        states.push((format!("{t}_O1aw_L3"), f.build(None, vec![l[2].clone()], vec![f.authorized(&o, OrderStatus::AwaitingPayment, 0)])));
        states.push((format!("{t}_O1paid_O2cx"), f.build(None, vec![], vec![f.authorized(&o, OrderStatus::Paid, 1), f.authorized(&o2, OrderStatus::Cancelled, 0)])));
    }
    let mut c = Corpus::new(root, "store-triad", &params_bytes);
    for (n, s) in &states {
        c.state(n, &cbor(s));
    }
    let find = |n: &str| states.iter().find(|(m, _)| m == n).unwrap().1.clone();
    let merged = |a: &StoreStateV1, b: &StoreStateV1| {
        let mut out = a.clone();
        out.merge(&a.clone(), &params, b).unwrap();
        out.listings.normalize();
        out.verify(&out, &params).unwrap();
        out
    };
    // Transitions: across all three owners and within one.
    let mut tn = 0;
    for (base, other) in [
        ("c_info2_L12", "b_L1"), ("b_info2_L12", "a_O1aw_L3"), ("c_O1paid_O2cx", "a_info1"),
        ("a_L1", "c_info2_L12"), ("b_L1", "c_O1paid_O2cx"), ("default", "c_O1aw_L3"),
        ("a_L1", "a_O1paid_O2cx"), ("b_O1aw_L3", "b_O1paid_O2cx"), ("c_L1", "default"),
    ] {
        let r = merged(&find(base), &find(other));
        let name = format!("t{tn}_{base}_with_{other}");
        tn += 1;
        c.state(&name, &cbor(&r));
        c.transition(base, &name);
    }
    // Chained: ((c + b) + a) as a single held state.
    let chain = merged(&merged(&find("c_info2_L12"), &find("b_O1paid_O2cx")), &find("a_L1"));
    c.state("chain_cba", &cbor(&chain));

    // Delta steps.
    let names: Vec<String> = states.iter().map(|(n, _)| n.clone()).collect();
    let mut steps = 0;
    for bn in &names {
        let b = find(bn);
        let summ = b.summarize(&b, &params);
        for tnm in &names {
            let t = find(tnm);
            // (1) what get_state_delta produces
            if let Some(d) = t.delta(&t, &params, &summ) {
                let mut r = b.clone();
                r.apply_delta(&b.clone(), &params, &Some(d.clone())).unwrap();
                r.verify(&r, &params).unwrap();
                c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
                steps += 1;
            }
            // (2) a LOSING owner's delta, forced: its full content measured
            // against the empty store, sent to a holder that outranks it.
            if let (Some(ho), Some(to)) = (b.owner, t.owner) {
                if ho.as_bytes() < to.as_bytes() {
                    let empty = StoreStateV1::default().summarize(&StoreStateV1::default(), &params);
                    let d = t.delta(&t, &params, &empty).unwrap();
                    let mut r = b.clone();
                    r.apply_delta(&b.clone(), &params, &Some(d.clone())).unwrap();
                    assert_eq!(cbor(&r), cbor(&b), "a losing delta must change nothing");
                    c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
                    steps += 1;
                }
                // (3) an owner-less delta with the same owner's records
                if ho == to {
                    if let Some(mut d) = t.delta(&t, &params, &summ) {
                        d.owner = None;
                        let mut r = b.clone();
                        r.apply_delta(&b.clone(), &params, &Some(d.clone())).unwrap();
                        r.verify(&r, &params).unwrap();
                        c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
                        steps += 1;
                    }
                }
            }
        }
    }
    println!("triad: {steps} delta steps");
    let mut all: Vec<StoreStateV1> = states.iter().map(|(_, s)| s.clone()).collect();
    all.push(chain);
    native_laws("triad", &params, &all);
    c.finish();
}

fn gen_triadcap(root: &Path) {
    let ([k1, k2, _k3], code) = three_keys_sharing_a_code();
    let (params_bytes, params) = code_params(&code);
    let lo = StoreFx::with(k1, params.clone());
    let hi = StoreFx::with(k2, params.clone());
    let full = |f: &StoreFx, base: i64| -> Vec<AuthorizedOrder> {
        (0..MAX_ORDERS as i64)
            .map(|i| f.authorized(&f.order(&format!("b{i}"), base + i), OrderStatus::AwaitingPayment, 0))
            .collect()
    };
    let newest = 1_800_000_000;
    let states: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("lo_full", lo.build(None, vec![], full(&lo, 1_700_000_000))),
        ("hi_full", hi.build(None, vec![], full(&hi, 1_700_000_000))),
        ("lo_P_x_aw", lo.build(None, vec![], vec![lo.authorized(&lo.order("x", newest), OrderStatus::AwaitingPayment, 0)])),
        ("lo_Q_x_cx", lo.build(None, vec![], vec![lo.authorized(&lo.order("x", newest), OrderStatus::Cancelled, 0)])),
        ("hi_P_x_aw", hi.build(None, vec![], vec![hi.authorized(&hi.order("x", newest), OrderStatus::AwaitingPayment, 0)])),
    ];
    let mut c = Corpus::new(root, "store-triadcap", &params_bytes);
    for (n, s) in &states {
        c.state(n, &cbor(s));
    }
    let find = |n: &str| states.iter().find(|(m, _)| *m == n).unwrap().1.clone();
    let names: Vec<&str> = states.iter().map(|(n, _)| *n).collect();
    let mut steps = 0;
    for bn in &names {
        let b = find(bn);
        let summ = b.summarize(&b, &params);
        for tnm in &names {
            let t = find(tnm);
            if let Some(d) = t.delta(&t, &params, &summ) {
                let mut r = b.clone();
                r.apply_delta(&b.clone(), &params, &Some(d.clone())).unwrap();
                r.verify(&r, &params).unwrap();
                c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
                steps += 1;
            }
        }
    }
    println!("triadcap: {steps} delta steps");
    let all: Vec<StoreStateV1> = states.iter().map(|(_, s)| s.clone()).collect();
    native_laws("triadcap", &params, &all);
    c.finish();
}


// ---------------------------------------------------------------------------
// harvest#93 phase 1a: a store key owns the store; backings, retirements and
// the closed flag. Three corpora:
//   store-backing      HONEST: built from empty through apply_delta, owner is a
//                      store key, with backings, retirements and closures in
//                      combination with details and listings
//   store-backing-adv  ADVERSARIAL-VALID: two differently-signed backings for
//                      one Ghost Key (a slot clash the per-slot minimum must
//                      settle), a retirement of a key that never backed
//   store-backing-bad  INVALID: a backing attached by the wrong Ghost Key, one
//                      without the store key's countersignature, a retirement
//                      and a closure signed by a key that is not the store's
// ---------------------------------------------------------------------------

use harvest_common::backing::{
    AuthorizedBacking, AuthorizedClosure, AuthorizedRetirement, BackingAcceptance,
    BackingStatement, Retirement, StoreClosure,
};

struct BackingFx {
    store: SigningKey,
    fx: StoreFx,
}

impl BackingFx {
    fn new() -> Self {
        let store = SigningKey::from_bytes(&[0xC3; 32]);
        let params = StoreParameters::new(store.verifying_key());
        Self {
            fx: StoreFx::with(store.clone(), params),
            store,
        }
    }

    fn statement(&self, backer: &SigningKey, height: u32) -> BackingStatement {
        BackingStatement {
            store: self.store.verifying_key(),
            backer: backer.verifying_key(),
            certificate_pem: format!("-----BEGIN THROWAWAY CERT {height}-----"),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height,
                hash: BlockHash([height as u8; 32]),
            },
        }
    }

    fn backing_signed(
        &self,
        statement: BackingStatement,
        backer_signer: &SigningKey,
        acceptor: &SigningKey,
    ) -> AuthorizedBacking {
        let (backer_scoped_payload, backer_signature) = sign_scoped(backer_signer, &statement);
        let (acceptance_scoped_payload, acceptance_signature) = sign_scoped(
            acceptor,
            &BackingAcceptance {
                backing: statement.clone(),
            },
        );
        AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        }
    }

    fn backing(&self, backer: &SigningKey, height: u32) -> AuthorizedBacking {
        self.backing_signed(self.statement(backer, height), backer, &self.store)
    }

    fn retirement_by(&self, signer: &SigningKey, backer: &SigningKey) -> AuthorizedRetirement {
        let retirement = Retirement {
            backer: backer.verifying_key(),
        };
        let (scoped_payload, signature) = sign_scoped(signer, &retirement);
        AuthorizedRetirement {
            retirement,
            scoped_payload,
            signature,
        }
    }

    fn closure_by(&self, signer: &SigningKey) -> AuthorizedClosure {
        let closure = StoreClosure {
            store: self.store.verifying_key(),
        };
        let (scoped_payload, signature) = sign_scoped(signer, &closure);
        AuthorizedClosure {
            closure,
            scoped_payload,
            signature,
        }
    }

    fn build(
        &self,
        info: Option<AuthorizedStoreInfoV1>,
        listings: Vec<AuthorizedListing>,
        backings: Vec<AuthorizedBacking>,
        retirements: Vec<AuthorizedRetirement>,
        closed: Vec<AuthorizedClosure>,
    ) -> StoreStateV1 {
        self.build_c(info, listings, backings, retirements, closed, vec![])
    }

    fn copy_by(&self, signer: &SigningKey, backer: &SigningKey, scope: u8, fill: u8) -> AuthorizedCopy {
        let copy = StoreKeyCopy {
            store: self.store.verifying_key(),
            backer: backer.verifying_key(),
            scope: WrapScope([scope; 32]),
            wrapped: WrappedStoreKey { scheme: 1, ciphertext: vec![fill; 48] },
        };
        let (scoped_payload, signature) = sign_scoped(signer, &copy);
        AuthorizedCopy { copy, scoped_payload, signature }
    }

    fn copy(&self, backer: &SigningKey, scope: u8, fill: u8) -> AuthorizedCopy {
        self.copy_by(&self.store, backer, scope, fill)
    }

    fn build_c(
        &self,
        info: Option<AuthorizedStoreInfoV1>,
        listings: Vec<AuthorizedListing>,
        backings: Vec<AuthorizedBacking>,
        retirements: Vec<AuthorizedRetirement>,
        closed: Vec<AuthorizedClosure>,
        copies: Vec<AuthorizedCopy>,
    ) -> StoreStateV1 {
        let mut s = StoreStateV1::default();
        let delta = StoreStateV1Delta {
            owner: Some(self.store.verifying_key()),
            info,
            listings: (!listings.is_empty()).then_some(listings),
            orders: None,
            backings: (!backings.is_empty()).then_some(backings),
            retirements: (!retirements.is_empty()).then_some(retirements),
            closed: (!closed.is_empty()).then_some(closed),
            copies: (!copies.is_empty()).then_some(copies),
            fulfilment: None,
        };
        s.apply_delta(&StoreStateV1::default(), &self.fx.params, &Some(delta))
            .unwrap();
        self.fx.check(&s);
        s
    }

    /// A state whose record at `slot` is replaced by `record`, bypassing
    /// `apply_delta`'s verification: for states the contract must refuse.
    fn with_raw_backing(&self, base: &StoreStateV1, record: AuthorizedBacking) -> StoreStateV1 {
        let mut s = base.clone();
        s.backings.records.insert(
            harvest_common::store::Bytes32(record.statement.backer.to_bytes()),
            record,
        );
        assert!(
            s.verify(&s, &self.fx.params).is_err(),
            "an invalid fixture must be one the contract refuses"
        );
        s
    }
}

fn gen_backing(root: &Path) {
    let bx = BackingFx::new();
    let params = cbor(&bx.fx.params);
    let g1 = SigningKey::from_bytes(&[0xD1; 32]);
    let g2 = SigningKey::from_bytes(&[0xD2; 32]);
    let g3 = SigningKey::from_bytes(&[0xD3; 32]);
    let g9 = SigningKey::from_bytes(&[0xD9; 32]);
    let b1 = bx.backing(&g1, 100);
    let b1_later = bx.backing(&g1, 150);
    let b2 = bx.backing(&g2, 200);
    let b3 = bx.backing(&g3, 300);
    let r1 = bx.retirement_by(&bx.store, &g1);
    let r2 = bx.retirement_by(&bx.store, &g2);
    let r9 = bx.retirement_by(&bx.store, &g9);
    let closed = bx.closure_by(&bx.store);
    let i1 = bx.fx.info(1, "Store Key Farm");
    let i2 = bx.fx.info(2, "Store Key Farm (renamed)");
    let l1 = bx.fx.listing(1);
    let l2 = bx.fx.listing(2);

    let honest: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("B1", bx.build(None, vec![], vec![b1.clone()], vec![], vec![])),
        ("B1_info1", bx.build(Some(i1.clone()), vec![], vec![b1.clone()], vec![], vec![])),
        ("B1_info1_L1", bx.build(Some(i1.clone()), vec![l1.clone()], vec![b1.clone()], vec![], vec![])),
        ("B2", bx.build(None, vec![], vec![b2.clone()], vec![], vec![])),
        ("B12", bx.build(None, vec![], vec![b1.clone(), b2.clone()], vec![], vec![])),
        ("B12_R1", bx.build(None, vec![], vec![b1.clone(), b2.clone()], vec![r1.clone()], vec![])),
        ("B123_R12", bx.build(Some(i2.clone()), vec![], vec![b1.clone(), b2.clone(), b3.clone()], vec![r1.clone(), r2.clone()], vec![])),
        ("closed", bx.build(None, vec![], vec![], vec![], vec![closed.clone()])),
        ("B1_closed_L2", bx.build(None, vec![l2.clone()], vec![b1.clone()], vec![], vec![closed.clone()])),
        ("B12_R1_info2", bx.build(Some(i2.clone()), vec![], vec![b1.clone(), b2.clone()], vec![r1.clone()], vec![])),
    ];
    let trans: Vec<(&str, &str, StoreStateV1)> = vec![
        ("B1", "t_B1_plus_B2", bx.build(None, vec![], vec![b2.clone()], vec![], vec![])),
        ("B12", "t_B12_retire1", bx.build(None, vec![], vec![b1.clone()], vec![r1.clone()], vec![])),
        ("B1_info1", "t_B1_info1_close", bx.build(None, vec![], vec![], vec![], vec![closed.clone()])),
        ("B12_R1", "t_B12_R1_plus_B3", bx.build(None, vec![], vec![b3.clone()], vec![], vec![])),
    ];

    let write = |name: &str, extra: &[(&str, StoreStateV1)], with_honest_transitions: bool| {
        let mut c = Corpus::new(root, name, &params);
        let mut all = honest.clone();
        let mut t_states = vec![];
        if with_honest_transitions {
            for (base, tname, upd) in &trans {
                let b = &all.iter().find(|(n, _)| n == base).unwrap().1;
                let r = bx.fx.merged(b, upd);
                t_states.push((*tname, r));
                c.transition(base, tname);
            }
        }
        all.extend(t_states);
        all.extend(extra.iter().cloned());
        for (n, s) in &all {
            c.state(n, &cbor(s));
        }
        if with_honest_transitions {
            let find = |n: &str| all.iter().find(|(m, _)| *m == n).unwrap().1.clone();
            for (base, targets) in [
                ("B1", vec!["B12", "B12_R1", "closed", "B1_info1_L1"]),
                ("B12_R1", vec!["B123_R12", "B1_closed_L2", "B12_R1_info2"]),
            ] {
                let b = find(base);
                let summ = b.summarize(&b, &bx.fx.params);
                for t in targets {
                    let tgt = find(t);
                    let Some(d) = tgt.delta(&tgt, &bx.fx.params, &summ) else {
                        continue;
                    };
                    let mut r = b.clone();
                    r.apply_delta(&b.clone(), &bx.fx.params, &Some(d.clone())).unwrap();
                    bx.fx.check(&r);
                    c.delta_step(&cbor(&b), &cbor(&summ), &cbor(&d), &cbor(&r));
                }
            }
        }
        c.finish();
    };

    write("store-backing", &[], true);

    let adv: Vec<(&str, StoreStateV1)> = vec![
        // Two genuinely signed backings by one Ghost Key: the slot clash.
        ("adv_B1later", bx.build(None, vec![], vec![b1_later.clone()], vec![], vec![])),
        ("adv_B1later_B2", bx.build(None, vec![], vec![b1_later.clone(), b2.clone()], vec![], vec![])),
        // A retirement of a key that never backed the store.
        ("adv_B1_R9_closed", bx.build(None, vec![], vec![b1.clone()], vec![r9.clone()], vec![closed.clone()])),
    ];
    write("store-backing-adv", &adv, false);

    let base = bx.build(None, vec![], vec![b2.clone()], vec![], vec![]);
    let wrong_ghost = bx.backing_signed(bx.statement(&g1, 110), &g9, &bx.store);
    let uncountersigned = bx.backing_signed(bx.statement(&g1, 120), &g1, &g9);
    let mut no_acceptance = bx.backing(&g3, 130);
    no_acceptance.acceptance_scoped_payload.clear();
    no_acceptance.acceptance_signature.clear();
    let mut bad_retired = base.clone();
    let wr = bx.retirement_by(&g9, &g1);
    bad_retired.retirements.records.insert(
        harvest_common::store::Bytes32(g1.verifying_key().to_bytes()),
        wr,
    );
    assert!(bad_retired.verify(&bad_retired, &bx.fx.params).is_err());
    let mut bad_closed = base.clone();
    let wc = bx.closure_by(&g9);
    bad_closed.closed.records.insert(
        harvest_common::store::Bytes32(bx.store.verifying_key().to_bytes()),
        wc,
    );
    assert!(bad_closed.verify(&bad_closed, &bx.fx.params).is_err());
    let bad: Vec<(&str, StoreStateV1)> = vec![
        ("bad_wrong_ghost_key", bx.with_raw_backing(&base, wrong_ghost)),
        ("bad_countersigned_by_stranger", bx.with_raw_backing(&base, uncountersigned)),
        ("bad_no_countersignature", bx.with_raw_backing(&base, no_acceptance)),
        ("bad_retired_by_stranger", bad_retired),
        ("bad_closed_by_stranger", bad_closed),
        ("bad_orphan_R1", raw_with_retirement(&bx, &base, r1.clone())),
        ("bad_orphan_R9_closed", raw_with_retirement(&bx, &bx.build(None, vec![], vec![b1.clone()], vec![], vec![closed.clone()]), r9.clone())),
    ];
    write("store-backing-bad", &bad, false);
}


// ---------------------------------------------------------------------------
// PR #98 review lens: CRDT laws on backings / retirements / closed
// ---------------------------------------------------------------------------

fn try_merge(params: &StoreParameters, a: &StoreStateV1, b: &StoreStateV1) -> Result<StoreStateV1, String> {
    let mut out = a.clone();
    out.merge(&a.clone(), params, b)?;
    out.listings.normalize();
    out.verify(&out, params)?;
    Ok(out)
}

fn native_laws_total(name: &str, params: &StoreParameters, all: &[(&str, StoreStateV1)]) {
    let (mut comm, mut assoc, mut idem, mut errs, mut n) = (0, 0, 0, 0, 0);
    for (an, a) in all {
        match try_merge(params, a, a) {
            Ok(m) => if cbor(&m) != cbor(a) { idem += 1; println!("  {name}: idem FAIL {an}"); },
            Err(e) => { errs += 1; println!("  {name}: merge({an},{an}) ERR {e}"); }
        }
        for (bn, b) in all {
            match (try_merge(params, a, b), try_merge(params, b, a)) {
                (Ok(x), Ok(y)) => if cbor(&x) != cbor(&y) { comm += 1; println!("  {name}: comm FAIL {an} {bn}"); },
                (x, y) => { errs += 1; if an < bn { println!("  {name}: merge({an},{bn}) ERR {:?} / reverse {:?}", x.err(), y.err()); } }
            }
            for (_cn, c3) in all {
                n += 1;
                let l = try_merge(params, a, b).and_then(|ab| try_merge(params, &ab, c3));
                let r = try_merge(params, b, c3).and_then(|bc| try_merge(params, a, &bc));
                if let (Ok(l), Ok(r)) = (l, r) { if cbor(&l) != cbor(&r) { assoc += 1; } }
            }
        }
    }
    println!("{name} native: {} states, {n} triples; comm {comm} assoc {assoc} idem {idem} merge-errors {errs}", all.len());
}

fn gen_review98(root: &Path) {
    let bx = BackingFx::new();
    let params = cbor(&bx.fx.params);
    let p = &bx.fx.params;
    let g1 = SigningKey::from_bytes(&[0xD1; 32]);
    let g2 = SigningKey::from_bytes(&[0xD2; 32]);
    let b1 = bx.backing(&g1, 100);
    let b1_later = bx.backing(&g1, 150);
    let b2 = bx.backing(&g2, 200);
    let r1 = bx.retirement_by(&bx.store, &g1);
    let r2 = bx.retirement_by(&bx.store, &g2);
    let closed = bx.closure_by(&bx.store);
    let l3 = bx.fx.listing(3);
    let l4 = bx.fx.listing(4);
    let i5 = bx.fx.info(5, "Race");

    // ---- (a) backing / retirement order, closed racing a listing ----------
    let race: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("B1", bx.build(None, vec![], vec![b1.clone()], vec![], vec![])),
        ("B1_R1", bx.build(None, vec![], vec![b1.clone()], vec![r1.clone()], vec![])),
        ("B1later", bx.build(None, vec![], vec![b1_later.clone()], vec![], vec![])),
        ("B1later_R1", bx.build(None, vec![], vec![b1_later.clone()], vec![r1.clone()], vec![])),
        ("B2_R2", bx.build(None, vec![], vec![b2.clone()], vec![r2.clone()], vec![])),
        // R1: a retirement arriving before the backing it retires.
        ("R1", bx.build(None, vec![], vec![], vec![r1.clone()], vec![])),
        ("R1_closed", bx.build(None, vec![], vec![], vec![r1.clone()], vec![closed.clone()])),
        ("closed", bx.build(None, vec![], vec![], vec![], vec![closed.clone()])),
        ("L3", bx.build(None, vec![l3.clone()], vec![], vec![], vec![])),
        ("L3_B1", bx.build(None, vec![l3.clone()], vec![b1.clone()], vec![], vec![])),
        ("closed_L4", bx.build(None, vec![l4.clone()], vec![], vec![], vec![closed.clone()])),
        ("info5_closed", bx.build(Some(i5.clone()), vec![], vec![], vec![], vec![closed.clone()])),
        ("L3_L4_closed", bx.build(None, vec![l3.clone(), l4.clone()], vec![], vec![], vec![closed.clone()])),
    ];
    native_laws_total("review98-race", p, &race);
    {
        let mut c = Corpus::new(root, "store-r98race", &params);
        let mut all = race.clone();
        let find = |all: &Vec<(&str, StoreStateV1)>, n: &str| all.iter().find(|(m, _)| *m == n).unwrap().1.clone();
        // transitions: each order of arrival
        let pairs = [("R1", "B1"), ("B1", "R1"), ("R1", "B1later"), ("B1later", "R1"), ("R1_closed", "L3_B1"), ("L3_B1", "R1_closed"), ("default", "R1"),
                     ("B1", "B1_R1"), ("B1_R1", "B1"), ("B2_R2", "B1_R1"), ("closed", "L3"), ("L3", "closed"), ("B1later", "B1"), ("B1", "B1later"),
                     ("closed_L4", "L3_B1"), ("L3_B1", "closed_L4"), ("B1_R1", "B2_R2"), ("info5_closed", "L3")];
        let mut extra = vec![];
        for (a, b) in pairs {
            let r = bx.fx.merged(&find(&all, a), &find(&all, b));
            let name: &'static str = Box::leak(format!("m_{a}__{b}").into_boxed_str());
            extra.push((a, name, r));
        }
        for (_, n, s) in &extra { all.push((n, s.clone())); }
        for (n, s) in &all { c.state(n, &cbor(s)); }
        for (a, n, _) in &extra { c.transition(a, n); }
        // delta steps for each ordered pair
        for (a, b) in pairs {
            let base = find(&all, a);
            let tgt = find(&all, b);
            let summ = base.summarize(&base, p);
            let Some(d) = tgt.delta(&tgt, p, &summ) else { continue };
            let mut r = base.clone();
            r.apply_delta(&base.clone(), p, &Some(d.clone())).unwrap();
            bx.fx.check(&r);
            c.delta_step(&cbor(&base), &cbor(&summ), &cbor(&d), &cbor(&r));
        }
        c.finish();
    }

    // ---- (b) caps: two sides at/under the cap whose union exceeds it -------
    let keys: Vec<SigningKey> = (0..70u8).map(|i| { let mut s = [0xE0u8; 32]; s[0] = i; s[1] = 0x77; SigningKey::from_bytes(&s) }).collect();
    let bk: Vec<AuthorizedBacking> = keys.iter().enumerate().map(|(i, k)| bx.backing(k, 1000 + i as u32)).collect();
    let rt: Vec<AuthorizedRetirement> = keys.iter().map(|k| bx.retirement_by(&bx.store, k)).collect();
    let full_a = bx.build(None, vec![], bk[0..64].to_vec(), vec![], vec![]);
    let full_b = bx.build(None, vec![], bk[1..65].to_vec(), vec![], vec![]); // union 65
    let under_c = bx.build(None, vec![], bk[0..63].to_vec(), vec![], vec![]); // subset of A
    let one_d = bx.build(None, vec![], vec![bk[69].clone()], vec![], vec![]); // A u D = 65
    let rfull_a = bx.build(None, vec![], bk[0..64].to_vec(), rt[0..64].to_vec(), vec![]);
    let rfull_b = bx.build(None, vec![], bk[6..70].to_vec(), rt[6..70].to_vec(), vec![]);
    // The largest slot of all 70, retired and not, alongside one other: it is
    // cut by every union with a full side, and must never come back unretired.
    let mut order: Vec<usize> = (0..70).collect();
    order.sort_by_key(|&i| keys[i].verifying_key().to_bytes());
    let (xi, si) = (order[69], order[0]);
    println!("review98-cap: largest slot is key {xi}, smallest {si}");
    let x_ret = bx.build(None, vec![], vec![bk[xi].clone(), bk[si].clone()], vec![rt[xi].clone()], vec![]);
    let x_plain = bx.build(None, vec![], vec![bk[xi].clone()], vec![], vec![]);
    let x_ret_closed = bx.build(None, vec![l4.clone()], vec![bk[xi].clone()], vec![rt[xi].clone()], vec![closed.clone()]);
    // A third full side: 64 of the 70 that is neither A nor B (skips 3..9).
    let full_c = bx.build(None, vec![], bk[0..3].iter().chain(bk[9..70].iter()).cloned().collect(), vec![], vec![]);
    let closed_only = bx.build(None, vec![], vec![], vec![], vec![closed.clone()]);
    let full_a_closed = bx.build(None, vec![], bk[0..64].to_vec(), vec![], vec![closed.clone()]);
    let listing_d = bx.build(None, vec![l3.clone()], vec![bk[69].clone()], vec![], vec![]);
    let cap: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("fullA", full_a.clone()),
        ("fullB", full_b.clone()),
        ("under63", under_c.clone()),
        ("oneD", one_d.clone()),
        ("rfullA", rfull_a.clone()),
        ("rfullB", rfull_b.clone()),
        ("closed", closed_only.clone()),
        ("fullA_closed", full_a_closed.clone()),
        ("L3_D", listing_d.clone()),
        ("Xret", x_ret.clone()),
        ("Xplain", x_plain.clone()),
        ("Xret_closed_L4", x_ret_closed.clone()),
        ("fullC", full_c.clone()),
    ];
    native_laws_total("review98-cap", p, &cap);
    // Does a closure / listing carried in the same delta as the overflowing
    // backings get through?
    {
        let summ = full_a.summarize(&full_a, p);
        let d = listing_d.delta(&listing_d, p, &summ).unwrap();
        let mut r = full_a.clone();
        println!("review98-cap: fullA <- delta(L3_D): listings {} backings {} -> {:?}",
            d.listings.as_ref().map_or(0, |v| v.len()), d.backings.as_ref().map_or(0, |v| v.len()),
            r.apply_delta(&full_a.clone(), p, &Some(d.clone())));
        let summ_b = full_b.summarize(&full_b, p);
        let d2 = full_a_closed.delta(&full_a_closed, p, &summ_b).unwrap();
        let mut r2 = full_b.clone();
        println!("review98-cap: fullB <- delta(fullA_closed): closed {} backings {} -> {:?}",
            d2.closed.as_ref().map_or(0, |v| v.len()), d2.backings.as_ref().map_or(0, |v| v.len()),
            r2.apply_delta(&full_b.clone(), p, &Some(d2)));
    }
    {
        let mut c = Corpus::new(root, "store-r98cap", &params);
        let mut all = cap.clone();
        let find = |all: &Vec<(&str, StoreStateV1)>, n: &str| all.iter().find(|(m, _)| *m == n).unwrap().1.clone();
        let names: Vec<&str> = cap.iter().map(|(n, _)| *n).collect();
        let pairs = [("fullA", "fullB"), ("fullB", "fullA"), ("fullA", "oneD"), ("oneD", "fullA"),
                     ("fullB", "fullA_closed"), ("fullA_closed", "fullB"), ("fullA", "L3_D"), ("L3_D", "fullA"),
                     ("rfullA", "rfullB"), ("rfullB", "rfullA"), ("rfullA", "fullB"), ("under63", "oneD"),
                     ("Xret", "fullA"), ("fullA", "Xret"), ("Xplain", "rfullA"), ("rfullB", "Xret_closed_L4"),
                     ("fullC", "fullB"), ("fullC", "Xplain")];
        let mut extra = vec![];
        for (a, b) in pairs {
            let r = bx.fx.merged(&find(&all, a), &find(&all, b));
            let name: &'static str = Box::leak(format!("m_{a}__{b}").into_boxed_str());
            extra.push((a, name, r));
        }
        for (_, n, s) in &extra { all.push((n, s.clone())); }
        for (n, s) in &all { c.state(n, &cbor(s)); }
        for (a, n, _) in &extra { c.transition(a, n); }
        // Delta steps: every ordered pair of the base states, so the delta
        // laws see same-base deltas that each push a union past the bound.
        let mut steps = 0;
        for a in &names {
            let base = find(&all, a);
            let summ = base.summarize(&base, p);
            for b in &names {
                let tgt = find(&all, b);
                let Some(d) = tgt.delta(&tgt, p, &summ) else { continue };
                let mut r = base.clone();
                r.apply_delta(&base.clone(), p, &Some(d.clone())).expect("a delta past the bound applies");
                bx.fx.check(&r);
                c.delta_step(&cbor(&base), &cbor(&summ), &cbor(&d), &cbor(&r));
                steps += 1;
            }
        }
        println!("review98-cap: {steps} delta steps");
        c.finish();
    }
}

// ---------------------------------------------------------------------------
// PR #98 fix-round re-check (head b1630ff): orphan retirements are now invalid
// states, and a retirement arriving before its backing is dropped.
// ---------------------------------------------------------------------------

/// `base` plus a retirement inserted raw, bypassing `normalize_backings`.
fn raw_with_retirement(bx: &BackingFx, base: &StoreStateV1, r: AuthorizedRetirement) -> StoreStateV1 {
    let mut s = base.clone();
    s.retirements.records.insert(
        harvest_common::store::Bytes32(r.retirement.backer.to_bytes()),
        r,
    );
    // Since the #98 merge-law re-check an orphan retirement is VALID (a
    // retirement may arrive before its backing); these states stay in the
    // corpus as ordinary ones.
    assert!(s.verify(&s, &bx.fx.params).is_ok(), "an orphan retirement is valid");
    s
}

fn gen_retire98(root: &Path) {
    let bx = BackingFx::new();
    let params = cbor(&bx.fx.params);
    let p = &bx.fx.params;
    let owner = Some(bx.store.verifying_key());
    let g1 = SigningKey::from_bytes(&[0xD1; 32]);
    let g2 = SigningKey::from_bytes(&[0xD2; 32]);
    let b1 = bx.backing(&g1, 100);
    let b2 = bx.backing(&g2, 200);
    let r1 = bx.retirement_by(&bx.store, &g1);
    let closed = bx.closure_by(&bx.store);
    // A full side whose 64 slots all rank below X, the largest of 71 keys.
    let keys: Vec<SigningKey> = (0..71u8).map(|i| { let mut s = [0xA0u8; 32]; s[0] = i; s[1] = 0x55; SigningKey::from_bytes(&s) }).collect();
    let mut order: Vec<usize> = (0..71).collect();
    order.sort_by_key(|&i| keys[i].verifying_key().to_bytes());
    let x = &keys[order[70]];
    let bx_x = bx.backing(x, 500);
    let rx = bx.retirement_by(&bx.store, x);
    let full_s = bx.build(None, vec![], order[0..64].iter().map(|&i| bx.backing(&keys[i], 400 + i as u32)).collect(), vec![], vec![]);

    let bases: Vec<(&str, StoreStateV1)> = vec![
        ("default", StoreStateV1::default()),
        ("B2", bx.build(None, vec![], vec![b2.clone()], vec![], vec![])),
        ("B1", bx.build(None, vec![], vec![b1.clone()], vec![], vec![])),
        ("B12", bx.build(None, vec![], vec![b1.clone(), b2.clone()], vec![], vec![])),
        ("B12_R1", bx.build(None, vec![], vec![b1.clone(), b2.clone()], vec![r1.clone()], vec![])),
        ("B1_R1", bx.build(None, vec![], vec![b1.clone()], vec![r1.clone()], vec![])),
        ("fullS", full_s.clone()),
        ("X", bx.build(None, vec![], vec![bx_x.clone()], vec![], vec![])),
        ("X_RX", bx.build(None, vec![], vec![bx_x.clone()], vec![rx.clone()], vec![])),
    ];
    let d = |backings: Vec<AuthorizedBacking>, retirements: Vec<AuthorizedRetirement>, cl: Vec<AuthorizedClosure>, own: bool| StoreStateV1Delta {
        owner: if own { owner } else { None },
        info: None,
        listings: None,
        orders: None,
        backings: (!backings.is_empty()).then_some(backings),
        retirements: (!retirements.is_empty()).then_some(retirements),
        closed: (!cl.is_empty()).then_some(cl),
        copies: None,
        fulfilment: None,
    };
    let deltas: Vec<(&str, StoreStateV1Delta)> = vec![
        ("ret1", d(vec![], vec![r1.clone()], vec![], true)),
        ("back1", d(vec![b1.clone()], vec![], vec![], true)),
        ("both1", d(vec![b1.clone()], vec![r1.clone()], vec![], true)),
        ("ret1_closed", d(vec![], vec![r1.clone()], vec![closed.clone()], true)),
        ("ret1_noowner", d(vec![], vec![r1.clone()], vec![], false)),
        ("retX", d(vec![], vec![rx.clone()], vec![], true)),
        ("backX", d(vec![bx_x.clone()], vec![], vec![], true)),
        ("bothX", d(vec![bx_x.clone()], vec![rx.clone()], vec![], true)),
    ];
    let apply = |base: &StoreStateV1, dl: &StoreStateV1Delta| -> Result<StoreStateV1, String> {
        let mut r = base.clone();
        r.apply_delta(&base.clone(), p, &Some(dl.clone()))?;
        r.verify(&r, p)?;
        Ok(r)
    };
    let retired = |s: &StoreStateV1, k: &SigningKey| s.retirements.records.contains_key(&harvest_common::store::Bytes32(k.verifying_key().to_bytes()));
    let held = |s: &StoreStateV1, k: &SigningKey| s.backings.records.contains_key(&harvest_common::store::Bytes32(k.verifying_key().to_bytes()));

    // Native: the two arrival orders of a retirement and its backing.
    for (bn, base) in &bases {
        for (key, ret, back) in [(&g1, "ret1", "back1"), (x, "retX", "backX")] {
            let dr = &deltas.iter().find(|(n, _)| *n == ret).unwrap().1;
            let db = &deltas.iter().find(|(n, _)| *n == back).unwrap().1;
            let o1 = apply(base, dr).and_then(|s| apply(&s, db));
            let o2 = apply(base, db).and_then(|s| apply(&s, dr));
            let desc = |o: &Result<StoreStateV1, String>| match o {
                Ok(s) => format!("held={} retired={}", held(s, key), retired(s, key)),
                Err(e) => format!("ERR {e}"),
            };
            let same = matches!((&o1, &o2), (Ok(a), Ok(b)) if cbor(a) == cbor(b));
            println!("retire98 native base {bn}: {ret} then {back}: {}   |   {back} then {ret}: {}   same={same}", desc(&o1), desc(&o2));
        }
    }

    let mut c = Corpus::new(root, "store-r98retire", &params);
    let mut all: Vec<(String, StoreStateV1)> = bases.iter().map(|(n, s)| (n.to_string(), s.clone())).collect();
    let mut steps = 0;
    let mut refused = vec![];
    for (bn, base) in &bases {
        let summ = base.summarize(base, p);
        for (dn, dl) in &deltas {
            match apply(base, dl) {
                Ok(r) => {
                    c.delta_step(&cbor(base), &cbor(&summ), &cbor(dl), &cbor(&r));
                    steps += 1;
                    let rn = format!("d_{bn}__{dn}");
                    if !all.iter().any(|(_, s)| cbor(s) == cbor(&r)) {
                        all.push((rn, r));
                    }
                }
                Err(e) => refused.push(format!("{bn}+{dn}: {e}")),
            }
        }
    }
    // Two-step results, so the states either arrival order leaves are in the
    // corpus and meet each other under the state laws.
    for (bn, base) in &bases {
        for (a, b) in [("ret1", "back1"), ("back1", "ret1"), ("retX", "backX"), ("backX", "retX")] {
            let da = &deltas.iter().find(|(n, _)| *n == a).unwrap().1;
            let db = &deltas.iter().find(|(n, _)| *n == b).unwrap().1;
            if let Ok(r) = apply(base, da).and_then(|s| apply(&s, db)) {
                if !all.iter().any(|(_, s)| cbor(s) == cbor(&r)) {
                    all.push((format!("dd_{bn}__{a}_{b}"), r));
                }
            }
        }
    }
    for (n, s) in &all { c.state(n, &cbor(s)); }
    println!("retire98: {} states, {steps} delta steps; refused (not stepped): {:?}", all.len(), refused);
    let named: Vec<(&str, StoreStateV1)> = all.iter().map(|(n, s)| (n.as_str(), s.clone())).collect();
    native_laws_total("retire98", p, &named);
    c.finish();
}
