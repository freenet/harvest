//! Test fixtures: genuinely signed, genuinely paid orders and complaints
//! about them. Test-only; nothing here is compiled into an artifact.
//!
//! Every signature and proof here verifies for real -- a fixture that only
//! looks right makes a refusal test pass for the wrong reason.

use chrono::DateTime;
use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::{
    spv::testing::payment_proof, BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim,
    ClaimBody, OutPoint, SignedClaim, SignedTipEntry, TipEntryBody,
};

use crate::feedback::FeedbackCategory;
use crate::payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus};
use crate::reputation::{Complaint, ComplaintTag, ComplaintTerms};

pub fn store_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

pub fn bridge_key() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

/// The buyer's receipt key for the order numbered `n`.
pub fn buyer_key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n.wrapping_add(100); 32])
}

/// Below every height a fixture confirms a payment at (100).
const ORDER_ANCHOR_HEIGHT: u32 = 99;
/// Where every fixture payment confirms.
pub const CONFIRM_HEIGHT: u32 = 100;

/// Order `n`, naming `buyer_key(n)` as its buyer.
pub fn order(n: u8) -> Order {
    Order {
        id: OrderId([0u8; 32]),
        buyer_fingerprint: format!("buyer-{n}"),
        seller_fingerprint: "seller-fingerprint".into(),
        amount_sats: 50_000,
        network: BitcoinNetwork::Signet,
        payment_script_pubkey: vec![0x00, 0x14, n, 0xbb],
        payment_hash: None,
        payment_address: "tb1qtest".into(),
        required_confirmations: 1,
        trusted_bridges: vec![BridgeId(bridge_key().verifying_key().to_bytes())],
        bitcoin_address_code_hash: None,
        anchor: Some(BlockAnchor {
            height: ORDER_ANCHOR_HEIGHT,
            hash: BlockHash([0x99; 32]),
        }),
        order_binding: None,
        listing_tag: None,
        buyer_receipt_key: Some(buyer_key(n).verifying_key().to_bytes()),
        created_at: DateTime::from_timestamp(1_700_000_000 + i64::from(n), 0).expect("time"),
    }
    .with_derived_id()
}

/// The requestor half of a test envelope, for tests that build a
/// deliberately malformed one.
#[derive(serde::Serialize)]
pub enum TestRequestorForTests {
    WebApp([u8; 32]),
}

pub fn harvest_requestor_for_tests() -> TestRequestorForTests {
    TestRequestorForTests::WebApp(harvest_requestor_bytes())
}

fn harvest_requestor_bytes() -> [u8; 32] {
    bs58::decode(crate::HARVEST_WEBAPP_CONTRACT_ID)
        .into_vec()
        .expect("HARVEST_WEBAPP_CONTRACT_ID decodes")
        .try_into()
        .expect("32 bytes")
}

/// Sign `data` as the ghostkey delegate's `ScopedPayload` would, pinned to
/// Harvest's requestor.
pub fn sign_scoped<T: serde::Serialize>(key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
    #[derive(serde::Serialize)]
    struct TestScopedPayload {
        requestor: TestRequestor,
        payload: Vec<u8>,
    }
    #[derive(serde::Serialize)]
    enum TestRequestor {
        WebApp([u8; 32]),
    }
    let scoped = crate::to_cbor(&TestScopedPayload {
        requestor: TestRequestor::WebApp(harvest_requestor_bytes()),
        payload: crate::to_cbor(data).expect("encode"),
    })
    .expect("encode");
    let signature = key.sign(&scoped).to_bytes().to_vec();
    (scoped, signature)
}

/// A bridge-signed proof that `order` was paid. `seed` varies the mined block,
/// so two seeds give two different, equally valid proofs for one order.
pub fn proof(order: &Order, seed: u8) -> OrderPaymentProof {
    let bridge = bridge_key();
    let (spv, txid, block_hash) = payment_proof(
        &order.payment_script_pubkey,
        order.amount_sats,
        1,
        [seed; 32],
    );
    let anchor = BlockAnchor {
        height: CONFIRM_HEIGHT,
        hash: block_hash,
    };
    let claim = SignedClaim::sign(
        &bridge,
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
    .expect("sign claim");
    let tip = SignedTipEntry::sign(
        &bridge,
        &TipEntryBody {
            network: order.network,
            anchor: BlockAnchor {
                height: CONFIRM_HEIGHT + order.required_confirmations - 1,
                hash: BlockHash([9u8; 32]),
            },
            prev_hash: BlockHash([8u8; 32]),
            block_time: 1_700_000_000,
            tx_count: 1,
            median_time: 1_700_000_000,
        },
    )
    .expect("sign tip");
    OrderPaymentProof::on_chain(vec![claim], tip)
}

/// `order` as the store publishes it: terms signed by `seller`, at `status`,
/// with a real proof when the status is `Paid`.
pub fn authorized(seller: &SigningKey, order: Order, status: OrderStatus) -> AuthorizedOrder {
    let (scoped_payload, signature) = sign_scoped(seller, &order);
    let payment_proof = (status == OrderStatus::Paid).then(|| proof(&order, 1));
    AuthorizedOrder {
        order,
        scoped_payload,
        signature,
        status,
        payment_proof,
        status_scoped_payload: None,
        status_signature: None,
    }
}

/// Order `n` of the fixture store, genuinely paid.
pub fn paid(n: u8) -> AuthorizedOrder {
    authorized(&store_key(), order(n), OrderStatus::Paid)
}

/// A complaint about `order`, signed by `buyer`.
pub fn complaint_by(
    buyer: &SigningKey,
    order: AuthorizedOrder,
    category: FeedbackCategory,
    block_height: u32,
) -> Complaint {
    let terms = ComplaintTerms {
        tag: ComplaintTag::HarvestComplaintV1,
        order_id: order.order.id.clone(),
        category: category.clone(),
        block_height,
    };
    let (scoped_payload, buyer_signature) = sign_scoped(buyer, &terms);
    Complaint {
        order,
        category,
        block_height,
        scoped_payload,
        buyer_signature,
    }
}

/// The genuine complaint about paid order `n`, by its buyer.
pub fn complaint(n: u8) -> Complaint {
    complaint_by(&buyer_key(n), paid(n), FeedbackCategory::NonDelivery, 200)
}

/// The same order envelope re-encoded compactly: the payload as one CBOR
/// byte string instead of an array of integers. ciborium decodes either
/// into a `Vec<u8>`, so it is the same terms under a fresh seller
/// signature, the same order id, and a valid store record.
pub fn compact_envelope(envelope: &[u8]) -> Vec<u8> {
    use ciborium::Value;
    let mut value: Value = ciborium::from_reader(envelope).expect("an envelope decodes");
    let Value::Map(entries) = &mut value else {
        panic!("an envelope is a map");
    };
    let mut rewrote = false;
    for (key, field) in entries.iter_mut() {
        if key.as_text() == Some("payload") {
            let Value::Array(items) = field else {
                panic!("the payload encodes as an array of integers");
            };
            let bytes: Vec<u8> = items
                .iter()
                .map(|item| u8::try_from(item.as_integer().expect("a byte")).expect("a byte"))
                .collect();
            *field = Value::Bytes(bytes);
            rewrote = true;
        }
    }
    assert!(rewrote, "the envelope has a payload");
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("encodes");
    out
}
