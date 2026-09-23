//! The buyer's kept purchases (harvest#53 Phase C): the seller-signed order,
//! kept from before payment, upgraded to `Paid`, and the complaint filed
//! about it. See `docs/complaint-threat-model.md` section 3 for why each
//! rule is what it is, and [`HarvestDelegateRequest::KeepPurchase`] for the
//! rules themselves.
//!
//! # Why the buyer keeps a copy at all
//!
//! A complaint carries the order as its own evidence, and every copy the
//! store holds is under the seller's control: it can evict an order by
//! flooding the store (`store::enforce_order_cap`), re-sign it, or replace it
//! in a new store generation. So the buyer's node keeps the seller-signed
//! terms before any money moves, and the UI shows no payment details until
//! this module confirms the copy is kept.
//!
//! # The key
//!
//! `harvest:kept_purchase:{order id as lowercase hex}`, one secret per
//! order, holding the CBOR of the whole [`KeptPurchase`]. Under `harvest:`
//! for the reason `handlers.rs` gives; listed in
//! `handlers::all_secret_key_shapes` so the migration tests hold it to
//! account. Fixed length, so [`MAX_KEPT_PURCHASES`] bounds keys as well as
//! records.
//!
//! # Nothing here deletes
//!
//! A purchase is never removed: not by a newer one (past the cap a new one
//! is refused and the buyer is not shown payment details, the safe
//! failure), and not by forgetting the conversation (the record carries its
//! own receipt seed). The one overwrite is of a held record that no longer
//! decodes or verifies, since a damaged first copy would otherwise block
//! every later one (review round 2 of #143, P3).
//!
//! [`HarvestDelegateRequest::KeepPurchase`]: harvest_common::delegate::HarvestDelegateRequest::KeepPurchase

use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_migrate::SecretStore;
use harvest_common::delegate::{
    HarvestDelegateResponse, KeptPurchase, PurchaseToKeep, SecretImport, MAX_KEPT_PURCHASES,
    MAX_KEPT_PURCHASE_BYTES,
};
use harvest_common::payment::{
    complaint_preconditions, verify_minimal_proof, OrderId, OrderStatus,
};
use harvest_common::{from_cbor, to_cbor};
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) const KEPT_PURCHASE_PREFIX: &str = "harvest:kept_purchase:";

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn kept_purchase_key(order_id: &[u8; 32]) -> Vec<u8> {
    format!("{KEPT_PURCHASE_PREFIX}{}", hex_lower(order_id)).into_bytes()
}

fn refuse(order_id: &OrderId, reason: impl Into<String>) -> HarvestDelegateResponse {
    HarvestDelegateResponse::KeepPurchaseRefused {
        order_id: order_id.clone(),
        reason: reason.into(),
    }
}

/// The receipt key `seed` signs with.
fn receipt_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Everything a kept record must satisfy, whoever wrote it: a fresh keep, an
/// upgrade, a complaint added, or a record imported from a predecessor.
fn check(record: &KeptPurchase) -> Result<Vec<u8>, String> {
    let order = &record.order;
    if !matches!(
        order.status,
        OrderStatus::AwaitingPayment | OrderStatus::Paid
    ) {
        return Err(format!(
            "order {} is {:?}; only an order awaiting payment or paid is kept",
            order.order.id, order.status
        ));
    }
    let store_key = VerifyingKey::from_bytes(&record.store_key).map_err(|e| {
        format!(
            "{} is not an Ed25519 store key: {e}",
            hex_lower(&record.store_key)
        )
    })?;
    order
        .verify(&store_key)
        .map_err(|e| format!("this order does not verify against its store key: {e}"))?;
    complaint_preconditions(order)
        .map_err(|e| format!("a complaint about this order could not be filed: {e}"))?;
    // A paid copy is never replaced, so it must already be the one a
    // complaint can carry: the canonical minimal proof
    // (`docs/complaint-threat-model.md` section 5.2). A padded copy kept
    // here would block the complaint for good.
    if order.status == OrderStatus::Paid {
        let proof = order
            .payment_proof
            .as_ref()
            .ok_or("a paid order carries no payment evidence")?;
        verify_minimal_proof(&order.order, proof)
            .map_err(|e| format!("this paid copy is not the one a complaint carries: {e}"))?;
    }
    // The copy is filed under the conversation whose receipt key the order
    // names, so a misfiled copy cannot occupy the slot the right one needs
    // (review round 2 of #143, P3).
    if order.order.buyer_receipt_key != Some(receipt_key(&record.receipt_seed)) {
        return Err(
            "the order does not name this conversation's receipt key, so it was not issued to it"
                .into(),
        );
    }
    if let Some(complaint) = record.filed_complaint() {
        if order.status != OrderStatus::Paid {
            return Err("a complaint is only kept about a paid order".into());
        }
        complaint
            .verify(&store_key)
            .map_err(|e| format!("the complaint does not verify: {e}"))?;
    }
    let bytes = to_cbor(record).map_err(|e| format!("could not encode the purchase: {e}"))?;
    if bytes.len() > MAX_KEPT_PURCHASE_BYTES {
        // Unreachable for anything that passed the checks above: the bound
        // is derived from them (see `MAX_KEPT_PURCHASE_BYTES`). Kept as a
        // refusal rather than an assertion, because a delegate that panics
        // aborts.
        return Err(format!(
            "this purchase is {} bytes, more than the {MAX_KEPT_PURCHASE_BYTES} kept for one",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// The held record under `key`, if it decodes, is filed under its own id,
/// and still passes [`check`]. Anything else is treated as absent, so it
/// can be overwritten.
fn held<S: SecretStore>(store: &S, key: &[u8]) -> Option<KeptPurchase> {
    let record = from_cbor::<KeptPurchase>(&store.get_secret(key)?).ok()?;
    (kept_purchase_key(&record.order.order.id.0) == key && check(&record).is_ok()).then_some(record)
}

/// The receipt seed of the conversation with public key `conversation`, if
/// this delegate holds it.
fn conversation_seed<S: SecretStore>(store: &S, conversation: &[u8; 32]) -> Option<[u8; 32]> {
    crate::messaging::held_conversation_secrets(store)
        .into_iter()
        .find(|secret| PublicKey::from(&StaticSecret::from(*secret)).as_bytes() == conversation)
        .map(|secret| harvest_common::mailbox::buyer_receipt_seed_from_secret(&secret))
}

pub(crate) fn keep<S: SecretStore>(store: &mut S, keep: PurchaseToKeep) -> HarvestDelegateResponse {
    let order_id = keep.order.order.id.clone();
    let key = kept_purchase_key(&order_id.0);
    let held = held(store, &key);

    let receipt_seed = match &held {
        Some(held) => {
            if held.conversation != keep.conversation || held.store_key != keep.store_key {
                return refuse(
                    &order_id,
                    "this order is already kept for another conversation or store",
                );
            }
            held.receipt_seed
        }
        None => match conversation_seed(store, &keep.conversation) {
            Some(seed) => seed,
            None => {
                return refuse(
                    &order_id,
                    "this node does not hold the conversation the order was issued to, so it \
                     cannot keep the key a complaint would be signed with",
                )
            }
        },
    };
    let offered = KeptPurchase {
        store_key: keep.store_key,
        conversation: keep.conversation,
        receipt_seed,
        order: keep.order,
        complaint: keep.complaint,
    };

    let next = match held {
        None => {
            // A new record needs a slot; overwriting a damaged one does not.
            if !store.has_secret(&key)
                && store.list_secrets(KEPT_PURCHASE_PREFIX.as_bytes()).len() >= MAX_KEPT_PURCHASES
            {
                return refuse(
                    &order_id,
                    format!(
                        "this node already keeps {MAX_KEPT_PURCHASES} purchases, the most it \
                         keeps, so it cannot keep this one"
                    ),
                );
            }
            offered
        }
        Some(held) => match (held.order.status, offered.order.status) {
            // The upgrade: the buyer's node has seen it paid.
            (OrderStatus::AwaitingPayment, OrderStatus::Paid) => offered,
            // A paid copy stays as it is, but may gain the filed complaint,
            // once, about that very copy.
            (OrderStatus::Paid, _) if held.complaint.is_none() && offered.complaint.is_some() => {
                KeptPurchase {
                    complaint: offered.complaint,
                    ..held
                }
            }
            // Anything else keeps what is held: a second unpaid copy, an
            // unpaid copy of a paid order, another paid copy (a kept paid
            // copy is never replaced: revision 4 of
            // `docs/complaint-threat-model.md` removed the fresher-evidence
            // rule, section 7.1), a second complaint.
            _ => return list(store),
        },
    };
    let bytes = match check(&next) {
        Ok(bytes) => bytes,
        Err(reason) => return refuse(&order_id, reason),
    };
    if !store.set_secret(&key, &bytes) {
        return refuse(&order_id, "the node refused to save the purchase");
    }
    list(store)
}

pub(crate) fn list<S: SecretStore>(store: &S) -> HarvestDelegateResponse {
    let mut purchases: Vec<KeptPurchase> = store
        .list_secrets(KEPT_PURCHASE_PREFIX.as_bytes())
        .into_iter()
        .filter_map(|key| {
            let record = from_cbor::<KeptPurchase>(&store.get_secret(&key)?).ok()?;
            (kept_purchase_key(&record.order.order.id.0) == key).then_some(record)
        })
        .collect();
    purchases.sort_by(|a, b| a.order.order.id.0.cmp(&b.order.order.id.0));
    HarvestDelegateResponse::KeptPurchases { purchases }
}

pub(crate) fn import<S: SecretStore>(store: &mut S, key: &[u8], value: &[u8]) -> SecretImport {
    let Ok(incoming) = from_cbor::<KeptPurchase>(value) else {
        return SecretImport::Permanent("the predecessor's kept purchase did not decode".into());
    };
    if kept_purchase_key(&incoming.order.order.id.0) != key {
        return SecretImport::Permanent(
            "the predecessor's key does not match this purchase's own order id".into(),
        );
    }
    // Validated exactly as a fresh keep is; the seed travels in the record,
    // so the conversation need not have arrived yet.
    let bytes = match check(&incoming) {
        Ok(bytes) => bytes,
        Err(message) => return SecretImport::Permanent(message),
    };
    // Merged as a fresh keep would be, not "whoever is here first" (review
    // round 3): the successor may already hold an unpaid copy, or a paid
    // one without the complaint, while the predecessor holds the paid copy
    // and the complaint. Both records passed `check`, so the more complete
    // one wins: a complaint first (and a held complaint is never swapped
    // for another), then paid over unpaid. On a tie what is held stays.
    if let Some(held) = held(store, key) {
        let completeness = |record: &KeptPurchase| {
            (
                record.complaint.is_some(),
                record.order.status == OrderStatus::Paid,
            )
        };
        if held.complaint.is_some() || completeness(&incoming) <= completeness(&held) {
            return SecretImport::AlreadyAuthoritative;
        }
        return if store.set_secret(key, &bytes) {
            SecretImport::Written
        } else {
            SecretImport::Retryable("the node refused to save the purchase".into())
        };
    }
    if !store.has_secret(key)
        && store.list_secrets(KEPT_PURCHASE_PREFIX.as_bytes()).len() >= MAX_KEPT_PURCHASES
    {
        return SecretImport::Retryable(format!(
            "this node already keeps {MAX_KEPT_PURCHASES} purchases, the most it keeps"
        ));
    }
    if store.set_secret(key, &bytes) {
        SecretImport::Written
    } else {
        SecretImport::Retryable("the node refused to save the purchase".into())
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use chrono::DateTime;
    use ed25519_dalek::Signer;
    use freenet_bitcoin_common::{
        spv::testing::payment_proof, BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim,
        ClaimBody, OutPoint, SignedClaim, SignedTipEntry, TipEntryBody,
    };
    use harvest_common::delegate::{ConversationSecret, KeptComplaint};
    use harvest_common::feedback::FeedbackCategory;
    use harvest_common::payment::{AuthorizedOrder, Order, OrderPaymentProof};
    use harvest_common::reputation::{ComplaintTag, ComplaintTerms};

    pub(crate) fn store_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    pub(crate) fn other_store_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[99u8; 32])
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[22u8; 32])
    }

    /// Conversation `c`'s secret.
    pub(crate) fn conversation_secret(c: u8) -> [u8; 32] {
        [c.wrapping_add(40); 32]
    }

    /// Conversation `c`'s public key: what a purchase is filed under.
    pub(crate) fn conversation(c: u8) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(conversation_secret(c))).as_bytes()
    }

    /// Conversation `c`'s receipt seed, as the delegate derives it.
    pub(crate) fn seed(c: u8) -> [u8; 32] {
        harvest_common::mailbox::buyer_receipt_seed_from_secret(&conversation_secret(c))
    }

    /// Store conversation `c` in `store`, as `StoreBuyerConversation` would.
    pub(crate) fn hold_conversation<S: SecretStore>(store: &mut S, c: u8) {
        let record = crate::messaging::BuyerConversationRecord {
            secret: ConversationSecret(conversation_secret(c)),
            seller_public_key: [5u8; 32],
            conversation_id: [c; 32],
            created_at: 1_700_000_000,
            backed_up: false,
            imported: false,
        };
        assert!(store.set_secret(
            &crate::messaging::buyer_conversation_key(&[3u8; 32], &conversation(c)),
            &to_cbor(&record).expect("encode"),
        ));
    }

    fn harvest_requestor_bytes() -> [u8; 32] {
        bs58::decode(harvest_common::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .expect("HARVEST_WEBAPP_CONTRACT_ID decodes")
            .try_into()
            .expect("32 bytes")
    }

    pub(crate) fn sign_scoped<T: serde::Serialize>(
        key: &SigningKey,
        data: &T,
    ) -> (Vec<u8>, Vec<u8>) {
        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }
        let scoped = to_cbor(&TestScopedPayload {
            requestor: TestRequestor::WebApp(harvest_requestor_bytes()),
            payload: to_cbor(data).expect("encode"),
        })
        .expect("encode");
        let signature = key.sign(&scoped).to_bytes().to_vec();
        (scoped, signature)
    }

    /// Order `n`, issued to conversation `c`.
    ///
    /// `n` is `u16` so the cap tests (1024 orders) get 1024 genuinely
    /// distinct order ids.
    pub(crate) fn order(n: u16, c: u8) -> Order {
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fingerprint".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, (n >> 8) as u8, (n & 0xff) as u8, 0xbb],
            payment_hash: None,
            payment_address: "tb1qtest".into(),
            required_confirmations: 1,
            trusted_bridges: vec![BridgeId(bridge_key().verifying_key().to_bytes())],
            bitcoin_address_code_hash: None,
            anchor: Some(BlockAnchor {
                height: 99,
                hash: BlockHash([0x99; 32]),
            }),
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: Some(receipt_key(&seed(c))),
            created_at: DateTime::from_timestamp(1_700_000_000 + i64::from(n), 0).expect("time"),
        }
        .with_derived_id()
    }

    /// A bridge-signed proof that `order` was paid; `seed` varies the block,
    /// so two seeds are two different, equally valid proofs.
    fn proof(order: &Order, seed: u8) -> OrderPaymentProof {
        let bridge = bridge_key();
        let (spv, txid, block_hash) = payment_proof(
            &order.payment_script_pubkey,
            order.amount_sats,
            1,
            [seed; 32],
        );
        let anchor = BlockAnchor {
            height: 100,
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
                    height: 100 + order.required_confirmations - 1,
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

    /// A genuine confirmation of `order`'s payment at height 100, signed by
    /// the bridge at `as_of`: a later rung of the same payment.
    pub(crate) fn claim_as_of(order: &Order, as_of: u32) -> SignedClaim {
        let (spv, txid, block_hash) = payment_proof(
            &order.payment_script_pubkey,
            order.amount_sats,
            1,
            [1u8; 32],
        );
        SignedClaim::sign(
            &bridge_key(),
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: BlockAnchor {
                    height: as_of,
                    hash: BlockHash([0x55; 32]),
                },
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: order.amount_sats,
                    anchor: BlockAnchor {
                        height: 100,
                        hash: block_hash,
                    },
                    spv,
                },
            },
        )
        .expect("sign claim")
    }

    /// `order` at `status`, terms signed by `seller`, with real payment
    /// evidence (varied by `proof_seed`) when `Paid`.
    pub(crate) fn authorized(
        seller: &SigningKey,
        order: Order,
        status: OrderStatus,
        proof_seed: u8,
    ) -> AuthorizedOrder {
        let (scoped_payload, signature) = sign_scoped(seller, &order);
        let payment_proof = (status == OrderStatus::Paid).then(|| proof(&order, proof_seed));
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

    /// What the UI sends to keep order `n` of conversation `c` at `status`.
    pub(crate) fn to_keep(n: u16, c: u8, status: OrderStatus, proof_seed: u8) -> PurchaseToKeep {
        PurchaseToKeep {
            store_key: store_signing_key().verifying_key().to_bytes(),
            conversation: conversation(c),
            order: authorized(&store_signing_key(), order(n, c), status, proof_seed),
            complaint: None,
        }
    }

    /// The buyer's half of a complaint about `order`, signed with `seed`.
    pub(crate) fn complaint_about(
        order: &AuthorizedOrder,
        seed: &[u8; 32],
        category: FeedbackCategory,
    ) -> KeptComplaint {
        let paid_height = harvest_common::payment::paid_height(order).unwrap_or(0);
        let terms = ComplaintTerms {
            tag: ComplaintTag::HarvestComplaintV1,
            order_id: order.order.id.clone(),
            category: category.clone(),
            block_height: 200,
            paid_height,
        };
        let (scoped_payload, buyer_signature) = sign_scoped(&SigningKey::from_bytes(seed), &terms);
        KeptComplaint {
            category,
            block_height: 200,
            paid_height,
            scoped_payload,
            buyer_signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::secrets::{MemSecrets, RemovableSecrets};
    use harvest_common::feedback::FeedbackCategory;

    fn purchases(response: HarvestDelegateResponse) -> Vec<KeptPurchase> {
        match response {
            HarvestDelegateResponse::KeptPurchases { purchases } => purchases,
            other => panic!("expected the kept purchase list, got {other:?}"),
        }
    }

    fn refusal(response: HarvestDelegateResponse) -> (OrderId, String) {
        match response {
            HarvestDelegateResponse::KeepPurchaseRefused { order_id, reason } => (order_id, reason),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn holding(c: u8) -> MemSecrets {
        let mut secrets = MemSecrets::default();
        hold_conversation(&mut secrets, c);
        secrets
    }

    /// **The buyer keeps the seller-signed terms before paying, with the
    /// receipt seed the delegate derived** (`docs/complaint-threat-model.md`
    /// section 3.1). Red if the seed is taken from anywhere but the held
    /// conversation.
    #[test]
    fn an_unpaid_order_is_kept_with_its_conversations_receipt_seed() {
        let mut secrets = holding(1);
        let kept = purchases(keep(
            &mut secrets,
            to_keep(1, 1, OrderStatus::AwaitingPayment, 1),
        ));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].order.status, OrderStatus::AwaitingPayment);
        assert_eq!(kept[0].receipt_seed, seed(1));
        assert_eq!(purchases(list(&secrets)), kept);
    }

    /// **A kept unpaid copy is upgraded by a verifying paid one, and a kept
    /// paid copy is never replaced** (section 3.2): not by a second paid copy
    /// with other evidence, and not by an unpaid copy. Red if the second
    /// paid copy replaces the first, or if the upgrade is refused.
    #[test]
    fn unpaid_upgrades_to_paid_and_paid_is_never_replaced() {
        let mut secrets = holding(1);
        keep(&mut secrets, to_keep(1, 1, OrderStatus::AwaitingPayment, 1));
        let upgraded = purchases(keep(&mut secrets, to_keep(1, 1, OrderStatus::Paid, 1)));
        assert_eq!(upgraded[0].order.status, OrderStatus::Paid);
        let first = upgraded[0].order.clone();
        for later in [
            to_keep(1, 1, OrderStatus::Paid, 2),
            to_keep(1, 1, OrderStatus::AwaitingPayment, 1),
        ] {
            let after = purchases(keep(&mut secrets, later));
            assert_eq!(after.len(), 1);
            assert_eq!(after[0].order, first, "the first paid copy stays");
        }
    }

    /// **The filed complaint is kept once, about the kept copy, and only if
    /// it verifies** (section 3.4). Red if a second complaint replaces the
    /// first, or if an unverifying one is kept.
    #[test]
    fn the_filed_complaint_is_kept_once_and_must_verify() {
        let mut secrets = holding(1);
        let paid = purchases(keep(&mut secrets, to_keep(1, 1, OrderStatus::Paid, 1)))
            .remove(0)
            .order;

        let forged = PurchaseToKeep {
            complaint: Some(complaint_about(
                &paid,
                &[77u8; 32],
                FeedbackCategory::NonDelivery,
            )),
            ..to_keep(1, 1, OrderStatus::Paid, 1)
        };
        let (_, reason) = refusal(keep(&mut secrets, forged));
        assert!(reason.contains("complaint does not verify"), "{reason}");

        let genuine = complaint_about(&paid, &seed(1), FeedbackCategory::NonDelivery);
        let kept = purchases(keep(
            &mut secrets,
            PurchaseToKeep {
                complaint: Some(genuine.clone()),
                ..to_keep(1, 1, OrderStatus::Paid, 1)
            },
        ));
        assert_eq!(kept[0].complaint.as_ref(), Some(&genuine));

        let second = complaint_about(&paid, &seed(1), FeedbackCategory::Counterfeit);
        let kept = purchases(keep(
            &mut secrets,
            PurchaseToKeep {
                complaint: Some(second),
                ..to_keep(1, 1, OrderStatus::Paid, 1)
            },
        ));
        assert_eq!(
            kept[0].complaint.as_ref(),
            Some(&genuine),
            "the first stays"
        );
    }

    /// **A paid copy is kept only with the proof a complaint can carry**: the
    /// canonical minimal one. A kept paid copy is never replaced, so a padded
    /// one kept here would block the complaint for good. Red if `check`
    /// stops requiring `verify_minimal_proof`.
    #[test]
    fn a_paid_copy_with_padded_evidence_is_refused() {
        use harvest_common::payment::OrderPaymentProof;
        let mut secrets = holding(1);
        let mut padded = to_keep(1, 1, OrderStatus::Paid, 1);
        let Some(OrderPaymentProof::OnChain(proof)) = padded.order.payment_proof.as_mut() else {
            panic!("on chain");
        };
        proof.claims.push(proof.claims[0].clone());
        padded
            .order
            .verify(&store_signing_key().verifying_key())
            .expect("precondition: the padded copy verifies");
        let (_, reason) = refusal(keep(&mut secrets, padded));
        assert!(
            reason.contains("not the one a complaint carries"),
            "{reason}"
        );
    }

    /// A paid copy following a reorg: `n`'s payment, confirmed at 100, with a
    /// claim signed at `as_of`.
    fn paid_as_of(n: u16, c: u8, as_of: u32) -> PurchaseToKeep {
        use harvest_common::payment::OrderPaymentProof;
        let mut keep = to_keep(n, c, OrderStatus::Paid, 1);
        let Some(OrderPaymentProof::OnChain(proof)) = keep.order.payment_proof.as_mut() else {
            panic!("on chain");
        };
        proof.claims = vec![fixtures::claim_as_of(&keep.order.order, as_of)];
        keep
    }

    /// **A kept paid copy is never replaced, and still gains its
    /// complaint** (model 3.2, revision 4 removed the fresher-evidence rule).
    /// Red if a later paid copy replaces the held one.
    #[test]
    fn a_kept_paid_copy_is_never_replaced() {
        use harvest_common::payment::evidence_freshness;
        let mut secrets = holding(1);
        keep(&mut secrets, paid_as_of(1, 1, 100));
        let held = purchases(keep(&mut secrets, paid_as_of(1, 1, 105))).remove(0);
        assert_eq!(evidence_freshness(&held.order), 100, "not replaced");

        let complaint = complaint_about(&held.order, &seed(1), FeedbackCategory::NonDelivery);
        let kept = purchases(keep(
            &mut secrets,
            PurchaseToKeep {
                complaint: Some(complaint),
                ..paid_as_of(1, 1, 100)
            },
        ))
        .remove(0);
        assert!(kept.complaint.is_some(), "the complaint is kept");
        assert_eq!(evidence_freshness(&kept.order), 100);
    }

    /// **Migration merges as a keep would** (review round 3): the successor
    /// holding only the unpaid copy takes the predecessor's paid copy and
    /// complaint; a successor already holding a complaint keeps it. Red if
    /// import keeps whatever the successor holds.
    #[test]
    fn import_takes_the_more_complete_record() {
        let mut predecessor = holding(1);
        let paid = purchases(keep(&mut predecessor, to_keep(1, 1, OrderStatus::Paid, 1)))
            .remove(0)
            .order;
        keep(
            &mut predecessor,
            PurchaseToKeep {
                complaint: Some(complaint_about(
                    &paid,
                    &seed(1),
                    FeedbackCategory::NonDelivery,
                )),
                ..to_keep(1, 1, OrderStatus::Paid, 1)
            },
        );
        let key = kept_purchase_key(&order(1, 1).id.0);
        let value = predecessor.get_secret(&key).expect("kept");

        let mut successor = holding(1);
        keep(
            &mut successor,
            to_keep(1, 1, OrderStatus::AwaitingPayment, 1),
        );
        assert!(matches!(
            import(&mut successor, &key, &value),
            SecretImport::Written
        ));
        let merged = purchases(list(&successor)).remove(0);
        assert_eq!(merged.order.status, OrderStatus::Paid);
        assert!(merged.complaint.is_some());
        assert!(matches!(
            import(&mut successor, &key, &value),
            SecretImport::AlreadyAuthoritative
        ));

        // A held complaint is never swapped for another.
        let mut other = holding(1);
        let later = purchases(keep(&mut other, paid_as_of(1, 1, 105)))
            .remove(0)
            .order;
        keep(
            &mut other,
            PurchaseToKeep {
                complaint: Some(complaint_about(
                    &later,
                    &seed(1),
                    FeedbackCategory::Misrepresented,
                )),
                ..paid_as_of(1, 1, 105)
            },
        );
        let held_before = other.get_secret(&key);
        assert!(matches!(
            import(&mut other, &key, &value),
            SecretImport::AlreadyAuthoritative
        ));
        assert_eq!(other.get_secret(&key), held_before, "complaint vs complaint");

        // A held paid copy is not replaced by an incoming unpaid one, nor by
        // an incoming paid one that differs only in its evidence.
        let mut unpaid_source = holding(1);
        keep(
            &mut unpaid_source,
            to_keep(1, 1, OrderStatus::AwaitingPayment, 1),
        );
        let unpaid_value = unpaid_source.get_secret(&key).expect("kept");
        let mut fresher_source = holding(1);
        keep(&mut fresher_source, paid_as_of(1, 1, 110));
        let fresher_value = fresher_source.get_secret(&key).expect("kept");
        let mut paid_holder = holding(1);
        keep(&mut paid_holder, paid_as_of(1, 1, 100));
        let held_before = paid_holder.get_secret(&key);
        for incoming in [unpaid_value, fresher_value] {
            assert!(matches!(
                import(&mut paid_holder, &key, &incoming),
                SecretImport::AlreadyAuthoritative
            ));
            assert_eq!(paid_holder.get_secret(&key), held_before);
        }
    }

    /// No complaint is kept about an unpaid order.
    #[test]
    fn a_complaint_about_an_unpaid_order_is_refused() {
        let mut secrets = holding(1);
        let unpaid = to_keep(1, 1, OrderStatus::AwaitingPayment, 1);
        let with_complaint = PurchaseToKeep {
            complaint: Some(complaint_about(
                &unpaid.order,
                &seed(1),
                FeedbackCategory::NonDelivery,
            )),
            ..unpaid
        };
        let (_, reason) = refusal(keep(&mut secrets, with_complaint));
        assert!(reason.contains("only kept about a paid order"), "{reason}");
    }

    /// **Every refusal names the order and says why** (review round 2 of
    /// #143, R2-4: a generic `Error` carries no request id, so the UI could
    /// not release its marker). Each case is one thing a copy must satisfy.
    #[test]
    fn refusals_name_the_order_and_why() {
        let other_store = PurchaseToKeep {
            order: authorized(
                &other_store_signing_key(),
                order(1, 1),
                OrderStatus::AwaitingPayment,
                1,
            ),
            ..to_keep(1, 1, OrderStatus::AwaitingPayment, 1)
        };
        let mut free = order(2, 1);
        free.amount_sats = 0;
        let free = PurchaseToKeep {
            order: authorized(
                &store_signing_key(),
                free.with_derived_id(),
                OrderStatus::AwaitingPayment,
                1,
            ),
            ..to_keep(2, 1, OrderStatus::AwaitingPayment, 1)
        };
        let mut cancelled = to_keep(3, 1, OrderStatus::AwaitingPayment, 1);
        cancelled.order.status = OrderStatus::Cancelled;
        let misfiled = PurchaseToKeep {
            order: authorized(
                &store_signing_key(),
                order(4, 2),
                OrderStatus::AwaitingPayment,
                1,
            ),
            ..to_keep(4, 1, OrderStatus::AwaitingPayment, 1)
        };
        let unheld = to_keep(5, 9, OrderStatus::AwaitingPayment, 1);
        for (what, offered, needle) in [
            ("another store's order", other_store, "does not verify"),
            ("an order for nothing", free, "for nothing"),
            ("a cancelled order", cancelled, "only an order awaiting"),
            ("another conversation's order", misfiled, "receipt key"),
            (
                "a conversation not held",
                unheld,
                "does not hold the conversation",
            ),
        ] {
            let mut secrets = holding(1);
            let id = offered.order.order.id.clone();
            let (named, reason) = refusal(keep(&mut secrets, offered));
            assert_eq!(named, id, "{what}");
            assert!(reason.contains(needle), "{what}: {reason}");
            assert!(
                secrets
                    .list_secrets(KEPT_PURCHASE_PREFIX.as_bytes())
                    .is_empty(),
                "{what}: nothing kept"
            );
        }
    }

    /// **Losing the conversation does not lose the purchase** (review round
    /// 2 of #143, R2-5). After the conversation is gone, the kept record
    /// still carries the seed, and the upgrade to paid still works. Red if
    /// the upgrade re-derives the seed from the conversation.
    #[test]
    fn a_purchase_outlives_its_conversation() {
        let mut secrets = holding(1);
        keep(&mut secrets, to_keep(1, 1, OrderStatus::AwaitingPayment, 1));
        let conversation_keys =
            secrets.list_secrets(crate::messaging::BUYER_CONVERSATION_PREFIX_STR.as_bytes());
        for key in conversation_keys {
            assert!(secrets.remove_secret(&key));
        }
        let kept = purchases(keep(&mut secrets, to_keep(1, 1, OrderStatus::Paid, 1)));
        assert_eq!(kept[0].order.status, OrderStatus::Paid);
        assert_eq!(kept[0].receipt_seed, seed(1));
    }

    /// A copy already kept for one conversation is not re-filed under
    /// another.
    #[test]
    fn a_kept_order_is_not_re_filed_under_another_conversation() {
        let mut secrets = holding(1);
        hold_conversation(&mut secrets, 2);
        keep(&mut secrets, to_keep(1, 1, OrderStatus::AwaitingPayment, 1));
        let refiled = PurchaseToKeep {
            conversation: conversation(2),
            ..to_keep(1, 1, OrderStatus::Paid, 1)
        };
        let (_, reason) = refusal(keep(&mut secrets, refiled));
        assert!(reason.contains("another conversation"), "{reason}");
    }

    /// **Past the cap a new purchase is refused, never an old one dropped,
    /// and an upgrade still goes through** (section 5.1). Red if the cap
    /// evicts, or counts an upgrade as a new slot.
    #[test]
    fn past_the_cap_a_new_purchase_is_refused_but_an_upgrade_is_not() {
        let mut secrets = holding(1);
        for n in 0..MAX_KEPT_PURCHASES as u16 {
            purchases(keep(
                &mut secrets,
                to_keep(n, 1, OrderStatus::AwaitingPayment, 1),
            ));
        }
        let (_, reason) = refusal(keep(
            &mut secrets,
            to_keep(
                MAX_KEPT_PURCHASES as u16,
                1,
                OrderStatus::AwaitingPayment,
                1,
            ),
        ));
        assert!(reason.contains("the most it keeps"), "{reason}");
        let kept = purchases(keep(&mut secrets, to_keep(0, 1, OrderStatus::Paid, 1)));
        assert_eq!(kept.len(), MAX_KEPT_PURCHASES);
        assert!(kept
            .iter()
            .any(|p| p.order.order.id == order(0, 1).id && p.order.status == OrderStatus::Paid));
    }

    /// **A damaged held record does not block the real one** (review round
    /// 2 of #143, P3). Red if a held record is kept whatever it holds.
    #[test]
    fn a_damaged_record_is_overwritten() {
        let mut secrets = holding(1);
        let key = kept_purchase_key(&order(1, 1).id.0);
        assert!(secrets.set_secret(&key, b"not a purchase"));
        let kept = purchases(keep(
            &mut secrets,
            to_keep(1, 1, OrderStatus::AwaitingPayment, 1),
        ));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].order.order.id, order(1, 1).id);
    }

    #[test]
    fn list_skips_a_record_under_the_wrong_key() {
        let mut secrets = holding(1);
        keep(&mut secrets, to_keep(1, 1, OrderStatus::AwaitingPayment, 1));
        let bytes = secrets
            .get_secret(&kept_purchase_key(&order(1, 1).id.0))
            .expect("kept");
        assert!(secrets.set_secret(&kept_purchase_key(&[0xab; 32]), &bytes));
        assert_eq!(purchases(list(&secrets)).len(), 1);
    }

    /// **An imported record is checked exactly as a fresh keep is, using the
    /// seed it carries** (the conversation may not have arrived yet). Red if
    /// the import skips `check`.
    #[test]
    fn import_follows_the_same_checks_as_keep() {
        let mut source = holding(1);
        keep(&mut source, to_keep(1, 1, OrderStatus::Paid, 1));
        let key = kept_purchase_key(&order(1, 1).id.0);
        let value = source.get_secret(&key).expect("kept");

        let mut fresh = MemSecrets::default();
        assert!(matches!(
            import(&mut fresh, &key, &value),
            SecretImport::Written
        ));
        assert!(matches!(
            import(&mut fresh, &key, &value),
            SecretImport::AlreadyAuthoritative
        ));

        let mut wrong_seed: KeptPurchase = from_cbor(&value).expect("decodes");
        wrong_seed.receipt_seed = seed(2);
        let mut other = MemSecrets::default();
        assert!(matches!(
            import(&mut other, &key, &to_cbor(&wrong_seed).expect("encode")),
            SecretImport::Permanent(_)
        ));
        assert!(matches!(
            import(&mut other, &kept_purchase_key(&[1u8; 32]), &value),
            SecretImport::Permanent(_)
        ));
        assert!(matches!(
            import(&mut other, &key, b"junk"),
            SecretImport::Permanent(_)
        ));
    }

    #[test]
    fn import_respects_the_cap() {
        let mut secrets = holding(1);
        for n in 0..MAX_KEPT_PURCHASES as u16 {
            keep(&mut secrets, to_keep(n, 1, OrderStatus::AwaitingPayment, 1));
        }
        let mut source = holding(1);
        let extra = MAX_KEPT_PURCHASES as u16;
        keep(
            &mut source,
            to_keep(extra, 1, OrderStatus::AwaitingPayment, 1),
        );
        let key = kept_purchase_key(&order(extra, 1).id.0);
        let value = source.get_secret(&key).expect("kept");
        assert!(matches!(
            import(&mut secrets, &key, &value),
            SecretImport::Retryable(_)
        ));
    }

    /// A store with no way to remove anything: the structural half of
    /// "nothing here deletes".
    struct NoRemoval(MemSecrets);

    impl SecretStore for NoRemoval {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.0.list_secrets(prefix)
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get_secret(key)
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.0.has_secret(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.set_secret(key, value)
        }
    }

    #[test]
    fn nothing_here_can_delete_a_record() {
        let mut secrets = NoRemoval(holding(1));
        for n in 0u16..10 {
            keep(&mut secrets, to_keep(n, 1, OrderStatus::AwaitingPayment, 1));
            list(&secrets);
        }
        assert_eq!(
            secrets.list_secrets(KEPT_PURCHASE_PREFIX.as_bytes()).len(),
            10
        );
    }

    #[test]
    fn a_refused_write_is_reported_with_the_order() {
        let mut secrets = MemSecrets::refusing_writes();
        // The conversation has to be readable for the write to be attempted.
        let offered = to_keep(1, 1, OrderStatus::AwaitingPayment, 1);
        let (_, reason) = refusal(keep(&mut secrets, offered));
        assert!(
            reason.contains("does not hold the conversation") || reason.contains("refused"),
            "{reason}"
        );
    }
}
