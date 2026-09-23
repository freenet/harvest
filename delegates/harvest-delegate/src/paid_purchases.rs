//! The buyer's own copy of a paid order (harvest#53 Phase C, review round 1
//! of #143, P1-2). Modelled closely on `known_stores.rs`.
//!
//! # Why this needs its own copy at all
//!
//! A complaint carries the paid order as its own evidence, and until now a
//! buyer read that order out of the store contract's own state. The seller
//! controls what that state keeps: `store::enforce_order_cap` drops the
//! oldest orders past `MAX_ORDERS`, so 4,096 newer unpaid orders -- free for
//! anyone to issue -- push a paid one out, and with it the buyer's only copy
//! of their evidence. A copy kept here, once seen, survives that.
//!
//! # The key
//!
//! `harvest:paid_order:{order id as lowercase hex}`, one secret per order,
//! holding the CBOR of the whole [`PaidPurchase`]. It starts with `harvest:`
//! for the reason `handlers.rs` gives: a key outside that prefix is silently
//! left behind by every future delegate migration. `handlers::all_secret_key_shapes`
//! lists it so the migration tests hold that to account. The key is fixed
//! length because an order id is, so [`MAX_PAID_PURCHASES`] bounds bytes as
//! well as entries once combined with [`MAX_PAID_PURCHASE_BYTES`].
//!
//! # Validated before it is ever written
//!
//! [`remember`] refuses anything that is not a `Paid`
//! [`harvest_common::payment::AuthorizedOrder`] verifying under
//! `purchase.store_key` -- terms, and payment evidence against the bridges
//! the seller signed into the order -- and anything whose CBOR encoding
//! exceeds [`MAX_PAID_PURCHASE_BYTES`]. A buyer's own copy is complaint
//! evidence; keeping something that never verified as paid would be worse
//! than keeping nothing, since a reader of the complaint would trust it.
//!
//! # First copy wins
//!
//! Two genuinely valid pieces of payment evidence can exist for one order id
//! (a bridge may sign more than one qualifying claim), so a second
//! `RememberPaidPurchase` for an order id already held is a no-op rather than
//! a replacement: replacing would let whichever caller runs LAST choose which
//! evidence the buyer's own device keeps, and the buyer's own copy is exactly
//! the one thing that must not be swappable after the fact by a later
//! message.
//!
//! # Held structurally, but only this far
//!
//! Every function in THIS module is generic over `SecretStore` alone, which
//! has no removal, so one of them deleting a record would need a new bound,
//! and `tests::nothing_here_can_delete_a_record` stops compiling for any
//! function it calls that gains one. It does not cover the rest of the
//! crate: the handlers hold `RemovableSecrets`, and nothing stops code there
//! from removing a `harvest:paid_order:` key directly.

use ed25519_dalek::VerifyingKey;
use freenet_migrate::SecretStore;
use harvest_common::delegate::{
    HarvestDelegateResponse, PaidPurchase, SecretImport, MAX_PAID_PURCHASES,
    MAX_PAID_PURCHASE_BYTES,
};
use harvest_common::payment::OrderStatus;
use harvest_common::{from_cbor, to_cbor};

/// Where every kept paid order's secret lives.
pub(crate) const PAID_PURCHASE_PREFIX: &str = "harvest:paid_order:";

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn paid_purchase_key(order_id: &[u8; 32]) -> Vec<u8> {
    format!("{PAID_PURCHASE_PREFIX}{}", hex_lower(order_id)).into_bytes()
}

fn refuse(message: impl Into<String>) -> HarvestDelegateResponse {
    HarvestDelegateResponse::Error {
        message: message.into(),
    }
}

/// Check `purchase` is genuinely a paid, verifying order that fits the
/// per-record cap, and return its key and CBOR encoding.
///
/// Shared by [`remember`] and [`import`], so a predecessor's export is held
/// to exactly the same rule as a fresh request: neither ever writes evidence
/// that does not verify.
fn validate(purchase: &PaidPurchase) -> Result<(Vec<u8>, Vec<u8>), String> {
    if purchase.order.status != OrderStatus::Paid {
        return Err(format!(
            "order {} is {:?}, not Paid, so there is nothing to keep a buyer's copy of",
            purchase.order.order.id, purchase.order.status
        ));
    }
    let store_key = VerifyingKey::from_bytes(&purchase.store_key).map_err(|e| {
        format!(
            "{} is not an Ed25519 store key: {e}",
            hex_lower(&purchase.store_key)
        )
    })?;
    purchase
        .order
        .verify(&store_key)
        .map_err(|e| format!("this order does not verify against its store key: {e}"))?;
    let bytes = to_cbor(purchase).map_err(|e| format!("could not encode the paid order: {e}"))?;
    if bytes.len() > MAX_PAID_PURCHASE_BYTES {
        return Err(format!(
            "this order's evidence is {} bytes, more than the {MAX_PAID_PURCHASE_BYTES} kept \
             for one purchase",
            bytes.len()
        ));
    }
    Ok((paid_purchase_key(&purchase.order.order.id.0), bytes))
}

/// `RememberPaidPurchase`: keep the buyer's own copy of a genuinely paid
/// order, refusing anything that does not verify or does not fit. See the
/// module docs for why a copy already held for the same order id is left
/// unchanged rather than replaced.
pub(crate) fn remember<S: SecretStore>(
    store: &mut S,
    purchase: PaidPurchase,
) -> HarvestDelegateResponse {
    let (key, bytes) = match validate(&purchase) {
        Ok(v) => v,
        Err(message) => return refuse(message),
    };
    if !store.has_secret(&key) {
        if store.list_secrets(PAID_PURCHASE_PREFIX.as_bytes()).len() >= MAX_PAID_PURCHASES {
            return refuse(format!(
                "this node already keeps {MAX_PAID_PURCHASES} paid orders, the most it keeps; \
                 this one verified but will not be kept"
            ));
        }
        if !store.set_secret(&key, &bytes) {
            return refuse("the node refused to save the paid order");
        }
    }
    list(store)
}

/// `ListPaidPurchases`: every held record that decodes and whose key suffix
/// matches its own order id, sorted by order id.
///
/// A key whose value does not decode, or whose suffix names a different order
/// than the one inside it, is skipped rather than answered: this module never
/// writes either shape, so it can only be damage, and handing it to the UI
/// would attach a complaint to the wrong order id or to none at all.
pub(crate) fn list<S: SecretStore>(store: &S) -> HarvestDelegateResponse {
    let mut purchases: Vec<PaidPurchase> = store
        .list_secrets(PAID_PURCHASE_PREFIX.as_bytes())
        .into_iter()
        .filter_map(|key| {
            let suffix = key.strip_prefix(PAID_PURCHASE_PREFIX.as_bytes())?;
            let hex = std::str::from_utf8(suffix).ok()?;
            let purchase = from_cbor::<PaidPurchase>(&store.get_secret(&key)?).ok()?;
            (hex == hex_lower(&purchase.order.order.id.0)).then_some(purchase)
        })
        .collect();
    purchases.sort_by(|a, b| a.order.order.id.0.cmp(&b.order.order.id.0));
    HarvestDelegateResponse::PaidPurchases { purchases }
}

/// Import a paid purchase from a predecessor delegate (harvest#123).
///
/// Held to the same validation as [`remember`]: a predecessor's export is not
/// trusted any further than a fresh request would be. Absent and under the
/// cap: written. Already held: `AlreadyAuthoritative`, never replaced, for
/// the same first-copy-wins reason as `remember`. At the cap: `Retryable`, not
/// `Permanent` -- the cap is a property of this node's other purchases, not of
/// this one, and it may have room again once the buyer's device catches up
/// with a later import order.
pub(crate) fn import<S: SecretStore>(store: &mut S, key: &[u8], value: &[u8]) -> SecretImport {
    let Ok(incoming) = from_cbor::<PaidPurchase>(value) else {
        return SecretImport::Permanent("the predecessor's paid order did not decode".into());
    };
    let (expected_key, bytes) = match validate(&incoming) {
        Ok(v) => v,
        Err(message) => return SecretImport::Permanent(message),
    };
    if expected_key != key {
        return SecretImport::Permanent(
            "the predecessor's key does not match this order's own id".into(),
        );
    }
    if store.has_secret(key) {
        return SecretImport::AlreadyAuthoritative;
    }
    if store.list_secrets(PAID_PURCHASE_PREFIX.as_bytes()).len() >= MAX_PAID_PURCHASES {
        return SecretImport::Retryable(format!(
            "this node already keeps {MAX_PAID_PURCHASES} paid orders, the most it keeps"
        ));
    }
    if store.set_secret(key, &bytes) {
        SecretImport::Written
    } else {
        SecretImport::Retryable("the node refused to save the paid order".into())
    }
}

/// A genuinely signed, genuinely paid order, built the way
/// `harvest_common::test_orders` builds one for the crate's own tests --
/// reproduced here because that module is `pub(crate)` to `harvest-common` and
/// `#[cfg(test)]`, so this crate cannot reach it. Every signature and proof
/// built here verifies for real, not merely looks right, or a refusal test
/// would pass for the wrong reason.
///
/// `pub(crate)` rather than private to `tests` below, so
/// `handlers::origin_gating_tests` can drive a genuine `RememberPaidPurchase`
/// through the real dispatcher without duplicating this fixture.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use chrono::DateTime;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::{
        spv::testing::payment_proof, BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim,
        ClaimBody, OutPoint, SignedClaim, SignedTipEntry, TipEntryBody,
    };
    use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof};

    pub(crate) fn store_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    pub(crate) fn other_store_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[99u8; 32])
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[22u8; 32])
    }

    fn harvest_requestor_bytes() -> [u8; 32] {
        bs58::decode(harvest_common::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .expect("HARVEST_WEBAPP_CONTRACT_ID decodes")
            .try_into()
            .expect("32 bytes")
    }

    /// Sign `data` as the ghostkey delegate's `ScopedPayload` would.
    fn sign_scoped<T: serde::Serialize>(key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
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

    /// Order `n`, naming a fresh buyer.
    ///
    /// `n` is `u16` rather than `u8` so that the cap tests (1024 orders, one
    /// past [`MAX_PAID_PURCHASES`]) get 1024 genuinely distinct order ids --
    /// `with_derived_id` hashes the whole struct, so any field that wraps
    /// back to a value already used silently collides two "different"
    /// orders into one id.
    pub(crate) fn order(n: u16) -> Order {
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: format!("buyer-{n}"),
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
            buyer_receipt_key: None,
            created_at: DateTime::from_timestamp(1_700_000_000 + i64::from(n), 0).expect("time"),
        }
        .with_derived_id()
    }

    /// A bridge-signed proof that `order` was paid. `seed` varies the mined
    /// block, so two seeds give two different, equally valid proofs for one
    /// order -- which is what the "first copy wins" tests rely on.
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

    /// `order` at `status`, terms signed by `seller`, with real payment
    /// evidence (varied by `seed`) when the status is `Paid`.
    pub(crate) fn authorized(
        seller: &SigningKey,
        order: Order,
        status: OrderStatus,
        seed: u8,
    ) -> AuthorizedOrder {
        let (scoped_payload, signature) = sign_scoped(seller, &order);
        let payment_proof = (status == OrderStatus::Paid).then(|| proof(&order, seed));
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

    pub(crate) fn paid_order(n: u16, seed: u8) -> AuthorizedOrder {
        authorized(&store_signing_key(), order(n), OrderStatus::Paid, seed)
    }

    pub(crate) fn purchase(n: u16, seed: u8) -> PaidPurchase {
        PaidPurchase {
            store_key: store_signing_key().verifying_key().to_bytes(),
            conversation: [(n & 0xff) as u8; 32],
            order: paid_order(n, seed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::secrets::MemSecrets;

    fn purchases(response: HarvestDelegateResponse) -> Vec<PaidPurchase> {
        match response {
            HarvestDelegateResponse::PaidPurchases { purchases } => purchases,
            other => panic!("expected the paid purchase list, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // remember / list
    // -----------------------------------------------------------------

    #[test]
    fn a_genuinely_paid_order_is_remembered_and_listed() {
        let mut secrets = MemSecrets::default();
        assert!(purchases(list(&secrets)).is_empty());
        let mine = purchase(1, 1);
        assert_eq!(purchases(remember(&mut secrets, mine.clone())), vec![mine]);
    }

    /// Mutated red by dropping the `status == Paid` check in `validate`.
    #[test]
    fn an_unpaid_order_is_refused() {
        let mut secrets = MemSecrets::default();
        let unpaid = PaidPurchase {
            store_key: store_signing_key().verifying_key().to_bytes(),
            conversation: [1; 32],
            order: authorized(
                &store_signing_key(),
                order(1),
                OrderStatus::AwaitingPayment,
                1,
            ),
        };
        assert!(matches!(
            remember(&mut secrets, unpaid),
            HarvestDelegateResponse::Error { .. }
        ));
        assert!(secrets.is_empty());
    }

    /// A `Paid` order whose proof was stripped fails `AuthorizedOrder::verify`
    /// itself (it demands evidence for `Paid`), which is exactly what this
    /// checks reaches. Mutated red by dropping the `.verify()` call in
    /// `validate`.
    #[test]
    fn a_paid_order_with_its_proof_removed_is_refused() {
        let mut secrets = MemSecrets::default();
        let mut stripped = paid_order(1, 1);
        stripped.payment_proof = None;
        let purchase = PaidPurchase {
            store_key: store_signing_key().verifying_key().to_bytes(),
            conversation: [1; 32],
            order: stripped,
        };
        assert!(matches!(
            remember(&mut secrets, purchase),
            HarvestDelegateResponse::Error { .. }
        ));
        assert!(secrets.is_empty());
    }

    /// An order signed by another store's key does not verify against the
    /// `store_key` the purchase names. Mutated red by dropping the
    /// `.verify()` call (or by trusting `store_key` without checking it
    /// against the signature).
    #[test]
    fn an_order_signed_by_another_store_is_refused() {
        let mut secrets = MemSecrets::default();
        let impostor = authorized(&other_store_signing_key(), order(1), OrderStatus::Paid, 1);
        let purchase = PaidPurchase {
            // Claims to be `store_signing_key`'s order, but the signature is
            // `other_store_signing_key`'s.
            store_key: store_signing_key().verifying_key().to_bytes(),
            conversation: [1; 32],
            order: impostor,
        };
        assert!(matches!(
            remember(&mut secrets, purchase),
            HarvestDelegateResponse::Error { .. }
        ));
        assert!(secrets.is_empty());
    }

    /// **First copy wins.** A second, equally valid piece of evidence for the
    /// same order id must not displace the first. Mutated red by writing on
    /// every `remember` rather than only when the key is absent.
    #[test]
    fn a_second_remember_of_the_same_order_keeps_the_first() {
        let mut secrets = MemSecrets::default();
        let first = purchase(1, 1);
        let second = purchase(1, 2);
        assert_ne!(
            first.order.payment_proof, second.order.payment_proof,
            "precondition: two distinct, equally valid proofs"
        );
        assert_eq!(
            purchases(remember(&mut secrets, first.clone())),
            vec![first.clone()]
        );
        assert_eq!(
            purchases(remember(&mut secrets, second)),
            vec![first],
            "the second, different evidence did not displace the first"
        );
    }

    /// Mutated red by removing the cap check.
    #[test]
    fn past_the_cap_a_new_order_is_refused() {
        let mut secrets = MemSecrets::default();
        for n in 0..MAX_PAID_PURCHASES {
            let n = n as u16;
            assert!(matches!(
                remember(&mut secrets, purchase(n, 1)),
                HarvestDelegateResponse::PaidPurchases { .. }
            ));
        }
        let refused = remember(&mut secrets, purchase(MAX_PAID_PURCHASES as u16, 1));
        assert!(matches!(refused, HarvestDelegateResponse::Error { .. }));
        assert_eq!(
            secrets.list_secrets(PAID_PURCHASE_PREFIX.as_bytes()).len(),
            MAX_PAID_PURCHASES
        );
    }

    /// A record filed under the wrong key -- damage this module never
    /// writes -- is skipped by `list` rather than answered under a link that
    /// names the wrong order. Mutated red by dropping the suffix check.
    #[test]
    fn list_skips_a_record_under_the_wrong_key() {
        let mut secrets = MemSecrets::default();
        let mine = purchase(1, 1);
        let bytes = to_cbor(&mine).unwrap();
        // Filed under order 2's key while holding order 1's evidence.
        let wrong_key = paid_purchase_key(&paid_order(2, 1).order.id.0);
        secrets.set_secret(&wrong_key, &bytes);
        assert!(purchases(list(&secrets)).is_empty());
    }

    // -----------------------------------------------------------------
    // import
    // -----------------------------------------------------------------

    #[test]
    fn import_follows_the_same_validation_as_remember() {
        let mut secrets = MemSecrets::default();
        let mine = purchase(1, 1);
        let key = paid_purchase_key(&mine.order.order.id.0);
        assert_eq!(
            import(&mut secrets, &key, &to_cbor(&mine).unwrap()),
            SecretImport::Written
        );
        assert_eq!(purchases(list(&secrets)), vec![mine.clone()]);

        // Already held: not replaced.
        let other_evidence = purchase(1, 2);
        assert_eq!(
            import(&mut secrets, &key, &to_cbor(&other_evidence).unwrap()),
            SecretImport::AlreadyAuthoritative
        );
        assert_eq!(purchases(list(&secrets)), vec![mine]);

        // Invalid evidence is refused, not merely skipped. The key is derived
        // from the STRIPPED order's own id (not a literal), so this exercises
        // `validate`'s `.verify()` failure rather than the key-mismatch
        // check below it.
        let mut stripped = paid_order(3, 1);
        stripped.payment_proof = None;
        let invalid_key = paid_purchase_key(&stripped.order.id.0);
        let invalid = PaidPurchase {
            store_key: store_signing_key().verifying_key().to_bytes(),
            conversation: [3; 32],
            order: stripped,
        };
        assert!(matches!(
            import(&mut secrets, &invalid_key, &to_cbor(&invalid).unwrap()),
            SecretImport::Permanent(_)
        ));
    }

    #[test]
    fn import_respects_the_cap() {
        let mut secrets = MemSecrets::default();
        for n in 0..MAX_PAID_PURCHASES {
            let n = n as u16;
            secrets.set_secret(
                &paid_purchase_key(&paid_order(n, 1).order.id.0),
                &to_cbor(&purchase(n, 1)).unwrap(),
            );
        }
        let overflow = purchase(MAX_PAID_PURCHASES as u16, 1);
        let key = paid_purchase_key(&overflow.order.order.id.0);
        assert!(matches!(
            import(&mut secrets, &key, &to_cbor(&overflow).unwrap()),
            SecretImport::Retryable(_)
        ));
    }

    /// A store with no way to remove anything: the structural half of "held
    /// but not deletable" -- see the module docs.
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
        let mut secrets = NoRemoval(MemSecrets::default());
        for n in 0u16..10 {
            remember(&mut secrets, purchase(n, 1));
            list(&secrets);
        }
        assert_eq!(
            secrets.list_secrets(PAID_PURCHASE_PREFIX.as_bytes()).len(),
            10
        );
    }

    #[test]
    fn a_refused_write_is_reported() {
        let mut secrets = MemSecrets::refusing_writes();
        assert!(matches!(
            remember(&mut secrets, purchase(1, 1)),
            HarvestDelegateResponse::Error { .. }
        ));
    }
}
