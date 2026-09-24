#![allow(unexpected_cfgs)]

use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::*;

use harvest_common::store::{
    StoreParameters, StoreStateV1, StoreStateV1Delta, StoreStateV1Summary,
};

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(ValidateResult::Valid);
        }

        let store_state = from_reader::<StoreStateV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        if !harvest_common::is_canonical_cbor(&store_state, bytes) {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: "State verification failed: state is not in canonical CBOR encoding \
                         (trailing bytes, an unknown key, or a non-minimal encoding)"
                    .into(),
            });
        }

        let parameters = from_reader::<StoreParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        // The embedded `OrderPaymentProof` on each order is the sole
        // authority on whether it is genuinely paid -- see
        // `harvest_common::payment`'s module docs for why. `verify` below
        // re-checks that proof (among everything else).
        //
        // Validity is a pure function of this state and these parameters.
        // Nothing here asks for related contracts: another contract's state
        // replicates on its own schedule, so letting it affect the verdict
        // would let two peers holding identical bytes disagree. An earlier
        // version fetched each paid order's Bitcoin address contract anyway,
        // purely to log a line when it held no claims; every peer paid up to
        // ten fetches per validation for that, and it was removed.
        if let Err(e) = store_state.verify(&store_state, &parameters) {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: format!("State verification failed: {e}"),
            });
        }

        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let parameters = from_reader::<StoreParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        // Zero bytes in and nothing but zero bytes merged in is zero bytes
        // out, not the encoded default: the two are one state, and answering
        // one with the other made `merge(A, A) != A` for the empty state
        // (`fdev verify-merge`, harvest#55). Anything non-empty arriving
        // switches this off, so merging an encoded default in is still that
        // encoding, whichever side it is on.
        let mut nothing_here = state.as_ref().is_empty();
        let mut store_state = if state.as_ref().is_empty() {
            StoreStateV1::default()
        } else {
            from_reader::<StoreStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    // Zero bytes means "there is no state here", the
                    // convention every other entry point uses (harvest#55).
                    // Decoding it failed, so a peer handed the valid empty
                    // state to merge answered with a decode error.
                    if new_state.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let new_state = from_reader::<StoreStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    store_state
                        .merge(&store_state.clone(), &parameters, &new_state)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let delta = from_reader::<StoreStateV1Delta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    store_state
                        .apply_delta(&store_state.clone(), &parameters, &Some(delta))
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                }
                _ => {
                    return Err(ContractError::InvalidUpdate);
                }
            }
        }

        // The scaffold skips a child's `apply_delta` when a merge brings it
        // nothing, so a stored state that is not canonical would otherwise be
        // written back as it came (harvest#26).
        store_state.listings.normalize();

        if nothing_here {
            return Ok(UpdateModification::valid(State::from(vec![])));
        }

        let mut updated_state = vec![];
        into_writer(&store_state, &mut updated_state)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        Ok(UpdateModification::valid(updated_state.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let parameters = from_reader::<StoreParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let store_state = from_reader::<StoreStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let summary = store_state.summarize(&store_state, &parameters);
        let mut summary_bytes = vec![];
        into_writer(&summary, &mut summary_bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(summary_bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let parameters = from_reader::<StoreParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // Zero bytes on either side means "there is no state here yet", not a
        // malformed encoding (harvest#55). `summarize_state` answers an empty
        // state with a zero-byte summary, which no `StoreStateV1Summary`
        // encodes to, so decoding either one used to fail and a new
        // subscriber's first exchange was answered with an error. The mailbox
        // contract already guards both; this is the same pattern.
        //
        // A holder with nothing has nothing to send.
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }
        let store_state = from_reader::<StoreStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // A requester with nothing knows nothing: the empty summary is the
        // summary of the empty state, so the delta is everything held.
        let old_summary = if summary.as_ref().is_empty() {
            let empty = StoreStateV1::default();
            empty.summarize(&empty, &parameters)
        } else {
            from_reader::<StoreStateV1Summary, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        match store_state.delta(&store_state, &parameters, &old_summary) {
            Some(delta) => {
                let mut delta_bytes = vec![];
                into_writer(&delta, &mut delta_bytes)
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(delta_bytes))
            }
            None => Ok(StateDelta::from(vec![])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::spv::testing::payment_proof;
    use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash, Claim, OutPoint};
    use harvest_common::payment::{
        AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus,
    };
    use harvest_common::store::OrdersV1;

    fn seller_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[22u8; 32])
    }

    fn harvest_requestor_bytes() -> [u8; 32] {
        let v = bs58::decode(harvest_common::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn sign_scoped<T: serde::Serialize>(signing_key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }

        let payload = harvest_common::to_cbor(data).unwrap();
        let scoped = TestScopedPayload {
            requestor: TestRequestor::WebApp(harvest_requestor_bytes()),
            payload,
        };
        let scoped_bytes = harvest_common::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes).to_bytes().to_vec();
        (scoped_bytes, signature)
    }

    fn make_order(script: &[u8], code_hash: Option<[u8; 32]>) -> Order {
        // One block before `make_paid_order` confirms its payment (100), so
        // the payment reads as made after the order, as an honest one is.
        make_order_anchored_at(script, code_hash, 99)
    }

    fn make_order_anchored_at(
        script: &[u8],
        code_hash: Option<[u8; 32]>,
        anchor_height: u32,
    ) -> Order {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        Order {
            request_id: None,
            id: OrderId([0u8; 32]),
            buyer_fingerprint: "buyer-fp".into(),
            seller_fingerprint: "seller-fp".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: script.to_vec(),
            payment_hash: None,
            payment_address: "tb1qtest".into(),
            required_confirmations: 1,
            trusted_bridges: vec![freenet_bitcoin_common::BridgeId(
                bridge_key().verifying_key().to_bytes(),
            )],
            bitcoin_address_code_hash: code_hash,
            anchor: Some(BlockAnchor {
                height: anchor_height,
                hash: BlockHash([0x42; 32]),
            }),
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            created_at: ts,
        }
        .with_derived_id()
    }

    fn make_paid_order(seller: &SigningKey, bridge: &SigningKey, order: Order) -> AuthorizedOrder {
        let addr_params = order.bitcoin_params();
        let (spv, txid, block_hash) = payment_proof(
            &order.payment_script_pubkey,
            order.amount_sats,
            1,
            [7u8; 32],
        );
        let claim_body = freenet_bitcoin_common::ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height: 100,
                hash: block_hash,
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
        };
        let claim = freenet_bitcoin_common::SignedClaim::sign(bridge, &claim_body).unwrap();
        let tip_body = freenet_bitcoin_common::TipEntryBody {
            network: order.network,
            anchor: BlockAnchor {
                height: 100,
                hash: BlockHash([9u8; 32]),
            },
            prev_hash: BlockHash([8u8; 32]),
            block_time: 1_700_000_000,
            tx_count: 1,
            median_time: 1_700_000_000,
        };
        let tip = freenet_bitcoin_common::SignedTipEntry::sign(bridge, &tip_body).unwrap();
        let proof = OrderPaymentProof::on_chain(vec![claim], tip);

        let (scoped_payload, signature) = sign_scoped(seller, &order);
        AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::Paid,
            payment_proof: Some(proof),
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// A `StoreStateV1` holding exactly one genuinely-Paid order, encoded as
    /// the raw bytes `validate_state` receives.
    fn paid_store_state_bytes(
        seller: &SigningKey,
        bridge: &SigningKey,
        order: Order,
    ) -> (Vec<u8>, OrderId) {
        let id = order.id.clone();
        let record = make_paid_order(seller, bridge, order);
        let state = StoreStateV1 {
            owner: Some(seller.verifying_key()),
            orders: OrdersV1 {
                orders: std::collections::BTreeMap::from([(id.clone(), record)]),
            },
            ..Default::default()
        };
        let mut bytes = vec![];
        into_writer(&state, &mut bytes).unwrap();
        (bytes, id)
    }

    fn params_bytes(seller: &SigningKey) -> Vec<u8> {
        let params = StoreParameters::new(seller.verifying_key());
        let mut bytes = vec![];
        into_writer(&params, &mut bytes).unwrap();
        bytes
    }

    /// A paid order validates on its embedded proof alone, whether or not it
    /// names the build of its Bitcoin address contract. The contract never
    /// asks for related contracts: it used to fetch the address contract of
    /// each paid order purely for a log line, and that fetch is gone.
    #[test]
    fn a_paid_order_validates_without_asking_for_related_contracts() {
        let seller = seller_key();
        let bridge = bridge_key();
        for code_hash in [None, Some([42u8; 32])] {
            let order = make_order(&[0x00, 0x14, 0xaa, 0xbb], code_hash);
            let (state_bytes, _id) = paid_store_state_bytes(&seller, &bridge, order);
            let params = params_bytes(&seller);

            let result = Contract::validate_state(
                Parameters::from(params),
                State::from(state_bytes),
                RelatedContracts::new(),
            )
            .unwrap();
            assert_eq!(
                result,
                ValidateResult::Valid,
                "a paid order must validate on its own embedded proof, with no \
                 related-contract request (code hash {code_hash:?})"
            );
        }
    }

    /// harvest#77, at the layer that decides. A store state holding an order
    /// marked `Paid` by a payment that confirmed (block 100) before the order
    /// was signed (anchored at block 150) is refused by the contract itself,
    /// so no peer running it accepts the settlement whatever the UI does.
    #[test]
    fn refuses_an_order_settled_by_a_payment_older_than_the_order() {
        let seller = seller_key();
        let bridge = bridge_key();
        let order = make_order_anchored_at(&[0x00, 0x14, 0xaa, 0xbb], None, 150);
        let (state_bytes, _id) = paid_store_state_bytes(&seller, &bridge, order);
        let params = params_bytes(&seller);

        let result = Contract::validate_state(
            Parameters::from(params),
            State::from(state_bytes),
            RelatedContracts::new(),
        );
        match result {
            Err(ContractError::InvalidUpdateWithInfo { reason }) => assert!(
                reason.contains("at or before block 150"),
                "the refusal should say the payment predates the order: {reason}"
            ),
            other => panic!("a pre-order payment must not settle the order, got {other:?}"),
        }
    }

    /// A store state with details in it. Unsigned: `get_state_delta` only
    /// reads, so nothing here needs the signature to verify.
    fn state_with_details() -> State<'static> {
        let mut state = StoreStateV1 {
            owner: Some(seller_key().verifying_key()),
            ..Default::default()
        };
        state.info.info.version = 3;
        state.info.info.store_name = "Shop".to_string();
        let mut bytes = vec![];
        into_writer(&state, &mut bytes).expect("encode state");
        State::from(bytes)
    }

    /// **A new subscriber's first exchange gets the state, not a decode
    /// error (harvest#55).**
    ///
    /// The subscriber has no state, so `summarize_state` gives it a zero-byte
    /// summary, which no `StoreStateV1Summary` encodes to. The empty summary
    /// means "knows nothing", so the answer is everything held.
    #[test]
    fn an_empty_summary_is_answered_with_everything_held() {
        let params = params_bytes(&seller_key());
        let empty_summary =
            Contract::summarize_state(Parameters::from(params.clone()), State::from(vec![]))
                .expect("summarize the absent state");
        assert!(
            empty_summary.as_ref().is_empty(),
            "precondition: the absent state's summary is zero bytes"
        );

        let delta = Contract::get_state_delta(
            Parameters::from(params),
            state_with_details(),
            empty_summary,
        )
        .expect("an empty summary must not be a decode error");
        let delta: StoreStateV1Delta = from_reader(delta.as_ref()).expect("decode delta");
        assert_eq!(
            delta.info.map(|i| i.info.store_name),
            Some("Shop".to_string()),
            "a requester that holds nothing is sent the store's details"
        );
    }

    /// The mirror image: a holder with no state of its own answers with an
    /// empty delta rather than failing to decode its own zero bytes.
    #[test]
    fn an_empty_state_answers_with_an_empty_delta() {
        let params = params_bytes(&seller_key());
        let some_summary =
            Contract::summarize_state(Parameters::from(params.clone()), state_with_details())
                .expect("summarize");
        for summary in [some_summary, StateSummary::from(vec![])] {
            let delta = Contract::get_state_delta(
                Parameters::from(params.clone()),
                State::from(vec![]),
                summary,
            )
            .expect("an empty state must not be a decode error");
            assert!(delta.as_ref().is_empty(), "nothing held, nothing to send");
        }
    }

    /// **`update_state` writes canonical listings even when the merge brings
    /// nothing (harvest#26).** The scaffold skips `ListingsV1::apply_delta`
    /// then, so without the explicit normalise a stored unsorted state would be
    /// written back unsorted, and the contract's own `verify` now refuses that.
    #[test]
    fn update_state_writes_canonical_listings_when_the_merge_brings_nothing() {
        use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};

        let seller = seller_key();
        let make = |title: &str| {
            let listing = Listing {
                checkout: None,
                choices: Vec::new(),
                id: ListingId([0u8; 32]),
                title: title.to_string(),
                description: String::new(),
                kind: ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }
            .with_derived_id();
            AuthorizedListing {
                listing,
                scoped_payload: Vec::new(),
                signature: Vec::new(),
                certificate_pem: String::new(),
            }
        };
        let mut listings = vec![make("Alpha"), make("Beta")];
        listings.sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        listings.reverse();

        let mut unsorted = StoreStateV1::default();
        unsorted.listings.listings = listings;
        let mut bytes = vec![];
        into_writer(&unsorted, &mut bytes).expect("encode");

        // Merging the empty state brings nothing, so nothing is verified and
        // the unsigned fixture is enough.
        let mut empty = vec![];
        into_writer(&StoreStateV1::default(), &mut empty).expect("encode");
        let out = Contract::update_state(
            Parameters::from(params_bytes(&seller)),
            State::from(bytes),
            vec![UpdateData::State(State::from(empty))],
        )
        .expect("update");
        let out: StoreStateV1 =
            from_reader(out.unwrap_valid().as_ref()).expect("decode the result");
        let ids: Vec<_> = out
            .listings
            .listings
            .iter()
            .map(|l| l.listing.id.clone())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "the written state must be sorted by id");
    }

    /// **Merging a zero-byte state is a no-op, not a decode error
    /// (harvest#55).** Zero bytes is a valid state (`validate_state` says
    /// so), so a peer can be handed one to merge; the `State` arm decoded it
    /// unconditionally and failed. The mailbox contract already guarded this.
    #[test]
    fn merging_a_zero_byte_state_changes_nothing() {
        let held = state_with_details();
        let out = Contract::update_state(
            Parameters::from(params_bytes(&seller_key())),
            held.clone(),
            vec![UpdateData::State(State::from(vec![]))],
        )
        .expect("a zero-byte state must merge");
        assert_eq!(out.unwrap_valid().as_ref(), held.as_ref());
    }
    /// **The empty state merged with itself is the empty state** (harvest#55,
    /// found by `fdev verify-merge`). `update_state` answered zero bytes with
    /// the encoded default, so `merge(A, A) != A` for the empty state. And an
    /// encoded default merged in from either side stays that encoding, so
    /// the rule does not break commutativity instead.
    #[test]
    fn the_empty_state_is_idempotent_and_the_rule_is_commutative() {
        let merge = |state: Vec<u8>, other: Vec<u8>| -> Vec<u8> {
            Contract::update_state(
                Parameters::from(params_bytes(&seller_key())),
                State::from(state),
                vec![UpdateData::State(State::from(other))],
            )
            .expect("merge")
            .unwrap_valid()
            .as_ref()
            .to_vec()
        };
        assert!(
            merge(vec![], vec![]).is_empty(),
            "merge(empty, empty) must be empty"
        );
        let mut default = vec![];
        into_writer(&StoreStateV1::default(), &mut default).expect("encode");
        assert_eq!(merge(vec![], default.clone()), default);
        assert_eq!(merge(default.clone(), vec![]), default);
    }

    /// A non-empty delta applied to the empty state is an update, so the
    /// result is the encoded state, not zero bytes. Without this the
    /// empty-state rule above would swallow a delta's content.
    #[test]
    fn a_delta_applied_to_the_empty_state_is_encoded() {
        let mut delta = vec![];
        into_writer(
            &StoreStateV1Delta {
                owner: None,
                info: None,
                listings: None,
                orders: None,
                ..Default::default()
            },
            &mut delta,
        )
        .expect("encode");
        let out = Contract::update_state(
            Parameters::from(params_bytes(&seller_key())),
            State::from(vec![]),
            vec![UpdateData::Delta(StateDelta::from(delta))],
        )
        .expect("update")
        .unwrap_valid()
        .as_ref()
        .to_vec();
        let mut default = vec![];
        into_writer(&StoreStateV1::default(), &mut default).expect("encode");
        assert_eq!(out, default);
    }

    /// **`validate_state` refuses a state that is not byte-canonical (PR
    /// #82 review, Should Fix 2).** Each of these decoded to a valid state
    /// and was accepted, then rewritten by the next merge, while its summary
    /// matched a canonical peer's so no delta ever repaired it.
    #[test]
    fn validate_state_refuses_non_canonical_bytes() {
        let validate = |bytes: Vec<u8>| {
            Contract::validate_state(
                Parameters::from(params_bytes(&seller_key())),
                State::from(bytes),
                RelatedContracts::new(),
            )
        };
        let mut canonical = vec![];
        into_writer(&StoreStateV1::default(), &mut canonical).expect("encode");
        assert!(
            matches!(validate(canonical.clone()), Ok(ValidateResult::Valid)),
            "the canonical encoding validates"
        );

        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert!(
            validate(trailing).is_err(),
            "a trailing byte must be refused"
        );

        #[derive(serde::Serialize)]
        struct WithExtraKey<T> {
            #[serde(flatten)]
            state: T,
            unknown: u8,
        }
        let mut extra = vec![];
        into_writer(
            &WithExtraKey {
                state: StoreStateV1::default(),
                unknown: 1,
            },
            &mut extra,
        )
        .expect("encode");
        assert!(validate(extra).is_err(), "an unknown key must be refused");
    }

    // --- harvest#52: the owner, through the contract's own entry points ---

    /// Two signing keys whose verifying keys share a two-character code, the
    /// lower-ranked first. `harvest-common`'s `claim_tests` explain why two
    /// characters stand in for sixteen; the contract accepts a code of any
    /// length, which is what makes this reachable at all.
    fn two_keys_sharing_a_code() -> (SigningKey, SigningKey, String) {
        let mut seen: HashMap<String, SigningKey> = HashMap::new();
        for i in 0u32..100_000 {
            let mut seed = [0x5au8; 32];
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
        panic!("no two keys shared a two-character code");
    }

    /// Parameters for an arbitrary code, encoded the way the struct encodes.
    fn code_params_bytes(code: &str) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Params<'a> {
            store_code: &'a str,
        }
        let mut bytes = vec![];
        into_writer(&Params { store_code: code }, &mut bytes).unwrap();
        bytes
    }

    fn owned_store_bytes(owner: &SigningKey, titles: &[&str]) -> Vec<u8> {
        use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};
        let mut state = StoreStateV1 {
            owner: Some(owner.verifying_key()),
            ..Default::default()
        };
        for title in titles {
            let listing = Listing {
                checkout: None,
                choices: Vec::new(),
                id: ListingId([0u8; 32]),
                title: title.to_string(),
                description: String::new(),
                kind: ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }
            .with_derived_id();
            let (scoped_payload, signature) = sign_scoped(owner, &listing);
            state.listings.listings.push(AuthorizedListing {
                listing,
                scoped_payload,
                signature,
                certificate_pem: String::new(),
            });
        }
        state.listings.normalize();
        let mut bytes = vec![];
        into_writer(&state, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn the_parameters_are_the_code_and_it_matches_the_struct_encoding() {
        let seller = seller_key();
        let code = harvest_common::store::store_code(&seller.verifying_key());
        assert_eq!(code.len(), harvest_common::store::STORE_CODE_LEN);
        assert_eq!(params_bytes(&seller), code_params_bytes(&code));
    }

    #[test]
    fn validate_state_refuses_an_owner_the_code_does_not_admit() {
        let seller = seller_key();
        let other = bridge_key();
        let validate = |params: Vec<u8>, state: Vec<u8>| {
            Contract::validate_state(
                Parameters::from(params),
                State::from(state),
                RelatedContracts::new(),
            )
        };
        assert!(matches!(
            validate(params_bytes(&seller), owned_store_bytes(&seller, &["Mine"])),
            Ok(ValidateResult::Valid)
        ));
        assert!(
            validate(
                params_bytes(&seller),
                owned_store_bytes(&other, &["Theirs"])
            )
            .is_err(),
            "a store at the seller's code owned by another key"
        );
        assert!(
            validate(params_bytes(&seller), owned_store_bytes(&seller, &[])).is_err(),
            "an owner with nothing it signed"
        );
    }

    /// The contract's `update_state` resolves two owners of one code the same
    /// way whichever state it holds, for whole states and for deltas.
    #[test]
    fn update_state_keeps_the_smaller_key_whichever_state_it_holds() {
        let (low, high, code) = two_keys_sharing_a_code();
        let params = code_params_bytes(&code);
        let a = owned_store_bytes(&low, &["Low"]);
        let b = owned_store_bytes(&high, &["High", "Two"]);
        let merge = |held: &[u8], incoming: &[u8]| -> Vec<u8> {
            Contract::update_state(
                Parameters::from(params.clone()),
                State::from(held.to_vec()),
                vec![UpdateData::State(State::from(incoming.to_vec()))],
            )
            .expect("merge")
            .unwrap_valid()
            .as_ref()
            .to_vec()
        };
        assert_eq!(merge(&a, &b), a);
        assert_eq!(merge(&b, &a), a);

        // And through a delta, which is how a client publishes: the held
        // lower owner ignores the higher one's update, without an error.
        let summary =
            Contract::summarize_state(Parameters::from(params.clone()), State::from(a.clone()))
                .unwrap();
        let delta = Contract::get_state_delta(
            Parameters::from(params.clone()),
            State::from(b.clone()),
            summary,
        )
        .unwrap();
        assert!(
            delta.as_ref().is_empty(),
            "the outranked store has nothing to send"
        );
        let mut higher_update = vec![];
        let decoded: StoreStateV1 = from_reader(b.as_slice()).unwrap();
        into_writer(
            &StoreStateV1Delta {
                owner: decoded.owner,
                listings: Some(decoded.listings.listings),
                ..Default::default()
            },
            &mut higher_update,
        )
        .unwrap();
        let out = Contract::update_state(
            Parameters::from(params),
            State::from(a.clone()),
            vec![UpdateData::Delta(StateDelta::from(higher_update))],
        )
        .expect("an outranked update is not an error")
        .unwrap_valid()
        .as_ref()
        .to_vec();
        assert_eq!(out, a);
    }
}
