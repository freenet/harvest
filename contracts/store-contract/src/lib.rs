#![allow(unexpected_cfgs)]

use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::*;

use freenet_bitcoin_common::BitcoinAddressStateV1;
use harvest_common::payment::OrderStatus;
use harvest_common::store::{
    StoreParameters, StoreStateV1, StoreStateV1Delta, StoreStateV1Summary,
};

/// How many related `BitcoinAddressContract` instances one `validate_state`
/// call will ask Freenet to fetch.
///
/// Freenet's related-contract protocol gives a contract exactly one round
/// trip per validation: returning `RequestRelated` again once the peer has
/// already resolved a prior request is an error, not a second chance to ask
/// for more. So every instance this call might ever want has to be named in
/// the single `RequestRelated` response, which is what this bounds -- a
/// store with more than 10 currently-Paid/PaymentReversed orders referencing
/// distinct scripts simply forfeits the cross-check for the rest.
const MAX_RELATED_CONTRACTS_PER_REQUEST: usize = 10;

/// Compute the `ContractInstanceId` a `BitcoinAddressContract` instance with
/// these parameters would have, without holding that contract's WASM.
///
/// `ContractInstanceId` is `BLAKE3(BLAKE3(wasm) || params_bytes)`
/// (`freenet_stdlib::ContractInstanceId::from_params_and_code`, via that
/// crate's private `generate_id`). That constructor needs the actual WASM
/// bytes so it can call `.hash()` on them -- it has no entry point that
/// accepts a hash directly -- but the store contract never holds the
/// Bitcoin contract's WASM; it only knows its hash, supplied out-of-band as
/// `Order::bitcoin_address_code_hash`. So this replicates the same two-hash
/// construction by hand instead of going through `ContractCode`.
///
/// This assumes the real `BitcoinAddressContract` was published with its
/// `BitcoinAddressParameters` encoded via `ciborium` (as
/// `bitcoin-address-contract`'s own `decode_params` expects) -- the hash is
/// over the exact on-wire parameter bytes, not a semantic re-encoding, so a
/// different encoder would silently compute the wrong id.
///
/// It used to have to assume something further and shakier: that the bridge
/// list's ORDER matched whatever the address contract was actually deployed
/// with, since the list came from the *store's* frozen parameters and had no
/// necessary relationship to any particular order. Now that both the bridge
/// list and the code hash travel in the order itself
/// (`harvest_common::payment::Order`), the seller states them per invoice and
/// signs them, so the address contract this names is the one the seller meant
/// for this payment. A mismatch costs the cross-check for that order and
/// nothing more -- see `validate_state` on why it is additive-only.
/// The address contract an order names, as a `ContractInstanceId`.
///
/// A thin wrapper over `Order::bitcoin_address_instance_id`, which is where
/// the derivation lives. It used to be a second hand-written copy of
/// `BLAKE3(code_hash || cbor(parameters))` here -- the shape ranked first in
/// `docs/untested-invariants.md`, where a duplicated contract-address
/// derivation drifted and made every derived id name a contract that had
/// never been published, silently.
fn bitcoin_address_instance_id(
    order: &harvest_common::payment::Order,
) -> Option<ContractInstanceId> {
    order
        .bitcoin_address_instance_id()
        .map(ContractInstanceId::new)
}

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(ValidateResult::Valid);
        }

        let store_state = from_reader::<StoreStateV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let parameters = from_reader::<StoreParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        // The embedded `OrderPaymentProof` on each order is the sole
        // authority on whether it is genuinely paid -- see
        // `harvest_common::payment`'s module docs for why. `verify` below
        // re-checks that proof (among everything else) independent of
        // anything past this point.
        if let Err(e) = store_state.verify(&store_state, &parameters) {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: format!("State verification failed: {e}"),
            });
        }

        // ---------------------------------------------------------------
        // Related-contract cross-check against each Paid/PaymentReversed
        // order's `BitcoinAddressContract`.
        //
        // THIS IS ADDITIVE ONLY. It can add corroborating information; it
        // can NEVER make otherwise-valid state invalid, and every branch
        // below is written so that no path through this section returns
        // `Invalid`. That is deliberate and it is the single most important
        // architectural fact in this file:
        //
        // A contract's verdict has to be a pure function of its own state
        // and parameters, or replicas that evaluate it at different moments
        // reach different answers and never converge. Related state is NOT
        // under this contract's control -- it is a separate contract,
        // replicated on its own schedule -- so a peer whose copy of it has
        // not caught up yet (or hasn't fetched it at all, or is running
        // with `bitcoin_address_code_hash: None` and therefore can't even
        // compute which contract to ask for) would, if this cross-check
        // were allowed to reject, judge a perfectly good order invalid
        // purely because of replication timing. Two peers holding
        // byte-identical `StoreStateV1` could then disagree about its
        // validity, which is precisely the divergence a Freenet contract
        // must never produce. The embedded proof is what makes validity
        // self-contained; the related-contract lookup below exists only to
        // fetch corroborating evidence for operators (surfaced via a log
        // line), never to gate it.
        // ---------------------------------------------------------------
        let mut wanted_ids: Vec<ContractInstanceId> = Vec::new();
        for record in store_state.orders.orders.values() {
            if !matches!(
                record.status,
                OrderStatus::Paid | OrderStatus::PaymentReversed
            ) {
                continue;
            }
            // `None` means the order names no code hash, so there is nothing
            // to compute a related instance id with -- skip that order's
            // cross-check rather than guessing at one. See the field's doc
            // comment on `Order`.
            let Some(instance_id) = bitcoin_address_instance_id(&record.order) else {
                continue;
            };
            if !wanted_ids.contains(&instance_id) {
                wanted_ids.push(instance_id);
            }
            if wanted_ids.len() >= MAX_RELATED_CONTRACTS_PER_REQUEST {
                break;
            }
        }

        // An id already present as a key in `related` -- whether its state
        // came back `Some` or `None` -- means Freenet already resolved a
        // prior request for it; asking again would be the disallowed
        // second round. Only an id that has NEVER been requested belongs in
        // this call's (one and only) `RequestRelated`.
        let already_requested: Vec<ContractInstanceId> =
            related.states().map(|(id, _)| *id).collect();
        let not_yet_requested: Vec<ContractInstanceId> = wanted_ids
            .iter()
            .filter(|id| !already_requested.contains(id))
            .cloned()
            .collect();

        if !not_yet_requested.is_empty() {
            return Ok(ValidateResult::RequestRelated(not_yet_requested));
        }

        // Every id we wanted has already been asked for (or we wanted none
        // at all). Cross-check whatever came back purely for diagnostics --
        // see the section header above for why this never affects the
        // verdict.
        for record in store_state.orders.orders.values() {
            if !matches!(
                record.status,
                OrderStatus::Paid | OrderStatus::PaymentReversed
            ) {
                continue;
            }
            let Some(instance_id) = bitcoin_address_instance_id(&record.order) else {
                continue;
            };
            let Some((_, Some(related_bytes))) =
                related.states().find(|(id, _)| **id == instance_id)
            else {
                // Not fetched (beyond the cap above) or fetched and empty --
                // nothing to cross-check against, and that is not evidence
                // of anything either way.
                continue;
            };
            let Ok(address_state) =
                from_reader::<BitcoinAddressStateV1, &[u8]>(related_bytes.as_ref())
            else {
                continue;
            };
            if address_state.claims.claims.is_empty() && address_state.claims.scanned.is_empty() {
                freenet_stdlib::log::info(&format!(
                    "store-contract: order {} is {:?} but its referenced Bitcoin address \
                     contract holds no claims at all (informational only -- the order's own \
                     embedded proof remains authoritative)",
                    record.order.id, record.status
                ));
            }
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

    #[test]
    fn skips_related_request_when_code_hash_absent() {
        let seller = seller_key();
        let bridge = bridge_key();
        let order = make_order(&[0x00, 0x14, 0xaa, 0xbb], None);
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
            "with no code hash configured, validate_state must skip the related-contract \
             request entirely and still accept the (embedded-proof-verified) order"
        );
    }

    #[test]
    fn requests_related_contract_for_a_paid_order_when_code_hash_known() {
        let seller = seller_key();
        let bridge = bridge_key();
        let code_hash = [42u8; 32];
        let order = make_order(&[0x00, 0x14, 0xaa, 0xbb], Some(code_hash));
        let expected_id = bitcoin_address_instance_id(&order).expect("the order names a build");

        let (state_bytes, _id) = paid_store_state_bytes(&seller, &bridge, order);
        let params = params_bytes(&seller);

        let result = Contract::validate_state(
            Parameters::from(params),
            State::from(state_bytes),
            RelatedContracts::new(),
        )
        .unwrap();
        match result {
            ValidateResult::RequestRelated(ids) => {
                assert_eq!(ids, vec![expected_id]);
            }
            other => panic!("expected RequestRelated, got {other:?}"),
        }
    }

    #[test]
    fn validates_once_related_state_resolves_even_if_it_came_back_empty() {
        let seller = seller_key();
        let bridge = bridge_key();
        let code_hash = [42u8; 32];
        let order = make_order(&[0x00, 0x14, 0xaa, 0xbb], Some(code_hash));
        let expected_id = bitcoin_address_instance_id(&order).expect("the order names a build");

        let (state_bytes, _id) = paid_store_state_bytes(&seller, &bridge, order);
        let params = params_bytes(&seller);

        // Simulate Freenet's second invocation: the id we would have asked
        // for is already a key in `related`, with no state behind it (the
        // related contract was not found, or simply hasn't been created
        // yet). This must NOT trigger a second `RequestRelated` -- that
        // would be the disallowed second round -- and it must NOT make the
        // order invalid: the embedded proof remains authoritative.
        let mut map: HashMap<ContractInstanceId, Option<State<'static>>> = HashMap::new();
        map.insert(expected_id, None);
        let related = RelatedContracts::from(map);

        let result =
            Contract::validate_state(Parameters::from(params), State::from(state_bytes), related)
                .unwrap();
        assert_eq!(
            result,
            ValidateResult::Valid,
            "an order whose related contract came back empty must still validate, on the \
             strength of its own embedded proof"
        );
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
        let mut state = StoreStateV1::default();
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
                info: None,
                listings: None,
                orders: None,
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
}
