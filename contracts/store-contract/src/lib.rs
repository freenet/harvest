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

        let mut store_state = if state.as_ref().is_empty() {
            StoreStateV1::default()
        } else {
            from_reader::<StoreStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
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
        let store_state = from_reader::<StoreStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let old_summary = from_reader::<StoreStateV1Summary, &[u8]>(summary.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

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
            anchor: None,
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
}
