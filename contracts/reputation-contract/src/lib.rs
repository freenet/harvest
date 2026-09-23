#![allow(unexpected_cfgs)]

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use harvest_common::reputation::{
    ReputationDelta, ReputationParameters, ReputationStateV1, ReputationSummary,
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

        let reputation_state = from_reader::<ReputationStateV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        if !harvest_common::is_canonical_cbor(&reputation_state, bytes) {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: "State verification failed: state is not in canonical CBOR encoding \
                         (trailing bytes, an unknown key, or a non-minimal encoding)"
                    .into(),
            });
        }

        let parameters = from_reader::<ReputationParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        reputation_state
            .verify(&parameters)
            .map(|_| ValidateResult::Valid)
            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("State verification failed: {e}"),
            })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let parameters = from_reader::<ReputationParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        // Zero bytes in and nothing but zero bytes merged in is zero bytes
        // out, not the encoded default: the two are one state, and answering
        // one with the other made `merge(A, A) != A` for the empty state
        // (`fdev verify-merge`, harvest#55). Anything non-empty arriving
        // switches this off, so merging an encoded default in is still that
        // encoding, whichever side it is on.
        let mut nothing_here = state.as_ref().is_empty();
        let mut reputation_state = if state.as_ref().is_empty() {
            ReputationStateV1::default()
        } else {
            from_reader::<ReputationStateV1, &[u8]>(state.as_ref())
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
                    let new_state = from_reader::<ReputationStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    reputation_state
                        .merge(&parameters, &new_state)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let delta = from_reader::<ReputationDelta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    reputation_state
                        .apply_delta(&parameters, &Some(delta))
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                }
                _ => {
                    return Err(ContractError::InvalidUpdate);
                }
            }
        }

        if nothing_here {
            return Ok(UpdateModification::valid(State::from(vec![])));
        }

        let mut updated_state = vec![];
        into_writer(&reputation_state, &mut updated_state)
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
        let _parameters = from_reader::<ReputationParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let reputation_state = from_reader::<ReputationStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let summary = reputation_state.summarize();
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
        let _parameters = from_reader::<ReputationParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // Zero bytes on either side means "there is no state here yet", not a
        // malformed encoding (harvest#55). `summarize_state` answers an empty
        // state with a zero-byte summary, and an empty `BTreeSet` encodes as
        // `0x80`, never as zero bytes, so decoding either one fails. The
        // mailbox contract already guards both; this is the same pattern.
        //
        // A holder with nothing has nothing to send.
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }
        let reputation_state = from_reader::<ReputationStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // A requester with nothing knows nothing: the empty summary is the
        // summary of the empty state, so the delta is everything held.
        let old_summary = if summary.as_ref().is_empty() {
            ReputationStateV1::default().summarize()
        } else {
            from_reader::<ReputationSummary, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        match reputation_state.delta(&old_summary) {
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

    /// `summarize_state` DECODES the state before summarizing it, which is why
    /// the tests in `harvest-common` do not reach the sharpest form of the
    /// encoding defect: they build state in-process, one layer below here.
    ///
    /// Every call through this entry point decodes the same bytes into a fresh
    /// collection. Under a `HashSet` that meant one node, holding one
    /// unchanging state, answered two `summarize_state` calls with DIFFERENT
    /// summary bytes -- because `RandomState::new` bumps a per-thread key on
    /// every construction, so each decode produced a differently-ordered set.
    ///
    /// This crate had no tests at all before this one, which is why the gap
    /// existed. Found by review of #54, not by CI.
    fn parameters() -> Parameters<'static> {
        let owner = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        let params = ReputationParameters::new(owner);
        let mut bytes = vec![];
        into_writer(&params, &mut bytes).expect("encode parameters");
        Parameters::from(bytes)
    }

    /// 32 complaints, not a handful: two small collections can agree on an order
    /// by luck, which would make the guard below pass without meaning to.
    fn encoded_state() -> State<'static> {
        let mut state = ReputationStateV1::default();
        for i in 1u8..33 {
            state.complaints.push(unsigned_complaint(i));
        }
        let mut bytes = vec![];
        into_writer(&state, &mut bytes).expect("encode state");
        State::from(bytes)
    }

    /// **One node, one unchanging state, two calls: the same summary bytes.**
    ///
    /// This is the form the network actually exercises, and it is the one that
    /// produced the freenet-core incident this class of defect is known for --
    /// a contract whose `summarize_state` serialized a hash collection emitted
    /// different summary bytes for the same logical state, so anti-entropy
    /// could never agree with itself.
    #[test]
    fn summarize_state_is_byte_stable_across_calls_on_one_state() {
        let state = encoded_state();

        let first = <Contract as ContractInterface>::summarize_state(parameters(), state.clone())
            .expect("summarize");
        let second = <Contract as ContractInterface>::summarize_state(parameters(), state)
            .expect("summarize");

        assert_eq!(
            first.as_ref(),
            second.as_ref(),
            "two summaries of one unchanged state must be byte-identical"
        );
    }

    /// The same property across two peers: the same members reached by
    /// different insertion orders must summarize to the same bytes through the
    /// entry point, not merely through the in-process helper.
    #[test]
    fn two_peers_holding_the_same_complaints_summarize_identically() {
        let mut ascending = ReputationStateV1::default();
        for i in 1u8..33 {
            ascending.complaints.push(unsigned_complaint(i));
        }
        let mut descending = ReputationStateV1::default();
        for i in (1u8..33).rev() {
            descending.complaints.push(unsigned_complaint(i));
        }

        let encode = |s: &ReputationStateV1| {
            let mut bytes = vec![];
            into_writer(s, &mut bytes).expect("encode state");
            State::from(bytes)
        };

        let a = <Contract as ContractInterface>::summarize_state(parameters(), encode(&ascending))
            .expect("summarize");
        let b = <Contract as ContractInterface>::summarize_state(parameters(), encode(&descending))
            .expect("summarize");

        assert_eq!(
            a.as_ref(),
            b.as_ref(),
            "two peers holding the same complaints must send the same summary bytes"
        );
    }

    /// A complaint in the shape the state holds. Its signatures and evidence
    /// do not verify, and nothing here needs them to: these paths only read,
    /// summarize or re-encode. Verification is `harvest_common::reputation`'s
    /// to test, with genuine fixtures.
    fn unsigned_complaint(n: u8) -> harvest_common::reputation::Complaint {
        use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
        let order = Order {
            id: OrderId([n; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: String::new(),
            amount_sats: 1,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![n],
            payment_hash: None,
            payment_address: String::new(),
            required_confirmations: 1,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: Some([n; 32]),
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
        };
        harvest_common::reputation::Complaint {
            order: AuthorizedOrder {
                order,
                scoped_payload: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                status: OrderStatus::Paid,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            },
            category: harvest_common::feedback::FeedbackCategory::NonDelivery,
            block_ref: BlockAnchor {
                height: 100,
                hash: BlockHash([n; 32]),
            },
            scoped_payload: vec![7, 8, 9],
            buyer_signature: vec![10, 11, 12],
        }
    }

    fn state_with_complaints() -> State<'static> {
        let mut state = ReputationStateV1::default();
        for n in [1u8, 2] {
            state.complaints.push(unsigned_complaint(n));
        }
        let mut bytes = vec![];
        into_writer(&state, &mut bytes).expect("encode state");
        State::from(bytes)
    }

    /// **A new subscriber's first exchange gets the state, not a decode
    /// error (harvest#55).**
    ///
    /// The subscriber has no state, so `summarize_state` gives it a zero-byte
    /// summary, and a holder asked for the delta against that summary used to
    /// fail decoding it: an empty `BTreeSet` encodes as `0x80`, never as zero
    /// bytes. The empty summary means "knows nothing", so the answer is
    /// everything held.
    #[test]
    fn an_empty_summary_is_answered_with_everything_held() {
        let empty_summary =
            <Contract as ContractInterface>::summarize_state(parameters(), State::from(vec![]))
                .expect("summarize the absent state");
        assert!(
            empty_summary.as_ref().is_empty(),
            "precondition: the absent state's summary is zero bytes"
        );

        let delta = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            state_with_complaints(),
            empty_summary,
        )
        .expect("an empty summary must not be a decode error");
        let delta: ReputationDelta = from_reader(delta.as_ref()).expect("decode delta");
        assert_eq!(
            delta.len(),
            2,
            "a requester that holds nothing is sent everything"
        );
    }

    /// The mirror image: a holder with no state of its own answers with an
    /// empty delta rather than failing to decode its own zero bytes.
    #[test]
    fn an_empty_state_answers_with_an_empty_delta() {
        let some_summary =
            <Contract as ContractInterface>::summarize_state(parameters(), state_with_complaints())
                .expect("summarize");
        for summary in [some_summary, StateSummary::from(vec![])] {
            let delta = <Contract as ContractInterface>::get_state_delta(
                parameters(),
                State::from(vec![]),
                summary,
            )
            .expect("an empty state must not be a decode error");
            assert!(delta.as_ref().is_empty(), "nothing held, nothing to send");
        }
    }

    /// **Merging a zero-byte state is a no-op, not a decode error
    /// (harvest#55).** Zero bytes is a valid state (`validate_state` says
    /// so), so a peer can be handed one to merge; the `State` arm decoded it
    /// unconditionally and failed. The mailbox contract already guarded this.
    #[test]
    fn merging_a_zero_byte_state_changes_nothing() {
        let held = state_with_complaints();
        let out = <Contract as ContractInterface>::update_state(
            parameters(),
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
            <Contract as ContractInterface>::update_state(
                parameters(),
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
        into_writer(&ReputationStateV1::default(), &mut default).expect("encode");
        assert_eq!(merge(vec![], default.clone()), default);
        assert_eq!(merge(default.clone(), vec![]), default);
    }

    /// A non-empty delta applied to the empty state is an update, so the
    /// result is the encoded state, not zero bytes. Without this the
    /// empty-state rule above would swallow a delta's content.
    #[test]
    fn a_delta_applied_to_the_empty_state_is_encoded() {
        let mut delta = vec![];
        into_writer(&ReputationDelta::new(), &mut delta).expect("encode");
        let out = <Contract as ContractInterface>::update_state(
            parameters(),
            State::from(vec![]),
            vec![UpdateData::Delta(StateDelta::from(delta))],
        )
        .expect("update")
        .unwrap_valid()
        .as_ref()
        .to_vec();
        let mut default = vec![];
        into_writer(&ReputationStateV1::default(), &mut default).expect("encode");
        assert_eq!(out, default);
    }

    #[test]
    fn validate_state_refuses_non_canonical_bytes() {
        let validate = |bytes: Vec<u8>| {
            <Contract as ContractInterface>::validate_state(
                parameters(),
                State::from(bytes),
                RelatedContracts::new(),
            )
        };
        let mut canonical = vec![];
        into_writer(
            &ReputationStateV1 {
                owner_certificate_pem: "CERT".into(),
                ..Default::default()
            },
            &mut canonical,
        )
        .expect("encode");
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
                state: ReputationStateV1 {
                    owner_certificate_pem: "CERT".into(),
                    ..Default::default()
                },
                unknown: 1,
            },
            &mut extra,
        )
        .expect("encode");
        assert!(validate(extra).is_err(), "an unknown key must be refused");
    }
}
