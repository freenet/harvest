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

        let mut reputation_state = if state.as_ref().is_empty() {
            ReputationStateV1::default()
        } else {
            from_reader::<ReputationStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let new_state = from_reader::<ReputationStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    // Merge: add any feedback entries we don't have
                    let delta: ReputationDelta = new_state
                        .feedback
                        .into_iter()
                        // nonce-identity-waiver: reputation keys identity on `token.nonce` and has the
                        // same defect the mailbox re-key fixed -- see
                        // `known_gap_two_feedback_variants_sharing_a_token_do_not_converge`. Parked
                        // until the reputation contract's own re-key; NOT a site to copy.
                        .filter(|e| !reputation_state.used_nonces.contains(&e.token.nonce))
                        .collect();
                    if !delta.is_empty() {
                        reputation_state
                            .apply_delta(&parameters, &Some(delta))
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: e.to_string(),
                            })?;
                    }
                    // Update certificate if empty
                    if reputation_state.owner_certificate_pem.is_empty() {
                        reputation_state.owner_certificate_pem = new_state.owner_certificate_pem;
                    }
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
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
        let reputation_state = from_reader::<ReputationStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let old_summary = from_reader::<ReputationSummary, &[u8]>(summary.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

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
        // `summarize_state` discards the decoded parameters, so only the SHAPE
        // has to decode; this DER is never parsed.
        let params = ReputationParameters::new(vec![9u8; 32], owner);
        let mut bytes = vec![];
        into_writer(&params, &mut bytes).expect("encode parameters");
        Parameters::from(bytes)
    }

    /// 32 nonces, not a handful: two small collections can agree on an order
    /// by luck, which would make the guard below pass without meaning to.
    fn encoded_state() -> State<'static> {
        let mut state = ReputationStateV1::default();
        for i in 1u8..33 {
            state.used_nonces.insert([i; 32]);
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
    fn two_peers_holding_the_same_nonces_summarize_identically() {
        let mut ascending = ReputationStateV1::default();
        for i in 1u8..33 {
            ascending.used_nonces.insert([i; 32]);
        }
        let mut descending = ReputationStateV1::default();
        for i in (1u8..33).rev() {
            descending.used_nonces.insert([i; 32]);
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
            "two peers holding the same nonces must send the same summary bytes"
        );
    }
}
