#![allow(unexpected_cfgs)]
//! The store presence contract: one store's latest heartbeat, addressed by
//! the store key alone. The rules live in `harvest_common::presence`; this is
//! only the contract interface.
//!
//! It reads no other contract: a heartbeat is the store key's own signed
//! statement, checked against the key in the parameters. It reads no clock
//! either, so whether a heartbeat is fresh is the reader's question
//! (`harvest_common::presence::presence_verdict`).

use ciborium::ser::into_writer;
use freenet_stdlib::prelude::*;

use harvest_common::presence::{
    decode_delta, decode_state, PresenceParameters, PresenceStateV1, PresenceSummaryV1,
};

#[allow(dead_code)]
struct Contract;

fn params(parameters: &Parameters<'static>) -> Result<PresenceParameters, ContractError> {
    harvest_common::from_cbor::<PresenceParameters>(parameters.as_ref())
        .map_err(ContractError::Deser)
}

fn invalid(reason: String) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason }
}

fn state_of(bytes: &[u8]) -> Result<PresenceStateV1, ContractError> {
    decode_state(bytes).map_err(ContractError::Deser)
}

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
        let params = params(&parameters)?;
        let presence = state_of(bytes)?;
        if !harvest_common::is_canonical_cbor(&presence, bytes) {
            return Err(invalid(
                "State verification failed: state is not in canonical CBOR encoding".into(),
            ));
        }
        presence
            .verify(&params)
            .map(|_| ValidateResult::Valid)
            .map_err(|e| invalid(format!("State verification failed: {e}")))
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = params(&parameters)?;
        // Zero bytes merged with nothing but zero bytes stays zero bytes, the
        // convention every Harvest contract keeps (harvest#55).
        let mut nothing_here = state.as_ref().is_empty();
        let mut presence = if state.as_ref().is_empty() {
            PresenceStateV1::default()
        } else {
            state_of(state.as_ref())?
        };
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    if new_state.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let other = state_of(new_state.as_ref())?;
                    presence.merge(&params, &other).map_err(invalid)?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let heartbeat = decode_delta(d.as_ref()).map_err(ContractError::Deser)?;
                    presence.apply_delta(&params, &heartbeat).map_err(invalid)?;
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        if nothing_here {
            return Ok(UpdateModification::valid(State::from(vec![])));
        }
        let mut out = vec![];
        into_writer(&presence, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(UpdateModification::valid(out.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let _params = params(&parameters)?;
        let presence = state_of(state.as_ref())?;
        match presence.summarize().map_err(ContractError::Deser)? {
            Some(summary) => {
                let mut out = vec![];
                into_writer(&summary, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateSummary::from(out))
            }
            None => Ok(StateSummary::from(vec![])),
        }
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _params = params(&parameters)?;
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }
        let presence = state_of(state.as_ref())?;
        let theirs = if summary.as_ref().is_empty() {
            None
        } else {
            Some(
                harvest_common::from_cbor::<PresenceSummaryV1>(summary.as_ref())
                    .map_err(ContractError::Deser)?,
            )
        };
        match presence
            .delta(theirs.as_ref())
            .map_err(ContractError::Deser)?
        {
            Some(heartbeat) => {
                let mut out = vec![];
                into_writer(&heartbeat, &mut out)
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(out))
            }
            None => Ok(StateDelta::from(vec![])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use harvest_common::presence::{Heartbeat, SignedHeartbeat, MAX_PRESENCE_STATE_BYTES};

    fn store_key() -> SigningKey {
        SigningKey::from_bytes(&[0x71; 32])
    }

    fn parameters() -> Parameters<'static> {
        Parameters::from(
            harvest_common::to_cbor(&PresenceParameters::new(store_key().verifying_key())).unwrap(),
        )
    }

    fn signed(at_ms: u64, taking_orders: bool) -> SignedHeartbeat {
        SignedHeartbeat::sign(&store_key(), Heartbeat::new(at_ms, at_ms, taking_orders)).unwrap()
    }

    fn state_bytes(at_ms: u64, taking_orders: bool) -> Vec<u8> {
        harvest_common::to_cbor(&PresenceStateV1 {
            heartbeat: Some(signed(at_ms, taking_orders)),
        })
        .unwrap()
    }

    fn merged(state: Vec<u8>, data: Vec<UpdateData<'static>>) -> Vec<u8> {
        match Contract::update_state(parameters(), State::from(state), data)
            .expect("an update of valid data")
            .new_state
        {
            Some(s) => s.as_ref().to_vec(),
            None => panic!("no state"),
        }
    }

    fn validate(
        params: Parameters<'static>,
        bytes: Vec<u8>,
    ) -> Result<ValidateResult, ContractError> {
        Contract::validate_state(params, State::from(bytes), RelatedContracts::new())
    }

    /// A valid state validates; one signed by another store's key does not.
    #[test]
    fn validation_follows_the_rules() {
        assert!(matches!(
            validate(parameters(), state_bytes(1_000, true)),
            Ok(ValidateResult::Valid)
        ));
        let other = Parameters::from(
            harvest_common::to_cbor(&PresenceParameters::new(
                SigningKey::from_bytes(&[0x72; 32]).verifying_key(),
            ))
            .unwrap(),
        );
        assert!(validate(other, state_bytes(1_000, true)).is_err());
        assert!(matches!(
            validate(parameters(), vec![]),
            Ok(ValidateResult::Valid)
        ));
    }

    /// A state that is not canonical CBOR is refused even though it decodes
    /// and verifies. Mutated red by dropping the canonical check.
    #[test]
    fn a_non_canonical_encoding_is_refused() {
        let mut trailing = state_bytes(1_000, true);
        trailing.push(0);
        match validate(parameters(), trailing) {
            Err(ContractError::InvalidUpdateWithInfo { reason }) => {
                assert!(reason.contains("canonical"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// An oversized state or delta is refused before it is decoded.
    #[test]
    fn an_oversized_state_or_delta_is_refused() {
        let big = vec![0u8; MAX_PRESENCE_STATE_BYTES + 1];
        assert!(validate(parameters(), big.clone()).is_err());
        assert!(Contract::update_state(
            parameters(),
            State::from(vec![]),
            vec![UpdateData::Delta(StateDelta::from(big.clone()))]
        )
        .is_err());
        assert!(Contract::update_state(
            parameters(),
            State::from(vec![]),
            vec![UpdateData::State(State::from(big))]
        )
        .is_err());
    }

    /// A forged heartbeat in a delta is refused, not ignored.
    #[test]
    fn a_forged_delta_is_refused() {
        let mut forged = signed(5_000, true);
        forged.signature[0] ^= 1;
        let refused = Contract::update_state(
            parameters(),
            State::from(state_bytes(1_000, true)),
            vec![UpdateData::Delta(StateDelta::from(
                harvest_common::to_cbor(&forged).unwrap(),
            ))],
        );
        assert!(matches!(
            refused,
            Err(ContractError::InvalidUpdateWithInfo { .. })
        ));
    }

    /// An update that is neither a state nor a delta is refused rather than
    /// ignored.
    #[test]
    fn an_unexpected_update_kind_is_refused() {
        let odd = UpdateData::StateAndDelta {
            state: State::from(state_bytes(2_000, true)),
            delta: StateDelta::from(vec![]),
        };
        assert!(matches!(
            Contract::update_state(
                parameters(),
                State::from(state_bytes(1_000, true)),
                vec![odd]
            ),
            Err(ContractError::InvalidUpdate)
        ));
    }

    /// State and delta merges agree, the later heartbeat wins, a peer that
    /// already holds it is sent nothing, and the empty state stays empty.
    #[test]
    fn a_delta_and_a_state_merge_to_the_same_bytes() {
        let old = state_bytes(1_000, true);
        let new = state_bytes(2_000, false);
        let by_state = merged(
            old.clone(),
            vec![UpdateData::State(State::from(new.clone()))],
        );
        let summary = Contract::summarize_state(parameters(), State::from(old.clone())).unwrap();
        let delta =
            Contract::get_state_delta(parameters(), State::from(new.clone()), summary).unwrap();
        assert!(!delta.as_ref().is_empty());
        let by_delta = merged(old.clone(), vec![UpdateData::Delta(delta)]);
        assert_eq!(by_state, by_delta);
        assert_eq!(by_state, new);
        // The newer side is sent nothing by the older.
        let summary = Contract::summarize_state(parameters(), State::from(new.clone())).unwrap();
        let back = Contract::get_state_delta(parameters(), State::from(old), summary).unwrap();
        assert!(back.as_ref().is_empty());
        // An empty summary asks for everything.
        let all = Contract::get_state_delta(
            parameters(),
            State::from(new.clone()),
            StateSummary::from(vec![]),
        )
        .unwrap();
        assert_eq!(merged(vec![], vec![UpdateData::Delta(all)]), new);
        assert!(merged(vec![], vec![]).is_empty());
        assert!(Contract::summarize_state(parameters(), State::from(vec![]))
            .unwrap()
            .as_ref()
            .is_empty());
    }
}
