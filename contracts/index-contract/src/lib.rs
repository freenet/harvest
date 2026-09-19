#![allow(unexpected_cfgs)]
//! The Ghost Key index contract (harvest#93 phase 1c): the stores a Ghost
//! Key has backed, addressed by the Ghost Key alone. The rules live in
//! `harvest_common::ghostkey_index`; this is only the contract interface.
//!
//! It reads no other contract (decision 6.7): an entry is the Ghost Key's
//! own signed statement, checked against the key in the parameters, and
//! whether that store accepted it is the store's to say.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use harvest_common::ghostkey_index::{
    GhostKeyIndexV1, IndexDeltaV1, IndexParameters, IndexSummaryV1,
};

#[allow(dead_code)]
struct Contract;

fn params(parameters: &Parameters<'static>) -> Result<IndexParameters, ContractError> {
    from_reader::<IndexParameters, &[u8]>(parameters.as_ref())
        .map_err(|e| ContractError::Deser(e.to_string()))
}

fn invalid(reason: String) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason }
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
        let index = from_reader::<GhostKeyIndexV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        if !harvest_common::is_canonical_cbor(&index, bytes) {
            return Err(invalid(
                "State verification failed: state is not in canonical CBOR encoding".into(),
            ));
        }
        index
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
        let mut index = if state.as_ref().is_empty() {
            GhostKeyIndexV1::default()
        } else {
            from_reader::<GhostKeyIndexV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    if new_state.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let other = from_reader::<GhostKeyIndexV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    index.merge(&params, &other).map_err(invalid)?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let delta = from_reader::<IndexDeltaV1, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    index.apply_delta(&params, &delta).map_err(invalid)?;
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        if nothing_here {
            return Ok(UpdateModification::valid(State::from(vec![])));
        }
        let mut out = vec![];
        into_writer(&index, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
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
        let index = from_reader::<GhostKeyIndexV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let mut out = vec![];
        into_writer(&index.summarize(), &mut out)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(out))
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
        let index = from_reader::<GhostKeyIndexV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let old = if summary.as_ref().is_empty() {
            IndexSummaryV1::default()
        } else {
            from_reader::<IndexSummaryV1, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
        match index.delta(&old) {
            Some(delta) => {
                let mut out = vec![];
                into_writer(&delta, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(out))
            }
            None => Ok(StateDelta::from(vec![])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};
    use harvest_common::backing::{store_key_envelope, BackingStatement};
    use harvest_common::ghostkey_index::IndexEntry;

    fn ghost() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }

    fn parameters() -> Parameters<'static> {
        Parameters::from(
            harvest_common::to_cbor(&IndexParameters::new(ghost().verifying_key())).unwrap(),
        )
    }

    fn entry(store: u8) -> IndexEntry {
        let statement = BackingStatement {
            store: SigningKey::from_bytes(&[store; 32]).verifying_key(),
            backer: ghost().verifying_key(),
            certificate_pem: "CERT".into(),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height: 10,
                hash: BlockHash([1; 32]),
            },
        };
        let scoped = store_key_envelope(harvest_common::to_cbor(&statement).unwrap()).unwrap();
        let signature = ghost().sign(&scoped).to_bytes().to_vec();
        IndexEntry {
            statement,
            scoped_payload: scoped,
            signature,
        }
    }

    fn state_of(entries: Vec<IndexEntry>) -> Vec<u8> {
        let mut index = GhostKeyIndexV1::default();
        index
            .apply_delta(&IndexParameters::new(ghost().verifying_key()), &entries)
            .unwrap();
        harvest_common::to_cbor(&index).unwrap()
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

    /// A valid index validates; one holding another key's statement does not.
    #[test]
    fn validation_follows_the_rules() {
        let good = state_of(vec![entry(1), entry(2)]);
        assert!(matches!(
            Contract::validate_state(parameters(), State::from(good), RelatedContracts::new()),
            Ok(ValidateResult::Valid)
        ));
        let other = Parameters::from(
            harvest_common::to_cbor(&IndexParameters::new(
                SigningKey::from_bytes(&[0x62; 32]).verifying_key(),
            ))
            .unwrap(),
        );
        assert!(Contract::validate_state(
            other,
            State::from(state_of(vec![entry(1)])),
            RelatedContracts::new()
        )
        .is_err());
        assert!(matches!(
            Contract::validate_state(parameters(), State::from(vec![]), RelatedContracts::new()),
            Ok(ValidateResult::Valid)
        ));
    }

    /// State and delta merges agree, and the empty state stays empty.
    #[test]
    fn a_delta_and_a_state_merge_to_the_same_bytes() {
        let a = state_of(vec![entry(1)]);
        let b = state_of(vec![entry(2), entry(3)]);
        let by_state = merged(a.clone(), vec![UpdateData::State(State::from(b.clone()))]);
        let summary = Contract::summarize_state(parameters(), State::from(a.clone())).unwrap();
        let delta =
            Contract::get_state_delta(parameters(), State::from(b.clone()), summary).unwrap();
        let by_delta = merged(a, vec![UpdateData::Delta(delta)]);
        assert_eq!(by_state, by_delta);
        assert_eq!(by_state, state_of(vec![entry(1), entry(2), entry(3)]));
        assert!(merged(vec![], vec![]).is_empty());
    }
}
