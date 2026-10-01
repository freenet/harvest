#![allow(unexpected_cfgs)]
//! The listing image contract: one baseline JPEG, addressed by its own
//! BLAKE3 hash (Ian, 2026-10-01). The parameters are the hash, the state is
//! the file, and the state can never change. The rules live in
//! `harvest_image`; this is only the contract interface.
//!
//! Anyone may publish an image under this code hash. That is fine: it is
//! just bytes, and a picture appears on a listing only because the store
//! key signed a listing naming its hash. Nothing published here can change
//! a picture someone else's listing names, because the key binds the bytes.
//!
//! # Fixed state, and the three ways a copy could go wrong
//!
//! Modelled on freenet-git's `pack-contract`, with three differences that
//! each close a way to blank an image whose hash is public (it is in the
//! signed listing):
//!
//! - **The empty state is invalid** (`harvest_image::validate`). Otherwise
//!   anyone could publish nothing under any image's key.
//! - **`update_state` never replaces a valid held state**, and every
//!   incoming copy must itself be valid, so an update can only ever leave
//!   the one valid image in place, or put it there over nothing (or over a
//!   wrong copy, which validation should make impossible). Its result is
//!   checked once more before it is returned.
//! - **The summary is the hash of the state actually held**, not the
//!   parameters. A wrong copy (which validation should make impossible) can
//!   then never claim to be in sync with a right one, and is sent the image,
//!   which `update_state` takes over it.
//!
//! A peer whose summary differs is sent the whole image as its "delta": a
//! fixed state has no smaller difference to send, and `update_state` checks
//! a delta exactly as it checks a state. An identical re-publish is
//! accepted, because a PUT to a contract a node already holds arrives as an
//! update.

use freenet_stdlib::prelude::*;

#[allow(dead_code)]
struct Contract;

fn invalid(reason: String) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason }
}

fn check(parameters: &Parameters<'_>, state: &[u8]) -> Result<(), ContractError> {
    harvest_image::validate(parameters.as_ref(), state)
        .map(|_| ())
        .map_err(|e| invalid(e.to_string()))
}

/// Fold one incoming copy into the held state. The incoming copy must be
/// valid. If what is held is not (nothing, or bytes that are not this
/// image), the valid copy replaces it: that is the repair the hash summary
/// exists to trigger. A valid held copy is kept.
fn merge(
    parameters: &Parameters<'_>,
    held: Vec<u8>,
    incoming: &[u8],
) -> Result<Vec<u8>, ContractError> {
    check(parameters, incoming)?;
    if check(parameters, &held).is_err() {
        return Ok(incoming.to_vec());
    }
    // Both are valid, so both hash to the parameters and are the same bytes:
    // keeping `held` and taking `incoming` are one outcome.
    Ok(held)
}

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        check(&parameters, state.as_ref())?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let mut held = state.as_ref().to_vec();
        for update in data {
            held = match update {
                UpdateData::State(s) => merge(&parameters, held, s.as_ref())?,
                // An empty delta is "nothing new", from a peer whose summary
                // matched. Any other delta is a whole image (see
                // `get_state_delta`).
                UpdateData::Delta(d) if d.as_ref().is_empty() => held,
                UpdateData::Delta(d) => merge(&parameters, held, d.as_ref())?,
                UpdateData::StateAndDelta { state, .. } => {
                    merge(&parameters, held, state.as_ref())?
                }
                // An image depends on no other contract. A node passes along
                // related states that arrive with an upsert; they say nothing
                // about this one, so they change nothing.
                _ => held,
            };
        }
        // Never hand back a state `validate_state` would refuse, such as
        // nothing at all after an update of only empty deltas.
        check(&parameters, &held)?;
        Ok(UpdateModification::valid(State::from(held)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(
            harvest_image::image_hash(state.as_ref()).to_vec(),
        ))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        if summary.as_ref() == harvest_image::image_hash(state.as_ref()) {
            Ok(StateDelta::from(Vec::new()))
        } else {
            Ok(StateDelta::from(state.as_ref().to_vec()))
        }
    }
}

#[cfg(test)]
mod tests;
