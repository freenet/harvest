//! Reaching a store's presence contract.
//!
//! The contract lives at `BLAKE3(BLAKE3(wasm) || cbor(PresenceParameters))`,
//! and the parameters are the store key alone, so anyone looking at a store
//! derives where its heartbeats are with no lookup: the seller's delegate to
//! send them, and a buyer to read them.
//!
//! No predecessor probe: a heartbeat is worthless ten minutes after it is
//! signed, and one at an older address comes from an older delegate
//! generation that cannot take an order placed at the current addresses
//! (`legacy/presence_contract.toml`).

use freenet_stdlib::prelude::{ContractCode, ContractKey};
use harvest_common::presence::PresenceParameters;

use super::store_ops::PRESENCE_CONTRACT_WASM;

/// The `ContractKey` of `store_key`'s presence contract, as this build
/// addresses it.
pub fn presence_contract_key(
    store_key: &ed25519_dalek::VerifyingKey,
) -> Result<ContractKey, String> {
    let params = crate::migrate::encode_params(&PresenceParameters::new(*store_key))?;
    // Hashed once: this runs for every store a buyer browses on every
    // minute tick, and the WASM is hundreds of KB.
    static CODE_HASH: std::sync::OnceLock<freenet_stdlib::prelude::CodeHash> =
        std::sync::OnceLock::new();
    let code_hash =
        *CODE_HASH.get_or_init(|| *ContractCode::from(PRESENCE_CONTRACT_WASM.to_vec()).hash());
    Ok(ContractKey::from_id_and_code(
        crate::migrate::current_id(&code_hash, &params),
        code_hash,
    ))
}

/// Create `store_key`'s presence contract holding `heartbeat`, or merge the
/// heartbeat into it if it exists (a PUT of an existing contract merges:
/// `index_ops::publish_entry`). The open seller tab does this once a
/// session, so the delegate's later heartbeats, sent as UPDATEs, find the
/// contract on this node. Resolves when the send succeeds.
#[cfg(target_arch = "wasm32")]
pub async fn publish(
    store_key: &[u8; 32],
    heartbeat: harvest_common::presence::SignedHeartbeat,
) -> Result<(), String> {
    use freenet_stdlib::prelude::{
        ContractContainer, ContractWasmAPIVersion, WrappedContract, WrappedState,
    };
    use std::sync::Arc;

    let key = ed25519_dalek::VerifyingKey::from_bytes(store_key)
        .map_err(|e| format!("the store key is unusable: {e}"))?;
    let params = crate::migrate::encode_params(&PresenceParameters::new(key))?;
    let wrapped = WrappedContract::new(
        Arc::new(ContractCode::from(PRESENCE_CONTRACT_WASM.to_vec())),
        params,
    );
    let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
    let state = harvest_common::to_cbor(&harvest_common::presence::PresenceStateV1 {
        heartbeat: Some(heartbeat),
    })
    .map_err(|e| format!("serialize presence state: {e}"))?;
    super::put_contract(container, WrappedState::new(state)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_stdlib::prelude::{Parameters, WrappedContract};
    use std::sync::Arc;

    /// The derived key is the one the node computes for the presence WASM
    /// and parameters, code hash included (`ContractKey`'s `PartialEq`
    /// ignores it). Mutated red by hashing the index WASM instead.
    #[test]
    fn the_derived_presence_key_is_the_one_the_node_computes() {
        let vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let params: Parameters<'static> =
            crate::migrate::encode_params(&PresenceParameters::new(vk)).unwrap();
        let expected = *WrappedContract::new(
            Arc::new(ContractCode::from(PRESENCE_CONTRACT_WASM.to_vec())),
            params,
        )
        .key();
        let derived = presence_contract_key(&vk).unwrap();
        assert_eq!(derived.id(), expected.id());
        assert_eq!(derived.code_hash(), expected.code_hash());
        // And not the reputation record, which the same store key also
        // addresses.
        assert_ne!(
            derived.id(),
            &super::super::store_ops::reputation_instance_id(&vk).unwrap()
        );
    }
}
