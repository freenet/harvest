//! Reaching a Ghost Key's index (harvest#93 phase 1c).
//!
//! The index lives at `BLAKE3(BLAKE3(wasm) || cbor(IndexParameters))`, and
//! the parameters are the Ghost Key alone, so anyone holding the key derives
//! the address: the seller's own device, a new device, and a buyer applying
//! "one current store per Ghost Key" to a store it opened.

use freenet_stdlib::prelude::{ContractCode, ContractKey};
use harvest_common::ghostkey_index::{GhostKeyIndexV1, IndexEntry};

use super::store_ops::INDEX_CONTRACT_WASM;

/// The `ContractKey` of `ghost_key`'s index, as this build addresses it.
pub fn index_contract_key(ghost_key: &ed25519_dalek::VerifyingKey) -> Result<ContractKey, String> {
    let params = crate::migrate::encode_params(&crate::migrate::index_params(ghost_key))?;
    let code_hash = *ContractCode::from(INDEX_CONTRACT_WASM.to_vec()).hash();
    Ok(ContractKey::from_id_and_code(
        crate::migrate::current_id(&code_hash, &params),
        code_hash,
    ))
}

/// The state that publishes one entry: an index holding it alone, which the
/// contract merges into whatever the index already holds.
pub fn single_entry_state(entry: IndexEntry) -> Result<Vec<u8>, String> {
    let mut index = GhostKeyIndexV1::default();
    index.entries.insert(entry.slot(), entry);
    harvest_common::to_cbor(&index).map_err(|e| format!("serialize index state: {e}"))
}

/// PUT `entry` into `ghost_key`'s index, creating the index if it does not
/// exist yet (a PUT of an existing contract merges). Resolves when the SEND
/// succeeds, as every contract write here does.
#[cfg(target_arch = "wasm32")]
pub async fn publish_entry(
    ghost_key: &ed25519_dalek::VerifyingKey,
    entry: IndexEntry,
) -> Result<(), String> {
    use freenet_stdlib::prelude::{
        ContractContainer, ContractWasmAPIVersion, WrappedContract, WrappedState,
    };
    use std::sync::Arc;

    let params = crate::migrate::encode_params(&crate::migrate::index_params(ghost_key))?;
    let wrapped = WrappedContract::new(
        Arc::new(ContractCode::from(INDEX_CONTRACT_WASM.to_vec())),
        params,
    );
    let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
    super::put_contract(container, WrappedState::new(single_entry_state(entry)?)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_stdlib::prelude::{Parameters, WrappedContract};
    use std::sync::Arc;

    /// The derived key is the one the node computes for the index WASM and
    /// parameters, code hash included (`ContractKey`'s `PartialEq` ignores
    /// it). Mutated red by hashing the mailbox WASM instead.
    #[test]
    fn the_derived_index_key_is_the_one_the_node_computes() {
        let vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let params: Parameters<'static> =
            crate::migrate::encode_params(&crate::migrate::index_params(&vk)).unwrap();
        let expected = *WrappedContract::new(
            Arc::new(ContractCode::from(INDEX_CONTRACT_WASM.to_vec())),
            params,
        )
        .key();
        let derived = index_contract_key(&vk).unwrap();
        assert_eq!(derived.id(), expected.id());
        assert_eq!(derived.code_hash(), expected.code_hash());
        // And not the mailbox, which the same key also addresses.
        assert_ne!(
            derived.id(),
            super::super::mailbox_ops::mailbox_contract_key(&vk)
                .unwrap()
                .id()
        );
    }
}
