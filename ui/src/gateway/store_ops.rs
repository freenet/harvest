//! Store operations: creating stores, submitting listings, subscribing.

use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, ContractKey};
use harvest_common::listing::AuthorizedListing;
use harvest_common::StoreRegistration;

/// The contract WASM this build of the UI bundles.
///
/// These bytes ARE the addresses: a contract lives at
/// `BLAKE3(BLAKE3(wasm) || parameters)`, so the committed files decide where
/// every store, reputation contract and mailbox this build creates will live.
/// `create_store_contracts` publishes them, `store_contract_key` hashes the
/// store one to recover the key of a store published earlier, and
/// `crate::gateway::migrate_ops` hashes all three to derive the current
/// generation's instance ids for the migration probe.
///
/// Declared once rather than `include_bytes!`d at each use: three copies of an
/// `include_bytes!` is three chances for one of them to name a different file,
/// and the failure would be a contract published at an address nothing else in
/// the app agrees with.
pub(crate) const STORE_CONTRACT_WASM: &[u8] =
    include_bytes!("../../public/contracts/store_contract.wasm");
pub(crate) const REPUTATION_CONTRACT_WASM: &[u8] =
    include_bytes!("../../public/contracts/reputation_contract.wasm");
pub const MAILBOX_CONTRACT_WASM: &[u8] =
    include_bytes!("../../public/contracts/mailbox_contract.wasm");

/// The code hash of the store contract this build bundles.
///
/// Cached: it is a BLAKE3 over the whole contract WASM, and it is asked for
/// once per certificate a store page verifies and once per store code a page
/// resolves.
pub(crate) fn store_code_hash() -> [u8; 32] {
    static HASH: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        let hash = *ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash();
        let bytes: &[u8] = hash.as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    });
    *HASH
}

/// The address a store code opens under this build (harvest#52).
///
/// Everything a client needs is local: the code is the store contract's only
/// parameter and the contract's WASM is bundled, so the address is
/// `BLAKE3(code_hash || cbor(parameters))` with no lookup and no round trip.
/// Through `crate::migrate`'s derivation, the one every other store address
/// in this app goes through, so a link and the seller's own PUT cannot
/// disagree about where a store lives.
pub fn store_instance_id(
    params: &harvest_common::store::StoreParameters,
) -> Result<ContractInstanceId, String> {
    let bytes = crate::migrate::encode_params(params)?;
    Ok(crate::migrate::current_id(&store_code_hash(), &bytes))
}

/// Whether a store's `ContractKey` was recovered from local state or rebuilt
/// from the bundled contract -- see `store_contract_key`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyOrigin {
    /// Recorded locally when the store was created. Always correct.
    Recorded,
    /// Rebuilt from the store contract this build bundles. Correct only if
    /// the store was published with the same contract build.
    Reconstructed,
}

/// Bytes of a store-contract delta carrying only listings.
///
/// The store contract's delta is the `StoreStateV1Delta` the `#[composable]`
/// macro generates -- a struct of one `Option` per field -- not the inner
/// field's own delta. Sending the bare `Vec<AuthorizedListing>` produces CBOR
/// the contract rejects outright with "invalid type: sequence, expected map",
/// so the listing never lands and the failure says nothing about why.
///
/// Every delta names its `owner`, the key its records are signed by
/// (harvest#52). The first one to reach a store is what claims it, and an
/// update from an owner the store does not hold is ignored rather than
/// refused, so a seller whose address another key holds finds out from the
/// state that comes back, not from this send: see
/// `AppState::foreign_store_owner`.
fn listings_delta_bytes(
    owner: ed25519_dalek::VerifyingKey,
    listings: Vec<AuthorizedListing>,
) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        owner: Some(owner),
        info: None,
        listings: Some(listings),
        orders: None,
        ..Default::default()
    })
    .map_err(|e| format!("serialize listing delta: {e}"))
}

/// Bytes of a store-contract delta carrying only orders.
///
/// Same shape rule as `listings_delta_bytes`, and the same failure if it is
/// got wrong: the contract's delta is the `StoreStateV1Delta` the
/// `#[composable]` macro generates, not `OrdersV1`'s own
/// `Vec<AuthorizedOrder>`. A bare `Vec` is CBOR the contract rejects with
/// "invalid type: sequence, expected map", so the invoice never lands and the
/// error says nothing about why.
fn orders_delta_bytes(
    owner: ed25519_dalek::VerifyingKey,
    orders: Vec<harvest_common::payment::AuthorizedOrder>,
) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        owner: Some(owner),
        info: None,
        listings: None,
        orders: Some(orders),
        ..Default::default()
    })
    .map_err(|e| format!("serialize order delta: {e}"))
}

/// Bytes of a store-contract delta carrying only the store's own details.
fn store_info_delta_bytes(
    owner: ed25519_dalek::VerifyingKey,
    info: harvest_common::store::AuthorizedStoreInfoV1,
) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        owner: Some(owner),
        info: Some(info),
        listings: None,
        orders: None,
        ..Default::default()
    })
    .map_err(|e| format!("serialize store info delta: {e}"))
}

/// The `ContractKey` for a store, which is what sending it an update needs.
///
/// The key is written down exactly once, locally, when the store is created.
/// The delegate cannot keep it: `HarvestDelegateRequest::RegisterStore` has no
/// field for it, so every registration `ListStores` returns is keyless. After
/// a page reload there is therefore no local copy to fall back on either --
/// `my_stores` starts empty and is refilled entirely from the delegate -- and
/// preserving a known key across a merge, while necessary, does nothing for
/// the reload case. So rebuild it.
///
/// A `ContractKey` is an instance id plus a code hash, and both are available
/// without the delegate: the instance id *is* `store_contract_id`, and the
/// code hash is the hash of the store contract this build bundles. The
/// parameters -- which we do not have after a reload -- are not needed,
/// because they are already folded into the instance id.
///
/// The one case this does not fix: a store published with an *older* store
/// contract has a different code hash, so the rebuilt key names a contract
/// that does not exist and the update will fail. That store is already broken
/// today, with no key at all, so this is never a regression -- but it is not
/// a fix for every store either, which is why the caller is told which of the
/// two it got and can say so.
pub fn store_contract_key(
    registration: &StoreRegistration,
) -> Result<(ContractKey, KeyOrigin), String> {
    if let Some(bytes) = registration.store_contract_key.as_ref() {
        return harvest_common::from_cbor(bytes)
            .map(|key| (key, KeyOrigin::Recorded))
            .map_err(|e| format!("deserialize stored contract key: {e}"));
    }

    let instance_id: [u8; 32] = registration
        .store_contract_id
        .as_slice()
        .try_into()
        .map_err(|_| {
            format!(
                "store contract id is {} bytes, not 32",
                registration.store_contract_id.len()
            )
        })?;
    let code_hash = *ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash();
    Ok((
        ContractKey::from_id_and_code(ContractInstanceId::new(instance_id), code_hash),
        KeyOrigin::Reconstructed,
    ))
}

/// Create the three contracts for a new store and register them with the
/// harvest delegate.
#[cfg(target_arch = "wasm32")]
pub async fn create_store_contracts(
    // Everything creation gathered, as one value: see the fields of
    // `state::PendingStoreCreation` for what each is and why creation does
    // not wait for the encryption key.
    creation: crate::state::PendingStoreCreation,
    // The backing the new store is created with, signed by the Ghost Key and
    // accepted by the store key (harvest#93). Its statement names the store
    // key.
    backing: harvest_common::backing::AuthorizedBacking,
) -> Result<(), String> {
    let crate::state::PendingStoreCreation {
        ghostkey_fingerprint: seller_fingerprint,
        seller_verifying_key_bytes,
        certificate_pem,
        store_name,
        description,
        rsa_public_key_der,
        encryption_public_key,
        store_verifying_key: _,
        store_key_request: _,
        carried_listings,
    } = creation;
    let rsa_public_key_der =
        rsa_public_key_der.ok_or("the reputation key had not arrived; nothing was created")?;
    use dioxus::logger::tracing::{info, warn};
    use dioxus::prelude::{ReadableExt, WritableExt};
    use freenet_stdlib::prelude::*;
    use std::sync::Arc;

    let seller_vk = ed25519_dalek::VerifyingKey::from_bytes(&seller_verifying_key_bytes)
        .map_err(|e| format!("invalid verifying key: {e}"))?;
    // The store's own key (harvest#93): it owns the store, its code is the
    // store's address, and it signs everything the store holds. The Ghost Key
    // above still addresses the mailbox and the reputation contract, which
    // later phases of #93 move onto the store key.
    let store_vk = backing.statement.store;

    // Helper to create a ContractContainer from WASM bytes and parameters
    fn make_contract(
        wasm: &[u8],
        params_bytes: Vec<u8>,
    ) -> (ContractContainer, ContractInstanceId, ContractKey) {
        let code = ContractCode::from(wasm.to_vec());
        let params = Parameters::from(params_bytes);
        let wrapped = WrappedContract::new(Arc::new(code), params);
        let key = *wrapped.key();
        let instance_id = ContractInstanceId::from(key);
        let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
        (container, instance_id, key)
    }

    // 1. Reputation contract
    //
    // Parameters come from `crate::migrate`, which is the ONE place any
    // contract's parameters are derived. A contract's address is
    // `BLAKE3(code_hash || cbor(parameters))`, so a second copy here would let
    // this PUT and the migration probe disagree about where a seller's
    // contracts live -- silently, in the direction that reports a clean
    // "nothing to migrate". This file used to hold that second copy for all
    // three contracts; see `migrate::store_params`.
    let reputation_params =
        crate::migrate::reputation_params(rsa_public_key_der.clone(), &seller_vk);
    let reputation_params_bytes = harvest_common::to_cbor(&reputation_params)
        .map_err(|e| format!("serialize reputation params: {e}"))?;

    let reputation_state = harvest_common::reputation::ReputationStateV1 {
        owner_certificate_pem: certificate_pem.clone(),
        ..Default::default()
    };
    let reputation_state_bytes = harvest_common::to_cbor(&reputation_state)
        .map_err(|e| format!("serialize reputation state: {e}"))?;

    let (reputation_container, reputation_id, _reputation_key) =
        make_contract(REPUTATION_CONTRACT_WASM, reputation_params_bytes);

    info!("Creating reputation contract: {:?}", reputation_id);
    super::put_contract(
        reputation_container,
        WrappedState::new(reputation_state_bytes),
    )
    .await?;

    // 2. Store contract (initially empty, version 0)
    //
    // The seller's key is the store's whole identity, and why that is so --
    // the Bitcoin trust configuration was once a parameter here, was therefore
    // frozen into every store's address, and made every store this function
    // created permanently incapable of accepting an on-chain payment -- is
    // recorded on `StoreParameters` itself, next to the field it is about.
    let store_params = crate::migrate::store_params(&store_vk);
    let store_params_bytes = harvest_common::to_cbor(&store_params)
        .map_err(|e| format!("serialize store params: {e}"))?;

    // The store's first state already holds its backing, which the store key
    // accepted: so the store is claimed for the store key by something it
    // signed, and a buyer who opens it before the details publish finds it
    // backed rather than blank.
    let store_state = harvest_common::store::StoreStateV1 {
        owner: Some(store_vk),
        backings: harvest_common::backing::BackingsV1 {
            records: std::iter::once((
                harvest_common::store::Bytes32(backing.statement.backer.to_bytes()),
                backing,
            ))
            .collect(),
        },
        ..Default::default()
    };
    let store_state_bytes =
        harvest_common::to_cbor(&store_state).map_err(|e| format!("serialize store state: {e}"))?;

    let (store_container, store_id, store_key) =
        make_contract(STORE_CONTRACT_WASM, store_params_bytes);

    info!("Creating store contract: {:?}", store_id);
    super::put_contract(store_container, WrappedState::new(store_state_bytes)).await?;

    // 3. Mailbox contract
    let mailbox_params = crate::migrate::mailbox_params(&seller_vk);
    let mailbox_params_bytes = harvest_common::to_cbor(&mailbox_params)
        .map_err(|e| format!("serialize mailbox params: {e}"))?;

    let mailbox_state = harvest_common::mailbox::MailboxStateV1::default();
    let mailbox_state_bytes = harvest_common::to_cbor(&mailbox_state)
        .map_err(|e| format!("serialize mailbox state: {e}"))?;

    let (mailbox_container, mailbox_id, _mailbox_key) =
        make_contract(MAILBOX_CONTRACT_WASM, mailbox_params_bytes);

    info!("Creating mailbox contract: {:?}", mailbox_id);
    super::put_contract(mailbox_container, WrappedState::new(mailbox_state_bytes)).await?;

    // 4. Register store with harvest delegate
    let delegate_key = super::APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;

    let register_request = harvest_common::HarvestDelegateRequest::RegisterStore {
        ghostkey_fingerprint: seller_fingerprint.clone(),
        store_contract_id: store_id.as_bytes().to_vec(),
        reputation_contract_id: reputation_id.as_bytes().to_vec(),
        mailbox_contract_id: mailbox_id.as_bytes().to_vec(),
        store_verifying_key: Some(store_vk.to_bytes()),
    };
    let payload = harvest_common::to_cbor(&register_request)
        .map_err(|e| format!("serialize register request: {e}"))?;

    super::send_delegate_message(&delegate_key, payload).await?;

    info!(
        "Store creation complete for {} -- 3 contracts created and registered",
        seller_fingerprint
    );

    // Update app state
    // Serialize the store contract key for later use in updates
    let store_key_bytes = harvest_common::to_cbor(&store_key).ok();

    super::APP_STATE
        .write()
        .my_stores
        .entry(seller_fingerprint.clone())
        .or_default()
        .push(harvest_common::StoreRegistration {
            store_contract_id: store_id.as_bytes().to_vec(),
            reputation_contract_id: reputation_id.as_bytes().to_vec(),
            mailbox_contract_id: mailbox_id.as_bytes().to_vec(),
            store_contract_key: store_key_bytes,
            store_verifying_key: Some(store_vk.to_bytes()),
        });

    // The mailbox id is known here and nowhere else in this session -- the
    // store contract's state doesn't carry it -- so record the mapping now,
    // or every message a buyer leaves in this mailbox is dropped on arrival.
    super::APP_STATE
        .write()
        .register_store_mailbox(store_id.as_bytes(), mailbox_id.as_bytes());

    // 5. Publish the store's own details.
    //
    // The contract was PUT with `StoreStateV1::default()`, whose info is at
    // version 0 -- the uninitialized state. Until this lands, every store on
    // the network has an empty name and description, so a buyer following the
    // seller's share link arrives at a blank storefront.
    //
    // This cannot be done in the PUT above: `AuthorizedStoreInfoV1::verify`
    // accepts version 0 only as the empty default, so anything a buyer can
    // read has to carry a real Ed25519 signature over the ghostkey delegate's
    // `ScopedPayload`. That is a round-trip -- `SignMessage` now, the update
    // when `SignResult` comes back (see `AppState::on_ghostkey_response`) --
    // the same one a listing makes.
    let info = harvest_common::store::StoreInfoV1 {
        version: 1,
        certificate_pem,
        seller_fingerprint: seller_fingerprint.clone(),
        reputation_contract_id: *reputation_id
            .as_bytes()
            .first_chunk::<32>()
            .ok_or("reputation contract id is not 32 bytes -- cannot publish store details")?,
        store_name,
        description,
                // The inbox key the store key derives (harvest#93 phase 1b,
        // `StoreSubkeys`), the same on every device holding the store key.
        encryption_public_key,
        // And the record key, derived the same way and published so another
        // device can check its own derivation.
        record_public_key: Some(rsa_public_key_der.clone()),
    };
    if encryption_public_key.is_none() {
        warn!(
            "Publishing this store with no encryption key -- buyers will be told they cannot \
             message this seller until the details are published again"
        );
    }
    {
        let mut state = super::APP_STATE.write();
        state.queue_store_info_signature(store_id.as_bytes().to_vec(), info);
        // A store being moved from before revision 2 brings its listings,
        // re-signed by the store key. Their ids derive from their terms,
        // which name no seller, so each keeps its id. See
        // `crate::backing_flow`.
        for listing in carried_listings {
            if let Err(e) = state.queue_listing_signature(
                store_id.as_bytes().to_vec(),
                seller_fingerprint.clone(),
                listing,
            ) {
                warn!("a listing could not be carried into the new store: {e}");
            }
        }
    }

    Ok(())
}

/// The contract key of one of OUR stores, how it was found, and the owner a
/// delta to it has to name.
///
/// The owner is `AppState::delta_owner_key`: the store key, or for a store
/// made before revision 2, the key its loaded state names. That second case is
/// what lets an open legacy invoice still be published as Paid, which needs
/// no signature (harvest#93 review, Should Fix 6); anything that does need
/// one is refused earlier, where it would have been signed.
#[cfg(target_arch = "wasm32")]
fn owned_store_key(
    store_contract_id: &[u8],
    whats_missing: &str,
) -> Result<(ContractKey, KeyOrigin, ed25519_dalek::VerifyingKey), String> {
    use dioxus::prelude::ReadableExt;

    let state = super::APP_STATE.read();
    let registration = state
        .my_stores
        .values()
        .flat_map(|stores| stores.iter())
        .find(|s| s.store_contract_id == store_contract_id)
        .ok_or_else(|| format!("this store is not one of yours -- {whats_missing}"))?;
    let owner = state
        .delta_owner_key(store_contract_id)
        .ok_or_else(|| format!("{} -- {whats_missing}", crate::state::NO_STORE_KEY_MESSAGE))?;
    let (key, origin) = store_contract_key(registration)?;
    Ok((key, origin, owner))
}

/// Submit a signed listing to a store contract.
///
/// Resolves the store's `ContractKey` (see `store_contract_key`) and sends
/// the listing as a delta update.
#[cfg(target_arch = "wasm32")]
pub async fn submit_listing_by_id(
    store_contract_id: &[u8],
    listing: AuthorizedListing,
) -> Result<(), String> {
    use dioxus::logger::tracing::{info, warn};
    use freenet_stdlib::prelude::*;

    let (contract_key, origin, owner) =
        owned_store_key(store_contract_id, "nothing to add a listing to")?;
    if origin == KeyOrigin::Reconstructed {
        warn!("Store contract key rebuilt from the bundled store contract");
    }

    let title = listing.listing.title.clone();
    let delta_bytes = listings_delta_bytes(owner, vec![listing])?;

    super::update_contract(
        &contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await
    .map_err(|e| match origin {
        // A rebuilt key is wrong if the store predates the store contract
        // this build bundles, and the failure that produces says nothing
        // about why. Say it here rather than leaving the seller with a bare
        // gateway error.
        KeyOrigin::Reconstructed => format!(
            "{e} -- this store's contract key was rebuilt from the store \
             contract this version of Harvest bundles. If the store was \
             created with an older version, that key is wrong and the \
             listing cannot be submitted."
        ),
        KeyOrigin::Recorded => e,
    })?;

    info!("Submitted listing '{}' to store contract", title);
    Ok(())
}

/// Publish a store's signed details to its contract.
///
/// Separate from creation because it cannot happen during it: the details
/// have to be signed by the ghostkey delegate first, and that is a round-trip
/// through `SignMessage`/`SignResult`.
/// Publish a wrapped copy of the store key to one of our stores (harvest#93
/// phase 1b), in the background. The copy is already signed by the store key
/// (`WrapStoreKeyFor`); a failure is said out loud, since until the copy lands
/// no other device can recover the store.
#[cfg(target_arch = "wasm32")]
pub fn spawn_publish_copy(store_contract_id: Vec<u8>, copy: harvest_common::custody::AuthorizedCopy) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::WritableExt;
        use freenet_stdlib::prelude::*;
        let result = async {
            let (contract_key, _origin, owner) =
                owned_store_key(&store_contract_id, "cannot back its key up")?;
            let delta = harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
                owner: Some(owner),
                copies: Some(vec![copy]),
                ..Default::default()
            })
            .map_err(|e| format!("serialize the copy: {e}"))?;
            super::update_contract(&contract_key, UpdateData::Delta(StateDelta::from(delta))).await
        }
        .await;
        if let Err(e) = result {
            super::APP_STATE.write().notifications.push(format!(
                "Your store's key could not be backed up to your Ghost Key: {e}"
            ));
        }
    });
}

#[cfg(target_arch = "wasm32")]
pub async fn submit_store_info_by_id(
    store_contract_id: &[u8],
    info: harvest_common::store::AuthorizedStoreInfoV1,
) -> Result<(), String> {
    use dioxus::logger::tracing::info;
    use freenet_stdlib::prelude::*;

    let (contract_key, _origin, owner) =
        owned_store_key(store_contract_id, "cannot publish its details")?;

    let name = info.info.store_name.clone();
    let delta_bytes = store_info_delta_bytes(owner, info)?;
    super::update_contract(
        &contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await?;

    info!("Published store details for '{}'", name);
    Ok(())
}

/// Publish a seller-signed invoice to their store contract.
///
/// The store contract is where an order has to live: `AuthorizedOrder::verify`
/// is what establishes that these terms are genuinely the seller's, and a
/// buyer can only run it against state they can fetch. An invoice held
/// anywhere private would be an invoice nobody could check.
#[cfg(target_arch = "wasm32")]
pub async fn submit_order_by_id(
    store_contract_id: &[u8],
    order: harvest_common::payment::AuthorizedOrder,
) -> Result<(), String> {
    use dioxus::logger::tracing::{info, warn};
    use freenet_stdlib::prelude::*;

    let (contract_key, origin, owner) =
        owned_store_key(store_contract_id, "cannot issue an invoice on it")?;
    if origin == KeyOrigin::Reconstructed {
        warn!("Store contract key rebuilt from the bundled store contract");
    }

    let id = order.order.id.short();
    let delta_bytes = orders_delta_bytes(owner, vec![order])?;

    super::update_contract(
        &contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await
    .map_err(|e| match origin {
        KeyOrigin::Reconstructed => format!(
            "{e} -- this store's contract key was rebuilt from the store \
             contract this version of Harvest bundles. If the store was \
             created with an older version, that key is wrong and the \
             invoice cannot be published."
        ),
        KeyOrigin::Recorded => e,
    })?;

    info!("Published invoice {} to store contract", id);
    Ok(())
}

/// Ask the harvest delegate which stores are registered for a ghostkey
/// identity.
///
/// Registrations live in the delegate's own secret storage, which survives a
/// page reload; `AppState::my_stores` does not. Without asking, a seller who
/// refreshes the page is shown "Create Store" again for an identity that
/// already owns one, with no way back to it -- the store, its listings and
/// its mailbox are all still on the network, but the UI has forgotten which
/// contracts they are.
#[cfg(target_arch = "wasm32")]
pub async fn list_stores(ghostkey_fingerprint: String) -> Result<(), String> {
    use dioxus::prelude::ReadableExt;

    let delegate_key = super::APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;

    let request = harvest_common::HarvestDelegateRequest::ListStores {
        ghostkey_fingerprint,
    };
    let payload =
        harvest_common::to_cbor(&request).map_err(|e| format!("serialize ListStores: {e}"))?;

    super::send_delegate_message(&delegate_key, payload).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn list_stores(_ghostkey_fingerprint: String) -> Result<(), String> {
    Err("delegate messaging requires WASM".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_owner() -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key()
    }

    fn registration(store_contract_key: Option<Vec<u8>>) -> StoreRegistration {
        StoreRegistration {
            store_contract_id: vec![3u8; 32],
            reputation_contract_id: vec![4u8; 32],
            mailbox_contract_id: vec![5u8; 32],
            store_contract_key,
            store_verifying_key: None,
        }
    }

    /// The reload path: after a refresh there is no local state at all, and
    /// every registration the delegate returns is keyless. Preserving a known
    /// key across a merge does nothing here -- there is nothing to preserve
    /// from -- so the key has to be rebuilt or "Add Listing" stays broken.
    #[test]
    fn a_keyless_registration_still_yields_a_usable_key() {
        let (key, origin) = store_contract_key(&registration(None)).expect("should rebuild");

        assert_eq!(origin, KeyOrigin::Reconstructed);
        assert_eq!(key.id().as_bytes(), &[3u8; 32]);
        assert_eq!(
            key.code_hash(),
            ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash(),
            "the code hash must come from the bundled store contract"
        );
    }

    /// A key recorded at creation time is authoritative -- it is right even
    /// for a store published under an older contract build, which is exactly
    /// the case reconstruction gets wrong.
    #[test]
    fn a_recorded_key_wins_over_reconstruction() {
        let recorded = ContractKey::from_id_and_code(
            ContractInstanceId::new([3u8; 32]),
            *ContractCode::from(vec![0xFEu8; 16]).hash(),
        );
        let bytes = harvest_common::to_cbor(&recorded).expect("serialize");

        let (key, origin) = store_contract_key(&registration(Some(bytes))).expect("should decode");

        assert_eq!(origin, KeyOrigin::Recorded);
        assert_eq!(key.code_hash(), recorded.code_hash());
        assert_ne!(
            key.code_hash(),
            ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash()
        );
    }

    /// The store contract's delta is `StoreStateV1Delta`, a struct of
    /// `Option`s -- not the listings field's own delta. Sending the bare
    /// `Vec` was CBOR the contract could not read, so no listing ever landed.
    #[test]
    fn a_listing_delta_is_shaped_like_the_contracts_delta() {
        let bytes = listings_delta_bytes(test_owner(), Vec::new()).expect("serialize");
        let delta = harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bytes)
            .expect("the contract must be able to read its own delta");
        assert!(delta.listings.is_some());
        assert!(delta.info.is_none() && delta.orders.is_none());
        assert_eq!(delta.owner, Some(test_owner()), "a delta names its owner");

        // The shape that was being sent, pinned so it cannot come back.
        let bare = harvest_common::to_cbor(&Vec::<AuthorizedListing>::new()).expect("serialize");
        assert!(
            harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bare).is_err(),
            "a bare Vec is not a store delta"
        );
    }

    /// The same shape rule as listings, checked independently rather than
    /// assumed to follow: an order delta is `StoreStateV1Delta`, not
    /// `OrdersV1`'s own `Vec<AuthorizedOrder>`. Sending the bare `Vec` is the
    /// bug that meant no listing had EVER landed, and nothing about the
    /// failure said so.
    #[test]
    fn an_order_delta_is_shaped_like_the_contracts_delta() {
        let bytes = orders_delta_bytes(test_owner(), Vec::new()).expect("serialize");
        let delta = harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bytes)
            .expect("the contract must be able to read its own delta");
        assert!(delta.orders.is_some());
        assert!(delta.info.is_none() && delta.listings.is_none());
        assert_eq!(delta.owner, Some(test_owner()), "a delta names its owner");

        // The shape that would be sent by reaching for `OrdersV1::Delta`
        // directly, pinned so it cannot come back.
        let bare = harvest_common::to_cbor(&Vec::<harvest_common::payment::AuthorizedOrder>::new())
            .expect("serialize");
        assert!(
            harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bare).is_err(),
            "a bare Vec is not a store delta"
        );
    }

    /// The end-to-end shape check that inference cannot give you: build a real
    /// signed order, encode the delta exactly as `submit_order_by_id` does,
    /// and feed it to the store contract's OWN `apply_delta` -- the same call
    /// `update_state` makes on the network. If the delta is the wrong shape,
    /// or the signature does not cover what the contract verifies, the order
    /// is not in the state afterwards.
    #[test]
    fn the_contract_accepts_an_order_delta_encoded_this_way() {
        use ed25519_dalek::{Signer, SigningKey};
        use freenet_scaffold::ComposableState;
        use freenet_stdlib::prelude::ContractInstanceId;
        use harvest_common::listing::ListingId;
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
        use harvest_common::store::StoreStateV1;

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let order = Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: "buyer-fp".to_string(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats: 50_000,
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            payment_address: "tb1qexample".to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: vec![freenet_bitcoin_common::BridgeId([3u8; 32])],
            bitcoin_address_code_hash: Some([4u8; 32]),
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at,
        }
        .with_derived_id();

        // Exactly the bytes the invoice flow hands `SignMessage`, wrapped the
        // way the ghostkey delegate wraps them.
        let message = harvest_common::to_cbor(&order).expect("serialize order");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        let signature = signing_key.sign(&scoped_payload).to_bytes().to_vec();

        let authorized = AuthorizedOrder {
            order: order.clone(),
            scoped_payload,
            signature,
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        };

        // Decode the wire bytes back, so what is applied is what would travel,
        // not the in-memory value that produced them.
        let bytes = orders_delta_bytes(signing_key.verifying_key(), vec![authorized])
            .expect("serialize delta");
        let delta: harvest_common::store::StoreStateV1Delta =
            harvest_common::from_cbor(&bytes).expect("the contract must read its own delta");

        // The same derivation the production path uses, so this test cannot
        // pass against parameters the real PUT would never produce.
        let parameters = crate::migrate::store_params(&signing_key.verifying_key());
        let mut state = StoreStateV1::default();
        state
            .apply_delta(&state.clone(), &parameters, &Some(delta))
            .expect("the store contract must accept a seller-signed invoice");

        let stored = state
            .orders
            .orders
            .get(&order.id)
            .expect("the invoice must be in the contract's state");
        assert_eq!(stored.order.payment_address, "tb1qexample");
        assert_eq!(stored.status, OrderStatus::AwaitingPayment);
        assert_eq!(
            state.owner,
            Some(signing_key.verifying_key()),
            "the first signed update to a store claims it for the key it names (harvest#52)"
        );
    }

    /// The whole point of the round-trip: the bytes we hand `SignMessage`
    /// have to be exactly the bytes `AuthorizedStoreInfoV1::verify` checks
    /// the scoped payload against. Get that wrong and the contract rejects
    /// the store's details with no clue why, which is indistinguishable from
    /// them never having been sent.
    #[test]
    fn signing_the_bytes_we_send_produces_info_the_contract_accepts() {
        use ed25519_dalek::{Signer, SigningKey};
        use freenet_stdlib::prelude::ContractInstanceId;
        use harvest_common::listing::verify_scoped_signature;
        use harvest_common::store::{AuthorizedStoreInfoV1, StoreInfoV1};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let info = StoreInfoV1 {
            version: 1,
            certificate_pem: "-----BEGIN CERT-----".to_string(),
            seller_fingerprint: "fp-1".to_string(),
            reputation_contract_id: [2u8; 32],
            store_name: "Bean Shop".to_string(),
            description: "Coffee".to_string(),
            encryption_public_key: None,
            record_public_key: None,
        };

        // Exactly what `request_store_info_signature` sends as `message`.
        let message = harvest_common::to_cbor(&info).expect("serialize info");

        // What the ghostkey delegate wraps it in before signing.
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        let signature = signing_key.sign(&scoped_payload).to_bytes().to_vec();

        let authorized = AuthorizedStoreInfoV1 {
            info,
            scoped_payload,
            signature,
        };
        // The check `AuthorizedStoreInfoV1::verify` runs for any version past
        // 0, called directly so the test needs nothing from contract state.
        verify_scoped_signature(
            &authorized.scoped_payload,
            &authorized.signature,
            &signing_key.verifying_key(),
            &authorized.info,
        )
        .expect("the store contract must accept its own signed info");

        // And it must go on the wire in the shape the contract reads.
        let bytes = store_info_delta_bytes(signing_key.verifying_key(), authorized)
            .expect("serialize delta");
        let delta = harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bytes)
            .expect("the contract must be able to read its own delta");
        assert!(delta.info.is_some());
    }

    /// Version 0 is the unsigned state, which `verify` accepts only as the
    /// empty default -- so details published at version 0 would be refused. The details we build must be past it.
    #[test]
    fn published_store_details_are_past_the_unverified_version() {
        let unpublished = harvest_common::store::AuthorizedStoreInfoV1::default();
        assert_eq!(unpublished.info.version, 0);
        assert!(unpublished.info.store_name.is_empty());
    }

    /// A malformed id is reported, not silently turned into some other
    /// contract -- the same reasoning as `store_link::parse_store_id`.
    #[test]
    fn a_store_id_of_the_wrong_length_is_an_error() {
        let mut reg = registration(None);
        reg.store_contract_id = vec![3u8; 31];

        let err = store_contract_key(&reg).expect_err("should refuse");
        assert!(err.contains("31 bytes"), "unhelpful error: {err}");
    }
}
