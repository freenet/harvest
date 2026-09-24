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
pub const INDEX_CONTRACT_WASM: &[u8] = include_bytes!("../../public/contracts/index_contract.wasm");

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

/// The code hash of the reputation contract this build bundles. Cached for
/// the reason [`store_code_hash`] gives.
pub(crate) fn reputation_code_hash() -> [u8; 32] {
    static HASH: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        let hash = *ContractCode::from(REPUTATION_CONTRACT_WASM.to_vec()).hash();
        let bytes: &[u8] = hash.as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    });
    *HASH
}

/// The reputation record a store key addresses under this build (harvest#53
/// Phase C).
///
/// A function of the store key alone, so a reader derives it from the store
/// it is looking at with no lookup, and a buyer can publish a complaint to a
/// store whose seller never opened Harvest after the upgrade. Through
/// `crate::migrate`'s derivation, the one store creation and the migration
/// use, so the three cannot disagree about where a record lives.
pub fn reputation_instance_id(
    store_key: &ed25519_dalek::VerifyingKey,
) -> Result<ContractInstanceId, String> {
    let bytes = crate::migrate::encode_params(&crate::migrate::reputation_params(store_key))?;
    Ok(crate::migrate::current_id(&reputation_code_hash(), &bytes))
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
    /// Rebuilt for the generation whose contract this build bundles, which
    /// the registration names (harvest#164): correct by construction.
    Current,
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

/// Bytes of a store-contract delta carrying one despatch AND the order it is
/// for (harvest#53 Phase B).
///
/// The order rides along so a replica that has not yet seen it keeps the
/// despatch: the store drops a despatch whose order it does not hold
/// (`StoreStateV1::normalize_fulfilment`), and a despatch sent alone to such
/// a replica would wait for the next summary exchange to come back.
fn despatch_delta_bytes(
    owner: ed25519_dalek::VerifyingKey,
    order: harvest_common::payment::AuthorizedOrder,
    despatch: harvest_common::fulfilment::AuthorizedDespatch,
) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        owner: Some(owner),
        orders: Some(vec![order]),
        fulfilment: Some(vec![despatch]),
        ..Default::default()
    })
    .map_err(|e| format!("serialize despatch delta: {e}"))
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
/// contract has a different code hash, so the rebuilt key pairs that older
/// instance with the wrong code. The node addresses by instance and runs the
/// older contract, so the update is refused, or accepted where no buyer reads
/// (harvest#164). A write to our own store therefore never reaches here while
/// the registration names an earlier generation of a store with a store key:
/// see [`current_store_write`]. What still can is a store from before revision
/// 2, whose generation cannot be derived, and one registered by a NEWER build
/// than this tab's, which this build cannot know is current; that is why the
/// caller is told how its key was found and can say so.
pub fn store_contract_key(
    registration: &StoreRegistration,
) -> Result<(ContractKey, KeyOrigin), String> {
    if let Some(bytes) = registration.store_contract_key.as_ref() {
        return harvest_common::from_cbor(bytes)
            .map(|key| (key, KeyOrigin::Recorded))
            .map_err(|e| format!("deserialize stored contract key: {e}"));
    }

    Ok((
        reconstruct_store_key(&registration.store_contract_id)?,
        KeyOrigin::Reconstructed,
    ))
}

/// A store's `ContractKey` built from its contract id alone.
///
/// The reconstruction half of [`store_contract_key`], split out because it
/// needs nothing but the id: a `ContractKey` is an instance id plus a code
/// hash, the instance id IS the store contract id, and the code hash is the
/// hash of the store contract this build bundles. Neither half comes from
/// `my_stores`, which is what lets a BUYER address a seller's store contract
/// (harvest#75) -- a store nobody on this device has a registration for.
///
/// It carries the same limit [`store_contract_key`] records: for a store
/// published under an OLDER store contract, the rebuilt key pairs that
/// instance with the wrong code, and the node runs the older contract. That is
/// why a caller is told how its key was found and says so when a send fails.
pub fn reconstruct_store_key(store_contract_id: &[u8]) -> Result<ContractKey, String> {
    let instance_id: [u8; 32] = store_contract_id.try_into().map_err(|_| {
        format!(
            "store contract id is {} bytes, not 32",
            store_contract_id.len()
        )
    })?;
    let code_hash = *ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash();
    Ok(ContractKey::from_id_and_code(
        ContractInstanceId::new(instance_id),
        code_hash,
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
        another_store: _,
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
        rsa_public_key_der.ok_or("the store's record key had not arrived; nothing was created")?;
    use dioxus::logger::tracing::{info, warn};
    use dioxus::prelude::{ReadableExt, WritableExt};
    use freenet_stdlib::prelude::*;
    use std::sync::Arc;

    let seller_vk = ed25519_dalek::VerifyingKey::from_bytes(&seller_verifying_key_bytes)
        .map_err(|e| format!("invalid verifying key: {e}"))?;
    // The store's own key (harvest#93): it owns the store, its code is the
    // store's address, and it signs everything the store holds -- and since
    // harvest#53 Phase C it alone addresses the store's reputation record.
    // The Ghost Key above still addresses the mailbox.
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
    let reputation_params = crate::migrate::reputation_params(&store_vk);
    let reputation_params_bytes = harvest_common::to_cbor(&reputation_params)
        .map_err(|e| format!("serialize reputation params: {e}"))?;

    // Only what the contract accepts: a genuine certificate in canonical
    // armour, or none (`ghostkey_cert::record_certificate`). Anything else
    // would make this PUT, and with it the store's creation, fail.
    let reputation_state = harvest_common::reputation::ReputationStateV1 {
        owner_certificate_pem: crate::ghostkey_cert::record_certificate(&certificate_pem),
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
///
/// Never the key of an EARLIER generation (harvest#164): see
/// [`current_store_write`], which this waits on.
#[cfg(target_arch = "wasm32")]
async fn owned_store_key(
    store_contract_id: &[u8],
    whats_missing: &str,
) -> Result<(ContractKey, KeyOrigin, ed25519_dalek::VerifyingKey), String> {
    use dioxus::prelude::ReadableExt;

    let registered = current_store_write(store_contract_id)
        .await?
        .ok_or_else(|| format!("this store is not one of yours -- {whats_missing}"))?;
    let state = super::APP_STATE.read();
    let owner = state
        .delta_owner_key(&registered)
        .ok_or_else(|| format!("{} -- {whats_missing}", crate::state::NO_STORE_KEY_MESSAGE))?;
    let (key, origin) = state.owned_write_key(&registered)?;
    Ok((key, origin, owner))
}

/// How long a write to one of our stores waits for this session to move to
/// the store's current generation before it is refused (harvest#164).
///
/// The move happens as soon as the node answers for the current generation,
/// which it does at once when an earlier load moved the store, or when the
/// migration walk's forward lands. On the E2E node the walk forwarded a live
/// store a little over two minutes after load, twice; this allows about
/// twice that.
pub const STORE_MOVE_WAIT_MS: f64 = 300_000.0;

/// How often a waiting write asks the node again.
#[cfg(target_arch = "wasm32")]
const STORE_MOVE_POLL_MS: u32 = 5_000;

/// Said when a write to a store still on an earlier generation gives up.
pub const STORE_STILL_MOVING: &str = "your store's current version is not on the network \
    yet, so nothing was sent to it. Harvest moves your store there from its earlier version \
    after the page loads; try again in a few minutes, and reload if this keeps happening";

/// What a write to one of our stores does next (harvest#164).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteStep {
    /// Send it to this id: the registration names the current generation.
    Send(Vec<u8>),
    /// Ask the node for this id, the current generation, and look again.
    /// Its state arriving moves the session there
    /// (`AppState::adopt_if_current_generation`).
    Probe(Vec<u8>),
    /// Waited [`STORE_MOVE_WAIT_MS`] for a store still on an earlier
    /// generation: refuse, and never send it there.
    GiveUp,
    /// No registration on this device names the store.
    NotOurs,
}

/// [`WriteStep`] for `target`, `waited_ms` into the wait.
pub fn write_step(target: crate::state::StoreWriteTarget, waited_ms: f64) -> WriteStep {
    use crate::state::StoreWriteTarget;
    match target {
        StoreWriteTarget::Ready(id) => WriteStep::Send(id),
        StoreWriteTarget::NotOurs => WriteStep::NotOurs,
        StoreWriteTarget::Moving { .. } if waited_ms >= STORE_MOVE_WAIT_MS => WriteStep::GiveUp,
        StoreWriteTarget::Moving { current, .. } => WriteStep::Probe(current),
    }
}

/// Wait until a write to one of our stores may go to the id this returns:
/// the store's CURRENT generation, never an earlier one (harvest#164).
/// `None` when no registration on this device names the store.
///
/// See [`write_step`] for each turn of the wait. A write is never sent to an
/// earlier generation: an older contract refuses a field it does not know,
/// and one that accepts the write holds it where no buyer reads.
#[cfg(target_arch = "wasm32")]
async fn current_store_write(store_contract_id: &[u8]) -> Result<Option<Vec<u8>>, String> {
    use dioxus::prelude::ReadableExt;

    let started = js_sys::Date::now();
    loop {
        let target = super::APP_STATE
            .read()
            .store_write_target(store_contract_id);
        match write_step(target, js_sys::Date::now() - started) {
            WriteStep::Send(id) => return Ok(Some(id)),
            WriteStep::NotOurs => return Ok(None),
            WriteStep::GiveUp => return Err(STORE_STILL_MOVING.to_string()),
            WriteStep::Probe(current) => {
                probe_current_generation(&current).await;
                // The answer, if it had state, has moved the session by now:
                // a waiter resumes only after the handler that woke it.
                if matches!(
                    super::APP_STATE
                        .read()
                        .store_write_target(store_contract_id),
                    crate::state::StoreWriteTarget::Moving { .. }
                ) {
                    gloo_timers::future::TimeoutFuture::new(STORE_MOVE_POLL_MS).await;
                }
            }
        }
    }
}

/// Keep asking for our store's current generation until this session has
/// moved there (harvest#164), backing off from 15 s to 5 min.
///
/// The walk's forward creates the current generation on a first load, but a
/// store forward stops being waited on after 12 s
/// (`migrate_seal::forward_give_up_ms`), and a forward PUT does not
/// subscribe, so its landing may never reach this session on its own. Until
/// it does, reads stay on the earlier generation and instant checkout is off.
///
/// One per store: every `StoreList` answer asks, and a store already being
/// asked about is not asked about twice.
#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn_move_to_current(current: Vec<u8>) {
    thread_local! {
        static ASKING: std::cell::RefCell<std::collections::HashSet<Vec<u8>>> =
            std::cell::RefCell::default();
    }
    if !ASKING.with(|asking| asking.borrow_mut().insert(current.clone())) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::ReadableExt;
        let mut wait_ms: u32 = 15_000;
        while super::APP_STATE.read().is_moving_to(&current) {
            probe_current_generation(&current).await;
            gloo_timers::future::TimeoutFuture::new(wait_ms).await;
            wait_ms = (wait_ms * 2).min(300_000);
        }
        ASKING.with(|asking| asking.borrow_mut().remove(&current));
    });
}

/// Ask the node for our store's current generation, at most once per
/// [`STORE_MOVE_POLL_MS`] however many writes are waiting on it.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn probe_current_generation(current: &[u8]) {
    thread_local! {
        static ASKED: std::cell::RefCell<std::collections::HashMap<Vec<u8>, f64>> =
            std::cell::RefCell::default();
    }
    let now = js_sys::Date::now();
    let due = ASKED.with(|asked| {
        let mut asked = asked.borrow_mut();
        let due = asked
            .get(current)
            .is_none_or(|at| now - at >= f64::from(STORE_MOVE_POLL_MS));
        if due {
            asked.insert(current.to_vec(), now);
        }
        due
    });
    let Ok(instance) = <[u8; 32]>::try_from(current) else {
        return;
    };
    if due {
        super::prime::reread(ContractInstanceId::new(instance)).await;
    }
}

/// The contract key of ANY store a settlement may be published to, ours or
/// not, how it was found, and the owner the delta has to name (harvest#75).
///
/// # Why this exists beside `owned_store_key`
///
/// `Paid` is authorized by Bitcoin evidence and by no signature at all
/// (`AuthorizedOrder::fields_used` marks `status_signature` unused for it),
/// and the store contract adds no origin check: `update_state` reads nothing
/// but the state and the parameters, and `OrdersV1::apply_delta` verifies each
/// record against the owner key the CURRENT STATE names. So any peer holding
/// the claims may publish the transition, and the buyer is the party who
/// cares soonest.
///
/// What stopped them was this module, not the network:
/// [`owned_store_key`] resolves the key out of `my_stores` and fails with
/// "this store is not one of yours", so a buyer's settlement had never once
/// been sent. A `ContractKey` needs no registration -- see
/// [`reconstruct_store_key`].
///
/// # Why it is still not `owned_store_key`'s replacement
///
/// Everything else a store publishes -- a listing, its details, an invoice --
/// is authorized by the OWNER'S SIGNATURE, so resolving a key for one without
/// a registration would only build an unsignable update. Those keep asking
/// for ownership. This is for the one transition that needs no signature, and
/// it is named for that rather than for the key it returns, so a later caller
/// cannot reach for it by accident.
///
/// A store we DO own still prefers its recorded key when it has one: the
/// reconstruction is right only for a store published under the store
/// contract this build bundles, and the recorded key is right for any.
#[cfg(target_arch = "wasm32")]
async fn settlement_store_key(
    store_contract_id: &[u8],
) -> Result<(ContractKey, KeyOrigin, ed25519_dalek::VerifyingKey), String> {
    use dioxus::prelude::ReadableExt;

    // One of ours goes where every other write to it goes: its current
    // generation, never an earlier one (harvest#164).
    let ours = current_store_write(store_contract_id).await?;
    let state = super::APP_STATE.read();
    let owner = state
        .settlement_owner_key(ours.as_deref().unwrap_or(store_contract_id))
        .or_else(|| state.settlement_owner_key(store_contract_id))
        .ok_or("this store's owner key is not known here, so a settlement cannot name it")?;
    match ours {
        Some(registered) => {
            let (key, origin) = state.owned_write_key(&registered)?;
            Ok((key, origin, owner))
        }
        None => Ok((
            reconstruct_store_key(store_contract_id)?,
            KeyOrigin::Reconstructed,
            owner,
        )),
    }
}

/// Whether `order` may be published by a party that does not hold the store
/// key: a `Paid` settlement (authorized by its evidence, harvest#75), or a
/// `Cancelled` record the order's BUYER signed with their receipt key
/// (harvest#53 Phase B). Anything else is refused before it is sent.
///
/// The buyer's cancel is checked in full against `owner`, the key the delta
/// names, and refused unless it is the buyer's signature rather than the
/// store key's: a seller's cancel is sent through [`submit_order_by_id`], so
/// a store-key-signed record arriving here means a caller is on the wrong
/// path, and saying so beats sending it quietly.
pub(crate) fn keyless_publishable(
    order: &harvest_common::payment::AuthorizedOrder,
    owner: &ed25519_dalek::VerifyingKey,
) -> Result<(), String> {
    use harvest_common::payment::OrderStatus;
    match order.status {
        OrderStatus::Paid => Ok(()),
        OrderStatus::Cancelled => {
            order
                .verify(owner)
                .map_err(|e| format!("this cancellation would be refused: {e}"))?;
            let buyer_signed = order.order.buyer_receipt_key.is_some_and(|key| {
                let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key) else {
                    return false;
                };
                let (Some(sp), Some(sig)) = (&order.status_scoped_payload, &order.status_signature)
                else {
                    return false;
                };
                harvest_common::listing::verify_scoped_signature(
                    sp,
                    sig,
                    &key,
                    &(order.order.id.clone(), OrderStatus::Cancelled),
                )
                .is_ok()
            });
            if buyer_signed {
                Ok(())
            } else {
                Err(
                    "only the buyer's own cancellation may be published without the \
                     store's key"
                        .to_string(),
                )
            }
        }
        OrderStatus::AwaitingPayment | OrderStatus::PaymentReversed => Err(format!(
            "only a Paid settlement or the buyer's own cancellation may be published \
             without the store's key; this record is {:?}",
            order.status
        )),
    }
}

/// Publish a record a party without the store key may send -- a `Paid`
/// settlement, or the buyer's own cancellation ([`keyless_publishable`]) --
/// to its store contract.
///
/// Separate from [`submit_order_by_id`] because it resolves the key through
/// [`settlement_store_key`] rather than through ownership: the record is
/// authorized by the evidence or the buyer signature it carries, so a buyer
/// may send it (harvest#75, harvest#53 Phase B). Everything about the send
/// itself is identical.
#[cfg(target_arch = "wasm32")]
pub async fn submit_settled_order_by_id(
    store_contract_id: &[u8],
    order: harvest_common::payment::AuthorizedOrder,
) -> Result<(), String> {
    use dioxus::logger::tracing::{info, warn};
    use freenet_stdlib::prelude::*;

    // The keyless path is justified by "the record is authorized by the
    // evidence it carries", and that is true of `Paid` SPECIFICALLY. Making
    // it structural rather than a property of the one current call site is
    // the same argument `AuthorizedOrder::fields_used` makes for staying
    // exhaustive: nothing here should depend on a caller remembering.
    //
    // Since harvest#53 Phase B there is exactly one other record a party
    // without the store key may publish: the BUYER's cancel of an unpaid
    // order, authorized by the receipt key the seller signed into its terms.
    // That is `keyless_publishable`, and it is decided on the record itself,
    // against the owner key the delta will name, rather than on the caller.
    // `PaymentReversed` needs retraction evidence and `AwaitingPayment`
    // loses every merge at rank 0, so neither is sent from here. Raised by
    // the authorization lens reviewing harvest#75.
    let (contract_key, origin, owner) = settlement_store_key(store_contract_id).await?;
    keyless_publishable(&order, &owner)?;
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
             settlement cannot be published."
        ),
        KeyOrigin::Recorded | KeyOrigin::Current => e,
    })?;

    info!("Published the settled order {} to its store contract", id);
    Ok(())
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
        owned_store_key(store_contract_id, "nothing to add a listing to").await?;
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
        KeyOrigin::Recorded | KeyOrigin::Current => e,
    })?;

    info!("Submitted listing '{}' to store contract", title);
    Ok(())
}

/// Publish a listing's availability, already signed by the store key, to one
/// of our stores (harvest#70).
///
/// A delta carrying only `listing_statuses`, under the same shape rule as
/// `listings_delta_bytes`.
#[cfg(target_arch = "wasm32")]
pub async fn submit_listing_status_by_id(
    store_contract_id: &[u8],
    status: harvest_common::listing::AuthorizedListingStatus,
) -> Result<(), String> {
    use freenet_stdlib::prelude::*;

    let (contract_key, _origin, owner) =
        owned_store_key(store_contract_id, "nothing to update a listing in").await?;
    let delta_bytes = harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        owner: Some(owner),
        listing_statuses: Some(vec![status]),
        ..Default::default()
    })
    .map_err(|e| format!("serialize listing status delta: {e}"))?;
    super::update_contract(
        &contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await
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
pub fn spawn_publish_copy(
    store_contract_id: Vec<u8>,
    copy: harvest_common::custody::AuthorizedCopy,
) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::WritableExt;
        use freenet_stdlib::prelude::*;
        let result = async {
            let (contract_key, _origin, owner) =
                owned_store_key(&store_contract_id, "cannot back its key up").await?;
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
        owned_store_key(store_contract_id, "cannot publish its details").await?;

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

/// Publish the seller's despatch of one of their paid orders (harvest#53
/// Phase B), with the order alongside (see [`despatch_delta_bytes`]).
///
/// Through [`owned_store_key`], like an invoice: only the store key signs a
/// despatch, so only its holder has one to send.
#[cfg(target_arch = "wasm32")]
pub async fn submit_despatch_by_id(
    store_contract_id: &[u8],
    order: harvest_common::payment::AuthorizedOrder,
    despatch: harvest_common::fulfilment::AuthorizedDespatch,
) -> Result<(), String> {
    use dioxus::logger::tracing::{info, warn};
    use freenet_stdlib::prelude::*;

    let (contract_key, origin, owner) =
        owned_store_key(store_contract_id, "cannot record a despatch on it").await?;
    if origin == KeyOrigin::Reconstructed {
        warn!("Store contract key rebuilt from the bundled store contract");
    }
    let id = order.order.id.short();
    let delta_bytes = despatch_delta_bytes(owner, order, despatch)?;
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
             despatch cannot be recorded."
        ),
        KeyOrigin::Recorded | KeyOrigin::Current => e,
    })?;
    info!(
        "Published the despatch of order {} to its store contract",
        id
    );
    Ok(())
}

/// The state a buyer publishes to put one complaint on a store's record:
/// the complaint alone, with no certificate (the seller's is back-filled by
/// the contract's merge from whichever side has one).
pub(crate) fn complaint_state_bytes(
    complaint: harvest_common::reputation::Complaint,
) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::reputation::ReputationStateV1 {
        owner_certificate_pem: String::new(),
        complaints: vec![complaint],
    })
}

/// Publish a buyer's complaint to the store's reputation record (harvest#53
/// Phase C).
///
/// A PUT of the record's contract with a state holding just this complaint,
/// not an UPDATE: the record is addressed by the store key alone, and for a
/// store whose seller has not opened Harvest since the upgrade the instance
/// may not exist yet. A PUT creates it if absent and is merged by the
/// contract if present, which keeps the complaint independent of anything
/// the seller does, the receipted design's point.
///
/// `follow` subscribes to the record afterwards, for a store this tab shows.
/// The re-assert sweep (`AppState::reassert_kept_complaints`) passes `false`:
/// a record for a store not shown has nowhere to be shown.
#[cfg(target_arch = "wasm32")]
pub async fn submit_complaint(
    store_key: ed25519_dalek::VerifyingKey,
    complaint: harvest_common::reputation::Complaint,
    follow: bool,
) -> Result<(), String> {
    use dioxus::logger::tracing::info;
    use freenet_stdlib::prelude::*;
    use std::sync::Arc;

    let id = complaint.order_id().short();
    let params = crate::migrate::encode_params(&crate::migrate::reputation_params(&store_key))?;
    let code = ContractCode::from(REPUTATION_CONTRACT_WASM.to_vec());
    let wrapped = WrappedContract::new(Arc::new(code), params);
    let instance_id = *wrapped.key().id();
    let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
    super::put_contract(
        container,
        WrappedState::new(complaint_state_bytes(complaint)?),
    )
    .await?;
    info!("Published a complaint about order {id} to the store's reputation record");
    if !follow {
        return Ok(());
    }
    // Follow the record, so the complaint shows here once the network has it
    // -- the store page's own subscription may have found nothing, if this
    // PUT is what created the record.
    //
    // The complaint is published once the PUT succeeded, so a failure here
    // is not the complaint's: reporting it as one released the sent marker
    // and invited a second complaint about an order already complained
    // about (review round 1 of #143, P2-8). Logged, and the store page's own
    // subscription still brings the record in.
    if let Err(e) = super::get_contract(&instance_id, true).await {
        dioxus::logger::tracing::warn!(
            "The complaint about order {id} was published, but following the record failed: {e}"
        );
    }
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
        owned_store_key(store_contract_id, "cannot issue an invoice on it").await?;
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
        KeyOrigin::Recorded | KeyOrigin::Current => e,
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

    /// The body of one `fn` in this file's non-test source, by name.
    fn body_of(name: &str) -> &'static str {
        let src = include_str!("store_ops.rs");
        let src = &src[..src.find("#[cfg(test)]\nmod tests").expect("tests module")];
        let start = src
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("fn {name} not found"));
        let rest = &src[start..];
        let end = rest.find("\n}\n").map_or(rest.len(), |e| e + 3);
        &rest[..end]
    }

    /// **No write to one of our stores is keyed off the registration's id
    /// until it names the current generation (harvest#164).** The
    /// registration names the generation the store was created under until
    /// this session moves, so a lookup by it sent listings, invoices and
    /// despatches to an earlier generation on every load: refused by an
    /// older contract, or kept where no buyer reads. Every owner write and
    /// every settlement to a store of ours goes through
    /// `current_store_write`, which sends only on `WriteStep::Send`, and the
    /// key comes from `AppState::owned_write_key` for the id it returned.
    ///
    /// Mutated red by resolving `owned_store_key` straight from `my_stores`
    /// again, by dropping `current_store_write` from `settlement_store_key`,
    /// and by sending on anything but `Send`.
    #[test]
    fn every_write_to_our_store_goes_to_its_current_generation() {
        let squash = |body: &str| body.split_whitespace().collect::<String>();
        assert!(
            squash(body_of("owned_store_key"))
                .contains("letregistered=current_store_write(store_contract_id).await?"),
            "owned_store_key must write to the id current_store_write returned, and fail with it"
        );
        let settlement = squash(body_of("settlement_store_key"));
        assert!(
            settlement.contains("letours=current_store_write(store_contract_id).await?;"),
            "settlement_store_key must fail when the wait does"
        );
        assert!(settlement
            .contains("Some(registered)=>{let(key,origin)=state.owned_write_key(&registered)?;"));
        for name in ["owned_store_key", "settlement_store_key"] {
            assert!(
                body_of(name).contains("owned_write_key(&registered)"),
                "{name} must key the write by the id current_store_write returned"
            );
        }
        let src = include_str!("store_ops.rs");
        let src = &src[..src.find("#[cfg(test)]\nmod tests").expect("tests module")];
        assert_eq!(
            src.matches("store_contract_id ==").count() + src.matches("== s.store").count(),
            0,
            "a store write looked a registration up by id itself"
        );
        let wait = body_of("current_store_write");
        assert_eq!(wait.matches("Ok(Some(").count(), 1);
        assert!(wait.contains("\n            WriteStep::Send(id) => return Ok(Some(id)),\n"));
        assert!(wait.contains(".store_write_target(store_contract_id);"));
        assert!(wait.contains("write_step(target, js_sys::Date::now() - started)"));
        // And every owner write goes through one of the two.
        for writer in [
            "submit_listing_by_id",
            "submit_listing_status_by_id",
            "spawn_publish_copy",
            "submit_store_info_by_id",
            "submit_despatch_by_id",
            "submit_order_by_id",
        ] {
            assert!(
                body_of(writer).contains("owned_store_key("),
                "{writer} must resolve its key through owned_store_key"
            );
        }
        assert!(body_of("submit_settled_order_by_id").contains("settlement_store_key("));
        // One send per writer above: a new store write has to join the list.
        assert_eq!(src.matches("super::update_contract(").count(), 7);
    }

    /// Each turn of a waiting write (harvest#164): a store on its current
    /// generation is written at once, one still on an earlier generation is
    /// asked about and never written, and after the wait it is refused.
    #[test]
    fn a_write_waits_for_the_current_generation_and_then_gives_up() {
        use crate::state::StoreWriteTarget;
        let moving = StoreWriteTarget::Moving {
            registered: vec![1; 32],
            current: vec![2; 32],
        };
        assert_eq!(
            write_step(StoreWriteTarget::Ready(vec![2; 32]), 0.0),
            WriteStep::Send(vec![2; 32])
        );
        assert_eq!(
            write_step(moving.clone(), 0.0),
            WriteStep::Probe(vec![2; 32])
        );
        assert_eq!(
            write_step(moving.clone(), STORE_MOVE_WAIT_MS - 1.0),
            WriteStep::Probe(vec![2; 32])
        );
        assert_eq!(write_step(moving, STORE_MOVE_WAIT_MS), WriteStep::GiveUp);
        assert_eq!(
            write_step(StoreWriteTarget::NotOurs, STORE_MOVE_WAIT_MS),
            WriteStep::NotOurs
        );
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

    /// **A buyer can address a seller's store contract with no registration
    /// at all (harvest#75).**
    ///
    /// This is the whole of #75's key problem. `Paid` needs no signature, so
    /// a buyer holding the Bitcoin evidence may publish it -- but every path
    /// to a `ContractKey` went through `my_stores`, and a buyer has no
    /// registration for the seller's store. Both halves of the key are
    /// derivable without one: the instance id IS the store contract id, and
    /// the code hash is the bundled contract's.
    ///
    /// Asserted against `store_contract_key`'s reconstructed answer rather
    /// than against a hand-built key, so the two cannot drift into addressing
    /// different contracts for one store.
    #[test]
    fn a_store_can_be_addressed_without_owning_it() {
        let rebuilt = reconstruct_store_key(&[3u8; 32]).expect("should rebuild");
        let (via_registration, origin) =
            store_contract_key(&registration(None)).expect("should rebuild");

        assert_eq!(origin, KeyOrigin::Reconstructed);
        assert_eq!(rebuilt.id().as_bytes(), &[3u8; 32]);
        assert_eq!(rebuilt.id(), via_registration.id());
        // `ContractKey`'s `PartialEq` ignores the code hash, so comparing the
        // keys would pass with two different contracts -- the same trap
        // `the_two_ways_to_address_a_mailbox_agree` records.
        assert_eq!(
            rebuilt.code_hash(),
            via_registration.code_hash(),
            "the two ways to address one store must name the same contract"
        );
        assert_eq!(
            rebuilt.code_hash(),
            ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash(),
            "the code hash must come from the bundled store contract"
        );

        assert!(
            reconstruct_store_key(&[3u8; 31]).is_err(),
            "an id that is not 32 bytes is refused rather than padded"
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
            request_id: None,
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
            buyer_receipt_key: None,
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

    /// A buyer-keyed order, signed by `seller` the way the store key signs,
    /// for the Phase B tests below.
    fn phase_b_order(
        seller: &ed25519_dalek::SigningKey,
        buyer: &ed25519_dalek::SigningKey,
    ) -> harvest_common::payment::AuthorizedOrder {
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
        let order = Order {
            request_id: None,
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
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
            buyer_receipt_key: Some(buyer.verifying_key().to_bytes()),
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
        }
        .with_derived_id();
        let (scoped_payload, signature) = sign_as_store_key(seller, &order);
        AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    fn sign_as_store_key<T: serde::Serialize>(
        key: &ed25519_dalek::SigningKey,
        value: &T,
    ) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer;
        let envelope = harvest_common::backing::store_key_envelope(
            harvest_common::to_cbor(value).expect("serialize"),
        )
        .expect("envelope");
        let signature = key.sign(&envelope).to_bytes().to_vec();
        (envelope, signature)
    }

    /// harvest#53 Phase B: the despatch delta, decoded from its wire bytes,
    /// lands in the contract's state -- on a replica that already holds the
    /// order AND on one that has never seen it, which is why the order rides
    /// along.
    #[test]
    fn the_contract_accepts_a_despatch_delta_encoded_this_way() {
        use freenet_scaffold::ComposableState;
        use harvest_common::fulfilment::{AuthorizedDespatch, Despatch};
        use harvest_common::store::StoreStateV1;

        let seller = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let buyer = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let order = phase_b_order(&seller, &buyer);
        let despatch = Despatch {
            order_id: order.order.id.clone(),
            anchor: freenet_bitcoin_common::BlockAnchor {
                height: 900,
                hash: freenet_bitcoin_common::BlockHash([9u8; 32]),
            },
        };
        let (scoped_payload, signature) = sign_as_store_key(&seller, &despatch);
        let despatch = AuthorizedDespatch {
            despatch,
            scoped_payload,
            signature,
        };
        let bytes = despatch_delta_bytes(seller.verifying_key(), order.clone(), despatch)
            .expect("serialize delta");
        let delta: harvest_common::store::StoreStateV1Delta =
            harvest_common::from_cbor(&bytes).expect("the contract must read its own delta");
        let parameters = crate::migrate::store_params(&seller.verifying_key());

        // A replica that has never seen the order.
        let mut fresh = StoreStateV1::default();
        fresh
            .apply_delta(&fresh.clone(), &parameters, &Some(delta.clone()))
            .expect("the store contract accepts the despatch");
        assert!(fresh.fulfilment.records.len() == 1, "the despatch is kept");
        fresh.verify(&fresh, &parameters).expect("and verifies");

        // One that already holds it.
        let mut holding = StoreStateV1::default();
        holding
            .apply_delta(
                &holding.clone(),
                &parameters,
                &Some(
                    harvest_common::from_cbor(
                        &orders_delta_bytes(seller.verifying_key(), vec![order]).unwrap(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        holding
            .apply_delta(&holding.clone(), &parameters, &Some(delta))
            .expect("applies over the held order");
        assert_eq!(holding, fresh);
    }

    /// harvest#53 Phase B: the keyless path takes a Paid record and the
    /// BUYER's cancellation, and refuses the store key's cancellation (that
    /// goes through the owned path), an unsigned one, and anything else.
    #[test]
    fn only_a_settlement_or_the_buyers_own_cancel_is_published_without_the_store_key() {
        use harvest_common::payment::OrderStatus;
        let seller = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let buyer = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let owner = seller.verifying_key();
        let base = phase_b_order(&seller, &buyer);
        let cancelled_by = |key: &ed25519_dalek::SigningKey| {
            let (sp, sig) =
                sign_as_store_key(key, &(base.order.id.clone(), OrderStatus::Cancelled));
            harvest_common::payment::AuthorizedOrder {
                status: OrderStatus::Cancelled,
                status_scoped_payload: Some(sp),
                status_signature: Some(sig),
                ..base.clone()
            }
        };

        keyless_publishable(&cancelled_by(&buyer), &owner).expect("the buyer's own cancel");
        // The buyer's signature is genuine, but the terms are not this
        // store's: the whole record is checked, not just the buyer's half.
        let other_store = ed25519_dalek::SigningKey::from_bytes(&[14u8; 32]).verifying_key();
        assert!(keyless_publishable(&cancelled_by(&buyer), &other_store).is_err());
        let by_seller = keyless_publishable(&cancelled_by(&seller), &owner)
            .expect_err("the seller's cancel is not a keyless record");
        assert!(by_seller.contains("buyer's own"), "{by_seller}");
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        assert!(keyless_publishable(&cancelled_by(&stranger), &owner).is_err());
        assert!(
            keyless_publishable(&base, &owner).is_err(),
            "AwaitingPayment"
        );
        let mut reversed = base.clone();
        reversed.status = OrderStatus::PaymentReversed;
        assert!(keyless_publishable(&reversed, &owner).is_err());
        // Paid passes this gate on its evidence; the contract checks that.
        let mut paid = base.clone();
        paid.status = OrderStatus::Paid;
        keyless_publishable(&paid, &owner).expect("a settlement");
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
