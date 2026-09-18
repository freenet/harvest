//! Routes incoming HostResponse messages to appropriate handlers.
//!
//! The Freenet gateway sends responses for contract operations (GET, PUT,
//! Subscribe, Update) and delegate operations. This module deserializes
//! them and updates application state, and triggers follow-up operations
//! (e.g., subscribing to a store's reputation contract after receiving
//! the store state).

use dioxus::logger::tracing::{error, info, warn};
// `Readable` is what puts `.read()` on `APP_STATE`; see `handle_delegate_response`.
use dioxus::prelude::ReadableExt;
use freenet_stdlib::client_api::{ContractResponse, HostResponse};

use harvest_common::{from_cbor, HarvestDelegateResponse};

use super::APP_STATE;

/// Process a single host response from the Freenet gateway.
pub fn handle_response(response: Result<HostResponse, String>) {
    match response {
        Ok(HostResponse::ContractResponse(contract_response)) => {
            handle_contract_response(contract_response);
        }
        Ok(HostResponse::DelegateResponse { key, values }) => {
            handle_delegate_response(key, values);
        }
        Ok(HostResponse::QueryResponse(_)) => {
            // Node queries -- not used by Harvest yet
        }
        Ok(other) => {
            info!("Unhandled host response: {:?}", other);
        }
        Err(e) => {
            error!("Gateway error: {}", e);
        }
    }
}

fn handle_contract_response(response: ContractResponse) {
    match response {
        ContractResponse::GetResponse {
            key,
            contract: _,
            state,
        } => {
            let contract_id = key.as_bytes().to_vec();
            let state_bytes = state.as_ref().to_vec();

            info!("GET response for contract ({} bytes)", state_bytes.len());

            // Offer it to the migration probe FIRST. A probe GETs a SUPERSEDED
            // generation's instance, whose state is perfectly decodable
            // store/reputation/mailbox state -- so letting it fall through to
            // `on_contract_state` would put an old generation on screen as if
            // it were the live store, and would follow its reputation link too.
            #[cfg(target_arch = "wasm32")]
            if super::migrate_ops::deliver_state(key.id(), &state_bytes) {
                return;
            }

            // Likewise the bridge's generation pointers: a pointer record is not
            // store, reputation or mailbox state, and must not reach
            // `on_contract_state` as though it were.
            #[cfg(target_arch = "wasm32")]
            if super::bitcoin_generation_ops::deliver_state(key.id(), &state_bytes) {
                return;
            }

            // Check if this is a store state -- if so, we need to follow
            // the reputation contract link
            let reputation_to_subscribe = check_for_reputation_link(&state_bytes);

            {
                let mut app = APP_STATE.write();
                app.on_contract_state(contract_id, state_bytes);
            }

            // Subscribe to the reputation contract if we found one
            if let Some(reputation_id) = reputation_to_subscribe {
                follow_reputation_link(reputation_id);
            }
        }

        ContractResponse::PutResponse { key } => {
            info!("PUT response for contract {:?}", key);
            // Offered to the migration, which is the only thing that acts on
            // it. Every other PUT this app makes is fire-and-forget by design
            // -- a store creation, a listing, an order -- but a migration may
            // not write its durable "already done" marker until the node has
            // said the recovered state actually landed, and this is the only
            // signal that says so. `put_contract` resolves when the WebSocket
            // SEND succeeds, which is a different claim entirely.
            #[cfg(target_arch = "wasm32")]
            let _consumed = super::migrate_ops::deliver_put_ack(key.id());
        }

        // The node answering, positively, that nothing is stored under this
        // key. This is the ONE signal a migration probe may read as absence;
        // every other way a GET fails to produce state (a timeout, a transport
        // fault, an error the gateway reports without a key) is silence, and
        // silence is recorded as unresolved so the walk can never seal over a
        // predecessor that was merely unreachable.
        //
        // Absence is worth less here than it looks even so: it is
        // unauthenticated, and a contract that exists answers NotFound while it
        // is momentarily unfindable. That is why an all-absent walk still does
        // not seal -- see `migrate::seal_decision`.
        ContractResponse::NotFound { instance_id } => {
            info!("NotFound for contract {instance_id}");
            // Offered to the migration probe, which is the only thing that
            // acts on it. `deliver_absent` is the ONE path a `NotFound` may
            // take into a probe: every other way a GET fails to produce state
            // (a timeout, a transport fault, an error the gateway reports
            // without a key) is silence, recorded as unresolved so the walk
            // can never seal over a predecessor that was merely unreachable.
            #[cfg(target_arch = "wasm32")]
            let _consumed = super::migrate_ops::deliver_absent(&instance_id);
            // And to the generation pointers, for which it is equally the one
            // signal that may be read as absence. Their ids never collide with
            // a probe's, so at most one of the two takes it.
            #[cfg(target_arch = "wasm32")]
            let _pointer = super::bitcoin_generation_ops::deliver_absent(&instance_id);
            // And to an invoice waiting to learn whether its payment address
            // was used before. Absence lets it sign, but it is not proof the
            // address is unused: a dead-ended GET reports NotFound for a
            // contract that exists. See `AppState::on_address_reuse_absent`.
            #[cfg(target_arch = "wasm32")]
            APP_STATE
                .write()
                .on_address_reuse_absent(instance_id.as_bytes());

            // Nothing else acts on it. `AppState` already has a
            // `store_state_unavailable` set that this could feed, and feeding
            // it here is deliberately left alone: this arm sees NotFound for
            // every contract kind, and marking a mailbox or reputation id as
            // an unpublished STORE would be wrong in the set and misleading in
            // the log. Routing it properly is its own change.
        }

        ContractResponse::UpdateResponse { key, summary: _ } => {
            info!("UPDATE response for contract {:?}", key);
        }

        ContractResponse::SubscribeResponse { key, subscribed } => {
            if subscribed {
                info!("Subscribed to contract {:?}", key);
            } else {
                warn!("Subscription failed for contract {:?}", key);
            }
        }

        ContractResponse::UpdateNotification { key, update: _ } => {
            info!("Update notification for contract {:?}", key);
            // Re-GET the authoritative full state rather than trying to
            // apply `update` in place. `update` is very often a genuine
            // delta -- for composable states (store, bitcoin tip/address)
            // that's a *different* wire shape from the full state (e.g.
            // `StoreStateV1Delta` has `orders: Option<Vec<AuthorizedOrder>>`
            // where `StoreStateV1` has `orders: OrdersV1`), so re-parsing
            // delta bytes as full state silently fails and the update gets
            // dropped -- exactly the bug that would have made "realtime"
            // updates invisible. Re-GET is more traffic but always correct;
            // proper client-side delta application would need each
            // contract's `ComposableState::apply_delta` (and its
            // `Parameters`) wired into the UI, which isn't done anywhere in
            // this codebase yet.
            request_full_state(key);
        }

        _ => {
            info!("Unhandled contract response");
        }
    }
}

/// If the state bytes deserialize as a StoreStateV1, extract the reputation
/// contract ID so we can subscribe to it automatically.
fn check_for_reputation_link(state_bytes: &[u8]) -> Option<Vec<u8>> {
    let store_state =
        harvest_common::from_cbor::<harvest_common::store::StoreStateV1>(state_bytes).ok()?;
    let reputation_id = store_state.info.info.reputation_contract_id;
    // Don't follow if it's all zeros (uninitialized)
    if reputation_id == [0u8; 32] {
        return None;
    }
    Some(reputation_id.to_vec())
}

/// Re-GET a contract's full state (re-subscribing is a harmless no-op if we
/// already are). See the long comment at the `UpdateNotification` call site
/// for why this exists instead of applying `update` in place.
fn request_full_state(_key: freenet_stdlib::prelude::ContractKey) {
    #[cfg(target_arch = "wasm32")]
    {
        let instance_id = *_key.id();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = super::get_contract(&instance_id, true).await {
                error!("Failed to re-GET contract after update notification: {}", e);
            }
        });
    }
}

/// Subscribe to a reputation contract that a store links to.
fn follow_reputation_link(_reputation_id: Vec<u8>) {
    info!("Following reputation link -- subscribing to reputation contract");

    #[cfg(target_arch = "wasm32")]
    {
        let reputation_id = _reputation_id;
        wasm_bindgen_futures::spawn_local(async move {
            if reputation_id.len() != 32 {
                error!(
                    "Reputation contract ID is not 32 bytes: {}",
                    reputation_id.len()
                );
                return;
            }
            let mut id_bytes = [0u8; 32];
            id_bytes.copy_from_slice(&reputation_id);
            let contract_id = freenet_stdlib::prelude::ContractInstanceId::new(id_bytes);
            if let Err(e) = super::get_contract(&contract_id, true).await {
                error!("Failed to subscribe to reputation contract: {}", e);
            }
        });
    }
}

/// Which delegate an application message came from.
///
/// Decided by the `DelegateKey` the gateway hands us, never by trying
/// decoders in turn. `HarvestDelegateResponse::Error { message: String }` and
/// `ghostkey_common::GhostkeyResponse::Error { message: String }` are
/// byte-identical externally-tagged CBOR -- `{"Error": {"message": "..."}}`
/// -- so a trial decode that reaches for Harvest first classifies EVERY
/// ghostkey error as a Harvest one. That silently defeated the certificate
/// gate: a failed `GetCertificate` raised a notification and cleared nothing,
/// leaving `pending_store_creation` and `pending_store_edit` waiting on an
/// answer that was never coming.
///
/// The key cannot collide the way the payloads can. It is derived from the
/// delegate's own WASM and parameters, so it identifies the sender outright.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DelegateSender {
    Harvest,
    Ghostkey,
    /// A key matching neither delegate this app registered. Nothing is
    /// decoded: guessing is what caused the bug this enum exists to fix.
    Unknown,
}

/// One decoded delegate message, already attributed to its sender.
#[derive(Debug)]
pub(crate) enum DelegateResponse {
    Harvest(HarvestDelegateResponse),
    Bitcoin(harvest_common::BitcoinDelegateResponse),
    Ghostkey(ghostkey_common::GhostkeyResponse),
}

pub(crate) fn delegate_sender(
    key: &freenet_stdlib::prelude::DelegateKey,
    harvest: Option<&freenet_stdlib::prelude::DelegateKey>,
    ghostkey: Option<&freenet_stdlib::prelude::DelegateKey>,
) -> DelegateSender {
    if harvest == Some(key) {
        DelegateSender::Harvest
    } else if ghostkey == Some(key) {
        DelegateSender::Ghostkey
    } else {
        DelegateSender::Unknown
    }
}

/// Decode one application message using the protocol of the delegate that
/// actually sent it.
///
/// The harvest delegate speaks two enums over one key -- its own responses
/// and its Bitcoin surface -- so that one pair is still separated by a trial
/// decode. That is sound where the cross-delegate version was not: the two
/// share no variant name, so no payload decodes as both, and either way the
/// message is genuinely from the harvest delegate. Add a variant to one that
/// collides with the other and this becomes wrong again.
pub(crate) fn decode_delegate_message(
    sender: DelegateSender,
    payload: &[u8],
) -> Result<DelegateResponse, String> {
    match sender {
        DelegateSender::Harvest => from_cbor::<HarvestDelegateResponse>(payload)
            .map(DelegateResponse::Harvest)
            .or_else(|harvest_err| {
                from_cbor::<harvest_common::BitcoinDelegateResponse>(payload)
                    .map(DelegateResponse::Bitcoin)
                    .map_err(|btc_err| {
                        format!(
                            "not a harvest delegate response ({harvest_err}) nor a Bitcoin \
                             one ({btc_err})"
                        )
                    })
            }),
        DelegateSender::Ghostkey => from_cbor::<ghostkey_common::GhostkeyResponse>(payload)
            .map(DelegateResponse::Ghostkey)
            .map_err(|e| format!("not a ghostkey delegate response ({e})")),
        DelegateSender::Unknown => {
            Err("message from a delegate this app never registered".to_string())
        }
    }
}

pub(crate) fn apply_delegate_response(
    app: &mut crate::state::AppState,
    response: DelegateResponse,
) {
    match response {
        DelegateResponse::Harvest(r) => {
            info!("Harvest delegate response: {:?}", r);
            app.on_delegate_response(r);
        }
        DelegateResponse::Bitcoin(r) => {
            info!("Bitcoin delegate response: {:?}", r);
            app.on_bitcoin_delegate_response(r);
        }
        DelegateResponse::Ghostkey(r) => {
            info!("Ghostkey response: {:?}", r);
            app.on_ghostkey_response(r);
        }
    }
}

fn handle_delegate_response(
    key: freenet_stdlib::prelude::DelegateKey,
    values: Vec<freenet_stdlib::prelude::OutboundDelegateMsg>,
) {
    // Read the registered keys and drop the guard before any write below --
    // APP_STATE is a RefCell underneath and holding both at once panics.
    let sender = {
        let app = APP_STATE.read();
        delegate_sender(
            &key,
            app.harvest_delegate_key.as_ref(),
            app.ghostkey_delegate_key.as_ref(),
        )
    };

    for value in values {
        match value {
            freenet_stdlib::prelude::OutboundDelegateMsg::ApplicationMessage(msg) => {
                match decode_delegate_message(sender, &msg.payload) {
                    Ok(response) => {
                        // Offer it to the migration gate FIRST, and outside
                        // the write guard. A marker answer can release a
                        // parked probe, and releasing one can run through to
                        // `finish`, which writes `APP_STATE` -- taking that
                        // write guard while this one is held panics, because
                        // `APP_STATE` is a `RefCell` underneath. Same ordering,
                        // and same reason, as the GET path above.
                        #[cfg(target_arch = "wasm32")]
                        if super::migrate_ops::deliver_delegate_response(&response) {
                            continue;
                        }
                        apply_delegate_response(&mut APP_STATE.write(), response)
                    }
                    Err(e) => error!("Undecodable delegate response from {:?}: {e}", key),
                }
            }
            freenet_stdlib::prelude::OutboundDelegateMsg::RequestUserInput(req) => {
                info!("Delegate requesting user input: {:?}", req.message);
                // Permission prompts from the ghostkey delegate will arrive here.
                // The Freenet runtime handles displaying these to the user and
                // routing the response back to the delegate.
            }
            _ => {
                info!("Unhandled delegate outbound message");
            }
        }
    }
}
