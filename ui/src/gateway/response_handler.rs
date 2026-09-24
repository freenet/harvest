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
            info!(
                "Unhandled host response: {}",
                super::log_summary::host_response_summary(&other)
            );
        }
        Err(e) => {
            error!("Gateway error: {}", e);
            // Parsed first: a write to `APP_STATE` re-renders the app, and
            // most gateway errors change nothing in it.
            if refused_update(&e).is_some() {
                apply_gateway_error(&mut APP_STATE.write(), &e);
            }
        }
    }
}

/// What a gateway error changes in the app: a refused update is said
/// (harvest#161). Split from `handle_response`, whose `APP_STATE` needs a
/// Dioxus runtime, so it can be driven on the host.
pub(crate) fn apply_gateway_error(state: &mut crate::state::AppState, error: &str) {
    if let Some((contract_id, reason)) = refused_update(error) {
        state.on_update_refused(&contract_id, reason);
    }
}

/// The contract an UPDATE refusal names, and the node's reason (harvest#161).
///
/// freenet-core reports a refused update as an error that names the contract
/// only in its English text ("update error for contract <id>, reason: ...")
/// and carries no request id; see `prime`'s module docs for the same limit.
/// Anything not in that shape is `None`, so a change of wording loses the
/// notice, never mis-attributes it.
pub(crate) fn refused_update(error: &str) -> Option<(Vec<u8>, &str)> {
    const MARKER: &str = "update error for contract ";
    let rest = &error[error.find(MARKER)? + MARKER.len()..];
    let (id, rest) = rest.split_once(", reason: ")?;
    // Only the contract's own verdict. The same wording carries conditions a
    // retry clears (the node not holding the contract yet, a storage budget),
    // which are not a refusal of what was sent.
    if !rest.contains("invalid contract update") {
        return None;
    }
    let id = bs58::decode(id.trim()).into_vec().ok()?;
    if id.len() != 32 {
        return None;
    }
    // The node nests its reasons; the innermost is the one a person can act on.
    let reason = rest.rsplit("reason: ").next().unwrap_or(rest).trim();
    Some((id, reason))
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

            // Any answer with state proves the node now holds this contract,
            // which is what a write waiting to be sent needs to know
            // (harvest#119). First, before the early returns below: which
            // request asked is irrelevant to that. The woken writers run
            // after this handler returns, so the state below is applied
            // before any of them looks.
            super::prime::deliver_answer(key.id(), super::prime::Primed::Held);

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
            // An answer, so a write waiting on it stops waiting (harvest#119).
            super::prime::deliver_answer(&instance_id, super::prime::Primed::Absent);
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
            // And to a store's reputation record, so the store page says
            // "no record found" rather than "Clean record" (#143 review
            // round 1, P1-5). Only a record id matches, so any other
            // contract's NotFound passes through untouched.
            #[cfg(target_arch = "wasm32")]
            APP_STATE.write().on_record_absent(instance_id.as_bytes());

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

/// If the state bytes deserialize as a StoreStateV1, the reputation record
/// its store key addresses, so we can subscribe to it automatically.
///
/// Derived from the store's OWNER key (harvest#53 Phase C), which the store
/// contract authenticates against its own address, rather than read from the
/// details' `reputation_contract_id`: every store published before Phase C
/// names an RSA generation's record there, and a version-0 detail is signed
/// by nobody. `AppState::on_contract_state` derives the same id through the
/// same function, which is what matches the record's state to its store.
fn check_for_reputation_link(state_bytes: &[u8]) -> Option<Vec<u8>> {
    let store_state =
        harvest_common::from_cbor::<harvest_common::store::StoreStateV1>(state_bytes).ok()?;
    let owner = store_state.owner?;
    super::store_ops::reputation_instance_id(&owner)
        .ok()
        .map(|id| id.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal the E2E seller's page never showed (harvest#161), in the
    /// node's own words.
    #[test]
    fn a_refused_update_names_its_contract_and_reason() {
        let seen = "client error: error while executing operation in the network: UPDATE \
                    failed: update error for contract \
                    2xaQ7k6oGhns9MTKjbTzA3GaZH8PfeCft85FzK7srwRf, reason: execution error: \
                    invalid contract update, reason: scoped payload content does not match \
                    expected data";
        let (id, reason) = refused_update(seen).expect("parsed");
        assert_eq!(
            id,
            bs58::decode("2xaQ7k6oGhns9MTKjbTzA3GaZH8PfeCft85FzK7srwRf")
                .into_vec()
                .unwrap()
        );
        assert_eq!(
            reason,
            "scoped payload content does not match expected data"
        );
        assert_eq!(refused_update("GET failed: contract not found"), None);
        assert_eq!(
            refused_update(
                "update error for contract notbase58!, reason: invalid contract update, reason: x"
            ),
            None
        );
        // A condition a retry clears is not a refusal.
        assert_eq!(
            refused_update(
                "update error for contract 2xaQ7k6oGhns9MTKjbTzA3GaZH8PfeCft85FzK7srwRf, \
                 reason: missing contract parameters"
            ),
            None
        );
    }

    /// A refusal naming one of our stores is said; `handle_response` hands
    /// every gateway error that is one to `apply_gateway_error`. Mutated red
    /// by dropping either.
    #[test]
    fn a_refused_update_to_our_store_is_said() {
        let store = [0x31u8; 32];
        let mut state = crate::state::AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: store.to_vec(),
                reputation_contract_id: vec![0x32; 32],
                mailbox_contract_id: vec![0x33; 32],
                store_contract_key: None,
                store_verifying_key: None,
            }],
        );
        let error = format!(
            "UPDATE failed: update error for contract {}, reason: execution error: invalid \
             contract update, reason: the order is not valid",
            bs58::encode(store).into_string()
        );
        apply_gateway_error(&mut state, &error);
        assert_eq!(state.notifications.len(), 1);
        assert!(state.notifications[0].starts_with(
            "A change to your store was refused by the network: the order is not valid"
        ));

        let src = include_str!("response_handler.rs");
        let handler = &src[src.find("pub fn handle_response(").unwrap()..];
        let err_arm = &handler[handler.find("Err(e) => {").unwrap()..];
        let err_arm = &err_arm[..err_arm.find("\n        }\n").unwrap()];
        assert!(err_arm.contains(
            "if refused_update(&e).is_some() {\n                apply_gateway_error(&mut APP_STATE.write(), &e);"
        ));
    }

    /// **An undecodable payload's error quotes nothing from it** (review of
    /// harvest#96). Where serde's visitor sees a string it did not expect --
    /// an enum that receives an unknown variant name -- its message quotes
    /// the string, and on version skew that string can be an xpub or a
    /// signing key PEM sitting where the old build expected an enum.
    #[test]
    fn a_decode_error_does_not_quote_the_payload() {
        #[derive(serde::Serialize)]
        struct SkewedStatus {
            xpub: String,
            network: String,
            next_index: u32,
        }
        #[derive(serde::Serialize)]
        enum Skewed {
            PaymentXpub {
                status: Option<SkewedStatus>,
            },
            PermissionGranted {
                fingerprint: String,
                requestor: String,
            },
        }
        const SECRET: &str = "vpubSECRETXPUB";
        let harvest = harvest_common::to_cbor(&Skewed::PaymentXpub {
            status: Some(SkewedStatus {
                xpub: "vpub".into(),
                network: SECRET.into(),
                next_index: 1,
            }),
        })
        .expect("cbor");
        let ghostkey = harvest_common::to_cbor(&Skewed::PermissionGranted {
            fingerprint: "fp-one".into(),
            requestor: SECRET.into(),
        })
        .expect("cbor");
        // Precondition: serde really does quote it, so the assertions below
        // are about the error text we build and not about serde's.
        for serde_says in [
            from_cbor::<harvest_common::BitcoinDelegateResponse>(&harvest).err(),
            from_cbor::<ghostkey_common::GhostkeyResponse>(&ghostkey).err(),
        ] {
            let serde_says = serde_says.expect("must not decode");
            assert!(serde_says.contains(SECRET), "{serde_says}");
        }

        for (sender, payload, variant) in [
            (DelegateSender::Harvest, &harvest, "PaymentXpub"),
            (DelegateSender::Ghostkey, &ghostkey, "PermissionGranted"),
        ] {
            let Err(error) = decode_delegate_message(sender, payload) else {
                panic!("a skewed payload decoded");
            };
            assert!(!error.contains(SECRET), "{error}");
            assert!(
                error.contains(&format!("variant `{variant}`, {} bytes", payload.len())),
                "{error}"
            );
        }
    }

    /// **The handler is what releases a waiting write** (harvest#119). A
    /// `NotFound` and a `GetResponse` are both answers; a write waiting on
    /// one that the handler did not pass on would sit out the whole deadline
    /// and then be bounced by the node, which is the bug.
    #[test]
    fn a_get_answer_releases_a_write_waiting_on_that_contract() {
        use super::super::prime::{register_answer_waiter, Primed};
        use freenet_stdlib::prelude::{CodeHash, ContractInstanceId, ContractKey, WrappedState};

        let absent = ContractInstanceId::new([21u8; 32]);
        let mut waiting = register_answer_waiter(absent);
        handle_response(Ok(HostResponse::ContractResponse(
            ContractResponse::NotFound {
                instance_id: absent,
            },
        )));
        assert_eq!(waiting.try_recv(), Ok(Some(Primed::Absent)));

        // A `GetResponse` goes on to write `APP_STATE`, which on the host
        // panics for want of a Dioxus runtime. The answer is delivered FIRST,
        // before that and before the migration and pointer early returns, so
        // the waiter is released even though the rest of the arm cannot run
        // here -- and that ordering is exactly the claim this half checks.
        let held = ContractInstanceId::new([22u8; 32]);
        let mut waiting = register_answer_waiter(held);
        let _ = std::panic::catch_unwind(|| {
            handle_response(Ok(HostResponse::ContractResponse(
                ContractResponse::GetResponse {
                    key: ContractKey::from_id_and_code(held, CodeHash::new([23u8; 32])),
                    contract: None,
                    state: WrappedState::new(vec![0xF6]),
                },
            )))
        });
        assert_eq!(waiting.try_recv(), Ok(Some(Primed::Held)));
    }

    /// The record followed is the one the store KEY addresses, whatever id
    /// the details name, and a store with no owner key links to nothing
    /// (harvest#53 Phase C).
    #[test]
    fn the_reputation_link_is_the_store_keys_record() {
        let mut state = harvest_common::store::StoreStateV1::default();
        state.info.info.reputation_contract_id = [0xBB; 32];
        state.info.info.version = 1;
        let bytes =
            |s: &harvest_common::store::StoreStateV1| harvest_common::to_cbor(s).expect("encode");
        assert_eq!(check_for_reputation_link(&bytes(&state)), None, "no owner");
        let owner = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        state.owner = Some(owner);
        let expected = super::super::store_ops::reputation_instance_id(&owner)
            .expect("derive")
            .as_bytes()
            .to_vec();
        assert_eq!(check_for_reputation_link(&bytes(&state)), Some(expected));
        assert_ne!(
            check_for_reputation_link(&bytes(&state)),
            Some(vec![0xBB; 32]),
            "the details' id is not what is followed"
        );
    }
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
                // Said on the store page rather than read as a clean record
                // (P1-5).
                use dioxus::prelude::WritableExt;
                APP_STATE.write().on_record_unavailable(&reputation_id);
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
///
/// Deliberately not `Debug`: it holds whole delegate responses, and one of
/// them (`GhostkeyResponse`) prints every secret it carries. Log it with
/// `log_summary` (harvest#94).
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
            .or_else(|_| {
                from_cbor::<harvest_common::BitcoinDelegateResponse>(payload)
                    .map(DelegateResponse::Bitcoin)
                    // Not serde's messages: on version skew they quote the
                    // value that failed, which can be a backup string or an
                    // xpub (harvest#94). The payload's shape is enough to
                    // tell skew from rubbish.
                    .map_err(|_| {
                        format!(
                            "not a harvest delegate response nor a Bitcoin one ({})",
                            super::log_summary::payload_shape(payload)
                        )
                    })
            }),
        DelegateSender::Ghostkey => from_cbor::<ghostkey_common::GhostkeyResponse>(payload)
            .map(DelegateResponse::Ghostkey)
            // As above: serde would quote a signing key PEM.
            .map_err(|_| {
                format!(
                    "not a ghostkey delegate response ({})",
                    super::log_summary::payload_shape(payload)
                )
            }),
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
        // Never `{:?}` of a response here: several carry secrets, and
        // `info!` survives release builds (harvest#94). See `log_summary`.
        DelegateResponse::Harvest(r) => {
            info!(
                "Harvest delegate response: {}",
                super::log_summary::harvest_response_summary(&r)
            );
            app.on_delegate_response(r);
        }
        DelegateResponse::Bitcoin(r) => {
            info!(
                "Bitcoin delegate response: {}",
                super::log_summary::bitcoin_response_summary(&r)
            );
            app.on_bitcoin_delegate_response(r);
        }
        DelegateResponse::Ghostkey(r) => {
            info!(
                "Ghostkey response: {}",
                super::log_summary::ghostkey_response_summary(&r)
            );
            app.on_ghostkey_response(r);
        }
    }
}

fn handle_delegate_response(
    key: freenet_stdlib::prelude::DelegateKey,
    values: Vec<freenet_stdlib::prelude::OutboundDelegateMsg>,
) {
    // An answer with no messages at all is how a `freenet network` node says
    // the delegate is not registered (harvest#150). If the migration walk is
    // waiting on that delegate, it is the walk's answer; otherwise there is
    // nothing in it to act on anyway.
    // The first empty answer from a delegate being registered is the node
    // saying it is registered (harvest#162), and releases what waits on it.
    if values.is_empty() && super::delegate_api::acknowledge_registration(&key) {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    if values.is_empty() && super::delegate_migrate_ops::offer_empty(&key) {
        return;
    }

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
                // The delegate migration's one call in flight, if this is its
                // answer: a predecessor's export (whose payload is not a
                // Harvest response at all), or the current delegate's answer
                // to an import. Offered first so neither reaches `AppState`.
                #[cfg(target_arch = "wasm32")]
                if super::delegate_migrate_ops::offer_payload(&key, &msg.payload) {
                    continue;
                }
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
                    Err(e) => error!("Undecodable delegate response from {sender:?}: {e}"),
                }
            }
            freenet_stdlib::prelude::OutboundDelegateMsg::RequestUserInput(req) => {
                info!(
                    "Delegate requesting user input: {}",
                    super::log_summary::user_input_summary(&req)
                );
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
