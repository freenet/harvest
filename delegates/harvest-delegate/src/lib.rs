#![allow(unexpected_cfgs)]

mod bip32;
mod bitcoin;
mod handlers;
mod import;
mod known_stores;
mod markers;
mod messaging;
mod migration;
mod origin;
mod secrets;
mod store_keys;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

use crate::secrets::CtxSecrets;
use harvest_common::migration::HarvestMigrationRequest;
use harvest_common::{
    from_cbor, to_cbor, BitcoinDelegateRequest, HarvestDelegateRequest, HarvestDelegateResponse,
};

// RSA key generation (`InitReputationKeys`) and blind signing
// (`BlindSignFeedbackToken`) need real randomness, via `rsa::rand_core::OsRng`.
// `getrandom` (which `OsRng` sits on) has no OS backend on
// `wasm32-unknown-unknown`, so the workspace enables its "custom" feature --
// but that feature only *allows* registering a source, it doesn't provide
// one. Without this registration the crate fails to LINK (missing
// `__getrandom_custom` symbol), not merely to produce bad randomness at
// runtime, so this was a pre-existing latent build break, independent of
// anything Bitcoin-related, that just hadn't been exercised by a fresh
// `cargo build --target wasm32-unknown-unknown` in this checkout.
//
// The entropy source is the delegate host's own RNG
// (`freenet_stdlib::rand::rand_bytes`, backed by `__frnt__rand__rand_bytes`),
// never a JS/browser API -- a delegate does not run in a browser. Per
// `getrandom::register_custom_getrandom!`'s docs, registration must happen in
// the root binary crate; this delegate IS that root (compiled directly to a
// `cdylib`, no separate `main.rs`), so registering here is correct. The
// registration is a no-op on every other target (native `cargo test` keeps
// using the OS RNG), so this cannot change test behavior.
fn harvest_delegate_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let bytes = freenet_stdlib::rand::rand_bytes(buf.len() as u32);
    buf.copy_from_slice(&bytes);
    Ok(())
}
getrandom::register_custom_getrandom!(harvest_delegate_getrandom);

pub struct HarvestDelegate;

#[delegate]
impl DelegateInterface for HarvestDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                // Application messages require a valid origin
                match origin {
                    Some(MessageOrigin::WebApp(_)) => {}
                    Some(MessageOrigin::Delegate(_)) => {
                        return Err(DelegateError::Other(
                            "harvest delegate does not accept inter-delegate calls".into(),
                        ));
                    }
                    None => {
                        return Err(DelegateError::Other("missing message origin".into()));
                    }
                    Some(_) => {
                        return Err(DelegateError::Other(
                            "unsupported message origin kind".into(),
                        ));
                    }
                }

                if app_msg.processed {
                    return Err(DelegateError::Other(
                        "cannot process an already processed message".into(),
                    ));
                }
                handle_request(ctx, origin.as_ref(), &app_msg.payload)
            }

            // Contract notifications are delivered when a subscribed contract's
            // state changes. This is how the delegate learns about new mailbox
            // messages, reputation entries, etc.
            InboundDelegateMsg::ContractNotification(notification) => {
                handle_contract_notification(ctx, &notification)
            }

            // Responses to contract operations the delegate initiated
            InboundDelegateMsg::GetContractResponse(response) => {
                handle_get_contract_response(ctx, &response)
            }

            InboundDelegateMsg::SubscribeContractResponse(key) => {
                // Subscription confirmed -- nothing to do for now
                let _ = key;
                Ok(vec![])
            }

            other => {
                let msg_type = match &other {
                    InboundDelegateMsg::UserResponse(_) => "UserResponse",
                    InboundDelegateMsg::PutContractResponse(_) => "PutContractResponse",
                    InboundDelegateMsg::UpdateContractResponse(_) => "UpdateContractResponse",
                    InboundDelegateMsg::DelegateMessage(_) => "DelegateMessage",
                    _ => "Unknown",
                };
                Err(DelegateError::Other(format!(
                    "unexpected message type: {msg_type}"
                )))
            }
        }
    }
}

fn handle_request(
    ctx: &mut DelegateCtx,
    origin: Option<&MessageOrigin>,
    payload: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // NOTHING is dispatched before the caller is checked.
    //
    // This line replaces a comment that said the migration export "is the only
    // request whose answer is this delegate's private keys, so it is the only
    // one whose authorization matters". That was true when it was written, and
    // the Bitcoin work made it false without touching it: `SetPaymentXpub`
    // decides which wallet every future invoice pays into, so an unchecked
    // caller redirects the seller's income rather than merely reading
    // something. It reached the handler because `migration::handle` was the
    // only one of the three families that even took an `origin` -- the other
    // two could not have checked if they had wanted to.
    //
    // Hence the gate here, at the one point every family passes through,
    // rather than three gates that a fourth family would silently not have.
    // `handlers::handle` and `bitcoin::handle` each re-apply the SAME
    // `origin::authorize`, so a future caller reaching them by another route is
    // still checked, and the two checks cannot disagree about who is allowed.
    //
    // A refused caller is turned away before any trial decode, so it also
    // learns nothing about which request shapes this build understands.
    crate::origin::authorize(origin)?;

    // A migration export is tried FIRST, and it is the one branch that must
    // not fall through to the others: it is the request whose answer is this
    // delegate's private keys, and `migration::handle` re-checks the same
    // policy on the way in. Trying it after a failed decode of something else
    // would still be correct, but putting it first keeps the
    // highest-consequence path at the top rather than reached by exhaustion.
    //
    // The trial decode is sound for the same reason the two below are: all
    // three enums are externally-tagged, so the variant name is part of the
    // encoding, and `ExportSecrets` appears in none of the others. A payload
    // for one fails to decode as another with "unknown variant" rather than
    // misparsing into the wrong shape. Add a colliding variant name and this
    // stops being true.
    if let Ok(request) = from_cbor::<HarvestMigrationRequest>(payload) {
        return migration::handle(ctx, origin, request);
    }

    // The Bitcoin payment surface (`harvest_common::bitcoin_delegate`) is
    // deliberately NOT folded into `HarvestDelegateRequest`/`Response` as new
    // variants -- that enum is owned by a different, concurrently-edited
    // workstream, and adding variants there would mean editing a file this
    // change doesn't need to touch. Instead we dispatch on which request
    // enum the payload actually decodes as. Both enums use externally-tagged
    // CBOR (the variant name is part of the encoding), so a
    // `BitcoinDelegateRequest` payload fails to decode as a
    // `HarvestDelegateRequest` with an "unknown variant" error rather than
    // silently misparsing into the wrong shape, which is what makes this
    // fallback safe rather than ambiguous.
    match from_cbor::<HarvestDelegateRequest>(payload) {
        Ok(request) => {
            let response = handlers::handle(&mut CtxSecrets(ctx), origin, request);

            let response_bytes = to_cbor(&response)
                .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

            Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(response_bytes),
            )])
        }
        Err(_) => {
            // Not serde's messages: where it meets a string it did not expect
            // it quotes it, and a request's strings include a backup and an
            // xpub. This error reaches the UI's log (harvest#96 review).
            let request: BitcoinDelegateRequest = from_cbor(payload).map_err(|_| {
                DelegateError::Other(format!(
                    "payload is neither a HarvestDelegateRequest nor a BitcoinDelegateRequest \
                     ({})",
                    payload_shape(payload)
                ))
            })?;

            let response = bitcoin::handle(&mut CtxSecrets(ctx), origin, request)?;

            let response_bytes = to_cbor(&response)
                .map_err(|e| DelegateError::Other(format!("serialize bitcoin response: {e}")))?;

            Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(response_bytes),
            )])
        }
    }
}

/// What a payload that did not decode looked like, without its contents:
/// the CBOR enum variant, if it is one and the name is a plain identifier,
/// and the length. The UI's `gateway::log_summary::payload_shape` is the same
/// rule on the other side of the wire.
fn payload_shape(payload: &[u8]) -> String {
    let variant = from_cbor::<ciborium::Value>(payload)
        .ok()
        .and_then(|value| match value {
            ciborium::Value::Text(name) => Some(name),
            ciborium::Value::Map(mut entries) if entries.len() == 1 => {
                match entries.pop().map(|(key, _)| key) {
                    Some(ciborium::Value::Text(name)) => Some(name),
                    _ => None,
                }
            }
            _ => None,
        })
        .filter(|name| {
            (1..=64).contains(&name.len())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    match variant {
        Some(name) => format!("variant `{name}`, {} bytes", payload.len()),
        None => format!("{} bytes", payload.len()),
    }
}

/// Handle a contract state change notification.
///
/// The delegate subscribes to mailbox and reputation contracts. When new
/// messages or feedback entries arrive, this handler processes them.
fn handle_contract_notification(
    _ctx: &mut DelegateCtx,
    notification: &freenet_stdlib::prelude::ContractNotification,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // The notification contains the contract key and the update data.
    // We need to determine which contract type this is and handle accordingly.
    //
    // For now, forward the notification to the UI as an application message
    // so the UI can update its view. The delegate will eventually handle
    // auto-responses (e.g., auto-signing feedback tokens) here.

    let notification_msg = HarvestDelegateResponse::ContractUpdate {
        contract_key: notification.contract_id.as_bytes().to_vec(),
        update_data: notification.new_state.as_ref().to_vec(),
    };

    let response_bytes = to_cbor(&notification_msg)
        .map_err(|e| DelegateError::Other(format!("serialize notification: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

/// Handle a response to a contract GET the delegate initiated.
fn handle_get_contract_response(
    _ctx: &mut DelegateCtx,
    response: &freenet_stdlib::prelude::GetContractResponse,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // Forward contract state to the UI
    let state_bytes = response
        .state
        .as_ref()
        .map(|s| s.as_ref().to_vec())
        .unwrap_or_default();
    let contract_key = response.contract_id.as_bytes().to_vec();

    let response_msg = HarvestDelegateResponse::ContractState {
        contract_key,
        state: state_bytes,
    };

    let response_bytes = to_cbor(&response_msg)
        .map_err(|e| DelegateError::Other(format!("serialize contract state: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

/// The gate at the crate's own entry point.
///
/// The per-family tests in `bitcoin` and `handlers` drive their handlers
/// against a real store; these drive the DISPATCHER, because the defect being
/// fixed was one of routing -- a request family reached a handler that had no
/// way to check who sent it. What matters here is that no payload gets as far
/// as being classified before the caller is.
#[cfg(test)]
mod boundary_tests {
    use super::*;
    use crate::origin::test_origins::{a_different_web_app, harvest};
    use freenet_bitcoin_common::BitcoinNetwork;
    use harvest_common::bitcoin_delegate::BitcoinDelegateRequest as BtcReq;
    use harvest_common::bitcoin_delegate::BitcoinDelegateResponse as BtcResp;
    use harvest_common::migration::HarvestMigrationRequest as MigReq;

    const A_VALID_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    /// The host's context. Its secret methods are inert off the `wasm32`
    /// target, which is exactly why the handlers take a store instead (see
    /// [`crate::secrets`]) -- but nothing below reaches a secret, because
    /// everything below is refused before dispatch.
    fn ctx() -> DelegateCtx {
        unsafe { DelegateCtx::__new() }
    }

    fn refusal(payload: &[u8], origin: Option<&MessageOrigin>) -> String {
        match handle_request(&mut ctx(), origin, payload).expect_err("must be refused") {
            DelegateError::Other(message) => message,
            other => panic!("expected a refusal message, got {other:?}"),
        }
    }

    /// **A request that does not decode is refused without quoting it**
    /// (harvest#96 review). serde quotes a string it did not expect -- here
    /// an xpub-shaped value where an enum belongs, the shape a version skew
    /// takes -- and this error reaches the UI's `Gateway error` log line.
    #[test]
    fn an_undecodable_request_is_refused_without_quoting_it() {
        #[derive(serde::Serialize)]
        enum Skewed {
            SetPaymentXpub {
                request_id: u64,
                xpub: String,
                network: String,
            },
        }
        const SECRET: &str = "zpubSECRETXPUB";
        let payload = to_cbor(&Skewed::SetPaymentXpub {
            request_id: 1,
            xpub: "x".into(),
            network: SECRET.into(),
        })
        .expect("cbor");
        // Precondition: serde does quote it.
        let serde_says = from_cbor::<BtcReq>(&payload).expect_err("must not decode");
        assert!(serde_says.contains(SECRET), "{serde_says}");

        let message = match handle_request(&mut ctx(), Some(&harvest()), &payload) {
            Err(DelegateError::Other(message)) => message,
            other => panic!("expected a refusal message, got {other:?}"),
        };
        assert!(!message.contains(SECRET), "{message}");
        assert!(
            message.contains(&format!(
                "variant `SetPaymentXpub`, {} bytes",
                payload.len()
            )),
            "{message}"
        );
    }

    /// The reported defect, at the dispatcher: a `SetPaymentXpub` from a web
    /// app that is not Harvest must not reach the handler that decides where
    /// the seller's invoices are paid.
    ///
    /// Mutated red by removing the `authorize` call from `handle_request`.
    #[test]
    fn a_foreign_web_app_cannot_set_the_payment_xpub() {
        let payload = to_cbor(&BtcReq::SetPaymentXpub {
            request_id: 1,
            xpub: A_VALID_ZPUB.to_string(),
            network: BitcoinNetwork::Bitcoin,
            published_scripts: Vec::new(),
        })
        .expect("cbor");

        let message = refusal(&payload, Some(&a_different_web_app()));
        assert!(
            message.contains("Harvest web app"),
            "the refusal must say why: {message}"
        );
    }

    /// Every family is refused at the same point, including the migration
    /// export, which is the one that was already checked.
    ///
    /// **Every** means every one: a family missing from this list is one this
    /// test silently stops covering, which is the shape of the payment-hijack
    /// hole it was written for. Add to it whenever a variant is added to
    /// `HarvestDelegateRequest`, `BitcoinDelegateRequest` or
    /// `HarvestMigrationRequest`.
    #[test]
    fn every_request_family_is_refused_for_a_foreign_web_app() {
        let payloads = [
            to_cbor(&MigReq::ExportSecrets {
                source_generation: 4,
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::ListTransactions).expect("cbor"),
            to_cbor(&BtcReq::ListWatched).expect("cbor"),
            // The messaging family. `InitEncryptionKey` decides which key
            // buyers will encrypt to, and `DeriveConversationKeys` is a
            // Diffie-Hellman oracle against the seller's long-term secret --
            // which is to say, a read of their private correspondence.
            to_cbor(&HarvestDelegateRequest::InitEncryptionKey {
                ghostkey_fingerprint: "fp".into(),
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::DeriveConversationKeys {
                request_id: 1,
                ghostkey_fingerprint: "fp".into(),
                peer_public_keys: vec![vec![1u8; 32]],
                store_verifying_key: None,
            })
            .expect("cbor"),
            // The buyer's half. `ListBuyerConversations` answers the keys
            // that read this node's own side of a public mailbox;
            // `ForgetBuyerConversation` destroys a capability that exists
            // nowhere else; `ExportBuyerConversations` answers the secrets
            // themselves; and `MarkConversationsBackedUp` silences the
            // warning that one of them exists in a single place, which is the
            // one that reads as harmless and is not.
            to_cbor(&HarvestDelegateRequest::StoreBuyerConversation {
                request_id: 1,
                store_contract_id: vec![3u8; 32],
                secret: harvest_common::ConversationSecret([4u8; 32]),
                seller_public_key: [5u8; 32],
                conversation_id: [6u8; 32],
                created_at: 1_700_000_000,
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::ListBuyerConversations {
                request_id: 1,
                store_contract_id: vec![3u8; 32],
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::ForgetBuyerConversation {
                request_id: 1,
                store_contract_id: vec![3u8; 32],
                buyer_public_key: [7u8; 32],
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::ExportBuyerConversation {
                request_id: 1,
                store_contract_id: vec![3u8; 32],
                buyer_public_key: [7u8; 32],
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::ImportBuyerConversation {
                request_id: 1,
                backup: harvest_common::BackupString("harvest-conv-backup-v2:whatever".into()),
            })
            .expect("cbor"),
            to_cbor(&HarvestDelegateRequest::MarkConversationBackedUp {
                request_id: 1,
                store_contract_id: vec![3u8; 32],
                buyer_public_key: [7u8; 32],
            })
            .expect("cbor"),
        ];
        for payload in payloads {
            assert!(refusal(&payload, Some(&a_different_web_app())).contains("Harvest web app"));
            assert!(refusal(&payload, None).contains("could not attest"));
        }
    }

    /// The refusal happens BEFORE the payload is classified, so a caller that
    /// is not allowed to be here learns nothing about which request shapes this
    /// build understands.
    ///
    /// Mutated red by removing the boundary gate and relying on the handlers'
    /// own checks: an undecodable payload then never reaches a handler at all,
    /// so the caller gets the decode error naming both request enums.
    #[test]
    fn a_refused_caller_is_turned_away_before_the_payload_is_decoded() {
        let nonsense = b"not a request of any kind";
        let message = refusal(nonsense, Some(&a_different_web_app()));
        assert!(
            message.contains("Harvest web app"),
            "expected an authorization refusal, got: {message}"
        );
        assert!(
            !message.contains("HarvestDelegateRequest"),
            "the refusal disclosed which request shapes exist: {message}"
        );

        // The genuine caller DOES get the decode error, which is what makes the
        // assertion above meaningful rather than a property of the payload.
        let message = refusal(nonsense, Some(&harvest()));
        assert!(
            message.contains("HarvestDelegateRequest"),
            "the Harvest web app should have been told its payload was undecodable: {message}"
        );
    }

    /// And the genuine caller is dispatched normally, so the tests above are
    /// not passing on a delegate that refuses everybody.
    #[test]
    fn the_harvest_web_app_is_dispatched() {
        let payload = to_cbor(&BtcReq::ListWatched).expect("cbor");
        let msgs = handle_request(&mut ctx(), Some(&harvest()), &payload)
            .expect("the Harvest web app must reach the handler");
        let OutboundDelegateMsg::ApplicationMessage(msg) = &msgs[0] else {
            panic!("expected an application message");
        };
        match from_cbor::<BtcResp>(&msg.payload) {
            Ok(BtcResp::WatchList { .. }) => {}
            other => panic!("expected a WatchList, got {other:?}"),
        }
    }
}
