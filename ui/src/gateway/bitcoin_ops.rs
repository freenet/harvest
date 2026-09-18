//! Bitcoin/Payments operations: talking to the harvest delegate's Bitcoin
//! surface, and subscribing to Bitcoin contracts (chain tip, watched
//! addresses) directly over the gateway connection.
//!
//! Subscribing is done here rather than through the delegate because
//! `get_contract(.., subscribe: true)` already gives the UI a live,
//! `UpdateNotification`-driven feed (see `gateway::response_handler`) --
//! there's no need to proxy chain data through the delegate at all, and
//! doing so would just add a hop.

#[cfg(target_arch = "wasm32")]
use dioxus::prelude::{ReadableExt, WritableExt};
use harvest_common::{to_cbor, BitcoinDelegateRequest, BridgeEndpoint, WatchedPayment};

use super::APP_STATE;

/// Send a `BitcoinDelegateRequest` to the harvest delegate, allocating a
/// fresh request id from `APP_STATE.bitcoin` and marking it in-flight.
#[cfg(target_arch = "wasm32")]
async fn send_request(build: impl FnOnce(u64) -> BitcoinDelegateRequest) -> Result<(), String> {
    let (delegate_key, request) = {
        let mut state = APP_STATE.write();
        let key = state
            .harvest_delegate_key
            .clone()
            .ok_or("harvest delegate not yet registered")?;
        let request_id = state.bitcoin.next_request_id();
        state.bitcoin.in_flight.insert(request_id);
        (key, build(request_id))
    };
    let payload = to_cbor(&request).map_err(|e| format!("serialize bitcoin request: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

/// Fetch the currently configured bridge (if any). Answered even before any
/// Ghost Key is connected -- this is what lets the first-run panel show
/// bridge status with no credential.
#[cfg(target_arch = "wasm32")]
pub async fn get_bridge() -> Result<(), String> {
    let delegate_key = APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not yet registered")?;
    let payload = to_cbor(&BitcoinDelegateRequest::GetBridge)
        .map_err(|e| format!("serialize GetBridge: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn get_bridge() -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Fetch the user's private watch list.
#[cfg(target_arch = "wasm32")]
pub async fn list_watched() -> Result<(), String> {
    let delegate_key = APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not yet registered")?;
    let payload = to_cbor(&BitcoinDelegateRequest::ListWatched)
        .map_err(|e| format!("serialize ListWatched: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn list_watched() -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Start (or refresh) watching an address.
#[cfg(target_arch = "wasm32")]
pub async fn watch(watch: WatchedPayment) -> Result<(), String> {
    send_request(|request_id| BitcoinDelegateRequest::Watch { request_id, watch }).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn watch(_watch: WatchedPayment) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Stop watching an address.
#[cfg(target_arch = "wasm32")]
pub async fn unwatch(
    network: freenet_bitcoin_common::BitcoinNetwork,
    script_pubkey: Vec<u8>,
) -> Result<(), String> {
    send_request(|request_id| BitcoinDelegateRequest::Unwatch {
        request_id,
        network,
        script_pubkey,
    })
    .await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn unwatch(
    _network: freenet_bitcoin_common::BitcoinNetwork,
    _script_pubkey: Vec<u8>,
) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Attach an existing watch to a Harvest order, so the UI groups it under
/// Payments instead of (or alongside) the manual watch list.
#[cfg(target_arch = "wasm32")]
pub async fn associate_order(
    network: freenet_bitcoin_common::BitcoinNetwork,
    script_pubkey: Vec<u8>,
    order_id: harvest_common::payment::OrderId,
    expected_amount_sats: u64,
) -> Result<(), String> {
    send_request(|request_id| BitcoinDelegateRequest::AssociateOrder {
        request_id,
        network,
        script_pubkey,
        order_id,
        expected_amount_sats,
    })
    .await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn associate_order(
    _network: freenet_bitcoin_common::BitcoinNetwork,
    _script_pubkey: Vec<u8>,
    _order_id: harvest_common::payment::OrderId,
    _expected_amount_sats: u64,
) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Configure which bridge to use and how to authorize to it.
#[cfg(target_arch = "wasm32")]
pub async fn configure_bridge(endpoint: BridgeEndpoint) -> Result<(), String> {
    send_request(|request_id| BitcoinDelegateRequest::ConfigureBridge {
        request_id,
        endpoint,
    })
    .await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn configure_bridge(_endpoint: BridgeEndpoint) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Record the seller's account xpub, so invoices can each be given a fresh
/// payment address.
///
/// `published_scripts` is `AppState::published_payment_scripts`, so the count
/// the delegate reports back already accounts for the store's own orders.
#[cfg(target_arch = "wasm32")]
pub async fn set_payment_xpub(
    xpub: String,
    network: freenet_bitcoin_common::BitcoinNetwork,
    published_scripts: Vec<Vec<u8>>,
) -> Result<(), String> {
    send_request(|request_id| BitcoinDelegateRequest::SetPaymentXpub {
        request_id,
        xpub,
        network,
        published_scripts,
    })
    .await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn set_payment_xpub(
    _xpub: String,
    _network: freenet_bitcoin_common::BitcoinNetwork,
    _published_scripts: Vec<Vec<u8>>,
) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Fetch the configured payment xpub, if any.
///
/// Unlike the request helpers above this allocates no request id: like
/// `GetBridge` and `ListWatched` it is a read rather than an action a button
/// is waiting on, so there is nothing to show as in-flight. It is issued on
/// load AND after every `OrderAddress`, whose answer advances the counter this
/// reports.
#[cfg(target_arch = "wasm32")]
pub async fn get_payment_xpub() -> Result<(), String> {
    let delegate_key = APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not yet registered")?;
    let payload = to_cbor(&BitcoinDelegateRequest::GetPaymentXpub)
        .map_err(|e| format!("serialize GetPaymentXpub: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn get_payment_xpub() -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// Ask for the next unused payment address, under an id the CALLER allocated.
///
/// This is the one Bitcoin request whose id is not allocated here, and the
/// reason is the same discipline the signature queue follows: the answer is
/// what completes the invoice, it can arrive as soon as the send returns, and
/// an answer whose invoice is not registered yet is dropped. So the caller
/// registers first (`AppState::pending_invoices`, keyed on this id) and sends
/// second -- which it cannot do if the id only exists inside this function.
///
/// `published_scripts` is `AppState::published_payment_scripts`: the delegate
/// moves its device-local counter past every one of them before it derives
/// (harvest#77).
#[cfg(target_arch = "wasm32")]
pub async fn derive_order_address(
    request_id: u64,
    published_scripts: Vec<Vec<u8>>,
) -> Result<(), String> {
    let delegate_key = APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not yet registered")?;
    let payload = to_cbor(&BitcoinDelegateRequest::DeriveOrderAddress {
        request_id,
        published_scripts,
    })
    .map_err(|e| format!("serialize DeriveOrderAddress: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn derive_order_address(
    _request_id: u64,
    _published_scripts: Vec<Vec<u8>>,
) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}

/// GET-and-subscribe a Bitcoin contract (tip or address) by its raw 32-byte
/// instance id. Realtime updates then arrive as `UpdateNotification`s routed
/// through the normal response handler, exactly like any other contract.
#[cfg(target_arch = "wasm32")]
pub async fn subscribe_contract(contract_id: &[u8]) -> Result<(), String> {
    super::get_contract_by_id(contract_id).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn subscribe_contract(_contract_id: &[u8]) -> Result<(), String> {
    Err("bitcoin operations require WASM".into())
}
