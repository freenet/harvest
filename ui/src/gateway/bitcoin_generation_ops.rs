//! Resolving the bridge's generation pointers over the node (#30, #59).
//!
//! Every decision lives in `crate::bitcoin_generation`, which is tested
//! without a browser. This is only the part that cannot be: sending the GETs,
//! arming their timeouts, asking again after a failure worth retrying, and
//! mirroring each artifact's resolution into `AppState.bitcoin`, where an
//! invoice reads the address generation it names.
//!
//! Until the address pointer resolves, no invoice can be issued, and the
//! seller is told why. That is deliberate: see the module docs of
//! `crate::bitcoin_generation` for why there is no fallback.

use std::cell::RefCell;

use dioxus::logger::tracing::{info, warn};
use freenet_stdlib::prelude::ContractInstanceId;

use crate::bitcoin_generation::{
    BridgeGenerations, Generation, PointerRequest, Resolve, Unresolved,
};

use super::APP_STATE;

/// How long a pointer GET may go unanswered before it counts as unreachable.
/// The same wait the migration probes use, which is `freenet-migrate`'s own
/// advice for a GET of a small contract.
const POINTER_TIMEOUT_MS: u32 = freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS as u32;

/// How long to wait before asking again after a failure worth retrying.
const RETRY_AFTER_MS: u32 = 30_000;

thread_local! {
    static GENERATIONS: RefCell<Option<BridgeGenerations>> = const { RefCell::new(None) };
}

/// Begin resolving the trusted bridge's pointers.
///
/// Safe to call again on a reconnect: resolution already under way is kept
/// rather than started twice, since a second concurrent resolution of one
/// pointer could not tell its answers from the first one's. A GET lost with the
/// old connection simply times out and is asked again.
pub fn start() {
    let started = GENERATIONS.with(|g| {
        let mut g = g.borrow_mut();
        if g.is_none() {
            match trusted_bridge() {
                Ok(bridge) => *g = Some(BridgeGenerations::new(bridge)),
                Err(why) => return Err(why),
            }
        }
        Ok(())
    });
    if let Err(why) = started {
        // A build whose bridge id is unusable can never resolve anything, so it
        // is reported as a refusal that stays rather than as a wait.
        warn!("cannot resolve the bridge's contract generations: {why}");
        let refused = Generation(Err(Unresolved::Refused(why)));
        let mut app = APP_STATE.write();
        app.bitcoin.address_generation = refused.clone();
        app.bitcoin.inbox_generation = refused;
        return;
    }
    send_due();
}

/// Offer a GET response. Returns `true` if it was a pointer this is waiting on,
/// in which case the bytes are a pointer record and NOT app state, and the
/// caller must not treat them as one.
pub fn deliver_state(id: &ContractInstanceId, bytes: &[u8]) -> bool {
    let settled =
        GENERATIONS.with(|g| g.borrow_mut().as_mut().and_then(|g| g.on_state(*id, bytes)));
    settle(settled)
}

/// Offer the node's positive answer that nothing is stored at `id`.
pub fn deliver_absent(id: &ContractInstanceId) -> bool {
    let settled = GENERATIONS.with(|g| g.borrow_mut().as_mut().and_then(|g| g.on_absent(*id)));
    settle(settled)
}

fn deliver_unreachable(request: PointerRequest) {
    let settled = GENERATIONS.with(|g| {
        g.borrow_mut()
            .as_mut()
            .and_then(|g| g.on_unreachable(request))
    });
    settle(settled);
}

fn trusted_bridge() -> Result<freenet_bitcoin_common::BridgeId, String> {
    let bridges =
        super::bitcoin_config::default_trusted_bridges(super::bitcoin_config::default_network())?;
    bridges
        .first()
        .copied()
        .ok_or_else(|| "this build names no trusted bridge".to_string())
}

/// GET every pointer now due, each with its own timeout.
fn send_due() {
    let due = GENERATIONS.with(|g| {
        g.borrow_mut()
            .as_mut()
            .map(BridgeGenerations::requests_due)
            .unwrap_or_default()
    });
    for request in due {
        info!("resolving a bridge generation pointer: {}", request.id);
        wasm_bindgen_futures::spawn_local(async move {
            // No subscription: a pointer record is the whole answer, and one
            // resolution needs one GET.
            if let Err(e) = super::delegate_api::get_contract(&request.id, false).await {
                warn!("could not ask for pointer {}: {e}", request.id);
                deliver_unreachable(request);
            }
        });
        // Harmless if the answer has already come, or a send error above has
        // already reported this attempt: the attempt number makes a report for
        // an attempt that is no longer current a no-op.
        gloo_timers::callback::Timeout::new(POINTER_TIMEOUT_MS, move || {
            deliver_unreachable(request)
        })
        .forget();
    }
    mirror();
}

/// After an artifact settles: publish its state, and ask again later if it
/// failed in a way worth retrying.
fn settle(settled: Option<Resolve>) -> bool {
    let Some(artifact) = settled else {
        return false;
    };
    mirror();
    let status = GENERATIONS.with(|g| g.borrow().as_ref().map(|g| g.status(artifact)));
    match status {
        Some(Ok(code_hash)) => info!(
            "the bridge's {artifact:?} generation resolved: {}",
            hex::encode(&code_hash[..8])
        ),
        Some(Err(why)) => {
            warn!("the bridge's {artifact:?} generation did not resolve: {why:?}");
            gloo_timers::callback::Timeout::new(RETRY_AFTER_MS, move || {
                // `retry` declines a withdrawal, so this asks again only when
                // asking again could change the answer.
                let due = GENERATIONS
                    .with(|g| g.borrow_mut().as_mut().is_some_and(|g| g.retry(artifact)));
                if due {
                    send_due();
                }
            })
            .forget();
        }
        None => {}
    }
    true
}

/// Copy each artifact's resolution into app state.
fn mirror() {
    let Some((address, inbox)) = GENERATIONS.with(|g| {
        g.borrow()
            .as_ref()
            .map(|g| (g.generation(Resolve::Address), g.generation(Resolve::Inbox)))
    }) else {
        return;
    };
    let mut app = APP_STATE.write();
    app.bitcoin.address_generation = address;
    app.bitcoin.inbox_generation = inbox;
}
