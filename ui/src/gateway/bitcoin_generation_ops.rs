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

/// How long to wait before asking again after the first failure worth
/// retrying. Doubled on each consecutive failure of the same pointer, up to
/// [`MAX_RETRY_AFTER_MS`], with jitter so many tabs do not ask in step.
const RETRY_AFTER_MS: u32 = 30_000;
const MAX_RETRY_AFTER_MS: u32 = 10 * 60_000;

/// How often every settled pointer is asked again, so a bridge that redeploys
/// while this tab is open is followed. See `BridgeGenerations::refresh`.
const REFRESH_EVERY_MS: u32 = 10 * 60_000;

/// How often to look for watch requests that have come due with nothing else
/// changing: a renewal, or a request whose time to land has passed. Only
/// local work happens unless something is due.
const WATCH_CHECK_EVERY_MS: u32 = 60_000;

thread_local! {
    static GENERATIONS: RefCell<Option<BridgeGenerations>> = const { RefCell::new(None) };
    static WATCH_CHECK: RefCell<Option<gloo_timers::callback::Interval>> = const { RefCell::new(None) };
    static REFRESH: RefCell<Option<gloo_timers::callback::Interval>> = const { RefCell::new(None) };
    static FAILURES: RefCell<std::collections::HashMap<Resolve, u32>> = RefCell::new(Default::default());
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
    WATCH_CHECK.with(|timer| {
        timer.borrow_mut().get_or_insert_with(|| {
            gloo_timers::callback::Interval::new(WATCH_CHECK_EVERY_MS, || {
                // Taking the state for writing re-renders the app, so only when
                // this node could have something to send.
                let could_act = {
                    use dioxus::prelude::ReadableExt;
                    APP_STATE.peek().watch_check_could_act()
                };
                if could_act {
                    APP_STATE.write().send_due_watch_requests();
                }
            })
        });
    });
    REFRESH.with(|timer| {
        timer.borrow_mut().get_or_insert_with(|| {
            gloo_timers::callback::Interval::new(REFRESH_EVERY_MS, || {
                let due = GENERATIONS.with(|g| {
                    g.borrow_mut().as_mut().is_some_and(|g| {
                        Resolve::ALL
                            .into_iter()
                            .fold(false, |due, artifact| g.refresh(artifact) || due)
                    })
                });
                if due {
                    send_due();
                }
            })
        });
    });
    send_due();
}

/// Offer a GET response. Returns `true` if it was a pointer this is waiting on,
/// in which case the bytes are a pointer record and NOT app state, and the
/// caller must not treat them as one.
pub fn deliver_state(id: &ContractInstanceId, bytes: &[u8]) -> bool {
    let settled =
        GENERATIONS.with(|g| g.borrow_mut().as_mut().and_then(|g| g.on_state(*id, bytes)));
    settle(settled) || is_pointer(id)
}

/// Offer the node's positive answer that nothing is stored at `id`.
pub fn deliver_absent(id: &ContractInstanceId) -> bool {
    let settled = GENERATIONS.with(|g| g.borrow_mut().as_mut().and_then(|g| g.on_absent(*id)));
    settle(settled) || is_pointer(id)
}

/// A pointer's answer that settles nothing, arriving late or unasked, is still
/// a pointer record and not app state.
fn is_pointer(id: &ContractInstanceId) -> bool {
    GENERATIONS.with(|g| g.borrow().as_ref().is_some_and(|g| g.is_pointer(id)))
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
        Some(Ok(code_hash)) => {
            FAILURES.with(|f| f.borrow_mut().remove(&artifact));
            info!(
                "the bridge's {artifact:?} generation resolved: {}",
                hex::encode(&code_hash[..8])
            );
            match artifact {
                Resolve::Tip => register_tip(code_hash),
                Resolve::Inbox => {
                    let bridge = GENERATIONS.with(|g| g.borrow().as_ref().map(|g| g.bridge()));
                    if let Some(bridge) = bridge {
                        APP_STATE.write().register_inbox_contract(bridge, code_hash);
                    }
                }
                Resolve::Address => {}
            }
        }
        Some(Err(Unresolved::Withdrawn)) => {
            // Authoritative, and not retried: only a newer record, found by a
            // refresh, lifts it.
            warn!("the bridge has withdrawn its {artifact:?} contract");
            FAILURES.with(|f| f.borrow_mut().remove(&artifact));
            if artifact == Resolve::Inbox {
                APP_STATE.write().withdraw_inbox();
            }
        }
        Some(Err(why)) => {
            warn!("the bridge's {artifact:?} generation did not resolve: {why:?}");
            let failures = FAILURES.with(|f| {
                let mut f = f.borrow_mut();
                let n = f.entry(artifact).or_insert(0);
                *n = n.saturating_add(1);
                *n
            });
            gloo_timers::callback::Timeout::new(retry_after_ms(failures), move || {
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

/// The wait before retry number `failures` of a pointer.
fn retry_after_ms(failures: u32) -> u32 {
    crate::bitcoin_generation::retry_delay_ms(
        failures,
        RETRY_AFTER_MS,
        MAX_RETRY_AFTER_MS,
        0.8 + 0.4 * js_sys::Math::random(),
    )
}

/// Subscribe to the tip contract the resolved tip generation names, for every
/// network this build can settle on.
///
/// This is what replaces the tip contract id Harvest used to carry as a
/// constant. Each is derived under that network's trusted bridges, the same
/// list an invoice on it carries, so the tip an invoice is anchored to and the
/// tip its payment depth is measured against are one contract. Every
/// settleable network gets one, not only the default: a network offered for
/// settlement with no tip could never date a payment.
fn register_tip(code_hash: [u8; 32]) {
    for &network in super::bitcoin_config::settleable_networks() {
        let id = super::bitcoin_config::default_trusted_bridges(network).and_then(|bridges| {
            crate::bitcoin_generation::tip_contract_id(&code_hash, network, &bridges)
        });
        match id {
            Ok(id) => {
                let id_bs58 = bs58::encode(id.as_bytes()).into_string();
                info!("subscribing to the {network:?} tip contract {id_bs58}");
                APP_STATE
                    .write()
                    .register_tip_contract_with_id(network, &id_bs58);
            }
            Err(e) => warn!("cannot derive the {network:?} tip contract: {e}"),
        }
    }
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
