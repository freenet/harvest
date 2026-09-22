//! The browser transport for the delegate secret migration (harvest#123).
//!
//! `crate::delegate_migrate` owns every decision; this module sends one
//! delegate message, waits for its one answer, and routes answers back. The
//! shared `WebApi` handler delivers every response to one place, so the
//! correlation is ours: the walk is sequential, so there is at most one call
//! in flight and one waiting slot ([`WAITER`]) is the whole table.
//!
//! # What reaches the slot
//!
//! * An application message from the key being waited on. A predecessor is
//!   spoken to by nothing else, so anything it sends is the answer. The
//!   current delegate answers the whole app, so its messages are offered by
//!   variant ([`Expect::matches`]) and everything else falls through.
//! * The node's `DelegateError::Missing` for the key being waited on, which
//!   the connection layer passes on typed rather than as a string
//!   ([`offer_error`]): a generation this node never ran answers at once
//!   instead of costing a timeout.
//!
//! A predecessor's message that arrives after its call timed out finds no
//! waiter and goes on to the response handler, which drops messages from a
//! delegate this app did not register; it never reaches `AppState`.

#![cfg(target_arch = "wasm32")]

use std::cell::{Cell, RefCell};

use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::{ReadableExt, WritableExt};
use freenet_stdlib::prelude::DelegateKey;
use futures::channel::oneshot;
use futures::future::{select, Either};

use crate::delegate_migrate::{self, CallError, DelegateCalls, Expect, Reply};

/// How long one delegate message may take. A delegate call is node-local and
/// answers in milliseconds; this is for the ones that never answer at all (an
/// execution error names no delegate, so it can only time out).
const CALL_TIMEOUT_MS: u32 = 5_000;

/// How long work that must follow the migration waits for it before going
/// ahead anyway. See [`after_delegate_migration`].
const SETTLE_DEADLINE_MS: u32 = 30_000;

struct Waiter {
    delegate: DelegateKey,
    expect: Expect,
    reply: oneshot::Sender<Reply>,
}

thread_local! {
    /// The one call in flight, if any.
    static WAITER: RefCell<Option<Waiter>> = const { RefCell::new(None) };

    /// Whether the walk has finished (or given up) in this session.
    static SETTLED: Cell<bool> = const { Cell::new(false) };

    /// Whether the walk has been started in this session.
    static STARTED: Cell<bool> = const { Cell::new(false) };

    /// Work that must not run until the walk has settled.
    static AFTER: RefCell<Vec<Box<dyn FnOnce()>>> = RefCell::new(Vec::new());
}

/// The browser's [`DelegateCalls`]: a handle to the thread-local slot.
#[derive(Clone, Copy)]
struct Browser;

impl DelegateCalls for Browser {
    async fn call(
        &mut self,
        delegate: &DelegateKey,
        payload: Vec<u8>,
        expect: Expect,
    ) -> Result<Reply, CallError> {
        let (tx, rx) = oneshot::channel();
        let busy = WAITER.with(|w| {
            let mut w = w.borrow_mut();
            if w.is_some() {
                return true;
            }
            *w = Some(Waiter {
                delegate: delegate.clone(),
                expect,
                reply: tx,
            });
            false
        });
        if busy {
            // Cannot happen while the crate awaits each call in turn; said
            // rather than assumed.
            return Err(CallError::Send(
                "another migration call is in flight".into(),
            ));
        }
        // Registered BEFORE sending: the answer can arrive as soon as the send
        // returns.
        if let Err(e) = super::send_delegate_message(delegate, payload).await {
            WAITER.with(|w| w.borrow_mut().take());
            return Err(CallError::Send(e));
        }
        let timeout = gloo_timers::future::TimeoutFuture::new(CALL_TIMEOUT_MS);
        match select(rx, timeout).await {
            Either::Left((Ok(reply), _)) => Ok(reply),
            Either::Left((Err(_), _)) => Err(CallError::Timeout),
            Either::Right(_) => {
                WAITER.with(|w| w.borrow_mut().take());
                Err(CallError::Timeout)
            }
        }
    }
}

/// Offer one application-message payload from `delegate`. Returns `true` if
/// the waiting call took it, in which case nothing else may act on it.
pub fn offer_payload(delegate: &DelegateKey, payload: &[u8]) -> bool {
    WAITER.with(|w| {
        let mut slot = w.borrow_mut();
        let Some(waiter) = slot.as_ref() else {
            return false;
        };
        if &waiter.delegate != delegate {
            return false;
        }
        let taken = match &waiter.expect {
            Expect::AnyFrom => true,
            expect => harvest_common::from_cbor::<harvest_common::HarvestDelegateResponse>(payload)
                .is_ok_and(|response| expect.matches(&response)),
        };
        if !taken {
            return false;
        }
        if let Some(waiter) = slot.take() {
            let _ = waiter.reply.send(Reply::Payloads(vec![payload.to_vec()]));
        }
        true
    })
}

/// Offer a node error. Only `DelegateError::Missing` for the delegate being
/// waited on is taken; returns `true` if it was.
pub fn offer_error(error: &freenet_stdlib::client_api::ClientError) -> bool {
    use freenet_stdlib::client_api::{DelegateError, ErrorKind, RequestError};
    let ErrorKind::RequestError(RequestError::DelegateError(DelegateError::Missing(key))) =
        error.kind()
    else {
        return false;
    };
    WAITER.with(|w| {
        let mut slot = w.borrow_mut();
        if slot.as_ref().is_none_or(|waiter| &waiter.delegate != key) {
            return false;
        }
        if let Some(waiter) = slot.take() {
            let _ = waiter.reply.send(Reply::Missing);
        }
        true
    })
}

/// Run `work` once the delegate migration has settled in this session, or
/// after [`SETTLE_DEADLINE_MS`], whichever is first.
///
/// For work that WRITES a secret the migration may be about to import. The
/// case today is `InitEncryptionKey`, sent for every Ghost Key on connect: it
/// mints a key if the delegate holds none, and on a freshly re-keyed delegate
/// it holds none until the import lands. Minted first, it would stand (the
/// import never overwrites) and the store info's published encryption key --
/// the old one -- would stop matching the secret, so buyers' messages would
/// be unreadable. The deadline is a bound, not a design: work that has waited
/// that long goes ahead and the import keeps whatever it then finds.
pub fn after_delegate_migration(work: impl FnOnce() + 'static) {
    if SETTLED.with(Cell::get) {
        work();
        return;
    }
    AFTER.with(|a| a.borrow_mut().push(Box::new(work)));
}

fn settle() {
    if SETTLED.with(|s| s.replace(true)) {
        return;
    }
    let work = AFTER.with(|a| std::mem::take(&mut *a.borrow_mut()));
    for job in work {
        job();
    }
}

/// Start the walk, once per session. Called after the current delegate is
/// registered and just before the response loop starts, so no call's deadline
/// runs while nothing is reading answers.
pub fn start() {
    if STARTED.with(|s| s.replace(true)) {
        return;
    }
    let Some(current) = super::APP_STATE.read().harvest_delegate_key.clone() else {
        warn!(
            "delegate migration: the harvest delegate is not registered; nothing to migrate into"
        );
        settle();
        return;
    };
    gloo_timers::callback::Timeout::new(SETTLE_DEADLINE_MS, || {
        if !SETTLED.with(Cell::get) {
            warn!("delegate migration: still running after the deadline; letting waiting work go ahead");
            settle();
        }
    })
    .forget();
    wasm_bindgen_futures::spawn_local(async move {
        let report = delegate_migrate::migrate(Browser, current).await;
        info!(
            "delegate migration: {}",
            delegate_migrate::summarize(&report)
        );
        let imported = delegate_migrate::imported_anything(&report);
        settle();
        if imported {
            refresh_from_delegate().await;
        }
    });
}

/// Ask the delegate again for everything the app read from it on connect,
/// now that it holds what the migration imported.
///
/// The connect path asked before the walk ran, so a returning user on a
/// freshly re-keyed delegate was answered "no stores, no payment key, no
/// conversations". These answers are additive in `AppState`
/// (`merge_store_registrations`, the conversation recall), so asking again
/// only fills in.
async fn refresh_from_delegate() {
    info!("delegate migration: secrets were imported; asking the delegate again");
    let fingerprints: Vec<String> = super::APP_STATE
        .read()
        .ghostkeys
        .iter()
        .map(|k| k.fingerprint.clone())
        .collect();
    for fingerprint in fingerprints {
        if let Err(e) = super::store_ops::list_stores(fingerprint.clone()).await {
            warn!("delegate migration: could not list stores for {fingerprint}: {e}");
        }
    }
    if let Err(e) = super::bitcoin_ops::get_bridge().await {
        warn!("delegate migration: could not fetch bridge config: {e}");
    }
    if let Err(e) = super::bitcoin_ops::list_watched().await {
        warn!("delegate migration: could not fetch watch list: {e}");
    }
    if let Err(e) = super::bitcoin_ops::get_payment_xpub().await {
        warn!("delegate migration: could not fetch payment key: {e}");
    }
    {
        let mut app = super::APP_STATE.write();
        app.forget_recalled_conversations();
        app.recall_conversations_for_known_stores();
        app.sync_remembered_stores();
    }
}
