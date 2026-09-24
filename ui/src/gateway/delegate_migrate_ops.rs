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
//! * The node saying the key being waited on is not registered: a
//!   generation this node never ran answers at once instead of costing a
//!   timeout. It says so in one of two shapes, and both are taken. A
//!   `freenet local` node sends `DelegateError::Missing`, which the
//!   connection layer passes on typed rather than as a string
//!   ([`offer_error`]). A `freenet network` node -- every user's -- answers
//!   with a `DelegateResponse` holding no messages ([`offer_empty`],
//!   [`Expect::reply_to_empty_answer`]). Only the first was handled until
//!   harvest#150, so every real walk timed out at the first generation its
//!   node never ran, and stopped there.
//!
//! A predecessor's message that arrives after its call timed out finds no
//! waiter and goes on to the response handler, which drops messages from a
//! delegate this app did not register; it never reaches `AppState`. A late
//! answer from the CURRENT delegate to one of the migration requests does
//! reach `AppState::on_delegate_response`, and is absorbed there by its
//! catch-all arm; nothing in `AppState` acts on those variants, and nothing
//! should.

#![cfg(target_arch = "wasm32")]

use std::cell::{Cell, RefCell};

use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::{ReadableExt, WritableExt};
use freenet_stdlib::prelude::DelegateKey;
use futures::channel::oneshot;
use futures::future::{select, Either};

use crate::delegate_migrate::{self, CallError, DelegateCalls, Expect, Reply, SettleGate};

/// How long a call to a PREDECESSOR delegate may take.
///
/// A delegate call is node-local and usually answers in milliseconds, but an
/// export is the predecessor's whole secret store and the first call to a
/// generation may compile its module, and a timeout STOPS the walk for this
/// load ([`delegate_migrate::Walk`]). So this is generous: it costs time only
/// for a generation that never answers at all (an execution error names no
/// delegate, so it can only time out), and those are few since V1-V4 are not
/// asked and unregistered ones answer at once ([`offer_error`],
/// [`offer_empty`]).
const PREDECESSOR_TIMEOUT_MS: u32 = 20_000;

/// How long a call to the CURRENT delegate may take.
///
/// Node-local, and usually milliseconds. But after a re-key the first call
/// to the new generation compiles its module, and a silence here STOPS the
/// walk for this load, which also holds back the work the walk gates. One
/// harvest#162 rehearsal run measured that first answer at 6.9 s on a loaded
/// machine, past the 5 s this was, and the walk stopped at the generation
/// holding the seller's secrets (one data point; two further runs answered in
/// 2.2 to 4.4 s). So the same deadline as a predecessor call: it costs time
/// only when the current delegate does not answer the call at all.
const CURRENT_TIMEOUT_MS: u32 = PREDECESSOR_TIMEOUT_MS;
// Not back under the measured first answer.
const _: () = assert!(CURRENT_TIMEOUT_MS >= 10_000);

struct Waiter {
    delegate: DelegateKey,
    expect: Expect,
    reply: oneshot::Sender<Reply>,
}

thread_local! {
    /// The one call in flight, if any.
    static WAITER: RefCell<Option<Waiter>> = const { RefCell::new(None) };

    /// Whether the walk has been started in this session.
    static STARTED: Cell<bool> = const { Cell::new(false) };

    /// Work that must not run until the walk has reached a verdict. See
    /// [`SettleGate`].
    static AFTER: RefCell<SettleGate<Box<dyn FnOnce()>>> = RefCell::new(SettleGate::default());
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
        let predecessor_call = expect.is_predecessor_call();
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
        let timeout = gloo_timers::future::TimeoutFuture::new(if predecessor_call {
            PREDECESSOR_TIMEOUT_MS
        } else {
            CURRENT_TIMEOUT_MS
        });
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
        let taken = slot.as_ref().is_some_and(|waiter| {
            &waiter.delegate == delegate && waiter.expect.accepts_payload(payload)
        });
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

/// Offer an answer that held NO messages, from `delegate`. Taken, as
/// [`Reply::Missing`], only when the call in flight is to that delegate and
/// is a predecessor call; see [`Expect::reply_to_empty_answer`]. Returns
/// `true` if it was taken.
pub fn offer_empty(delegate: &DelegateKey) -> bool {
    WAITER.with(|w| {
        let mut slot = w.borrow_mut();
        let Some(reply) = slot
            .as_ref()
            .and_then(|waiter| waiter.expect.take_empty_answer(&waiter.delegate, delegate))
        else {
            return false;
        };
        if let Some(waiter) = slot.take() {
            let _ = waiter.reply.send(reply);
        }
        true
    })
}

/// Run `work` once the delegate migration has reached a verdict on every
/// registered predecessor; drop it for this load if the walk did not. See
/// [`SettleGate`] for why there is no "go ahead anyway".
pub fn after_delegate_migration(work: impl FnOnce() + 'static) {
    if let Some(work) = AFTER.with(|a| a.borrow_mut().defer(Box::new(work))) {
        work();
    }
}

fn settle(complete: bool) {
    let work = AFTER.with(|a| a.borrow_mut().settle(complete));
    if !complete {
        warn!(
            "delegate migration: did not reach every generation; work that could pre-empt an \
             import (minting an encryption key) is left for the next load"
        );
    }
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
        // Nothing could be imported, so nothing can be pre-empted either.
        settle(true);
        return;
    };
    wasm_bindgen_futures::spawn_local(async move {
        let outcome = delegate_migrate::migrate(Browser, current).await;
        info!(
            "delegate migration: {}{}",
            delegate_migrate::summarize(&outcome.report),
            if outcome.walk.halted {
                " (stopped: a generation did not answer)"
            } else {
                ""
            }
        );
        let imported = delegate_migrate::imported_anything(&outcome.report);
        settle(outcome.complete());
        if imported {
            refresh_from_delegate(outcome.imported_rsa_fingerprints()).await;
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
async fn refresh_from_delegate(rsa_fingerprints: Vec<String>) {
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
    // The imported RSA public keys, by name: the answer is what starts the
    // reputation migration for that identity. Only imported ones -- see the
    // "Ordering" section of `delegate_migrate`.
    for fingerprint in rsa_fingerprints {
        let request = harvest_common::HarvestDelegateRequest::GetRsaPublicKey {
            ghostkey_fingerprint: fingerprint.clone(),
        };
        // Bound first: a read guard held across the `.await` below is the
        // leaked-guard shape `state.rs` warns about.
        let delegate_key = super::APP_STATE.read().harvest_delegate_key.clone();
        let sent = match (harvest_common::to_cbor(&request), delegate_key) {
            (Ok(payload), Some(key)) => super::send_delegate_message(&key, payload).await,
            _ => Err("could not build the request".to_string()),
        };
        if let Err(e) = sent {
            warn!("delegate migration: could not ask for the RSA key of {fingerprint}: {e}");
        }
    }
    // And recall each Ghost Key's encryption key the app does not hold yet:
    // the connect path's recall ran before the import and found nothing, and
    // the mint that would have followed may have been dropped by an
    // incomplete walk. A recall never mints.
    let missing: Vec<String> = {
        let app = super::APP_STATE.read();
        app.ghostkeys
            .iter()
            .map(|k| k.fingerprint.clone())
            .filter(|fp| !app.encryption_public_keys.contains_key(fp))
            .collect()
    };
    for fingerprint in missing {
        crate::components::ensure_encryption_key(fingerprint);
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
        // The kept purchases the migration imported: their payment details,
        // their complaints, and the re-assert of each (review round 3; the
        // first list of the session came from the delegate before the import).
        app.sync_kept_purchases();
    }
}
