//! Driving the migration probe over the gateway's shared response handler.
//!
//! `crate::migrate` owns every decision -- what to ask next, what a silence
//! means, whether a result may be sealed. This module owns only the I/O: send
//! a GET, arm a deadline, route a response back, and PUT the recovered state
//! forward. That split is deliberate, because the decisions are the part that
//! loses data when it is wrong and this is the part that cannot be unit-tested
//! (it needs a browser and a node).
//!
//! # Why the probe is hand-pumped
//!
//! `WebApi` delivers every response to one app-registered handler, so a
//! request and its answer are not connected by anything the language can see:
//! there is no future to await. `ProbeDriver` is the migration crate's sans-IO
//! answer to exactly that shape. `PROBES` below is the correlation the
//! transport does not provide -- a candidate id maps to the probe waiting on
//! it, and an answer for anything else is ignored rather than guessed at.
//!
//! # Why a probe response must not reach `AppState`
//!
//! A probe GETs an OLD generation's instance. Its state is real, decodable
//! store/mailbox/reputation state, and feeding it to `on_contract_state` would
//! display a superseded generation as if it were the live store.
//! `handle_contract_response` therefore offers every GET response to
//! [`deliver_state`] first and returns if it is consumed.
//!
//! # Why the repeat gate is asynchronous
//!
//! The durable marker lives in the harvest delegate's secret store, so reading
//! it is a round trip and not a function call. It used to be a `localStorage`
//! read, which is synchronous and, in the deployed gateway, is not a read at
//! all: Freenet serves a webapp inside an iframe with no `allow-same-origin`,
//! so the frame has an opaque origin and `window.localStorage` throws. The
//! gate worked under `dx serve` and silently did nothing once published.
//!
//! So a probe is now built first and *held* in [`PENDING`] while the delegate
//! is asked. Exactly three things can release it, and two of them run it:
//! the delegate says `present` (dropped), the delegate says absent (run), or
//! nothing usable comes back within [`MARKER_QUERY_TIMEOUT_MS`] (run). The
//! send failing runs it immediately, for the same reason. Building the probe
//! before the answer arrives is what keeps that decision in one place --
//! `migrate::probe_gate` -- rather than spread across three callbacks.

#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;
use std::collections::HashMap;

use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::{ReadableExt, WritableExt};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, WrappedContract, WrappedState,
};
use harvest_common::mailbox::MailboxStateV1;
use harvest_common::reputation::ReputationStateV1;
use harvest_common::store::StoreStateV1;

use crate::migrate::{self, Artifact, MailboxOps, ProbeSession, ReputationOps, Seal, StoreOps};

use super::migrate_gate::{self, Admission, SessionWalks};
use super::migrate_seal::{self, Disposition, ForwardPut, SuccessorReference};
use super::store_ops::{MAILBOX_CONTRACT_WASM, REPUTATION_CONTRACT_WASM, STORE_CONTRACT_WASM};

/// One probe's state machine plus the context needed to act on its result.
struct Probe {
    artifact: Artifact,
    fingerprint: String,
    /// The durable marker this probe may write, and only if it earns it.
    marker: String,
    /// Every candidate this walk has asked about, in the order it asked.
    ///
    /// Collected as the walk advances rather than derived afterwards: these
    /// are exactly the generations that may still be named by a registration,
    /// and `adopt_recovered` records all of them as superseded. Re-deriving
    /// the lineage at the end would be a second derivation of the same
    /// addresses, and the store's predecessors are not derivable from today's
    /// parameters at all (see `start_identity_migration`).
    probed: Vec<ContractInstanceId>,
    params: Parameters<'static>,
    session: Session,
}

/// The three probe types behind one handle.
///
/// Boxed: the variants differ by ~400 bytes (a `StoreOps` carries the full
/// `StoreParameters`, a `MailboxOps` one verifying key), and every `Probe`
/// would otherwise be padded to the largest. There are at most three of these
/// alive at a time so the size hardly matters, but the enum is moved into and
/// out of the correlation table on every hop of every walk, and a boxed
/// variant makes each of those a pointer move.
enum Session {
    Store(Box<ProbeSession<StoreOps>>),
    Reputation(Box<ProbeSession<ReputationOps>>),
    Mailbox(Box<ProbeSession<MailboxOps>>),
}

/// The recovered state to PUT forward, already CBOR-encoded.
struct Forward {
    bytes: Vec<u8>,
    wasm: &'static [u8],
}

thread_local! {
    /// Probes that have an outstanding GET, keyed by the candidate they are
    /// waiting on.
    ///
    /// A `thread_local` rather than a dioxus signal: the browser is
    /// single-threaded, nothing renders from this, and keeping it out of
    /// `APP_STATE` removes any chance of holding two `RefCell` borrows at once
    /// -- the failure the delegate-response path already carries a comment
    /// about.
    ///
    /// The driver probes one candidate at a time, so a probe appears here
    /// under exactly one key, and the key changes as the walk advances.
    static PROBES: RefCell<HashMap<ContractInstanceId, Probe>> = RefCell::new(HashMap::new());

    /// Which lineages this session has walked, so a second `GhostKeyList`
    /// (the vault sends one per connect) neither starts a duplicate walk nor
    /// re-runs a finished one.
    ///
    /// In-memory only, and deliberately NOT the durable marker: this bounds
    /// repetition within a session, the durable one would bound it across
    /// loads. They used to be treated as interchangeable -- this was released
    /// the moment a walk settled, on the assumption the durable marker took
    /// over from there. It does not: the seal is withheld
    /// (`successor_reference_is_durable`), so nothing was left holding the
    /// gate and every reconnect re-walked the whole lineage. See
    /// [`SessionWalks`].
    static SESSION_WALKS: RefCell<SessionWalks> = RefCell::new(SessionWalks::default());

    /// Probes that are built and waiting on the delegate's answer about their
    /// durable marker, keyed by that marker.
    ///
    /// A probe sits here for one round trip and no longer. Whichever of the
    /// three releases arrives first takes it; the other two then find nothing
    /// and do nothing, which is what makes a late answer and a fired timeout
    /// harmless in either order.
    static PENDING: RefCell<HashMap<String, Probe>> = RefCell::new(HashMap::new());
}

/// How long to wait for one candidate before recording it as unresolved.
///
/// `freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS` is the crate's own advice.
/// Expiring the timer is [`ProbeSession::on_unknown`], never `on_absent`: a
/// deadline establishes nothing, and typing it as absence is what lets a
/// migration seal over live data.
const PROBE_TIMEOUT_MS: u32 = freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS as u32;

/// How long to wait for the delegate's answer about a marker before running
/// the probe anyway.
///
/// Shorter than [`PROBE_TIMEOUT_MS`], because it is a different kind of wait:
/// a delegate call is node-local and answers in milliseconds, where a contract
/// GET crosses the network. Expiring costs one walk that may not have
/// been needed; never expiring would leave a migration that has not been
/// sealed permanently un-run, which is the failure this whole module exists to
/// prevent.
const MARKER_QUERY_TIMEOUT_MS: u32 = 8_000;

/// The BLAKE3 code hash of a bundled contract -- the current generation.
fn code_hash(wasm: &[u8]) -> [u8; 32] {
    let hash = *ContractCode::from(wasm.to_vec()).hash();
    let bytes: &[u8] = hash.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

/// Start the migrations that need nothing but the seller's ghostkey: their
/// store and their mailbox.
///
/// Called the moment a ghostkey identity becomes known. Both artifacts'
/// parameters are derivable from the verifying key alone, so this runs even
/// for a seller whose delegate secrets did not survive -- which is the whole
/// reason it does not wait for the delegate.
pub fn start_identity_migration(fingerprint: &str, verifying_key_bytes: &[u8]) {
    let Some(vk) = verifying_key(verifying_key_bytes) else {
        warn!("cannot migrate for {fingerprint}: ghostkey verifying key is not 32 valid bytes");
        return;
    };

    let store_params = migrate::store_params(&vk);
    // The store's predecessors are NOT addressed by these parameter bytes.
    // `StoreParameters` has had three encodings -- the whole key, the whole key
    // with two Bitcoin fields, and since harvest#52 a code -- so every
    // already-published generation lives at an address derived from an older
    // one, and `store_candidates` is what derives each generation under the
    // encoding it was published with. These parameters address the CURRENT
    // instance, which is what `start` needs them for.
    match (
        migrate::encode_params(&store_params),
        migrate::store_candidates(&vk),
    ) {
        (Ok(params), Ok(candidates)) => {
            start(
                Artifact::Store,
                fingerprint,
                params.clone(),
                STORE_CONTRACT_WASM,
                move |_p| {
                    Session::Store(Box::new(ProbeSession::start_with_candidates(
                        StoreOps {
                            params: store_params.clone(),
                            seller: vk,
                        },
                        local_snapshot(),
                        candidates.clone(),
                        migrate::fold_all_policy(),
                    )))
                },
            );
        }
        (Err(e), _) | (_, Err(e)) => warn!("cannot migrate store for {fingerprint}: {e}"),
    }

    let mailbox_params = migrate::mailbox_params(&vk);
    match migrate::encode_params(&mailbox_params) {
        Ok(params) => start(
            Artifact::Mailbox,
            fingerprint,
            params,
            MAILBOX_CONTRACT_WASM,
            |p| {
                Session::Mailbox(Box::new(ProbeSession::start(
                    MailboxOps {
                        params: mailbox_params.clone(),
                    },
                    local_snapshot(),
                    p,
                    migrate::mailbox_lineage(),
                    migrate::fold_all_policy(),
                )))
            },
        ),
        Err(e) => warn!("cannot migrate mailbox for {fingerprint}: {e}"),
    }
}

/// Start the store probe for a store owned by a STORE key (harvest#93).
///
/// `start_identity_migration` probes the addresses a Ghost Key's store had,
/// which is every store up to generation V18. A store made since is addressed
/// by its own store key, which the Ghost Key cannot derive, so the next re-key
/// would strand it at this generation's address unless it is probed by that
/// key. The registration records the key, so this runs once per registered
/// store key, from the delegate's `StoreList` answer.
///
/// The lineage walked is the whole store lineage: generations before V19
/// never held a store at a store key's address, so their candidates are
/// simply absent, which a probe already handles.
pub fn start_store_key_migration(store_verifying_key: &[u8; 32]) {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(store_verifying_key) else {
        warn!("cannot migrate a store: its store key is not a valid key");
        return;
    };
    let label = format!("store {}", harvest_common::store::store_code(&vk));
    let store_params = migrate::store_params(&vk);
    match (
        migrate::encode_params(&store_params),
        migrate::store_candidates(&vk),
    ) {
        (Ok(params), Ok(candidates)) => start(
            Artifact::Store,
            &label,
            params,
            STORE_CONTRACT_WASM,
            move |_p| {
                Session::Store(Box::new(ProbeSession::start_with_candidates(
                    StoreOps {
                        params: store_params.clone(),
                        seller: vk,
                    },
                    local_snapshot(),
                    candidates.clone(),
                    migrate::fold_all_policy(),
                )))
            },
        ),
        (Err(e), _) | (_, Err(e)) => warn!("cannot migrate {label}: {e}"),
    }
}

/// Start the reputation migration, which cannot run until the delegate has
/// produced this identity's RSA public key.
///
/// **This is the ordering constraint, enforced.**
/// `ReputationParameters::rsa_public_key_der` is that key, so it is an input to
/// the reputation contract's address: without it there is no way to derive a
/// predecessor id at all, and no way to derive the CURRENT one either. Running
/// this before the key arrives would probe ids belonging to nobody, find
/// nothing, and could seal that verdict over a recoverable instance.
///
/// [`migrate::reputation_probe_inputs`] is what makes that structural rather
/// than remembered -- there is no way to call this without the key, and a
/// missing key returns without starting anything rather than substituting a
/// placeholder.
pub fn start_reputation_migration(fingerprint: &str, verifying_key_bytes: &[u8]) {
    let Some(vk) = verifying_key(verifying_key_bytes) else {
        return;
    };
    let der = super::APP_STATE
        .read()
        .rsa_public_keys
        .get(fingerprint)
        .cloned();
    let Some(inputs) = migrate::reputation_probe_inputs(der.as_ref(), &vk) else {
        // Not yet, never "nothing to migrate". The next delegate response for
        // this identity calls back in.
        info!("reputation migration for {fingerprint} waits on the delegate's RSA public key");
        return;
    };

    match migrate::encode_params(&inputs.params) {
        Ok(params) => start(
            Artifact::Reputation,
            fingerprint,
            params,
            REPUTATION_CONTRACT_WASM,
            |p| {
                Session::Reputation(Box::new(ProbeSession::start(
                    ReputationOps {
                        params: inputs.params.clone(),
                    },
                    local_snapshot(),
                    p,
                    migrate::reputation_lineage(),
                    migrate::fold_all_policy(),
                )))
            },
        ),
        Err(e) => warn!("cannot migrate reputation for {fingerprint}: {e}"),
    }
}

fn verifying_key(bytes: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// The client's own snapshot to seed a probe with.
///
/// It is `default()` for all three artifacts, and that is a statement about
/// Harvest rather than a shortcut. The probe is seeded from the client's
/// snapshot so a recovery can never drop local-only state -- state the device
/// holds that the network does not. Harvest has none: `AppState` keeps a
/// DECOMPOSED view (`BrowsingStore` holds an unsigned `StoreInfoV1`, a listing
/// list and an order list, not the contract state), so there is no faithful
/// snapshot to hand over in the first place, and every edit the seller makes
/// is sent to the contract as it is made rather than accumulating locally.
///
/// If a local-only write is ever introduced, this is the function that has to
/// learn about it, or that write is what a migration silently drops.
fn local_snapshot<S: Default>() -> S {
    S::default()
}

/// Build a probe and ask the delegate whether its lineage is already done.
///
/// The durable marker is consulted HERE and nowhere else, and it gates only
/// the repeat: a first run for this `(instance, current code hash)` is
/// unconditional. Nothing asks whether the successor is empty -- an emptiness
/// gate is satisfied by any write to the new key, including this app's own
/// `create_store_contracts` PUT of a default state, and would then suppress
/// the migration forever (freenet/river#621).
///
/// The probe is built before the answer arrives and parked in [`PENDING`].
/// That is not eagerness for its own sake: it means the marker's three
/// possible outcomes all reduce to "release this probe, or drop it", decided
/// by `migrate::probe_gate` rather than by three separate code paths.
fn start<F>(
    artifact: Artifact,
    fingerprint: &str,
    params: Parameters<'static>,
    wasm: &'static [u8],
    build: F,
) where
    F: FnOnce(&Parameters<'static>) -> Session,
{
    let current_hash = code_hash(wasm);
    let current = migrate::current_id(&current_hash, &params);
    let marker = migrate::marker_key(artifact, &current, &current_hash);

    // The session guard comes first, and covers the marker query as well as
    // the walk. Without that, a second `GhostKeyList` arriving inside the
    // query's round trip would park a second probe under the same marker and
    // silently evict the first from `PENDING` -- a migration that never ran
    // and never reported anything.
    match SESSION_WALKS.with(|w| w.borrow_mut().claim(&marker)) {
        Admission::Admit => {}
        Admission::AlreadyWalking => {
            // Ordinarily routine: the vault sends a `GhostKeyList` per connect
            // and two can overlap, so refusing the second is the normal case.
            //
            // Logged anyway because this arm is also where a lineage would sit
            // if `finish`'s unreachable arms ever fired, and silence there
            // would be a migration that quietly did not run. The two are told
            // apart by repetition: this line recurring on every connect, with
            // no completion line ever following it, is the stuck case.
            info!(
                "migration: a walk of the {} lineage for {fingerprint} is already in \
                 flight; not starting a second",
                artifact.as_str()
            );
            return;
        }
        Admission::AlreadyWalked => {
            // Not silent, because this is the gate now doing the job the
            // durable marker cannot: if it stops firing, the walk goes back to
            // running once per connect and nothing else would say so.
            info!(
                "migration: the {} lineage for {fingerprint} was already walked in this \
                 session; it runs again on the next load",
                artifact.as_str()
            );
            return;
        }
    }

    let probe = Probe {
        artifact,
        fingerprint: fingerprint.to_string(),
        marker: marker.clone(),
        probed: Vec::new(),
        params: params.clone(),
        session: build(&params),
    };
    PENDING.with(|p| p.borrow_mut().insert(marker.clone(), probe));

    // The deadline first, so a send that never produces a response cannot
    // strand the probe. An expiry that finds the probe already gone is a
    // no-op.
    {
        let marker = marker.clone();
        gloo_timers::callback::Timeout::new(MARKER_QUERY_TIMEOUT_MS, move || {
            // A `None` here is the normal case: the delegate already answered
            // and the probe is long gone. Saying so when it is NOT is what
            // matters -- a timeout firing on every load is the signal that
            // markers are not reaching the delegate at all.
            if release_pending(&marker).is_some() {
                warn!(
                    "migration: the delegate did not answer about marker {marker}; \
                     treating it as not migrated and probing"
                );
            }
        })
        .forget();
    }

    let query = migrate::marker_query(&marker);
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = send_harvest_request(&query).await {
            // Unavailable, so the probe runs. `probe_gate` is where that
            // choice is argued; this is only the path that reaches it.
            warn!("migration: could not ask the delegate about {marker}: {e}");
            release_pending(&marker);
        }
    });
}

/// Send one request to the harvest delegate.
async fn send_harvest_request(
    request: &harvest_common::HarvestDelegateRequest,
) -> Result<(), String> {
    let delegate_key = super::APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;
    let payload =
        harvest_common::to_cbor(request).map_err(|e| format!("serialize delegate request: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

/// Release a parked probe and run it, returning it if this call is the one
/// that found it.
///
/// Idempotent by construction: the probe is removed from [`PENDING`] under one
/// borrow, so of a late delegate answer, an expired deadline and a failed send
/// exactly one does anything and the rest find nothing.
fn release_pending(marker: &str) -> Option<()> {
    let probe = PENDING.with(|p| p.borrow_mut().remove(marker))?;
    info!(
        "migration: probing {} predecessor generation(s) of the {} contract for {}",
        probe.artifact.lineage().len(),
        probe.artifact.as_str(),
        probe.fingerprint
    );
    pump(probe);
    Some(())
}

/// Drop a parked probe without running it: the delegate says this lineage was
/// already carried forward under this exact code hash.
fn drop_pending(marker: &str) {
    let dropped = PENDING.with(|p| p.borrow_mut().remove(marker));
    if let Some(probe) = dropped {
        info!(
            "migration: the {} contract for {} is already migrated at this generation",
            probe.artifact.as_str(),
            probe.fingerprint
        );
    }
    // The session guard is what stops a later `GhostKeyList` re-asking the
    // delegate about a marker this session has already settled.
    SESSION_WALKS.with(|w| w.borrow_mut().settled_without_walking(marker));
}

/// A delegate response arrived. Returns `true` if it belonged to the migration
/// and must not reach `AppState`.
///
/// Offered BEFORE the app-state write guard is taken, for the same reason
/// `deliver_state` is: releasing a probe can run all the way through to
/// `finish`, which writes `APP_STATE`, and `APP_STATE` is a `RefCell`
/// underneath -- taking the write guard twice panics.
pub fn deliver_delegate_response(response: &super::response_handler::DelegateResponse) -> bool {
    use harvest_common::HarvestDelegateResponse;
    let super::response_handler::DelegateResponse::Harvest(harvest) = response else {
        return false;
    };
    match harvest {
        HarvestDelegateResponse::MigrationMarker { marker, present } => {
            match migrate::probe_gate(if *present {
                migrate::MarkerLookup::Present
            } else {
                migrate::MarkerLookup::Absent
            }) {
                migrate::Gate::Skip => drop_pending(marker),
                migrate::Gate::Run => {
                    release_pending(marker);
                }
            }
            true
        }
        HarvestDelegateResponse::MigrationMarkerRecorded { marker, recorded } => {
            if !*recorded {
                warn!(
                    "migration: the delegate did not record marker {marker}; \
                     this lineage will be probed again on the next load"
                );
            }
            true
        }
        _ => false,
    }
}

/// Advance one probe: ask for the next candidate, or finish it.
///
/// Takes the probe by value and re-registers it under the candidate it is now
/// waiting on. That is what makes `PROBES` a correlation table rather than a
/// list to search: an arriving response either names a candidate some probe is
/// waiting on, or belongs to nobody.
fn pump(mut probe: Probe) {
    let next = match &mut probe.session {
        Session::Store(s) => s.next_get(),
        Session::Reputation(s) => s.next_get(),
        Session::Mailbox(s) => s.next_get(),
    };

    let Some(candidate) = next else {
        finish(probe);
        return;
    };

    // Recorded before the send for the same reason it is registered before
    // the send: this is the list of generations that may still be named by a
    // registration, and a candidate that was asked about counts whatever the
    // answer turns out to be.
    probe.probed.push(candidate);

    // Register BEFORE sending. The response can arrive as soon as the send
    // returns, and an answer with nothing registered is dropped -- the same
    // ordering `request_store_info_signature` documents for signatures.
    PROBES.with(|p| p.borrow_mut().insert(candidate, probe));

    wasm_bindgen_futures::spawn_local(async move {
        // Never subscribe to a legacy key: the point is to read it once, not
        // to start receiving its updates forever.
        if let Err(e) = super::get_contract(&candidate, false).await {
            warn!("migration: GET for predecessor {candidate} could not be sent: {e}");
            deliver_unknown(candidate);
        }
    });

    // The deadline. An expired timer is `on_unknown`, never `on_absent`: a
    // deadline establishes nothing, and typing silence as absence is what lets
    // a migration seal over live data (freenet-migrate#19).
    gloo_timers::callback::Timeout::new(PROBE_TIMEOUT_MS, move || {
        deliver_unknown(candidate);
    })
    .forget();
}

/// Offer a GET response to the probes. Returns `true` if a probe consumed it,
/// in which case the caller must NOT treat the bytes as current app state:
/// they belong to a superseded generation.
pub fn deliver_state(id: &ContractInstanceId, bytes: &[u8]) -> bool {
    let Some(mut probe) = PROBES.with(|p| p.borrow_mut().remove(id)) else {
        return false;
    };
    match &mut probe.session {
        Session::Store(s) => s.on_state(*id, bytes),
        Session::Reputation(s) => s.on_state(*id, bytes),
        Session::Mailbox(s) => s.on_state(*id, bytes),
    }
    pump(probe);
    true
}

/// Offer a positive `NotFound` to the probes.
///
/// Only ever called for `ContractResponse::NotFound` -- an answer the node
/// actually gave. Every other way a GET can fail to produce state routes to
/// [`deliver_unknown`].
pub fn deliver_absent(id: &ContractInstanceId) -> bool {
    let Some(mut probe) = PROBES.with(|p| p.borrow_mut().remove(id)) else {
        return false;
    };
    match &mut probe.session {
        Session::Store(s) => s.on_absent(*id),
        Session::Reputation(s) => s.on_absent(*id),
        Session::Mailbox(s) => s.on_absent(*id),
    }
    pump(probe);
    true
}

/// Record that nothing came back for `id`. Harmless if the probe already
/// advanced past this candidate -- the entry is simply not there.
fn deliver_unknown(id: ContractInstanceId) {
    let Some(mut probe) = PROBES.with(|p| p.borrow_mut().remove(&id)) else {
        return;
    };
    match &mut probe.session {
        Session::Store(s) => s.on_unknown(id),
        Session::Reputation(s) => s.on_unknown(id),
        Session::Mailbox(s) => s.on_unknown(id),
    }
    pump(probe);
}

/// How long to wait for the node's `PutResponse` before giving up on a forward
/// PUT.
///
/// The same length and the same reasoning as [`PROBE_TIMEOUT_MS`], and the
/// same direction on expiry: a deadline establishes nothing. An expired
/// forward is recorded as unconfirmed and seals nothing, so the lineage is
/// walked again on the next load.
const FORWARD_TIMEOUT_MS: u32 = PROBE_TIMEOUT_MS;

/// A recovery that has been sent to the successor and is waiting for the node
/// to say it landed.
///
/// Everything the seal needs is carried here rather than left on the `Probe`,
/// because the probe is finished: its walk is over and the only thing still
/// outstanding is the write.
struct Forwarded {
    artifact: Artifact,
    fingerprint: String,
    marker: String,
    /// Every generation this walk asked about; all are superseded by the
    /// successor and any of them may be what the registry names.
    probed: Vec<ContractInstanceId>,
    seal: Seal,
    note: String,
}

thread_local! {
    /// Forward PUTs with an outstanding `PutResponse`, keyed by the successor
    /// instance they were written to.
    ///
    /// The same shape as [`PROBES`] and for the same reason: `WebApi` delivers
    /// every response to one handler, so a request and its answer are not
    /// connected by anything the language can see. A `PutResponse` for
    /// anything else is ignored rather than guessed at.
    static FORWARDS: RefCell<HashMap<ContractInstanceId, Forwarded>> =
        RefCell::new(HashMap::new());
}

/// # What must be true before a migration may declare itself done
///
/// The durable marker is not a note about what happened. It is a claim that
/// nothing needs to run again for this lineage, and every later load believes
/// it without checking. So it may only be written when BOTH of these hold:
///
/// 1. **The recovered state reached the successor** -- acknowledged by the
///    node, not merely handed to the WebSocket. `put_contract` resolves when
///    the *send* succeeds (`delegate_api.rs`), which says nothing about
///    whether the contract accepted the state or whether it arrived at all.
///    This used to be the whole of the check: the PUT was spawned
///    fire-and-forget and the marker was written on the next line, so a
///    rejected or lost PUT still sealed and the state was orphaned silently
///    and permanently. The old comment here described sealing "after the
///    forward PUT is queued", which was true and was the bug -- it reasoned
///    only about a probe that could not encode its result, which is a much
///    narrower failure than the one the ordering actually admitted.
///
/// 2. **Every durable pointer a later load follows already names the
///    successor.** A marker with a stale pointer is worse than no marker: the
///    next load restores the PREDECESSOR ids from the delegate, finds the
///    marker present, skips the probe, and quietly goes back to the old
///    generation -- with the migrated instances sitting unreferenced beside
///    it. The migration would appear to succeed and then undo itself on
///    reload.
///
/// These are one decision, not two, which is why they are stated in one place.
/// The seal is the moment the migration stops being repeatable, so both have
/// to be facts before it, and anything short of a fact resolves the same way
/// everything else in this module resolves: do not seal, walk again next load.
/// That is wasteful and correct.
///
/// Condition 2 cannot be satisfied today; see
/// [`successor_reference_is_durable`]. Nothing seals, and the walk repeats.
fn finish(mut probe: Probe) {
    // # The `None => return` arms below
    //
    // They are unreachable, and they are deliberate rather than an oversight
    // or a forgotten path -- do not "tidy" them into an `unwrap` or a panic.
    //
    // `pump` calls this only when `next_get` returned `None`, and `next_get`
    // returns `None` only after it has stored a result (`ProbeSession`, in
    // `crate::migrate`): either it was already finished, or the driver
    // answered `Step::Done`, at which point `take_outcome` yields the outcome.
    // freenet-migrate asserts that invariant itself -- "Step::Done implies an
    // untaken outcome", `driver.rs` -- and `take_outcome` returns `None` only
    // while still `Probing`. A probe is also moved into this function, so it
    // cannot be finished twice.
    //
    // So the arms encode an invariant this code depends on but cannot enforce,
    // held in a dependency. Returning is the right response to it being
    // violated: nothing was recovered, so there is nothing to adopt, forward
    // or seal, and the lineage stays claimed as `Walking` in `SESSION_WALKS`.
    // That is safe in the direction everything here resolves -- `claim` refuses
    // a `Walking` lineage exactly as it refuses a settled one, so no repeat can
    // start, and a reload clears the record and retries. It is the same
    // retry-on-reload bound the rest of the module takes.
    //
    // One honest gap if it ever does fire: `start`'s `AlreadyWalking` arm
    // returns silently where `AlreadyWalked` logs, so a lineage stuck this way
    // would not announce itself. Nothing would be lost, but nothing would say
    // the migration had not run either.
    let (note, seal, forward) = match &mut probe.session {
        Session::Store(s) => match s.take_result() {
            Some((outcome, seal)) => {
                let note = migrate::describe(&outcome);
                let forward = match outcome {
                    freenet_migrate::Outcome::Recovered { merged, .. } => {
                        encode_forward(&merged, STORE_CONTRACT_WASM)
                    }
                    _ => None,
                };
                (note, seal, forward)
            }
            None => return,
        },
        Session::Reputation(s) => match s.take_result() {
            Some((outcome, seal)) => {
                let note = migrate::describe(&outcome);
                let forward = match outcome {
                    freenet_migrate::Outcome::Recovered { merged, .. } => {
                        encode_forward(&merged, REPUTATION_CONTRACT_WASM)
                    }
                    _ => None,
                };
                (note, seal, forward)
            }
            None => return,
        },
        Session::Mailbox(s) => match s.take_result() {
            Some((outcome, seal)) => {
                let note = migrate::describe(&outcome);
                let forward = match outcome {
                    freenet_migrate::Outcome::Recovered { merged, .. } => {
                        encode_forward(&merged, MAILBOX_CONTRACT_WASM)
                    }
                    _ => None,
                };
                (note, seal, forward)
            }
            None => return,
        },
    };

    info!(
        "migration: {} contract for {}: {note}",
        probe.artifact.as_str(),
        probe.fingerprint
    );

    // Tell the seller what the migration could not carry, BEFORE the early
    // return below. That return is the nothing-was-recovered path, which is
    // precisely the case this reports -- draining after it would mean the one
    // message that matters is the one never sent.
    //
    // The migration seals after this, so there is no second attempt and no
    // later screen where it turns up again. See `migrate::take_uncarried`.
    report_uncarried();

    let Some(forward) = forward else {
        // Nothing to carry forward, so there is nothing that could have
        // reached the successor and condition 1 cannot hold. `Seal` without a
        // recovery cannot happen today -- only `Recovered` seals, and
        // `Recovered` always yields state -- but if a future outcome made it
        // possible, not sealing is the safe half.
        SESSION_WALKS.with(|w| w.borrow_mut().settled(&probe.marker));
        return;
    };

    // The session guard is deliberately still held. It covers the write as
    // well as the walk, so a second `GhostKeyList` arriving while the PUT is
    // outstanding cannot start a duplicate walk of a lineage this session is
    // in the middle of carrying forward. It is settled on every path out of
    // `settle_forward`.
    send_forward(
        Forwarded {
            artifact: probe.artifact,
            fingerprint: probe.fingerprint.clone(),
            marker: probe.marker.clone(),
            probed: std::mem::take(&mut probe.probed),
            seal,
            note,
        },
        probe.params.clone(),
        forward,
    );
}

/// PUT a recovered state under the CURRENT generation's key and wait for the
/// node to acknowledge it.
///
/// A PUT rather than an UPDATE because the current instance may not exist on
/// the network at all -- that is the normal case straight after a re-key, and
/// an UPDATE to a contract nobody holds has nothing to update. Where it does
/// exist the node merges rather than replaces (`update_state` merges for all
/// three contracts), so this is safe to repeat and safe when another client
/// has already written. Repeating it is exactly what an unsealed migration
/// does on the next load.
fn send_forward(forwarded: Forwarded, params: Parameters<'static>, forward: Forward) {
    let code = std::sync::Arc::new(ContractCode::from(forward.wasm.to_vec()));
    let wrapped = WrappedContract::new(code, params);
    let key: ContractKey = *wrapped.key();
    let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
    let bytes = forward.bytes;

    // The id the node will name in its `PutResponse`, and the id the recovery
    // is therefore reachable at. Derived from the contract just built rather
    // than recomputed alongside it, so the correlation key, the address the
    // state goes to, and the id this session adopts cannot drift apart.
    let successor = *key.id();
    let artifact = forwarded.artifact;

    // Register BEFORE sending, for the reason `pump` documents: the response
    // can arrive as soon as the send returns, and an answer with nothing
    // registered is dropped.
    FORWARDS.with(|f| f.borrow_mut().insert(successor, forwarded));

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = super::put_contract(container, WrappedState::new(bytes)).await {
            warn!(
                "migration: could not send the recovered {} state forward: {e}",
                artifact.as_str()
            );
            settle_forward(successor, Confirmation::Failed);
        }
    });

    // The deadline. An expired timer is `Unconfirmed`, never a confirmation: a
    // send that was accepted by the WebSocket and never answered by the node
    // establishes nothing about whether the state landed, and reading it as
    // success is precisely what condition 1 exists to stop.
    gloo_timers::callback::Timeout::new(FORWARD_TIMEOUT_MS, move || {
        settle_forward(successor, Confirmation::Unconfirmed);
    })
    .forget();
}

/// How a forward PUT ended.
enum Confirmation {
    /// The node answered `PutResponse` for the successor. This is the ONE
    /// signal that satisfies condition 1; every other way the write can end is
    /// silence about whether the state landed.
    Acknowledged,
    /// The send itself failed, so nothing was ever transmitted.
    Failed,
    /// The deadline expired with no answer.
    Unconfirmed,
}

/// Offer a `PutResponse` to the outstanding forward PUTs. Returns `true` if
/// one consumed it.
///
/// Called from the shared response handler, which otherwise only logs
/// `PutResponse`. Every other PUT this app makes is fire-and-forget by design
/// (a store creation, a listing, an order); this is the one that has to know.
///
/// # This correlates on the instance id, which is not the same as on the PUT
///
/// `FORWARDS` is keyed by successor instance, and that is the only thing a
/// `PutResponse` carries. But the successor instance is the CURRENT
/// generation's id for that seller -- the id `create_store_contracts` writes a
/// fresh default state to, and the id another tab on the same node may be
/// writing. An acknowledgement matched here may therefore be answering
/// somebody else's PUT while ours failed.
///
/// So this settles the forward, and `migrate_seal::put_response_evidence`
/// decides what that is worth: enough to adopt, never enough to seal. Do NOT
/// "simplify" that into `ForwardPut::Acknowledged` -- today the seal is
/// withheld for an unrelated reason, so the mistake would be invisible until
/// `successor_reference_is_durable` is implemented, and then it would seal
/// migrations that never landed.
pub fn deliver_put_ack(id: &ContractInstanceId) -> bool {
    if FORWARDS.with(|f| f.borrow().contains_key(id)) {
        settle_forward(*id, Confirmation::Acknowledged);
        return true;
    }
    false
}

/// Finish a forward PUT, whichever way it ended.
///
/// Idempotent by construction, the same way [`release_pending`] is: the entry
/// is removed under one borrow, so of an acknowledgement, a failed send and an
/// expired deadline exactly one does anything and the rest find nothing.
///
/// The decision itself is [`migrate_seal::disposition`] and is made nowhere
/// else -- it is the part that loses data when it is wrong, and it is the only
/// part of this module the host can test.
fn settle_forward(successor: ContractInstanceId, how: Confirmation) {
    let Some(forwarded) = FORWARDS.with(|f| f.borrow_mut().remove(&successor)) else {
        return;
    };

    // Settled on every path out, including the ones that seal nothing -- and
    // settled means CLOSED for this session, not released. This used to
    // release the marker so a failed migration could be retried; with the seal
    // withheld there was then nothing holding the gate at all, and the retry
    // it enabled was every reconnect re-walking the lineage and re-PUTting the
    // full state, without bound. A transient failure is retried by reloading.
    SESSION_WALKS.with(|w| w.borrow_mut().settled(&forwarded.marker));

    let put = match how {
        // Never `ForwardPut::Acknowledged` directly: how much a `PutResponse`
        // is worth is decided once, in `migrate_seal`, and it is not worth
        // enough to seal on. See `put_response_evidence`.
        Confirmation::Acknowledged => migrate_seal::put_response_evidence(),
        // Two different events, one epistemic state: a send that failed and a
        // deadline that expired both leave this code knowing nothing about
        // whether the state reached the contract.
        Confirmation::Failed | Confirmation::Unconfirmed => ForwardPut::Unconfirmed,
    };
    let stale = successor_reference_is_durable(forwarded.artifact).err();
    let reference = match stale {
        None => SuccessorReference::Durable,
        Some(_) => SuccessorReference::Stale,
    };

    match migrate_seal::disposition(put, reference, forwarded.seal) {
        Disposition::Discard => {
            warn!(
                "migration: the recovered {} state for {} was not confirmed written to \
                 {successor}; nothing adopted and nothing sealed, so the lineage is walked \
                 again on the next load",
                forwarded.artifact.as_str(),
                forwarded.fingerprint
            );
        }
        Disposition::AdoptAndSeal => {
            adopt_and_announce(&forwarded, successor);
            record_marker(&forwarded.marker, &forwarded.note);
        }
        Disposition::AdoptWithoutSealing => {
            adopt_and_announce(&forwarded, successor);
            match stale {
                Some(reason) => warn!(
                    "migration: the {} contract for {} was recovered and written to \
                     {successor}, but the successor reference is not durable ({reason}); not \
                     sealing, so the lineage is walked again on the next load",
                    forwarded.artifact.as_str(),
                    forwarded.fingerprint
                ),
                // `migrate::seal_decision` typed the outcome as `Retry` -- an
                // incomplete walk, which adopts what it found and asks again.
                None => info!(
                    "migration: the {} contract for {} was recovered, but the walk was not \
                     complete enough to seal; it runs again on the next load",
                    forwarded.artifact.as_str(),
                    forwarded.fingerprint
                ),
            }
        }
    }
}

/// Push everything the migration could not carry into the notifications the
/// seller actually sees.
///
/// A `probe_warn` is a browser console line. The loss is permanent -- the
/// migration seals -- and a decision the person affected is not told about is
/// indistinguishable from a bug, so this is the half that reaches them.
fn report_uncarried() {
    let lost = crate::migrate::take_uncarried();
    if lost.is_empty() {
        return;
    }
    let mut state = super::APP_STATE.write();
    for what in lost {
        warn!("migration: {what}");
        state.notifications.push(what);
    }
}

/// Repoint this session at the successor and tell the seller.
///
/// Only ever called once condition 1 holds. Announcing a recovery whose write
/// was never confirmed would be telling the seller something this code does
/// not know.
fn adopt_and_announce(forwarded: &Forwarded, successor: ContractInstanceId) {
    info!(
        "migration: PUT recovered {} state forward to {successor}",
        forwarded.artifact.as_str()
    );
    adopt_recovered(&forwarded.probed, successor);
    super::APP_STATE.write().notifications.push(format!(
        "Recovered your {} from an earlier version of Harvest.",
        forwarded.artifact.as_str()
    ));
}

/// Whether every durable pointer a later load follows already names the
/// successor -- condition 2 of the sealing rule in [`finish`].
///
/// **It never does, today, and this returns `Err` for every artifact.** That
/// is a statement about a missing capability, not a placeholder:
///
/// * All three successor ids live in one `harvest_common::StoreRegistration`
///   in the harvest delegate, which is what `ListStores` restores into
///   `AppState::my_stores` after a reload.
/// * The delegate has no request that can REPLACE a registration.
///   `RegisterStore` appends, and is a no-op for a store id it already holds,
///   so re-registering the successor triple would leave the predecessor's
///   registration in place and FIRST in the list -- and `stores.first()` is
///   the entry the listing path uses. It would add a phantom store rather than
///   repoint anything.
/// * The one case where there would be nothing stale to repoint -- an identity
///   with no registration at all, which is the seller whose delegate secrets
///   did not survive -- cannot be detected either. `merge_store_registrations`
///   deliberately does not create an entry for an empty answer, so "asked, and
///   owns none" is indistinguishable from "not asked yet". Reading the second
///   as the first would be the same mistake as typing a probe timeout as
///   absence.
///
/// So nothing seals. The migration re-runs on every load, re-PUTs a state the
/// contracts merge idempotently, and re-adopts in memory; the seller's store
/// works, at the cost of a lineage walk per load.
///
/// **In-session adoption sticking does NOT satisfy this.**
/// `AppState::adopt_migrated_contract_id` now keeps a `ListStores` answer from
/// reverting the repoint mid-session, which is a real fix for a real race --
/// but it holds the mapping in memory, and the delegate's registry still names
/// the predecessor. A reload starts from that registry with nothing
/// remembered, so condition 2 is false either way and this must keep returning
/// `Err`. Reading a successful in-session adoption as durability is how a
/// migration would start sealing again over exactly the state that reverts.
///
/// Closing this needs a delegate request that replaces a `StoreRegistration`
/// -- `common/src/delegate.rs` plus the delegate's own handler, with the
/// duplicate handling that `RegisterStore`'s append semantics currently dodge.
/// When it exists, this function sends it, awaits its acknowledgement, and
/// returns `Ok` on that acknowledgement alone.
///
/// # Making this return `Ok` arms three things at once
///
/// Nothing seals today, so three separate protections are currently
/// unreachable and have never run against a real migration. All three become
/// load-bearing on the same commit, which is why that commit wants reviewing
/// as one change rather than as a small fix to this function:
///
/// 1. **Sealing becomes reachable at all.** `migrate_seal::disposition` can
///    return `AdoptAndSeal` for the first time, so every path into it starts
///    mattering.
/// 2. **Acknowledgement attribution becomes load-bearing.** A `PutResponse`
///    cannot be attributed to a particular put, so `put_response_evidence`
///    caps the evidence at `AcknowledgedForInstance`, which never seals. If
///    that cap is lifted or bypassed, a store creation's put to the same id
///    seals a migration that never landed.
/// 3. **The session gate becomes the only bound on repetition.** With sealing
///    live, a walk that fails to seal must still not re-run per connect;
///    `migrate_gate::SessionWalks` is what stops it.
///
/// Each is pinned by a test, so the protections will not vanish silently. What
/// no test covers is their INTERACTION, because it does not exist until this
/// function returns `Ok`.
fn successor_reference_is_durable(_artifact: Artifact) -> Result<(), String> {
    Err(
        "the harvest delegate has no request that can replace a StoreRegistration, so the \
         registry a later load reads still names the predecessor"
            .to_string(),
    )
}

/// Ask the delegate to record a completed migration.
///
/// Fire-and-forget, and that is sound here in a way it was not for the forward
/// PUT: this is the LAST step, and the direction it fails in is safe. A write
/// the delegate refuses, or a send that never arrives, leaves the marker
/// unwritten, and an unwritten marker means the walk runs again on the next
/// load -- wasteful and correct. An unconfirmed forward PUT failed in the
/// opposite direction, which is why it is no longer treated this way.
fn record_marker(marker: &str, note: &str) {
    let request = migrate::marker_write(marker, note);
    let marker = marker.to_string();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = send_harvest_request(&request).await {
            warn!("migration: could not record marker {marker}: {e}");
        }
    });
}

fn encode_forward<T: serde::Serialize>(state: &T, wasm: &'static [u8]) -> Option<Forward> {
    match harvest_common::to_cbor(state) {
        Ok(bytes) => Some(Forward { bytes, wasm }),
        Err(e) => {
            warn!("migration: recovered state could not be re-encoded: {e}");
            None
        }
    }
}

/// Record every generation this walk asked about as superseded by the one
/// that now holds the data.
///
/// `AppState::adopt_migrated_contract_id` both remembers the mapping and
/// repoints anything currently held, across all three id fields of every
/// registration -- so this repoints the store, the mailbox and the reputation
/// contract, not just the store.
///
/// # Why no registration is read
///
/// This used to read the predecessor out of `my_stores.first()` and return
/// early when there was no entry -- which is the state the app is in until the
/// delegate's `ListStores` answer arrives, and stays in permanently if that
/// answer errors (its send only logs). Nothing was recorded in that window, so
/// the answer that arrived afterwards installed the predecessor's triple and
/// the migration reverted: exactly the failure the remembering exists to
/// prevent, in exactly the case it was needed. A decision whose job is to
/// survive the registry being late cannot take the registry as an input, so
/// this one does not have it: see `migrate_gate::superseded_ids`.
///
/// Every probed generation is recorded rather than only the one that hit,
/// because the registry may name any of them and all are equally superseded.
///
/// This is still the in-memory half. The durable half is condition 2 of the
/// sealing rule; see [`successor_reference_is_durable`].
fn adopt_recovered(probed: &[ContractInstanceId], successor: ContractInstanceId) {
    let superseded = migrate_gate::superseded_ids(probed, successor);
    let successor_bytes = successor.as_bytes().to_vec();
    let mut app = super::APP_STATE.write();
    for predecessor in superseded {
        app.adopt_migrated_contract_id(predecessor.as_bytes(), successor_bytes.clone());
    }
}
