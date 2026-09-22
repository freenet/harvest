//! Carrying the harvest delegate's secrets across a delegate re-key
//! (harvest#123).
//!
//! # Why this exists
//!
//! A delegate lives at `BLAKE3(BLAKE3(wasm) || params)`, and its secrets live
//! on the node under that key, encrypted with the node's own key and never
//! replicated. Every rebuild of the delegate -- any change to `harvest-common`,
//! any dependency bump -- therefore strands everything it holds: a buyer's
//! conversation keys (their only way to read a seller's reply, and their
//! recourse), a seller's payment key, the watch list, the store registry. None
//! of it is on the network, so nothing else can recover it. Seventeen
//! generations were stranded this way before this module existed.
//!
//! Every generation from V5 on carries an export handler
//! (`delegates/harvest-delegate/src/migration.rs`), so a predecessor CAN hand
//! its secrets over. Nothing asked. This module asks.
//!
//! # Who does what
//!
//! * `freenet_migrate::migrate_delegate_secrets` decides: which predecessors,
//!   newest first, when one is already done, how each answer is classified,
//!   and when to write a completion marker.
//! * [`Predecessors`] talks to each old delegate in Harvest's own protocol:
//!   a cheap `ListStores` to see whether it runs at all, then
//!   `HarvestMigrationRequest::ExportSecrets`.
//! * [`Successor`] hands each recovered secret to the CURRENT delegate's
//!   `ImportMigratedSecret`, which applies that secret's own rules -- merge a
//!   list, respect a cap, never overwrite -- and keeps the completion markers.
//! * [`DelegateCalls`] is the transport: send one message, wait for the one
//!   answer. The browser's is `gateway::delegate_migrate_ops`; the tests'
//!   is a scripted fake. Nothing in this file needs a browser.
//!
//! # The policy, and why it is Union
//!
//! `UnionAllGenerations`, not the crate's default `NewestSnapshotWins`. The
//! default stops at the first predecessor that does not answer, and a node
//! answers `Missing` for every generation it never ran -- which is every
//! release the user did not open Harvest during. Under the default, one
//! skipped release would hide every older generation's secrets for good.
//! Union walks them all.
//!
//! Union has two documented costs, and both are handled where they arise:
//!
//! * **The newest value must win a shared key.** Predecessors are offered
//!   newest first, and that only means anything if the writer declines a key
//!   it already holds -- the delegate's import never overwrites -- AND if no
//!   newer generation that holds data was skipped. A generation registered
//!   here that does not answer therefore stops the walk ([`Walk`]); only one
//!   the node never ran (`Missing`) is walked past.
//! * **It resurrects what a newer generation deleted by absence** -- a
//!   conversation the buyer forgot, an address unwatched, a conversation
//!   evicted at the cap. Each generation's completion markers stay behind
//!   with it, so without more, every re-key would walk back to V5 and bring
//!   those back. Sealing a predecessor therefore also writes a record that
//!   TRAVELS (`harvest:folded:<key>`, `delegates/.../import.rs`), and a later
//!   generation that imports it treats that predecessor as done. What is left:
//!   this first walk has no such records to find, so something deleted on one
//!   generation from V5 to V17 can come back from an older one, once.
//!
//! # What cannot be recovered
//!
//! * V1 to V4 have no export handler and are not walked at all (they would
//!   answer every export with an error, which is a timeout here).
//! * A generation the node never registered answers `Missing`, is recorded
//!   `Unresponsive`, and is asked again on the next load at the cost of two
//!   node-local round trips.
//! * Store keys are never exported; custody recovers them.
//! * A write made by a stale tab of an OLD UI, to its old delegate, after
//!   that generation was sealed here, is not carried: re-walking a sealed
//!   generation would undo deletions instead.
//! * A buyer conversation is kept under the store's CONTRACT id. It is
//!   imported whatever that id is, but the app recalls conversations by the
//!   store's current id, so one kept under a store generation that has since
//!   re-keyed is carried and not shown. That is the store re-key's gap, not
//!   this migration's.
//! * A family at its cap answers `Retryable`, so its predecessor is not
//!   sealed and is walked again each load until there is room.
//!
//! # Ordering against the contract migration
//!
//! The migration doctrine says to migrate delegate secrets before any contract
//! whose parameters are derived from one. Harvest has one such parameter, the
//! reputation contract's RSA key: `migrate_ops::start_reputation_migration`
//! waits until the delegate has reported it, and nothing on connect asks. So
//! when this walk imports an RSA public key, the app asks for it by
//! fingerprint ([`Outcome::imported_rsa_fingerprints`],
//! `crate::gateway::delegate_migrate_ops`), and the answer is what starts the
//! reputation walk. Asking for a key the delegate does not hold would answer
//! an `Error` that `AppState` reads as the failure of a store creation in
//! flight, which is why only imported fingerprints are asked about.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;

use freenet_migrate::{
    DelegateLineageEntry, DelegateMigrationReport, ItemWrite, MarkerQuery, MigrationAuthorization,
    MigrationMarker, PredecessorMigration, PredecessorSecretsIo, RecoveredSecret,
    SecretSelectionPolicy, SuccessorSecretsIo, UnionAck,
};
use freenet_stdlib::prelude::DelegateKey;
use harvest_common::delegate::{
    HarvestDelegateRequest, HarvestDelegateResponse, MigratedSecretValue, PredecessorMarkerState,
    SecretImport,
};
use harvest_common::migration::HarvestMigrationRequest;

/// The first generation whose delegate can answer an export request.
///
/// V1 to V4 predate `delegates/harvest-delegate/src/migration.rs`; their
/// `handle_request` rejects the request, which reaches this app as an
/// execution error that names no delegate and so can only time out. Asking
/// them costs a timeout per load and can never recover anything.
pub const FIRST_EXPORTING_GENERATION: u32 = 5;

/// The predecessor generations this walk asks, oldest first as the registry
/// records them (the crate orders them newest first itself).
pub fn exporting_predecessors() -> Vec<DelegateLineageEntry> {
    crate::migrate::delegate_lineage()
        .iter()
        .filter(|entry| entry.generation >= FIRST_EXPORTING_GENERATION)
        .cloned()
        .collect()
}

/// What came back for one delegate message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The delegate answered with these application-message payloads.
    Payloads(Vec<Vec<u8>>),
    /// The node answered that no delegate is registered under the key
    /// (`DelegateError::Missing`): a generation this node never ran.
    Missing,
}

/// Why a delegate message produced no reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// Nothing came back within the transport's deadline.
    Timeout,
    /// The message could not be sent.
    Send(String),
}

impl core::fmt::Display for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CallError::Timeout => f.write_str("no answer within the deadline"),
            CallError::Send(e) => write!(f, "could not send: {e}"),
        }
    }
}

/// Which answer a call is waiting for.
///
/// A predecessor is talked to by nothing but this walk, so any answer from its
/// key is the answer. The CURRENT delegate answers the whole app, so a call to
/// it names the response variant, and the fields, that make an answer its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    AnyFrom,
    /// Only a payload that decodes as `freenet_migrate::ExportedSecrets`:
    /// the answer to `ExportSecrets`. Anything else a predecessor sends is
    /// left alone rather than taken as the export.
    Export,
    PredecessorMarker([u8; 32]),
    PredecessorMarkerRecorded([u8; 32]),
    SecretImported {
        predecessor: [u8; 32],
        key: Vec<u8>,
    },
}

impl Expect {
    /// Whether `response` from the current delegate is the one this call is
    /// waiting for.
    pub fn matches(&self, response: &HarvestDelegateResponse) -> bool {
        match (self, response) {
            (Expect::AnyFrom, _) => true,
            // Never a Harvest response; see `accepts_payload`.
            (Expect::Export, _) => false,
            (
                Expect::PredecessorMarker(want),
                HarvestDelegateResponse::PredecessorMarker { predecessor, .. },
            ) => predecessor == want,
            (
                Expect::PredecessorMarkerRecorded(want),
                HarvestDelegateResponse::PredecessorMarkerRecorded { predecessor, .. },
            ) => predecessor == want,
            (
                Expect::SecretImported {
                    predecessor: want,
                    key: want_key,
                },
                HarvestDelegateResponse::MigratedSecretImported {
                    predecessor, key, ..
                },
            ) => predecessor == want && key == want_key,
            _ => false,
        }
    }
}

impl Expect {
    /// Whether a raw application-message payload from the delegate being
    /// waited on is this call's answer. The one decision the transport makes.
    pub fn accepts_payload(&self, payload: &[u8]) -> bool {
        match self {
            Expect::AnyFrom => true,
            Expect::Export => freenet_migrate::ExportedSecrets::from_bytes(payload).is_ok(),
            expect => harvest_common::from_cbor::<HarvestDelegateResponse>(payload)
                .is_ok_and(|response| expect.matches(&response)),
        }
    }
}

/// What one walk learned, shared by both adapters.
///
/// # Why a predecessor that does not answer stops the walk
///
/// Union walks every generation, and the newest generation's value wins a
/// shared key only because it is offered first and the import never
/// overwrites. That holds only if every newer generation that holds data
/// answers in the same run as the older ones, or before them. One that is
/// registered here but silent -- a timeout, a garbled answer -- would let an
/// older generation's RSA key, encryption key or payment counter land first,
/// and it would then stand for good. So after the first such silence the
/// walk stops ([`Successor::migration_marker`] refuses the next predecessor,
/// which the crate reads as `WriterUnavailable`) and tries again next load.
///
/// `Missing` does not stop it: that is the node saying it never ran the
/// generation, so there is nothing there to be shadowed. Stopping on it would
/// mean one skipped release hid every older one, which is the reason for
/// Union in the first place.
#[derive(Default, Debug)]
pub struct Walk {
    /// A registered predecessor failed to answer. Nothing older is imported
    /// in this run.
    pub halted: bool,
    /// Keys the current delegate reported `Written`, so the app knows what to
    /// ask for again. Key names only, never values.
    pub written: Vec<Vec<u8>>,
}

/// Send one message to one delegate and wait for its answer.
///
/// One call at a time: the crate walks sequentially and awaits each call, so
/// an implementation needs a single waiting slot, not a correlation table.
pub trait DelegateCalls {
    fn call(
        &mut self,
        delegate: &DelegateKey,
        payload: Vec<u8>,
        expect: Expect,
    ) -> impl Future<Output = Result<Reply, CallError>>;
}

fn encode<T: serde::Serialize>(message: &T) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(message).map_err(|e| format!("encode: {e}"))
}

/// The predecessor-side adapter: Harvest's own protocol, spoken to old
/// delegates.
pub struct Predecessors<T> {
    calls: T,
    generations: HashMap<[u8; 32], u32>,
    walk: Rc<RefCell<Walk>>,
}

impl<T> Predecessors<T> {
    pub fn new(calls: T, lineage: &[DelegateLineageEntry], walk: Rc<RefCell<Walk>>) -> Self {
        Self {
            calls,
            generations: lineage
                .iter()
                .map(|e| (e.delegate_key, e.generation))
                .collect(),
            walk,
        }
    }

    fn halt(&self) {
        self.walk.borrow_mut().halted = true;
    }
}

impl<T: DelegateCalls> PredecessorSecretsIo for Predecessors<T> {
    type Error = String;

    /// Does this predecessor run at all? A read every generation answers.
    ///
    /// `Missing` is the node saying it never registered this generation;
    /// silence is the crate's "no reply within the bound". Both are
    /// `Ok(false)`, which the crate records `Unresponsive` and never seals --
    /// but only silence halts the walk (see [`Walk`]).
    async fn probe_executable(&mut self, predecessor: &DelegateKey) -> Result<bool, String> {
        let payload = encode(&HarvestDelegateRequest::ListStores {
            ghostkey_fingerprint: String::new(),
        })?;
        match self.calls.call(predecessor, payload, Expect::AnyFrom).await {
            Ok(Reply::Payloads(_)) => Ok(true),
            Ok(Reply::Missing) => Ok(false),
            Err(CallError::Timeout) => {
                self.halt();
                Ok(false)
            }
            Err(CallError::Send(e)) => {
                self.halt();
                Err(e)
            }
        }
    }

    /// Ask the predecessor to export.
    ///
    /// Only an ANSWERED export is `Ok`: an empty list is the positive claim
    /// "it has nothing", which seals the predecessor for good, so silence, an
    /// undecodable answer, or an export naming another generation are all
    /// `Err` -- a retry next load, never a seal (freenet-migrate#19).
    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> Result<Vec<freenet_migrate::SecretPair>, String> {
        let generation = *self
            .generations
            .get(&key_bytes(predecessor)?)
            .ok_or("not a recorded predecessor")?;
        let payload = encode(&HarvestMigrationRequest::ExportSecrets {
            source_generation: generation,
        })?;
        let answer = match self.calls.call(predecessor, payload, Expect::Export).await {
            Ok(reply) => interpret_export(reply, generation),
            Err(e) => Err(format!("export not answered: {e}")),
        };
        if answer.is_err() {
            // It answered the probe, so it runs and may hold data: nothing
            // older may be imported ahead of it in this run.
            self.halt();
        }
        answer
    }
}

/// Read a predecessor's answer to `ExportSecrets`. A pure function so every
/// arm is tested.
pub fn interpret_export(
    reply: Reply,
    generation: u32,
) -> Result<Vec<freenet_migrate::SecretPair>, String> {
    let Reply::Payloads(payloads) = reply else {
        return Err("the predecessor is not registered on this node".into());
    };
    for payload in payloads {
        if let Ok(exported) = freenet_migrate::ExportedSecrets::from_bytes(&payload) {
            if exported.source_generation != generation {
                return Err(format!(
                    "asked generation {generation} to export and generation {} answered",
                    exported.source_generation
                ));
            }
            return Ok(exported.secrets);
        }
    }
    Err("the predecessor answered, but not with an export".into())
}

/// The successor-side adapter: the CURRENT delegate's own import path.
pub struct Successor<T> {
    calls: T,
    current: DelegateKey,
    walk: Rc<RefCell<Walk>>,
}

impl<T> Successor<T> {
    pub fn new(calls: T, current: DelegateKey, walk: Rc<RefCell<Walk>>) -> Self {
        Self {
            calls,
            current,
            walk,
        }
    }
}

impl<T: DelegateCalls> Successor<T> {
    async fn ask(
        &mut self,
        request: &HarvestDelegateRequest,
        expect: Expect,
    ) -> Result<HarvestDelegateResponse, String> {
        let payload = encode(request)?;
        let reply = self
            .calls
            .call(&self.current, payload, expect.clone())
            .await
            .map_err(|e| format!("the current delegate did not answer: {e}"))?;
        let Reply::Payloads(payloads) = reply else {
            return Err("the current delegate is not registered".into());
        };
        payloads
            .iter()
            .filter_map(|p| harvest_common::from_cbor::<HarvestDelegateResponse>(p).ok())
            .find(|r| expect.matches(r))
            .ok_or_else(|| "the current delegate answered something else".to_string())
    }
}

impl<T: DelegateCalls> SuccessorSecretsIo for Successor<T> {
    type Error = String;

    /// `Err` stops the walk under every policy, which is right: without a
    /// marker read the crate cannot tell migrated from not.
    async fn migration_marker(
        &mut self,
        query: &MarkerQuery<'_>,
    ) -> Result<Option<MigrationMarker>, String> {
        if self.walk.borrow().halted {
            return Err(
                "a newer generation did not answer; stopping so an older one cannot shadow it"
                    .into(),
            );
        }
        let predecessor = key_bytes(query.predecessor)?;
        match self
            .ask(
                &HarvestDelegateRequest::GetPredecessorMarker { predecessor },
                Expect::PredecessorMarker(predecessor),
            )
            .await?
        {
            HarvestDelegateResponse::PredecessorMarker { marker, .. } => Ok(marker.map(to_crate)),
            _ => Err("unexpected answer".into()),
        }
    }

    async fn record_marker(
        &mut self,
        predecessor: &DelegateKey,
        marker: MigrationMarker,
    ) -> Result<(), String> {
        let predecessor = key_bytes(predecessor)?;
        match self
            .ask(
                &HarvestDelegateRequest::RecordPredecessorMarker {
                    predecessor,
                    marker: from_crate(marker),
                },
                Expect::PredecessorMarkerRecorded(predecessor),
            )
            .await?
        {
            HarvestDelegateResponse::PredecessorMarkerRecorded { recorded: true, .. } => Ok(()),
            _ => Err("the current delegate did not record the marker".into()),
        }
    }

    /// Silence is `retryable`, never `already_authoritative`: the latter is a
    /// success the crate seals on.
    async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<String> {
        let predecessor = match key_bytes(item.predecessor) {
            Ok(bytes) => bytes,
            Err(e) => return ItemWrite::permanent(e),
        };
        let request = HarvestDelegateRequest::ImportMigratedSecret {
            predecessor,
            key: item.key.to_vec(),
            value: MigratedSecretValue(item.value.to_vec()),
        };
        let expect = Expect::SecretImported {
            predecessor,
            key: item.key.to_vec(),
        };
        match self.ask(&request, expect).await {
            Ok(HarvestDelegateResponse::MigratedSecretImported { outcome, .. }) => {
                if outcome == SecretImport::Written {
                    self.walk.borrow_mut().written.push(item.key.to_vec());
                }
                to_item_write(outcome)
            }
            Ok(_) => ItemWrite::retryable("unexpected answer".into()),
            Err(e) => ItemWrite::retryable(e),
        }
    }
}

/// A delegate key's 32 bytes. Every key is 32 bytes; the check is here so a
/// malformed one is an error rather than a panic.
fn key_bytes(key: &DelegateKey) -> Result<[u8; 32], String> {
    key.bytes()
        .try_into()
        .map_err(|_| "a delegate key that is not 32 bytes".to_string())
}

fn to_crate(marker: PredecessorMarkerState) -> MigrationMarker {
    match marker {
        PredecessorMarkerState::InProgress { saw_data } => MigrationMarker::InProgress { saw_data },
        PredecessorMarkerState::Done { had_data } => MigrationMarker::Done { had_data },
    }
}

fn from_crate(marker: MigrationMarker) -> PredecessorMarkerState {
    match marker {
        MigrationMarker::InProgress { saw_data } => PredecessorMarkerState::InProgress { saw_data },
        MigrationMarker::Done { had_data } => PredecessorMarkerState::Done { had_data },
    }
}

/// The delegate's verdict on one secret, in the crate's terms.
pub fn to_item_write(outcome: SecretImport) -> ItemWrite<String> {
    match outcome {
        SecretImport::Written => ItemWrite::written(),
        SecretImport::AlreadyAuthoritative => ItemWrite::already_authoritative(),
        SecretImport::Retryable(why) => ItemWrite::retryable(why),
        SecretImport::Permanent(why) => ItemWrite::permanent(why),
    }
}

/// What a walk ended with.
pub struct Outcome {
    pub report: DelegateMigrationReport,
    pub walk: Walk,
}

impl Outcome {
    /// Every registered predecessor reached a verdict: nothing was silent,
    /// nothing is half-imported, the current delegate answered throughout.
    /// Only then may work that could pre-empt an import go ahead
    /// ([`SettleGate`]).
    pub fn complete(&self) -> bool {
        !self.walk.halted
            && !self.report.predecessors.iter().any(|p| {
                matches!(
                    p,
                    PredecessorMigration::Incomplete { .. }
                        | PredecessorMigration::WriterUnavailable { .. }
                )
            })
    }

    /// The Ghost Key fingerprints whose RSA public key was imported, so the
    /// app can ask for it: nothing else does, and the reputation migration
    /// waits on it.
    pub fn imported_rsa_fingerprints(&self) -> Vec<String> {
        self.walk
            .written
            .iter()
            .filter_map(|k| k.strip_prefix(b"harvest:rsa_pk:"))
            .filter_map(|fp| String::from_utf8(fp.to_vec()).ok())
            .collect()
    }
}

/// Run the walk. See the module docs for the policy.
pub async fn migrate<T: DelegateCalls + Clone>(calls: T, current: DelegateKey) -> Outcome {
    let lineage = exporting_predecessors();
    let walk = Rc::new(RefCell::new(Walk::default()));
    let mut successor = Successor::new(calls.clone(), current, walk.clone());
    let mut predecessors = Predecessors::new(calls, &lineage, walk.clone());
    let report = freenet_migrate::migrate_delegate_secrets(
        &mut successor,
        &mut predecessors,
        &lineage,
        MigrationAuthorization::app_author_ack(),
        SecretSelectionPolicy::UnionAllGenerations(
            UnionAck::i_understand_union_resurrects_deleted_by_absence_secrets(),
        ),
    )
    .await;
    drop((successor, predecessors));
    let walk = Rc::try_unwrap(walk)
        .map(RefCell::into_inner)
        .unwrap_or_else(|shared| std::mem::take(&mut *shared.borrow_mut()));
    Outcome { report, walk }
}

/// Work that must wait for the delegate migration, and what becomes of it.
///
/// The one user today is `InitEncryptionKey`, sent for every Ghost Key on
/// connect: it MINTS a key if the delegate holds none, and a freshly re-keyed
/// delegate holds none until the import lands. Minted first, the new key
/// would stand -- the import never overwrites -- while the store info still
/// publishes the old one, and buyers' messages would be unreadable for good.
///
/// So the work runs only once a walk has reached a verdict on every
/// registered predecessor ([`Outcome::complete`]). A walk that did not --
/// a silent generation, a half-imported one -- DROPS the work for this load,
/// and the next load tries again: an encryption key missing for one load
/// costs a retry, one minted ahead of the import costs the conversations.
/// There is no deadline that lets the work go ahead anyway, for the same
/// reason; every call the walk makes has its own timeout, so it always ends.
pub enum SettleGate<W> {
    Waiting(Vec<W>),
    Released,
    Withheld,
}

impl<W> Default for SettleGate<W> {
    fn default() -> Self {
        SettleGate::Waiting(Vec::new())
    }
}

impl<W> SettleGate<W> {
    /// Offer work. Returns it back if it may run now; keeps it if the walk
    /// is still running; drops it if this load's walk did not complete.
    pub fn defer(&mut self, work: W) -> Option<W> {
        match self {
            SettleGate::Waiting(queue) => {
                queue.push(work);
                None
            }
            SettleGate::Released => Some(work),
            SettleGate::Withheld => None,
        }
    }

    /// The walk ended. Returns the work that may now run: all of it if the
    /// walk completed, none if it did not. A second call changes nothing.
    pub fn settle(&mut self, complete: bool) -> Vec<W> {
        match std::mem::replace(self, SettleGate::Withheld) {
            SettleGate::Waiting(queue) if complete => {
                *self = SettleGate::Released;
                queue
            }
            SettleGate::Waiting(_) => Vec::new(),
            already => {
                *self = already;
                Vec::new()
            }
        }
    }
}

/// Whether a report carried anything in, so the app should ask the delegate
/// again for what it now holds.
pub fn imported_anything(report: &DelegateMigrationReport) -> bool {
    report.predecessors.iter().any(|p| match p {
        PredecessorMigration::Imported { tally, .. }
        | PredecessorMigration::Incomplete { tally, .. } => tally.written > 0,
        _ => false,
    })
}

/// A one-line summary of a report for the log. Names generations and counts,
/// never a secret key or value.
pub fn summarize(report: &DelegateMigrationReport) -> String {
    let mut parts = Vec::new();
    for p in &report.predecessors {
        let what = match p {
            PredecessorMigration::Imported { tally, .. } => format!("imported {}", tally.written),
            PredecessorMigration::NoData { .. } => "empty".to_string(),
            PredecessorMigration::AlreadyMigrated { .. } => "done earlier".to_string(),
            PredecessorMigration::Unresponsive { .. } => "not answering".to_string(),
            PredecessorMigration::Incomplete { tally, .. } => format!(
                "incomplete ({} written, {} failed, {} refused)",
                tally.written, tally.failed, tally.rejected
            ),
            PredecessorMigration::WriterUnavailable { .. } => {
                "current delegate unavailable".to_string()
            }
            PredecessorMigration::Superseded { .. } => "superseded".to_string(),
        };
        parts.push(format!("V{}: {what}", p.generation()));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests;
