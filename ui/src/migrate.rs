//! Carrying a seller's data forward when Harvest's contracts re-key.
//!
//! # Why this exists
//!
//! A contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, so **the compiled
//! bytes are the address**. Every rebuild that changes codegen -- a source
//! edit, a direct or transitive dependency bump, a rustc upgrade, a `cargo fmt`
//! that moves a panic location -- moves every store, reputation and mailbox
//! instance to a new address. The new address is empty. The seller's listings,
//! feedback and messages are still sitting at the old one, and nothing anywhere
//! reports a problem.
//!
//! Freenet has no core mechanism to carry state across that, deliberately and
//! permanently (freenet-core#2776), so it is app-level work. `legacy/*.toml`
//! records every superseded code hash; this module walks them.
//!
//! # What makes Harvest's instance ids re-derivable
//!
//! A predecessor's instance id is `BLAKE3(old_code_hash || cbor(params))`, so
//! recovering an old generation needs the OLD hash (from the registry) and the
//! parameter bytes that generation was published under -- never the old WASM,
//! which is why the artifacts being stale and irreproducible (harvest#18) does
//! not block any of this.
//!
//! Harvest's parameters happen to be derivable from things the client already
//! knows:
//!
//! * **Store** -- the seller's ghostkey verifying key.
//! * **Mailbox** -- the owner's ghostkey verifying key.
//! * **Reputation** -- the seller's RSA public key AND their verifying key.
//!
//! The first two need nothing but the ghostkey, which is why a store is
//! recoverable even for a seller whose delegate secrets are gone. The third
//! does not, and that asymmetry is the ordering constraint below.
//!
//! ## When the PARAMETERS change, not just the code
//!
//! `freenet_migrate` derives every predecessor id from one set of parameter
//! bytes, which is right only while the parameter encoding is stable. The
//! store's is not: `StoreParameters` GAINED two fields when the Bitcoin bridge
//! list arrived and then shed them again when it moved onto `Order`, so
//! generations V2-V5 -- and only those -- live at addresses no encoding this
//! build produces can reproduce. [`store_candidates`] derives each generation
//! under the encoding it was actually published with, and
//! [`published_under_legacy_store_params`] is the band. Any future change to a
//! contract's parameters needs the same treatment, and its absence is silent:
//! the probe finds nothing at every address and reports success.
//!
//! # The ordering constraint
//!
//! `ReputationParameters::rsa_public_key_der` is exactly the value the harvest
//! delegate holds under `harvest:rsa_pk:{fingerprint}`. So a reputation
//! instance id -- for **any** generation, the current one included -- cannot be
//! derived until that secret has been carried forward. Probing reputation
//! first would not merely fail to find anything: it would probe ids derived
//! from the wrong key, get nothing, and could seal a "nothing there" marker
//! over a perfectly recoverable instance.
//!
//! Here the constraint is structural rather than a rule to remember:
//! [`reputation_probe_inputs`] cannot be constructed without the RSA key, and
//! the only source of that key is a delegate response. Store and mailbox have
//! no such dependency and run as soon as the ghostkey is known.
//!
//! # When the probe runs
//!
//! **Unconditionally, once per `(instance, current_code_hash)`, seeded from
//! whatever snapshot the client already holds.** Only the REPEAT is gated, on a
//! durable marker.
//!
//! The first run is deliberately *not* gated on the successor being empty. An
//! emptiness gate reads like a free optimisation and is the shape that lost
//! River's rooms (freenet/river#621): any write to the new key satisfies "not
//! empty" first, and the probe then never fires -- an optimistic PUT, a
//! placeholder seed, a cached snapshot pushed forward all qualify, and all of
//! them are silent. Harvest has exactly such a write:
//! `create_store_contracts` PUTs `StoreStateV1::default()` under the current
//! key. Under an emptiness gate that PUT would permanently disable the
//! migration for that seller.
//!
//! # What may seal a marker
//!
//! Only `Recovered` with no unresolved candidates and no truncated fold. That
//! is the one *positive* result: the data was found and the search is known to
//! have been complete.
//!
//! Never `SeedLocal`, however conclusive it looks. Absence on Freenet is
//! unauthenticated: with the placement migration disabled (freenet-core#4440),
//! present-but-unfindable dead-ends were measured at ~99.6% of all
//! `get_not_found` traffic, so an all-`Absent` walk is more likely reporting a
//! routing failure than an empty lineage. The crate's own 0.6.0 documentation
//! says outright that it cannot tell you sealing is safe.
//!
//! `Outcome` is `#[non_exhaustive]`, so the wildcard arm in [`seal_decision`]
//! falls through to *retry* -- for today's non-definitive variants and for
//! every variant added later. A wildcard defaulting to "done" would write a
//! permanent marker for a case nobody has seen yet.

use freenet_migrate::{
    contract_id_from_code_hash, ContractLineageEntry, DelegateLineageEntry, FoldAllAck, Outcome,
    ProbeStateOps, SelectionPolicy,
};
use freenet_stdlib::prelude::{ContractInstanceId, Parameters};
use harvest_common::mailbox::{MailboxParameters, MailboxStateV1};
use harvest_common::reputation::{ReputationParameters, ReputationStateV1};
use harvest_common::store::{StoreParameters, StoreStateV1};

// The codegen emits both a contract and a delegate const per file; only one of
// each pair is populated. Wrapping each in its own module keeps the names from
// colliding, and the `dead_code` allow covers the empty half rather than
// editing generated source.
#[allow(dead_code)]
mod store_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_store_contract.rs"));
}
#[allow(dead_code)]
mod reputation_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_reputation_contract.rs"));
}
#[allow(dead_code)]
mod mailbox_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_mailbox_contract.rs"));
}
#[allow(dead_code)]
mod delegate_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_harvest_delegate.rs"));
}

/// Superseded generations of the store contract, oldest first.
pub fn store_lineage() -> &'static [ContractLineageEntry] {
    store_gen::LEGACY_STORE_CONTRACT
}

/// Superseded generations of the reputation contract, oldest first.
pub fn reputation_lineage() -> &'static [ContractLineageEntry] {
    reputation_gen::LEGACY_REPUTATION_CONTRACT
}

/// Superseded generations of the mailbox contract, oldest first.
pub fn mailbox_lineage() -> &'static [ContractLineageEntry] {
    mailbox_gen::LEGACY_MAILBOX_CONTRACT
}

/// Superseded generations of the harvest delegate, oldest first.
///
/// Recorded and exercised by tests, but nothing recovers from them yet: the
/// export handshake needs the PREDECESSOR delegate to answer an export
/// request, and no generation before the current one has an export handler.
/// See `legacy/harvest_delegate.toml`.
pub fn delegate_lineage() -> &'static [DelegateLineageEntry] {
    delegate_gen::LEGACY_HARVEST_DELEGATE
}

/// Which artifact a probe is for. Used to key durable markers, so that a
/// store and a mailbox whose instance ids somehow coincided could not share
/// one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Artifact {
    Store,
    Reputation,
    Mailbox,
}

impl Artifact {
    pub fn as_str(self) -> &'static str {
        match self {
            Artifact::Store => "store",
            Artifact::Reputation => "reputation",
            Artifact::Mailbox => "mailbox",
        }
    }

    pub fn lineage(self) -> &'static [ContractLineageEntry] {
        match self {
            Artifact::Store => store_lineage(),
            Artifact::Reputation => reputation_lineage(),
            Artifact::Mailbox => mailbox_lineage(),
        }
    }
}

// --- parameters ---------------------------------------------------------

/// The store parameters a seller's store is published under.
///
/// These must match `create_store_contracts` exactly, or every id derived here
/// names a contract that does not exist. The seller's key is the only
/// parameter, which is what makes every generation's store instance derivable
/// from the seller's ghostkey alone -- the Bitcoin trust configuration used to
/// sit here too and is now per-order, so it can no longer re-key a store.
pub fn store_params(seller_verifying_key: &ed25519_dalek::VerifyingKey) -> StoreParameters {
    StoreParameters::new(*seller_verifying_key)
}

/// The FIRST store generation published under the old `StoreParameters` shape.
///
/// See [`published_under_legacy_store_params`] for why the band has a lower
/// end at all.
pub const FIRST_LEGACY_STORE_PARAM_GENERATION: u32 = 2;

/// The last store generation published under the old `StoreParameters` shape.
pub const LAST_LEGACY_STORE_PARAM_GENERATION: u32 = 5;

/// Whether generation `generation` was published under
/// [`legacy_store_params_cbor`] rather than under today's encoding.
///
/// # Why a generation split exists at all
///
/// A contract's address is `BLAKE3(code_hash || parameter_bytes)`, and
/// `freenet_migrate::ContractLineageEntry` carries only the code hash: the
/// crate derives every predecessor's id using the parameters the CURRENT build
/// encodes. That is right as long as the parameter *encoding* never changes,
/// and it silently stops being right the moment it does -- the probe walks a
/// list of addresses that never existed, finds nothing at every one, and
/// reports a clean "nothing to migrate".
///
/// # Why it is a band and not a threshold
///
/// The encoding did not change once. It changed and then changed back:
///
/// | generation | built at  | `StoreParameters` | cbor  |
/// |------------|-----------|-------------------|-------|
/// | V1         | `ded0e3a` | 1 field           | 56 B  |
/// | V2..=V5    | `78d1020`..`9e3e1fb` | 3 fields | 109 B |
/// | V6..       | `ea94a33` | 1 field           | 56 B  |
///
/// `7c192d2` added `trusted_bitcoin_bridges` and `bitcoin_address_code_hash`
/// (first shipped in the V2 artifact); `fc760ed` moved them onto `Order`
/// again (first shipped in the V6 artifact). So the legacy encoding is a
/// middle band, which a single "at or below" threshold cannot express: as one,
/// it bucketed V1 as legacy, because generations are 1-based.
///
/// That was the whole of the bug worth naming here. **V1 is the only
/// generation ever published to the network** -- its code hash `4d7ad3c3...`
/// is what `git show origin/main:ui/public/contracts/store_contract.wasm`
/// hashes to -- so deriving it under the wrong encoding meant the probe could
/// not find the one store that exists, and said "nothing to migrate" about it.
///
/// These are fixed historical facts, not things to bump on the next re-key: a
/// generation added from here on is published under the current shape, so it
/// falls outside the band on its own.
pub fn published_under_legacy_store_params(generation: u32) -> bool {
    (FIRST_LEGACY_STORE_PARAM_GENERATION..=LAST_LEGACY_STORE_PARAM_GENERATION).contains(&generation)
}

/// The parameter bytes generations
/// [`FIRST_LEGACY_STORE_PARAM_GENERATION`]..=[`LAST_LEGACY_STORE_PARAM_GENERATION`]
/// were actually published under.
///
/// Mirrors the old `StoreParameters` exactly, including the values
/// `create_store_contracts` supplied for the two Bitcoin fields: an empty
/// bridge list and no code hash. This is a frozen record of bytes that already
/// exist on the network, so it is written out here rather than derived from
/// the live struct -- deriving it from a type that is still being edited is
/// how it would go quietly wrong again.
fn legacy_store_params_cbor(
    seller_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<Parameters<'static>, String> {
    #[derive(serde::Serialize)]
    struct LegacyStoreParameters {
        seller_verifying_key: ed25519_dalek::VerifyingKey,
        trusted_bitcoin_bridges: Vec<[u8; 32]>,
        bitcoin_address_code_hash: Option<[u8; 32]>,
    }
    encode_params(&LegacyStoreParameters {
        seller_verifying_key: *seller_verifying_key,
        trusted_bitcoin_bridges: Vec::new(),
        bitcoin_address_code_hash: None,
    })
}

/// Every superseded store instance to probe, newest generation first, each id
/// derived under the parameter encoding ITS generation was published with.
///
/// This is what `freenet_migrate::NewestFirst::from_lineage` would do if the
/// encoding had never changed; it exists only because it did. See
/// [`published_under_legacy_store_params`].
pub fn store_candidate_ids(
    seller_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<Vec<ContractInstanceId>, String> {
    let current = encode_params(&store_params(seller_verifying_key))?;
    let legacy = legacy_store_params_cbor(seller_verifying_key)?;

    let mut by_generation: Vec<(u32, ContractInstanceId)> = store_lineage()
        .iter()
        .map(|e| {
            let params = if published_under_legacy_store_params(e.generation) {
                &legacy
            } else {
                &current
            };
            (
                e.generation,
                contract_id_from_code_hash(&e.code_hash, params),
            )
        })
        .collect();
    // Same ordering rule as `NewestFirst::from_lineage`: by the registry's
    // declared generation, never by slice order.
    by_generation.sort_by_key(|(generation, _)| core::cmp::Reverse(*generation));
    Ok(by_generation.into_iter().map(|(_, id)| id).collect())
}

/// [`store_candidate_ids`] as the ordering-proof type `ProbeSession` wants.
///
/// `assume_ordered` is safe here for the reason it asks for: the list is sorted
/// by the registry's declared `generation`, descending, immediately above.
pub fn store_candidates(
    seller_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<freenet_migrate::NewestFirst, String> {
    Ok(freenet_migrate::NewestFirst::assume_ordered(
        store_candidate_ids(seller_verifying_key)?,
    ))
}

pub fn mailbox_params(owner_verifying_key: &ed25519_dalek::VerifyingKey) -> MailboxParameters {
    MailboxParameters::new(*owner_verifying_key)
}

pub fn reputation_params(
    rsa_public_key_der: Vec<u8>,
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> ReputationParameters {
    ReputationParameters::new(rsa_public_key_der, *owner_verifying_key)
}

/// The reputation probe's inputs, which cannot be assembled without the RSA
/// public key the harvest delegate holds.
///
/// This type exists to make the ordering constraint structural rather than
/// remembered: there is no way to start a reputation probe while the delegate
/// secret is still missing, because there is no way to build this.
pub struct ReputationProbeInputs {
    pub params: ReputationParameters,
}

/// Assemble the reputation probe's inputs, or `None` if the delegate has not
/// yet produced this identity's RSA public key.
///
/// `None` means **not yet**, never "nothing to migrate". The caller must not
/// substitute a placeholder key or fall back to probing without one: the ids
/// would be wrong, the walk would find nothing, and a seal on that would
/// strand a recoverable instance permanently.
pub fn reputation_probe_inputs(
    rsa_public_key_der: Option<&Vec<u8>>,
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Option<ReputationProbeInputs> {
    let der = rsa_public_key_der?;
    if der.is_empty() {
        return None;
    }
    Some(ReputationProbeInputs {
        params: reputation_params(der.clone(), owner_verifying_key),
    })
}

/// CBOR-encode parameters the way the contracts do.
pub fn encode_params<T: serde::Serialize>(params: &T) -> Result<Parameters<'static>, String> {
    harvest_common::to_cbor(params)
        .map(Parameters::from)
        .map_err(|e| format!("serialize contract parameters: {e}"))
}

/// The instance ids of every superseded generation, for these parameters.
///
/// The crate's own derivation, re-exported rather than reimplemented: this is
/// the function whose agreement with the node's addressing the whole scheme
/// rests on, and a second copy is a second thing to get wrong.
pub use freenet_migrate::predecessor_ids;

/// The instance id this build's WASM produces for these parameters.
pub fn current_id(code_hash: &[u8; 32], params: &Parameters<'_>) -> ContractInstanceId {
    contract_id_from_code_hash(code_hash, params)
}

// --- state semantics ----------------------------------------------------

thread_local! {
    /// What a migration could not carry forward, waiting to be told to the
    /// person who lost it.
    ///
    /// # Why a collector rather than a return value
    ///
    /// The fold's outcome reaches the UI through `ProbeStateOps`, whose
    /// methods are `freenet_migrate`'s and return only the merged state --
    /// there is nowhere in that signature to put "and here is what I refused".
    /// The alternative is threading a handle through a foreign generic
    /// session type, which is more moving parts than the thing being
    /// reported.
    ///
    /// `thread_local` rather than a `Mutex`: this is single-threaded in the
    /// browser, and per-thread is what keeps `cargo test`'s parallel tests
    /// from seeing each other's reports -- the cross-test interference this
    /// project has a rule about.
    static UNCARRIED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Record that a migration could not carry something forward.
///
/// Beside [`probe_warn`], not instead of it: the log line is for whoever is
/// debugging, and this is for the person whose data it was.
pub(crate) fn record_uncarried(what: String) {
    UNCARRIED.with(|lost| lost.borrow_mut().push(what));
}

/// Take everything a migration could not carry, clearing it.
///
/// Draining is what stops one migration's loss being announced again on every
/// later notification, which would teach a seller the message means nothing.
pub fn take_uncarried() -> Vec<String> {
    UNCARRIED.with(|lost| std::mem::take(&mut *lost.borrow_mut()))
}

/// Say something the operator needs to hear, from a file that is compiled
/// twice.
///
/// This module is built into the Dioxus web app AND, by `#[path]`, into
/// `tests/rehearsal` -- a plain native binary that deliberately does not
/// depend on dioxus (see its `Cargo.toml`: it is its own workspace so that
/// building it can never move a dependency version and re-key an artifact).
/// So the file cannot name `dioxus` unconditionally. The wasm build is the
/// browser one and has the logger; every other build has a stderr.
fn probe_warn(message: &str) {
    #[cfg(target_arch = "wasm32")]
    dioxus::logger::tracing::warn!("{message}");
    #[cfg(not(target_arch = "wasm32"))]
    eprintln!("{message}");
}

/// Decode a probed state, saying out loud when bytes that ARE there cannot be
/// read.
///
/// `ProbeStateOps::decode` returns an `Option`, so on its own it collapses two
/// completely different situations into `None`: "this address holds nothing"
/// and "this address holds a state I could not parse". The probe treats the
/// second as the first, walks on, and can go on to report a clean "nothing to
/// migrate" over a store it actually found and read off the network.
///
/// That is not hypothetical -- it is exactly what hid `StoreStateV1::orders`
/// having no `#[serde(default)]`, which made every real V1 state undecodable.
/// The control flow is unchanged (an unreadable state is still not a
/// migration candidate: there is nothing useful to do with bytes we cannot
/// parse), but it no longer happens silently.
fn decode_probed_state<T>(artifact: &str, bytes: &[u8]) -> Option<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    if bytes.is_empty() {
        // Genuinely absent. Not a decode failure, and not worth a line.
        return None;
    }
    match harvest_common::from_cbor::<T>(bytes) {
        Ok(state) => Some(state),
        Err(e) => {
            probe_warn(&format!(
                "migration probe: {} bytes of {artifact} state are present but did NOT decode \
                 -- treating as no candidate, which is NOT the same as an empty address. \
                 This is how a recoverable generation goes missing silently. serde: {e}",
                bytes.len()
            ));
            None
        }
    }
}

/// Merge rules for a store's state.
///
/// The merge is the contract's own `ComposableState::merge`, reused rather
/// than reimplemented: folding a generation is then the same operation the
/// network performs between two peers, so its correctness does not have to be
/// argued separately from the contract's.
pub struct StoreOps {
    pub params: StoreParameters,
}

impl ProbeStateOps for StoreOps {
    type State = StoreStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        decode_probed_state("store", bytes)
    }

    /// "Real" means the seller actually did something with this store.
    ///
    /// A store PUT at creation time holds `StoreStateV1::default()`: info at
    /// version 0 (the uninitialized version `verify` skips), no listings, no
    /// orders. Adopting one of those would report a hit while recovering
    /// nothing, and -- worse -- could satisfy a caller that stops at the first
    /// hit, so a genuinely populated older generation would never be reached.
    fn is_real(&self, state: &Self::State) -> bool {
        state.info.info.version > 0
            || !state.listings.listings.is_empty()
            || !state.orders.orders.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        merge_store(recovered, local, &self.params, DiscardedSide::LocalSnapshot)
    }

    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        merge_store(newer, &older, &self.params, DiscardedSide::Predecessor)
    }
}

/// **The keep-primary arm of every fold, in one place.**
///
/// A fold that cannot apply a predecessor generation keeps the newer one --
/// the behaviour `ProbeStateOps` documents, and the right one, since a
/// partially-applied state is worse than an unapplied one. What must never
/// happen is that it does so in SILENCE: a migration that found a populated
/// predecessor and carried none of it is otherwise indistinguishable, in the
/// log and on screen, from one that found nothing. **And this migration
/// SEALS** -- `seal_decision` writes a durable marker on a clean `Recovered`,
/// which gates future walks, so a generation dropped quietly on the sealing
/// run is never looked at again. Nothing is destroyed (predecessors stay on
/// the network and the merge only ever adds), but the app stops asking.
///
/// # Why this is a function rather than three `probe_warn` calls
///
/// Because there were three arms and only one of them warned. `merge_mailbox`
/// got the warning; `merge_store` never had one, and the reputation fold's
/// report covered token collisions but not the whole-generation refusal --
/// measured at 0 of 3 predecessor entries carried, 2 of them verifiable, with
/// nothing said. Three arms that each have to remember is the same shape as
/// three sites each deciding "already held" for themselves, and it failed the
/// same way. There is now one place to forget, and it is this one.
///
/// The `discarded` flag is returned rather than only logged so a test can
/// observe it; a `probe_warn` alone has no consumer a test can reach.
fn fold_or_keep_primary<S: Clone>(
    artifact: &str,
    mut base: S,
    apply: impl FnOnce(&mut S) -> Result<(), String>,
) -> FoldOutcome<S> {
    let snapshot = base.clone();
    match apply(&mut base) {
        Ok(()) => FoldOutcome {
            state: base,
            discarded: false,
        },
        Err(e) => {
            probe_warn(&format!(
                "migration fold: the predecessor {artifact} generation was REFUSED in full \
                 and none of it was carried into the new generation -- keeping the newer \
                 generation unchanged. This is how a recoverable generation goes missing \
                 silently, and this migration seals, so it will not be looked at again. \
                 reason: {e}"
            ));
            FoldOutcome {
                state: snapshot,
                discarded: true,
            }
        }
    }
}

/// The result of a fold, and whether it discarded the predecessor wholesale.
pub(crate) struct FoldOutcome<S> {
    pub(crate) state: S,
    /// True when the whole predecessor generation was refused. Distinct from
    /// the per-item report (`MailboxFold::dropped_oversized`), which describes
    /// things that did not fit an otherwise-successful fold.
    pub(crate) discarded: bool,
}

/// Which side of a fold `other` is, so a discard is described truthfully.
///
/// # Why the message cannot be unconditional
///
/// `merge_store_reporting_discard` has two callers and `other` means a
/// different thing in each: for `merge_generations` it is the PREDECESSOR,
/// which is what the upgrade wording is written for; for `merge_with_local`
/// it is this node's own CURRENT-generation snapshot.
///
/// Telling a seller that the store already at the new address "was not
/// carried over when Harvest upgraded" and that they should republish it
/// would be false, and would send them re-publishing data that is fine.
/// Reachability is low -- a local snapshot's listings are current-derivation
/// by construction, so the merge should not refuse them -- but this message
/// is seen once and then the data is gone, which is the standard that forbids
/// relying on "should not".
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum DiscardedSide {
    /// An older generation, refused while being carried forward.
    Predecessor,
    /// This node's own snapshot of the current generation, refused while
    /// being merged with what was recovered.
    LocalSnapshot,
}

fn merge_store(
    base: StoreStateV1,
    other: &StoreStateV1,
    params: &StoreParameters,
    side: DiscardedSide,
) -> StoreStateV1 {
    merge_store_reporting_discard(base, other, params, side).state
}

/// [`merge_store`], saying whether it discarded the predecessor wholesale.
///
/// A merge fails here when the other side carries a listing whose signature
/// does not verify against these parameters. Discarding that side is the right
/// answer -- but it takes every VERIFIED listing with it, measured at 0 of 2
/// carried with 1 verifiable, so it is reported rather than assumed harmless.
pub(crate) fn merge_store_reporting_discard(
    base: StoreStateV1,
    other: &StoreStateV1,
    params: &StoreParameters,
    side: DiscardedSide,
) -> FoldOutcome<StoreStateV1> {
    use freenet_scaffold::ComposableState;
    let snapshot = base.clone();
    let mut outcome =
        fold_or_keep_primary("store", base, |base| base.merge(&snapshot, params, other));
    // The scaffold's merge skips `ListingsV1::apply_delta` when the other side
    // brings nothing new, so a base written under the old, permissive `verify`
    // would be carried forward unsorted, and the current contract refuses that
    // (harvest#26).
    outcome.state.listings.normalize();
    if outcome.discarded {
        // Named specifically, and here rather than in `fold_or_keep_primary`,
        // because this is the only place that still holds the refused side
        // and can say WHAT was in it. "Migration incomplete" is not something a
        // seller can act on; "your store's name and two listings were not
        // carried, republish them" is.
        record_uncarried(describe_lost_store(other, side));
    }
    outcome
}

/// What a seller lost when a predecessor store generation was refused.
///
/// # Why this is a whole function
///
/// It is the only thing the person affected ever sees about it. The migration
/// SEALS after a fold, so there is no second attempt and no later screen where
/// this turns up again -- one message, once, and then the data is gone for
/// good. That is also why it names the store rather than an artifact: a seller
/// with several stores needs to know which one.
///
/// # Why it says the loss was EXPECTED
///
/// Because it was: Ian decided on 2026-09-06 that no published store holds
/// data worth preserving and that sellers republish. A message that describes
/// a deliberate consequence in the language of a fault sends the seller
/// looking for a bug, or for someone to report it to, when the only useful
/// thing they can do is republish. The distinction between "a decision we
/// made" and "a thing that happened to you" is carried entirely by this
/// sentence, so it is asserted rather than left to whoever edits the copy
/// next.
fn describe_lost_store(lost: &StoreStateV1, side: DiscardedSide) -> String {
    let name = lost.info.info.store_name.trim();
    let which = if name.is_empty() {
        "One of your stores".to_string()
    } else {
        format!("Your store \"{name}\"")
    };
    let listings = lost.listings.listings.len();
    let orders = lost.orders.orders.len();

    let mut said = match side {
        DiscardedSide::Predecessor => format!(
            "{which} was not carried over when Harvest upgraded. This is expected -- an \
             upgrade moves your store to a new address and this one could not be brought \
             across -- but it does mean the following is gone: its name, description and \
             seller certificate"
        ),
        // Deliberately different: this store is at the new address and is not
        // going anywhere. What failed is the merge, not the store, so
        // "republish it" would send the seller re-publishing data that is
        // fine.
        DiscardedSide::LocalSnapshot => format!(
            "{which} could not be merged with what was recovered from an earlier version of \
             Harvest. Your store here is intact; what could not be brought in alongside it \
             is: its name, description and seller certificate"
        ),
    };
    if listings > 0 {
        said.push_str(&format!(", {listings} listing(s)"));
    }
    if orders > 0 {
        said.push_str(&format!(", {orders} order(s)"));
    }
    said.push_str(match side {
        DiscardedSide::Predecessor => {
            ". Nothing was recovered and it will not be retried. Publish your store details \
             and listings again to carry on selling."
        }
        DiscardedSide::LocalSnapshot => {
            ". Nothing from the earlier version was recovered and it will not be retried. \
             Your current store is unaffected."
        }
    });
    said
}

/// Merge rules for a reputation contract's state.
pub struct ReputationOps {
    pub params: ReputationParameters,
}

impl ProbeStateOps for ReputationOps {
    type State = ReputationStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        decode_probed_state("reputation", bytes)
    }

    /// Feedback is what a reputation contract is for. A state holding only a
    /// certificate is the shell created alongside a store and carries nothing
    /// to recover.
    fn is_real(&self, state: &Self::State) -> bool {
        !state.feedback.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        merge_reputation(recovered, local, &self.params)
    }

    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        merge_reputation(newer, &older, &self.params)
    }
}

/// The reputation contract's own merge, `ReputationStateV1::merge`, which is
/// also its `update_state`'s `UpdateData::State` arm.
fn merge_reputation(
    base: ReputationStateV1,
    other: &ReputationStateV1,
    params: &ReputationParameters,
) -> ReputationStateV1 {
    merge_reputation_reporting_discard(base, other, params).state
}

/// [`merge_reputation`], saying whether it discarded the other side wholesale.
///
/// # There is no per-entry exclusion to report any more
///
/// This used to report entries it could not carry because they shared a
/// token with a DIFFERENT entry the successor held: the RSA signature covered
/// the token alone, so both were validly signed, nothing could tell which was
/// genuine, and whichever side the fold held won. harvest#22 closed that. The
/// token's entry key now signs every field, so a third party cannot build a
/// variant at all, and two entries the buyer signed for one token are
/// resolved by a total order over their bytes -- the same survivor whichever
/// side it is on, so nothing is excluded by the order of the fold.
///
/// One unverifiable entry still rejects the WHOLE delta, taking every
/// verifiable entry with it; that is reported through `discarded`. Every
/// generation before this one signed nothing but the token, so its entries
/// all fail here -- see `legacy/reputation_contract.toml`.
pub(crate) fn merge_reputation_reporting_discard(
    base: ReputationStateV1,
    other: &ReputationStateV1,
    params: &ReputationParameters,
) -> FoldOutcome<ReputationStateV1> {
    fold_or_keep_primary("reputation", base, |base| base.merge(params, other))
}

/// Merge rules for a mailbox's state.
pub struct MailboxOps {
    pub params: MailboxParameters,
}

impl ProbeStateOps for MailboxOps {
    type State = MailboxStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        decode_probed_state("mailbox", bytes)
    }

    fn is_real(&self, state: &Self::State) -> bool {
        !state.messages.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        merge_mailbox(recovered, local)
    }

    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        merge_mailbox(newer, &older)
    }
}

/// The mailbox contract's own merge: hand everything to `apply_delta` and let
/// it decide what is already held and what the cap keeps.
///
/// # It used to decide "already held" here, by nonce
///
/// It filtered on `held.nonce == m.nonce`, which was right while the nonce
/// WAS the identity and silently wrong once `verify`, `summarize`, `delta`
/// and the dedup moved to `entry_digest`. This is the sharpest place for that
/// mistake to live: the fold runs during a RE-KEY, carrying a buyer's
/// messages forward from a superseded generation, so a message dropped here
/// is dropped at the moment the whole migration exists to preserve it.
///
/// It was the FOURTH site with this shape, and the first found by the source
/// scrape rather than by a person -- see
/// `mailbox-contract`'s `no_production_code_compares_message_nonces_for_identity`.
/// There is no comparison here any more; `apply_delta` dedups by
/// `entry_digest`, so handing it everything is correct and idempotent.
///
/// # It also used to drop an oversized message from one side only
///
/// `apply_delta` refuses a message over
/// `harvest_common::mailbox::MAX_MESSAGE_BYTES`, on the INCOMING side. A fold
/// puts the PREDECESSOR on that side, so the same message survived if it was
/// in the successor and vanished if it was in the predecessor -- a result that
/// depended on which side it arrived on rather than on the bytes, which is
/// exactly the commutativity `fold_all_policy`'s ack token is minted against.
/// The refusal is now applied to both sides here, before the merge, and what
/// it cannot carry is reported rather than swallowed. See
/// `merge_mailbox_reporting_drops` for why dropping is the right direction and
/// keeping is not.
///
/// Folding an older generation can push the mailbox over
/// `harvest_common::mailbox::MAX_MESSAGES` or
/// `harvest_common::mailbox::MAX_MAILBOX_BYTES`. `apply_delta` runs
/// `enforce_message_cap` on every call, which enforces the count cap and a
/// count cap per size class (which is how the byte bound is met since
/// harvest#85) and keeps the
/// highest-ranked messages by `(timestamp, nonce, entry_digest)` -- a total
/// order and a pure function of message content, so the fold result is trimmed
/// to exactly the subset any peer would keep from the same bytes.
///
/// What that does NOT give you is a guarantee the older generation's messages
/// survive the fold: a mailbox at the cap drops whatever ranks lowest, and both
/// ranking fields are chosen by whoever wrote the message. See
/// `MailboxStateV1::apply_delta` for what the cap does and does not buy.
///
/// This described a 30-day TTL prune until `ecbec18` deleted it -- retention
/// keyed on timestamps an unauthenticated sender controls let one message
/// dated far in the future evict every legitimate one. There is no age rule
/// here any more, and nothing in this module should imply one.
/// What a fold carried, and what it could not.
///
/// The count exists so the drop can be REPORTED. A migration whose whole
/// purpose is to carry messages forward must never fail to carry one in
/// silence, which is the same standard `decode_probed_state` already holds
/// itself to for the neighbouring failure.
pub(crate) struct MailboxFold {
    pub(crate) state: MailboxStateV1,
    /// DISTINCT messages refused by the size bound, across both sides.
    ///
    /// Distinct, because an oversized message present on both sides is one
    /// message that could not be carried, not two. Counting the raw drops
    /// double-counted it.
    pub(crate) dropped_oversized: usize,
    /// DISTINCT messages that fit the size bound but were pruned by the count
    /// caps (`MAX_MESSAGES` and the per-size-class caps, harvest#85) when the
    /// two sides were combined (PR #82 review, Should Fix 7).
    ///
    /// A fold is where a mailbox is most likely to go over a cap: two
    /// generations' messages meet for the first time. Pruning there is the
    /// same deterministic prune any peer would run, so it is not a defect,
    /// but it is a loss, and a loss during migration is reported rather than
    /// swallowed.
    pub(crate) pruned_by_cap: usize,
    /// The whole predecessor generation was refused. See [`FoldOutcome`].
    pub(crate) discarded: bool,
}

impl MailboxFold {
    /// What to tell the operator, or `None` if everything was carried.
    ///
    /// The text is built here rather than at the `probe_warn` call site so a
    /// test can assert on it. **What no test observes is the emission
    /// itself**: deleting the `probe_warn` line in [`merge_mailbox`] leaves
    /// the whole suite green, because a log line has no consumer a test can
    /// reach without a process-global sink -- and this repository's own rules
    /// name a process-global sink shared across parallel tests as its own
    /// trap. So the count and the wording are pinned and the call is not,
    /// which is stated here rather than left to be assumed.
    pub(crate) fn unfoldable_warning(&self) -> Option<String> {
        let mut said = Vec::new();
        if self.dropped_oversized > 0 {
            said.push(format!(
                "migration fold: {} message(s) exceed MAX_MESSAGE_BYTES ({}) and were NOT \
                 carried into the new generation. They cannot be: the successor contract's \
                 own apply_delta refuses them, so keeping one would leave this node holding \
                 an entry no peer has. This is how a message goes missing silently.",
                self.dropped_oversized,
                harvest_common::mailbox::MAX_MESSAGE_BYTES
            ));
        }
        if self.pruned_by_cap > 0 {
            said.push(format!(
                "migration fold: {} message(s) were pruned because the combined mailbox went \
                 over its count caps (MAX_MESSAGES {} and the per-size-class caps {:?}); the \
                 lowest-ranked go first, the same prune every peer runs.",
                self.pruned_by_cap,
                harvest_common::mailbox::MAX_MESSAGES,
                harvest_common::mailbox::SIZE_CLASS_CAPS
            ));
        }
        (!said.is_empty()).then(|| said.join(" "))
    }
}

/// [`merge_mailbox`], plus what it had to leave behind.
///
/// Split out from `merge_mailbox` so a test can assert on the count instead of
/// grepping a log; `merge_mailbox` is the plain-merge shape `ProbeStateOps`
/// wants.
pub(crate) fn merge_mailbox_reporting_drops(
    mut base: MailboxStateV1,
    other: &MailboxStateV1,
) -> MailboxFold {
    // The size bound is applied to BOTH sides, here, before the merge.
    //
    // `apply_delta` applies it to the INCOMING side only, which is correct for
    // the contract -- refusing an incoming message is recoverable, invalidating
    // a state a peer already holds is not. It is wrong for a FOLD, because
    // `merge_generations(newer, older)` puts the predecessor on the incoming
    // side: the same message survived if it was in the successor and was
    // dropped if it was in the predecessor. That is a merge whose result
    // depends on which side a message arrived on rather than on the bytes, and
    // commutativity is precisely what `FoldAllAck` is minted against
    // (`fold_all_policy`, and the crate's own `assert_merge_commutative`).
    //
    // Symmetry could have been restored in either direction; dropping is the
    // only one that works. `verify` refuses a state holding an oversized
    // message (harvest#85), so a fold that kept one could not be PUT at all.
    // Before harvest#85 it could, and was worse: every peer that merged it
    // refused the message in `apply_delta`, leaving this node holding an
    // entry no other peer had, for good.
    //
    // No published generation ever enforced a size limit -- `MAX_MESSAGE_BYTES`
    // and the send-side refusal both arrive on this branch, after the commit
    // recording V7 -- so a V1..V7 mailbox really can hold one, from a plaintext
    // over `LARGEST_BUCKET` or from an oversized `sender_public_key`, which was
    // an unbounded `Vec<u8>` in an open-write contract.
    let oversized = |m: &harvest_common::mailbox::EncryptedMessage| {
        harvest_common::mailbox::message_bytes(m) > harvest_common::mailbox::MAX_MESSAGE_BYTES
    };
    // Counted as DISTINCT entries, by digest. A message present on both sides
    // is one message the fold could not carry; counting the raw drops reported
    // it twice, and a migration report that overstates a loss is as
    // untrustworthy as one that understates it.
    let dropped_oversized = base
        .messages
        .iter()
        .chain(other.messages.iter())
        .filter(|m| oversized(m))
        .map(harvest_common::mailbox::entry_digest)
        .collect::<std::collections::HashSet<_>>()
        .len();
    base.messages.retain(|m| !oversized(m));
    let carried: Vec<_> = other
        .messages
        .iter()
        .filter(|m| !oversized(m))
        .cloned()
        .collect();

    // `apply_delta` has no `?` and no `return Err`; it ends `Ok(())`
    // unconditionally, so the keep-primary arm is unreachable today. It goes
    // through the shared helper rather than being special-cased, because the
    // semantics it encodes have to be decided somewhere and the shape it would
    // take if `apply_delta` became fallible is not obviously right: ONE refused
    // message would discard the WHOLE predecessor generation, which is much
    // harder to justify for a mailbox, where the predecessor may hold the only
    // copy of a conversation.
    // Everything that fit the size bound, by digest, so a message on both
    // sides counts once; whatever of it the result lacks was pruned by a cap.
    let offered: std::collections::HashSet<[u8; 32]> = base
        .messages
        .iter()
        .chain(carried.iter())
        .map(harvest_common::mailbox::entry_digest)
        .collect();
    let outcome = fold_or_keep_primary("mailbox", base, |base| base.apply_delta(&Some(carried)));
    let kept: std::collections::HashSet<[u8; 32]> = outcome
        .state
        .messages
        .iter()
        .map(harvest_common::mailbox::entry_digest)
        .collect();
    MailboxFold {
        pruned_by_cap: offered.difference(&kept).count(),
        state: outcome.state,
        dropped_oversized,
        discarded: outcome.discarded,
    }
}

fn merge_mailbox(base: MailboxStateV1, other: &MailboxStateV1) -> MailboxStateV1 {
    let fold = merge_mailbox_reporting_drops(base, other);
    if let Some(warning) = fold.unfoldable_warning() {
        probe_warn(&warning);
    }
    fold.state
}

// --- policy -------------------------------------------------------------

/// `FoldAll` for all three artifacts, and the acknowledgement is earned rather
/// than waved through.
///
/// Fold-all is only sound where deletions are EXPLICIT, because it resurrects
/// anything deleted by mere absence. For each of Harvest's three states:
///
/// * **Store** -- listings are grow-only and keyed by `ListingId`; the
///   contract has no removal path at all, so absence is never a deletion.
///   Orders are capacity-pruned by `enforce_order_cap`, which is deterministic
///   and re-run inside `apply_delta`, so a fold that re-admits a pruned order
///   is pruned again identically.
/// * **Reputation** -- one entry per token, keyed by `token.nonce`, with no
///   removal path whatsoever. Nothing can be resurrected because nothing is
///   ever deleted. Until harvest#22 a second entry could be published under a
///   token by anyone, because the RSA signature covered the token alone, and
///   the fold kept whichever side already held it, so a genuine entry could be
///   excluded by the fold. The token's entry key now signs every field, and
///   two entries its holder signed for one token are resolved by a total
///   order over their bytes, so the survivor does not depend on which side of
///   the fold it was on.
/// * **Mailbox** -- messages are keyed by
///   `harvest_common::mailbox::entry_digest` over the whole entry, and
///   capacity-pruned by `enforce_message_cap`, re-applied on every
///   `apply_delta`. Same argument as the order cap. (This said "keyed by
///   nonce" until 2026-09-05, which was the precise claim the entry-digest
///   change existed to retire, still standing in the soundness argument that
///   mints the token; and "pruned by a TTL measured against the newest message
///   present" until `ecbec18` deleted that rule. The soundness argument
///   survives both, because it never depended on WHICH deterministic
///   prune ran, only on there being one.)
///
/// **Does the mailbox argument still hold now that identity is the digest?
/// It holds, and it is STRONGER -- it does not merely transfer.** Fold-all is
/// unsound where absence encodes a deletion. Under nonce identity, absence had
/// a second cause: an entry sharing a nonce displaced another, so a message
/// could be missing from the successor because somebody removed it, and the
/// fold's own nonce filter then declined to bring it back -- which is exactly
/// the defect found at `merge_mailbox`. Under digest identity nothing is
/// removed by collision at all, so absence means only "never held it" or
/// "capacity-pruned", and the prune is deterministic and re-run on every
/// merge. The set of things a fold could fail to restore shrinks, and it
/// shrinks in the direction the ack cares about.
///
/// One property of the mailbox merge that this argument DOES depend on, and
/// that the obvious precondition test cannot see: the merge **normalises**.
/// It prunes to the caps and refuses oversized messages, so `merge(a, a) == a`
/// -- the strict idempotence `policy_check::assert_merge_idempotent` asserts
/// -- is false for any state that is not already normalised. That has been
/// true since the cap existed; a sample set of three small mailboxes simply
/// never met it. What fold-all needs instead is commutativity, order
/// invariance, idempotence on the merge's OWN OUTPUT, and absorption
/// (re-folding an already-folded generation is a no-op). All four are
/// asserted in `fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising`,
/// on samples DERIVED from the three bounds rather than written as numbers.
///
/// That derivation is the point, not a nicety. When this sentence first said
/// "samples that cross every bound" it was false: the largest sample was 2.86%
/// of `MAX_MAILBOX_BYTES`, and adding a sample that actually reached the byte
/// budget made freenet-migrate's own `assert_fold_order_invariant` FAIL. That
/// was the third time a precondition fixture had been too small to observe the
/// property it attests. The fixtures now compute their sizes from
/// `MAX_MESSAGE_BYTES`, `MAX_MESSAGES` and `MAX_MAILBOX_BYTES`, so they cannot
/// fall behind a retuned constant a fourth time.
///
/// The order-invariance failure was real. It was first fixed by making
/// `harvest_common::mailbox::enforce_message_cap` SKIP a message that would not
/// fit instead of stopping at it: under the prefix walk the surviving set
/// depended on which large message happened to block the walk, so removing the
/// blocker let a smaller message behind it fit, and a re-run of the migration
/// was not a fixed point. The skip was not a complete fix: `fdev verify-merge`
/// later found the merge still not associative (harvest#85), because a message
/// skipped while one merge had the budget full never came back. Since
/// harvest#85 the byte bound is met by a count cap per size class instead,
/// which is a matroid, so the greedy pick is path independent and the fold is
/// order invariant by construction.
///
/// Fold-all matters here rather than being a free upgrade: Harvest has re-keyed
/// repeatedly -- `legacy/store_contract.toml` records five superseded store
/// generations -- so a seller who used it across generations has listings at
/// several DIFFERENT instances, none of which was ever carried forward.
/// `NewestFirstWins` would stop at the newest populated one and leave the rest.
///
/// The preconditions are asserted on real states in this module's tests via
/// the crate's own `policy_check` helpers, which is the point of the ack being
/// a token rather than a comment.
pub fn fold_all_policy() -> SelectionPolicy {
    SelectionPolicy::FoldAll(FoldAllAck::i_understand_fold_all_resurrects_without_tombstones())
}

// --- sealing ------------------------------------------------------------

/// Whether a finished probe may record a durable "done" marker.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seal {
    /// Positive evidence: the data was found and the search was complete.
    Seal,
    /// Anything else. Adopt what there is, seal nothing, probe again next run.
    Retry,
}

/// The sealing rule.
///
/// Exactly one shape may seal: `Recovered` with **no** unresolved candidates
/// and **no** truncated fold. Everything else retries, including the wildcard
/// -- `Outcome` is `#[non_exhaustive]`, so a variant added by a future release
/// lands there, and a wildcard that defaulted to `Seal` would write a
/// permanent marker for a case this code has never seen.
///
/// `SeedLocal` is called out separately below because it is the one that looks
/// safe. It means every candidate answered and none held state -- but a
/// `NotFound` on Freenet is unauthenticated and routinely wrong (~99.6% of
/// `get_not_found` traffic was present-but-unfindable when the placement
/// migration was disabled, freenet-core#4440), and an undecodable answer lands
/// here too. Sealing on it would mark a live predecessor permanently empty.
pub fn seal_decision<S>(outcome: &Outcome<S>) -> Seal {
    match outcome {
        Outcome::Recovered {
            truncated_fold: false,
            unresolved,
            ..
        } if unresolved.is_empty() => Seal::Seal,
        // A recovery that is missing generations is a partial answer. Adopt it
        // -- the merge only ever adds -- but leave the migration open.
        Outcome::Recovered { .. } => Seal::Retry,
        // Never. See this function's docs.
        Outcome::SeedLocal { .. } => Seal::Retry,
        Outcome::Indeterminate { .. } => Seal::Retry,
        // An empty lineage is not evidence of anything. It also cannot happen
        // here -- ui/build.rs fails the build on a registry with no rows --
        // but sealing on it would be wrong if it ever did.
        Outcome::NoLegacy { .. } => Seal::Retry,
        _ => Seal::Retry,
    }
}

/// A one-line description of an outcome, for the log and the notification bar.
pub fn describe<S>(outcome: &Outcome<S>) -> String {
    match outcome {
        Outcome::Recovered {
            source,
            truncated_fold,
            unresolved,
            ..
        } => {
            let mut s = format!("recovered state from predecessor {source}");
            if *truncated_fold {
                s.push_str("; the fold was cut short by the hop cap");
            }
            if !unresolved.is_empty() {
                s.push_str(&format!(
                    "; {} predecessor(s) never answered, so this is not the whole story",
                    unresolved.len()
                ));
            }
            s
        }
        Outcome::SeedLocal { .. } => {
            "every predecessor answered and none held state; keeping local, sealing nothing"
                .to_string()
        }
        Outcome::Indeterminate { unresolved, .. } => format!(
            "{} predecessor(s) did not answer; adopting nothing and retrying later",
            unresolved.len()
        ),
        Outcome::NoLegacy { .. } => "no predecessor generations recorded".to_string(),
        _ => "unrecognised migration outcome; treating as retry".to_string(),
    }
}

// --- durable markers ----------------------------------------------------

/// The id under which a completed migration is recorded.
///
/// Keyed by `(artifact, instance, current code hash)`. The code hash is part
/// of the key because a marker only ever means "this generation has finished
/// pulling its predecessors forward" -- the next re-key produces a new key and
/// the walk runs again, which is the whole point.
///
/// **Both ids are hex.** Raw bytes in a storage key alias: anything that puts
/// a key through a lossy UTF-8 conversion maps every invalid byte to U+FFFD,
/// so two distinct 32-byte ids collapse onto one marker slot and one of them
/// gets sealed having never been migrated. River hit exactly that.
///
/// The `v1.` prefix versions the id FORMAT. It is the client that mints these,
/// so a change of shape has to invalidate the old ones from here; the delegate
/// only prefixes its own namespace and cannot know the format moved.
///
/// This is an id, not a storage key: the harvest delegate concatenates it onto
/// `harvest:migrate:` itself, so nothing chosen here can name another secret.
pub fn marker_key(
    artifact: Artifact,
    instance: &ContractInstanceId,
    current_code_hash: &[u8; 32],
) -> String {
    format!(
        "v1.{}.{}.{}",
        artifact.as_str(),
        hex::encode(instance.as_bytes()),
        hex::encode(current_code_hash),
    )
}

/// What the delegate said about a marker -- or failed to say.
///
/// The third variant is the one that matters. A marker query can fail to
/// produce an answer in ways that are not "absent": the delegate may not be
/// registered yet, the send may fail, the reply may never arrive. Those are
/// silence, and silence has to be distinguishable from a definite `Absent` at
/// the type level so neither can be quietly read as the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MarkerLookup {
    /// The delegate answered: this migration is already recorded as done.
    Present,
    /// The delegate answered: nothing is recorded.
    Absent,
    /// No usable answer -- not registered, send failed, or nothing came back.
    Unavailable,
}

/// Whether a probe should run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate {
    /// The marker says this generation already finished. Skip.
    Skip,
    /// Run the walk.
    Run,
}

/// The repeat gate: **only a definite `Present` skips.**
///
/// # Why the direction is the whole design
///
/// This gate used to be a `localStorage` read, which in the deployed gateway
/// is not a gate at all: Freenet serves a webapp inside an iframe with no
/// `allow-same-origin`, so the frame has an opaque origin and
/// `window.localStorage` throws. The marker worked under `dx serve` and was a
/// silent no-op once published -- every seller re-swept every generation of
/// every artifact on every page load, forever. It cost performance and nothing
/// else, and the reason it cost nothing else is precisely this direction:
/// storage that cannot answer reads as "not migrated".
///
/// So the marker moved into the harvest delegate's secret store (which is
/// where River keeps its own, for the same reason), and the direction moved
/// with it. `Unavailable` runs the walk. A walk that did not need to run
/// merges what it finds into what is already there and adds nothing; a walk
/// that was skipped because a storage failure looked like "done" leaves the
/// seller's listings at an address nothing will ever visit again.
pub fn probe_gate(lookup: MarkerLookup) -> Gate {
    match lookup {
        MarkerLookup::Present => Gate::Skip,
        MarkerLookup::Absent => Gate::Run,
        // Never `Skip`. See this function's docs.
        MarkerLookup::Unavailable => Gate::Run,
    }
}

/// The delegate request that asks whether a marker is recorded.
///
/// Built here rather than at the call site so the wire shape is next to the
/// rules it serves, and so it is exercised by this module's native tests --
/// the call site is wasm-only.
pub fn marker_query(marker: &str) -> harvest_common::HarvestDelegateRequest {
    harvest_common::HarvestDelegateRequest::GetMigrationMarker {
        marker: marker.to_string(),
    }
}

/// The delegate request that records a completed migration.
///
/// Best effort by design: a write the delegate refuses means the probe
/// repeats, which is wasteful and correct.
pub fn marker_write(marker: &str, note: &str) -> harvest_common::HarvestDelegateRequest {
    harvest_common::HarvestDelegateRequest::SetMigrationMarker {
        marker: marker.to_string(),
        note: note.to_string(),
    }
}

// --- the probe, as a hand-pumped session -------------------------------

/// One probe of one artifact for one identity.
///
/// # Why hand-pumped rather than `migrate_contract`
///
/// `freenet_migrate::migrate_contract` wants an awaitable
/// request/response adapter. The browser does not have one: `WebApi` delivers
/// every response to a single app-registered handler, so correlation is the
/// app's job. `ProbeDriver` is the crate's sans-IO answer to exactly that
/// environment, and this is a thin wrapper over it -- the two make identical
/// decisions.
///
/// Wrapping rather than using `ProbeDriver` directly at the call site buys one
/// thing that matters: the sequencing lives in native-testable code. The
/// wasm-only part is reduced to sending a GET, arming a timer, and routing a
/// response, and everything with a decision in it -- what to ask next, what a
/// silence means, whether the result may be sealed -- is exercised by
/// `cargo test` on the host.
pub struct ProbeSession<O: ProbeStateOps> {
    driver: freenet_migrate::ProbeDriver<O>,
    /// The candidate a GET is outstanding for, if any. Held here as well as in
    /// the driver so a stale response or a fired timer can be recognised as
    /// stale by the caller before it reaches the driver.
    outstanding: Option<ContractInstanceId>,
    finished: Option<(Outcome<O::State>, Seal)>,
}

impl<O: ProbeStateOps> ProbeSession<O> {
    /// Start a probe over a lineage.
    ///
    /// Candidates are ordered by the registry's `generation` field, descending
    /// -- never by slice order, so a generation appended out of order (which is
    /// exactly what "append the outgoing hash" invites) is still probed in the
    /// right place.
    pub fn start(
        ops: O,
        local_snapshot: O::State,
        params: &Parameters<'_>,
        lineage: &[ContractLineageEntry],
        policy: SelectionPolicy,
    ) -> Self {
        Self::start_with_candidates(
            ops,
            local_snapshot,
            freenet_migrate::NewestFirst::from_lineage(params, lineage),
            policy,
        )
    }

    /// Start a probe over candidates the caller derived itself.
    ///
    /// Only for an artifact whose PARAMETER ENCODING changed at some point in
    /// its lineage, so one set of parameter bytes cannot address every
    /// generation -- see [`store_candidates`]. Everything else should use
    /// [`start`](Self::start), which cannot be handed a wrong order.
    pub fn start_with_candidates(
        ops: O,
        local_snapshot: O::State,
        candidates: freenet_migrate::NewestFirst,
        policy: SelectionPolicy,
    ) -> Self {
        Self {
            driver: freenet_migrate::ProbeDriver::new(ops, local_snapshot, candidates, policy),
            outstanding: None,
            finished: None,
        }
    }

    /// The next candidate to GET, or `None` when the probe is finished.
    ///
    /// Idempotent: asking again without an intervening event returns the same
    /// candidate rather than advancing.
    pub fn next_get(&mut self) -> Option<ContractInstanceId> {
        if self.finished.is_some() {
            return None;
        }
        match self.driver.next_action() {
            freenet_migrate::Step::Get(id) => {
                self.outstanding = Some(id);
                Some(id)
            }
            freenet_migrate::Step::Done => {
                self.outstanding = None;
                if let Some(outcome) = self.driver.take_outcome() {
                    let seal = seal_decision(&outcome);
                    self.finished = Some((outcome, seal));
                }
                None
            }
        }
    }

    /// The candidate a GET is currently outstanding for.
    pub fn outstanding(&self) -> Option<ContractInstanceId> {
        self.outstanding
    }

    /// A GET response arrived for `id`.
    pub fn on_state(&mut self, id: ContractInstanceId, bytes: &[u8]) {
        self.driver.on_response(id, bytes);
        self.clear_if(id);
    }

    /// The node answered, positively, that there is nothing at `id`
    /// (`ContractResponse::NotFound`).
    ///
    /// Only ever call this for an answer actually received. Routing a deadline
    /// here types silence as absence, which is the data-loss default
    /// freenet-migrate#19 exists to remove.
    pub fn on_absent(&mut self, id: ContractInstanceId) {
        self.driver.on_absent(id);
        self.clear_if(id);
    }

    /// Nothing came back for `id`: a timeout, a send failure, an unexpected
    /// response, an error the transport could not attribute.
    ///
    /// This establishes nothing, so the candidate is recorded as unresolved
    /// and the walk can never end in a sealable outcome because of it.
    pub fn on_unknown(&mut self, id: ContractInstanceId) {
        self.driver.on_unknown(id);
        self.clear_if(id);
    }

    fn clear_if(&mut self, id: ContractInstanceId) {
        if self.outstanding == Some(id) {
            self.outstanding = None;
        }
    }

    /// The terminal outcome and whether it may seal a durable marker, once the
    /// probe is done. `None` while it is still running.
    ///
    /// Taking it leaves the session finished; a second call returns `None`.
    pub fn take_result(&mut self) -> Option<(Outcome<O::State>, Seal)> {
        self.finished.take()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod predecessor_generation_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_stdlib::prelude::ContractInstanceId;
    use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};

    /// The listing id derivation as it was BEFORE this branch: seller
    /// fingerprint, creation time and title, truncated to 16 bytes.
    ///
    /// Written out here rather than imported, because the point is to build a
    /// record the way a PREDECESSOR generation built it. Importing today's
    /// function would make the test agree with itself.
    fn v1_listing_id(
        seller_fingerprint: &str,
        created_at: &chrono::DateTime<chrono::Utc>,
        title: &str,
    ) -> ListingId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seller_fingerprint.as_bytes());
        hasher.update(&created_at.timestamp_millis().to_le_bytes());
        hasher.update(title.as_bytes());
        // The old width, zero-extended into today's type -- which is what a
        // record from before the widening would look like IF the decode
        // succeeded. It does not (see
        // `payment::order_wire_compat_tests::an_order_from_before_the_id_was_widened_does_not_decode`),
        // so this stands in for the derivation-only half of the boundary: a
        // record whose bytes still decode but whose id is not the one its
        // terms give.
        let mut id = [0u8; 32];
        id[..16].copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        ListingId(id)
    }

    fn signed(listing: Listing, key: &SigningKey) -> AuthorizedListing {
        let message = harvest_common::to_cbor(&listing).expect("serialize");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        AuthorizedListing {
            signature: key.sign(&scoped_payload).to_bytes().to_vec(),
            listing,
            scoped_payload,
            certificate_pem: String::new(),
        }
    }

    /// **KNOWN GAP: a predecessor generation's store is discarded in full,
    /// and the seller is told only in a console log.**
    ///
    /// This branch made a listing's id a function of its own terms. That is
    /// right, and it is what stops two differently-priced listings sharing an
    /// id and diverging permanently. But it also means every listing
    /// published under a PREVIOUS generation carries an id the current
    /// `AuthorizedListing::verify` refuses -- and `ListingsV1::apply_delta`
    /// returns on the first refusal, so `fold_or_keep_primary` keeps the
    /// newer generation and drops the predecessor **entirely**: the listings,
    /// the orders, and the store's own info with them. A seller upgrading
    /// loses their shop.
    ///
    /// Three things make it worse than the loss itself, and they are why this
    /// is pinned rather than left to the prose:
    ///
    /// * it is reported by `probe_warn`, which is a browser console line and
    ///   not something a user sees;
    /// * the fold's own message says the migration then SEALS, so the
    ///   generation is never looked at again;
    /// * every other test in this repository builds its fixtures with the
    ///   NEW derivation, so none of them can see it.
    ///
    /// **There is no clean repair and that is why this is a decision rather
    /// than a bug to fix here.** The id is inside what the seller signed, so
    /// the fold cannot re-stamp a record without invalidating its signature.
    /// Accepting the old form in `verify` would work mechanically -- the
    /// seller's fingerprint is derivable from the verifying key `verify`
    /// already holds -- but it reopens exactly the hole the change closed,
    /// since a seller could still mint two listings under one old-form id.
    /// So the options are to accept the loss loudly, or not to make the
    /// change; both are product decisions.
    ///
    /// This test asserts the CURRENT behaviour. It is not an endorsement of
    /// it: it exists so that whoever resolves the decision finds a failing
    /// test rather than a seller finding an empty shop.
    #[test]
    fn known_gap_a_predecessor_generations_store_is_discarded_in_full() {
        let key = SigningKey::from_bytes(&[51u8; 32]);
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let old = signed(
            Listing {
                id: v1_listing_id("seller-fp", &created_at, "Ghost Pepper"),
                title: "Ghost Pepper".into(),
                description: "Hot".into(),
                kind: ListingKind::Sale,
                price: None,
                created_at,
            },
            &key,
        );
        assert!(
            old.verify(&key.verifying_key()).is_err(),
            "the premise: a predecessor's listing no longer verifies"
        );

        let mut predecessor = StoreStateV1::default();
        predecessor.listings.listings = vec![old];
        predecessor.info.info.store_name = "Alice's Hot Sauce".to_string();
        predecessor.info.info.version = 1;

        let outcome = merge_store_reporting_discard(
            StoreStateV1::default(),
            &predecessor,
            &StoreParameters::new(key.verifying_key()),
            DiscardedSide::Predecessor,
        );

        assert!(
            outcome.discarded,
            "the fold refuses the predecessor in full"
        );
        assert!(
            outcome.state.listings.listings.is_empty(),
            "and carries none of its listings"
        );
        assert_eq!(
            outcome.state.info.info.store_name, "",
            "not even the store's own name, which had nothing wrong with it"
        );
    }

    /// **A predecessor whose records DO carry their terms' ids is folded
    /// normally.**
    ///
    /// The other half, so the test above is read as "this input is refused"
    /// rather than "the fold is broken". It also pins that the refusal is
    /// about the id and not about anything else the branch changed.
    #[test]
    fn a_predecessor_whose_ids_are_their_terms_is_carried_forward() {
        let key = SigningKey::from_bytes(&[51u8; 32]);
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let good = signed(
            Listing {
                id: ListingId([0u8; 32]),
                title: "Ghost Pepper".into(),
                description: "Hot".into(),
                kind: ListingKind::Sale,
                price: None,
                created_at,
            }
            .with_derived_id(),
            &key,
        );

        let mut predecessor = StoreStateV1::default();
        predecessor.listings.listings = vec![good];

        let outcome = merge_store_reporting_discard(
            StoreStateV1::default(),
            &predecessor,
            &StoreParameters::new(key.verifying_key()),
            DiscardedSide::Predecessor,
        );

        assert!(!outcome.discarded);
        assert_eq!(outcome.state.listings.listings.len(), 1);
    }
}

#[cfg(test)]
mod uncarried_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_stdlib::prelude::ContractInstanceId;
    use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};

    /// A listing carrying an id derived the way a PREDECESSOR generation
    /// derived it, rather than the way this one does.
    ///
    /// The whole finding this module exists for is that every fixture in this
    /// repository builds records with the CURRENT derivation, so not one of
    /// them could see a change to it break the migration. This is the fixture
    /// that can: it constructs the record the old way and asserts what the
    /// fold does with it. See `predecessor_generation_tests` for the same
    /// shape applied to the fold's outcome.
    fn listing_with_a_foreign_id(key: &SigningKey, title: &str) -> AuthorizedListing {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let listing = Listing {
            // Not `with_derived_id`. Any id that is not the one these terms
            // give stands in for "derived by a generation that is not this
            // one" -- which is what a predecessor's records are.
            id: ListingId([0xAB; 32]),
            title: title.to_string(),
            description: String::new(),
            kind: ListingKind::Sale,
            price: None,
            created_at,
        };
        let message = harvest_common::to_cbor(&listing).expect("serialize");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        AuthorizedListing {
            signature: key.sign(&scoped_payload).to_bytes().to_vec(),
            listing,
            scoped_payload,
            certificate_pem: String::new(),
        }
    }

    /// **A record whose id this generation did not derive is refused, is
    /// reported, and takes its whole generation with it -- for EVERY id in
    /// the store's state.**
    ///
    /// # The structural fix, and why it is worth more than the finding
    ///
    /// A change to how a `ListingId` is derived broke the migration in a way
    /// that destroyed a seller's shop, passed all four gates and survived a
    /// review round. It was invisible for one reason: **every fixture in this
    /// repository builds its records with the CURRENT derivation**, so no
    /// test in it could hold a record the previous generation would have
    /// produced.
    ///
    /// This is the test that can. It builds each record with an id that is
    /// simply NOT the one its terms give -- which is what every record of a
    /// predecessor generation becomes the moment a derivation changes -- and
    /// asserts the three things a future author needs to know before changing
    /// one again:
    ///
    /// 1. the fold refuses it,
    /// 2. it takes the entire predecessor with it, the store's own details
    ///    included, and
    /// 3. the seller is told, by name, in something other than a log line.
    ///
    /// It is written over a LIST of the ids, so adding a fourth id-bearing
    /// record to `StoreStateV1` and forgetting this file means adding a case
    /// here, not discovering the omission from a seller.
    ///
    /// **What it does not do is prevent the loss.** It cannot: the id is
    /// inside what the seller signed, so no fold can re-stamp a record
    /// without invalidating it. What it prevents is the loss being a
    /// surprise -- which, given the migration seals and there is no second
    /// attempt, is the whole of the available protection.
    #[test]
    fn a_derivation_change_fails_here_before_it_reaches_a_seller() {
        let key = SigningKey::from_bytes(&[53u8; 32]);
        let params = StoreParameters::new(key.verifying_key());

        // One case per id-bearing record a store's state can hold. A new one
        // belongs in this list.
        let cases: Vec<(&str, StoreStateV1)> = vec![
            ("listing", {
                let mut state = StoreStateV1::default();
                state.info.info.store_name = "Alice's Hot Sauce".to_string();
                state.info.info.version = 1;
                state.listings.listings = vec![listing_with_a_foreign_id(&key, "Ghost Pepper")];
                state
            }),
            ("order", {
                let mut state = StoreStateV1::default();
                state.info.info.store_name = "Alice's Hot Sauce".to_string();
                state.info.info.version = 1;
                let order = order_with_a_foreign_id(&key);
                state.orders.orders.insert(order.order.id.clone(), order);
                state
            }),
        ];

        for (what, predecessor) in cases {
            take_uncarried();
            let outcome = merge_store_reporting_discard(
                StoreStateV1::default(),
                &predecessor,
                &params,
                DiscardedSide::Predecessor,
            );

            assert!(
                outcome.discarded,
                "a {what} whose id this generation did not derive must be refused"
            );
            assert_eq!(
                outcome.state.info.info.store_name, "",
                "and it takes the store's own details with it, which is the part that hurts \
                 ({what})"
            );
            let lost = take_uncarried();
            assert_eq!(lost.len(), 1, "the seller is told, once ({what})");
            assert!(
                lost[0].contains("Alice's Hot Sauce"),
                "by name ({what}): {}",
                lost[0]
            );
        }
    }

    /// An order carrying an id this generation did not derive, otherwise
    /// entirely valid and correctly signed.
    fn order_with_a_foreign_id(key: &SigningKey) -> harvest_common::payment::AuthorizedOrder {
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};

        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let order = Order {
            // Not `with_derived_id`, for the same reason as the listing above.
            id: OrderId([0xCD; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats: 50_000,
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa],
            payment_address: "tb1qexample".to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at,
        };
        let message = harvest_common::to_cbor(&order).expect("serialize");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        AuthorizedOrder {
            signature: key.sign(&scoped_payload).to_bytes().to_vec(),
            order,
            scoped_payload,
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// **A discarded predecessor names what was lost, in the seller's terms.**
    ///
    /// Ian's decision on 2026-09-06 was that no published store holds data
    /// worth preserving and sellers republish. That makes the loss a decision
    /// rather than an accident -- and a decision the person affected is not
    /// told about is indistinguishable from a bug.
    ///
    /// "Migration incomplete" would not do. The seller has to know their
    /// store's name and description are gone, how many listings went with
    /// them, and that republishing is what fixes it.
    #[test]
    fn a_discarded_predecessor_says_what_was_lost() {
        take_uncarried();
        let key = SigningKey::from_bytes(&[52u8; 32]);

        let mut predecessor = StoreStateV1::default();
        predecessor.info.info.store_name = "Alice's Hot Sauce".to_string();
        predecessor.info.info.version = 1;
        predecessor.listings.listings = vec![
            listing_with_a_foreign_id(&key, "Ghost Pepper"),
            listing_with_a_foreign_id(&key, "Scotch Bonnet"),
        ];

        let outcome = merge_store_reporting_discard(
            StoreStateV1::default(),
            &predecessor,
            &StoreParameters::new(key.verifying_key()),
            DiscardedSide::Predecessor,
        );
        assert!(outcome.discarded, "the premise");

        let lost = take_uncarried();
        assert_eq!(lost.len(), 1, "one report for one discarded generation");
        let said = &lost[0];
        assert!(
            said.contains("Alice's Hot Sauce"),
            "the seller should recognise their own store: {said}"
        );
        assert!(
            said.contains('2'),
            "and be told how many listings went with it: {said}"
        );
        assert!(
            said.to_lowercase().contains("publish"),
            "and what to do about it: {said}"
        );
        assert!(
            said.to_lowercase().contains("expected"),
            "and that this was a consequence of the upgrade rather than a fault -- without \
             it the seller goes looking for a bug instead of republishing: {said}"
        );
    }

    /// **A refused LOCAL snapshot is not described as an upgrade loss.**
    ///
    /// Found in review. `merge_store_reporting_discard` has two callers and
    /// `other` means a different thing in each: the predecessor for
    /// `merge_generations`, and this node's own current-generation snapshot
    /// for `merge_with_local`. The message was unconditional, so on the
    /// second path a seller would be told the store already at the new
    /// address "was not carried over when Harvest upgraded" and that they
    /// should republish it -- false, and it would send them re-publishing
    /// data that is fine.
    ///
    /// Low reachability: a local snapshot's listings are current-derivation
    /// by construction. That is not a reason to leave it, because this
    /// message is seen once and then the data is gone.
    #[test]
    fn a_refused_local_snapshot_is_described_as_a_failed_merge() {
        take_uncarried();
        let key = SigningKey::from_bytes(&[52u8; 32]);
        let mut local = StoreStateV1::default();
        local.info.info.store_name = "Alice's Hot Sauce".to_string();
        local.info.info.version = 1;
        local.listings.listings = vec![listing_with_a_foreign_id(&key, "Ghost Pepper")];

        let outcome = merge_store_reporting_discard(
            StoreStateV1::default(),
            &local,
            &StoreParameters::new(key.verifying_key()),
            DiscardedSide::LocalSnapshot,
        );
        assert!(outcome.discarded, "the premise");

        let said = take_uncarried().pop().expect("the seller is told");
        assert!(
            said.contains("Alice's Hot Sauce"),
            "it still names the store: {said}"
        );
        assert!(
            !said.contains("was not carried over when Harvest upgraded"),
            "but not as an upgrade loss -- this store is at the new address: {said}"
        );
        assert!(said.contains("intact"), "and it says so: {said}");
        assert!(
            !said.to_lowercase().contains("publish your store details"),
            "and does not send the seller re-publishing data that is fine: {said}"
        );
    }

    /// **A fold that carries everything reports nothing.**
    ///
    /// The counterpart, so the report cannot be a constant. A notification
    /// that appears on every successful migration is one a seller learns to
    /// dismiss, which costs exactly the case it exists for.
    #[test]
    fn a_successful_fold_reports_nothing_lost() {
        take_uncarried();
        let key = SigningKey::from_bytes(&[52u8; 32]);

        let mut predecessor = StoreStateV1::default();
        predecessor.listings.listings = vec![listing_with_a_foreign_id(&key, "Ghost Pepper")];
        // The same listing, stamped the way this generation stamps one.
        predecessor.listings.listings[0].listing = predecessor.listings.listings[0]
            .listing
            .clone()
            .with_derived_id();
        let re_signed = {
            let listing = predecessor.listings.listings[0].listing.clone();
            let message = harvest_common::to_cbor(&listing).expect("serialize");
            let scoped = ghostkey_common::ScopedPayload {
                requestor: ghostkey_common::SignatureRequestor::WebApp(
                    harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                        .parse::<ContractInstanceId>()
                        .expect("canonical webapp id"),
                ),
                payload: message,
            };
            let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
            AuthorizedListing {
                signature: key.sign(&scoped_payload).to_bytes().to_vec(),
                listing,
                scoped_payload,
                certificate_pem: String::new(),
            }
        };
        predecessor.listings.listings = vec![re_signed];

        let outcome = merge_store_reporting_discard(
            StoreStateV1::default(),
            &predecessor,
            &StoreParameters::new(key.verifying_key()),
            DiscardedSide::Predecessor,
        );

        assert!(!outcome.discarded);
        assert!(
            take_uncarried().is_empty(),
            "a migration that lost nothing must say nothing"
        );
    }

    /// **Taking the reports clears them.**
    ///
    /// The drain is what stops one migration's loss being announced again on
    /// the next notification, which would teach a seller the message means
    /// nothing.
    #[test]
    fn taking_the_reports_clears_them() {
        take_uncarried();
        record_uncarried("something".to_string());
        assert_eq!(take_uncarried().len(), 1);
        assert!(take_uncarried().is_empty());
    }
}
