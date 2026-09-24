//! When a migration may declare itself done.
//!
//! Split out of `migrate_ops` because that module is wasm-only
//! (`gateway/mod.rs` gates it on `target_arch = "wasm32"`, since it exists to
//! drive the gateway's shared response handler, which has no native
//! counterpart). Nothing in it is reachable from `cargo test`, so the one
//! decision in it that loses data when it is wrong lives here instead, where
//! the host can run it -- the same split `crate::migrate` already makes
//! against the rest of the probe.

use crate::migrate::{Artifact, Seal};

/// Whether the recovered state actually reached the successor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForwardPut {
    /// The node confirmed THIS put landed.
    ///
    /// **Nothing can produce this today.** The client API carries no way to
    /// attribute a `PutResponse` to the put it answers -- see
    /// [`put_response_evidence`] -- so this variant exists to say what the
    /// seal actually requires, and to keep the requirement in the type rather
    /// than in a comment somebody has to remember.
    Acknowledged,
    /// A `PutResponse` naming the successor instance arrived, but nothing says
    /// WHOSE put it answers.
    ///
    /// The successor instance id is the current generation's id for that
    /// seller: the same id `create_store_contracts` puts a fresh default state
    /// to, and the same id another tab on the same node may be writing. Any of
    /// those acknowledgements looks exactly like this one, so this is evidence
    /// that SOMETHING landed at the target, not that our recovery did.
    AcknowledgedForInstance,
    /// The send failed, or the deadline expired with no answer. Both say the
    /// same thing: nothing is known about whether the state arrived.
    ///
    /// `put_contract` resolving is NOT this or the other -- it reports that
    /// the WebSocket accepted the bytes, which is not a claim about the
    /// contract at all.
    Unconfirmed,
}

/// Whether the durable pointers a later load follows name the successor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuccessorReference {
    /// They do. A later load that skips the probe still reaches the migrated
    /// data.
    Durable,
    /// They do not: the delegate's registry still names the predecessor, so a
    /// later load would restore the old ids, find the marker, skip the probe,
    /// and quietly go back to the superseded generation.
    Stale,
}

/// What to do with a migration whose forward PUT has settled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// Repoint this session at the successor, tell the seller, and write the
    /// durable marker so no later load repeats the walk.
    AdoptAndSeal,
    /// Repoint this session and tell the seller, but leave the lineage
    /// unsealed: the next load walks it again, re-PUTs a state the contracts
    /// merge idempotently, and re-adopts.
    AdoptWithoutSealing,
    /// Do neither. The write was never confirmed, so there is nothing to adopt
    /// and nothing to tell the seller about.
    Discard,
}

/// The strongest evidence a `PutResponse` can give about a forward put.
///
/// It is [`ForwardPut::AcknowledgedForInstance`] and cannot be better, because
/// `ContractResponse::PutResponse` carries a `key` and nothing else
/// (freenet-stdlib 0.8.5), and `ContractRequest::Put` carries no
/// client-supplied id to echo back. Two puts to one instance are therefore
/// indistinguishable in the response: correlating on the instance id, which is
/// all `FORWARDS` can key on, cannot tell our recovery's put from a store
/// creation's put or another tab's.
///
/// A function rather than a literal at the call site so the ceiling is stated
/// once and tested. Raising it needs an upstream change -- a correlation token
/// on `ContractRequest::Put` echoed in `PutResponse` -- and when that exists
/// this takes the token and may return [`ForwardPut::Acknowledged`].
pub fn put_response_evidence() -> ForwardPut {
    ForwardPut::AcknowledgedForInstance
}

/// How long a MAILBOX forward PUT is waited on before it is given up as
/// unconfirmed.
///
/// **Not the probe's 12 s** (harvest#152). A GET of a predecessor is a read,
/// usually served from the node's own copy; a PUT on a `freenet network` node
/// is answered only after its remote hops, and the node tries peers one at a
/// time, each for up to its own operation lifetime (60 s, freenet-core
/// `config.rs` `OPERATION_TTL`). With the probe's deadline a mailbox write
/// that was slow but landed was discarded: nothing was adopted, and the
/// successor mailbox, which is where buyers write, was not routed for that
/// load -- harvest#148's symptom again, on exactly the loads the isolated
/// rehearsal node (which answers a PUT at once) cannot produce.
///
/// A node that never answers is given up after this and resolves as it
/// always did, [`ForwardPut::Unconfirmed`], walk again next load. What an
/// answer is worth does not change: see [`put_response_evidence`].
pub const MAILBOX_FORWARD_GIVE_UP_MS: u32 = 10 * 60 * 1000;

/// When an unanswered forward PUT is logged as slow, and when every artifact
/// but the mailbox gives up: the probe's deadline, as before harvest#152.
pub const FORWARD_SLOW_NOTICE_MS: u32 = freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS as u32;

/// How long a forward PUT of `artifact` is waited on.
///
/// # Why only the mailbox waits longer
///
/// Both kinds of adopt can land mid-session once the wait is long, and both
/// move something the seller writes. They differ in what that costs:
///
/// * **A store, reputation or index adopt** repoints `my_stores`. An invoice
///   accepted into the predecessor store while the forward was outstanding is
///   then outside everything that watches, re-reads and settles this seller's
///   orders for the rest of the session, and a write waiting on a signature
///   fails with "not one of yours" (#154 review round 1). A payment to that
///   invoice can be missed for good. So these keep the probe's deadline.
///   Since harvest#164 no write goes to an earlier generation, and the
///   session moves to the current one when state for it arrives
///   (`AppState::adopt_if_current_generation`), which
///   `store_ops::spawn_move_to_current` keeps asking for, backing off to
///   5 min, until it does. A slow store forward therefore delays the move
///   rather than keeping the load on the predecessor, and this device's
///   writes and the reads it acts on follow one generation. (The earlier
///   generation's subscription is not dropped on the move; it is not taken
///   for a second store of ours, since only the id a registration names
///   counts as one.)
/// * **A mailbox adopt** moves where the seller's replies and invoice accepts
///   are sent (`browsing_stores[..].mailbox_contract_id`). One sent to the
///   predecessor before a late adopt is not seen by a buyer on the current
///   build, and drops out of the seller's own inbox when the successor's
///   state replaces it, until the next load's walk carries the predecessor's
///   messages forward (#154 review round 2). That is a delay, not a loss.
///   Against it: without the wait, a slow load routes only the predecessor
///   mailbox for the WHOLE load, so every buyer request written to the
///   successor meanwhile goes unseen, which is harvest#152 itself. The wait
///   is the better side of that trade.
///
/// The longer wait also widens the window in which a `PutResponse` for the
/// same instance from some OTHER put of this tab is taken as ours (see
/// [`put_response_evidence`]). For the mailbox that is
/// `store_ops::create_store_contracts`, which PUTs a default state to the
/// mailbox derived from the seller's key, so a seller who creates a store
/// during the wait can have the successor adopted with our forward
/// unconfirmed: the successor is the right place to point anyway, and
/// nothing seals, so the next load walks again. For the index,
/// `index_flow` publishes the seller's entry to the current index on every
/// load that finds it unlisted, which is the normal state after an index
/// re-key: another reason the rule is per artifact.
pub fn forward_give_up_ms(artifact: Artifact) -> u32 {
    match artifact {
        Artifact::Mailbox => MAILBOX_FORWARD_GIVE_UP_MS,
        Artifact::Store | Artifact::Reputation | Artifact::Index => FORWARD_SLOW_NOTICE_MS,
    }
}

/// What a forward PUT's timer means when it fires.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForwardTimer {
    /// The node may still answer. Keep the forward outstanding, so an answer
    /// that arrives later still adopts.
    StillWaiting,
    /// Past [`forward_give_up_ms`]: settle it as [`ForwardPut::Unconfirmed`].
    GiveUp,
}

/// What a timer fired `elapsed_ms` after a forward PUT of `artifact` was sent
/// means.
///
/// The one place the wait is decided, so it can be tested off-target: the
/// timers themselves are wasm-only (`migrate_ops::send_forward`).
pub fn forward_timer(artifact: Artifact, elapsed_ms: u32) -> ForwardTimer {
    if elapsed_ms >= forward_give_up_ms(artifact) {
        ForwardTimer::GiveUp
    } else {
        ForwardTimer::StillWaiting
    }
}

/// The sealing rule, in one place.
///
/// The marker is not a note about what happened; it is a claim that nothing
/// needs to run again, which every later load believes without checking. Two
/// facts have to hold before that claim is true, and both of them are things
/// that can silently not happen:
///
/// 1. the recovered state reached the successor, and
/// 2. every durable pointer a later load follows already names it.
///
/// Anything short of a fact resolves the same way: do not seal, walk again
/// next load. That is wasteful and correct, and it is the direction every
/// other uncertainty in the migration resolves in.
pub fn disposition(put: ForwardPut, reference: SuccessorReference, seal: Seal) -> Disposition {
    match put {
        // Nothing is known to have landed, so there is nothing to adopt, and
        // telling the seller their data was recovered would be a claim this
        // code cannot support.
        ForwardPut::Unconfirmed => Disposition::Discard,
        // Something landed at the target, but not provably ours. Worth
        // adopting -- the successor is where this session should point either
        // way -- and never worth sealing, because sealing on it would record
        // "this migration is done, never run again" on the strength of
        // somebody else's put.
        ForwardPut::AcknowledgedForInstance => Disposition::AdoptWithoutSealing,
        ForwardPut::Acknowledged => match (reference, seal) {
            (SuccessorReference::Durable, Seal::Seal) => Disposition::AdoptAndSeal,
            // Adopting without sealing is the safe half of every remaining
            // case: this session uses the successor, and the next load checks
            // again rather than trusting a claim that was never established.
            _ => Disposition::AdoptWithoutSealing,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUTS: [ForwardPut; 3] = [
        ForwardPut::Acknowledged,
        ForwardPut::AcknowledgedForInstance,
        ForwardPut::Unconfirmed,
    ];
    const REFERENCES: [SuccessorReference; 2] =
        [SuccessorReference::Durable, SuccessorReference::Stale];
    const SEALS: [Seal; 2] = [Seal::Seal, Seal::Retry];

    /// Defect 1. The forward PUT used to be `spawn_local`'d fire-and-forget
    /// with the marker written on the next line, so a PUT the node rejected,
    /// or never received, still sealed -- and every later load skipped the
    /// migration for a recovery that had not landed. The state was orphaned
    /// permanently and silently.
    #[test]
    fn an_unconfirmed_forward_put_neither_adopts_nor_seals() {
        for reference in REFERENCES {
            for seal in SEALS {
                assert_eq!(
                    disposition(ForwardPut::Unconfirmed, reference, seal),
                    Disposition::Discard,
                    "an unconfirmed PUT must not adopt or seal ({reference:?}, {seal:?})"
                );
            }
        }
    }

    /// Defect 2. Sealing over a registry that still names the predecessor is
    /// worse than not sealing at all: the next load restores the old ids,
    /// finds the marker, skips the probe, and returns to the superseded
    /// generation with the migrated instances sitting unreferenced beside it.
    /// The migration appears to succeed and then undoes itself on reload.
    #[test]
    fn a_stale_successor_reference_blocks_the_seal() {
        for seal in SEALS {
            assert_ne!(
                disposition(ForwardPut::Acknowledged, SuccessorReference::Stale, seal),
                Disposition::AdoptAndSeal,
                "a stale successor reference must not seal ({seal:?})"
            );
        }
    }

    /// The positive half, so the rule cannot be satisfied by refusing to seal
    /// anything at all.
    #[test]
    fn an_acknowledged_put_with_a_durable_reference_seals() {
        assert_eq!(
            disposition(
                ForwardPut::Acknowledged,
                SuccessorReference::Durable,
                Seal::Seal
            ),
            Disposition::AdoptAndSeal
        );
    }

    /// `migrate::seal_decision` still has the final say: an outcome it typed
    /// as `Retry` is adopted but never sealed, however well the write went.
    #[test]
    fn a_retry_outcome_never_seals() {
        for put in PUTS {
            for reference in REFERENCES {
                assert_ne!(
                    disposition(put, reference, Seal::Retry),
                    Disposition::AdoptAndSeal,
                    "Retry must never seal ({put:?}, {reference:?})"
                );
            }
        }
    }

    /// An acknowledgement that cannot be attributed to this put must never
    /// seal. The successor instance id is the current generation's id, so a
    /// `PutResponse` for it may be answering `create_store_contracts`'s put of
    /// a fresh default state, or another tab's, while OUR forward put failed.
    ///
    /// This is currently latent rather than harmful: `reference` is always
    /// `Stale`, so nothing seals whatever the put evidence says. It stops
    /// being latent the day `successor_reference_is_durable` is implemented,
    /// which the migration's own comments name as the next step -- and then a
    /// false acknowledgement seals a migration that never landed. Pinning it
    /// now is what stops that fix arming this one.
    #[test]
    fn an_ack_that_cannot_be_attributed_to_this_put_never_seals() {
        for reference in REFERENCES {
            for seal in SEALS {
                assert_ne!(
                    disposition(ForwardPut::AcknowledgedForInstance, reference, seal),
                    Disposition::AdoptAndSeal,
                    "an unattributable acknowledgement must not seal ({reference:?}, {seal:?})"
                );
            }
        }
    }

    /// The other half: an unattributable acknowledgement is still worth
    /// acting on. The successor IS where this session should be pointing, and
    /// the walk repeats on the next load anyway, so refusing to adopt would
    /// leave the seller on the predecessor for no gain.
    #[test]
    fn an_unattributable_ack_still_adopts() {
        assert_eq!(
            disposition(
                ForwardPut::AcknowledgedForInstance,
                SuccessorReference::Durable,
                Seal::Seal
            ),
            Disposition::AdoptWithoutSealing
        );
    }

    /// The evidence ceiling, pinned where it is produced rather than where it
    /// is consumed. `migrate_ops` has exactly one way to turn a `PutResponse`
    /// into evidence, and this is it.
    #[test]
    fn a_put_response_is_never_attributable_to_one_put() {
        assert_eq!(put_response_evidence(), ForwardPut::AcknowledgedForInstance);
        assert_ne!(
            put_response_evidence(),
            ForwardPut::Acknowledged,
            "the client API carries nothing that attributes a PutResponse to a put"
        );
    }

    /// harvest#152. A mailbox forward PUT on a network node is answered only
    /// after its remote hops, and the node tries peers one after another,
    /// each for up to 60 s. The wait used to be the probe's 12 s, so an answer
    /// after that found the forward already discarded, and a migrated
    /// seller's successor mailbox went unrouted for the load. Red with the
    /// mailbox give-up put back at the probe timeout.
    #[test]
    fn a_mailbox_forward_answered_after_the_probe_timeout_is_still_waited_for() {
        let probe_timeout = freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS as u32;
        let several_node_attempts = 5 * 60_000;
        for elapsed in [
            probe_timeout,
            60_000,
            several_node_attempts,
            MAILBOX_FORWARD_GIVE_UP_MS - 1,
        ] {
            assert_eq!(
                forward_timer(Artifact::Mailbox, elapsed),
                ForwardTimer::StillWaiting,
                "a mailbox forward unanswered after {elapsed} ms may still land"
            );
        }
    }

    /// The other half: a node that never answers does not hold the forward
    /// for the rest of the session. It resolves as an unanswered forward
    /// always has, unconfirmed, which discards.
    #[test]
    fn a_mailbox_forward_nobody_answers_is_given_up_as_unconfirmed() {
        assert_eq!(
            forward_timer(Artifact::Mailbox, MAILBOX_FORWARD_GIVE_UP_MS),
            ForwardTimer::GiveUp
        );
        assert_eq!(
            forward_timer(Artifact::Mailbox, u32::MAX),
            ForwardTimer::GiveUp
        );
        const { assert!(FORWARD_SLOW_NOTICE_MS < MAILBOX_FORWARD_GIVE_UP_MS) };
    }

    /// **Only the mailbox waits longer** (#154 review round 1). Adopting a
    /// store, reputation or index contract moves where the seller's own
    /// writes go, so a late adopt would strand an invoice accepted meanwhile
    /// outside everything that watches and settles it. Those keep the
    /// probe's deadline. Red with the long wait applied to every artifact.
    #[test]
    fn a_contract_the_seller_writes_to_keeps_the_probe_deadline() {
        for artifact in [Artifact::Store, Artifact::Reputation, Artifact::Index] {
            assert_eq!(
                forward_timer(artifact, FORWARD_SLOW_NOTICE_MS - 1),
                ForwardTimer::StillWaiting
            );
            assert_eq!(
                forward_timer(artifact, FORWARD_SLOW_NOTICE_MS),
                ForwardTimer::GiveUp,
                "{artifact:?} gives up at the probe deadline"
            );
        }
    }

    /// Stated as an implication over the whole input space rather than as
    /// three separate cases, so a future input added to `disposition` cannot
    /// open a fourth way to seal without failing here.
    #[test]
    fn nothing_else_seals() {
        for put in PUTS {
            for reference in REFERENCES {
                for seal in SEALS {
                    if disposition(put, reference, seal) == Disposition::AdoptAndSeal {
                        assert_eq!(put, ForwardPut::Acknowledged);
                        assert_eq!(reference, SuccessorReference::Durable);
                        assert_eq!(seal, Seal::Seal);
                    }
                }
            }
        }
    }
}
