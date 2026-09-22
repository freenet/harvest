//! Whether a migration may START, and what a completed one leaves behind.
//!
//! The companion to [`super::migrate_seal`], which decides when a migration
//! may declare itself DONE. Both live outside `migrate_ops` for the same
//! reason: that module is gated to `target_arch = "wasm32"` by `mod.rs`, so no
//! host check compiles a line of it, and the decisions inside it are the part
//! that loses data when they are wrong.

use std::collections::HashMap;

use freenet_stdlib::prelude::ContractInstanceId;

use crate::migrate::{notice_gate, MarkerLookup, NoticeGate};

/// Whether a lineage may be walked now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admission {
    /// Nothing has walked this lineage in this session. Go.
    Admit,
    /// A walk is in flight. The vault sends a `GhostKeyList` per connect, so
    /// two can overlap; the second must not start a duplicate.
    AlreadyWalking,
    /// A walk already reached a terminal outcome in this session.
    AlreadyWalked,
}

/// Which lineages this session has walked, keyed by durable marker.
///
/// # Why a session record exists at all
///
/// The durable marker was supposed to be this: walk, seal, and every later
/// load skips it. But the seal is deliberately withheld
/// ([`super::migrate_seal`] and `migrate_ops::successor_reference_is_durable`
/// explain why), so nothing is ever written and the durable gate can never
/// fire. Without a session record the walk therefore repeats on every
/// `GhostKeyList` -- once per connect, for the life of the tab.
///
/// That is not the same as the repetition the no-seal decision knowingly
/// accepts. Repeating on a fresh LOAD is bounded by the user reloading and is
/// the price of not sealing over a recovery that may revert. Repeating within
/// one session is unbounded, and each repetition is a full lineage of GETs
/// plus a full-state PUT against a live network.
///
/// # Why entries are never released
///
/// A claim is made when a walk starts and is never given back. `settled` only
/// records that the walk reached an outcome; it does not re-open the lineage,
/// because "this walk finished" and "this walk may run again" are different
/// claims and conflating them is what produced the repetition. Only a reload
/// clears this, which is exactly the bound wanted.
///
/// # Why this cannot leak
///
/// Keys are migration markers: one per (artifact, current instance, code
/// hash), so at most three per ghostkey identity the vault reports. The set is
/// bounded by the identities in the user's own vault and cannot be driven by
/// anything the network says -- no contract, peer or message adds a key. It
/// holds no contract-controlled values, so a count bound is a real bound here
/// rather than the count-cap-over-unbounded-values trap.
#[derive(Default)]
pub struct SessionWalks {
    walks: HashMap<String, WalkState>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WalkState {
    Walking,
    Settled,
}

impl SessionWalks {
    /// Claim a lineage for a walk. Returns [`Admission::Admit`] at most once
    /// per marker per session.
    pub fn claim(&mut self, marker: &str) -> Admission {
        match self.walks.get(marker) {
            Some(WalkState::Walking) => Admission::AlreadyWalking,
            Some(WalkState::Settled) => Admission::AlreadyWalked,
            None => {
                self.walks.insert(marker.to_string(), WalkState::Walking);
                Admission::Admit
            }
        }
    }

    /// Record that a walk reached a terminal outcome, whatever that outcome
    /// was -- recovered and sealed, recovered and unsealed, nothing found, or
    /// a forward PUT that was never confirmed.
    ///
    /// Every one of those is terminal FOR THIS SESSION.
    ///
    /// # Retry is by reload, and that is deliberate
    ///
    /// A walk that failed transiently -- an unconfirmed forward put, an
    /// unreachable node -- is retried by reloading the page, not by
    /// reconnecting. **Do not "fix" this by releasing the claim here.** That
    /// is what this code used to do, and with the seal withheld it left
    /// nothing holding the gate at all: every reconnect re-walked the whole
    /// lineage and re-PUT the full state, once per connect, for the life of
    /// the tab.
    ///
    /// Bounded in-session retries (allow two, then stop) were considered and
    /// rejected on review. They would be a second bound, whose behaviour under
    /// connection churn someone then has to reason about, to buy something a
    /// reload already provides -- and a seller whose migration failed is
    /// reloading anyway, because that is what people do when an app looks
    /// wrong. The simpler bound is worth more here than the extra recovery.
    ///
    /// This is an accepted trade, not an oversight.
    pub fn settled(&mut self, marker: &str) {
        self.walks.insert(marker.to_string(), WalkState::Settled);
    }

    /// Also settles a lineage, for the case where the walk never ran because
    /// the delegate said it was already migrated.
    pub fn settled_without_walking(&mut self, marker: &str) {
        self.walks.insert(marker.to_string(), WalkState::Settled);
    }

    pub fn len(&self) -> usize {
        self.walks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.walks.is_empty()
    }
}

/// The predecessor ids a completed migration must record as superseded.
///
/// Deliberately a function of the candidates the walk actually PROBED and the
/// successor alone. It does NOT consult the store registry, and that is the
/// whole point: reading the predecessor out of a registration meant that when
/// no registration had arrived yet -- a `ListStores` still in flight, or one
/// that errored -- nothing was recorded at all, and the answer that arrived
/// later reinstated the predecessor's triple. The registry cannot be an input
/// to a decision whose job is to survive the registry being late.
///
/// Every probed generation is recorded, not just the one that hit, because the
/// registry may name any generation in the lineage and all of them are equally
/// superseded by the successor.
pub fn superseded_ids(
    probed: &[ContractInstanceId],
    successor: ContractInstanceId,
) -> Vec<ContractInstanceId> {
    let mut out: Vec<ContractInstanceId> = Vec::new();
    for id in probed {
        // The successor is not superseded by itself: a lineage that includes
        // the current generation would otherwise record a self-referential
        // mapping.
        if *id == successor || out.contains(id) {
            continue;
        }
        out.push(*id);
    }
    out
}

/// Which migration notices are waiting on the delegate, and which this
/// session has already settled (harvest#121).
///
/// A migration that has not sealed walks again on the next load and finds the
/// same things again, so its notices would be shown on every visit. Each
/// notice has a durable id (`migrate::notice_marker`), and the delegate is
/// asked whether it was shown on an earlier load before it goes up. This is
/// the bookkeeping around that question, split out of the wasm-only
/// `migrate_ops` so the property that matters -- a second walk over the same
/// lineage puts up no second notice -- can be tested on the host.
///
/// Bounded like [`SessionWalks`]: entries are keyed by notices this app wrote
/// from its own migrations, a handful per identity, and nothing the network
/// says can add one.
#[derive(Default)]
pub struct NoticeLedger {
    waiting: HashMap<String, String>,
    settled: std::collections::HashSet<String>,
}

impl NoticeLedger {
    /// Offer a notice. Returns `true` if the caller should ask the delegate
    /// about it now; `false` if the same notice is already waiting on an
    /// answer or was settled earlier in this session.
    pub fn offer(&mut self, marker: &str, text: String) -> bool {
        if self.settled.contains(marker) || self.waiting.contains_key(marker) {
            return false;
        }
        self.waiting.insert(marker.to_string(), text);
        true
    }

    /// The delegate answered, or failed to, about `marker`.
    ///
    /// `None` if `marker` is not a waiting notice -- it may be a lineage's
    /// marker, or a late answer for a notice already settled -- so the caller
    /// can route the answer elsewhere. Otherwise `Some` of the text to show,
    /// or `Some(None)` when the delegate says it was shown before. Settles the
    /// notice either way, so a later answer or a second walk finds nothing.
    pub fn settle(&mut self, marker: &str, lookup: MarkerLookup) -> Option<Option<String>> {
        let text = self.waiting.remove(marker)?;
        self.settled.insert(marker.to_string());
        Some(match notice_gate(lookup) {
            NoticeGate::Show => Some(text),
            NoticeGate::Suppress => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "harvest:migrate:store:aaaa";
    const B: &str = "harvest:migrate:mailbox:bbbb";

    /// The concurrent-duplicate case the module has always guarded: the vault
    /// sends a `GhostKeyList` per connect, and two can overlap.
    #[test]
    fn a_second_claim_while_walking_is_refused() {
        let mut walks = SessionWalks::default();
        assert_eq!(walks.claim(A), Admission::Admit);
        assert_eq!(walks.claim(A), Admission::AlreadyWalking);
    }

    /// **The regression that matters.** With the durable marker withheld,
    /// nothing outside this type stops a repeat, so releasing the claim when a
    /// walk settles makes every later `GhostKeyList` re-run the entire
    /// lineage -- a full set of GETs and a full-state PUT, once per connect,
    /// for the life of the tab.
    #[test]
    fn a_second_ghostkey_list_does_not_restart_a_settled_walk() {
        let mut walks = SessionWalks::default();
        assert_eq!(walks.claim(A), Admission::Admit);
        walks.settled(A);
        assert_eq!(
            walks.claim(A),
            Admission::AlreadyWalked,
            "a walk that has already finished in this session must not run again"
        );
    }

    /// Settling must not be a way to re-open the lineage indirectly, however
    /// many times it happens.
    #[test]
    fn settling_repeatedly_never_re_admits() {
        let mut walks = SessionWalks::default();
        walks.claim(A);
        for _ in 0..5 {
            walks.settled(A);
            assert_eq!(walks.claim(A), Admission::AlreadyWalked);
        }
    }

    /// The delegate-says-already-migrated path, which drops the probe without
    /// walking. It must gate exactly as a completed walk does.
    #[test]
    fn a_lineage_dropped_as_already_migrated_is_not_walked_later() {
        let mut walks = SessionWalks::default();
        walks.settled_without_walking(A);
        assert_eq!(walks.claim(A), Admission::AlreadyWalked);
    }

    /// Lineages are independent: gating one must not gate another.
    #[test]
    fn markers_do_not_gate_each_other() {
        let mut walks = SessionWalks::default();
        assert_eq!(walks.claim(A), Admission::Admit);
        assert_eq!(walks.claim(B), Admission::Admit);
    }

    /// The leak check. Reconnecting repeatedly is the ONE thing that happens
    /// without bound, so it must not add an entry each time.
    #[test]
    fn repeated_connects_do_not_grow_the_record() {
        let mut walks = SessionWalks::default();
        walks.claim(A);
        walks.settled(A);
        for _ in 0..1_000 {
            walks.claim(A);
        }
        assert_eq!(
            walks.len(),
            1,
            "one entry per lineage, however many connects"
        );
    }

    fn id(byte: u8) -> ContractInstanceId {
        ContractInstanceId::new([byte; 32])
    }

    /// The bug this replaces read the predecessor out of a `StoreRegistration`
    /// and recorded nothing when there was none. There is no registration in
    /// this signature at all, so that failure cannot be expressed.
    #[test]
    fn every_probed_generation_is_recorded_as_superseded() {
        let probed = [id(1), id(2), id(3)];
        assert_eq!(
            superseded_ids(&probed, id(9)),
            vec![id(1), id(2), id(3)],
            "the registry may name ANY probed generation, so all are superseded"
        );
    }

    /// A lineage that includes the current generation must not map it to
    /// itself: that would be a self-referential entry in the id map.
    #[test]
    fn the_successor_is_never_recorded_as_superseded_by_itself() {
        assert_eq!(superseded_ids(&[id(1), id(9)], id(9)), vec![id(1)]);
    }

    #[test]
    fn a_repeated_candidate_is_recorded_once() {
        assert_eq!(superseded_ids(&[id(1), id(1)], id(9)), vec![id(1)]);
    }

    /// A walk that probed nothing has nothing to repoint, and must not invent
    /// a mapping.
    #[test]
    fn probing_nothing_supersedes_nothing() {
        assert!(superseded_ids(&[], id(9)).is_empty());
    }
    const NOTICE: &str = "v1.notice.00112233445566778899aabbccddeeff";

    /// **The harvest#121 regression.** The walk repeats on every load until it
    /// seals, and it used to put its notices up every time. A notice the
    /// delegate says was shown before stays down. Mutated red by showing on
    /// `Present`.
    #[test]
    fn a_notice_shown_on_an_earlier_load_is_not_shown_again() {
        let mut ledger = NoticeLedger::default();
        assert!(ledger.offer(NOTICE, "Recovered your store".into()));
        assert_eq!(ledger.settle(NOTICE, MarkerLookup::Present), Some(None));
    }

    /// The first time, it is shown.
    #[test]
    fn a_new_notice_is_shown() {
        let mut ledger = NoticeLedger::default();
        assert!(ledger.offer(NOTICE, "Recovered your store".into()));
        assert_eq!(
            ledger.settle(NOTICE, MarkerLookup::Absent),
            Some(Some("Recovered your store".into()))
        );
    }

    /// A delegate that cannot answer is never "already told": a loss notice
    /// is the only thing the person affected hears. Mutated red by
    /// suppressing on `Unavailable`.
    #[test]
    fn silence_from_the_delegate_shows_the_notice() {
        let mut ledger = NoticeLedger::default();
        assert!(ledger.offer(NOTICE, "lost".into()));
        assert_eq!(
            ledger.settle(NOTICE, MarkerLookup::Unavailable),
            Some(Some("lost".into()))
        );
    }

    /// A second walk in the same session -- or two walks finding the same
    /// thing -- asks nothing and shows nothing, whatever the delegate would
    /// have said. Mutated red by not recording the settled id, and by not
    /// checking the waiting set.
    #[test]
    fn a_second_walk_in_the_same_session_puts_up_no_second_notice() {
        let mut ledger = NoticeLedger::default();
        assert!(ledger.offer(NOTICE, "Recovered your store".into()));
        assert!(
            !ledger.offer(NOTICE, "Recovered your store".into()),
            "still waiting"
        );
        assert!(ledger.settle(NOTICE, MarkerLookup::Absent).is_some());
        assert!(
            !ledger.offer(NOTICE, "Recovered your store".into()),
            "already shown"
        );
        assert_eq!(
            ledger.settle(NOTICE, MarkerLookup::Absent),
            None,
            "a late answer"
        );
    }

    /// An answer about something that is not a waiting notice -- a lineage's
    /// own marker -- is not taken, so the probe still gets it.
    #[test]
    fn a_lineage_marker_answer_is_left_for_the_probe() {
        let mut ledger = NoticeLedger::default();
        assert_eq!(ledger.settle(A, MarkerLookup::Absent), None);
    }
}
