//! Asking the node again for an order's payment address (#67).
//!
//! # Why anything has to ask twice
//!
//! Harvest learns that an invoice was paid by reading the Bitcoin address
//! contract the order names. It asks for that contract once, when the order
//! first appears, and then waits for the node to volunteer every later
//! version. That is enough while the node keeps up, and the node does not
//! always keep up: a peer that misses one live fan-out serves its own copy
//! until anti-entropy repairs it, which took ~18 minutes in the live test on
//! 2026-09-17 and is measured in the field at 300s to 40-75 minutes
//! (freenet-core#5527). While that lasts, every GET is answered from the
//! stale copy, because a peer serves its best local copy immediately rather
//! than blocking a read to confirm freshness (`hosting-invariants.md`
//! invariant 1, which also says there is no freshness flag to ask for).
//!
//! So the node heals on its own, and nothing told Harvest. A seller watched
//! an order that had been paid, confirmed and attested sit on "awaiting
//! payment", and a reload did not help, because a reload asks once too.
//!
//! The fix is to keep asking while an order is unsettled. Re-asking cannot
//! make a stale answer fresh, and it is not trying to: it is what converts a
//! node that has since healed into a screen that says so.
//!
//! # What this module is
//!
//! The decision half, kept apart from the sending half so it can be tested
//! without a browser: given the addresses worth asking about and the time,
//! which to ask for now. [`AddressRereads`] holds only when each was last
//! asked for.
//!
//! # The spacing, and why it widens
//!
//! The first re-ask comes [`FIRST_RETRY_MS`] after the last one, and each
//! consecutive ask doubles the wait to a ceiling of [`MAX_RETRY_MS`]. The
//! widening is the point: while the node is stale every answer is identical,
//! so asking at a fixed minute would spend an unbounded number of GETs
//! learning nothing, and the repair it is waiting for takes tens of minutes.
//! Settling at a few minutes costs little and still notices a heal promptly
//! against a window that long.
//!
//! Arriving state deliberately does NOT reset the spacing. A stale copy
//! answers every ask, so resetting on arrival would hold the fastest cadence
//! for exactly the case the widening exists to bound.
//!
//! # What bounds it
//!
//! Nothing here. The caller passes only addresses still worth asking about,
//! which is how an invoice nobody ever pays stops being asked about: see
//! `AppState::address_contracts_to_reread`, which drops an order that has
//! settled and one whose anchor has aged out of the payable window. Entries
//! for addresses the caller stops naming are forgotten by [`Self::retain`],
//! so a long session does not accumulate them.

use std::collections::BTreeMap;

/// How long after asking for an address before asking again.
///
/// A minute is the cadence the rest of the app's periodic work already runs
/// at, and the shortest wait that is clearly not a retry storm.
pub const FIRST_RETRY_MS: u64 = 60_000;

/// The longest the wait grows to.
///
/// Five minutes against a repair measured in tens of minutes: fast enough
/// that a healed node is noticed well inside the window a person would call
/// "it updated", slow enough that an order left open all day costs a few
/// hundred GETs rather than a few thousand.
pub const MAX_RETRY_MS: u64 = 5 * 60_000;

/// When each address contract was last asked for, and how many times in a
/// row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressRereads {
    asked: BTreeMap<[u8; 32], Asked>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Asked {
    at_ms: u64,
    /// Asks since this entry was created. Saturating, and only ever used as a
    /// shift count that is clamped well below the width of the wait.
    consecutive: u32,
}

impl AddressRereads {
    /// How long to wait after the `consecutive`-th ask before the next.
    ///
    /// `consecutive` counts asks, so it is 1 after the first one and the
    /// shift is one less: the wait after a single ask is [`FIRST_RETRY_MS`]
    /// itself, not double it. An earlier version shifted by the count and
    /// silently made every wait twice what it says here, which the spacing
    /// tests caught.
    ///
    /// Clamped before the shift rather than after: `1 << 64` is undefined
    /// behaviour in C and a panic in debug Rust, and a tab left open long
    /// enough would reach it.
    fn spacing(consecutive: u32) -> u64 {
        FIRST_RETRY_MS
            .saturating_mul(1u64 << consecutive.saturating_sub(1).min(8))
            .min(MAX_RETRY_MS)
    }

    /// Which of `wanted` to ask for now, in the caller's order.
    ///
    /// An address never asked for is due at once. That is the first re-ask
    /// after the original subscription, and it is wanted: the subscription's
    /// own answer is exactly the one that may be stale.
    pub fn due(&self, wanted: &[[u8; 32]], now_ms: u64) -> Vec<[u8; 32]> {
        wanted
            .iter()
            .filter(|id| match self.asked.get(*id) {
                None => true,
                Some(asked) => {
                    now_ms.saturating_sub(asked.at_ms) >= Self::spacing(asked.consecutive)
                }
            })
            .copied()
            .collect()
    }

    /// Record that `id` has just been asked for.
    pub fn note_asked(&mut self, id: [u8; 32], now_ms: u64) {
        let entry = self.asked.entry(id).or_insert(Asked {
            at_ms: now_ms,
            consecutive: 0,
        });
        entry.at_ms = now_ms;
        entry.consecutive = entry.consecutive.saturating_add(1);
    }

    /// Forget every address not in `wanted`.
    ///
    /// An order that settles, or ages out, stops being named; so does every
    /// order in a store the tab navigates away from. Without this a session
    /// that browses many stores keeps an entry per order it ever saw.
    ///
    /// Forgetting also resets the spacing, which is right: an address that
    /// becomes wanted again is a different question from the one that was
    /// being asked, and is worth asking promptly.
    pub fn retain(&mut self, wanted: &[[u8; 32]]) {
        self.asked.retain(|id, _| wanted.contains(id));
    }

    /// How many addresses are being tracked. For tests and diagnostics.
    pub fn tracked(&self) -> usize {
        self.asked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];

    /// **An address never asked about is asked about at once.**
    ///
    /// The first tick after an invoice appears is the first chance to find a
    /// subscription whose one answer was already stale.
    #[test]
    fn an_unasked_address_is_due_immediately() {
        let tracker = AddressRereads::default();
        assert_eq!(tracker.due(&[A], 0), vec![A]);
    }

    /// **An address just asked about is not asked again.**
    ///
    /// The bug this guards is a tick that re-asks every time it fires,
    /// which against a 60s interval is 60 GETs an hour per unsettled order
    /// and against a faster one is a retry storm.
    #[test]
    fn an_address_just_asked_for_waits() {
        let mut tracker = AddressRereads::default();
        tracker.note_asked(A, 1_000);

        assert!(
            tracker.due(&[A], 1_000).is_empty(),
            "not in the same instant"
        );
        assert!(
            tracker.due(&[A], 1_000 + FIRST_RETRY_MS - 1).is_empty(),
            "not a millisecond early"
        );
        assert_eq!(
            tracker.due(&[A], 1_000 + FIRST_RETRY_MS),
            vec![A],
            "due once the first wait has passed"
        );
    }

    /// **The wait doubles per consecutive ask, to a ceiling.**
    ///
    /// Asserted as the actual due-times rather than by calling `spacing`,
    /// so the test would fail if `due` stopped consulting it. A version of
    /// this test that checked `spacing` alone passed under a mutation that
    /// made `due` ignore the count entirely.
    #[test]
    fn the_wait_widens_and_then_stops_widening() {
        let mut tracker = AddressRereads::default();
        let mut now = 0u64;
        let mut waits = Vec::new();
        for _ in 0..8 {
            tracker.note_asked(A, now);
            let mut waited = 0;
            while tracker.due(&[A], now + waited).is_empty() {
                waited += 1_000;
                assert!(waited <= MAX_RETRY_MS * 2, "a wait that never ends");
            }
            waits.push(waited);
            now += waited;
        }

        assert_eq!(waits[0], FIRST_RETRY_MS, "the first wait is the base");
        assert_eq!(waits[1], FIRST_RETRY_MS * 2, "then double");
        assert_eq!(waits[2], FIRST_RETRY_MS * 4, "then double again");
        assert!(
            waits.iter().all(|w| *w <= MAX_RETRY_MS),
            "no wait exceeds the ceiling: {waits:?}"
        );
        assert_eq!(
            *waits.last().expect("eight waits"),
            MAX_RETRY_MS,
            "and it settles at the ceiling rather than growing forever"
        );
    }

    /// **Asking about one address does not delay another.**
    ///
    /// Two unsettled orders are two independent questions. A tracker keyed
    /// by nothing, or one that stored a single last-asked time, would let a
    /// busy seller's newest invoice hide behind an older one.
    #[test]
    fn addresses_are_spaced_independently() {
        let mut tracker = AddressRereads::default();
        tracker.note_asked(A, 0);

        let due = tracker.due(&[A, B], 1_000);
        assert_eq!(due, vec![B], "B has never been asked about, A just was");
    }

    /// **An address that stops being wanted is forgotten.**
    ///
    /// And, because forgetting resets the spacing, one that becomes wanted
    /// again is asked about promptly rather than at the widened wait it had
    /// reached before.
    #[test]
    fn dropping_an_address_forgets_its_spacing() {
        let mut tracker = AddressRereads::default();
        for _ in 0..5 {
            tracker.note_asked(A, 0);
        }
        tracker.note_asked(B, 0);
        assert_eq!(tracker.tracked(), 2);

        tracker.retain(&[B]);
        assert_eq!(tracker.tracked(), 1, "A is gone");

        assert_eq!(
            tracker.due(&[A], 1),
            vec![A],
            "and asking about A again starts from scratch"
        );
    }

    /// **The widening cannot overflow the shift.**
    ///
    /// `1u64 << 64` panics in debug builds. A tab open for a long time on an
    /// unsettled order reaches a high count, so the clamp is load-bearing
    /// rather than defensive.
    #[test]
    fn a_very_long_session_does_not_panic() {
        let mut tracker = AddressRereads::default();
        for _ in 0..1_000 {
            tracker.note_asked(A, 0);
        }
        assert_eq!(
            tracker.due(&[A], MAX_RETRY_MS),
            vec![A],
            "still due at the ceiling, however many asks have gone before"
        );
    }
}
