//! A seller's pause: "this store is closed for now", signed by the store key
//! and held in the store's state (step 2).
//!
//! Unlike [`crate::backing::StoreClosure`], a pause is reversible: each
//! [`StorePause`] carries a `revision`, and the store keeps the highest, so a
//! later "resume" supersedes an earlier "pause" (and the reverse). It lives
//! in store state rather than only in the heartbeat so that every device
//! holding the store key reads the same answer, and so a buyer whose view of
//! presence is stale still sees it. A closure overrides it: a closed store
//! stays closed whatever its pause says.
//!
//! While paused the seller's delegate declines Buy nows, keeps watching the
//! addresses of invoices already issued, and sends heartbeats saying
//! `Paused`; a manual invoice still goes out.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::listing::verify_scoped_signature;
use crate::store::Bytes32;

/// A one-variant tag, so a pause never decodes as any other store-key message
/// nor any other as a pause ([`crate::backing::classify_store_key_message`]).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorePauseKind {
    HarvestStorePauseV1,
}

/// "This store is (or is no longer) paused", as of `revision`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StorePause {
    pub kind: StorePauseKind,
    /// The store. Must be the owner; carried so the signed bytes name it.
    pub store: VerifyingKey,
    /// Larger is later: the signer's `max(held + 1, now in ms)`, so it keeps
    /// rising through a clock that jumps back, and a pause made on a device
    /// that never saw an earlier one still supersedes it, clocks permitting.
    pub revision: u64,
    /// Paused (true) or resumed (false).
    pub paused: bool,
}

impl StorePause {
    pub fn new(store: VerifyingKey, revision: u64, paused: bool) -> Self {
        Self {
            kind: StorePauseKind::HarvestStorePauseV1,
            store,
            revision,
            paused,
        }
    }

    /// The revision a new pause or resume should carry, given the one held
    /// (if any) and the time now.
    pub fn next_revision(held: Option<&AuthorizedStorePause>, now_ms: u64) -> u64 {
        held.map_or(0, |held| held.pause.revision.saturating_add(1))
            .max(now_ms)
    }
}

/// A [`StorePause`] signed by the store key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedStorePause {
    pub pause: StorePause,
    #[serde(with = "serde_bytes")]
    pub scoped_payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl AuthorizedStorePause {
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        if self.pause.store != *owner {
            return Err("pause names a different store key than this store's owner".into());
        }
        verify_scoped_signature(&self.scoped_payload, &self.signature, owner, &self.pause)
            .map_err(|e| format!("pause is not signed by the store key: {e}"))
    }
}

/// The store's pause: empty, or the latest signed pause or resume. One slot
/// (the store key), ranked by revision.
pub type PauseV1 = crate::backing::SignedSetV1<AuthorizedStorePause>;

impl crate::backing::SignedRecord for AuthorizedStorePause {
    fn slot(&self) -> Bytes32 {
        Bytes32(self.pause.store.to_bytes())
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    fn rank(&self) -> u64 {
        self.pause.revision
    }
    const WHAT: &'static str = "pause";
    // `verify` requires the pause to name the owner, so it sits in the
    // owner's slot.
    const MAX_RECORDS: usize = 1;
}

/// Whether `pause` says the store is paused now.
pub fn is_paused(pause: &PauseV1) -> bool {
    pause.records.values().any(|record| record.pause.paused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing::sign_with_store_key;
    use crate::merge_laws::{assert_laws, Rng};
    use crate::store::{StoreParameters, StoreStateV1, StoreStateV1Delta};
    use ed25519_dalek::SigningKey;
    use freenet_scaffold::ComposableState;

    fn store_key() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }

    fn params() -> StoreParameters {
        StoreParameters::new(store_key().verifying_key())
    }

    fn signed(key: &SigningKey, revision: u64, paused: bool) -> AuthorizedStorePause {
        let pause = StorePause::new(key.verifying_key(), revision, paused);
        let (scoped_payload, signature) =
            sign_with_store_key(key, crate::to_cbor(&pause).unwrap()).expect("a store record");
        AuthorizedStorePause {
            pause,
            scoped_payload,
            signature,
        }
    }

    fn state_with(pauses: Vec<AuthorizedStorePause>) -> Result<StoreStateV1, String> {
        let mut state = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        // One delta per pause: a delta carries at most one (a store holds
        // one), so several reach a store as several updates.
        for pause in pauses {
            state
                .apply_delta(
                    &StoreStateV1::default(),
                    &params(),
                    &Some(StoreStateV1Delta {
                        owner: Some(store_key().verifying_key()),
                        pause: Some(vec![pause]),
                        ..Default::default()
                    }),
                )
                .map_err(|e| format!("{e:?}"))?;
        }
        Ok(state)
    }

    fn merged(a: &StoreStateV1, b: &StoreStateV1) -> StoreStateV1 {
        let mut out = a.clone();
        out.merge(&a.clone(), &params(), b).expect("merge");
        out
    }

    fn bytes(state: &StoreStateV1) -> Vec<u8> {
        crate::to_cbor(state).expect("encode")
    }

    /// A later resume supersedes an earlier pause and the reverse, whichever
    /// arrives first. Mutated red by ranking every pause 0 (the smaller
    /// encoding, `paused: false`, then always wins).
    #[test]
    fn the_latest_pause_or_resume_wins_in_either_order() {
        let pause = state_with(vec![signed(&store_key(), 5, true)]).unwrap();
        let resume = state_with(vec![signed(&store_key(), 4, false)]).unwrap();
        assert!(pause.paused() && !resume.paused());
        assert!(merged(&pause, &resume).paused());
        assert!(merged(&resume, &pause).paused());
        let later = state_with(vec![signed(&store_key(), 6, false)]).unwrap();
        assert!(!merged(&pause, &later).paused());
        assert!(!merged(&later, &pause).paused());
        assert_eq!(
            StorePause::next_revision(pause.pause.records.values().next(), 3),
            6,
            "past the held one when the clock is behind it"
        );
        assert_eq!(StorePause::next_revision(None, 9), 9);
    }

    /// Only the store's own key pauses it: a pause signed by another key, or
    /// naming another store, is refused. Mutated red by dropping the store
    /// check in `verify`.
    #[test]
    fn only_the_store_key_pauses_the_store() {
        let other = SigningKey::from_bytes(&[0x62; 32]);
        assert!(state_with(vec![signed(&other, 1, true)]).is_err());
        // Signed by the store key, but naming another store.
        let pause = StorePause::new(other.verifying_key(), 1, true);
        let (scoped_payload, signature) =
            sign_with_store_key(&store_key(), crate::to_cbor(&pause).unwrap()).unwrap();
        let wrong = AuthorizedStorePause {
            pause,
            scoped_payload,
            signature,
        };
        assert!(state_with(vec![wrong]).is_err());
    }

    /// A store holds one pause, so a delta may carry one: two (here a pause
    /// and the resume after it, both genuine) are refused whole, before
    /// either is checked, and the store is left as it was. Mutated red by
    /// raising the bound to 2.
    #[test]
    fn a_delta_of_two_pauses_is_refused() {
        let mut state = state_with(vec![signed(&store_key(), 1, true)]).unwrap();
        let held = state.clone();
        let why = state
            .apply_delta(
                &StoreStateV1::default(),
                &params(),
                &Some(StoreStateV1Delta {
                    owner: Some(store_key().verifying_key()),
                    pause: Some(vec![
                        signed(&store_key(), 2, true),
                        signed(&store_key(), 3, false),
                    ]),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        assert!(why.contains("more than a store holds"), "{why}");
        assert_eq!(state, held);
    }

    /// A store never paused encodes, summarizes and deltas exactly as it did
    /// before the pause existed, so every earlier state passes the
    /// re-encoding check. Mutated red by dropping `skip_serializing_if`.
    #[test]
    fn no_pause_encodes_as_before_it_existed() {
        let state = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        let has_pause_key = |encoded: Vec<u8>| {
            let value: ciborium::Value = crate::from_cbor(&encoded).unwrap();
            value
                .as_map()
                .unwrap()
                .iter()
                .any(|(k, _)| k.as_text() == Some("pause"))
        };
        assert!(!has_pause_key(bytes(&state)));
        assert!(!has_pause_key(
            crate::to_cbor(&state.summarize(&state, &params())).unwrap()
        ));
        assert!(!has_pause_key(
            crate::to_cbor(&StoreStateV1Delta::default()).unwrap()
        ));
        assert!(!state.paused());
    }

    /// The store key signs a pause, and a pause is no other store record:
    /// not a closure, whose only field it also carries. Mutated red by
    /// dropping the pause from `classify_store_key_message`.
    #[test]
    fn the_store_key_signs_a_pause_and_nothing_else_reads_as_one() {
        let pause = StorePause::new(store_key().verifying_key(), 1, true);
        assert_eq!(
            crate::backing::classify_store_key_message(&crate::to_cbor(&pause).unwrap()),
            Some(crate::backing::StoreKeyMessage::Pause)
        );
        let closure = crate::backing::StoreClosure {
            store: store_key().verifying_key(),
        };
        assert_eq!(
            crate::backing::classify_store_key_message(&crate::to_cbor(&closure).unwrap()),
            Some(crate::backing::StoreKeyMessage::Closure)
        );
    }

    /// Seeded merge laws, on bytes, over clashing pauses: several revisions,
    /// and equal revisions saying opposite things.
    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let key = store_key();
        let mut pool = Vec::new();
        for revision in [1u64, 2, 2, 5] {
            for paused in [true, false] {
                pool.push(signed(&key, revision, paused));
            }
        }
        let mut rng = Rng::new(0x9a_05);
        let mut states = vec![state_with(vec![]).unwrap()];
        for _ in 0..20 {
            let picked = rng.subset(&pool, 3);
            states.push(state_with(picked).unwrap());
        }
        assert_laws(&states, 300, &mut rng, merged, bytes);
    }
}
