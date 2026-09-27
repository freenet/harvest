//! Store presence: whether a store is open right now.
//!
//! # The rule
//!
//! A store is OPEN iff its seller's node sent a heartbeat at most
//! [`PRESENCE_FRESH_MS`] ago AND that heartbeat says the store can still
//! issue payment details ([`Heartbeat::taking_orders`]). Otherwise it is
//! CLOSED: greyed, sorted last, no Buy now. [`presence_verdict`] is that
//! rule, as a reader applies it.
//!
//! # Where the heartbeat lives, and why not in the store
//!
//! In a contract of its own, one per store, addressed by the store key
//! alone ([`PresenceParameters`]). The seller's Harvest delegate signs a
//! heartbeat with the STORE key about every [`HEARTBEAT_EVERY_MS`] and
//! updates this contract. Putting it in the store contract would make every
//! hosting peer re-validate the whole store (every listing and order
//! signature) every five minutes, and ship a large state around; a presence
//! update is one small signed record.
//!
//! # State and merge
//!
//! At most one [`SignedHeartbeat`]. Two are ordered by `at_ms`, larger
//! first, then by the smaller canonical encoding: a total order, so keeping
//! the maximum is commutative, associative and idempotent. The contract
//! checks the signature, the exact envelope and the size bounds; it reads no
//! clock (a contract has none it can agree on), so it cannot refuse a
//! heartbeat dated in the future. Only the store key can sign one, and
//! [`presence_verdict`] treats one dated more than [`PRESENCE_SKEW_MS`]
//! ahead as closed.
//!
//! # A re-key needs no migration
//!
//! A heartbeat is ephemeral: it is worthless ten minutes after it is signed.
//! When this contract's code moves, the next heartbeat simply lands at the
//! new address, and nothing at the old one is worth carrying forward.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::listing::verify_scoped_signature;
use crate::store::Bytes32;

/// How often the seller's delegate signs a heartbeat.
pub const HEARTBEAT_EVERY_MS: u64 = 5 * 60 * 1000;

/// How old a heartbeat may be and still keep the store open: two heartbeat
/// periods, so one late or lost heartbeat does not close the store.
pub const PRESENCE_FRESH_MS: u64 = 10 * 60 * 1000;

/// How far AHEAD of the reader's clock a heartbeat may be dated and still
/// count. Further ahead is closed: a far-future heartbeat would otherwise
/// keep a store open long after its seller went offline.
pub const PRESENCE_SKEW_MS: u64 = 10 * 60 * 1000;

/// The most a heartbeat's `scoped_payload` may be. The exact envelope
/// ([`crate::backing::is_exact_harvest_envelope`]) is required anyway, which
/// is well under this; the bound is the cheap refusal that runs before
/// anything is decoded or hashed.
pub const MAX_HEARTBEAT_ENVELOPE_BYTES: usize = 512;

/// An Ed25519 signature is exactly this long.
pub const HEARTBEAT_SIGNATURE_BYTES: usize = 64;

/// The most a presence state, or a delta, may be on the wire. Checked before
/// decoding ([`decode_state`], [`decode_delta`]), so a peer cannot make a
/// hosting node decode or store more than one bounded record.
pub const MAX_PRESENCE_STATE_BYTES: usize = 1024;

/// The presence contract's parameters: the store key, and nothing else, so
/// anyone looking at a store derives its presence contract with no lookup.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PresenceParameters {
    /// Named `store_verifying_key`, not `store_key`: `ReputationParameters`
    /// is `{ store_key }`, and two structs that encode alike for the same
    /// key are what the address guard exists to keep apart.
    ///
    /// `pub(crate)` on purpose: see [`PresenceParameters::new`].
    pub(crate) store_verifying_key: VerifyingKey,
}

impl PresenceParameters {
    /// The only way to build these parameters from outside `harvest-common`:
    /// the field set is hashed into the contract's address, so a second
    /// place building it by hand can address a different contract (the
    /// reason `StoreParameters::new` gives).
    pub fn new(store_verifying_key: VerifyingKey) -> Self {
        Self {
            store_verifying_key,
        }
    }

    pub fn store_verifying_key(&self) -> &VerifyingKey {
        &self.store_verifying_key
    }
}

/// The domain tag a [`Heartbeat`] carries. One variant, so a heartbeat
/// decodes only with exactly this tag, and nothing else the store key signs
/// has a field of this name: the CBOR of a heartbeat can never classify as
/// another store-key message, or one of those as a heartbeat
/// ([`crate::backing::classify_store_key_message`]).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeartbeatKind {
    HarvestPresenceV1,
}

/// "This store's seller is online at `at_ms`", signed by the store key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Heartbeat {
    pub kind: HeartbeatKind,
    /// Unix milliseconds, by the seller's clock.
    pub at_ms: u64,
    /// Whether the store can issue payment details now. False closes the
    /// store as surely as silence does.
    pub taking_orders: bool,
}

impl Heartbeat {
    pub fn new(at_ms: u64, taking_orders: bool) -> Self {
        Self {
            kind: HeartbeatKind::HarvestPresenceV1,
            at_ms,
            taking_orders,
        }
    }
}

/// A [`Heartbeat`] signed by the store key: the exact Harvest envelope
/// around its CBOR, and the signature over that envelope.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SignedHeartbeat {
    pub heartbeat: Heartbeat,
    #[serde(with = "serde_bytes")]
    pub scoped_payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedHeartbeat {
    /// Sign `heartbeat` with the store key, as the delegate does
    /// ([`crate::backing::sign_with_store_key`]).
    pub fn sign(
        store_key: &ed25519_dalek::SigningKey,
        heartbeat: Heartbeat,
    ) -> Result<Self, String> {
        let payload = crate::to_cbor(&heartbeat)?;
        let (scoped_payload, signature) = crate::backing::sign_with_store_key(store_key, payload)?;
        Ok(Self {
            heartbeat,
            scoped_payload,
            signature,
        })
    }

    /// Whether the store owned by `store_key` signed this: bounded, the
    /// exact envelope around this heartbeat's own CBOR, and a valid
    /// signature by that key over it. The bounds are checked first, so an
    /// oversized record costs no hashing.
    pub fn verify(&self, store_key: &VerifyingKey) -> Result<(), String> {
        if self.scoped_payload.len() > MAX_HEARTBEAT_ENVELOPE_BYTES {
            return Err(format!(
                "heartbeat envelope is {} bytes, the most one may be is \
                 {MAX_HEARTBEAT_ENVELOPE_BYTES}",
                self.scoped_payload.len()
            ));
        }
        if self.signature.len() != HEARTBEAT_SIGNATURE_BYTES {
            return Err(format!(
                "heartbeat signature is {} bytes, an Ed25519 signature is \
                 {HEARTBEAT_SIGNATURE_BYTES}",
                self.signature.len()
            ));
        }
        let payload = crate::to_cbor(&self.heartbeat)?;
        if !crate::backing::is_exact_harvest_envelope(&self.scoped_payload, &payload) {
            return Err("heartbeat envelope is not exactly the Harvest envelope around it".into());
        }
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            store_key,
            &self.heartbeat,
        )
        .map_err(|e| format!("heartbeat is not signed by the store key: {e}"))
    }

    /// The canonical encoding, which an `at_ms` tie is decided by.
    fn bytes(&self) -> Result<Vec<u8>, String> {
        crate::to_cbor(self)
    }

    fn digest(&self) -> Result<Bytes32, String> {
        Ok(Bytes32(*blake3::hash(&self.bytes()?).as_bytes()))
    }
}

/// Whether `held` stays when `incoming` arrives: it is later, or as late
/// and encodes no larger. A total order (at_ms descending, then bytes
/// ascending), so keeping its maximum is idempotent, commutative and
/// associative.
fn keeps_held(held: &SignedHeartbeat, incoming: &SignedHeartbeat) -> Result<bool, String> {
    Ok(match held.heartbeat.at_ms.cmp(&incoming.heartbeat.at_ms) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => held.bytes()? <= incoming.bytes()?,
    })
}

/// A store's presence: its latest heartbeat, if any has arrived.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct PresenceStateV1 {
    #[serde(default)]
    pub heartbeat: Option<SignedHeartbeat>,
}

/// What a peer tells another it holds: the heartbeat's time and a digest of
/// it. The digest is what makes two heartbeats with the same `at_ms` (the
/// same moment, `taking_orders` flipped) converge; `at_ms` alone would
/// call them equal and neither side would ever send.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct PresenceSummaryV1 {
    pub at_ms: u64,
    pub digest: Bytes32,
}

/// A presence delta is one heartbeat.
pub type PresenceDeltaV1 = SignedHeartbeat;

/// Decode a presence state, refusing one over [`MAX_PRESENCE_STATE_BYTES`]
/// before decoding it.
pub fn decode_state(bytes: &[u8]) -> Result<PresenceStateV1, String> {
    bounded(bytes, "state")?;
    crate::from_cbor(bytes)
}

/// Decode a presence delta, refusing one over [`MAX_PRESENCE_STATE_BYTES`]
/// before decoding it.
pub fn decode_delta(bytes: &[u8]) -> Result<PresenceDeltaV1, String> {
    bounded(bytes, "delta")?;
    crate::from_cbor(bytes)
}

fn bounded(bytes: &[u8], what: &str) -> Result<(), String> {
    if bytes.len() > MAX_PRESENCE_STATE_BYTES {
        return Err(format!(
            "presence {what} is {} bytes, the most one may be is {MAX_PRESENCE_STATE_BYTES}",
            bytes.len()
        ));
    }
    Ok(())
}

impl PresenceStateV1 {
    /// The whole-state check: the heartbeat, if any, is this store's.
    pub fn verify(&self, params: &PresenceParameters) -> Result<(), String> {
        match &self.heartbeat {
            Some(heartbeat) => heartbeat.verify(&params.store_verifying_key),
            None => Ok(()),
        }
    }

    pub fn summarize(&self) -> Result<Option<PresenceSummaryV1>, String> {
        self.heartbeat
            .as_ref()
            .map(|h| {
                Ok(PresenceSummaryV1 {
                    at_ms: h.heartbeat.at_ms,
                    digest: h.digest()?,
                })
            })
            .transpose()
    }

    /// Our heartbeat, if the peer that sent `theirs` may be missing it: it
    /// holds none, an older one, or a different one of the same moment.
    /// Sending one that loses the tie-break is safe; the receiver keeps its
    /// own.
    pub fn delta(
        &self,
        theirs: Option<&PresenceSummaryV1>,
    ) -> Result<Option<PresenceDeltaV1>, String> {
        let Some(ours) = &self.heartbeat else {
            return Ok(None);
        };
        let send = match theirs {
            None => true,
            Some(theirs) => match ours.heartbeat.at_ms.cmp(&theirs.at_ms) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => ours.digest()? != theirs.digest,
            },
        };
        Ok(send.then(|| ours.clone()))
    }

    /// Fold one heartbeat in. It is verified before anything changes, so a
    /// refused heartbeat leaves the state exactly as it was.
    pub fn apply_delta(
        &mut self,
        params: &PresenceParameters,
        incoming: &SignedHeartbeat,
    ) -> Result<(), String> {
        incoming.verify(&params.store_verifying_key)?;
        let keep = match &self.heartbeat {
            Some(held) => keeps_held(held, incoming)?,
            None => false,
        };
        if !keep {
            self.heartbeat = Some(incoming.clone());
        }
        Ok(())
    }

    /// Merge a whole state in.
    pub fn merge(&mut self, params: &PresenceParameters, other: &Self) -> Result<(), String> {
        match &other.heartbeat {
            Some(incoming) => self.apply_delta(params, incoming),
            None => Ok(()),
        }
    }
}

/// Why a store reads as closed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClosedWhy {
    /// No heartbeat has ever arrived.
    NoHeartbeat,
    /// The latest heartbeat is older than [`PRESENCE_FRESH_MS`].
    Stale { age_ms: u64 },
    /// The seller is online, and says the store cannot issue payment
    /// details.
    NotTakingOrders,
    /// The heartbeat is dated more than [`PRESENCE_SKEW_MS`] ahead of the
    /// reader's clock.
    FromTheFuture,
}

/// Whether a store is open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Presence {
    Open,
    Closed(ClosedWhy),
}

/// Whether the store whose presence is `state` is open at `now_ms`, by the
/// reader's clock.
///
/// OPEN iff there is a heartbeat, it is dated no more than
/// [`PRESENCE_SKEW_MS`] ahead of `now_ms`, no more than [`PRESENCE_FRESH_MS`]
/// behind it (both bounds inclusive), and it says `taking_orders`. When
/// several reasons apply the first of future, stale, not taking orders is
/// given: a stale "not taking orders" says nothing about now.
///
/// **This does not verify the signature.** A caller passes a state it has
/// already checked with [`PresenceStateV1::verify`] against the store's
/// [`PresenceParameters`], as the UI checks every other contract state it
/// reads (`index_flow::on_index_state`: "not trusted because a node served
/// it"). A node could serve any bytes at this address; the contract's own
/// validation only binds the nodes that ran it.
pub fn presence_verdict(state: Option<&PresenceStateV1>, now_ms: u64) -> Presence {
    let Some(signed) = state.and_then(|s| s.heartbeat.as_ref()) else {
        return Presence::Closed(ClosedWhy::NoHeartbeat);
    };
    let at_ms = signed.heartbeat.at_ms;
    if at_ms > now_ms.saturating_add(PRESENCE_SKEW_MS) {
        return Presence::Closed(ClosedWhy::FromTheFuture);
    }
    let age_ms = now_ms.saturating_sub(at_ms);
    if age_ms > PRESENCE_FRESH_MS {
        return Presence::Closed(ClosedWhy::Stale { age_ms });
    }
    if !signed.heartbeat.taking_orders {
        return Presence::Closed(ClosedWhy::NotTakingOrders);
    }
    Presence::Open
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_laws::{assert_laws, Rng};
    use ed25519_dalek::{Signer, SigningKey};

    fn store_key() -> SigningKey {
        SigningKey::from_bytes(&[0x71; 32])
    }

    fn params() -> PresenceParameters {
        PresenceParameters::new(store_key().verifying_key())
    }

    fn signed(at_ms: u64, taking_orders: bool) -> SignedHeartbeat {
        SignedHeartbeat::sign(&store_key(), Heartbeat::new(at_ms, taking_orders)).unwrap()
    }

    fn state(h: SignedHeartbeat) -> PresenceStateV1 {
        PresenceStateV1 { heartbeat: Some(h) }
    }

    fn refusal(h: &SignedHeartbeat) -> String {
        let mut s = PresenceStateV1::default();
        let err = s.apply_delta(&params(), h).expect_err("refused");
        assert_eq!(s, PresenceStateV1::default(), "a refusal changes nothing");
        err
    }

    #[test]
    fn a_heartbeat_signed_by_the_store_key_verifies_and_is_small() {
        let h = signed(1_000, true);
        h.verify(&store_key().verifying_key()).unwrap();
        let bytes = crate::to_cbor(&state(h)).unwrap();
        // The point of a separate contract is a small update.
        assert!(
            bytes.len() < 400,
            "a presence state is {} bytes",
            bytes.len()
        );
        assert!(bytes.len() <= MAX_PRESENCE_STATE_BYTES);
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let mut h = signed(1_000, true);
        h.signature[0] ^= 1;
        assert!(refusal(&h).contains("not signed by the store key"));
    }

    #[test]
    fn a_heartbeat_by_another_key_is_refused() {
        let other = SigningKey::from_bytes(&[0x72; 32]);
        let h = SignedHeartbeat::sign(&other, Heartbeat::new(1_000, true)).unwrap();
        assert!(refusal(&h).contains("not signed by the store key"));
    }

    #[test]
    fn a_changed_heartbeat_under_a_valid_signature_is_refused() {
        let mut h = signed(1_000, false);
        h.heartbeat.taking_orders = true;
        assert!(refusal(&h).contains("envelope"));
        let mut h = signed(1_000, true);
        h.heartbeat.at_ms = 9_999_999;
        assert!(refusal(&h).contains("envelope"));
    }

    /// A store-key signature over something that is not a heartbeat (a
    /// retirement, which the delegate will sign) cannot be passed off as one.
    #[test]
    fn another_store_key_record_is_not_a_heartbeat() {
        let retirement = crate::backing::Retirement {
            backer: SigningKey::from_bytes(&[3; 32]).verifying_key(),
        };
        let (scoped_payload, signature) =
            crate::backing::sign_with_store_key(&store_key(), crate::to_cbor(&retirement).unwrap())
                .unwrap();
        let h = SignedHeartbeat {
            heartbeat: Heartbeat::new(1_000, true),
            scoped_payload,
            signature,
        };
        assert!(refusal(&h).contains("envelope"));
    }

    /// Past the exact-envelope check: the signature check refuses on its
    /// own, so dropping the envelope check still refuses a foreign payload.
    #[test]
    fn a_foreign_payload_fails_the_signature_check_too() {
        let retirement = crate::backing::Retirement {
            backer: SigningKey::from_bytes(&[3; 32]).verifying_key(),
        };
        let (scoped, sig) =
            crate::backing::sign_with_store_key(&store_key(), crate::to_cbor(&retirement).unwrap())
                .unwrap();
        assert!(verify_scoped_signature(
            &scoped,
            &sig,
            &store_key().verifying_key(),
            &Heartbeat::new(1_000, true)
        )
        .is_err());
    }

    #[test]
    fn an_envelope_with_trailing_bytes_is_refused() {
        let mut h = signed(1_000, true);
        // Re-sign the padded envelope, so only the exactness check objects.
        h.scoped_payload.push(0);
        h.signature = store_key().sign(&h.scoped_payload).to_bytes().to_vec();
        assert!(refusal(&h).contains("envelope"));
    }

    #[test]
    fn an_oversized_envelope_is_refused_before_anything_else() {
        let mut h = signed(1_000, true);
        h.scoped_payload = vec![0; MAX_HEARTBEAT_ENVELOPE_BYTES + 1];
        assert!(refusal(&h).contains("513 bytes, the most"));
        // At the bound it is not the size that refuses it.
        h.scoped_payload = vec![0; MAX_HEARTBEAT_ENVELOPE_BYTES];
        assert!(!refusal(&h).contains("bytes, the most"));
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let mut h = signed(1_000, true);
        h.signature.push(0);
        assert!(refusal(&h).contains("signature is 65 bytes"));
        h.signature.truncate(10);
        assert!(refusal(&h).contains("signature is 10 bytes"));
    }

    #[test]
    fn an_oversized_state_or_delta_is_refused_before_decoding() {
        let big = vec![0u8; MAX_PRESENCE_STATE_BYTES + 1];
        assert!(decode_state(&big)
            .unwrap_err()
            .contains("presence state is"));
        assert!(decode_delta(&big)
            .unwrap_err()
            .contains("presence delta is"));
        let good = crate::to_cbor(&state(signed(5, true))).unwrap();
        assert_eq!(decode_state(&good).unwrap(), state(signed(5, true)));
        let delta = crate::to_cbor(&signed(5, true)).unwrap();
        assert_eq!(decode_delta(&delta).unwrap(), signed(5, true));
    }

    #[test]
    fn a_whole_state_with_a_forged_heartbeat_is_refused() {
        let mut h = signed(1_000, true);
        h.signature[5] ^= 0x10;
        assert!(state(h).verify(&params()).is_err());
        assert!(state(signed(1_000, true)).verify(&params()).is_ok());
        assert!(PresenceStateV1::default().verify(&params()).is_ok());
        let mut s = PresenceStateV1::default();
        let mut forged = signed(9, true);
        forged.signature[0] ^= 1;
        assert!(s.merge(&params(), &state(forged)).is_err());
        assert_eq!(s, PresenceStateV1::default());
    }

    #[test]
    fn the_later_heartbeat_wins_either_way() {
        let (old, new) = (signed(1_000, true), signed(2_000, false));
        for (first, second) in [(&old, &new), (&new, &old)] {
            let mut s = PresenceStateV1::default();
            s.apply_delta(&params(), first).unwrap();
            s.apply_delta(&params(), second).unwrap();
            assert_eq!(s.heartbeat.as_ref(), Some(&new));
        }
    }

    #[test]
    fn a_tie_on_time_goes_to_the_smaller_encoding_either_way() {
        let (a, b) = (signed(1_000, true), signed(1_000, false));
        let smaller = if crate::to_cbor(&a).unwrap() < crate::to_cbor(&b).unwrap() {
            &a
        } else {
            &b
        };
        for (first, second) in [(&a, &b), (&b, &a)] {
            let mut s = PresenceStateV1::default();
            s.apply_delta(&params(), first).unwrap();
            s.apply_delta(&params(), second).unwrap();
            assert_eq!(s.heartbeat.as_ref(), Some(smaller));
        }
    }

    #[test]
    fn a_delta_is_sent_only_when_the_peer_may_be_missing_it() {
        let held = state(signed(2_000, true));
        let summary = |s: &PresenceStateV1| s.summarize().unwrap();
        // Nothing held there: send.
        assert_eq!(held.delta(None).unwrap(), held.heartbeat.clone());
        // Older there: send.
        let older = summary(&state(signed(1_000, true)));
        assert!(held.delta(older.as_ref()).unwrap().is_some());
        // The same there: nothing.
        assert_eq!(held.delta(summary(&held).as_ref()).unwrap(), None);
        // Newer there: nothing.
        let newer = summary(&state(signed(3_000, true)));
        assert_eq!(held.delta(newer.as_ref()).unwrap(), None);
        // Same moment, different heartbeat: send, so the tie converges.
        let twin = summary(&state(signed(2_000, false)));
        assert!(held.delta(twin.as_ref()).unwrap().is_some());
        // An empty state sends nothing and summarizes to nothing.
        assert_eq!(PresenceStateV1::default().delta(None).unwrap(), None);
        assert_eq!(summary(&PresenceStateV1::default()), None);
    }

    /// Exchanging summaries and deltas both ways leaves two replicas equal,
    /// whatever each held, the same-moment tie included.
    #[test]
    fn summary_and_delta_exchange_converges() {
        let pool = [
            None,
            Some(signed(1_000, true)),
            Some(signed(1_000, false)),
            Some(signed(2_000, true)),
        ];
        for a in &pool {
            for b in &pool {
                let mut x = PresenceStateV1 {
                    heartbeat: a.clone(),
                };
                let mut y = PresenceStateV1 {
                    heartbeat: b.clone(),
                };
                let (sx, sy) = (x.summarize().unwrap(), y.summarize().unwrap());
                if let Some(d) = x.delta(sy.as_ref()).unwrap() {
                    y.apply_delta(&params(), &d).unwrap();
                }
                if let Some(d) = y.delta(sx.as_ref()).unwrap() {
                    x.apply_delta(&params(), &d).unwrap();
                }
                assert_eq!(x, y, "{a:?} / {b:?}");
            }
        }
    }

    #[test]
    fn seeded_random_presence_states_obey_the_merge_laws() {
        let mut rng = Rng::new(0x5eed_9e5e);
        let times = [0u64, 1, 1_000, 1_000, 2_000, u64::MAX];
        let mut states = vec![PresenceStateV1::default()];
        for _ in 0..24 {
            let at = times[rng.below(times.len())];
            states.push(state(signed(at, rng.below(2) == 0)));
        }
        assert_laws(
            &states,
            400,
            &mut rng,
            |a, b| {
                let mut out = a.clone();
                out.merge(&params(), b).unwrap();
                out
            },
            |s| crate::to_cbor(s).unwrap(),
        );
    }

    fn at(at_ms: u64, taking_orders: bool) -> PresenceStateV1 {
        state(signed(at_ms, taking_orders))
    }

    #[test]
    fn the_verdict_at_every_boundary() {
        let now = 100 * PRESENCE_FRESH_MS;
        let v = |s: &PresenceStateV1| presence_verdict(Some(s), now);
        assert_eq!(
            presence_verdict(None, now),
            Presence::Closed(ClosedWhy::NoHeartbeat)
        );
        assert_eq!(
            v(&PresenceStateV1::default()),
            Presence::Closed(ClosedWhy::NoHeartbeat)
        );
        assert_eq!(v(&at(now, true)), Presence::Open);
        // Exactly ten minutes old is open; a millisecond more is not.
        assert_eq!(v(&at(now - PRESENCE_FRESH_MS, true)), Presence::Open);
        assert_eq!(
            v(&at(now - PRESENCE_FRESH_MS - 1, true)),
            Presence::Closed(ClosedWhy::Stale {
                age_ms: PRESENCE_FRESH_MS + 1
            })
        );
        // Exactly the allowed skew ahead is open; a millisecond more is not.
        assert_eq!(v(&at(now + PRESENCE_SKEW_MS, true)), Presence::Open);
        assert_eq!(
            v(&at(now + PRESENCE_SKEW_MS + 1, true)),
            Presence::Closed(ClosedWhy::FromTheFuture)
        );
        // Fresh, but not taking orders.
        assert_eq!(
            v(&at(now, false)),
            Presence::Closed(ClosedWhy::NotTakingOrders)
        );
        // Stale and not taking orders: stale is the reason.
        assert!(matches!(
            v(&at(now - PRESENCE_FRESH_MS - 1, false)),
            Presence::Closed(ClosedWhy::Stale { .. })
        ));
        // No overflow at the ends of the clock.
        assert_eq!(
            presence_verdict(Some(&at(u64::MAX, true)), u64::MAX),
            Presence::Open
        );
        assert_eq!(
            presence_verdict(Some(&at(u64::MAX, true)), 0),
            Presence::Closed(ClosedWhy::FromTheFuture)
        );
    }
}
