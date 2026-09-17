//! Which contract generation the bridge actually publishes to, read from the
//! generation pointers it signs (#30, #59).
//!
//! # What goes wrong without this
//!
//! Harvest used to carry the address contract's code hash as a build-time
//! constant, and stamp it onto every invoice. A contract's address is
//! `BLAKE3(code_hash || parameters)`, so the moment the bridge was redeployed
//! with different bytes, every invoice this build issued named an address
//! contract the bridge had stopped writing to. The buyer's payment would land on
//! chain, the proof would be published somewhere else, and the order would sit
//! at `AwaitingPayment` for ever with no error anywhere. On 2026-09-16 that is
//! exactly what the constant was: `cd2ae741`, the generation replaced that day
//! by `c2273660`.
//!
//! # What this does instead
//!
//! The bridge signs a pointer record per contract, naming the code hash it
//! currently publishes to. A pointer lives at an address derived from the
//! bridge's own key and a frozen contract, so it is computable offline and does
//! not move when the bridge's contracts re-key. This module resolves those
//! pointers and hands the rest of the app a code hash to derive from.
//!
//! Following the pointer adds no trust: it is signed by the same key that signs
//! every claim Harvest verifies, and every claim is still checked against its
//! own Bitcoin evidence.
//!
//! # There is no fallback, on purpose
//!
//! `freenet_migrate` permits falling back to a baked-in hash when a pointer has
//! never been published. Harvest does not, because the only hash it could bake
//! in is exactly the kind that goes stale, and a stale one is not a degraded
//! answer: it is an invoice naming a dead contract, with real money behind it.
//! Until a pointer resolves, the artifact has no code hash and nothing derives
//! from it, which means a seller cannot issue an invoice yet. That is the honest
//! state, and [`Unresolved`] says why.
//!
//! No I/O happens here, so resolution is tested against real signed records.

use freenet_bitcoin_common::{BitcoinNetwork, BitcoinTipParameters, BridgeId};
use freenet_bitcoin_generation::Artifact;
use freenet_migrate::pointer::{PointerFloor, PointerOutcome, PointerResolver};
use freenet_stdlib::prelude::ContractInstanceId;

/// The bridge contracts Harvest needs a generation for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Resolve {
    /// Where the bridge publishes what it has seen paid to an address.
    Address,
    /// Where the bridge takes requests to watch an address.
    Inbox,
    /// Where the bridge publishes the chain tip, which every invoice's anchor
    /// and every payment's depth is measured against.
    Tip,
}

impl Resolve {
    pub const ALL: [Resolve; 3] = [Resolve::Address, Resolve::Inbox, Resolve::Tip];

    pub const fn artifact(self) -> Artifact {
        match self {
            Resolve::Address => Artifact::Address,
            Resolve::Inbox => Artifact::Inbox,
            Resolve::Tip => Artifact::Tip,
        }
    }
}

/// The tip contract for `network`, at the generation `code_hash` names.
///
/// Its parameters are the network and the bridges it trusts, encoded with the
/// bridge's own encoder, since the address is a hash over those bytes. This is
/// what replaces the tip contract id Harvest used to carry as a constant, which
/// was once found three days and ~400 blocks stale, rendering as live (#30).
pub fn tip_contract_id(
    code_hash: &[u8; 32],
    network: BitcoinNetwork,
    trusted_bridges: &[BridgeId],
) -> Result<ContractInstanceId, String> {
    let params = freenet_bitcoin_common::to_cbor(&BitcoinTipParameters {
        network,
        trusted_bridges: trusted_bridges.to_vec(),
    })?;
    Ok(crate::migrate::current_id(
        code_hash,
        &freenet_stdlib::prelude::Parameters::from(params),
    ))
}

/// Why an artifact has no code hash to derive from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unresolved {
    /// Not yet asked, or asked and not yet answered.
    Pending,
    /// No usable answer came back: silence, an empty reply, or a node that
    /// could not be reached. Worth asking again.
    Unreachable,
    /// The node answered that no pointer is there. The bridge has not
    /// published one, or it could not be found this time. Worth asking again.
    NeverPublished,
    /// A record came back and was refused: malformed, not signed by this
    /// bridge, or not for this contract. A different peer may serve the real
    /// one, so worth asking again.
    Refused(String),
    /// The bridge signed a withdrawal of this contract. Authoritative, so it is
    /// not asked again and nothing may be derived from it.
    Withdrawn,
}

impl Unresolved {
    fn retryable(&self) -> bool {
        !matches!(self, Unresolved::Withdrawn | Unresolved::Pending)
    }

    /// Why nothing can be derived yet, in words a seller can act on.
    pub fn explain(&self) -> String {
        match self {
            Unresolved::Pending => {
                "the bridge's contract generation is still being looked up; wait a moment and \
                 try again"
                    .into()
            }
            Unresolved::Unreachable => {
                "the bridge's contract generation could not be looked up, because its pointer \
                 did not answer; this is retried automatically"
                    .into()
            }
            Unresolved::NeverPublished => {
                "the bridge has not published which contract generation it uses; this is \
                 retried automatically"
                    .into()
            }
            Unresolved::Refused(why) => format!(
                "the bridge's contract generation could not be trusted ({why}); this is retried \
                 automatically"
            ),
            Unresolved::Withdrawn => {
                "the bridge has withdrawn this contract, so nothing can be paid through it".into()
            }
        }
    }
}

/// What the app knows of one artifact's generation, as plain data it can keep
/// in state, render, and pass to code that must not reach for the network.
///
/// The resolver itself stays with the gateway: it is not `Clone`, and nothing
/// in the view should drive it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation(pub Result<[u8; 32], Unresolved>);

impl Default for Generation {
    /// Not yet resolved. There is deliberately no default code hash.
    fn default() -> Self {
        Generation(Err(Unresolved::Pending))
    }
}

impl Generation {
    pub fn resolved(code_hash: [u8; 32]) -> Self {
        Generation(Ok(code_hash))
    }

    pub fn code_hash(&self) -> Option<[u8; 32]> {
        self.0.as_ref().ok().copied()
    }
}

#[derive(Debug)]
enum Slot {
    Asking {
        id: ContractInstanceId,
        resolver: Box<PointerResolver>,
        asked: bool,
        /// Which attempt this is. See [`PointerRequest::attempt`].
        attempt: u32,
        /// What was settled before this attempt, for a refresh. It stays in
        /// force while the refresh is out, and again if the refresh learns
        /// nothing: a pointer that did not answer this time has not been
        /// withdrawn.
        prior: Option<Settled>,
    },
    Resolved {
        code_hash: [u8; 32],
        floor: PointerFloor,
    },
    Withdrawn {
        floor: PointerFloor,
    },
    Failed(Unresolved),
}

/// A settled answer, kept while a refresh asks again.
#[derive(Clone, Copy, Debug)]
enum Settled {
    Resolved {
        code_hash: [u8; 32],
        floor: PointerFloor,
    },
    Withdrawn {
        floor: PointerFloor,
    },
}

impl Settled {
    fn into_slot(self) -> Slot {
        match self {
            Settled::Resolved { code_hash, floor } => Slot::Resolved { code_hash, floor },
            Settled::Withdrawn { floor } => Slot::Withdrawn { floor },
        }
    }

    fn status(&self) -> Result<[u8; 32], Unresolved> {
        match self {
            Settled::Resolved { code_hash, .. } => Ok(*code_hash),
            Settled::Withdrawn { .. } => Err(Unresolved::Withdrawn),
        }
    }
}

/// A pointer contract to GET, and the attempt the GET belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerRequest {
    pub id: ContractInstanceId,
    /// Unique across every attempt this resolution makes, for either pointer.
    ///
    /// A pointer's id is the same on every attempt, and the resolver matches
    /// answers on the id alone, so a timeout armed for one attempt cannot tell
    /// from the id that a retry has since replaced it. Without this, a first
    /// attempt answered quickly with "not found" and retried would have its
    /// retry declared unreachable by the FIRST attempt's timer, well before the
    /// retry had its own chance to answer. So a timeout carries the attempt it
    /// was armed for, and is ignored once that attempt is not the current one.
    pub attempt: u32,
}

/// The resolution of one bridge's address, inbox and tip pointers.
#[derive(Debug)]
pub struct BridgeGenerations {
    bridge: BridgeId,
    address: Slot,
    inbox: Slot,
    tip: Slot,
    next_attempt: u32,
}

impl BridgeGenerations {
    /// Begin resolving `bridge`'s pointers. Nothing is sent until
    /// [`Self::requests_due`] is asked for what to GET.
    pub fn new(bridge: BridgeId) -> Self {
        let mut g = BridgeGenerations {
            bridge,
            // Placeholders, replaced at once below.
            address: Slot::Failed(Unresolved::Pending),
            inbox: Slot::Failed(Unresolved::Pending),
            tip: Slot::Failed(Unresolved::Pending),
            next_attempt: 0,
        };
        g.address = g.begin(Resolve::Address);
        g.inbox = g.begin(Resolve::Inbox);
        g.tip = g.begin(Resolve::Tip);
        g
    }

    /// The bridge whose pointers these are.
    pub fn bridge(&self) -> BridgeId {
        self.bridge
    }

    /// The pointer contracts to GET now, each marked as asked.
    ///
    /// The two may be in flight together: Harvest's node replies name the
    /// contract they are about, `NotFound` included, so an answer is never
    /// attributed to the wrong pointer.
    pub fn requests_due(&mut self) -> Vec<PointerRequest> {
        let mut out = Vec::new();
        for slot in [&mut self.address, &mut self.inbox, &mut self.tip] {
            if let Slot::Asking {
                id,
                resolver,
                asked,
                attempt,
                ..
            } = slot
            {
                if !*asked {
                    // Arms the resolver: it accepts no answer it has not asked for.
                    let _ = resolver.next_action();
                    *asked = true;
                    out.push(PointerRequest {
                        id: *id,
                        attempt: *attempt,
                    });
                }
            }
        }
        out
    }

    /// A pointer contract's state. Returns which artifact it settled, or
    /// `None` if the id is not a pointer this is waiting on, in which case the
    /// caller should treat the bytes as the ordinary contract state they are.
    ///
    /// Accepted from any attempt: the record is checked against the bridge's
    /// signature either way, so a late answer to an earlier GET is as good as
    /// an answer to the current one.
    pub fn on_state(&mut self, id: ContractInstanceId, bytes: &[u8]) -> Option<Resolve> {
        self.deliver(id, None, |r| r.on_response(id, bytes))
    }

    /// The node's positive answer that nothing is stored at `id`.
    pub fn on_absent(&mut self, id: ContractInstanceId) -> Option<Resolve> {
        self.deliver(id, None, |r| r.on_absent(id))
    }

    /// No answer to `request` in time. Never treated as absence, and ignored
    /// if a later attempt has replaced it: see [`PointerRequest::attempt`].
    pub fn on_unreachable(&mut self, request: PointerRequest) -> Option<Resolve> {
        let id = request.id;
        self.deliver(id, Some(request.attempt), |r| r.on_unreachable(id))
    }

    /// The code hash to derive `artifact`'s address from, or why there is none.
    pub fn status(&self, artifact: Resolve) -> Result<[u8; 32], Unresolved> {
        match self.slot(artifact) {
            Slot::Resolved { code_hash, .. } => Ok(*code_hash),
            Slot::Withdrawn { .. } => Err(Unresolved::Withdrawn),
            Slot::Failed(why) => Err(why.clone()),
            Slot::Asking {
                prior: Some(prior), ..
            } => prior.status(),
            Slot::Asking { prior: None, .. } => Err(Unresolved::Pending),
        }
    }

    /// The code hash for `artifact`, if it has resolved.
    pub fn code_hash(&self, artifact: Resolve) -> Option<[u8; 32]> {
        self.status(artifact).ok()
    }

    /// `artifact`'s resolution as plain data for app state.
    pub fn generation(&self, artifact: Resolve) -> Generation {
        Generation(self.status(artifact))
    }

    /// Start `artifact` over after a failure worth retrying. Returns whether a
    /// new request is now due from [`Self::requests_due`]. A withdrawal is
    /// never retried, and neither is anything resolved or still in flight.
    pub fn retry(&mut self, artifact: Resolve) -> bool {
        let retryable = matches!(self.slot(artifact), Slot::Failed(why) if why.retryable());
        if !retryable {
            return false;
        }
        let fresh = self.begin(artifact);
        let due = matches!(fresh, Slot::Asking { .. });
        *self.slot_mut(artifact) = fresh;
        due
    }

    /// Ask again about an artifact that has settled, from the floor it settled
    /// at. Returns whether a request is now due.
    ///
    /// Without this a tab resolves each pointer once and keeps the answer for
    /// as long as it is open. A bridge that redeploys meanwhile would leave it
    /// issuing invoices naming the address contract the bridge has moved off,
    /// and sending watch requests to an inbox nothing reads any more.
    ///
    /// Asked from the settled floor, so an older record a peer serves is
    /// refused as stale rather than adopted, and a withdrawal is superseded
    /// only by a newer record. Anything else leaves the settled answer
    /// standing.
    pub fn refresh(&mut self, artifact: Resolve) -> bool {
        let prior = match self.slot(artifact) {
            Slot::Resolved { code_hash, floor } => Settled::Resolved {
                code_hash: *code_hash,
                floor: *floor,
            },
            Slot::Withdrawn { floor } => Settled::Withdrawn { floor: *floor },
            _ => return false,
        };
        let attempt = self.next_attempt;
        self.next_attempt += 1;
        let fresh = asking(&self.bridge, artifact, attempt, Some(prior));
        let due = matches!(fresh, Slot::Asking { .. });
        *self.slot_mut(artifact) = fresh;
        due
    }

    /// Whether `id` is one of this bridge's pointer contracts, answered or not.
    /// A late answer to a pointer is still a pointer record, not app state.
    pub fn is_pointer(&self, id: &ContractInstanceId) -> bool {
        Resolve::ALL
            .iter()
            .any(|&artifact| pointer_id(&self.bridge, artifact).as_ref() == Some(id))
    }

    /// A new attempt at `artifact`, numbered after every attempt before it.
    fn begin(&mut self, artifact: Resolve) -> Slot {
        let attempt = self.next_attempt;
        self.next_attempt += 1;
        asking(&self.bridge, artifact, attempt, None)
    }

    fn deliver(
        &mut self,
        id: ContractInstanceId,
        only_attempt: Option<u32>,
        feed: impl FnOnce(&mut PointerResolver) -> bool,
    ) -> Option<Resolve> {
        for artifact in Resolve::ALL {
            let slot = self.slot_mut(artifact);
            let Slot::Asking {
                id: slot_id,
                resolver,
                attempt,
                prior,
                ..
            } = slot
            else {
                continue;
            };
            if *slot_id != id {
                continue;
            }
            if only_attempt.is_some_and(|a| a != *attempt) {
                return None;
            }
            if !feed(resolver) {
                return None;
            }
            let outcome = resolver.take_outcome()?;
            *slot = interpret(outcome, *prior);
            return Some(artifact);
        }
        None
    }

    fn slot(&self, artifact: Resolve) -> &Slot {
        match artifact {
            Resolve::Address => &self.address,
            Resolve::Inbox => &self.inbox,
            Resolve::Tip => &self.tip,
        }
    }

    fn slot_mut(&mut self, artifact: Resolve) -> &mut Slot {
        match artifact {
            Resolve::Address => &mut self.address,
            Resolve::Inbox => &mut self.inbox,
            Resolve::Tip => &mut self.tip,
        }
    }
}

/// The wait before retry number `failures` (from 1) of a pointer that did not
/// resolve: doubling from `first_ms`, capped at `max_ms`, then scaled by
/// `jitter`, which the caller draws from `0.8..=1.2` so many tabs do not ask in
/// step.
pub fn retry_delay_ms(failures: u32, first_ms: u32, max_ms: u32, jitter: f64) -> u32 {
    let doublings = failures.saturating_sub(1).min(8);
    let base = first_ms.saturating_mul(1 << doublings).min(max_ms);
    (f64::from(base) * jitter.clamp(0.8, 1.2)) as u32
}

/// A resolution for one artifact, from `prior`'s floor if it has settled
/// before in this tab.
///
/// A first resolution starts from `never_resolved`, because nothing here
/// persists a floor across a reload. The exposure that leaves is a peer
/// serving a genuine but superseded record on the first ask after a load,
/// which would name an older generation of the bridge's own contracts until
/// the next refresh finds the newer one. Persisting the floor closes it and is
/// a follow-up, not part of this change.
fn asking(bridge: &BridgeId, artifact: Resolve, attempt: u32, prior: Option<Settled>) -> Slot {
    let floor = match prior {
        Some(Settled::Resolved { floor, .. } | Settled::Withdrawn { floor }) => floor,
        None => PointerFloor::never_resolved(),
    };
    match freenet_bitcoin_generation::resolver(bridge, artifact.artifact(), floor) {
        Ok(resolver) => Slot::Asking {
            id: resolver.pointer_id(),
            resolver: Box::new(resolver),
            asked: false,
            attempt,
            prior,
        },
        // Only a bridge id that is not a valid Ed25519 point gets here, and
        // such a bridge could never have signed anything.
        Err(e) => Slot::Failed(Unresolved::Refused(format!(
            "the bridge id is not a signing key: {e}"
        ))),
    }
}

/// The pointer contract's id for `artifact`, or `None` for a bridge id that is
/// not a signing key.
fn pointer_id(bridge: &BridgeId, artifact: Resolve) -> Option<ContractInstanceId> {
    freenet_bitcoin_generation::resolver(
        bridge,
        artifact.artifact(),
        PointerFloor::never_resolved(),
    )
    .ok()
    .map(|r| r.pointer_id())
}

/// What an outcome settles the slot to. A refresh that learned nothing new
/// (no answer, an older record, a competing one, a refusal) leaves `prior`
/// standing.
fn interpret(
    outcome: Result<PointerOutcome, freenet_migrate::pointer::PointerError>,
    prior: Option<Settled>,
) -> Slot {
    if let Ok(outcome) = &outcome {
        if let Some(floor) = outcome.next_floor() {
            return match outcome.resolved() {
                Some(r) => Slot::Resolved {
                    code_hash: r.code_hash(),
                    floor,
                },
                None => Slot::Withdrawn { floor },
            };
        }
    }
    if let Some(prior) = prior {
        return prior.into_slot();
    }
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => return Slot::Failed(Unresolved::Refused(e.to_string())),
    };
    match outcome {
        // Unreachable in practice: both carry a floor and returned above.
        PointerOutcome::Resolved(_) | PointerOutcome::Unchanged(_) => Slot::Failed(
            Unresolved::Refused("a resolved record carried no floor".into()),
        ),
        PointerOutcome::Withdrawn { .. } => Slot::Failed(Unresolved::Withdrawn),
        PointerOutcome::NeverPublished => Slot::Failed(Unresolved::NeverPublished),
        PointerOutcome::Unavailable => Slot::Failed(Unresolved::Unreachable),
        PointerOutcome::Stale { served, floor } => Slot::Failed(Unresolved::Refused(format!(
            "version {served} does not supersede {floor}"
        ))),
        PointerOutcome::CompetingRecord { version, .. } => Slot::Failed(Unresolved::Refused(
            format!("two different records at version {version}"),
        )),
        // `PointerOutcome` is #[non_exhaustive]. A variant added later must land
        // somewhere that derives nothing from it.
        _ => Slot::Failed(Unresolved::Unreachable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_migrate::pointer::{PointerRecord, TOMBSTONE_CODE_HASH};

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn bridge() -> BridgeId {
        BridgeId(bridge_key().verifying_key().to_bytes())
    }

    /// A pointer record signed by `signer`, as the bridge publishes one.
    fn record(
        signer: &SigningKey,
        artifact: Artifact,
        version: u32,
        code_hash: [u8; 32],
    ) -> Vec<u8> {
        let message =
            freenet_bitcoin_generation::signing_message(&bridge(), artifact, version, &code_hash)
                .expect("the signing message lays out");
        PointerRecord {
            version,
            code_hash,
            signature: signer.sign(&message).to_bytes(),
        }
        .encode()
        .to_vec()
    }

    /// Ask for both pointers, and return each one's request, found by the id
    /// derived independently rather than by position.
    fn ask(g: &mut BridgeGenerations) -> (PointerRequest, PointerRequest) {
        let due = g.requests_due();
        let find = |artifact: Artifact| {
            let id = freenet_bitcoin_generation::pointer_id(&bridge(), artifact)
                .expect("the pointer id derives");
            *due.iter()
                .find(|r| r.id == id)
                .expect("the pointer is among those requested")
        };
        (find(Artifact::Address), find(Artifact::Inbox))
    }

    /// The decision this module turns on: before a pointer answers, there is no
    /// code hash at all, and in particular not a baked-in one.
    #[test]
    fn nothing_is_derived_before_the_pointer_answers() {
        let g = BridgeGenerations::new(bridge());
        for artifact in Resolve::ALL {
            assert_eq!(g.status(artifact), Err(Unresolved::Pending));
            assert_eq!(g.code_hash(artifact), None);
        }
    }

    #[test]
    fn a_record_the_bridge_signed_names_the_generation() {
        let mut g = BridgeGenerations::new(bridge());
        let (address, _) = ask(&mut g);
        let hash = [0x42; 32];

        let settled = g.on_state(
            address.id,
            &record(&bridge_key(), Artifact::Address, 3, hash),
        );
        assert_eq!(settled, Some(Resolve::Address));
        assert_eq!(g.code_hash(Resolve::Address), Some(hash));
        assert_eq!(
            g.code_hash(Resolve::Inbox),
            None,
            "the inbox is resolved on its own"
        );
    }

    /// Anyone can serve bytes at a pointer's address. Only the bridge's
    /// signature may move what Harvest derives from.
    #[test]
    fn a_record_signed_by_anyone_else_is_refused() {
        let mut g = BridgeGenerations::new(bridge());
        let (address, _) = ask(&mut g);
        let impostor = SigningKey::from_bytes(&[1u8; 32]);

        g.on_state(
            address.id,
            &record(&impostor, Artifact::Address, 3, [0x42; 32]),
        );
        assert!(matches!(
            g.status(Resolve::Address),
            Err(Unresolved::Refused(_))
        ));
        assert_eq!(g.code_hash(Resolve::Address), None);
    }

    /// The bridge's inbox record is genuinely signed by the bridge, but it
    /// names the inbox's code, and deriving an address contract from it would
    /// name a contract that is not one. The signature covers which pointer it
    /// is for, so it is refused at the address.
    #[test]
    fn the_inbox_record_cannot_stand_in_for_the_address() {
        let mut g = BridgeGenerations::new(bridge());
        let (address, _) = ask(&mut g);

        g.on_state(
            address.id,
            &record(&bridge_key(), Artifact::Inbox, 1, [0x77; 32]),
        );
        assert!(matches!(
            g.status(Resolve::Address),
            Err(Unresolved::Refused(_))
        ));
    }

    #[test]
    fn silence_and_absence_derive_nothing_and_are_asked_again() {
        let mut g = BridgeGenerations::new(bridge());
        let (address, inbox) = ask(&mut g);

        g.on_unreachable(address);
        assert_eq!(g.status(Resolve::Address), Err(Unresolved::Unreachable));
        g.on_absent(inbox.id);
        assert_eq!(g.status(Resolve::Inbox), Err(Unresolved::NeverPublished));

        assert!(g.retry(Resolve::Address), "silence is asked again");
        assert!(g.retry(Resolve::Inbox), "absence is asked again");
        let (address_again, inbox_again) = ask(&mut g);
        assert_eq!((address_again.id, inbox_again.id), (address.id, inbox.id));

        g.on_state(
            address.id,
            &record(&bridge_key(), Artifact::Address, 3, [0x42; 32]),
        );
        assert_eq!(
            g.code_hash(Resolve::Address),
            Some([0x42; 32]),
            "and resolves once answered"
        );
    }

    /// The race the attempt number exists for. A first GET is answered quickly
    /// with "not found" and retried; the first GET's timeout is still armed and
    /// fires while the retry is waiting. It must not end the retry, which has
    /// had no chance to answer, and the retry must still resolve afterwards.
    #[test]
    fn a_timeout_from_an_earlier_attempt_does_not_end_a_later_one() {
        let mut g = BridgeGenerations::new(bridge());
        let (first, _) = ask(&mut g);

        g.on_absent(first.id);
        assert!(g.retry(Resolve::Address));
        // Only the address was retried; the inbox is still in flight from the
        // first ask, so it is correctly not due again.
        let due = g.requests_due();
        assert_eq!(due.len(), 1, "only the retried pointer is due");
        let second = due[0];
        assert_eq!(second.id, first.id, "the same pointer");
        assert_ne!(second.attempt, first.attempt, "but a different attempt");

        assert_eq!(
            g.on_unreachable(first),
            None,
            "the first attempt's timer is ignored"
        );
        assert_eq!(
            g.status(Resolve::Address),
            Err(Unresolved::Pending),
            "the retry is still waiting"
        );

        g.on_state(
            first.id,
            &record(&bridge_key(), Artifact::Address, 3, [0x42; 32]),
        );
        assert_eq!(g.code_hash(Resolve::Address), Some([0x42; 32]));
    }

    /// And the current attempt's own timer is not ignored.
    #[test]
    fn the_current_attempts_timeout_counts() {
        let mut g = BridgeGenerations::new(bridge());
        let (address, _) = ask(&mut g);
        assert_eq!(g.on_unreachable(address), Some(Resolve::Address));
        assert_eq!(g.status(Resolve::Address), Err(Unresolved::Unreachable));
    }

    /// Both pointers are in flight together, so either may answer first. The
    /// inbox answering while the address is still pending must settle the
    /// inbox, and not be turned away by the address's resolver on the way past
    /// it. Every other test here happens to settle the address first, which is
    /// how a deleted id check once passed all of them.
    #[test]
    fn either_pointer_may_answer_first() {
        let mut g = BridgeGenerations::new(bridge());
        let (_, inbox) = ask(&mut g);

        let settled = g.on_state(
            inbox.id,
            &record(&bridge_key(), Artifact::Inbox, 1, [0x77; 32]),
        );
        assert_eq!(settled, Some(Resolve::Inbox));
        assert_eq!(g.code_hash(Resolve::Inbox), Some([0x77; 32]));
        assert_eq!(
            g.status(Resolve::Address),
            Err(Unresolved::Pending),
            "the address is still waiting on its own answer"
        );
    }

    /// A withdrawal is a signed instruction, not a failure to reach anything.
    #[test]
    fn a_withdrawal_derives_nothing_and_is_not_asked_again() {
        let mut g = BridgeGenerations::new(bridge());
        let (address, _) = ask(&mut g);

        g.on_state(
            address.id,
            &record(&bridge_key(), Artifact::Address, 4, TOMBSTONE_CODE_HASH),
        );
        assert_eq!(g.status(Resolve::Address), Err(Unresolved::Withdrawn));
        assert!(!g.retry(Resolve::Address));
        assert!(g.requests_due().is_empty());
    }

    /// State for any other contract is not a pointer's, and must reach the rest
    /// of the app rather than be swallowed here. So is an answer nothing asked
    /// for.
    #[test]
    fn answers_it_did_not_ask_for_are_not_taken() {
        let mut g = BridgeGenerations::new(bridge());
        let address = freenet_bitcoin_generation::pointer_id(&bridge(), Artifact::Address).unwrap();
        let bytes = record(&bridge_key(), Artifact::Address, 3, [0x42; 32]);

        assert_eq!(
            g.on_state(address, &bytes),
            None,
            "not accepted before it was asked"
        );
        ask(&mut g);
        assert_eq!(
            g.on_state(ContractInstanceId::new([5u8; 32]), &bytes),
            None,
            "another contract's state is left for the app"
        );
        assert_eq!(g.on_state(address, &bytes), Some(Resolve::Address));
    }

    /// The pointer ids this derives for the live bridge are the ones that
    /// bridge publishes to, taken from its own journal on 2026-09-16. If they
    /// differed, Harvest would look for the generation somewhere the bridge
    /// never writes, and every artifact would stay unresolved.
    /// The tip contract this derives from the live bridge's tip pointer is the
    /// contract that bridge publishes the signet tip to. The code hash is the
    /// one its tip pointer named on 2026-09-16 (`DUtUZJER...`), and the contract
    /// id is the one its journal reported (`tip contract network=Signet
    /// contract=FXFgLKfu...`). Derived from the pointer, it matches without any
    /// constant in the build.
    #[test]
    fn the_live_signet_tip_contract_is_derived_from_its_pointers_code_hash() {
        let live = BridgeId::from_bs58(crate::gateway::bitcoin_config::TRUSTED_BRIDGE_ID_BS58)
            .expect("the trusted bridge id parses");
        let code_hash: [u8; 32] =
            hex::decode("b97120c8b8e9644defc4f9a0230576ac4a3449ce30a6e68d7cfa47ad0df1664c")
                .unwrap()
                .try_into()
                .unwrap();
        let id = tip_contract_id(&code_hash, BitcoinNetwork::Signet, &[live]).expect("derives");
        assert_eq!(
            bs58::encode(id.as_bytes()).into_string(),
            "FXFgLKfuMm3NPtzWg3Ghgt5otv4Yo7N4CWGDvHpVeZMm"
        );
    }

    #[test]
    fn the_live_bridges_pointers_are_where_the_bridge_publishes_them() {
        let live = BridgeId::from_bs58(crate::gateway::bitcoin_config::TRUSTED_BRIDGE_ID_BS58)
            .expect("the trusted bridge id parses");
        let b58 = |a| {
            bs58::encode(
                freenet_bitcoin_generation::pointer_id(&live, a)
                    .expect("derives")
                    .as_bytes(),
            )
            .into_string()
        };
        assert_eq!(
            b58(Artifact::Address),
            "C1cTJXmyZ9EMDMKwTEMTSq2PNwoMNhrKWrnzWK2XbcKV"
        );
        assert_eq!(
            b58(Artifact::Inbox),
            "EJFxTePBSFXQpAHyf5w6iK4SUZGwKP2fQN5uFco4SLau"
        );
        assert_eq!(
            b58(Artifact::Tip),
            "G9brbHSKXEdFZW8jKtfMHYT2GcrvJH6jhebkykN35mo9"
        );
    }

    /// The address request due after a refresh.
    fn asked_again(g: &mut BridgeGenerations) -> PointerRequest {
        let id = freenet_bitcoin_generation::pointer_id(&bridge(), Artifact::Address)
            .expect("the pointer id derives");
        *g.requests_due()
            .iter()
            .find(|r| r.id == id)
            .expect("the address pointer is asked again")
    }

    fn resolved_at(version: u32, hash: [u8; 32]) -> BridgeGenerations {
        let mut g = BridgeGenerations::new(bridge());
        let (address, _) = ask(&mut g);
        g.on_state(
            address.id,
            &record(&bridge_key(), Artifact::Address, version, hash),
        );
        assert_eq!(g.code_hash(Resolve::Address), Some(hash));
        g
    }

    /// **A redeploy while the tab is open is followed.** Without a refresh the
    /// first answer stood for the life of the tab, and invoices kept naming the
    /// contract the bridge had moved off.
    #[test]
    fn a_refresh_follows_the_bridge_to_a_new_generation() {
        let mut g = resolved_at(3, [0x42; 32]);
        assert!(g.refresh(Resolve::Address));
        let request = asked_again(&mut g);
        assert_eq!(
            g.code_hash(Resolve::Address),
            Some([0x42; 32]),
            "the settled generation stays in force while the refresh is out"
        );

        g.on_state(
            request.id,
            &record(&bridge_key(), Artifact::Address, 4, [0x43; 32]),
        );
        assert_eq!(g.code_hash(Resolve::Address), Some([0x43; 32]));
    }

    /// **A refresh never goes backwards.** A genuine older record served by a
    /// peer is refused against the settled floor.
    #[test]
    fn a_refresh_does_not_adopt_an_older_record() {
        let mut g = resolved_at(4, [0x43; 32]);
        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        g.on_state(
            request.id,
            &record(&bridge_key(), Artifact::Address, 3, [0x42; 32]),
        );
        assert_eq!(g.code_hash(Resolve::Address), Some([0x43; 32]));
    }

    /// **A refresh that learns nothing keeps what was settled.** A pointer
    /// that did not answer this time has not been withdrawn.
    #[test]
    fn a_refresh_that_fails_keeps_the_settled_generation() {
        let mut g = resolved_at(4, [0x43; 32]);

        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        g.on_unreachable(request);
        assert_eq!(g.code_hash(Resolve::Address), Some([0x43; 32]), "silence");

        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        g.on_absent(request.id);
        assert_eq!(g.code_hash(Resolve::Address), Some([0x43; 32]), "absence");

        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        let impostor = SigningKey::from_bytes(&[1u8; 32]);
        g.on_state(
            request.id,
            &record(&impostor, Artifact::Address, 9, [0x66; 32]),
        );
        assert_eq!(g.code_hash(Resolve::Address), Some([0x43; 32]), "a forgery");
    }

    /// **A withdrawal is final until the bridge publishes past it.** The
    /// refresh asks from the withdrawal's floor, so a replayed pre-withdrawal
    /// record does not revive it and a newer record does.
    #[test]
    fn a_withdrawal_is_lifted_only_by_a_newer_record() {
        let mut g = resolved_at(4, [0x43; 32]);
        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        g.on_state(
            request.id,
            &record(&bridge_key(), Artifact::Address, 5, TOMBSTONE_CODE_HASH),
        );
        assert_eq!(g.status(Resolve::Address), Err(Unresolved::Withdrawn));
        assert!(!g.retry(Resolve::Address), "not retried as a failure");

        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        g.on_state(
            request.id,
            &record(&bridge_key(), Artifact::Address, 4, [0x43; 32]),
        );
        assert_eq!(
            g.status(Resolve::Address),
            Err(Unresolved::Withdrawn),
            "a replay of the record it withdrew"
        );

        g.refresh(Resolve::Address);
        let request = asked_again(&mut g);
        g.on_state(
            request.id,
            &record(&bridge_key(), Artifact::Address, 6, [0x44; 32]),
        );
        assert_eq!(g.code_hash(Resolve::Address), Some([0x44; 32]));
    }

    #[test]
    fn only_a_settled_artifact_is_refreshed() {
        let mut g = BridgeGenerations::new(bridge());
        assert!(!g.refresh(Resolve::Address), "still asking");
        let (address, _) = ask(&mut g);
        g.on_unreachable(address);
        assert!(
            !g.refresh(Resolve::Address),
            "a failure is retried, not refreshed"
        );
    }

    #[test]
    fn every_pointer_id_is_recognised_answered_or_not() {
        let g = BridgeGenerations::new(bridge());
        for artifact in [Artifact::Address, Artifact::Inbox, Artifact::Tip] {
            let id = freenet_bitcoin_generation::pointer_id(&bridge(), artifact)
                .expect("the pointer id derives");
            assert!(g.is_pointer(&id));
        }
        assert!(!g.is_pointer(&ContractInstanceId::new([5u8; 32])));
    }

    #[test]
    fn a_pointer_retry_waits_longer_each_time_up_to_a_cap_with_bounded_jitter() {
        let delay = |n, j| retry_delay_ms(n, 30_000, 600_000, j);
        assert_eq!(delay(1, 1.0), 30_000);
        assert_eq!(delay(2, 1.0), 60_000);
        assert_eq!(delay(3, 1.0), 120_000);
        assert_eq!(delay(6, 1.0), 600_000, "capped");
        assert_eq!(delay(u32::MAX, 1.0), 600_000, "no overflow");
        assert_eq!(delay(1, 0.8), 24_000);
        assert_eq!(delay(1, 1.2), 36_000);
        assert_eq!(delay(1, 5.0), 36_000, "jitter is bounded");
    }
}
