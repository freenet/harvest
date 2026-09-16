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

use freenet_bitcoin_common::BridgeId;
use freenet_bitcoin_generation::Artifact;
use freenet_migrate::pointer::{PointerFloor, PointerOutcome, PointerResolver};
use freenet_stdlib::prelude::ContractInstanceId;

/// The bridge contracts Harvest needs a generation for.
///
/// Not the tip contract: Harvest still addresses that by a well-known id, and
/// resolving it would also need the tip contract's parameters derived here. A
/// separate type makes asking this module for the tip a compile error rather
/// than a silent `None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolve {
    /// Where the bridge publishes what it has seen paid to an address.
    Address,
    /// Where the bridge takes requests to watch an address.
    Inbox,
}

impl Resolve {
    pub const ALL: [Resolve; 2] = [Resolve::Address, Resolve::Inbox];

    pub const fn artifact(self) -> Artifact {
        match self {
            Resolve::Address => Artifact::Address,
            Resolve::Inbox => Artifact::Inbox,
        }
    }
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
}

#[derive(Debug)]
enum Slot {
    Asking {
        id: ContractInstanceId,
        resolver: Box<PointerResolver>,
        asked: bool,
    },
    Resolved {
        code_hash: [u8; 32],
    },
    Failed(Unresolved),
}

/// The resolution of one bridge's address and inbox pointers.
#[derive(Debug)]
pub struct BridgeGenerations {
    bridge: BridgeId,
    address: Slot,
    inbox: Slot,
}

impl BridgeGenerations {
    /// Begin resolving `bridge`'s pointers. Nothing is sent until
    /// [`Self::to_request`] is asked for the ids to GET.
    pub fn new(bridge: BridgeId) -> Self {
        BridgeGenerations {
            address: asking(&bridge, Resolve::Address),
            inbox: asking(&bridge, Resolve::Inbox),
            bridge,
        }
    }

    /// The pointer contracts to GET now, each marked as asked.
    ///
    /// The two may be in flight together: Harvest's node replies name the
    /// contract they are about, `NotFound` included, so an answer is never
    /// attributed to the wrong pointer.
    pub fn to_request(&mut self) -> Vec<ContractInstanceId> {
        let mut out = Vec::new();
        for slot in [&mut self.address, &mut self.inbox] {
            if let Slot::Asking {
                id,
                resolver,
                asked,
            } = slot
            {
                if !*asked {
                    // Arms the resolver: it accepts no answer it has not asked for.
                    let _ = resolver.next_action();
                    *asked = true;
                    out.push(*id);
                }
            }
        }
        out
    }

    /// A pointer contract's state. Returns which artifact it settled, or
    /// `None` if the id is not a pointer this is waiting on, in which case the
    /// caller should treat the bytes as the ordinary contract state they are.
    pub fn on_state(&mut self, id: ContractInstanceId, bytes: &[u8]) -> Option<Resolve> {
        self.deliver(id, |r| r.on_response(id, bytes))
    }

    /// The node's positive answer that nothing is stored at `id`.
    pub fn on_absent(&mut self, id: ContractInstanceId) -> Option<Resolve> {
        self.deliver(id, |r| r.on_absent(id))
    }

    /// No answer for `id` in time. Never treated as absence.
    pub fn on_unreachable(&mut self, id: ContractInstanceId) -> Option<Resolve> {
        self.deliver(id, |r| r.on_unreachable(id))
    }

    /// The code hash to derive `artifact`'s address from, or why there is none.
    pub fn status(&self, artifact: Resolve) -> Result<[u8; 32], Unresolved> {
        match self.slot(artifact) {
            Slot::Resolved { code_hash } => Ok(*code_hash),
            Slot::Failed(why) => Err(why.clone()),
            Slot::Asking { .. } => Err(Unresolved::Pending),
        }
    }

    /// The code hash for `artifact`, if it has resolved.
    pub fn code_hash(&self, artifact: Resolve) -> Option<[u8; 32]> {
        self.status(artifact).ok()
    }

    /// Start `artifact` over after a failure worth retrying. Returns whether a
    /// new request is now due from [`Self::to_request`]. A withdrawal is never
    /// retried, and neither is anything resolved or still in flight.
    pub fn retry(&mut self, artifact: Resolve) -> bool {
        let bridge = self.bridge;
        let slot = self.slot_mut(artifact);
        match slot {
            Slot::Failed(why) if why.retryable() => {
                *slot = asking(&bridge, artifact);
                matches!(slot, Slot::Asking { .. })
            }
            _ => false,
        }
    }

    fn deliver(
        &mut self,
        id: ContractInstanceId,
        feed: impl FnOnce(&mut PointerResolver) -> bool,
    ) -> Option<Resolve> {
        for artifact in Resolve::ALL {
            let slot = self.slot_mut(artifact);
            let Slot::Asking {
                id: slot_id,
                resolver,
                ..
            } = slot
            else {
                continue;
            };
            if *slot_id != id {
                continue;
            }
            if !feed(resolver) {
                return None;
            }
            let outcome = resolver.take_outcome()?;
            *slot = interpret(outcome);
            return Some(artifact);
        }
        None
    }

    fn slot(&self, artifact: Resolve) -> &Slot {
        match artifact {
            Resolve::Address => &self.address,
            Resolve::Inbox => &self.inbox,
        }
    }

    fn slot_mut(&mut self, artifact: Resolve) -> &mut Slot {
        match artifact {
            Resolve::Address => &mut self.address,
            Resolve::Inbox => &mut self.inbox,
        }
    }
}

/// A fresh resolution for one artifact.
///
/// The floor is `never_resolved` because nothing here persists one across a
/// reload. The exposure that leaves is a peer serving a genuine but superseded
/// record, which would name an older generation of the bridge's own contracts.
/// For Harvest that is worse than stale display: an invoice issued meanwhile
/// would name a contract the bridge has moved off. Persisting the floor closes
/// it and is a follow-up, not part of this change.
fn asking(bridge: &BridgeId, artifact: Resolve) -> Slot {
    match freenet_bitcoin_generation::resolver(
        bridge,
        artifact.artifact(),
        PointerFloor::never_resolved(),
    ) {
        Ok(resolver) => Slot::Asking {
            id: resolver.pointer_id(),
            resolver: Box::new(resolver),
            asked: false,
        },
        // Only a bridge id that is not a valid Ed25519 point gets here, and
        // such a bridge could never have signed anything.
        Err(e) => Slot::Failed(Unresolved::Refused(format!(
            "the bridge id is not a signing key: {e}"
        ))),
    }
}

fn interpret(outcome: Result<PointerOutcome, freenet_migrate::pointer::PointerError>) -> Slot {
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => return Slot::Failed(Unresolved::Refused(e.to_string())),
    };
    match outcome {
        PointerOutcome::Resolved(r) | PointerOutcome::Unchanged(r) => Slot::Resolved {
            code_hash: r.code_hash(),
        },
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

    fn id_of(g: &mut BridgeGenerations, artifact: Resolve) -> ContractInstanceId {
        let expected = freenet_bitcoin_generation::pointer_id(&bridge(), artifact.artifact())
            .expect("the pointer id derives");
        let asked = g.to_request();
        assert!(
            asked.contains(&expected),
            "the pointer is among those requested"
        );
        expected
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
        let address = id_of(&mut g, Resolve::Address);
        let hash = [0x42; 32];

        let settled = g.on_state(address, &record(&bridge_key(), Artifact::Address, 3, hash));
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
        let address = id_of(&mut g, Resolve::Address);
        let impostor = SigningKey::from_bytes(&[1u8; 32]);

        g.on_state(
            address,
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
        let address = id_of(&mut g, Resolve::Address);

        g.on_state(
            address,
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
        let address = id_of(&mut g, Resolve::Address);
        let inbox = freenet_bitcoin_generation::pointer_id(&bridge(), Artifact::Inbox).unwrap();

        g.on_unreachable(address);
        assert_eq!(g.status(Resolve::Address), Err(Unresolved::Unreachable));
        g.on_absent(inbox);
        assert_eq!(g.status(Resolve::Inbox), Err(Unresolved::NeverPublished));

        assert!(g.retry(Resolve::Address), "silence is asked again");
        assert!(g.retry(Resolve::Inbox), "absence is asked again");
        let again = g.to_request();
        assert!(again.contains(&address) && again.contains(&inbox));

        g.on_state(
            address,
            &record(&bridge_key(), Artifact::Address, 3, [0x42; 32]),
        );
        assert_eq!(
            g.code_hash(Resolve::Address),
            Some([0x42; 32]),
            "and resolves once answered"
        );
    }

    /// Both pointers are in flight together, so either may answer first. The
    /// inbox answering while the address is still pending must settle the
    /// inbox, and not be turned away by the address's resolver on the way past
    /// it. Every other test here happens to settle the address first, which is
    /// how a deleted id check once passed all of them.
    #[test]
    fn either_pointer_may_answer_first() {
        let mut g = BridgeGenerations::new(bridge());
        assert_eq!(g.to_request().len(), 2, "both are asked at once");
        let inbox = freenet_bitcoin_generation::pointer_id(&bridge(), Artifact::Inbox).unwrap();

        let settled = g.on_state(
            inbox,
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
        let address = id_of(&mut g, Resolve::Address);

        g.on_state(
            address,
            &record(&bridge_key(), Artifact::Address, 4, TOMBSTONE_CODE_HASH),
        );
        assert_eq!(g.status(Resolve::Address), Err(Unresolved::Withdrawn));
        assert!(!g.retry(Resolve::Address));
        assert!(g.to_request().is_empty());
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
        g.to_request();
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
    }
}
