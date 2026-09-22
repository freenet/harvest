//! Reaching a seller's mailbox, from a buyer who has never met them.
//!
//! # How a buyer finds the address at all
//!
//! Nothing publishes it. `StoreInfoV1` names the reputation contract and not
//! the mailbox, and the store's state does not carry it either -- the id is
//! known at creation time and nowhere else (see
//! `store_ops::create_store_contracts`). So the buyer DERIVES it: a mailbox
//! lives at `BLAKE3(BLAKE3(wasm) || cbor(MailboxParameters))`, and
//! `MailboxParameters`' only field is the seller's Ed25519 verifying key,
//! which the buyer already recovers from the store's ghostkey certificate in
//! order to decide whether to trust the store at all.
//!
//! That the key comes from `ghostkey_cert::store_verifying_key` rather than
//! from anything the seller says about themselves is load-bearing: it is
//! returned only when the certificate verifies AGAINST THIS STORE, so a
//! scammer who pastes somebody else's genuine certificate onto their store
//! gets no key, rather than getting the victim's -- which would send the
//! buyer's message into the victim's mailbox while reporting success.
//!
//! # What this cannot reach
//!
//! A mailbox published by a different build of Harvest. The code hash is this
//! build's `mailbox_contract.wasm`, so a seller whose mailbox predates it
//! lives at an address derived here from the wrong hash. Unlike
//! `store_ops::store_contract_key`, there is no recorded key to fall back on:
//! a buyer has no registration for someone else's store. The failure is a
//! contract that does not exist, which the node answers with silence, so the
//! UI cannot distinguish it from a slow network and must not claim delivery.
//! `components::message_view` says exactly that.

use freenet_stdlib::prelude::{ContractCode, ContractKey};
use harvest_common::mailbox::EncryptedMessage;

use super::store_ops::MAILBOX_CONTRACT_WASM;

/// The `ContractKey` of the mailbox belonging to the holder of
/// `owner_verifying_key`, as this build addresses it.
///
/// Both halves come from the same two inputs the seller's own PUT used: the
/// parameters from [`crate::migrate::mailbox_params`], which is the one place
/// they are derived, and the code hash of the bundled mailbox WASM.
pub fn mailbox_contract_key(
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<ContractKey, String> {
    let params =
        crate::migrate::encode_params(&crate::migrate::mailbox_params(owner_verifying_key))?;
    let code_hash = *ContractCode::from(MAILBOX_CONTRACT_WASM.to_vec()).hash();
    Ok(ContractKey::from_id_and_code(
        crate::migrate::current_id(&code_hash, &params),
        code_hash,
    ))
}

/// The `ContractKey` of a mailbox whose instance id is already known.
///
/// The seller's own mailbox is reached this way rather than by re-deriving
/// it: the id they are READING came from their delegate's registration, and
/// replying into a different one than they are reading would put the answer
/// somewhere the buyer is not looking. Same reasoning, and the same residual,
/// as `store_ops::store_contract_key`'s reconstructed path -- the code hash
/// is this build's, so a mailbox published by an older build is addressed
/// wrongly here.
pub fn mailbox_key_from_id(instance_id: &[u8]) -> Result<ContractKey, String> {
    let id: [u8; 32] = instance_id
        .try_into()
        .map_err(|_| format!("mailbox contract id is {} bytes, not 32", instance_id.len()))?;
    let code_hash = *ContractCode::from(MAILBOX_CONTRACT_WASM.to_vec()).hash();
    Ok(ContractKey::from_id_and_code(
        freenet_stdlib::prelude::ContractInstanceId::new(id),
        code_hash,
    ))
}

/// Bytes of a mailbox update carrying new messages.
///
/// The mailbox contract's delta is `MailboxDelta`, a bare
/// `Vec<EncryptedMessage>` -- NOT the per-field `Option` struct the store
/// contract's `#[composable]` macro generates. The two are different wire
/// shapes and the contract rejects the wrong one outright, so the mistake
/// `store_ops::listings_delta_bytes` documents is available here in the
/// opposite direction. Pinned by
/// `the_delta_is_the_shape_the_mailbox_contract_decodes`.
pub fn mailbox_delta_bytes(messages: Vec<EncryptedMessage>) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&messages).map_err(|e| format!("serialize mailbox delta: {e}"))
}

/// How long after handing a message to the node the buyer's copy of the
/// mailbox is re-read to see whether the message is in it.
///
/// Long enough for an update the node applied to be in its own copy (it is
/// applied locally before it is forwarded), short enough that a buyer who is
/// still looking at the page learns about a lost message while they can do
/// something about it.
///
/// The WORST case to a "not received" card is longer than this suggests:
/// the first write may wait up to `prime::PRIME_TIMEOUT_MS` for its priming
/// answer, and each check is this wait plus a re-read that may itself wait
/// up to `PRIME_TIMEOUT_MS`, twice over -- roughly 30 + 2 x (20 + 30)
/// seconds. The card says "not yet visible" throughout.
pub const DELIVERY_CHECK_AFTER_MS: u32 = 20_000;

/// How many times the IDENTICAL sealed bytes are handed to the node again,
/// automatically, before the buyer is told the seller does not have them.
pub const AUTOMATIC_RESENDS: u8 = 1;

/// What one delivery check established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// The message is in the mailbox.
    Landed,
    /// The node answered a fresh read of the mailbox, and the message is not
    /// in it.
    Missing,
    /// No fresh answer (the re-read timed out or could not be sent), or this
    /// tab does not route that mailbox's state anywhere it can look. Nothing
    /// was learned, so nothing may be claimed.
    CannotTell,
}

impl Check {
    /// `landed` is what the mailbox as last read says; `fresh` is whether
    /// the node answered the re-read that preceded it.
    ///
    /// A message seen in the mailbox has landed whether or not the read was
    /// fresh. Its ABSENCE counts only from a fresh read: a stale copy
    /// predates the write, so it says nothing about it.
    pub fn from_read(landed: Option<bool>, fresh: bool) -> Self {
        match (landed, fresh) {
            (Some(true), _) => Check::Landed,
            (Some(false), true) => Check::Missing,
            _ => Check::CannotTell,
        }
    }
}

/// What to do after a delivery check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryStep {
    /// The message is in the mailbox. Nothing more to do.
    Landed,
    /// Not seen yet: hand the same bytes to the node again. Harmless even
    /// when the check could not tell, since identical bytes cannot land
    /// twice.
    SendAgain,
    /// Missing after every automatic attempt: say so, and offer to resend.
    TellTheBuyer,
    /// Still unable to tell after every automatic attempt. Claim nothing
    /// about the seller, but say Harvest could not check, and offer the
    /// resend: #119's own condition (a GET that never answers) lands here,
    /// and a buyer left with no button would retype the message, which is a
    /// fresh seal and a possible duplicate.
    CouldNotCheck,
}

/// `sends` is how many times these bytes have been handed to the node so far.
pub fn after_delivery_check(check: Check, sends: u8) -> DeliveryStep {
    match check {
        Check::Landed => DeliveryStep::Landed,
        _ if sends <= AUTOMATIC_RESENDS => DeliveryStep::SendAgain,
        Check::Missing => DeliveryStep::TellTheBuyer,
        Check::CannotTell => DeliveryStep::CouldNotCheck,
    }
}

/// What delivering one message needs from the world. A trait so the retry
/// behaviour runs on the host; see `NodeDelivery` for the real one.
pub(crate) trait Delivery {
    /// Hand `message` to the node.
    async fn write(&self, message: &EncryptedMessage) -> Result<(), String>;
    /// Wait [`DELIVERY_CHECK_AFTER_MS`], then re-read the mailbox from the
    /// node. `true` only when the node actually answered the re-read.
    async fn wait_and_reread(&self) -> bool;
    /// Whether the message with this digest is in the mailbox as last read;
    /// `None` when this tab cannot tell.
    fn landed(&self, digest: &[u8; 32]) -> Option<bool>;
    /// The message did not arrive: record it so the buyer is told and can
    /// resend. `error` is the node's failure when it could not be reached.
    fn not_arrived(&self, digest: &[u8; 32], why: crate::state::NotArrived, error: Option<String>);
}

/// Hand a sealed message to the node, check that it reached the mailbox,
/// re-send the identical bytes if it did not, and say so if it still has
/// not.
///
/// # Why a re-send is safe here, and a re-seal would not be
///
/// Every attempt hands the node the SAME `EncryptedMessage`. The mailbox
/// keys entries by `entry_digest`, so a second copy of bytes that did land is
/// merged away rather than shown twice. Sealing again would produce a fresh
/// nonce and a second, distinct message. Nothing here holds a key it could
/// seal with, which is the point.
///
/// # What "landed" means
///
/// That the message is in the buyer's own node's copy of the mailbox, read
/// back after waiting. An update is applied by the local node before it is
/// forwarded, so a message missing from a FRESH read of that copy was not
/// applied at all -- which is what harvest#119 looked like from the outside.
/// Whether the network then carries it to the seller's node is not
/// observable from here.
///
/// # What it cannot rule out
///
/// A GET answer carries no request id, so "fresh" means "the node answered
/// a GET for this mailbox after the re-read was registered", which an older
/// GET still in flight could satisfy with a pre-write state. The first
/// check's verdict only ever triggers the resend, so one such stale answer
/// on the SECOND check is enough for a false "not received" card. It errs
/// only that way, and the card clears by itself once a later read of the
/// sending store's mailbox shows the message (`AppState::unconfirmed_sent`
/// filters on what is in it) -- except for a second store under the same
/// Ghost Key, whose mailbox state this tab files under the first store
/// (freenet/harvest#130).
pub(crate) async fn deliver(io: &impl Delivery, message: EncryptedMessage) {
    use crate::state::NotArrived;

    let digest = harvest_common::mailbox::entry_digest(&message);
    let mut sends: u8 = 0;
    loop {
        sends = sends.saturating_add(1);
        if let Err(e) = io.write(&message).await {
            // Only the FIRST write failing means nothing was ever sent. A
            // resend failing says nothing about the copy that did reach the
            // node, which may well have landed.
            let why = if sends == 1 {
                NotArrived::NeverReachedNode
            } else {
                NotArrived::Unconfirmed
            };
            io.not_arrived(&digest, why, Some(e));
            return;
        }
        let fresh = io.wait_and_reread().await;
        match after_delivery_check(Check::from_read(io.landed(&digest), fresh), sends) {
            DeliveryStep::Landed => return,
            DeliveryStep::CouldNotCheck => {
                io.not_arrived(&digest, NotArrived::Unconfirmed, None);
                return;
            }
            DeliveryStep::SendAgain => continue,
            DeliveryStep::TellTheBuyer => {
                io.not_arrived(&digest, NotArrived::NotInMailbox, None);
                return;
            }
        }
    }
}

/// Write one encrypted message into a seller's mailbox, and see that it
/// arrives.
///
/// # What "sent" means here, and what it does not
///
/// A write resolves when the WebSocket SEND to the local node succeeds. The
/// node answers an `UpdateResponse` with no correlation id, so nothing here
/// can match a confirmation or a rejection to this send. The only delivery
/// signal Harvest has is the message turning up in the mailbox, which
/// [`deliver`] checks for; callers must not report delivery before that. See
/// `components::message_view` for the wording.
///
/// # A buyer's node usually does not hold the seller's mailbox
///
/// A node cannot apply an update to a contract it does not hold; it bounces
/// it and asks the client to retry, uncorrelated (harvest#119). Every write
/// therefore waits for the node to answer a GET for the mailbox first --
/// `gateway::prime`, which all contract writes go through -- and [`deliver`]
/// covers what priming cannot: a GET that never answers, after which the
/// write goes out anyway and may be bounced.
///
/// Subscription is a separate decision made once, on the buyer's first
/// message, by `components::message_view` -- a reader who never writes
/// advertises no interest in anybody's mailbox.
#[cfg(target_arch = "wasm32")]
pub async fn send_message(
    store_contract_id: Vec<u8>,
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
    message: EncryptedMessage,
) -> Result<(), String> {
    let key = mailbox_contract_key(owner_verifying_key)?;
    deliver(
        &NodeDelivery {
            store_contract_id,
            key,
        },
        message,
    )
    .await;
    Ok(())
}

/// The real [`Delivery`]: this node, and `APP_STATE` for what it holds.
#[cfg(target_arch = "wasm32")]
struct NodeDelivery {
    store_contract_id: Vec<u8>,
    key: ContractKey,
}

#[cfg(target_arch = "wasm32")]
impl Delivery for NodeDelivery {
    async fn write(&self, message: &EncryptedMessage) -> Result<(), String> {
        write_to_mailbox(&self.key, message.clone()).await
    }
    async fn wait_and_reread(&self) -> bool {
        gloo_timers::future::TimeoutFuture::new(DELIVERY_CHECK_AFTER_MS).await;
        super::prime::reread(*self.key.id()).await == super::prime::Primed::Held
    }
    fn landed(&self, digest: &[u8; 32]) -> Option<bool> {
        use dioxus::prelude::ReadableExt;
        super::APP_STATE
            .read()
            .mailbox_holds(self.key.id().as_bytes(), digest)
    }
    fn not_arrived(&self, digest: &[u8; 32], why: crate::state::NotArrived, error: Option<String>) {
        use dioxus::prelude::WritableExt;
        let mut app = super::APP_STATE.write();
        app.mark_not_arrived(&self.store_contract_id, digest, why);
        if let Some(e) = error {
            dioxus::logger::tracing::error!("Failed to send message: {e}");
            app.notifications
                .push(format!("Your message could not be sent: {e}"));
        }
    }
}

/// Write into a mailbox whose key is already known.
///
/// The seller's own replies take this path: the id comes from their
/// delegate's registration rather than from a derivation. They are
/// subscribed to their own mailbox, so the priming every write does is
/// answered from their node's own store. No delivery check: the seller's
/// Inbox shows what is in the mailbox, their own replies included.
#[cfg(target_arch = "wasm32")]
pub async fn reply_to_mailbox(
    mailbox_instance_id: &[u8],
    message: EncryptedMessage,
) -> Result<(), String> {
    write_to_mailbox(&mailbox_key_from_id(mailbox_instance_id)?, message).await
}

/// The one place a message becomes a contract update.
#[cfg(target_arch = "wasm32")]
async fn write_to_mailbox(key: &ContractKey, message: EncryptedMessage) -> Result<(), String> {
    use freenet_stdlib::prelude::{StateDelta, UpdateData};

    let delta = mailbox_delta_bytes(vec![message])?;
    super::update_contract(key, UpdateData::Delta(StateDelta::from(delta))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_stdlib::prelude::{Parameters, WrappedContract};
    use std::sync::Arc;

    fn seller() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[9u8; 32]).verifying_key()
    }

    /// The derived key must be the key the NODE computes for the same
    /// contract and parameters.
    ///
    /// The comparison is against `freenet-stdlib`'s own `WrappedContract`,
    /// which is what decides the address on the network -- not against a
    /// second hand-rolled derivation, which would only prove this file agrees
    /// with itself. Same argument as `migrate`'s re-export of
    /// `predecessor_ids`.
    ///
    /// Observed red on 2026-09-05 by hashing `STORE_CONTRACT_WASM` instead.
    #[test]
    fn the_derived_mailbox_key_is_the_one_the_node_computes() {
        let vk = seller();
        let params: Parameters<'static> =
            crate::migrate::encode_params(&crate::migrate::mailbox_params(&vk))
                .expect("encode mailbox parameters");
        let expected = *WrappedContract::new(
            Arc::new(ContractCode::from(MAILBOX_CONTRACT_WASM.to_vec())),
            params,
        )
        .key();

        let derived = mailbox_contract_key(&vk).expect("derive");
        assert_eq!(
            derived.id(),
            expected.id(),
            "the buyer would address a contract the seller never published"
        );
        // Separately, for the reason spelled out on
        // `the_two_ways_to_address_a_mailbox_agree`: `ContractKey`'s
        // `PartialEq` ignores the code hash, so `assert_eq!` on the keys
        // alone would not notice a wrong one.
        assert_eq!(derived.code_hash(), expected.code_hash());
    }

    /// The two ways to reach a mailbox must agree.
    ///
    /// A buyer derives the key from the seller's verifying key; the seller
    /// rebuilds it from the instance id their delegate recorded. If those
    /// disagreed, a seller would reply into a contract the buyer never reads
    /// -- and both sides would report success.
    ///
    /// **The code hash is compared explicitly, and that is not pedantry.**
    /// `ContractKey`'s `PartialEq` compares the instance id only, so
    /// `assert_eq!(derived, from_id)` on its own passes even when the two
    /// carry different code hashes -- which was checked rather than assumed:
    /// the first version of this test was written that way and survived the
    /// mutation below unchanged.
    ///
    /// Observed red on 2026-09-05 by hashing `STORE_CONTRACT_WASM` in
    /// `mailbox_key_from_id`, but only once the code-hash assertion was
    /// added.
    #[test]
    fn the_two_ways_to_address_a_mailbox_agree() {
        let derived = mailbox_contract_key(&seller()).expect("derive");
        let from_id = mailbox_key_from_id(derived.id().as_bytes()).expect("rebuild");

        assert_eq!(derived.id(), from_id.id(), "different instance");
        assert_eq!(
            derived.code_hash(),
            from_id.code_hash(),
            "same instance, different code hash -- the seller would reply into a contract \
             addressed by a hash the buyer is not reading"
        );
    }

    /// Two sellers do not share a mailbox, so the test above is not passing
    /// because the derivation ignores its argument.
    #[test]
    fn two_sellers_have_different_mailboxes() {
        let one = mailbox_contract_key(&seller()).expect("derive");
        let two = mailbox_contract_key(&SigningKey::from_bytes(&[10u8; 32]).verifying_key())
            .expect("derive");
        assert_ne!(one, two);
    }

    use crate::state::NotArrived;

    /// One `not_arrived` report: digest, reason, node error.
    type Report = ([u8; 32], NotArrived, Option<String>);

    /// A mailbox that takes (or refuses) writes, and answers re-reads, as
    /// the test says.
    struct FakeMailbox {
        /// Digest of every message handed to the node, in order.
        writes: std::cell::RefCell<Vec<[u8; 32]>>,
        /// The write (1-based) after which the message is in the mailbox, if
        /// any.
        lands_after: Option<usize>,
        write_fails: bool,
        /// Whether the node answers re-reads.
        answers: bool,
        /// Whether this tab can see the mailbox's state at all.
        routed: bool,
        not_arrived: std::cell::RefCell<Vec<Report>>,
    }

    impl FakeMailbox {
        fn new(lands_after: Option<usize>) -> Self {
            Self {
                writes: Default::default(),
                lands_after,
                write_fails: false,
                answers: true,
                routed: true,
                not_arrived: Default::default(),
            }
        }
    }

    impl Delivery for FakeMailbox {
        async fn write(&self, message: &EncryptedMessage) -> Result<(), String> {
            self.writes
                .borrow_mut()
                .push(harvest_common::mailbox::entry_digest(message));
            if self.write_fails {
                Err("not connected to gateway".into())
            } else {
                Ok(())
            }
        }
        async fn wait_and_reread(&self) -> bool {
            self.answers
        }
        fn landed(&self, _digest: &[u8; 32]) -> Option<bool> {
            self.routed.then(|| {
                self.lands_after
                    .is_some_and(|n| self.writes.borrow().len() >= n)
            })
        }
        fn not_arrived(&self, digest: &[u8; 32], why: NotArrived, error: Option<String>) {
            self.not_arrived.borrow_mut().push((*digest, why, error));
        }
    }

    fn a_message() -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: harvest_common::mailbox::ConversationId([4u8; 32]),
            sender_public_key: vec![5u8; 32],
            ciphertext: vec![6u8; 48],
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            nonce: [7u8; 24],
        }
    }

    /// **harvest#119, the part priming cannot cover.** A write the node
    /// bounced is re-sent -- the identical bytes, once, automatically -- and
    /// if the message is still missing the buyer is told rather than left
    /// believing it arrived.
    #[test]
    fn a_message_that_never_lands_is_resent_once_then_reported() {
        let message = a_message();
        let digest = harvest_common::mailbox::entry_digest(&message);
        let mailbox = FakeMailbox::new(None);
        futures::executor::block_on(deliver(&mailbox, message));

        assert_eq!(
            *mailbox.writes.borrow(),
            vec![digest; 1 + AUTOMATIC_RESENDS as usize],
            "every attempt must hand the node the SAME bytes, and stop"
        );
        assert_eq!(
            *mailbox.not_arrived.borrow(),
            vec![(digest, NotArrived::NotInMailbox, None)]
        );
    }

    /// The resend is what rescues a first write the node bounced.
    #[test]
    fn a_message_that_lands_on_the_resend_is_not_reported() {
        let mailbox = FakeMailbox::new(Some(2));
        futures::executor::block_on(deliver(&mailbox, a_message()));
        assert_eq!(mailbox.writes.borrow().len(), 2);
        assert!(mailbox.not_arrived.borrow().is_empty());
    }

    /// A message that landed is not sent again.
    #[test]
    fn a_message_that_lands_first_time_is_sent_once() {
        let mailbox = FakeMailbox::new(Some(1));
        futures::executor::block_on(deliver(&mailbox, a_message()));
        assert_eq!(mailbox.writes.borrow().len(), 1);
        assert!(mailbox.not_arrived.borrow().is_empty());
    }

    /// A node that cannot be reached is reported at once, AS unreachable and
    /// with the reason, and not retried into the same failure.
    #[test]
    fn a_write_that_cannot_reach_the_node_is_reported_as_such() {
        let mut mailbox = FakeMailbox::new(None);
        mailbox.write_fails = true;
        futures::executor::block_on(deliver(&mailbox, a_message()));
        assert_eq!(mailbox.writes.borrow().len(), 1);
        let reported = mailbox.not_arrived.borrow();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].1, NotArrived::NeverReachedNode);
        assert_eq!(reported[0].2.as_deref(), Some("not connected to gateway"));
    }

    /// **A read the node never answered is not evidence** (review of
    /// harvest#126, Codex). A stale copy predates the write, so the buyer
    /// must not be told the seller lacks the message on the strength of it.
    /// The resend still happens: identical bytes cannot land twice.
    #[test]
    fn an_unanswered_reread_never_reports_the_message_missing() {
        let message = a_message();
        let digest = harvest_common::mailbox::entry_digest(&message);
        let mut mailbox = FakeMailbox::new(None);
        mailbox.answers = false;
        futures::executor::block_on(deliver(&mailbox, message));
        assert_eq!(
            mailbox.writes.borrow().len(),
            1 + AUTOMATIC_RESENDS as usize
        );
        assert_eq!(
            *mailbox.not_arrived.borrow(),
            vec![(digest, NotArrived::Unconfirmed, None)],
            "told the buyer the seller lacks it without a fresh read, or left them with \
             nothing to act on"
        );
    }

    /// Nor is a mailbox whose state this tab does not route anywhere.
    #[test]
    fn a_mailbox_this_tab_cannot_see_never_reports_the_message_missing() {
        let mut mailbox = FakeMailbox::new(None);
        mailbox.routed = false;
        futures::executor::block_on(deliver(&mailbox, a_message()));
        let reported = mailbox.not_arrived.borrow();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].1, NotArrived::Unconfirmed);
    }

    /// **A resend that cannot reach the node is not "never sent"** (round 2
    /// of the harvest#126 review). The first copy did reach it and may have
    /// landed; the socket dropping during the wait says nothing about that.
    #[test]
    fn a_resend_that_cannot_reach_the_node_claims_nothing_about_the_first_copy() {
        struct DropsAfterFirst(FakeMailbox);
        impl Delivery for DropsAfterFirst {
            async fn write(&self, message: &EncryptedMessage) -> Result<(), String> {
                let first = self.0.writes.borrow().is_empty();
                self.0
                    .writes
                    .borrow_mut()
                    .push(harvest_common::mailbox::entry_digest(message));
                if first {
                    Ok(())
                } else {
                    Err("not connected to gateway".into())
                }
            }
            async fn wait_and_reread(&self) -> bool {
                false
            }
            fn landed(&self, digest: &[u8; 32]) -> Option<bool> {
                self.0.landed(digest)
            }
            fn not_arrived(&self, digest: &[u8; 32], why: NotArrived, error: Option<String>) {
                self.0.not_arrived(digest, why, error)
            }
        }
        let mailbox = DropsAfterFirst(FakeMailbox::new(None));
        futures::executor::block_on(deliver(&mailbox, a_message()));
        assert_eq!(mailbox.0.writes.borrow().len(), 2);
        let reported = mailbox.0.not_arrived.borrow();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].1, NotArrived::Unconfirmed);
    }

    /// A message seen in the mailbox has landed even when the read that
    /// showed it was not fresh.
    #[test]
    fn a_message_seen_in_a_stale_read_has_still_landed() {
        let mut mailbox = FakeMailbox::new(Some(1));
        mailbox.answers = false;
        futures::executor::block_on(deliver(&mailbox, a_message()));
        assert_eq!(mailbox.writes.borrow().len(), 1);
        assert!(mailbox.not_arrived.borrow().is_empty());
    }

    /// The delta a buyer sends has to be the shape the mailbox contract
    /// decodes, and the contract is the only thing that would otherwise say
    /// so -- at which point the message is already lost with an error that
    /// does not name the cause.
    ///
    /// Checked by round-tripping through the exact types
    /// `contracts/mailbox-contract` uses: `MailboxDelta` for the decode, then
    /// `MailboxStateV1::apply_delta` for the merge.
    ///
    /// Observed red on 2026-09-05 by wrapping the messages in a
    /// `StoreStateV1Delta`-style map, which is the mistake the store
    /// contract's own delta helpers exist to prevent.
    #[test]
    fn the_delta_is_the_shape_the_mailbox_contract_decodes() {
        use harvest_common::mailbox::{ConversationId, MailboxDelta, MailboxStateV1};

        let message = EncryptedMessage {
            conversation_id: ConversationId([4u8; 32]),
            sender_public_key: vec![5u8; 32],
            ciphertext: vec![6u8; 48],
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            nonce: [7u8; 24],
        };

        let bytes = mailbox_delta_bytes(vec![message.clone()]).expect("serialize");
        let decoded: MailboxDelta = harvest_common::from_cbor(&bytes)
            .expect("the mailbox contract decodes the delta as a MailboxDelta");

        let mut state = MailboxStateV1::default();
        state
            .apply_delta(&Some(decoded))
            .expect("the contract merges it");

        assert_eq!(state.messages, vec![message]);
    }
}
