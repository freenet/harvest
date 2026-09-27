//! A buyer's messages to a seller, and the Ghost Key voucher they carry.
//!
//! # The rule
//!
//! Buyer-to-seller messages require a Ghost Key (anti-spam). Buying itself
//! does not (Ian, settled). A Ghost Key is minted by donating to Freenet, so
//! it is scarce, and a seller's inbox that shows only text a Ghost Key vouches
//! for costs a spammer one donation per key rather than nothing.
//!
//! # Why both sides
//!
//! The mailbox is open-write, so the compose gate below stops only a buyer
//! using this UI. The seller's side is what enforces the rule:
//! `components::message_view::shown_to_seller` leaves out buyer text that
//! carries no voucher verifying for the conversation it arrived in.
//!
//! # The voucher is per conversation
//!
//! The Ghost Key signs `harvest_common::sealed::voucher_terms(tag)`, the
//! conversation's routing tag under a domain, through the vault's
//! `SignMessage` -- one prompt per conversation, not per message. The result
//! is cached here by (store, tag), and attached to every text in that
//! conversation, so each message is self-contained: a seller verifies any one
//! of them without needing another that may have been pruned.
//!
//! Texts typed before the signature comes back wait here in order, and are
//! sealed and sent in that order once it does. A refusal or a vault that does
//! not answer hands them back to the buyer with the reason, unsent.

use std::collections::HashMap;

use harvest_common::mailbox::EncryptedMessage;
use harvest_common::sealed::MessageVoucher;

use crate::state::{AppState, PendingSignature};

/// What a buyer with no Ghost Key connected is told in place of the compose
/// box.
pub const NEEDS_GHOST_KEY: &str = "Messages to sellers need a Ghost Key. It keeps sellers' \
     inboxes free of spam. You don't need one to buy.";

/// How long a voucher request waits on the vault before its messages are
/// handed back. Long, because the vault may be showing the buyer a permission
/// prompt.
pub const MESSAGE_VOUCHER_TIMEOUT_MS: u32 = 120_000;

/// A voucher asked of the vault and not yet answered.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingMessageVoucher {
    /// The Ghost Key asked.
    pub fingerprint: String,
    pub store_contract_id: Vec<u8>,
    /// The conversation's routing tag, which is what gets signed.
    pub tag: [u8; 32],
    /// When it was asked, so a timeout for an earlier request cannot end a
    /// later one for the same conversation.
    pub queued_at_ms: u64,
}

/// A text the buyer sent, waiting on its conversation's voucher.
#[derive(Clone, Debug, PartialEq)]
pub struct TextAwaitingVoucher {
    pub store_contract_id: Vec<u8>,
    pub tag: [u8; 32],
    pub seller_encryption_key: [u8; 32],
    pub seller_verifying_key: [u8; 32],
    pub text: String,
}

/// Texts handed back unsent, and why.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct VoucherFailure {
    pub why: String,
    pub texts: Vec<String>,
}

/// A buyer's voucher state, in `AppState::vouchers`.
#[derive(Clone, Debug, Default)]
pub struct VoucherState {
    /// Vouchers the vault has signed, by (store contract id, tag). Per tab:
    /// after a reload the first text in a conversation asks again.
    pub signed: HashMap<(Vec<u8>, [u8; 32]), MessageVoucher>,
    /// Texts waiting on a voucher, oldest first.
    pub awaiting: Vec<TextAwaitingVoucher>,
    /// By store: what was handed back unsent, until the buyer sends again.
    pub failures: HashMap<Vec<u8>, VoucherFailure>,
}

/// Whether the compose box can be offered at all.
#[derive(Clone, Debug, PartialEq)]
pub enum ComposeGate {
    /// No Ghost Key is connected: show [`NEEDS_GHOST_KEY`] instead.
    NeedsGhostKey,
    /// Messages will be vouched for by this Ghost Key.
    Ready { fingerprint: String },
}

/// The gate for a buyer holding `ghostkeys`. The first connected key vouches.
pub fn compose_gate(ghostkeys: &[ghostkey_common::GhostKeyInfo]) -> ComposeGate {
    match ghostkeys.first() {
        None => ComposeGate::NeedsGhostKey,
        Some(key) => ComposeGate::Ready {
            fingerprint: key.fingerprint.clone(),
        },
    }
}

/// What composing did.
#[derive(Clone, Debug, PartialEq)]
pub enum VouchedCompose {
    /// Sealed under a voucher already held; the caller delivers it.
    Sealed(EncryptedMessage),
    /// Waiting on the voucher. `Some` when this text started the request,
    /// which the caller must send to the vault; `None` when one was already
    /// on its way.
    AwaitingSignature(Option<PendingMessageVoucher>),
}

/// A text sealed once its voucher arrived, for delivery.
#[derive(Clone, Debug, PartialEq)]
pub struct VouchedDelivery {
    pub store_contract_id: Vec<u8>,
    pub seller_verifying_key: [u8; 32],
    pub text: String,
    pub sealed: EncryptedMessage,
}

impl AppState {
    /// [`compose_gate`] over the connected Ghost Keys.
    pub fn compose_gate(&self) -> ComposeGate {
        compose_gate(&self.ghostkeys)
    }

    /// Seal a buyer's text to a store under its conversation's voucher, or
    /// queue it behind the voucher's signature.
    ///
    /// Continues the store's last conversation, opening one if there is none,
    /// as every buyer message does.
    pub fn compose_vouched_to_seller(
        &mut self,
        store_contract_id: &[u8],
        seller_encryption_key: &[u8; 32],
        seller_verifying_key: &[u8; 32],
        text: String,
        now_ms: u64,
    ) -> Result<VouchedCompose, String> {
        let ComposeGate::Ready { fingerprint } = self.compose_gate() else {
            return Err(NEEDS_GHOST_KEY.to_string());
        };
        let conversation = self.conversation_with(store_contract_id, seller_encryption_key)?;
        // Refused now rather than after the vault has been asked: the voucher
        // adds about 2 KB, so a text near the limit fits alone and not with it.
        conversation.seal_vouched(text.clone(), oversize_probe(), chrono::Utc::now())?;
        let tag = conversation.buyer_public_key;
        self.vouchers.failures.remove(store_contract_id);

        let key = (store_contract_id.to_vec(), tag);
        if let Some(voucher) = self.vouchers.signed.get(&key).cloned() {
            let sealed = self
                .conversation_with(store_contract_id, seller_encryption_key)?
                .seal_vouched(text, voucher, chrono::Utc::now())?;
            self.keep_this_conversation(store_contract_id, seller_encryption_key);
            return Ok(VouchedCompose::Sealed(sealed));
        }

        self.vouchers.awaiting.push(TextAwaitingVoucher {
            store_contract_id: store_contract_id.to_vec(),
            tag,
            seller_encryption_key: *seller_encryption_key,
            seller_verifying_key: *seller_verifying_key,
            text,
        });
        if self.voucher_requested(store_contract_id, &tag) {
            return Ok(VouchedCompose::AwaitingSignature(None));
        }
        let pending = PendingMessageVoucher {
            fingerprint,
            store_contract_id: store_contract_id.to_vec(),
            tag,
            queued_at_ms: now_ms,
        };
        self.pending_signatures
            .push_back(PendingSignature::MessageVoucher(Box::new(pending.clone())));
        Ok(VouchedCompose::AwaitingSignature(Some(pending)))
    }

    /// Whether a voucher for this conversation is waiting on the vault.
    fn voucher_requested(&self, store_contract_id: &[u8], tag: &[u8; 32]) -> bool {
        self.pending_signatures.iter().any(|pending| {
            matches!(pending, PendingSignature::MessageVoucher(voucher)
                if voucher.store_contract_id == store_contract_id && voucher.tag == *tag)
        })
    }

    /// The vault signed a voucher: keep it, and seal every text waiting on
    /// it, in the order typed. Returns what to deliver.
    ///
    /// The voucher is checked as the seller will check it before anything is
    /// sealed under it. One the seller would refuse (a Ghost Key whose
    /// certificate does not chain to Freenet's master key, say) would have
    /// every message silently hidden from them, so the buyer is told instead.
    pub(crate) fn on_message_voucher_signed(
        &mut self,
        pending: PendingMessageVoucher,
        voucher: MessageVoucher,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<VouchedDelivery> {
        let store = pending.store_contract_id.clone();
        let tag = pending.tag;
        // Already taken off the queue when this arrived as the vault's answer;
        // done here too so no path can leave the request outstanding.
        self.pending_signatures.retain(|queued| {
            !matches!(queued, PendingSignature::MessageVoucher(voucher)
                if voucher.store_contract_id == store && voucher.tag == tag)
        });
        if let Err(e) =
            crate::ghostkey_cert::verify_voucher_under(&voucher, &tag, &self.voucher_master())
        {
            self.message_voucher_failed(
                &store,
                &tag,
                &format!("your Ghost Key's signature would not be accepted by the seller ({e})"),
            );
            return Vec::new();
        }
        self.vouchers
            .signed
            .insert((store.clone(), tag), voucher.clone());

        let (waiting, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.vouchers.awaiting)
            .into_iter()
            .partition(|text| text.store_contract_id == store && text.tag == tag);
        self.vouchers.awaiting = rest;

        let mut ready = Vec::new();
        let mut unsent = Vec::new();
        let mut why = String::new();
        let mut keep = None;
        for (i, text) in waiting.into_iter().enumerate() {
            // A millisecond apart, so the thread (sorted by timestamp) shows
            // them in the order they were typed.
            let at = now + chrono::Duration::milliseconds(i as i64);
            let conversation = self
                .browsing_stores
                .get(&store)
                .and_then(|s| s.conversations.iter().find(|c| c.buyer_public_key == tag));
            let sealed = match conversation {
                Some(conversation) => {
                    conversation.seal_vouched(text.text.clone(), voucher.clone(), at)
                }
                None => Err("the conversation was forgotten before it could be sent".to_string()),
            };
            match sealed {
                Ok(sealed) => {
                    keep = Some(text.seller_encryption_key);
                    ready.push(VouchedDelivery {
                        store_contract_id: store.clone(),
                        seller_verifying_key: text.seller_verifying_key,
                        text: text.text,
                        sealed,
                    });
                }
                Err(e) => {
                    why = e;
                    unsent.push(text.text);
                }
            }
        }
        if let Some(seller_encryption_key) = keep {
            self.keep_this_conversation(&store, &seller_encryption_key);
        }
        if !unsent.is_empty() {
            self.vouchers
                .failures
                .insert(store, VoucherFailure { why, texts: unsent });
        }
        ready
    }

    /// The voucher for this conversation will not come: withdraw its request
    /// and hand its waiting texts back to the buyer, with `why`.
    pub(crate) fn message_voucher_failed(
        &mut self,
        store_contract_id: &[u8],
        tag: &[u8; 32],
        why: &str,
    ) {
        self.pending_signatures.retain(|pending| {
            !matches!(pending, PendingSignature::MessageVoucher(voucher)
                if voucher.store_contract_id == store_contract_id && voucher.tag == *tag)
        });
        let (unsent, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.vouchers.awaiting)
            .into_iter()
            .partition(|text| text.store_contract_id == store_contract_id && text.tag == *tag);
        self.vouchers.awaiting = rest;
        if unsent.is_empty() {
            return;
        }
        let failure = self
            .vouchers
            .failures
            .entry(store_contract_id.to_vec())
            .or_default();
        failure.why = why.to_string();
        failure
            .texts
            .extend(unsent.into_iter().map(|text| text.text));
    }

    /// The vault has not answered the request asked at `queued_at_ms`. A
    /// later request for the same conversation is left alone.
    pub(crate) fn message_voucher_timed_out(
        &mut self,
        store_contract_id: &[u8],
        tag: &[u8; 32],
        queued_at_ms: u64,
    ) {
        let still_waiting = self.pending_signatures.iter().any(|pending| {
            matches!(pending, PendingSignature::MessageVoucher(voucher)
                if voucher.store_contract_id == store_contract_id
                    && voucher.tag == *tag
                    && voucher.queued_at_ms == queued_at_ms)
        });
        if still_waiting {
            self.message_voucher_failed(
                store_contract_id,
                tag,
                "your Ghost Key vault did not answer",
            );
        }
    }

    /// The texts to this store waiting on a voucher, oldest first.
    pub fn texts_awaiting_voucher(&self, store_contract_id: &[u8]) -> Vec<String> {
        self.vouchers
            .awaiting
            .iter()
            .filter(|text| text.store_contract_id == store_contract_id)
            .map(|text| text.text.clone())
            .collect()
    }

    /// What was handed back unsent for this store, if anything.
    pub fn voucher_failure(&self, store_contract_id: &[u8]) -> Option<&VoucherFailure> {
        self.vouchers.failures.get(store_contract_id)
    }

    /// Whether `voucher` vouches for the conversation `tag`, remembered: the
    /// seller's inbox asks on every render.
    pub fn voucher_verifies(&self, voucher: &MessageVoucher, tag: &[u8; 32]) -> bool {
        let key = crate::ghostkey_cert::voucher_verdict_key(voucher, tag);
        if let Some(verdict) = self.voucher_verdicts.borrow().get(&key) {
            return *verdict;
        }
        let verdict =
            crate::ghostkey_cert::verify_voucher_under(voucher, tag, &self.voucher_master())
                .is_ok();
        let mut verdicts = self.voucher_verdicts.borrow_mut();
        // A mailbox holds at most `MAX_MESSAGES` entries, so this is far past
        // honest use; it bounds a session watching a mailbox churn.
        if verdicts.len() >= 4096 {
            verdicts.clear();
        }
        verdicts.insert(key, verdict);
        verdict
    }

    /// Freenet's master key (`None`), except where a test supplies its own.
    fn voucher_master(&self) -> Option<ed25519_dalek::VerifyingKey> {
        #[cfg(test)]
        {
            self.voucher_master_for_tests
        }
        #[cfg(not(test))]
        {
            None
        }
    }
}

/// A voucher of the largest size a real one comes to, for checking a text
/// fits before the vault is asked. A certificate is about 1.6 KB of PEM.
fn oversize_probe() -> MessageVoucher {
    MessageVoucher {
        certificate_pem: "x".repeat(2048),
        scoped_payload: vec![0; 256],
        signature: vec![0; 64],
    }
}

/// Hand texts sealed under a fresh voucher to the node.
///
/// Spawned, because this is reached from the vault's answer while the app
/// state is held for writing, and delivering writes it again.
pub(crate) fn deliver_vouched(ready: Vec<VouchedDelivery>) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::WritableExt;
        for delivery in ready {
            let result = ed25519_dalek::VerifyingKey::from_bytes(&delivery.seller_verifying_key)
                .map_err(|e| format!("this store's identity key is unusable: {e}"))
                .and_then(|seller| {
                    crate::components::message_view::deliver_to_seller(
                        &delivery.store_contract_id,
                        seller,
                        delivery.text,
                        delivery.sealed,
                    )
                });
            if let Err(e) = result {
                crate::gateway::APP_STATE
                    .write()
                    .notifications
                    .push(format!("Your message could not be sent: {e}"));
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = ready;
}

/// Ask the vault to sign a conversation's voucher, queued by
/// [`AppState::compose_vouched_to_seller`], and give up on it after
/// [`MESSAGE_VOUCHER_TIMEOUT_MS`].
#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn_message_voucher_signature(pending: PendingMessageVoucher) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};

        let fail = |reason: String| {
            dioxus::logger::tracing::warn!("message voucher not requested: {reason}");
            crate::gateway::APP_STATE.write().message_voucher_failed(
                &pending.store_contract_id,
                &pending.tag,
                &reason,
            );
        };
        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            fail("the Ghost Key vault is not connected yet".to_string());
            return;
        };
        let message = match harvest_common::sealed::voucher_message(&pending.tag) {
            Ok(message) => message,
            Err(e) => {
                fail(format!("could not prepare it for signing: {e}"));
                return;
            }
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint: pending.fingerprint.clone(),
            message,
        };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                fail(format!("could not prepare it for signing: {e}"));
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            fail(format!("it could not be sent to your Ghost Key vault: {e}"));
            return;
        }
        gloo_timers::future::TimeoutFuture::new(MESSAGE_VOUCHER_TIMEOUT_MS).await;
        crate::gateway::APP_STATE.write().message_voucher_timed_out(
            &pending.store_contract_id,
            &pending.tag,
            pending.queued_at_ms,
        );
    });
}

/// Off the browser there is no vault to ask.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn spawn_message_voucher_signature(_pending: PendingMessageVoucher) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::message_view::shown_to_seller;
    use crate::ghostkey_cert::tests::{test_master, vouch};
    use crate::messaging::{ConversationKeys, MailboxEntry, MessageContent};
    use x25519_dalek::{PublicKey, StaticSecret};

    const STORE: &[u8] = &[1u8; 32];
    const SELLER_VK: [u8; 32] = [2u8; 32];

    fn ghostkey(fingerprint: &str) -> ghostkey_common::GhostKeyInfo {
        ghostkey_common::GhostKeyInfo {
            fingerprint: fingerprint.into(),
            label: None,
            notary_info: String::new(),
            verifying_key_bytes: None,
            backed_up: false,
        }
    }

    fn seller_secret() -> StaticSecret {
        StaticSecret::from([21u8; 32])
    }

    fn seller_public() -> [u8; 32] {
        *PublicKey::from(&seller_secret()).as_bytes()
    }

    /// A buyer with a Ghost Key connected, whose vouchers are checked against
    /// the test authority.
    fn buyer() -> AppState {
        let mut state = AppState {
            ghostkeys: vec![ghostkey("buyer-fp")],
            voucher_master_for_tests: test_master(),
            ..Default::default()
        };
        state.browsing_stores.entry(STORE.to_vec()).or_default();
        state
    }

    fn compose(state: &mut AppState, text: &str) -> VouchedCompose {
        state
            .compose_vouched_to_seller(STORE, &seller_public(), &SELLER_VK, text.into(), 1_000)
            .expect("compose")
    }

    fn pending_vouchers(state: &AppState) -> Vec<PendingMessageVoucher> {
        state
            .pending_signatures
            .iter()
            .filter_map(|p| match p {
                PendingSignature::MessageVoucher(v) => Some((**v).clone()),
                _ => None,
            })
            .collect()
    }

    /// The seller's inbox over `messages`, as the seller is shown it.
    fn seller_sees(messages: &[EncryptedMessage]) -> (Vec<MailboxEntry>, usize) {
        let mut keys = HashMap::new();
        for m in messages {
            let tag: [u8; 32] = m.sender_public_key.as_slice().try_into().unwrap();
            let shared = seller_secret()
                .diffie_hellman(&PublicKey::from(tag))
                .to_bytes();
            keys.insert(tag.to_vec(), ConversationKeys::from_shared_secret(&shared));
        }
        shown_to_seller(crate::messaging::read_mailbox(messages, &keys), |v, t| {
            crate::ghostkey_cert::verify_voucher_under(v, t, &test_master()).is_ok()
        })
    }

    #[test]
    fn with_no_ghost_key_the_compose_box_is_a_gate() {
        assert_eq!(compose_gate(&[]), ComposeGate::NeedsGhostKey);
        let mut state = AppState::default();
        state.browsing_stores.entry(STORE.to_vec()).or_default();
        assert_eq!(state.compose_gate(), ComposeGate::NeedsGhostKey);
        assert_eq!(
            state.compose_vouched_to_seller(STORE, &seller_public(), &SELLER_VK, "hi".into(), 0),
            Err(NEEDS_GHOST_KEY.to_string())
        );
        assert!(state.pending_signatures.is_empty());
        assert!(
            state.browsing_stores[STORE].conversations.is_empty(),
            "a refused message opens no conversation"
        );
    }

    #[test]
    fn the_first_connected_ghost_key_vouches() {
        assert_eq!(
            compose_gate(&[ghostkey("a"), ghostkey("b")]),
            ComposeGate::Ready {
                fingerprint: "a".into()
            }
        );
    }

    /// Texts typed while the vault is signing wait, one request is made for
    /// all of them, and they go out in the order typed, each carrying the
    /// voucher -- and the seller is shown every one.
    #[test]
    fn queued_texts_are_sent_in_order_once_the_voucher_is_signed() {
        let mut state = buyer();
        let first = compose(&mut state, "one");
        let VouchedCompose::AwaitingSignature(Some(pending)) = first else {
            panic!("the first text asks for the voucher: {first:?}");
        };
        assert_eq!(pending.fingerprint, "buyer-fp");
        assert_eq!(
            compose(&mut state, "two"),
            VouchedCompose::AwaitingSignature(None)
        );
        assert_eq!(
            compose(&mut state, "three"),
            VouchedCompose::AwaitingSignature(None)
        );
        assert_eq!(
            pending_vouchers(&state),
            vec![pending.clone()],
            "asked once"
        );
        assert_eq!(state.texts_awaiting_voucher(STORE), ["one", "two", "three"]);

        let (voucher, _, _) = vouch(&pending.tag);
        let ready =
            state.on_message_voucher_signed(pending.clone(), voucher.clone(), chrono::Utc::now());
        assert_eq!(
            ready.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
            ["one", "two", "three"]
        );
        assert!(
            ready
                .windows(2)
                .all(|w| w[0].sealed.timestamp < w[1].sealed.timestamp),
            "stamped in the order typed, so the thread shows them that way"
        );
        assert!(state.texts_awaiting_voucher(STORE).is_empty());

        let sealed: Vec<EncryptedMessage> = ready.iter().map(|r| r.sealed.clone()).collect();
        let (shown, hidden) = seller_sees(&sealed);
        assert_eq!((shown.len(), hidden), (3, 0));
        assert!(shown.iter().all(|entry| matches!(
            entry,
            MailboxEntry::Readable { content: MessageContent::VouchedText { voucher: v, .. }, .. }
                if *v == voucher
        )));

        // A later text reuses the voucher: no second prompt.
        let VouchedCompose::Sealed(later) = compose(&mut state, "four") else {
            panic!("the voucher is held, so this seals at once");
        };
        assert!(pending_vouchers(&state).is_empty());
        assert_eq!(seller_sees(&[later]).1, 0);
    }

    /// The vault's own answer settles the request through the ordinary
    /// signature path and keeps the voucher for the conversation.
    #[test]
    fn the_vaults_answer_settles_the_voucher_request() {
        let mut state = buyer();
        let VouchedCompose::AwaitingSignature(Some(pending)) = compose(&mut state, "hello") else {
            panic!("asks for the voucher");
        };
        let (voucher, _, _) = vouch(&pending.tag);
        state.on_ghostkey_response(ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: voucher.scoped_payload.clone(),
            signature: voucher.signature.clone(),
            certificate_pem: voucher.certificate_pem.clone(),
        });
        assert!(pending_vouchers(&state).is_empty());
        assert!(state.texts_awaiting_voucher(STORE).is_empty());
        assert_eq!(
            state.vouchers.signed.get(&(STORE.to_vec(), pending.tag)),
            Some(&voucher)
        );
    }

    #[test]
    fn a_refused_voucher_hands_the_texts_back() {
        let mut state = buyer();
        compose(&mut state, "a");
        compose(&mut state, "b");
        state.on_ghostkey_response(ghostkey_common::GhostkeyResponse::Error {
            message: "no".into(),
        });
        assert!(pending_vouchers(&state).is_empty());
        assert!(state.texts_awaiting_voucher(STORE).is_empty());
        let failure = state.voucher_failure(STORE).expect("handed back");
        assert_eq!(failure.texts, ["a", "b"]);
        // Sending again starts over, and clears what was handed back.
        compose(&mut state, "c");
        assert!(state.voucher_failure(STORE).is_none());
        assert_eq!(pending_vouchers(&state).len(), 1);
    }

    /// A vault that never answers hands the texts back; a timer for an
    /// earlier request does not end a later one.
    #[test]
    fn a_timed_out_voucher_hands_the_texts_back_and_a_stale_timer_does_nothing() {
        let mut state = buyer();
        let VouchedCompose::AwaitingSignature(Some(pending)) = compose(&mut state, "a") else {
            panic!("asks for the voucher");
        };
        state.message_voucher_timed_out(STORE, &pending.tag, pending.queued_at_ms + 1);
        assert_eq!(
            pending_vouchers(&state).len(),
            1,
            "not this request's timer"
        );
        state.message_voucher_timed_out(STORE, &pending.tag, pending.queued_at_ms);
        assert!(pending_vouchers(&state).is_empty());
        assert_eq!(state.voucher_failure(STORE).unwrap().texts, ["a"]);
    }

    /// A voucher the seller would refuse is not sent under: the buyer is
    /// told, rather than having every message silently hidden.
    #[test]
    fn a_voucher_the_seller_would_refuse_is_not_used() {
        let mut state = buyer();
        state.voucher_master_for_tests = None; // Freenet's master key
        let VouchedCompose::AwaitingSignature(Some(pending)) = compose(&mut state, "a") else {
            panic!("asks for the voucher");
        };
        let (voucher, _, _) = vouch(&pending.tag);
        assert!(state
            .on_message_voucher_signed(pending, voucher, chrono::Utc::now())
            .is_empty());
        assert!(state.vouchers.signed.is_empty());
        assert_eq!(state.voucher_failure(STORE).unwrap().texts, ["a"]);
    }

    /// A text too long to carry a voucher is refused before the vault is
    /// asked, not after.
    #[test]
    fn a_text_too_long_for_a_voucher_is_refused_up_front() {
        let mut state = buyer();
        let long = "x".repeat(harvest_common::mailbox::LARGEST_BUCKET - 1000);
        assert!(state
            .compose_vouched_to_seller(STORE, &seller_public(), &SELLER_VK, long, 0)
            .is_err());
        assert!(pending_vouchers(&state).is_empty());
        assert!(state.texts_awaiting_voucher(STORE).is_empty());
    }

    /// The seller's verdicts are remembered per (voucher, conversation), and
    /// a voucher for one conversation is not remembered as good for another.
    #[test]
    fn voucher_verdicts_are_remembered_per_conversation() {
        let mut state = AppState {
            voucher_master_for_tests: test_master(),
            ..Default::default()
        };
        let tag = [5u8; 32];
        let (voucher, _, _) = vouch(&tag);
        assert!(state.voucher_verifies(&voucher, &tag));
        assert!(!state.voucher_verifies(&voucher, &[6u8; 32]));
        // Answered from memory: under Freenet's own key it would not verify.
        state.voucher_master_for_tests = None;
        assert!(state.voucher_verifies(&voucher, &tag));
        assert_eq!(state.voucher_verdicts.borrow().len(), 2);
    }
}
