//! Buyer-to-seller messaging: a buyer's conversation with a store, on its own
//! page (`buyer_conversation`), and the seller's side, one conversation per
//! page (`seller_pages`), both read from here ([`seller_inbox`],
//! [`SellerConversation`], [`Compose`]).
//!
//! # What messaging may and may not claim
//!
//! An earlier version told the buyer "Messages are end-to-end encrypted. The
//! seller cannot see who you are unless you choose to share identifying
//! information", offered a textarea and a Send button, and then -- on submit
//! -- logged a line and pushed a notification. Nothing was encrypted and
//! nothing was sent. The version after that removed the claim and disabled
//! the box, because the seller published no key to encrypt to.
//!
//! A seller now publishes one ([`harvest_common::store::StoreInfoV1::
//! encryption_public_key`]) and the box works. The claims below are therefore
//! re-enabled -- but only the ones that are true, and each is stated at the
//! strength it actually holds:
//!
//! * **Encrypted to the seller.** True. The message is sealed to the key
//!   published in the store's signed details, and the matching secret never
//!   leaves the seller's delegate.
//! * **Not anonymous against a network observer.** Writing to a mailbox
//!   contract is a contract update, and the mailbox's address is derived from
//!   the seller's identity. Anybody watching knows this node wrote to this
//!   seller. The message CONTENT is hidden; the fact of contact is not.
//! * **Replies work, and survive a reload on THIS device.** The seller
//!   answers into their own mailbox and the buyer reads it out of the same
//!   contract. The key that reads it is kept by this node's harvest delegate,
//!   because the browser has no durable storage at all here -- the gateway's
//!   sandboxed iframe has no `allow-same-origin`, so `localStorage`,
//!   `sessionStorage`, IndexedDB and cookies all throw. It does NOT follow
//!   the buyer to another device, and that has to be on screen BEFORE they
//!   send rather than discovered when they need the answer. See
//!   `docs/buyer-conversation-persistence.md`.
//! * **Handed over, not delivered.** `update_contract` resolves when the
//!   local node has taken the send (after it answered for the mailbox; see
//!   `gateway::prime`). Nothing confirms the contract took it or that the
//!   seller ever looks. The button is an action label and says "Send";
//!   what must not claim delivery is the CONFIRMATION, and a message not yet
//!   seen in the mailbox says "sending" instead. Once the delivery check
//!   gives up (harvest#119) its bubble says which of three things is true --
//!   it never reached the node, fresh reads show it is not in the mailbox,
//!   or Harvest could not confirm either way -- each with a "Send again".
//!
//! None of that is said as a caveat on screen any more (round-6 critique):
//! the one line under the box is "Only {store} can read this."
//!
//! # Why a store can still be unmessageable
//!
//! Two independent reasons, and the notice names whichever applies:
//!
//! 1. The seller published no encryption key -- every store created before
//!    the field existed, and any seller whose delegate has not minted one.
//! 2. The store's ghostkey certificate does not verify against this store, so
//!    [`crate::ghostkey_cert::store_verifying_key`] yields nothing and the
//!    mailbox address cannot be derived. This also covers a store published
//!    by a NEWER build of Harvest, which is indistinguishable here from a
//!    stolen certificate.
use dioxus::prelude::*;

use crate::gateway::APP_STATE;
use crate::messaging::{MailboxEntry, MessageContent};

/// Forget one conversation: the delegate deletes the key that reads it.
/// Two steps, because there is no undo and no second copy anywhere: the
/// messages stay in the seller's mailbox and become unreadable by everyone,
/// including the buyer.
#[component]
pub(crate) fn ForgetConversation(store_contract_id: Vec<u8>, tag: [u8; 32]) -> Element {
    let mut confirming = use_signal(|| false);
    rsx! {
        if confirming() {
            p { class: "text-warning small",
                "Forget this conversation? Your messages and the seller's replies stay in the \
                 seller's mailbox and become unreadable by everyone, including you. This cannot be \
                 undone."
            }
            div { class: "form-actions",
                button {
                    class: "btn btn-sm btn-primary",
                    onclick: move |_| {
                        APP_STATE.write().forget_conversation(&store_contract_id, &tag);
                        confirming.set(false);
                    },
                    "Yes, forget it"
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| confirming.set(false),
                    "Keep it"
                }
            }
        } else {
            button {
                class: "link-btn quiet-link",
                onclick: move |_| confirming.set(true),
                "Forget this conversation"
            }
        }
    }
}

/// Saving ONE conversation, and saying you have.
///
/// # What the string is
///
/// It holds the secret itself -- that is what makes it work on another
/// machine, and what makes it worth exactly as much as the conversation it
/// restores. Anyone who has it can read that conversation and, once a
/// seller's reply carries a pre-signed statement, file the complaint it
/// authorizes as though they were the buyer. That is said beside the string
/// rather than in a tooltip, because it is the whole basis on which a person
/// decides where to put it.
///
/// # Why one conversation at a time
///
/// A store-wide backup is too easy to leave out of date: taken on Monday,
/// silently incomplete on Tuesday, with nothing about the artefact saying
/// which conversations it covered. And a "saved" marker set from a store-wide
/// export would falsely cover a conversation created after it. Per
/// conversation the marker means something checkable: THIS one exists in more
/// than one place.
///
/// # Why "I have saved this" is a separate button
///
/// Showing a backup is not saving one. A buyer who opens the panel, reads the
/// string and closes the tab has saved nothing, so revealing it must not
/// clear the warning -- only the buyer saying they have it does. The delegate
/// gates that marker for the same reason: the party that benefits from the
/// warning stopping is not the party that loses the conversation.
#[component]
pub(crate) fn ConversationBackupControl(store_contract_id: Vec<u8>, tag: [u8; 32]) -> Element {
    // The string, once the delegate has answered, and only for THIS
    // conversation -- one is on screen at a time and it must never appear
    // under another conversation's heading.
    let backup = APP_STATE
        .read()
        .conversation_backup_on_screen
        .as_ref()
        .filter(|backup| {
            backup.store_contract_id == store_contract_id && backup.buyer_public_key == tag
        })
        .map(|backup| backup.text().to_string());

    rsx! {
        if let Some(backup) = backup {
            p { class: "text-warning", style: "font-size: 0.85rem;",
                "Save this somewhere only you can reach. Anyone who has it can read this "
                "conversation, and can use it to complain about this seller as though they "
                "were you. It is not a password you can change: it is the conversation."
            }
            // Also a value to copy rather than a field to edit, and the one
            // here matters most: a mistyped character makes the backup
            // useless, and nothing would say so until it was needed. Shown
            // whole, wrapping, with Copy (Ian, 2026-09-29): the old 3-row
            // box scrolled, so nobody could see all 520 characters at once.
            super::pay_card::CopyField {
                label: "Your backup",
                value: backup.clone(),
                salt: "backup".to_string(),
            }
            button {
                class: "btn btn-primary",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    move |_| {
                        let mut app = APP_STATE.write();
                        app.mark_conversation_backed_up(&store_contract_id, &tag);
                        app.conversation_backup_on_screen = None;
                    }
                },
                "I have saved this"
            }
            button {
                class: "btn btn-outline",
                onclick: move |_| {
                    APP_STATE.write().conversation_backup_on_screen = None;
                },
                "Hide it"
            }
        } else {
            button {
                class: "btn btn-sm btn-outline",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    move |_| APP_STATE.write().export_conversation(&store_contract_id, &tag)
                },
                "Save a backup"
            }
        }
    }
}

/// Putting a saved conversation back.
///
/// Offered even on a device holding nothing: restoring onto a new machine is
/// the case the whole mechanism exists for, and there is nothing kept there
/// to hang the control off. One string covers one conversation, so a buyer
/// restoring a machine pastes several in a row.
#[component]
pub(crate) fn Restore() -> Element {
    let mut paste = use_signal(String::new);

    rsx! {
        div {
            p { class: "text-muted small",
                "A backup is one line of text holding one store\u{2019}s conversation and its orders. \
                 Paste it here to see them on this device; paste them one after another if you \
                 saved several."
            }
            div { class: "form-group",
                textarea {
                    class: "form-textarea",
                    rows: 3,
                    placeholder: "Paste a Harvest backup here.",
                    value: "{paste}",
                    oninput: move |event| paste.set(event.value()),
                }
            }
            button {
                class: "btn btn-outline",
                disabled: paste().trim().is_empty(),
                onclick: move |_| {
                    let pasted = paste().trim().to_string();
                    if pasted.is_empty() {
                        return;
                    }
                    APP_STATE.write().import_conversation(pasted);
                    paste.set(String::new());
                },
                "Restore"
            }
        }
    }
}

/// A buyer's messages with one store, as bubbles: what they wrote, what came
/// back, and what has not been seen landing yet. `tag` narrows it to one
/// conversation (an order's own thread); `None` is every conversation this
/// node holds with the store.
///
/// Requests to buy and the seller's acceptances are not shown: the purchase
/// card shows the order (`chat_item`). What the buyer's own node could not
/// read is not shown either, and no crypto caveats are (round-6 critique).
#[component]
pub(crate) fn Thread(store_contract_id: Vec<u8>, tag: Option<[u8; 32]>) -> Element {
    let (lines, unconfirmed) = {
        let state = APP_STATE.read();
        let unconfirmed: Vec<crate::state::SentMessage> = state
            .unconfirmed_sent(&store_contract_id)
            .into_iter()
            .filter(|sent| tag.is_none_or(|tag| sent.sealed.sender_public_key == tag))
            .collect();
        (
            buyer_chat_lines(&state, &store_contract_id, tag),
            unconfirmed,
        )
    };

    rsx! {
        if !lines.is_empty() {
            ChatLines { lines }
        }

        // Handed to the node, not yet seen in the seller's mailbox. Kept
        // separate from the thread above rather than shown as sent,
        // because "the node accepted it" and "it is in the mailbox" are
        // different claims and only the second is evidence.
        //
        // Once the delivery check has given up (harvest#119) it says the
        // seller does not have it, and offers the one thing that helps.
        if !unconfirmed.is_empty() {
            div { class: "bubbles",
                for message in unconfirmed.iter() {
                    if let Some(why) = message.not_arrived {
                        {
                            let store_contract_id = store_contract_id.clone();
                            let digest = message.digest;
                            let explanation = match why {
                                crate::state::NotArrived::NeverReachedNode => {
                                    "The seller hasn't received this. It never reached your \
                                     Freenet node, so nothing was sent."
                                }
                                crate::state::NotArrived::NotInMailbox => {
                                    "The seller hasn't received this yet. Harvest sent it more \
                                     than once. Sending it again can't deliver it twice."
                                }
                                crate::state::NotArrived::Unconfirmed => {
                                    "Harvest couldn't confirm this reached the seller. It may \
                                     have. Sending it again can't deliver it twice."
                                }
                            };
                            let label = match why {
                                crate::state::NotArrived::Unconfirmed => "You \u{00b7} delivery unknown",
                                crate::state::NotArrived::NeverReachedNode
                                | crate::state::NotArrived::NotInMailbox => "You \u{00b7} not received",
                            };
                            rsx! {
                                div { class: "bubble mine",
                                    span { class: "bubble-who", "{label}" }
                                    "{message.text}"
                                    span { class: "bubble-note", "{explanation}" }
                                    button {
                                        class: "btn btn-sm btn-outline",
                                        onclick: move |_| {
                                            if let Err(e) = resend(&store_contract_id, &digest) {
                                                APP_STATE
                                                    .write()
                                                    .notifications
                                                    .push(format!("Your message could not be sent again: {e}"));
                                            }
                                        },
                                        "Send again"
                                    }
                                }
                            }
                        }
                    } else {
                        div { class: "bubble mine",
                            span { class: "bubble-who", "You \u{00b7} sending" }
                            "{message.text}"
                        }
                    }
                }
            }
        }
    }
}

/// The messages a buyer's node reads in its conversations with a store,
/// oldest first: all of them, or only the conversation `tag`.
fn buyer_messages(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: Option<[u8; 32]>,
) -> Vec<crate::messaging::ConversationMessage> {
    match tag {
        None => state.conversation_thread(store_contract_id),
        Some(tag) => {
            let Some(store) = state.browsing_stores.get(store_contract_id) else {
                return Vec::new();
            };
            let mut messages: Vec<crate::messaging::ConversationMessage> = store
                .conversations
                .iter()
                .filter(|conversation| conversation.buyer_public_key == tag)
                .flat_map(|conversation| conversation.read(&store.mailbox_messages))
                .collect();
            messages.sort_by_key(|message| (message.timestamp, message.nonce));
            messages
        }
    }
}

/// A buyer's conversations with a store (or only `tag`) as chat lines,
/// oldest first, with "You" only for what this device sent ([`who`]).
pub(crate) fn buyer_chat_lines(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: Option<[u8; 32]>,
) -> Vec<ChatLine> {
    let messages = buyer_messages(state, store_contract_id, tag);
    chat_lines(&messages, Role::Buyer, |digest| {
        state.authored_here(store_contract_id, digest)
    })
}

/// Whether a buyer's conversation (or all of them) with a store has any
/// message to show at all, confirmed as theirs or not: what decides that its
/// thread, or a question card, is shown, and its button's label. After a
/// reload the buyer's own messages are not confirmed as theirs, and a
/// question card holding only those must not disappear.
pub(crate) fn buyer_thread_has_messages(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: Option<[u8; 32]>,
) -> bool {
    buyer_chat_lines(state, store_contract_id, tag)
        .iter()
        .any(|line| matches!(line.item, ChatItem::Said(_)))
        || unconfirmed_sends(state, store_contract_id, tag) > 0
}

/// One of a buyer's conversations with a store, as a row of Purchases >
/// Messages (P7) and the header's count read it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ConversationSummary {
    /// The newest thing either side wrote: who ("You", "Seller", or
    /// [`UNCONFIRMED`]), what, and when, as the thread shows it.
    pub latest: Option<ChatLine>,
    /// When that was written, by its writer's clock: the list's order.
    pub latest_at: Option<chrono::DateTime<chrono::Utc>>,
    /// How many messages it holds that a person wrote.
    pub said: usize,
    /// The store wrote last: its newest message comes after anything this
    /// side wrote.
    pub store_wrote_last: bool,
}

/// [`ConversationSummary`] of the buyer's conversation `tag` with a store, or
/// `None` when nobody has written anything in it (it holds only orders).
pub(crate) fn buyer_conversation_summary(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: [u8; 32],
) -> Option<ConversationSummary> {
    let messages = buyer_messages(state, store_contract_id, Some(tag));
    let mut said: Vec<(chrono::DateTime<chrono::Utc>, ChatLine)> = messages
        .iter()
        .filter_map(|message| {
            chat_line(
                Role::Buyer,
                message.addressing,
                state.authored_here(store_contract_id, &message.digest),
                message.timestamp,
                &message.content,
            )
            .filter(|line| matches!(line.item, ChatItem::Said(_)))
            .map(|line| (message.timestamp, line))
        })
        .collect();
    let unconfirmed = unconfirmed_sends(state, store_contract_id, Some(tag));
    if said.is_empty() && unconfirmed == 0 {
        return None;
    }
    said.sort_by_key(|(at, _)| *at);
    let last = said.last().cloned();
    Some(ConversationSummary {
        // A message of this side's still on its way is newer than anything
        // in the mailbox.
        store_wrote_last: unconfirmed == 0
            && last
                .as_ref()
                .is_some_and(|(_, line)| line.trusted && !line.mine && line.who == "Seller"),
        said: said.len(),
        latest_at: last.as_ref().map(|(at, _)| *at),
        latest: last.map(|(_, line)| line),
    })
}

/// The buyer's conversations this session has shown, each with when its
/// newest message was written: a store's reply is "New reply" until its
/// conversation is opened. By time, not by count, so a mailbox that loses
/// old entries cannot hide a new reply (review of #214). Kept for the session only: nothing in the browser
/// lasts across a reload here (`docs/buyer-conversation-persistence.md`),
/// and the delegate has no field for it yet.
pub(crate) static SEEN_CONVERSATIONS: GlobalSignal<
    std::collections::HashMap<[u8; 32], chrono::DateTime<chrono::Utc>>,
> = GlobalSignal::new(std::collections::HashMap::new);

/// Whether the store's reply in this conversation is new to the buyer: the
/// store wrote last, and the conversation has not been opened in this
/// session since it did.
pub(crate) fn is_new_reply(summary: &ConversationSummary, tag: &[u8; 32]) -> bool {
    summary.store_wrote_last
        && SEEN_CONVERSATIONS
            .read()
            .get(tag)
            .is_none_or(|seen| summary.latest_at.is_some_and(|at| at > *seen))
}

/// Messages this tab sent to a store (or to its conversation `tag`) not yet
/// seen landing in the mailbox.
fn unconfirmed_sends(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: Option<[u8; 32]>,
) -> usize {
    state
        .unconfirmed_sent(store_contract_id)
        .iter()
        .filter(|sent| tag.is_none_or(|tag| sent.sealed.sender_public_key == tag))
        .count()
}

/// Whether "once this order is paid, you can message the seller here" is
/// what happens next in the buyer's conversation `tag`
/// (`AppState::payment_would_open`: an order there that can be paid now and
/// that the paid gate would tie to this conversation; codex on #205).
fn awaits_payment(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: &[u8; 32],
) -> bool {
    state.payment_would_open(store_contract_id, tag)
}

/// The compose box, shown only when a message can genuinely be sealed and
/// addressed.
///
/// `target` is the conversation it writes into: an order's own thread, or
/// (`None`) whichever conversation a new message continues. The gate is that
/// conversation's (`AppState::compose_gate_in`): open without a Ghost Key
/// where an order in it is paid, else a Ghost Key's.
#[component]
pub(crate) fn Compose(
    store_contract_id: Vec<u8>,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
    target: Option<[u8; 32]>,
    label: String,
    placeholder: String,
    hint: String,
) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);

    let (gate, signing, failure, name, awaiting_payment) = {
        let state = APP_STATE.read();
        // What is waiting or was handed back in THIS conversation only.
        let tag = state.compose_tag(&store_contract_id, target);
        (
            state.compose_gate_in(&store_contract_id, target),
            tag.map(|tag| state.texts_awaiting_voucher(&store_contract_id, &tag))
                .unwrap_or_default(),
            tag.and_then(|tag| state.voucher_failure(&store_contract_id, &tag).cloned()),
            state.store_name_of(&store_contract_id).label(),
            target.is_some_and(|tag| awaits_payment(&state, &store_contract_id, &tag)),
        )
    };
    // No Ghost Key and nothing paid, no compose box: the seller would not be
    // shown what was typed (`shown_to_seller`), so offering the box would be
    // a dead end.
    if gate == crate::voucher_flow::ComposeGate::NeedsGhostKey {
        return rsx! {
            GhostKeyGate { after_payment: awaiting_payment }
        };
    }
    let vouched = matches!(gate, crate::voucher_flow::ComposeGate::Ready { .. });

    let can_send = !draft().trim().is_empty();

    rsx! {
        div { class: "form-group",
            label { class: "form-label visually-hidden", r#for: "compose-box", "{label}" }
            textarea {
                id: "compose-box",
                class: "form-textarea",
                value: "{draft}",
                placeholder: "{placeholder}",
                oninput: move |event| draft.set(event.value()),
            }
        }

        if let Some(message) = problem() {
            p { class: "text-warning", "{message}" }
        }

        // Waiting on the Ghost Key's signature for this conversation. Shown
        // here rather than in the thread: nothing has been sent yet.
        for text in signing.iter() {
            div { class: "bubble mine",
                span { class: "bubble-who", "You \u{00b7} signing with your Ghost Key" }
                "{text}"
            }
        }
        if let Some(failure) = failure {
            p { class: "text-warning",
                "Not sent: {failure.why}. Copy anything you want to keep, then send again."
            }
            for text in failure.texts.iter() {
                div { class: "bubble mine",
                    span { class: "bubble-who", "You \u{00b7} not sent" }
                    "{text}"
                }
            }
        }

        div { class: "form-actions",
            button {
                class: "btn btn-primary",
                disabled: !can_send,
                onclick: move |_| {
                    let text = draft().trim().to_string();
                    if text.is_empty() {
                        return;
                    }
                    match send(&store_contract_id, &seller_encryption_key, &seller_verifying_key, text, target) {
                        Ok(()) => {
                            draft.set(String::new());
                            problem.set(None);
                        }
                        Err(e) => problem.set(Some(e)),
                    }
                },
                "Send"
            }
        }
        p { class: "text-muted small", "{hint}" }
        // What a Ghost Key's voucher shows the seller, said before the first
        // send: it is a stable pseudonym (`docs/messaging-privacy.md`).
        if vouched {
            p { class: "text-muted small",
                "Sent with your Ghost Key: {name} sees which one, and nobody else does."
            }
        }
    }
}

/// Seal one message and hand it to the local node.
///
/// Returns an error rather than notifying, so the compose box can say what
/// went wrong beside the box the buyer just typed into rather than in a
/// notification list somewhere else on the page.
///
/// The local record is written only after the send is dispatched, so a
/// message that could not be sealed does not appear as one the buyer wrote.
fn send(
    store_contract_id: &[u8],
    seller_encryption_key: &[u8; 32],
    seller_verifying_key: &[u8; 32],
    text: String,
    target: Option<[u8; 32]>,
) -> Result<(), String> {
    let seller = ed25519_dalek::VerifyingKey::from_bytes(seller_verifying_key)
        .map_err(|e| format!("this store's identity key is unusable: {e}"))?;

    // Taken for writing only for this statement: the dispatch below writes
    // the state again.
    let composed = APP_STATE.write().compose_message_to_seller(
        store_contract_id,
        seller_encryption_key,
        seller_verifying_key,
        text.clone(),
        target,
        crate::state::now_ms(),
    )?;
    match composed {
        crate::voucher_flow::VouchedCompose::Sealed(sealed) => {
            deliver_to_seller(store_contract_id, seller, text, sealed)
        }
        crate::voucher_flow::VouchedCompose::AwaitingSignature(Some(pending)) => {
            crate::voucher_flow::spawn_message_voucher_signature(pending);
            Ok(())
        }
        crate::voucher_flow::VouchedCompose::AwaitingSignature(None) => Ok(()),
    }
}

/// In place of the compose box for a buyer with no Ghost Key connected and
/// nothing paid in the conversation.
///
/// Worded for someone who has never heard of a Ghost Key: what it is for,
/// that buying does not need one, and where to get one. In the thread of an
/// order still waiting for payment (`after_payment`, [`awaits_payment`]) it
/// also says the box opens once the order is paid.
#[component]
fn GhostKeyGate(#[props(default)] after_payment: bool) -> Element {
    rsx! {
        div { class: "info-box",
            p { "{crate::voucher_flow::NEEDS_GHOST_KEY}" }
            if after_payment {
                p { class: "text-muted small",
                    "Once this order is paid, you can message the seller here without one."
                }
            }
            super::my_store::GhostKeyAccessNote {}
            div { class: "form-actions",
                button {
                    class: "btn btn-primary",
                    onclick: move |_| super::my_store::connect_ghostkey(),
                    "Use a Ghost Key"
                }
                a {
                    class: "btn btn-outline",
                    href: "{super::my_store::ghost_key_create_url()}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    "What is a Ghost Key?"
                }
            }
        }
    }
}

/// Subscribe, dispatch, and record -- everything a buyer's outgoing message
/// needs once it is sealed.
///
/// Shared with the buy form rather than copied, because the subscribe is the
/// part that is easy to leave out of a second copy: without it the buyer
/// never fetches the mailbox again, and the seller's acceptance -- the one
/// thing that tells them which commitment is theirs -- sits there unread.
///
/// `record_as` is what the buyer's own record calls this message. It is not
/// the message: a request carries structured fields, and the local record
/// exists to say "you wrote this", not to reproduce it.
pub(crate) fn deliver_to_seller(
    store_contract_id: &[u8],
    seller: ed25519_dalek::VerifyingKey,
    record_as: String,
    sealed: harvest_common::mailbox::EncryptedMessage,
) -> Result<(), String> {
    // Subscribe to the seller's mailbox, once, on the first message. This is
    // what makes a reply reachable: without it the buyer never fetches the
    // contract again and the answer sits there unread.
    //
    // Deliberately NOT done merely by opening a storefront. Subscribing
    // advertises a standing interest in that mailbox to the network, which is
    // a longer-lived signal than a single write -- so a reader who never
    // messages anyone advertises nothing.
    let mailbox = crate::gateway::mailbox_ops::mailbox_contract_key(&seller)?;
    APP_STATE
        .write()
        .register_store_mailbox(store_contract_id, mailbox.id().as_bytes());

    dispatch(store_contract_id.to_vec(), seller, sealed.clone(), false);

    APP_STATE
        .write()
        .record_sent_to_seller(store_contract_id, record_as, &sealed, &seller);
    Ok(())
}

/// Hand a sealed message to the local node, and check that it arrives.
///
/// The caller must not read this as delivery: see
/// `gateway::mailbox_ops::send_message`. What the buyer learns comes later,
/// from the mailbox: the message moves into the thread when it lands, or is
/// marked as not received (with a resend) when it does not. A failure to
/// even reach the node is also a notification, which is the only channel
/// left once the compose box has been told the send was dispatched.
///
/// `_handed_over` is whether a copy of these bytes already reached the node
/// (a resend), so a failure now is not reported as "nothing was sent".
fn dispatch(
    _store_contract_id: Vec<u8>,
    _seller: ed25519_dalek::VerifyingKey,
    _sealed: harvest_common::mailbox::EncryptedMessage,
    _handed_over: bool,
) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::mailbox_ops::send_message(
            _store_contract_id,
            &_seller,
            _sealed,
            _handed_over,
        )
        .await
        {
            dioxus::logger::tracing::error!("Failed to send message: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Your message could not be sent: {e}"));
        }
    });
}

/// Send a message the seller has not received again: the identical sealed
/// bytes, never a fresh seal, so it cannot arrive twice (harvest#119).
///
/// Re-registers the mailbox as the first send does, so a subscription that
/// gave up in the meantime is asked for again and the re-read has somewhere
/// to land.
fn resend(store_contract_id: &[u8], digest: &[u8; 32]) -> Result<(), String> {
    let Some((seller, sealed, handed_over)) = APP_STATE
        .write()
        .take_for_resend(store_contract_id, digest)?
    else {
        // Already being sent again (a second click before the re-render).
        return Ok(());
    };
    // Cannot fail here: the same derivation succeeded for this key on the
    // first send. If it ever did, the message is re-marked rather than left
    // with no mark and no delivery.
    let mailbox = match crate::gateway::mailbox_ops::mailbox_contract_key(&seller) {
        Ok(mailbox) => mailbox,
        Err(e) => {
            APP_STATE.write().mark_not_arrived(
                store_contract_id,
                digest,
                crate::state::NotArrived::Unconfirmed,
            );
            return Err(e);
        }
    };
    {
        let mut app = APP_STATE.write();
        // Only when this store records no mailbox, or records this one (a
        // subscribe that gave up drops the routing but keeps the record, and
        // this re-asks for it). A store re-backed since records a different
        // one, and repointing it here would file two mailboxes' states into
        // one store.
        let same_or_none = app
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.mailbox_contract_id.as_deref())
            .is_none_or(|recorded| recorded == mailbox.id().as_bytes());
        if same_or_none {
            app.register_store_mailbox(store_contract_id, mailbox.id().as_bytes());
        }
    }
    dispatch(store_contract_id.to_vec(), seller, sealed, handed_over);
    Ok(())
}

/// Why this store cannot be messaged, said plainly and with the compose box
/// gone rather than disabled -- a disabled box invites a buyer to keep
/// trying.
#[component]
pub(crate) fn Unavailable(why: String) -> Element {
    rsx! {
        p { class: "text-warning", "{why}" }
        p { class: "text-muted",
            style: "font-size: 0.85rem;",
            "Use whatever contact route the store's description gives you instead."
        }
    }
}

/// What the seller reads once, where buyers' messages appear to them (Ian,
/// 2026-09-30, after the extortion second opinion): one place per screen,
/// above the reply box of the one conversation open, never per message.
pub(crate) const SELLER_GUIDANCE: &str =
    "Harvest can't hold anyone to a deal. A refund doesn't prevent or remove a complaint.";

/// The one quiet line about entries this device could not read, in place of
/// a card per entry (round-6 critique 10-3). Anyone can write to a mailbox,
/// so some are junk; the rest were sealed to keys this device does not hold.
pub(crate) const SOME_UNREADABLE: &str = "Some messages couldn't be read and are hidden. Anyone \
     can write to your store's mailbox, so some are junk.";

/// The reasons the seller's store gives in a Decline, word for word: the
/// harvest delegate's `Refusal::buyer_reason` and its stock check
/// (`delegates/harvest-delegate/src/auto_invoice.rs`). Copied rather than
/// depended on (the UI takes nothing from the delegate crate); the test
/// `the_store_decline_reasons_are_the_delegates` reads the delegate's source
/// and fails if they drift.
pub(crate) const STORE_DECLINE_REASONS: [&str; 6] = [
    "What is left is held for orders not yet paid. Try again in about an hour.",
    "This store can't take more orders right now. Please try again later.",
    "This listing has changed since you opened it. Reload the store to see it as it is now, \
     then try again.",
    "This listing has been taken down.",
    "Your computer's clock is ahead of the right time. Set it right, then try again.",
    "Sold out",
];

/// Whether `reason` is exactly one the seller's store sends
/// ([`STORE_DECLINE_REASONS`], "Only N left" with N a plain number, and
/// [`harvest_common::delegate::TOO_MANY_UNPAID`]). Shown whoever sealed it:
/// a forger copying one only repeats the store's own words, and it is what
/// lets a seller see "Sold out" on their store's automatic declines.
pub(crate) fn is_store_decline_reason(reason: &str) -> bool {
    let only_n_left = reason
        .strip_prefix("Only ")
        .and_then(|rest| rest.strip_suffix(" left"))
        // Exactly how the delegate writes a u32 count: ASCII digits, no
        // sign, no leading zero, within u32 (review round 4 of #205).
        .is_some_and(|n| {
            n.bytes().all(|b| b.is_ascii_digit())
                && (n == "0" || !n.starts_with('0'))
                && n.parse::<u32>().is_ok()
        });
    STORE_DECLINE_REASONS.contains(&reason)
        || reason == harvest_common::delegate::TOO_MANY_UNPAID
        || only_n_left
}

/// What one message is, as a conversation shows it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ChatItem {
    /// Something a person wrote: a bubble.
    Said(String),
    /// A step that is not a message, said in one muted line.
    Event(String),
}

/// How `content` appears in a conversation, or `None` where it does not.
///
/// Requests to buy and acceptances (the store's automatic invoice answers
/// included) are NOT chat (round-6 critique 10-6): they are shown as what
/// they are, on the order card, the pay card, and the seller's request card
/// for one still waiting on them. A decline is one muted line.
pub(crate) fn chat_item(content: &MessageContent) -> Option<ChatItem> {
    match content {
        MessageContent::Text(text) | MessageContent::VouchedText { text, .. } => {
            Some(ChatItem::Said(text.clone()))
        }
        MessageContent::Decline { reason } if reason.trim().is_empty() => {
            Some(ChatItem::Event("An order was declined.".to_string()))
        }
        MessageContent::Decline { reason } => Some(ChatItem::Event(format!(
            "An order was declined: {}",
            reason.trim()
        ))),
        MessageContent::OrderRequest { .. } | MessageContent::OrderAccepted { .. } => None,
    }
}

/// Which side of a conversation this browser is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Buyer,
    Seller,
}

/// The label on a message in this side's direction that this device did not
/// send (review of #205, S2). It claims nothing about who wrote it.
pub(crate) const UNCONFIRMED: &str = "Not confirmed as yours";

/// The one line under a conversation holding [`UNCONFIRMED`] messages, so
/// they don't read as tampering when they are only the reader's own from
/// before (review round 2 of #205, R4; msg1 critique MSG-2). True for both
/// sides: the only other person who can write in the reader's direction is
/// the other party, so a message the reader doesn't recognise is theirs.
pub(crate) const UNCONFIRMED_WHY: &str = "Messages marked \u{201c}Not confirmed as yours\u{201d} \
     may be ones you sent earlier or from another device. If you don't recognise one, you \
     didn't write it.";

/// The name above a message: `(name, drawn as this side's own, trusted for
/// the timeline)`.
///
/// Direction is not authorship. Both parties hold both keys, so either can
/// seal a message in either direction (a seller's inbox once showed "as
/// agreed, I confess" as the seller's own reply, written by the buyer; with
/// paid-order messaging a paid buyer needs no Ghost Key to try it). So:
///
/// * the other side's direction is named for the other side ("Buyer" on
///   the seller's screen, "Seller" on the buyer's): if this side sealed it
///   itself, the only person it can mislead is the one who wrote it;
/// * this side's direction is "You" only for what THIS device sent
///   (`authored_here`, `AppState::authored_here`: the entry's digest, which
///   the other party cannot reproduce);
/// * anything else in this side's direction is [`UNCONFIRMED`]: it keeps its
///   place in time, but on neither side (full width, dashed, neutral), never
///   drawn as this side's word ([`ChatLines`], [`bubble_class`]). It includes this side's
///   own messages from another device or from before a reload, which is the
///   price of never putting the other party's words under "You".
fn who(
    role: Role,
    addressing: crate::messaging::Addressing,
    authored_here: bool,
) -> (&'static str, bool, bool) {
    use crate::messaging::Addressing;
    match (role, addressing) {
        (Role::Seller, Addressing::ToSeller) => ("Buyer", false, true),
        (Role::Buyer, Addressing::ToBuyer) => ("Seller", false, true),
        _ if authored_here => ("You", true, true),
        _ => (UNCONFIRMED, false, false),
    }
}

/// When a message says it was written, in this browser's local time: "29
/// Sep, 18:42". The writer's own claim, like everything in the envelope; it
/// orders the thread and dates the bubble, and decides nothing.
fn when(at: chrono::DateTime<chrono::Utc>) -> String {
    at.with_timezone(&chrono::Local)
        .format("%-d %b, %H:%M")
        .to_string()
}

/// One line of a conversation as [`ChatLines`] draws it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChatLine {
    pub(crate) who: &'static str,
    pub(crate) mine: bool,
    /// Placed in the timeline ([`who`]); an [`UNCONFIRMED`] line is not.
    pub(crate) trusted: bool,
    pub(crate) when: String,
    pub(crate) item: ChatItem,
}

/// One message as a chat line, or `None` where it is not chat
/// ([`chat_item`]). A step (a decline) is always drawn as trusted: its words
/// claim nothing about who wrote them (and an untrusted reason is dropped).
fn chat_line(
    role: Role,
    addressing: crate::messaging::Addressing,
    authored_here: bool,
    timestamp: chrono::DateTime<chrono::Utc>,
    content: &MessageContent,
) -> Option<ChatLine> {
    use crate::messaging::Addressing;
    let this_side = matches!(
        (role, addressing),
        (Role::Seller, Addressing::ToBuyer) | (Role::Buyer, Addressing::ToSeller)
    );
    // A decline this device did not send keeps its place as a step but not
    // its words, unless they are the store's own fixed words
    // ([`is_store_decline_reason`]): the reason is free text another party
    // could have written. On the seller's screen that is every decline in
    // either direction (review rounds 2 and 3 of #205, R5): the store and
    // its delegate address theirs to the buyer, so one addressed to the
    // seller was written by the buyer, and "Refund sent, order closed by the
    // seller" in a muted step reads as the seller's own record. On the
    // buyer's screen, one in the buyer's direction; the seller's are theirs
    // to word.
    let reason_shown = |reason: &str| {
        authored_here || is_store_decline_reason(reason) || (role == Role::Buyer && !this_side)
    };
    let item = match content {
        MessageContent::Decline { reason } if !reason_shown(reason) => {
            ChatItem::Event("An order was declined.".to_string())
        }
        _ => chat_item(content)?,
    };
    let (who, mine, trusted) = who(role, addressing, authored_here);
    Some(ChatLine {
        who,
        mine,
        trusted: trusted || matches!(item, ChatItem::Event(_)),
        when: when(timestamp),
        item,
    })
}

/// A buyer's messages as chat lines, in the order given; `authored_here`
/// is what this device sent (`AppState::authored_here`).
fn chat_lines(
    messages: &[crate::messaging::ConversationMessage],
    role: Role,
    authored_here: impl Fn(&[u8; 32]) -> bool,
) -> Vec<ChatLine> {
    messages
        .iter()
        .filter_map(|message| {
            chat_line(
                role,
                message.addressing,
                authored_here(&message.digest),
                message.timestamp,
                &message.content,
            )
        })
        .collect()
}

/// How many messages `lines` shows: what people wrote, not steps (no
/// decline is counted, the store's automatic ones or a seller's own), and
/// not a line [`UNCONFIRMED`] (review after b9c727f: one a forger dated can
/// never be a thread's word in a count).
fn said_count(lines: &[ChatLine]) -> usize {
    lines
        .iter()
        .filter(|line| line.trusted && matches!(line.item, ChatItem::Said(_)))
        .count()
}

/// A conversation, as bubbles (mockup `msgs()`), every message in time
/// order (msg1 critique MSG-1: a separate group below the other side's
/// messages left a returning reader a conversation told by one side).
///
/// A message in this side's direction this device did not send
/// ([`UNCONFIRMED`]) keeps its place in time, but on neither side: full
/// width, dashed, on a neutral background, with its own label in place of
/// "You" ([`bubble_class`]). On this side's alignment it looked exactly like
/// the reader's own messages after a reload, and a forger picks its date, so
/// a forged "Agreed, full refund" read as this side's reply in context
/// (review after b9c727f). One line under the conversation says what the
/// label means ([`UNCONFIRMED_WHY`]).
#[component]
fn ChatLines(lines: Vec<ChatLine>) -> Element {
    let any_unconfirmed = lines.iter().any(|line| !line.trusted);
    rsx! {
        div { class: "bubbles",
            for line in lines.iter() {
                match &line.item {
                    ChatItem::Said(text) => rsx! {
                        div { class: bubble_class(line),
                            span { class: "bubble-who", "{line.who} \u{00b7} {line.when}" }
                            "{text}"
                        }
                    },
                    ChatItem::Event(text) => rsx! {
                        p { class: "msg-event", "{text} \u{00b7} {line.when}" }
                    },
                }
            }
        }
        if any_unconfirmed {
            p { class: "text-muted small", "{UNCONFIRMED_WHY}" }
        }
    }
}

/// How a said line is drawn: the other side's plain on the left, this side's
/// own filled on the right, and an [`UNCONFIRMED`] one full width, dashed and
/// neutral, on neither side, so it can never pass for this side's word
/// (review round 1 S2, and after b9c727f).
pub(crate) fn bubble_class(line: &ChatLine) -> &'static str {
    match (line.trusted, line.mine) {
        (false, _) => "bubble unconfirmed",
        (true, true) => "bubble mine",
        (true, false) => "bubble",
    }
}

/// One conversation in a seller's mailbox, as the seller is shown it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SellerThread {
    pub tag: [u8; 32],
    /// Whether it is open ([`open_conversations`]): a verified voucher or a
    /// paid order of the store's in it.
    pub open: bool,
    /// Its readable entries as [`shown_to_seller`] shows them, newest first
    /// by each writer's own timestamp (`messaging::read_mailbox`'s display
    /// order, never used to decide anything).
    pub entries: Vec<MailboxEntry>,
    /// Its chat lines, oldest first by the writer's timestamp, worked out
    /// once in [`seller_inbox`] (the authorship check needs the state).
    pub lines: Vec<ChatLine>,
    /// Requests in it waiting for the seller's hand answer
    /// (`offered_requests`), so an order card can say one waits without
    /// opening the conversation.
    pub waiting: usize,
    /// The store's orders that belong to it
    /// (`order_threads::order_in_conversation`), whatever their status: the
    /// order cards it is shown under.
    pub orders: Vec<harvest_common::payment::OrderId>,
    /// Those of [`Self::orders`] a request in it names
    /// (`order_threads::order_by_request`), which binds the conversation's
    /// tag: what [`SellerInbox::for_order`] prefers.
    pub by_request: Vec<harvest_common::payment::OrderId>,
    /// The buyer wrote last and the seller has not replied since
    /// ([`awaiting_reply`]): what the "need you" count and the "New message
    /// from the buyer" line say.
    pub awaiting_reply: bool,
    /// The short refs of the orders in it the seller is shown (not an unpaid
    /// Buy now), newest first: what its header names (msg1 critique MSG-4).
    pub order_refs: Vec<String>,
}

impl SellerThread {
    /// How many messages it shows (not steps): the count on its button.
    pub(crate) fn chat_count(&self) -> usize {
        said_count(&self.lines)
    }

    /// The newest thing a buyer wrote in it, by its own timestamp, for a
    /// question's row: a display choice, decided whatever order `entries`
    /// arrive in.
    pub(crate) fn latest_from_buyer(&self) -> Option<(String, chrono::DateTime<chrono::Utc>)> {
        self.entries
            .iter()
            .filter_map(|entry| match entry {
                MailboxEntry::Readable {
                    content: MessageContent::Text(text) | MessageContent::VouchedText { text, .. },
                    addressing: crate::messaging::Addressing::ToSeller,
                    timestamp,
                    ..
                } => Some((text.clone(), *timestamp)),
                _ => None,
            })
            .max_by_key(|(_, at)| *at)
    }
}

/// A seller's mailbox at one store, as the Orders tab shows it: one
/// [`SellerThread`] per conversation with anything readable in it, and the
/// two counts its quiet lines say.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SellerInbox {
    pub threads: Vec<SellerThread>,
    /// Entries this device could not read ([`SOME_UNREADABLE`]).
    pub unreadable: usize,
    /// Buyer text [`shown_to_seller`] held back ([`hidden_unvouched_line`]).
    pub held_back: usize,
}

impl SellerInbox {
    /// The conversation order `id` belongs to, if this device can read it.
    ///
    /// A conversation whose request names the order comes first
    /// (`order_threads::order_by_request`): the request id hashes that
    /// conversation's own tag, so no other tag can claim it, even one that
    /// shares its keys. Only when none does (a quote invoice, or a Buy now
    /// whose request has left the mailbox) is the order matched by its
    /// listing tag, which every tag sharing the conversation's keys would
    /// match; those twins are never read (`messaging::is_canonical_tag`:
    /// canonical, in the prime-order subgroup), so one conversation holds the
    /// claim, and should two ever hold it the lowest tag wins, which no
    /// writer's timestamp or arrival order steers.
    pub(crate) fn for_order(&self, id: &harvest_common::payment::OrderId) -> Option<&SellerThread> {
        let by_request = self
            .threads
            .iter()
            .filter(|thread| thread.by_request.contains(id))
            .min_by_key(|thread| thread.tag);
        by_request.or_else(|| {
            self.threads
                .iter()
                .filter(|thread| thread.orders.contains(id))
                .min_by_key(|thread| thread.tag)
        })
    }

    /// [`for_order`](Self::for_order) for every order at once, built in one
    /// pass over the threads (review after 01f2bcf: the Orders tab asked
    /// `for_order` per card, threads × orders on each render). Same rule:
    /// a conversation whose request names the order wins, then the lowest
    /// tag.
    pub(crate) fn by_order(
        &self,
    ) -> std::collections::HashMap<&harvest_common::payment::OrderId, &SellerThread> {
        let rank = |thread: &SellerThread, id: &harvest_common::payment::OrderId| {
            // Sorted (see `seller_inbox`), so a search, not a scan.
            (
                thread.by_request.binary_search(id).is_ok(),
                std::cmp::Reverse(thread.tag),
            )
        };
        let mut map: std::collections::HashMap<&harvest_common::payment::OrderId, &SellerThread> =
            std::collections::HashMap::new();
        for thread in &self.threads {
            for id in &thread.orders {
                map.entry(id)
                    .and_modify(|held| {
                        if rank(thread, id) > rank(held, id) {
                            *held = thread;
                        }
                    })
                    .or_insert(thread);
            }
        }
        map
    }
}

/// [`SellerInbox`] for one of our stores. The anti-spam gate's seller half
/// runs here, before anything is grouped: buyer text neither a Ghost Key nor
/// a paid order vouches for is taken out ([`shown_to_seller`]), and the
/// address of an order past its complaint window is hidden
/// ([`request_address_hidden`]).
///
/// Not cached (review after 9417fbf): what it reads includes every order's
/// full terms and payment proof (up to 256 KiB each), despatches, the owner,
/// keys, tips and this tab's sent record, so a fingerprint complete enough
/// to be safe costs more than reading the mailbox again (at most 512 entries
/// opened), and a stale one showed a wrong inbox with nothing to re-render
/// it. Each caller reads it fresh.
pub(crate) fn seller_inbox(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
) -> SellerInbox {
    let Some(store) = state.browsing_stores.get(store_contract_id) else {
        return SellerInbox::default();
    };
    let now = chrono::Utc::now();
    state.prune_first_seen();
    let all = state.mailbox_entries(store_contract_id);
    let unreadable = all
        .iter()
        .filter(|entry| matches!(entry, MailboxEntry::Unreadable { .. }))
        .count();
    // Each conversation's orders through one lookup, so each costs what its
    // own claims hold, never claims × orders (review after 1bd9bcd: with
    // free junk conversations that froze the Orders tab and the header); and
    // the paid set through the one function the tests also run.
    let members = seller_members(&all, &store.orders, &store.listings, |tag| {
        state.conversation_keys.get(tag)
    });
    let paid = paid_set(&members);
    // `shown_to_seller` works the vouchers out again below; that is a cache
    // hit (`voucher_verifies` remembers each verdict), not a second chain
    // check.
    let open = open_conversations(
        &all,
        |voucher, tag| state.voucher_verifies(voucher, tag),
        |tag| paid.contains(tag),
    );
    let index = OrderIndex::new(&store.orders);
    let (shown, held_back) = shown_to_seller(
        all,
        |voucher, tag| state.voucher_verifies(voucher, tag),
        |tag| paid.contains(tag),
        |entry| {
            request_address_hidden(
                entry,
                &index,
                state.conversation_keys.get(entry.conversation()),
                |order| state.address_retained_for(order),
            )
        },
        |digest| state.authored_here(store_contract_id, digest),
    );
    // What is shown, by conversation, once: a conversation with nothing
    // shown is dropped before any per-thread work.
    let mut shown_by_tag: std::collections::HashMap<[u8; 32], Vec<MailboxEntry>> =
        std::collections::HashMap::new();
    for entry in shown {
        if let (MailboxEntry::Readable { .. }, Ok(tag)) =
            (&entry, <[u8; 32]>::try_from(entry.conversation()))
        {
            shown_by_tag.entry(tag).or_default().push(entry);
        }
    }
    let threads = members
        .into_iter()
        .filter_map(|(tag, orders)| {
            let entries = shown_by_tag.remove(&tag)?;
            let mut timed: Vec<(chrono::DateTime<chrono::Utc>, ChatLine)> = entries
                .iter()
                .filter_map(|entry| match entry {
                    MailboxEntry::Readable {
                        content,
                        addressing,
                        timestamp,
                        digest,
                        ..
                    } => chat_line(
                        Role::Seller,
                        *addressing,
                        state.authored_here(store_contract_id, digest),
                        *timestamp,
                        content,
                    )
                    .map(|line| (*timestamp, line)),
                    MailboxEntry::Unreadable { .. } => None,
                })
                .collect();
            timed.sort_by_key(|(at, _)| *at);
            let awaiting = awaiting_reply(open.contains(tag.as_slice()), &entries, |digest| {
                state.first_seen(digest, now)
            });
            let mut seen_orders: Vec<&harvest_common::payment::AuthorizedOrder> = orders
                .iter()
                .map(|(order, _)| *order)
                .filter(|order| !crate::fulfilment::is_unpaid_buy_now(order))
                .collect();
            seen_orders
                .sort_by_key(|order| std::cmp::Reverse((order.order.created_at, order.order.id.0)));
            // Sorted, so a thread's props compare equal from one render to
            // the next (the lookup returns them in hash order).
            let mut ids: Vec<harvest_common::payment::OrderId> = orders
                .iter()
                .map(|(order, _)| order.order.id.clone())
                .collect();
            ids.sort();
            let mut by_request: Vec<harvest_common::payment::OrderId> = orders
                .iter()
                .filter(|(_, by_request)| *by_request)
                .map(|(order, _)| order.order.id.clone())
                .collect();
            by_request.sort();
            Some(SellerThread {
                tag,
                open: open.contains(tag.as_slice()),
                entries,
                lines: timed.into_iter().map(|(_, line)| line).collect(),
                waiting: 0,
                orders: ids,
                by_request,
                awaiting_reply: awaiting,
                order_refs: seen_orders
                    .iter()
                    .map(|order| order.order.id.short())
                    .collect(),
            })
        })
        .map(|mut thread| {
            thread.waiting = offered_requests(state, &thread, &store.listings, &index).len();
            thread
        })
        .collect();
    SellerInbox {
        threads,
        unreadable,
        held_back,
    }
}

/// Whether a seller conversation waits for the seller's reply (msg1 critique
/// MSG-3): it is open (a Ghost Key's voucher or a paid order, so junk and
/// unopened conversations never count), the buyer has written in it, and a
/// buyer line comes after every reply of the seller's.
///
/// Every timestamp is its writer's claim and either clock can be off, fast
/// or slow, so "after" is decided by what this device saw where it can be
/// (`first_seen`, kept per session by `AppState::first_seen`; reviews after
/// 9417fbf and 1bd9bcd):
///
/// * a buyer line and a reply first seen at different moments of this
///   session (one arrived while the page was open) are ordered by when they
///   were seen. That keeps a quick follow-up waiting whatever its writer's
///   clock says, fast or slow, and a reply dated in the future answers only
///   what was seen before it;
/// * two first seen together (the mailbox as it stood when the page opened,
///   or arriving in one update) are ordered by their own timestamps; a buyer
///   line dated after it was first seen (in the future when the page opened)
///   is answered by any reply in the conversation, since its date cannot be
///   true and nothing says where it falls (review after 6c61839: capped at
///   the page's opening, it beat every reply on every reload, a permanent
///   "need you" any paid buyer or Ghost Key holder could set). With no reply
///   at all it still waits.
///
/// What is left wherever the timestamps decide, which is every buyer line
/// and reply first seen together (the mailbox when the page opens, and a
/// buyer line arriving in the same update as a reply):
///
/// * a buyer line from a buyer clock ahead of this device's, answered by a
///   reply sent within that lead, reads as waiting again, an error toward
///   "need you";
/// * a buyer line backdated before a reply (a buyer clock behind) reads as
///   answered;
/// * a buyer line still dated in the future when first seen (a buyer clock
///   ahead of this device's) is taken as answered by any reply in the
///   conversation, for the session;
/// * and when `AppState::prune_first_seen` clears the record at 16,384
///   entries, every entry of every store is first seen again at once, so
///   all of them fall back to the timestamps, as at a page opening.
///
/// A reply is text in the seller's direction (confirmed as the seller's or
/// not: text the buyer sealed there clears only their own waiting), or a
/// decline with a reason of the seller's own. The store's automatic
/// declines ([`is_store_decline_reason`]) are not the seller answering.
pub(crate) fn awaiting_reply(
    open: bool,
    entries: &[MailboxEntry],
    first_seen: impl Fn(&[u8; 32]) -> chrono::DateTime<chrono::Utc>,
) -> bool {
    use crate::messaging::Addressing;
    type Seen = (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>);
    if !open {
        return false;
    }
    let mut buyer: Vec<Seen> = Vec::new();
    let mut replies: Vec<Seen> = Vec::new();
    for entry in entries {
        let MailboxEntry::Readable {
            content,
            addressing,
            timestamp,
            digest,
            ..
        } = entry
        else {
            continue;
        };
        let text = matches!(
            content,
            MessageContent::Text(_) | MessageContent::VouchedText { .. }
        );
        match addressing {
            Addressing::ToSeller if text => buyer.push((*timestamp, first_seen(digest))),
            Addressing::ToBuyer => {
                let reply = text
                    || matches!(content, MessageContent::Decline { reason }
                        if !reason.trim().is_empty() && !is_store_decline_reason(reason));
                if reply {
                    replies.push((*timestamp, first_seen(digest)));
                }
            }
            Addressing::ToSeller => {}
        }
    }
    // Whether buyer line `b` comes after reply `r`, by first sight when they
    // were seen at different moments, else by their timestamps. (The reply's
    // cap at first sight cannot change an outcome: seen together, both share
    // one first-seen moment, which a believable buyer date never exceeds. It
    // is kept for symmetry, and its mutation survives for that reason.)
    let after = |(b_stamp, b_seen): &Seen, (r_stamp, r_seen): &Seen| {
        if b_seen != r_seen {
            b_seen > r_seen
        } else if b_stamp > b_seen {
            // Dated after it was first seen, so after the page opened: its
            // date can't be true, and nothing says where it falls, so any
            // reply answers it. Capped at the page's opening instead, it
            // beat every reply on every reload: a permanent "need you" any
            // paid buyer or Ghost Key holder could set (review after
            // 6c61839).
            false
        } else {
            *b_stamp > (*r_stamp).min(*r_seen)
        }
    };
    buyer.iter().any(|b| replies.iter().all(|r| after(b, r)))
}

/// How many of one of our stores' buyer conversations wait for the seller's
/// reply ([`awaiting_reply`]): counted in "need you" on the header, the
/// store's card and its Orders tab.
pub(crate) fn replies_awaited(state: &crate::state::AppState, store_contract_id: &[u8]) -> usize {
    seller_inbox(state, store_contract_id)
        .threads
        .iter()
        .filter(|thread| thread.awaiting_reply)
        .count()
}

/// The requests in `thread` the seller is offered a hand answer for.
fn offered_requests(
    state: &crate::state::AppState,
    thread: &SellerThread,
    listings: &[harvest_common::listing::AuthorizedListing],
    index: &OrderIndex<'_>,
) -> Vec<PendingRequest> {
    unanswered_requests_in(
        &thread.entries,
        listings,
        index,
        state.conversation_keys.get(thread.tag.as_slice()),
    )
    .into_iter()
    .filter(|request| offered_by_hand(request, thread.open))
    .collect()
}

/// Whether a seller conversation with no order card of its own is worth a
/// row among the questions: something a person wrote in an open
/// conversation, or a request waiting for the seller's answer. An unpaid
/// Buy now alone is neither: the store answers it itself, and the seller
/// hears of it once it is paid.
pub(crate) fn is_question(thread: &SellerThread) -> bool {
    (thread.open && thread.chat_count() > 0) || thread.waiting > 0
}

/// One conversation with one buyer, as the seller reads it: the messages,
/// any request still waiting for a hand answer (shown as the request it is,
/// with its accept control), the guidance line, and the reply box.
#[component]
pub(crate) fn SellerConversation(
    store_contract_id: Vec<u8>,
    thread: SellerThread,
    /// What the seller's pages call this buyer (`seller_pages::SellerData`).
    #[props(default = "this buyer".to_string())]
    name: String,
) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);
    let (offered, availability) = {
        let state = APP_STATE.read();
        let store = state.browsing_stores.get(&store_contract_id);
        let offered = store
            .map(|store| {
                offered_requests(
                    &state,
                    &thread,
                    &store.listings,
                    &OrderIndex::new(&store.orders),
                )
            })
            .unwrap_or_default();
        let availability: Vec<bool> = offered
            .iter()
            .map(|request| {
                state
                    .listing_availability(&store_contract_id, &request.listing_id)
                    .is_buyable()
            })
            .collect();
        (offered, availability)
    };
    let lines = thread.lines.clone();
    let tag = thread.tag;

    rsx! {
        div { class: "conversation",
            if lines.is_empty() {
                p { class: "text-muted small", "No messages yet." }
            } else {
                ChatLines { lines }
            }

            // A request to buy is the one thing in a conversation with an
            // action attached, so it gets the control rather than leaving
            // the seller to copy a listing id into a form by hand -- which is
            // also how the reply-to tag would get lost. Shown as the request
            // it is, not as a message.
            for (request , on_sale) in offered.iter().zip(availability) {
                // The key sits on the first node of the loop body, the only
                // place dioxus reads a list key from, so each request keeps
                // its own accept control's state when an earlier one drops
                // out of the list.
                div { key: "{bs58::encode(request.digest).into_string()}", class: "request-card",
                    RequestDetails {
                        store_contract_id: store_contract_id.clone(),
                        thread: thread.clone(),
                        digest: request.digest,
                    }
                    // A request made before the listing sold out, or for a
                    // listing since replaced by an edit (harvest#70), can
                    // still be answered: the buyer asked while it was on
                    // sale. The seller is told, so they decide knowingly.
                    if !on_sale {
                        p { class: "text-muted small",
                            "{request.listing_title} is no longer on sale in your store. You can still \
                             invoice this buyer, since they asked while it was, or reply to say it has gone."
                        }
                    }
                    super::buy_view::AcceptRequest {
                        store_contract_id: store_contract_id.clone(),
                        tag: tag.to_vec(),
                        listing_id: request.listing_id.clone(),
                        listing_title: request.listing_title.clone(),
                        order_binding: request.order_binding,
                        buyer_receipt_key: request.buyer_receipt_key,
                        quantity: request.quantity,
                        instant: request.instant,
                    }
                }
            }

            p { class: "text-muted small", "{SELLER_GUIDANCE}" }
            div { class: "form-group",
                label { class: "form-label visually-hidden", r#for: "seller-reply", "Reply" }
                textarea {
                    id: "seller-reply",
                    class: "form-textarea",
                    value: "{draft}",
                    placeholder: "Reply to {name}",
                    oninput: move |event| draft.set(event.value()),
                }
            }
            if let Some(message) = problem() {
                p { class: "text-warning", "{message}" }
            }
            div { class: "form-actions",
                button {
                    class: "btn btn-primary",
                    disabled: draft().trim().is_empty(),
                    onclick: {
                        let store_contract_id = store_contract_id.clone();
                        move |_| {
                            let text = draft().trim().to_string();
                            if text.is_empty() {
                                return;
                            }
                            match reply(&store_contract_id, &tag, text) {
                                Ok(()) => {
                                    draft.set(String::new());
                                    problem.set(None);
                                }
                                Err(e) => problem.set(Some(e)),
                            }
                        }
                    },
                    "Send reply"
                }
            }
            p { class: "text-muted small", "Only {name} can read your reply." }
        }
    }
}

/// What a request still waiting for the seller asks for, read from its entry
/// in the conversation: the address (or why it is not shown), the buyer's
/// picks named by their group, and the note.
#[component]
fn RequestDetails(store_contract_id: Vec<u8>, thread: SellerThread, digest: [u8; 32]) -> Element {
    let Some(MailboxEntry::Readable {
        content:
            MessageContent::OrderRequest {
                listing_id,
                quantity,
                shipping,
                note,
                instant,
                ..
            },
        ..
    }) = thread.entries.iter().find(|entry| entry.digest() == digest)
    else {
        return rsx! {};
    };
    let groups = APP_STATE
        .read()
        .browsing_stores
        .get(&store_contract_id)
        .and_then(|store| store.listings.iter().find(|l| l.listing.id == *listing_id))
        .map(|l| l.listing.choices.clone())
        .unwrap_or_default();
    let request = crate::state::SellerOrderRequest {
        listing_id: Some(listing_id.clone()),
        title: None,
        quantity: *quantity,
        shipping: shipping.clone(),
        note: note.clone(),
        region: instant.as_ref().and_then(|s| s.region.clone()),
        choices: crate::state::labelled_choices(
            &groups,
            instant
                .as_ref()
                .map(|s| s.choices.as_slice())
                .unwrap_or_default(),
        ),
    };
    rsx! {
        super::invoice_form::RequestView { request }
    }
}

/// The line a seller sees about buyer text [`shown_to_seller`] held back:
/// messages left out, and notes and reasons blanked in a conversation that
/// is not open.
pub(crate) fn hidden_unvouched_line(hidden: usize) -> String {
    // "couldn't match to a paid order", not "came without one": a paid
    // order's conversation can close if its request leaves the mailbox and
    // its listing is not in the store (`order_threads`), and the line must
    // stay true then.
    if hidden == 1 {
        "1 message was held back: it came without a Ghost Key, and Harvest couldn't match it \
         to a paid order."
            .to_string()
    } else {
        format!(
            "{hidden} messages were held back: they came without a Ghost Key, and Harvest \
             couldn't match them to a paid order."
        )
    }
}

/// A seller's inbox as the seller is shown it, and how many buyer messages
/// were left out for carrying no Ghost Key's voucher.
///
/// Buyer-to-seller messages need a Ghost Key (anti-spam); buying does not.
/// The mailbox is open-write, so the buyer's compose gate alone stops nobody
/// with a script, and this is the half that does: free text reaches the
/// seller only in a conversation that is OPEN, which takes one of
///
/// * a [`MessageContent::VouchedText`] whose voucher verifies for THIS
///   conversation's tag (`verifies`), so one copied from another
///   conversation vouches for nothing; or
/// * one of the store's orders that is PAID and belongs to this
///   conversation (`paid`, [`paid_conversations`]; the rule and what it
///   refuses to count are in `crate::order_threads`): money, not a Ghost
///   Key, but no cheaper for a spammer. A buyer's plain text in such a
///   conversation is shown, which is what lets a buyer with a paid order
///   write without a Ghost Key.
///
/// A request to buy on its own opens nothing: it costs nothing to send.
///
/// In a conversation that is open, a buyer's plain [`MessageContent::Text`]
/// is shown: that is how a buyer with a paid order writes without a Ghost
/// Key.
///
/// In a conversation that is not open:
///
/// * a buyer's plain [`MessageContent::Text`] is left out (a buyer with a
///   Ghost Key sends `VouchedText`), and so is text addressed to the BUYER:
///   that is the seller's reply direction, but both parties hold both keys
///   (`who`), so a script can flip the direction;
/// * the free text inside other steps is blanked rather than the step left
///   out, so what a request or a decline DOES (answering, counting) is
///   unchanged: a request's `note`, `shipping` (the address shows once it is
///   paid, [`SHIPPING_SHOWN_ONCE_PAID`]) and Buy now picks (region, choices),
///   and a decline's `reason`.
///
/// A request whose order's complaint window has closed (`address_hidden`,
/// [`request_address_hidden`]) shows [`crate::fulfilment::ADDRESS_HIDDEN`] in
/// place of its address, and no note, wherever it is.
///
/// Whatever this tab wrote itself (`authored_here`, by digest) is shown as
/// written: it is the seller's own text.
///
/// The count is of buyer text the seller did not see: buyer-direction
/// messages left out, and quote requests whose note or picks were blanked.
/// Not counted: an unpaid Buy now's blanked note or picks and a blanked
/// address (a seller is not told about an unpaid Buy now at all, so the
/// count would grow with every abandoned checkout), a blanked decline
/// (mostly the store's own answer to one), and reply-direction text left out
/// (as likely the seller's own, after a reload, as anyone's).
pub(crate) fn shown_to_seller(
    entries: Vec<MailboxEntry>,
    verifies: impl Fn(&harvest_common::sealed::MessageVoucher, &[u8; 32]) -> bool,
    paid: impl Fn(&[u8; 32]) -> bool,
    address_hidden: impl Fn(&MailboxEntry) -> bool,
    authored_here: impl Fn(&[u8; 32]) -> bool,
) -> (Vec<MailboxEntry>, usize) {
    let (verdicts, opened) = verdicts_and_open(&entries, &verifies, &paid);
    shown_given(entries, verdicts, &opened, address_hidden, authored_here)
}

/// Whether the request `entry` is answered by one of the store's orders
/// whose ship-to address the seller's app no longer shows (`retained` false,
/// `AppState::address_retained_for`: its complaint window has closed). A Buy
/// now is matched by its request id, a quote request by the order carrying
/// its binding and its listing's tag under this conversation's keys.
/// [`shown_to_seller`] then shows [`crate::fulfilment::ADDRESS_HIDDEN`] in
/// place of the address and blanks the note.
pub(crate) fn request_address_hidden(
    entry: &MailboxEntry,
    index: &OrderIndex<'_>,
    keys: Option<&crate::messaging::ConversationKeys>,
    retained: impl Fn(&harvest_common::payment::AuthorizedOrder) -> bool,
) -> bool {
    let MailboxEntry::Readable {
        conversation,
        content:
            MessageContent::OrderRequest {
                listing_id,
                order_binding,
                buyer_receipt_key,
                instant,
                ..
            },
        timestamp,
        ..
    } = entry
    else {
        return false;
    };
    let Ok(tag) = <[u8; 32]>::try_from(conversation.as_slice()) else {
        return false;
    };
    let answering = match instant {
        Some(selection) => selection
            .answered_request(&tag)
            .and_then(|request| index.order(&request.order_id())),
        None => keys.and_then(|keys| {
            index.quote_answering(
                *timestamp,
                order_binding,
                buyer_receipt_key,
                &keys.listing_tag(listing_id),
            )
        }),
    };
    answering.is_some_and(|order| !retained(order))
}

// How many `OrderIndex`es this thread has built, and how many lookups it
// has answered: lets a test prove the seller's inbox builds one per read,
// never one per conversation, and asks it once per request, never scanning
// every order per request (review after 01f2bcf).
#[cfg(test)]
thread_local! {
    pub(crate) static ORDER_INDEX_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static ORDER_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static BINDING_TAG_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The store's orders, indexed once per render for matching requests to
/// the orders answering them (codex on #205 round 3): by id, and each quote
/// order under its (binding, listing tag), sorted by (signed date, id). A
/// lookup then scans one buyer's orders for one listing, not all of a
/// store's (up to `MAX_ORDERS`), for each of up to 512 mailbox entries.
pub(crate) struct OrderIndex<'a> {
    by_id: std::collections::HashMap<
        &'a harvest_common::payment::OrderId,
        &'a harvest_common::payment::AuthorizedOrder,
    >,
    quotes: std::collections::HashMap<
        ([u8; 32], [u8; 32]),
        Vec<&'a harvest_common::payment::AuthorizedOrder>,
    >,
    /// Every order, a Buy now's too, by (binding, listing tag): what
    /// `unanswered_requests_in` matches a quote request against.
    by_binding_and_tag: std::collections::HashMap<
        ([u8; 32], [u8; 32]),
        Vec<&'a harvest_common::payment::AuthorizedOrder>,
    >,
}

impl<'a> OrderIndex<'a> {
    pub(crate) fn new(published: &'a [harvest_common::payment::AuthorizedOrder]) -> Self {
        #[cfg(test)]
        ORDER_INDEX_BUILDS.with(|n| n.set(n.get() + 1));
        let mut quotes: std::collections::HashMap<
            ([u8; 32], [u8; 32]),
            Vec<&'a harvest_common::payment::AuthorizedOrder>,
        > = std::collections::HashMap::new();
        let mut by_binding_and_tag: std::collections::HashMap<
            ([u8; 32], [u8; 32]),
            Vec<&'a harvest_common::payment::AuthorizedOrder>,
        > = std::collections::HashMap::new();
        for order in published {
            let Some(key) = order.order.order_binding.zip(order.order.listing_tag) else {
                continue;
            };
            by_binding_and_tag.entry(key).or_default().push(order);
            if order.order.request_id.is_none() {
                quotes.entry(key).or_default().push(order);
            }
        }
        for group in quotes.values_mut() {
            group.sort_by_key(|order| (order.order.created_at, order.order.id.0));
        }
        OrderIndex {
            by_binding_and_tag,
            by_id: published
                .iter()
                .map(|order| (&order.order.id, order))
                .collect(),
            quotes,
        }
    }

    /// Every order (a Buy now's too) carrying `binding` and `listing_tag`.
    pub(crate) fn with_binding_and_tag(
        &self,
        binding: &[u8; 32],
        listing_tag: &[u8; 32],
    ) -> &[&'a harvest_common::payment::AuthorizedOrder] {
        #[cfg(test)]
        BINDING_TAG_LOOKUPS.with(|n| n.set(n.get() + 1));
        self.by_binding_and_tag
            .get(&(*binding, *listing_tag))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The order with id `id`, if the store holds one.
    pub(crate) fn order(
        &self,
        id: &harvest_common::payment::OrderId,
    ) -> Option<&'a harvest_common::payment::AuthorizedOrder> {
        #[cfg(test)]
        ORDER_LOOKUPS.with(|n| n.set(n.get() + 1));
        self.by_id.get(id).copied()
    }

    /// The quote order answering an ask made at `asked_at` with `binding`,
    /// `receipt_key` and `listing_tag`, by [`quote_order_answers`]'s rule:
    /// among the orders with that binding and tag (and that receipt key, when
    /// the ask names one), sorted by (signed date, id), the first issued at
    /// or after the ask. Each earlier one was issued before the ask, which is
    /// exactly "after the previous such order and no later than this one",
    /// so at most one order answers any ask.
    pub(crate) fn quote_answering(
        &self,
        asked_at: chrono::DateTime<chrono::Utc>,
        binding: &[u8; 32],
        receipt_key: &Option<[u8; 32]>,
        listing_tag: &[u8; 32],
    ) -> Option<&'a harvest_common::payment::AuthorizedOrder> {
        self.quotes
            .get(&(*binding, *listing_tag))?
            .iter()
            .filter(|order| receipt_key.is_none() || order.order.buyer_receipt_key == *receipt_key)
            .find(|order| asked_at <= order.order.created_at)
            .copied()
    }
}

/// The conversations a seller's inbox shows free text in (see
/// [`shown_to_seller`]): those with a verified voucher, or with a paid order
/// of the store's own (`paid`). Also what decides whether a Buy now may be
/// answered by hand ([`offered_by_hand`]).
pub(crate) fn open_conversations(
    entries: &[MailboxEntry],
    verifies: impl Fn(&harvest_common::sealed::MessageVoucher, &[u8; 32]) -> bool,
    paid: impl Fn(&[u8; 32]) -> bool,
) -> std::collections::HashSet<Vec<u8>> {
    verdicts_and_open(entries, &verifies, &paid).1
}

fn verdicts_and_open(
    entries: &[MailboxEntry],
    verifies: &impl Fn(&harvest_common::sealed::MessageVoucher, &[u8; 32]) -> bool,
    paid: &impl Fn(&[u8; 32]) -> bool,
) -> (Vec<bool>, std::collections::HashSet<Vec<u8>>) {
    let tag_of = |conversation: &[u8]| <[u8; 32]>::try_from(conversation).ok();
    let vouched = |entry: &MailboxEntry| match entry {
        MailboxEntry::Readable {
            conversation,
            content: MessageContent::VouchedText { voucher, .. },
            ..
        } => tag_of(conversation).is_some_and(|tag| verifies(voucher, &tag)),
        _ => false,
    };
    // Verified once per entry: `verifies` may be an RSA chain check.
    let verdicts: Vec<bool> = entries.iter().map(vouched).collect();
    let opened: std::collections::HashSet<Vec<u8>> = entries
        .iter()
        .zip(&verdicts)
        .filter(|(entry, verified)| {
            **verified || tag_of(entry.conversation()).is_some_and(|tag| paid(&tag))
        })
        .map(|(entry, _)| entry.conversation().to_vec())
        .collect();
    (verdicts, opened)
}

fn shown_given(
    entries: Vec<MailboxEntry>,
    verdicts: Vec<bool>,
    opened: &std::collections::HashSet<Vec<u8>>,
    address_hidden: impl Fn(&MailboxEntry) -> bool,
    authored_here: impl Fn(&[u8; 32]) -> bool,
) -> (Vec<MailboxEntry>, usize) {
    use crate::messaging::Addressing;
    let mut hidden = 0;
    let mut shown = Vec::with_capacity(entries.len());
    for (mut entry, verified) in entries.into_iter().zip(verdicts) {
        // What this tab wrote itself (a seller's reply, or a decline it
        // sent) is the seller's own text: shown as written wherever it is.
        if authored_here(&entry.digest()) {
            shown.push(entry);
            continue;
        }
        let open = opened.contains(entry.conversation());
        let hide_address = address_hidden(&entry);
        let keep = match &mut entry {
            // Past the order's complaint window: hidden, not counted (it is
            // no buyer's message held back, and nothing is deleted).
            MailboxEntry::Readable {
                content: MessageContent::OrderRequest { note, shipping, .. },
                ..
            } if hide_address => {
                note.clear();
                *shipping = crate::fulfilment::ADDRESS_HIDDEN.to_string();
                true
            }
            MailboxEntry::Readable {
                content: MessageContent::VouchedText { .. },
                ..
            } => verified,
            // A buyer's plain text: shown only where a paid order opened the
            // conversation (a voucher opens it too, but a buyer holding one
            // sends `VouchedText`). Elsewhere it is what a script writing
            // past the compose gate sends.
            MailboxEntry::Readable {
                content: MessageContent::Text(_),
                addressing: Addressing::ToSeller,
                ..
            } => open,
            // Left out, not counted: in the reply direction it is as likely
            // the seller's own reply (after a reload this tab no longer knows
            // it wrote it) as a buyer's, and the count's line blames buyers.
            MailboxEntry::Readable {
                content: MessageContent::Text(_),
                addressing: Addressing::ToBuyer,
                ..
            } if !open => continue,
            MailboxEntry::Readable {
                content:
                    MessageContent::OrderRequest {
                        note,
                        shipping,
                        instant,
                        ..
                    },
                ..
            } if !open => {
                // Every free-text field a buyer fills, the picks included:
                // the terms the seller needs (the request and the total) are
                // not text and stay.
                let picks = instant.as_mut().map(|selection| {
                    let had = selection
                        .region
                        .take()
                        .is_some_and(|r| !r.trim().is_empty())
                        || !selection.choices.is_empty();
                    selection.choices.clear();
                    had
                });
                // Counted only for a quote request, the one kind the
                // seller is asked to answer. An unpaid Buy now is answered by
                // the store, and the seller never sees it: counting its note
                // would grow the line with every abandoned checkout.
                if instant.is_none() && (!note.trim().is_empty() || picks == Some(true)) {
                    hidden += 1;
                }
                note.clear();
                *shipping = SHIPPING_SHOWN_ONCE_PAID.to_string();
                true
            }
            MailboxEntry::Readable {
                content: MessageContent::Decline { reason },
                ..
            } if !open => {
                // Blanked, not counted: a decline in a conversation nothing
                // opened is mostly this store's own answer to an unpaid Buy
                // now ("sold out"), which is nobody's message to the seller.
                reason.clear();
                true
            }
            _ => true,
        };
        if keep {
            shown.push(entry);
        } else {
            hidden += 1;
        }
    }
    (shown, hidden)
}

/// Whether the quote order `order` is the one answering a quote request made
/// at `asked_at` carrying `binding` and `receipt_key`, for the listing whose
/// tag in this conversation is `listing_tag`.
///
/// An order does not say which ask it answered (it carries no quantity and
/// no request digest), and the binding, listing tag and receipt key are the
/// same for every ask for that listing in a conversation. So the ask is
/// placed in time: an order answers the asks made after the previous such
/// order was issued and no later than it was (its signed `created_at`). One
/// ask, one order, so a later order never shows an earlier order's address,
/// and a closed earlier order never hides a later one's. Two orders issued
/// in the same instant are ordered by id. The ask's time is its writer's
/// clock, the same caveat `unanswered_requests` gives. Residual: an order the
/// store's order cap has pruned is no longer there to bound the next one, so
/// that one then also claims the pruned order's asks (a false "more than one
/// version", or the pruned order's address, on its card); nothing the reader
/// holds says where the pruned order's asks ended.
pub(crate) fn quote_order_answers(
    order: &harvest_common::payment::AuthorizedOrder,
    published: &[harvest_common::payment::AuthorizedOrder],
    asked_at: chrono::DateTime<chrono::Utc>,
    binding: &[u8; 32],
    receipt_key: &Option<[u8; 32]>,
    listing_tag: &[u8; 32],
) -> bool {
    OrderIndex::new(published)
        .quote_answering(asked_at, binding, receipt_key, listing_tag)
        .is_some_and(|answering| answering.order.id == order.order.id)
}

/// [`quote_order_answers`] as first written, one full scan per question:
/// the reference the indexed version is checked against.
#[cfg(test)]
fn quote_order_answers_by_scan(
    order: &harvest_common::payment::AuthorizedOrder,
    published: &[harvest_common::payment::AuthorizedOrder],
    asked_at: chrono::DateTime<chrono::Utc>,
    binding: &[u8; 32],
    receipt_key: &Option<[u8; 32]>,
    listing_tag: &[u8; 32],
) -> bool {
    let same = |o: &harvest_common::payment::AuthorizedOrder| {
        o.order.request_id.is_none()
            && o.order.order_binding == Some(*binding)
            && o.order.listing_tag == Some(*listing_tag)
            && (receipt_key.is_none() || o.order.buyer_receipt_key == *receipt_key)
    };
    if !same(order) || asked_at > order.order.created_at {
        return false;
    }
    // Earlier by (signed date, id): two orders issued in the same instant
    // are ordered by id, so they cannot both claim the same asks.
    let this = (order.order.created_at, order.order.id.0);
    published
        .iter()
        .filter(|o| same(o) && (o.order.created_at, o.order.id.0) < this)
        .map(|o| o.order.created_at)
        .max()
        .is_none_or(|previous| asked_at > previous)
}

/// Whether the seller's inbox offers to answer `request` by hand. A Buy now
/// only in an open conversation ([`open_conversations`]: a verified voucher
/// or a paid order of the store's in it): elsewhere its picks are blanked, so the seller
/// could not check the total against them, and a Buy now from a buyer who
/// has neither vouched nor paid is not the seller's to answer (the store
/// answers it itself). Openness is per conversation on purpose: only the
/// holder of that conversation's key can write under its tag, so a voucher
/// or payment there speaks for every request in it. A quote request (from
/// before fixed prices) is offered as before.
fn offered_by_hand(request: &PendingRequest, open: bool) -> bool {
    request.instant.is_none() || open
}

/// What a seller reads in place of the address on a request whose
/// conversation is not open ([`shown_to_seller`]).
pub(crate) const SHIPPING_SHOWN_ONCE_PAID: &str = "(shown once it is paid)";

/// What each conversation in a seller's inbox lets an order be matched
/// against (`order_threads::ConversationClaims`), in tag order (never in
/// any order a writer chooses): the requests to buy read in it, in either direction (only the two holders
/// of its keys can write a readable entry, and the order must still be the
/// store's own), and the store's current listings, under that conversation's
/// keys when this seller holds them.
pub(crate) fn seller_claims<'a>(
    entries: &[MailboxEntry],
    listings: &[harvest_common::listing::AuthorizedListing],
    keys_for: impl Fn(&[u8]) -> Option<&'a crate::messaging::ConversationKeys>,
) -> Vec<([u8; 32], crate::order_threads::ConversationClaims)> {
    // Canonical tags only (`messaging::is_canonical_tag`): a twin shares its
    // keys with a real conversation and would claim that conversation's
    // orders. Ordered by tag, never by anything a writer chooses.
    // And only tags with something readable: the mailbox is open-write, so
    // anyone can fill it with unreadable entries under fresh tags, which
    // must not each cost a scan of every order (review round 4 of #205).
    // Unreadable entries are counted on their own.
    // One pass: each readable canonical tag, with the requests read under it
    // (review after 1bd9bcd: a scan of every entry per tag was tags ×
    // entries).
    type Requests<'e> = Vec<(
        &'e harvest_common::listing::ListingId,
        Option<&'e crate::messaging::InstantSelection>,
    )>;
    let mut by_tag: std::collections::BTreeMap<[u8; 32], Requests<'_>> =
        std::collections::BTreeMap::new();
    for entry in entries {
        let MailboxEntry::Readable {
            conversation,
            content,
            ..
        } = entry
        else {
            continue;
        };
        if !crate::messaging::is_canonical_tag(conversation) {
            continue;
        }
        let Ok(tag) = <[u8; 32]>::try_from(conversation.as_slice()) else {
            continue;
        };
        let requests = by_tag.entry(tag).or_default();
        if let MessageContent::OrderRequest {
            listing_id,
            instant,
            ..
        } = content
        {
            requests.push((listing_id, instant.as_ref()));
        }
    }
    by_tag
        .into_iter()
        .map(|(tag, requests)| {
            // The tag key derived once per conversation, not per listing.
            let tagger = keys_for(&tag).map(|keys| keys.listing_tagger());
            let claims = crate::order_threads::ConversationClaims::of(
                &tag,
                requests,
                listings.iter().map(|l| &l.listing.id),
                |listing| tagger.as_ref().map(|tagger| tagger.tag(listing)),
            );
            (tag, claims)
        })
        .collect()
}

/// Each readable conversation in a seller's inbox with the store's orders
/// belonging to it ([`seller_claims`] matched through
/// `order_threads::OrderLookup`, never conversation by order), each with
/// whether by its request: what [`paid_set`] and the threads read.
pub(crate) type Members<'o> = Vec<(
    [u8; 32],
    Vec<(&'o harvest_common::payment::AuthorizedOrder, bool)>,
)>;

pub(crate) fn seller_members<'a, 'o>(
    entries: &[MailboxEntry],
    published: &'o [harvest_common::payment::AuthorizedOrder],
    listings: &[harvest_common::listing::AuthorizedListing],
    keys_for: impl Fn(&[u8]) -> Option<&'a crate::messaging::ConversationKeys>,
) -> Members<'o> {
    let lookup = crate::order_threads::OrderLookup::new(published);
    seller_claims(entries, listings, keys_for)
        .iter()
        .map(|(tag, claims)| (*tag, lookup.in_conversation(claims)))
        .collect()
}

/// The conversations one of the store's own paid orders opens
/// (`order_threads::conversation_has_paid_order`): THE seller's paid set,
/// which `seller_inbox` and [`paid_conversations`] both take, so a test of
/// either tests the gate the inbox runs (review after 6c61839).
pub(crate) fn paid_set(members: &Members<'_>) -> std::collections::HashSet<[u8; 32]> {
    members
        .iter()
        .filter(|(_, orders)| crate::order_threads::conversation_has_paid_order(orders))
        .map(|(tag, _)| *tag)
        .collect()
}

/// [`paid_set`] over a mailbox: what opens a conversation to the seller
/// without a voucher ([`shown_to_seller`]).
pub(crate) fn paid_conversations<'a>(
    entries: &[MailboxEntry],
    published: &[harvest_common::payment::AuthorizedOrder],
    listings: &[harvest_common::listing::AuthorizedListing],
    keys_for: impl Fn(&[u8]) -> Option<&'a crate::messaging::ConversationKeys>,
) -> std::collections::HashSet<[u8; 32]> {
    paid_set(&seller_members(entries, published, listings, keys_for))
}

/// [`unanswered_requests_in`] over `published`, indexed: the shape this
/// module's tests ask in.
#[cfg(test)]
fn unanswered_requests(
    entries: &[MailboxEntry],
    listings: &[harvest_common::listing::AuthorizedListing],
    published: &[harvest_common::payment::AuthorizedOrder],
    keys: Option<&crate::messaging::ConversationKeys>,
) -> Vec<PendingRequest> {
    unanswered_requests_in(entries, listings, &OrderIndex::new(published), keys)
}

/// The requests to buy in a conversation still waiting for the seller's
/// answer, matched against the store's orders through `index` (review after
/// 6c61839: a scan of every order per request was requests × orders on
/// each read of the inbox, and requests in unopened conversations reach it).
///
/// `entries` is a seller's own inbox view, which `mailbox_entries` returns
/// newest first. The result is ordered by content digest (see the end of the
/// function for why).
///
/// # Why direction is not checked here, and where it IS
///
/// This is the seller's side, and it deliberately does NOT mirror the buyer's
/// rule (`state::AppState::buyer_purchases`, which ignores an acceptance not
/// addressed to the buyer). `MailboxEntry::Readable` does carry
/// `addressing`, so the check is available -- an earlier version of this
/// comment said it was not, which was simply false and is corrected here
/// rather than quietly dropped, because a reader auditing why the two sides
/// differ was being given one true reason and one invented one.
///
/// The true reason stands on its own: a request the SELLER composed is one
/// they wrote to themselves, and acting on it costs them their own
/// derivation index and publishes a commitment nobody will pay. There is
/// nothing for a third party to gain, because there is no third party -- only
/// the two holders of the conversation key can produce a readable entry at
/// all. What protects the BUYER is not this filter but the binding: accepting
/// publishes a commitment carrying a value only the real buyer can match.
fn unanswered_requests_in(
    entries: &[MailboxEntry],
    listings: &[harvest_common::listing::AuthorizedListing],
    index: &OrderIndex<'_>,
    keys: Option<&crate::messaging::ConversationKeys>,
) -> Vec<PendingRequest> {
    let mut requests: Vec<PendingRequest> = Vec::new();
    for entry in entries {
        let MailboxEntry::Readable {
            content:
                MessageContent::OrderRequest {
                    listing_id,
                    quantity,
                    order_binding,
                    buyer_receipt_key,
                    instant,
                    ..
                },
            digest,
            timestamp,
            conversation,
            ..
        } = entry
        else {
            continue;
        };
        // Already answered, decided from the seller's OWN published state
        // rather than from anything in the mailbox: an order carrying this
        // request's binding and this listing's tag is the answer to it. The
        // buyer cannot forge one. The tag stands in for the listing id orders
        // no longer publish (harvest#57); only this conversation's keys can
        // compute it.
        // An instant request is answered by exactly one order: the one its
        // request id names (`OrderId::for_request`), whatever its status. The
        // binding-and-tag rule below would also count any other order in the
        // conversation for the same listing, and so hide a second instant
        // request the delegate left for the seller.
        let request = instant.as_ref().and_then(|selection| {
            let tag: [u8; 32] = conversation.as_slice().try_into().ok()?;
            selection.answered_request(&tag)
        });
        if let Some(request) = request {
            if index.order(&request.order_id()).is_some() {
                continue;
            }
        }
        let answered = request.is_none()
            && keys.is_some_and(|keys| {
                let tag = keys.listing_tag(listing_id);
                let answers: Vec<&harvest_common::payment::AuthorizedOrder> = index
                    .with_binding_and_tag(order_binding, &tag)
                    .iter()
                    .copied()
                    .filter(|order| {
                        order.order.order_binding == Some(*order_binding)
                        && order.order.listing_tag == Some(tag)
                        // A request carrying the buyer's receipt key
                        // (harvest#53 Phase B) is answered only by an order
                        // carrying THAT key: an order without it is one the
                        // buyer refuses to pay (`CommitmentLacksBuyerKey`),
                        // and the buyer is told to send the request again.
                        && (buyer_receipt_key.is_none()
                            || order.order.buyer_receipt_key == *buyer_receipt_key)
                    })
                    .collect();
                if answers
                    .iter()
                    .any(|order| order.status != harvest_common::payment::OrderStatus::Cancelled)
                {
                    return true;
                }
                // Only CANCELLED answers. The buyer can now withdraw one (the
                // buyer cancel, harvest#53 Phase B), and "cancel it and ask
                // again" is the ordinary way to put a mistake right -- but the
                // binding, the tag and the key are all fixed per conversation, so
                // the cancelled order matches the new request exactly as it
                // matched the old one. Nothing published says WHICH ask an order
                // answered (an order carries no quantity and no request digest),
                // so the ask is placed in time instead: a cancelled order answers
                // every ask made up to the moment the seller issued it (its
                // signed `created_at`), and an ask made after the newest
                // cancelled answer is waiting. That holds however the seller
                // chose among several asks, and however often one was resent
                // (round 4 of harvest#136: an earlier count of distinct asks
                // against cancelled orders re-offered a withdrawn request
                // whenever the seller had not answered oldest first).
                //
                // The ask's time is the writer's own timestamp, so a buyer can
                // only move their own asks. A buyer whose clock runs behind the
                // seller's by more than the time between the seller issuing and
                // the buyer asking again is not surfaced until they ask later.
                // The other direction: a buyer whose clock runs AHEAD of the
                // seller's by more than the seller took to answer stamps the
                // answered ask after `issued`, so once that answer is cancelled
                // the ask is offered to the seller again although the buyer
                // withdrew it. No tolerance is added for either, because one
                // would widen the first case's wait to cure the second.
                answers
                    .iter()
                    .map(|order| order.order.created_at)
                    .max()
                    .is_some_and(|issued| *timestamp <= issued)
            });
        if answered {
            continue;
        }
        // One control per distinct request. Two identical requests are one
        // ask repeated, and offering the seller two controls for it would
        // invite two published debts for one order.
        if requests.iter().any(|held| {
            held.listing_id == *listing_id
                && held.quantity == *quantity
                && held.buyer_receipt_key == *buyer_receipt_key
                && held.instant.map(|i| i.request) == request
        }) {
            continue;
        }
        requests.push(PendingRequest {
            listing_id: listing_id.clone(),
            listing_title: listings
                .iter()
                .find(|listing| listing.listing.id == *listing_id)
                .map(|listing| listing.listing.title.clone())
                .unwrap_or_default(),
            quantity: *quantity,
            order_binding: *order_binding,
            buyer_receipt_key: *buyer_receipt_key,
            digest: *digest,
            instant: instant
                .as_ref()
                .zip(request)
                .map(|(selection, request)| InstantAnswer {
                    request,
                    total_sats: selection.expected_total_sats,
                }),
        });
    }
    // An unkeyed request with a keyed twin (same listing, quantity and
    // binding: a buyer's resend from a build that carries the receipt key,
    // harvest#53 Phase B) is one ask, not two. Only the keyed one is offered:
    // accepting the unkeyed one would publish an order the buyer refuses to
    // pay, and the keyed control would then invite a second debt.
    let keyed: Vec<(harvest_common::listing::ListingId, u32, [u8; 32])> = requests
        .iter()
        .filter(|r| r.buyer_receipt_key.is_some())
        .map(|r| (r.listing_id.clone(), r.quantity, r.order_binding))
        .collect();
    requests.retain(|r| {
        r.buyer_receipt_key.is_some()
            || !keyed.contains(&(r.listing_id.clone(), r.quantity, r.order_binding))
    });
    // Ordered by the entry's own content digest, NOT by the timestamp
    // `entries` arrives in. That timestamp is chosen by whoever wrote the
    // message and signed by nobody -- `read_mailbox` says so where it sorts
    // on it, and calls it a display order -- so letting it decide which
    // request a seller answers first would put the choice of what gets priced
    // in the buyer's clock. The digest is content-derived and total.
    requests.sort_by_key(|request| request.digest);
    requests
}

/// One request a seller has not yet answered, as the accept control needs it.
///
/// A struct rather than a tuple because the accept control publishes a
/// commitment out of every one of these fields, and a positional call that
/// swapped two of them would price the wrong listing or bind the commitment
/// to the wrong buyer.
#[derive(Clone, Debug, PartialEq)]
struct PendingRequest {
    listing_id: harvest_common::listing::ListingId,
    /// The listing's title as the SELLER's own store publishes it, or empty
    /// when this store's listings have not arrived.
    ///
    /// Deliberately not taken from the message: the buyer names a listing by
    /// id, and a title carried in their message would be a name the buyer
    /// chose for the thing the seller is about to price.
    listing_title: String,
    quantity: u32,
    order_binding: [u8; 32],
    /// The buyer's receipt key from the request (harvest#53 Phase B), copied
    /// into the commitment the same way `order_binding` is.
    buyer_receipt_key: Option<[u8; 32]>,
    /// `harvest_common::mailbox::entry_digest` of the message this came from.
    ///
    /// Used to order the controls deterministically without consulting a
    /// timestamp the sender chose, and to key the rendered list.
    digest: [u8; 32],
    /// Set when the buyer sent this with instant checkout.
    instant: Option<InstantAnswer>,
}

/// What a seller answering an instant-checkout request by hand carries over
/// from it: the request id, so their order and any the delegate issued for
/// the same request are one order in the store (`Order::request_id`), and the
/// total the buyer was shown, to start the amount from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InstantAnswer {
    pub request: harvest_common::payment::AnsweredRequest,
    pub total_sats: u64,
}

/// Enough of a conversation tag to tell two apart on screen, and no more --
/// the whole thing is 44 characters of base58 that means nothing to a reader.
///
/// One implementation, in `state`, because the same shortening appears in
/// notifications this component does not render: two would drift, and a
/// buyer matching a warning against a line on screen needs them identical.
fn short_tag(tag: &[u8]) -> String {
    crate::state::short_conversation_tag(tag)
}

/// Seal a seller's reply and hand it to the node.
fn reply(store_contract_id: &[u8], tag: &[u8], text: String) -> Result<(), String> {
    let text_for_record = text.clone();
    let (sealed, mailbox) = {
        let state = APP_STATE.read();
        let sealed = state.compose_reply(store_contract_id, tag, text)?;
        let mailbox = state
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.mailbox_contract_id.clone())
            .ok_or("this store's mailbox id is not known, so there is nowhere to reply into")?;
        (sealed, mailbox)
    };
    dispatch_reply(mailbox, sealed.clone());

    // Recorded for the same reason the buyer's messages are: it is the only
    // thing this browser can know about authorship. Without it the seller's
    // own reply comes back from the mailbox indistinguishable from one a
    // buyer wrote in that direction.
    APP_STATE
        .write()
        .record_sent_message(store_contract_id, text_for_record, &sealed);
    Ok(())
}

/// Hand a sealed reply to the local node. Fire-and-forget for the same
/// reason `dispatch` is; see `gateway::mailbox_ops::send_message`.
fn dispatch_reply(_mailbox: Vec<u8>, _sealed: harvest_common::mailbox::EncryptedMessage) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::mailbox_ops::reply_to_mailbox(&_mailbox, _sealed).await {
            dioxus::logger::tracing::error!("Failed to send reply: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Your reply could not be sent: {e}"));
        }
    });
}

/// How many buyers' requests in one of our stores' inboxes are still waiting
/// for an invoice: the count My store shows beside Orders and in the top
/// navigation, so a seller sees that a request arrived without opening the
/// inbox (harvest#93 phase 2).
///
/// The same rule the inbox itself uses to offer the accept control
/// ([`unanswered_requests`]), per conversation, so the count and the controls
/// cannot disagree.
pub(crate) fn requests_awaiting_invoice(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
) -> usize {
    let Some(store) = state.browsing_stores.get(store_contract_id) else {
        return 0;
    };
    count_unanswered(
        state.mailbox_entries(store_contract_id),
        &store.listings,
        &store.orders,
        |tag| state.conversation_keys.get(tag),
        |listing| store.availability(listing).is_buyable(),
    )
}

/// [`requests_awaiting_invoice`] in the one conversation `tag`: what the
/// Home page's "Answer ..." row and the Messages page's "Needs an invoice"
/// say, so each row is one the header counted (review of #214).
pub(crate) fn requests_awaiting_invoice_in(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: &[u8; 32],
) -> usize {
    let Some(store) = state.browsing_stores.get(store_contract_id) else {
        return 0;
    };
    count_unanswered(
        state
            .mailbox_entries(store_contract_id)
            .into_iter()
            .filter(|entry| entry.conversation() == tag.as_slice())
            .collect(),
        &store.listings,
        &store.orders,
        |tag| state.conversation_keys.get(tag),
        |listing| store.availability(listing).is_buyable(),
    )
}

/// [`requests_awaiting_invoice`] over given entries, grouped by conversation,
/// each group judged with its own conversation's keys.
///
/// Counts only requests for a listing the store holds and still has on sale.
/// The inbox still offers Accept on the others (a buyer who asked before an
/// item sold out, or before an edit replaced it, can still be invoiced), but
/// a count the seller cannot bring to zero by answering, since a reply that
/// declines publishes no order, teaches them to ignore it.
fn count_unanswered<'a>(
    entries: Vec<MailboxEntry>,
    listings: &[harvest_common::listing::AuthorizedListing],
    published: &[harvest_common::payment::AuthorizedOrder],
    keys_for: impl Fn(&[u8]) -> Option<&'a crate::messaging::ConversationKeys>,
    on_sale: impl Fn(&harvest_common::listing::ListingId) -> bool,
) -> usize {
    // Grouped in one pass, and matched through one index (review after
    // 6c61839): the header asks for this on every state change.
    let index = OrderIndex::new(published);
    let mut conversations: std::collections::BTreeMap<Vec<u8>, Vec<MailboxEntry>> =
        std::collections::BTreeMap::new();
    for entry in entries {
        conversations
            .entry(entry.conversation().to_vec())
            .or_default()
            .push(entry);
    }
    conversations
        .iter()
        .map(|(tag, group)| {
            unanswered_requests_in(group, listings, &index, keys_for(tag))
                .iter()
                // Not a Buy now: an unpaid one is not an order and does not
                // need the seller (Ian, 2026-09-26). The seller's store
                // answers every Buy now it reads, with an invoice or a
                // decline saying why; one whose invoice the store refused is
                // decided again on its next run (`auto_invoice::
                // on_store_update_answer`), and one it has not read yet when
                // it next runs. The inbox still offers the seller the control
                // to answer one by hand. (A timer on the buyer's envelope
                // time was tried and dropped in review: that clock is the
                // buyer's, and a decline cannot be matched to its request.)
                .filter(|request| request.instant.is_none())
                .filter(|request| {
                    listings.iter().any(|l| l.listing.id == request.listing_id)
                        && on_sale(&request.listing_id)
                })
                .count()
        })
        .sum()
}

#[cfg(test)]
mod inbox_tests {
    use super::*;
    use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};

    const BINDING: [u8; 32] = [0x5a; 32];

    /// [`request_address_hidden`] over `published`, indexed as a render does.
    fn hidden_by_index(
        entry: &MailboxEntry,
        published: &[harvest_common::payment::AuthorizedOrder],
        keys: Option<&crate::messaging::ConversationKeys>,
        retained: impl Fn(&harvest_common::payment::AuthorizedOrder) -> bool,
    ) -> bool {
        request_address_hidden(entry, &OrderIndex::new(published), keys, retained)
    }

    fn listing(id: ListingId, title: &str) -> AuthorizedListing {
        AuthorizedListing {
            listing: Listing {
                checkout: None,
                choices: Vec::new(),
                id,
                title: title.to_string(),
                description: String::new(),
                kind: ListingKind::Sale,
                price: None,
                created_at: chrono::Utc::now(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            certificate_pem: String::new(),
        }
    }

    fn readable(content: MessageContent, digest: [u8; 32]) -> MailboxEntry {
        MailboxEntry::Readable {
            conversation: vec![1u8; 32],
            conversation_id: harvest_common::mailbox::ConversationId([2u8; 32]),
            addressing: crate::messaging::Addressing::ToSeller,
            timestamp: chrono::Utc::now(),
            nonce: [0u8; 24],
            digest,
            content,
        }
    }

    fn keys() -> crate::messaging::ConversationKeys {
        crate::messaging::ConversationKeys::from_shared_secret(&[4u8; 32])
    }

    fn request(listing_id: ListingId, quantity: u32, digest: [u8; 32]) -> MailboxEntry {
        readable(
            MessageContent::OrderRequest {
                instant: None,
                listing_id,
                quantity,
                shipping: "12 Example St".into(),
                note: String::new(),
                order_binding: BINDING,
                buyer_receipt_key: None,
            },
            digest,
        )
    }

    /// A published commitment with order id `[n; 32]` under `binding`, built
    /// by hand: only the two fields the answered-check reads matter here, and
    /// signing one would test the signature path instead.
    fn published(
        n: u8,
        binding: Option<[u8; 32]>,
        tag: Option<[u8; 32]>,
    ) -> harvest_common::payment::AuthorizedOrder {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        harvest_common::payment::AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: None,
                id: harvest_common::payment::OrderId([n; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                amount_sats: 1,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: Vec::new(),
                payment_address: String::new(),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: binding,
                listing_tag: tag,
                buyer_receipt_key: None,
                created_at,
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: harvest_common::payment::OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// An instant request is answered only by the order its request id
    /// names: another order for the same listing in the same conversation
    /// (the binding and tag match) does not hide it, and two instant requests
    /// that differ only in their nonce are two asks. The accept control
    /// carries the request id and the buyer's total. Mutated red by letting
    /// the binding-and-tag rule decide an instant request.
    #[test]
    fn an_instant_request_is_answered_only_by_its_own_order() {
        let id = ListingId([9u8; 32]);
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let instant = |nonce: u8, digest: u8| {
            readable(
                MessageContent::OrderRequest {
                    instant: Some(crate::messaging::InstantSelection {
                        requested_at_ms: 1_700_000_000_000,
                        nonce: [nonce; 16],
                        region: None,
                        choices: vec![],
                        expected_total_sats: 12_000,
                    }),
                    listing_id: id.clone(),
                    quantity: 1,
                    shipping: "12 Example St".into(),
                    note: String::new(),
                    order_binding: BINDING,
                    buyer_receipt_key: None,
                },
                [digest; 32],
            )
        };
        let request = |nonce: u8| harvest_common::payment::AnsweredRequest {
            request_id: harvest_common::payment::request_id(&[1u8; 32], &[nonce; 16]),
            requested_at: chrono::DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
        };
        let entries = vec![instant(1, 1), instant(2, 2)];
        let found = unanswered_requests(&entries, &listings, &[], Some(&keys()));
        assert_eq!(found.len(), 2, "two asks");
        assert_eq!(
            found
                .iter()
                .map(|r| r.instant.unwrap().request.request_id)
                .collect::<std::collections::BTreeSet<_>>(),
            [request(1).request_id, request(2).request_id].into()
        );
        assert!(found
            .iter()
            .all(|r| r.instant.unwrap().total_sats == 12_000));

        // The first ask answered by its own order; an unrelated order in the
        // same conversation for the same listing answers nothing.
        let mut answer = published(1, Some(BINDING), Some(keys().listing_tag(&id)));
        answer.order.id = request(1).order_id();
        let found = unanswered_requests(&entries, &listings, &[answer], Some(&keys()));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].instant.unwrap().request, request(2));
    }

    /// A Buy now is offered for a hand answer only in an open conversation,
    /// where its picks can be read; a quote request is offered as before.
    /// Mutated red by offering every Buy now.
    #[test]
    fn a_buy_now_is_answered_by_hand_only_in_an_open_conversation() {
        let id = ListingId([9u8; 32]);
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let request = |instant| {
            readable(
                MessageContent::OrderRequest {
                    instant,
                    listing_id: id.clone(),
                    quantity: 1,
                    shipping: "12 Example St".into(),
                    note: String::new(),
                    order_binding: BINDING,
                    buyer_receipt_key: None,
                },
                [1; 32],
            )
        };
        let buy_now = request(Some(crate::messaging::InstantSelection {
            requested_at_ms: 1_700_000_000_000,
            nonce: [1; 16],
            region: None,
            choices: vec![],
            expected_total_sats: 12_000,
        }));
        let found = unanswered_requests(&[buy_now], &listings, &[], Some(&keys()));
        assert_eq!(found.len(), 1);
        assert!(!offered_by_hand(&found[0], false));
        assert!(offered_by_hand(&found[0], true));
        let quote = unanswered_requests(&[request(None)], &listings, &[], Some(&keys()));
        assert!(offered_by_hand(&quote[0], false));
    }

    /// A seller's inbox opens a conversation for a paid order of the
    /// store's that belongs to it: a Buy now by its own request, a quote
    /// invoice by its listing tag. Not unpaid, not cancelled, not another
    /// order, not another conversation. Mutated red by dropping the paid
    /// check, and the id match.
    #[test]
    fn only_a_paid_order_opens_its_conversation() {
        use harvest_common::payment::OrderStatus;
        // A real buyer key: the inbox reads only tags in the prime-order
        // subgroup (`messaging::is_canonical_tag`).
        let tag =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([8u8; 32])).as_bytes();
        let under_tag = |mut entry: MailboxEntry| {
            if let MailboxEntry::Readable { conversation, .. } = &mut entry {
                *conversation = tag.to_vec();
            }
            entry
        };
        let selection = crate::messaging::InstantSelection {
            requested_at_ms: 1_700_000_000_000,
            nonce: [4; 16],
            region: None,
            choices: vec![],
            expected_total_sats: 12_000,
        };
        let id = ListingId([9u8; 32]);
        let buy_now = readable(
            MessageContent::OrderRequest {
                instant: Some(selection.clone()),
                listing_id: id.clone(),
                quantity: 1,
                shipping: "12 Example St".into(),
                note: String::new(),
                order_binding: BINDING,
                buyer_receipt_key: None,
            },
            [1u8; 32],
        );
        let own = selection.answered_request(&tag).unwrap();
        let mut order = published(1, Some(BINDING), None);
        order.order.id = own.order_id();
        order.order.request_id = Some(own.request_id);
        let k = keys();
        let paid = |orders: &[harvest_common::payment::AuthorizedOrder],
                    entries: &[MailboxEntry]| {
            paid_conversations(entries, orders, &[], |_| Some(&k))
        };
        let entries = [under_tag(buy_now)];
        assert!(paid(&[order.clone()], &entries).is_empty(), "unpaid");
        order.status = OrderStatus::Cancelled;
        assert!(paid(&[order.clone()], &entries).is_empty(), "cancelled");
        order.status = OrderStatus::Paid;
        assert_eq!(paid(&[order.clone()], &entries), [tag].into());
        // Paid and then reversed (a reorg) was still paid for: money was
        // spent to open it, which is the bar.
        let mut reversed = order.clone();
        reversed.status = OrderStatus::PaymentReversed;
        assert_eq!(paid(&[reversed], &entries), [tag].into());
        let mut other = order.clone();
        other.order.id = harvest_common::payment::OrderId([7; 32]);
        assert!(paid(&[other], &entries).is_empty(), "another order");

        // A paid quote invoice, by its listing tag under THIS
        // conversation's keys.
        let quote = under_tag(request(id.clone(), 1, [2u8; 32]));
        let mut invoice = published(2, Some(BINDING), Some(k.listing_tag(&id)));
        invoice.status = OrderStatus::Paid;
        assert_eq!(
            paid(&[invoice.clone()], std::slice::from_ref(&quote)),
            [tag].into()
        );
        let other_keys = crate::messaging::ConversationKeys::from_shared_secret(&[6u8; 32]);
        assert!(
            paid_conversations(std::slice::from_ref(&quote), &[invoice], &[], |_| {
                Some(&other_keys)
            })
            .is_empty(),
            "another conversation's keys"
        );
    }

    /// A request's address is hidden only when the order answering IT is
    /// past its window: a Buy now's own order by request id, a quote's by
    /// binding and listing tag under this conversation's keys. Another
    /// order, another binding, or no keys hides nothing. Red with the
    /// binding check dropped, and with the retention verdict ignored.
    #[test]
    fn only_the_answering_orders_window_hides_a_requests_address() {
        let id = ListingId([9u8; 32]);
        let selection = crate::messaging::InstantSelection {
            requested_at_ms: 1_700_000_000_000,
            nonce: [4; 16],
            region: None,
            choices: vec![],
            expected_total_sats: 12_000,
        };
        let buy_now = readable(
            MessageContent::OrderRequest {
                instant: Some(selection.clone()),
                listing_id: id.clone(),
                quantity: 1,
                shipping: "12 Example St".into(),
                note: String::new(),
                order_binding: BINDING,
                buyer_receipt_key: None,
            },
            [1u8; 32],
        );
        let mut own = published(1, Some(BINDING), None);
        own.order.id = selection.answered_request(&[1u8; 32]).unwrap().order_id();
        let k = keys();
        assert!(hidden_by_index(&buy_now, &[own.clone()], Some(&k), |_| {
            false
        }));
        assert!(!hidden_by_index(&buy_now, &[own], Some(&k), |_| { true }));
        let other = published(2, Some(BINDING), None);
        assert!(!hidden_by_index(&buy_now, &[other], Some(&k), |_| false));

        let mut quote = request(id.clone(), 1, [2u8; 32]);
        let invoice = published(3, Some(BINDING), Some(k.listing_tag(&id)));
        // Asked before the invoice was issued, as an answered ask is.
        if let MailboxEntry::Readable { timestamp, .. } = &mut quote {
            *timestamp = invoice.order.created_at - chrono::Duration::minutes(1);
        }
        assert!(hidden_by_index(
            &quote,
            std::slice::from_ref(&invoice),
            Some(&k),
            |_| false
        ));
        assert!(!hidden_by_index(
            &quote,
            std::slice::from_ref(&invoice),
            None,
            |_| false
        ));
        let mut elsewhere = invoice;
        elsewhere.order.order_binding = Some([0x11; 32]);
        assert!(!hidden_by_index(&quote, &[elsewhere], Some(&k), |_| false));
    }

    fn thread(tag: u8, open: bool, said: bool, waiting: usize, orders: &[u8]) -> SellerThread {
        let at = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).unwrap();
        let mut text = readable(MessageContent::Text(format!("from {tag}")), [tag; 32]);
        if let MailboxEntry::Readable { timestamp, .. } = &mut text {
            *timestamp = at(1_700_000_000 + i64::from(tag));
        }
        SellerThread {
            tag: [tag; 32],
            open,
            entries: vec![text],
            lines: if said {
                vec![ChatLine {
                    who: "Buyer",
                    mine: false,
                    trusted: true,
                    when: String::new(),
                    item: ChatItem::Said("hi".into()),
                }]
            } else {
                Vec::new()
            },
            waiting,
            orders: orders
                .iter()
                .map(|n| harvest_common::payment::OrderId([*n; 32]))
                .collect(),
            by_request: Vec::new(),
            awaiting_reply: false,
            order_refs: Vec::new(),
        }
    }

    /// **A conversation is a question worth answering when it holds one**:
    /// something said in an open conversation, or a request waiting for the
    /// seller. Red with `is_question` always true.
    #[test]
    fn a_question_is_something_to_answer() {
        assert!(is_question(&thread(1, true, true, 0, &[])), "said, open");
        assert!(
            !is_question(&thread(3, false, true, 0, &[])),
            "said, but not open"
        );
        assert!(
            !is_question(&thread(4, true, false, 0, &[])),
            "open, nothing said"
        );
        assert!(
            is_question(&thread(5, false, false, 1, &[])),
            "a request waits"
        );
    }

    /// **A conversation waits for the seller's reply when the buyer wrote
    /// last** (msg1 critique MSG-3), and only an open one with readable buyer
    /// text: an unopened conversation, junk and a request never count. Seen
    /// live at different moments, a buyer line and a reply are ordered by
    /// first sight, whatever either clock says; seen together (when the page
    /// opened), by their timestamps, a buyer line dated in the future being
    /// answered by any reply (reviews after 9417fbf, 1bd9bcd and 6c61839).
    /// Red with the open check dropped, with first sight ignored, with the
    /// future-dated rule dropped, and with the store's automatic declines
    /// counted as replies. (The cap on a reply's timestamp cannot change an
    /// outcome; see `awaiting_reply`.)
    #[test]
    fn a_conversation_waits_for_a_reply_only_when_the_buyer_wrote_last() {
        use crate::messaging::Addressing::{ToBuyer, ToSeller};
        let at = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).unwrap();
        // When the page opened: everything not listed was first seen then.
        const OPENED: i64 = 50_000;
        let mut next = 0u8;
        let mut said = |addressing, secs: i64, content: MessageContent| {
            next += 1;
            let mut entry = readable(content, [next; 32]);
            if let MailboxEntry::Readable {
                timestamp,
                addressing: a,
                ..
            } = &mut entry
            {
                *timestamp = at(secs);
                *a = addressing;
            }
            entry
        };
        let text = |t: &str| MessageContent::Text(t.into());
        let decline = |r: &str| MessageContent::Decline { reason: r.into() };
        let seen = |live: Vec<(&MailboxEntry, i64)>| {
            let live: Vec<([u8; 32], i64)> = live.iter().map(|(e, s)| (e.digest(), *s)).collect();
            move |digest: &[u8; 32]| {
                at(live
                    .iter()
                    .find(|(d, _)| d == digest)
                    .map(|(_, s)| *s)
                    .unwrap_or(OPENED))
            }
        };

        // On the page when it opened: the timestamps decide.
        let buyer = said(ToSeller, 5_000, text("is it on its way?"));
        assert!(awaiting_reply(
            true,
            std::slice::from_ref(&buyer),
            seen(vec![])
        ));
        assert!(
            !awaiting_reply(false, std::slice::from_ref(&buyer), seen(vec![])),
            "an unopened conversation never counts"
        );
        let reply = said(ToBuyer, 6_000, text("posted today"));
        assert!(!awaiting_reply(
            true,
            &[buyer.clone(), reply.clone()],
            seen(vec![])
        ));

        // A quick follow-up seen live after a reply seen live: waits.
        let follow_up = said(ToSeller, 6_200, text("thanks, which carrier?"));
        assert!(awaiting_reply(
            true,
            &[reply.clone(), follow_up.clone()],
            seen(vec![(&reply, 6_000), (&follow_up, 6_200)])
        ));
        // ... even from a buyer whose clock runs 5 minutes slow: replied at
        // 9_900, follow-up stamped 9_700, seen at 10_000.
        let late_reply = said(ToBuyer, 9_900, text("posted"));
        let slow = said(ToSeller, 9_700, text("thanks!"));
        assert!(awaiting_reply(
            true,
            &[late_reply.clone(), slow.clone()],
            seen(vec![(&late_reply, 9_900), (&slow, 10_000)])
        ));

        // A buyer 5 minutes fast, seen at 10_000, answered at 10_100.
        let fast = said(ToSeller, 10_300, text("sent just now"));
        let answer = said(ToBuyer, 10_100, text("on it"));
        assert!(!awaiting_reply(
            true,
            &[fast.clone(), answer.clone()],
            seen(vec![(&fast, 10_000), (&answer, 10_100)])
        ));
        // After a reload both were first seen when the page opened, and the
        // timestamps decide: a buyer clock ahead of this device's, answered
        // within its lead, reads as waiting again (a residual the
        // `awaiting_reply` doc names).
        assert!(awaiting_reply(true, &[fast, answer], seen(vec![])));

        // A buyer line dated in the future, seen at 5_000, answered by a
        // reply seen at 6_000: answered.
        let future = said(ToSeller, 99_999, text("reply to me forever"));
        assert!(!awaiting_reply(
            true,
            &[future.clone(), reply.clone()],
            seen(vec![(&future, 5_000), (&reply, 6_000)])
        ));
        // ... and after a reload too (review after 6c61839): a date that
        // cannot be true is answered by the reply, so the count can't be
        // pinned on. With no reply at all, it waits.
        assert!(!awaiting_reply(
            true,
            &[future.clone(), reply.clone()],
            seen(vec![])
        ));
        assert!(awaiting_reply(
            true,
            std::slice::from_ref(&future),
            seen(vec![])
        ));

        // Both dated in the future and on the page when it opened: the buyer
        // line's date is after it was first seen, so it cannot be true and
        // any reply answers it; the buyer's later date does not win.
        let far = said(ToSeller, 99_999, text("far"));
        let far_reply = said(ToBuyer, 80_000, text("far reply"));
        assert!(!awaiting_reply(true, &[far, far_reply], seen(vec![])));

        // A reply dated in the future answers only what was seen before it.
        let future_reply = said(ToBuyer, 99_999, text("done"));
        let after_it = said(ToSeller, 7_000, text("not received"));
        assert!(awaiting_reply(
            true,
            &[future_reply.clone(), after_it.clone()],
            seen(vec![(&future_reply, 6_000), (&after_it, 7_000)])
        ));

        // The store's own automatic decline is not a reply; the seller's is.
        let store_decline = said(ToBuyer, 7_000, decline("Sold out"));
        assert!(awaiting_reply(
            true,
            &[buyer.clone(), store_decline],
            seen(vec![])
        ));
        let own_decline = said(ToBuyer, 7_000, decline("Can't ship there, sorry"));
        assert!(!awaiting_reply(
            true,
            &[buyer.clone(), own_decline],
            seen(vec![])
        ));
        let empty = said(ToBuyer, 7_000, decline(""));
        assert!(awaiting_reply(true, &[buyer, empty], seen(vec![])));

        // Junk, a request and nothing are nothing.
        let junk = MailboxEntry::Unreadable {
            conversation: vec![1u8; 32],
            timestamp: at(9_000),
            nonce: [0; 24],
            digest: [0xee; 32],
            why: "junk".into(),
        };
        assert!(!awaiting_reply(
            true,
            &[junk, request(ListingId([9; 32]), 1, [0xdd; 32])],
            seen(vec![])
        ));
        assert!(!awaiting_reply(true, &[], seen(vec![])));
    }

    /// **Nothing unconfirmed is drawn as this side's word** (review round 1
    /// S2, kept by msg1 MSG-1's in-place layout): an untrusted line is the
    /// dashed class wherever it sits, never the filled "You" bubble. Red with
    /// untrusted lines drawn as `mine`.
    #[test]
    fn an_unconfirmed_line_is_never_drawn_as_yours() {
        let line = |mine, trusted| ChatLine {
            who: if trusted { "You" } else { UNCONFIRMED },
            mine,
            trusted,
            when: String::new(),
            item: ChatItem::Said("x".into()),
        };
        assert_eq!(bubble_class(&line(false, false)), "bubble unconfirmed");
        assert_eq!(bubble_class(&line(true, false)), "bubble unconfirmed");
        assert_eq!(bubble_class(&line(true, true)), "bubble mine");
        assert_eq!(bubble_class(&line(false, true)), "bubble");
    }

    /// **An order goes under the conversation whose request names it**,
    /// even when another conversation also matches it by listing tag and
    /// has the lower tag: the request id binds the tag (review round 2 of
    /// #205, B1). With no request match, the lowest listing-tag match. Red
    /// with the request preference dropped.
    #[test]
    fn an_order_goes_under_the_conversation_whose_request_names_it() {
        let mut low = thread(1, true, true, 0, &[7]);
        let mut high = thread(2, true, true, 0, &[7]);
        high.by_request = vec![harvest_common::payment::OrderId([7; 32])];
        low.by_request = Vec::new();
        let inbox = SellerInbox {
            threads: vec![low, high],
            unreadable: 0,
            held_back: 0,
        };
        let id = harvest_common::payment::OrderId([7; 32]);
        assert_eq!(inbox.for_order(&id).map(|t| t.tag), Some([2; 32]));
        let mut none_by_request = inbox.clone();
        none_by_request.threads[1].by_request.clear();
        assert_eq!(none_by_request.for_order(&id).map(|t| t.tag), Some([1; 32]));
    }

    /// **The Orders tab's one map per render files every order where
    /// `for_order` does** (review after 01f2bcf): over three conversations
    /// sharing orders, in every arrival order and every choice of which ones
    /// a request binds, `by_order` and `for_order` agree on each order. Red
    /// with the request preference or the lowest-tag tie-break dropped from
    /// `by_order`.
    #[test]
    fn the_orders_tab_map_files_each_order_where_for_order_does() {
        let ids: Vec<harvest_common::payment::OrderId> = [5u8, 6, 7]
            .iter()
            .map(|n| harvest_common::payment::OrderId([*n; 32]))
            .collect();
        let base = [
            thread(1, true, true, 0, &[5, 6, 7]),
            thread(2, true, true, 0, &[6, 7]),
            thread(3, true, true, 0, &[7]),
        ];
        let arrivals: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        // Bit `t` of `bound`: conversation `t` has a request naming order 7
        // (and, for bit 1, order 6 too).
        for bound in 0u8..8 {
            for arrival in arrivals {
                let threads: Vec<SellerThread> = arrival
                    .iter()
                    .map(|&t| {
                        let mut thread = base[t].clone();
                        thread.by_request = Vec::new();
                        if bound & (1 << t) != 0 {
                            if t == 1 {
                                thread.by_request.push(ids[1].clone());
                            }
                            thread.by_request.push(ids[2].clone());
                        }
                        thread
                    })
                    .collect();
                let inbox = SellerInbox {
                    threads,
                    unreadable: 0,
                    held_back: 0,
                };
                let map = inbox.by_order();
                for id in &ids {
                    assert_eq!(
                        map.get(id).map(|t| t.tag),
                        inbox.for_order(id).map(|t| t.tag),
                        "bound {bound:#b}, arrival {arrival:?}"
                    );
                }
                assert_eq!(map.len(), ids.len());
            }
        }
    }

    /// A question's preview is the buyer's newest text by its timestamp,
    /// whatever order the entries come in. Red taking the first entry.
    #[test]
    fn a_questions_preview_is_the_newest_buyer_text() {
        let at = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).unwrap();
        let text = |words: &str, secs: i64| {
            let mut entry = readable(MessageContent::Text(words.into()), [secs as u8; 32]);
            if let MailboxEntry::Readable { timestamp, .. } = &mut entry {
                *timestamp = at(secs);
            }
            entry
        };
        let mut t = thread(1, true, true, 0, &[]);
        t.entries = vec![text("older", 10), text("newest", 30), text("middle", 20)];
        assert_eq!(t.latest_from_buyer(), Some(("newest".into(), at(30))));
    }

    /// **The indexed lookup gives exactly the answers the full scan did**
    /// (codex on #205 round 3): over orders mixing two bindings, two listing
    /// tags, three receipt keys (one absent), repeated and tied dates, and a
    /// Buy now among them, every (order, ask time, ask receipt key) agrees.
    /// Red with the index's receipt filter or date bound changed.
    #[test]
    fn the_indexed_quote_lookup_matches_the_full_scan() {
        let k = keys();
        let tags = [
            k.listing_tag(&ListingId([9u8; 32])),
            k.listing_tag(&ListingId([8u8; 32])),
        ];
        let at = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).unwrap();
        let mut orders = Vec::new();
        let mut n = 0u8;
        for binding in [BINDING, [0x11; 32]] {
            for tag in tags {
                for (issued, receipt) in [
                    (100, Some([0x33; 32])),
                    (100, Some([0x44; 32])),
                    (200, None),
                    (200, Some([0x33; 32])),
                    (300, Some([0x33; 32])),
                ] {
                    n += 1;
                    let mut o = published(n, Some(binding), Some(tag));
                    o.order.created_at = at(issued);
                    o.order.buyer_receipt_key = receipt;
                    orders.push(o);
                }
            }
        }
        let mut buy_now = published(250, Some(BINDING), Some(tags[0]));
        buy_now.order.request_id = Some([1; 32]);
        orders.push(buy_now);
        for order in &orders {
            for asked in [50, 100, 150, 200, 250, 300, 350] {
                for receipt in [None, Some([0x33; 32]), Some([0x44; 32])] {
                    for binding in [BINDING, [0x11; 32]] {
                        for tag in &tags {
                            assert_eq!(
                                quote_order_answers(
                                    order,
                                    &orders,
                                    at(asked),
                                    &binding,
                                    &receipt,
                                    tag
                                ),
                                quote_order_answers_by_scan(
                                    order,
                                    &orders,
                                    at(asked),
                                    &binding,
                                    &receipt,
                                    tag
                                ),
                                "order {} asked {asked} receipt {receipt:?}",
                                order.order.id.0[0]
                            );
                        }
                    }
                }
            }
        }
    }

    /// **A quote order answers the asks made after the previous such order
    /// and no later than itself** (review of #205, L1): a later order never
    /// takes an earlier order's ask, and a closed earlier order never hides
    /// a later order's address. An order carrying another receipt key
    /// answers nothing. Red with the previous-order bound dropped, and with
    /// the receipt-key clause dropped.
    #[test]
    fn each_quote_order_answers_its_own_ask() {
        let id = ListingId([9u8; 32]);
        let k = keys();
        let tag = k.listing_tag(&id);
        let at = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).unwrap();
        let order = |n: u8, issued: i64| {
            let mut o = published(n, Some(BINDING), Some(tag));
            o.order.created_at = at(issued);
            o.order.buyer_receipt_key = Some([0x33; 32]);
            o
        };
        let first = order(1, 100);
        let second = order(2, 300);
        let both = [first.clone(), second.clone()];
        let key = Some([0x33; 32]);
        let answers = |o: &harvest_common::payment::AuthorizedOrder, asked: i64| {
            quote_order_answers(o, &both, at(asked), &BINDING, &key, &tag)
        };
        assert!(answers(&first, 50));
        assert!(
            !answers(&second, 50),
            "the earlier ask is the first order's"
        );
        assert!(answers(&second, 200));
        assert!(!answers(&first, 200), "made after the first was issued");
        assert!(!answers(&second, 400), "made after the second was issued");
        // Two issued in the same instant: exactly one answers an ask.
        let twin = order(3, 100);
        let pair = [first.clone(), twin.clone()];
        let claimed = [&first, &twin]
            .iter()
            .filter(|o| quote_order_answers(o, &pair, at(50), &BINDING, &key, &tag))
            .count();
        assert_eq!(claimed, 1, "a tie is broken by id");
        let mut other_key = second.clone();
        other_key.order.buyer_receipt_key = Some([0x44; 32]);
        assert!(!quote_order_answers(
            &other_key,
            &[first.clone(), other_key.clone()],
            at(200),
            &BINDING,
            &key,
            &tag
        ));

        // The first order's window has closed; the second order's ask keeps
        // its address.
        let ask = |secs: i64| {
            let mut entry = request(id.clone(), 1, [secs as u8; 32]);
            if let MailboxEntry::Readable {
                timestamp,
                content:
                    MessageContent::OrderRequest {
                        buyer_receipt_key, ..
                    },
                ..
            } = &mut entry
            {
                *timestamp = at(secs);
                *buyer_receipt_key = key;
            }
            entry
        };
        let closed = |o: &harvest_common::payment::AuthorizedOrder| o.order.id != first.order.id;
        assert!(hidden_by_index(&ask(50), &both, Some(&k), closed));
        assert!(!hidden_by_index(&ask(200), &both, Some(&k), closed));
    }

    /// **Order requests and the store's automatic answers are not chat**
    /// (round-6 critique 10-6): a request and an acceptance are shown as
    /// what they are (the order card, the pay card, a request card), never as
    /// a bubble; a decline is one muted line; text is a bubble. Red with
    /// requests described as messages again.
    #[test]
    fn requests_and_acceptances_are_not_chat() {
        let id = ListingId([9u8; 32]);
        assert_eq!(
            chat_item(&MessageContent::Text("hi".into())),
            Some(ChatItem::Said("hi".into()))
        );
        let MailboxEntry::Readable { content, .. } = request(id, 1, [1; 32]) else {
            unreachable!()
        };
        assert_eq!(chat_item(&content), None);
        assert_eq!(
            chat_item(&MessageContent::OrderAccepted {
                order_id: harvest_common::payment::OrderId([3; 32])
            }),
            None
        );
        assert_eq!(
            chat_item(&MessageContent::Decline {
                reason: " sold out ".into()
            }),
            Some(ChatItem::Event("An order was declined: sold out".into()))
        );
    }

    /// **The store decline reasons the UI shows from anyone are exactly the
    /// delegate's** (review round 3 of #205): each is a string literal the
    /// delegate's source sends, "Only N left" is its format string, and
    /// nothing looser passes. Red when a copy drifts from the delegate.
    #[test]
    fn the_store_decline_reasons_are_the_delegates() {
        let delegate = include_str!("../../../delegates/harvest-delegate/src/auto_invoice.rs");
        // Joined across `\` line continuations, as the compiler reads them.
        let mut joined = String::new();
        let mut lines = delegate.lines();
        // Joins a string continued over any number of lines (`\` at the
        // end of each).
        let mut carrying = false;
        for line in lines.by_ref() {
            let piece = if carrying { line.trim_start() } else { line };
            match piece.trim_end().strip_suffix('\\') {
                Some(head) => {
                    joined.push_str(head);
                    carrying = true;
                }
                None => {
                    joined.push_str(piece);
                    joined.push('\n');
                    carrying = false;
                }
            }
        }
        for reason in STORE_DECLINE_REASONS {
            assert!(
                joined.contains(&format!("\"{reason}\"")),
                "the delegate no longer sends {reason:?}"
            );
            assert!(is_store_decline_reason(reason));
        }
        assert!(joined.contains("format!(\"Only {left} left\")"));
        assert!(joined.contains("reason: harvest_common::delegate::TOO_MANY_UNPAID"));
        assert!(is_store_decline_reason("Only 3 left"));
        assert!(is_store_decline_reason("Only 4294967295 left"));
        assert!(is_store_decline_reason(
            harvest_common::delegate::TOO_MANY_UNPAID
        ));
        for loose in [
            "Only three left",
            "Only 03 left",
            "Only 4294967296 left",
            "Only 9999999999 left",
            "Only +3 left",
            "Only  left",
            "sold out",
            "Sold out.",
        ] {
            assert!(!is_store_decline_reason(loose), "{loose:?}");
        }
    }

    /// Bubbles are labelled by side, "You" for this side's direction, and
    /// never "Addressed to" with a caveat (round-6 critique 10-5).
    #[test]
    fn bubbles_are_labelled_by_side() {
        use crate::messaging::Addressing::{ToBuyer, ToSeller};
        for authored in [false, true] {
            assert_eq!(
                who(Role::Seller, ToSeller, authored),
                ("Buyer", false, true)
            );
            assert_eq!(who(Role::Buyer, ToBuyer, authored), ("Seller", false, true));
        }
        assert_eq!(who(Role::Seller, ToBuyer, true), ("You", true, true));
        assert_eq!(who(Role::Buyer, ToSeller, true), ("You", true, true));
    }

    /// **"You" only for what this device sent** (review of #205, S2): in
    /// this side's direction, anything else is [`UNCONFIRMED`] and out of
    /// the timeline, on both screens. A decline stays in the timeline, as a
    /// step. Red with `who` labelling by direction alone.
    #[test]
    fn this_sides_direction_is_you_only_when_sent_from_here() {
        // Round 3 of #205: on the seller's screen a decline ADDRESSED TO the
        // seller (only a buyer writes those) shows no free-text reason
        // either; the store's exact words are shown from anyone.
        let forged_to_seller = chat_line(
            Role::Seller,
            crate::messaging::Addressing::ToSeller,
            false,
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            &MessageContent::Decline {
                reason: "Refund of 50,000 sats sent, order closed by the seller".into(),
            },
        )
        .unwrap();
        assert_eq!(
            forged_to_seller.item,
            ChatItem::Event("An order was declined.".into())
        );
        for (role, addressing) in [
            (Role::Seller, crate::messaging::Addressing::ToBuyer),
            (Role::Seller, crate::messaging::Addressing::ToSeller),
            (Role::Buyer, crate::messaging::Addressing::ToSeller),
        ] {
            let store_words = chat_line(
                role,
                addressing,
                false,
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                &MessageContent::Decline {
                    reason: "Sold out".into(),
                },
            )
            .unwrap();
            assert_eq!(
                store_words.item,
                ChatItem::Event("An order was declined: Sold out".into()),
                "{role:?} {addressing:?}"
            );
        }
        use crate::messaging::Addressing::{ToBuyer, ToSeller};
        assert_eq!(
            who(Role::Seller, ToBuyer, false),
            (UNCONFIRMED, false, false)
        );
        assert_eq!(
            who(Role::Buyer, ToSeller, false),
            (UNCONFIRMED, false, false)
        );
        let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let forged = chat_line(
            Role::Seller,
            ToBuyer,
            false,
            at,
            &MessageContent::Text("Agreed, full refund".into()),
        )
        .unwrap();
        assert!(!forged.trusted);
        let decline = chat_line(
            Role::Seller,
            ToBuyer,
            false,
            at,
            &MessageContent::Decline {
                reason: "sold out".into(),
            },
        )
        .unwrap();
        assert!(decline.trusted);
        assert_eq!(
            decline.item,
            ChatItem::Event("An order was declined.".into()),
            "a forged reason in this side's name is not shown (R5)"
        );
        let own = chat_line(
            Role::Seller,
            ToBuyer,
            true,
            at,
            &MessageContent::Decline {
                reason: "sold out".into(),
            },
        )
        .unwrap();
        assert_eq!(
            own.item,
            ChatItem::Event("An order was declined: sold out".into())
        );
        let theirs = chat_line(
            Role::Buyer,
            ToBuyer,
            false,
            at,
            &MessageContent::Decline {
                reason: "sold out".into(),
            },
        )
        .unwrap();
        assert_eq!(
            theirs.item,
            ChatItem::Event("An order was declined: sold out".into()),
            "the other side's reason stands as theirs"
        );
    }

    /// The count beside Orders is the number of accept controls the inbox
    /// would show, summed over conversations, each judged with its OWN keys,
    /// less requests for a listing not on sale or not in the store.
    #[test]
    fn the_orders_count_is_the_unanswered_requests_across_conversations() {
        let id = ListingId([9u8; 32]);
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        // The same listing and binding asked in a second conversation.
        let mut other = request(id.clone(), 1, [7u8; 32]);
        if let MailboxEntry::Readable { conversation, .. } = &mut other {
            *conversation = vec![5u8; 32];
        }
        let entries = vec![
            request(id.clone(), 2, [3u8; 32]),
            readable(MessageContent::Text("hello".into()), [4u8; 32]),
            other,
        ];
        let first = keys();
        let second = crate::messaging::ConversationKeys::from_shared_secret(&[6u8; 32]);
        let keys_for = |tag: &[u8]| {
            if tag == [5u8; 32].as_slice() {
                Some(&second)
            } else {
                Some(&first)
            }
        };
        assert_eq!(
            count_unanswered(entries.clone(), &listings, &[], keys_for, |_| true),
            2
        );

        // An order under the FIRST conversation's tag answers only its
        // request: the second conversation computes a different tag.
        let answered = vec![published(1, Some(BINDING), Some(first.listing_tag(&id)))];
        assert_eq!(
            count_unanswered(entries.clone(), &listings, &answered, keys_for, |_| true),
            1
        );

        // Not on sale, or never in this store: not counted.
        assert_eq!(
            count_unanswered(entries.clone(), &listings, &[], keys_for, |_| false),
            0
        );
        assert_eq!(count_unanswered(entries, &[], &[], keys_for, |_| true), 0);
    }

    /// A Buy now the store did not answer is left out of the count: an
    /// unpaid Buy now is not an order and does not need the seller. It is
    /// still in the inbox, where the seller can answer it by hand. Mutated
    /// red by dropping the `instant.is_none()` filter.
    #[test]
    fn an_unanswered_buy_now_does_not_need_the_seller() {
        let id = ListingId([9u8; 32]);
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let buy_now = readable(
            MessageContent::OrderRequest {
                instant: Some(crate::messaging::InstantSelection {
                    requested_at_ms: 1_700_000_000_000,
                    nonce: [1; 16],
                    region: None,
                    choices: vec![],
                    expected_total_sats: 12_000,
                }),
                listing_id: id.clone(),
                quantity: 1,
                shipping: "12 Example St".into(),
                note: String::new(),
                order_binding: BINDING,
                buyer_receipt_key: None,
            },
            [1u8; 32],
        );
        let k = keys();
        assert_eq!(
            unanswered_requests(std::slice::from_ref(&buy_now), &listings, &[], Some(&k)).len(),
            1,
            "still offered in the inbox"
        );
        assert_eq!(
            count_unanswered(vec![buy_now], &listings, &[], |_| Some(&k), |_| true),
            0
        );
    }

    /// **The seller is offered an Accept only when there is a request.**
    ///
    /// An accept control on an ordinary question would publish a commitment
    /// against an order nobody asked for.
    #[test]
    fn an_ordinary_message_offers_nothing_to_accept() {
        let entries = vec![readable(
            MessageContent::Text("is this in stock?".into()),
            [1u8; 32],
        )];
        assert!(unanswered_requests(&entries, &[], &[], Some(&keys())).is_empty());
    }

    /// **A request carries its listing, its title, its quantity and its
    /// binding through to the accept control.**
    ///
    /// Not merely "there is a request": all four are what the commitment is
    /// published out of. Dropping the listing id would price the wrong item;
    /// dropping the binding would publish a commitment no buyer will pay;
    /// dropping the TITLE leaves the seller typing a satoshi amount for an
    /// item the screen never names, which is the state the accept control was
    /// in when review found it.
    #[test]
    fn a_request_carries_everything_the_accept_control_publishes() {
        let id = ListingId([9u8; 32]);
        let entries = vec![
            readable(MessageContent::Text("hello".into()), [1u8; 32]),
            request(id.clone(), 4, [2u8; 32]),
        ];
        let found = unanswered_requests(
            &entries,
            &[listing(id.clone(), "Ghost Pepper")],
            &[],
            Some(&keys()),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].listing_id, id);
        assert_eq!(found[0].listing_title, "Ghost Pepper");
        assert_eq!(found[0].quantity, 4);
        assert_eq!(found[0].order_binding, BINDING);
    }

    /// **A title the store has not published is empty, not invented.**
    ///
    /// The accept control refuses to price an unnamed listing rather than
    /// showing a made-up label; a placeholder here would defeat that.
    #[test]
    fn a_listing_the_store_has_not_published_has_no_title() {
        let id = ListingId([9u8; 32]);
        let found = unanswered_requests(&[request(id, 1, [2u8; 32])], &[], &[], Some(&keys()));
        assert_eq!(found[0].listing_title, "");
    }

    /// **An unreadable entry is not a request.**
    ///
    /// The mailbox is open-write, so most of what arrives at a busy store is
    /// junk; an accept control that appeared for it would invite the seller
    /// to publish a commitment against nothing.
    #[test]
    fn an_unreadable_entry_is_not_a_request() {
        let entries = vec![MailboxEntry::Unreadable {
            conversation: vec![1u8; 32],
            timestamp: chrono::Utc::now(),
            nonce: [0u8; 24],
            digest: [0u8; 32],
            why: "not for us".to_string(),
        }];
        assert!(unanswered_requests(&entries, &[], &[], Some(&keys())).is_empty());
    }

    /// **A request the seller has already answered is not offered again.**
    ///
    /// Found in review: the only thing preventing a second accept was a
    /// component signal, which is gone after a reload -- so a seller coming
    /// back to the tab was invited to publish a second commitment for one
    /// order, burning a second derivation index and leaving the buyer with
    /// two cards they could reasonably pay both of.
    ///
    /// "Answered" is decided from the seller's OWN published state, which the
    /// buyer cannot forge: an order carrying this request's binding and this
    /// listing's tag. (The buyer CAN withdraw one by cancelling it; see
    /// `a_request_after_a_cancelled_answer_is_offered_again`.) Not from the mailbox, where the seller's
    /// acceptance can be lost or evicted.
    #[test]
    fn a_request_already_answered_is_not_offered_again() {
        let id = ListingId([9u8; 32]);
        let entries = vec![request(id.clone(), 1, [2u8; 32])];
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let tag = keys().listing_tag(&id);

        assert_eq!(
            unanswered_requests(&entries, &listings, &[], Some(&keys())).len(),
            1,
            "unanswered while nothing is published"
        );
        assert!(
            unanswered_requests(
                &entries,
                &listings,
                &[published(7, Some(BINDING), Some(tag))],
                Some(&keys())
            )
            .is_empty(),
            "an order carrying this request's binding and listing tag IS the answer to it"
        );
    }

    /// harvest#53 Phase B: a request carrying the buyer's receipt key is
    /// answered only by an order carrying that key. An order without it is
    /// one the buyer refuses to pay, and the buyer is told to send the request
    /// again, so the seller must be offered the control for the keyed resend;
    /// and a keyed request is not folded into an unkeyed one.
    #[test]
    fn a_keyed_request_is_answered_only_by_an_order_carrying_its_key() {
        let id = ListingId([9u8; 32]);
        let key = [0x33; 32];
        let keyed = |digest: [u8; 32]| {
            readable(
                MessageContent::OrderRequest {
                    instant: None,
                    listing_id: id.clone(),
                    quantity: 1,
                    shipping: "12 Example St".into(),
                    note: String::new(),
                    order_binding: BINDING,
                    buyer_receipt_key: Some(key),
                },
                digest,
            )
        };
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let tag = keys().listing_tag(&id);
        let unkeyed_order = published(7, Some(BINDING), Some(tag));
        let mut keyed_order = published(8, Some(BINDING), Some(tag));
        keyed_order.order.buyer_receipt_key = Some(key);

        let open = unanswered_requests(
            &[keyed([2u8; 32])],
            &listings,
            std::slice::from_ref(&unkeyed_order),
            Some(&keys()),
        );
        assert_eq!(open.len(), 1, "an order without the key does not answer it");
        assert_eq!(open[0].buyer_receipt_key, Some(key));
        assert!(unanswered_requests(
            &[keyed([2u8; 32])],
            &listings,
            &[unkeyed_order, keyed_order],
            Some(&keys())
        )
        .is_empty());

        // The old unkeyed request and the keyed resend are ONE ask, offered
        // as the keyed request, in either order.
        for entries in [
            [request(id.clone(), 1, [1u8; 32]), keyed([2u8; 32])],
            [keyed([2u8; 32]), request(id.clone(), 1, [1u8; 32])],
        ] {
            let one = unanswered_requests(&entries, &listings, &[], Some(&keys()));
            assert_eq!(one.len(), 1);
            assert_eq!(one[0].buyer_receipt_key, Some(key));
        }
        // A different quantity is a different ask.
        let two = unanswered_requests(
            &[request(id.clone(), 2, [1u8; 32]), keyed([2u8; 32])],
            &listings,
            &[],
            Some(&keys()),
        );
        assert_eq!(two.len(), 2);
    }

    /// **A Buy now in the conversation keeps a quote request answered**
    /// (review after 01f2bcf). `OrderIndex::by_binding_and_tag` holds every
    /// order, a Buy now's too, as the scan it replaced read them: a buyer who
    /// asked for a quote and then bought the listing outright has had their
    /// answer, and the quote request is not offered to the seller again. Red
    /// with only quote orders indexed there.
    #[test]
    fn a_buy_now_for_the_listing_keeps_a_quote_request_answered() {
        let id = ListingId([9u8; 32]);
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let tag = keys().listing_tag(&id);
        let mut buy_now = published(7, Some(BINDING), Some(tag));
        buy_now.order.request_id = Some([1; 32]);
        assert!(unanswered_requests(
            &[request(id.clone(), 1, [2u8; 32])],
            &listings,
            std::slice::from_ref(&buy_now),
            Some(&keys()),
        )
        .is_empty());
        // The control: with no order at all, the same request waits.
        assert_eq!(
            unanswered_requests(&[request(id, 1, [2u8; 32])], &listings, &[], Some(&keys())).len(),
            1
        );
    }

    /// **A buyer who cancels and asks again reaches the seller** (rounds 3
    /// and 4 of harvest#136).
    ///
    /// The binding, the listing tag and the receipt key are all fixed per
    /// conversation, so a cancelled order matches every later request for the
    /// same listing in that conversation. An order that is not cancelled
    /// answers every ask; a cancelled one answers the asks made up to when
    /// the seller issued it, whichever of them the seller chose and however
    /// often one was resent; an ask made after the newest cancelled answer is
    /// waiting.
    #[test]
    fn a_request_after_a_cancelled_answer_is_offered_again() {
        use harvest_common::payment::OrderStatus::{AwaitingPayment, Cancelled, Paid};
        let id = ListingId([9u8; 32]);
        let key = [0x33; 32];
        let at = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).expect("timestamp");
        let ask = |quantity: u32, digest: u8, when: i64| {
            let mut entry = readable(
                MessageContent::OrderRequest {
                    instant: None,
                    listing_id: id.clone(),
                    quantity,
                    shipping: "12 Example St".into(),
                    note: String::new(),
                    order_binding: BINDING,
                    buyer_receipt_key: Some(key),
                },
                [digest; 32],
            );
            if let MailboxEntry::Readable { timestamp, .. } = &mut entry {
                *timestamp = at(when);
            }
            entry
        };
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let tag = keys().listing_tag(&id);
        let order = |n: u8, status, issued: i64| {
            let mut order = published(n, Some(BINDING), Some(tag));
            order.order.buyer_receipt_key = Some(key);
            order.order.created_at = at(issued);
            order.status = status;
            order
        };
        let open = |entries: &[MailboxEntry],
                    orders: &[harvest_common::payment::AuthorizedOrder]| {
            unanswered_requests(entries, &listings, orders, Some(&keys()))
                .iter()
                .map(|r| r.digest[0])
                .collect::<Vec<u8>>()
        };
        let cancelled_at_200 = [order(7, Cancelled, 200)];

        // Asked, answered, cancelled: answered -- including an ask stamped in
        // the very second the order was issued.
        assert_eq!(open(&[ask(1, 1, 100)], &cancelled_at_200), Vec::<u8>::new());
        assert_eq!(open(&[ask(1, 1, 200)], &cancelled_at_200), Vec::<u8>::new());
        assert_eq!(open(&[ask(1, 1, 201)], &cancelled_at_200), vec![1]);
        // A resend before the answer (a fresh digest, as every real resend
        // has) is answered by it too.
        assert_eq!(
            open(&[ask(1, 2, 150), ask(1, 1, 100)], &cancelled_at_200),
            Vec::<u8>::new()
        );
        // Two different asks, the seller answering the NEWER one: both are
        // answered, so the one the buyer just withdrew is not offered again.
        assert_eq!(
            open(&[ask(2, 2, 110), ask(1, 1, 100)], &cancelled_at_200),
            Vec::<u8>::new()
        );

        // Asked again after the cancel (newest first): the new ask waits,
        // the old one does not.
        let again = [ask(2, 3, 300), ask(1, 1, 100)];
        assert_eq!(open(&again, &cancelled_at_200), vec![3]);
        let found = unanswered_requests(&again, &listings, &cancelled_at_200, Some(&keys()));
        assert_eq!(found[0].quantity, 2);

        // Answered again, however the new order stands.
        for status in [AwaitingPayment, Paid, Cancelled] {
            assert_eq!(
                open(&again, &[order(7, Cancelled, 200), order(8, status, 400)]),
                Vec::<u8>::new(),
                "{status:?}"
            );
        }
        // An order that is not cancelled answers every ask, even one made
        // after it was issued: a second debt for one purchase is the worse
        // mistake.
        assert_eq!(
            open(&again, &[order(8, AwaitingPayment, 200)]),
            Vec::<u8>::new()
        );
        // A cancelled answer for ANOTHER listing answers nothing here.
        let mut elsewhere = order(7, Cancelled, 400);
        elsewhere.order.listing_tag = Some(keys().listing_tag(&ListingId([8u8; 32])));
        assert_eq!(open(&[ask(1, 1, 100)], &[elsewhere]), vec![1]);
    }

    /// **Nothing short of that answers the request.**
    #[test]
    fn a_request_is_answered_only_by_an_order_with_its_binding_and_tag() {
        let id = ListingId([9u8; 32]);
        let entries = vec![request(id.clone(), 1, [2u8; 32])];
        let listings = vec![listing(id.clone(), "Ghost Pepper")];
        let tag = keys().listing_tag(&id);
        let other_conversation = crate::messaging::ConversationKeys::from_shared_secret(&[5u8; 32]);
        let still_open = |orders: &[harvest_common::payment::AuthorizedOrder],
                          keys: Option<&crate::messaging::ConversationKeys>,
                          why: &str| {
            assert_eq!(
                unanswered_requests(&entries, &listings, orders, keys).len(),
                1,
                "{why}"
            );
        };

        still_open(
            &[published(7, Some([0x11; 32]), Some(tag))],
            Some(&keys()),
            "same listing, another buyer's binding",
        );
        still_open(
            &[published(
                7,
                Some(BINDING),
                Some(keys().listing_tag(&ListingId([8u8; 32]))),
            )],
            Some(&keys()),
            "this buyer's binding, another listing",
        );
        still_open(
            &[published(7, None, Some(tag))],
            Some(&keys()),
            "an unbound commitment answers nobody",
        );
        still_open(
            &[published(7, Some(BINDING), None)],
            Some(&keys()),
            "an order naming no listing answers no request",
        );
        still_open(
            &[published(
                7,
                Some(BINDING),
                Some(other_conversation.listing_tag(&id)),
            )],
            Some(&keys()),
            "a tag computed under another conversation's key",
        );
        still_open(
            &[published(7, Some(BINDING), Some(tag))],
            None,
            "without this conversation's keys nothing can be matched",
        );
    }

    /// **Which request is offered first is not decided by the sender's
    /// clock.**
    ///
    /// `entries` arrives sorted by `MailboxEntry::timestamp`, which
    /// `read_mailbox` documents in as many words as "chosen by whoever wrote
    /// the message and signed by nobody ... a display order and NOT evidence
    /// about when anything happened". Letting it choose which listing a
    /// seller prices first would put that choice in the buyer's clock -- the
    /// writer-chosen-ordering defect this repository has already paid for
    /// three times. The order here is by the entry's own content digest.
    ///
    /// Both orderings of the same two entries must produce the same list.
    #[test]
    fn the_order_offered_does_not_depend_on_the_senders_clock() {
        let cheap = ListingId([1u8; 32]);
        let dear = ListingId([2u8; 32]);
        let listings = vec![
            listing(cheap.clone(), "Cheap"),
            listing(dear.clone(), "Dear"),
        ];
        let first = request(cheap, 1, [0x01; 32]);
        let second = request(dear, 1, [0x02; 32]);

        let one = unanswered_requests(
            &[first.clone(), second.clone()],
            &listings,
            &[],
            Some(&keys()),
        );
        let other = unanswered_requests(&[second, first], &listings, &[], Some(&keys()));
        assert_eq!(one, other, "the seller sees the same order either way");
        assert_eq!(one[0].digest, [0x01; 32], "and it is the digest order");
    }

    /// **One ask repeated is one control.**
    ///
    /// A buyer whose send retried, or who pressed the button twice, has asked
    /// once; two controls would invite two published debts for one order.
    #[test]
    fn the_same_request_twice_is_offered_once() {
        let id = ListingId([9u8; 32]);
        let entries = vec![
            request(id.clone(), 2, [0x01; 32]),
            request(id.clone(), 2, [0x02; 32]),
        ];
        let found =
            unanswered_requests(&entries, &[listing(id, "Ghost Pepper")], &[], Some(&keys()));
        assert_eq!(found.len(), 1);
    }
}

#[cfg(test)]
mod voucher_view_tests {
    use super::*;
    use crate::ghostkey_cert::tests::{test_master, vouch};
    use crate::messaging::Addressing;

    const TAG: [u8; 32] = [1; 32];
    const OTHER: [u8; 32] = [2; 32];

    fn entry(tag: [u8; 32], addressing: Addressing, content: MessageContent) -> MailboxEntry {
        MailboxEntry::Readable {
            conversation: tag.to_vec(),
            conversation_id: harvest_common::mailbox::ConversationId([3; 32]),
            addressing,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            nonce: [0; 24],
            digest: [tag[0]; 32],
            content,
        }
    }

    fn vouched(tag: [u8; 32], voucher: &harvest_common::sealed::MessageVoucher) -> MailboxEntry {
        entry(
            tag,
            Addressing::ToSeller,
            MessageContent::VouchedText {
                text: "hello".into(),
                voucher: voucher.clone(),
            },
        )
    }

    fn text(tag: [u8; 32], addressing: Addressing) -> MailboxEntry {
        entry(tag, addressing, MessageContent::Text("hi".into()))
    }

    fn order_request(tag: [u8; 32]) -> MailboxEntry {
        entry(
            tag,
            Addressing::ToSeller,
            MessageContent::OrderRequest {
                listing_id: harvest_common::listing::ListingId([9; 32]),
                quantity: 1,
                shipping: "12 Example St".into(),
                note: String::new(),
                order_binding: [5; 32],
                buyer_receipt_key: None,
                instant: None,
            },
        )
    }

    /// The conversation whose Buy now is paid, in these tests.
    const PAID: [u8; 32] = [6; 32];

    fn shown(entries: Vec<MailboxEntry>) -> (Vec<MailboxEntry>, usize) {
        shown_to_seller(
            entries,
            |voucher, tag| {
                crate::ghostkey_cert::verify_voucher_under(voucher, tag, &test_master()).is_ok()
            },
            |tag| *tag == PAID,
            |entry| entry.digest() == [CLOSED; 32],
            |digest| *digest == [AUTHORED; 32],
        )
    }

    /// The first byte of the digest of what this tab wrote itself, in these
    /// tests (`entry` makes a digest of the tag's first byte).
    const AUTHORED: u8 = 7;

    /// The first byte of the digest of a request whose order's complaint
    /// window has closed, in these tests.
    const CLOSED: u8 = 8;

    /// A request whose order is past its complaint window shows the hidden
    /// line in place of its address, and no note, in a conversation that is
    /// open; nothing is counted as held back. Mutated red by dropping the
    /// arm.
    #[test]
    fn a_closed_orders_address_is_hidden() {
        let mut closed = buy_now([CLOSED; 32], "flat 3, side door");
        let entries = vec![closed.clone()];
        let (shown_entries, hidden) = shown_to_seller(
            entries,
            |_, _| false,
            |_| true,
            |entry| entry.digest() == [CLOSED; 32],
            |_| false,
        );
        assert_eq!(hidden, 0);
        assert_eq!(
            free_text(&shown_entries[0]),
            (String::new(), crate::fulfilment::ADDRESS_HIDDEN.to_string())
        );
        // Any other request in the same open conversation keeps its address.
        if let MailboxEntry::Readable { digest, .. } = &mut closed {
            *digest = [9; 32];
        }
        let (kept, _) = shown_to_seller(
            vec![closed],
            |_, _| false,
            |_| true,
            |e| e.digest() == [CLOSED; 32],
            |_| false,
        );
        assert_eq!(free_text(&kept[0]).1, "12 Example St");
    }

    fn buy_now(tag: [u8; 32], note: &str) -> MailboxEntry {
        buy_now_picking(tag, note, None, vec![])
    }

    fn buy_now_picking(
        tag: [u8; 32],
        note: &str,
        region: Option<&str>,
        choices: Vec<String>,
    ) -> MailboxEntry {
        entry(
            tag,
            Addressing::ToSeller,
            MessageContent::OrderRequest {
                listing_id: harvest_common::listing::ListingId([9; 32]),
                quantity: 1,
                shipping: "12 Example St".into(),
                note: note.into(),
                order_binding: [5; 32],
                buyer_receipt_key: None,
                instant: Some(crate::messaging::InstantSelection {
                    requested_at_ms: 1_700_000_000_000,
                    nonce: [4; 16],
                    region: region.map(str::to_string),
                    choices,
                    expected_total_sats: 12_000,
                }),
            },
        )
    }

    fn decline(tag: [u8; 32], reason: &str) -> MailboxEntry {
        entry(
            tag,
            Addressing::ToBuyer,
            MessageContent::Decline {
                reason: reason.into(),
            },
        )
    }

    fn free_text(entry: &MailboxEntry) -> (String, String) {
        match entry {
            MailboxEntry::Readable {
                content: MessageContent::OrderRequest { note, shipping, .. },
                ..
            } => (note.clone(), shipping.clone()),
            MailboxEntry::Readable {
                content: MessageContent::Decline { reason },
                ..
            } => (reason.clone(), String::new()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn vouched_text_is_shown() {
        let (voucher, _, _) = vouch(&TAG);
        assert_eq!(
            shown(vec![vouched(TAG, &voucher)]),
            (vec![vouched(TAG, &voucher)], 0)
        );
    }

    /// Plain text from a buyer, which is what a script writing past the
    /// compose gate sends, is not shown -- except in a conversation a paid
    /// order opened, where it is how a buyer with a paid order writes
    /// without a Ghost Key. Mutated red by hiding it there too (the rule
    /// before 2026-09-30), and by showing it everywhere.
    #[test]
    fn unvouched_buyer_text_is_hidden_unless_a_paid_order_opened_it() {
        assert_eq!(shown(vec![text(TAG, Addressing::ToSeller)]), (vec![], 1));
        assert_eq!(
            shown(vec![text(PAID, Addressing::ToSeller)]),
            (vec![text(PAID, Addressing::ToSeller)], 0)
        );
    }

    /// A voucher copied from another conversation vouches for nothing here,
    /// and one that does not verify at all is no better than none.
    #[test]
    fn a_voucher_that_does_not_verify_for_this_conversation_is_hidden() {
        let (voucher, _, _) = vouch(&OTHER);
        assert_eq!(shown(vec![vouched(TAG, &voucher)]).1, 1);
        let (mut broken, _, _) = vouch(&TAG);
        broken.signature[0] ^= 1;
        assert_eq!(shown(vec![vouched(TAG, &broken)]).1, 1);
    }

    /// Buying needs no Ghost Key: a request to buy and a decline are shown
    /// in any conversation, but the free text in them only once the
    /// conversation is open. Otherwise one free request carries a spammer's
    /// text past the gate. Mutated red by showing them unblanked, and by not
    /// counting what was blanked.
    #[test]
    fn requests_and_declines_are_shown_with_their_text_held_back() {
        let (shown_entries, hidden) = shown(vec![
            order_request(TAG),
            buy_now(OTHER, "buy my stuff at example.com"),
            decline(OTHER, "cheap pills"),
        ]);
        assert_eq!(shown_entries.len(), 3, "every step is shown");
        assert_eq!(
            free_text(&shown_entries[0]),
            (String::new(), SHIPPING_SHOWN_ONCE_PAID.to_string())
        );
        assert_eq!(
            free_text(&shown_entries[1]),
            (String::new(), SHIPPING_SHOWN_ONCE_PAID.to_string())
        );
        assert_eq!(free_text(&shown_entries[2]).0, "");
        // An unpaid Buy now's note is not counted (the seller never sees an
        // unpaid Buy now), nor is an address or a decline held back.
        assert_eq!(hidden, 0);
        // A quote request's note is: the seller is asked to answer it.
        // Mutated red by counting only Buy nows, or both.
        let mut noted = order_request(TAG);
        if let MailboxEntry::Readable {
            content: MessageContent::OrderRequest { note, .. },
            ..
        } = &mut noted
        {
            *note = "call me first".into();
        }
        assert_eq!(shown(vec![noted]).1, 1);

        // A Buy now's picks are the buyer's text too.
        let (shown_entries, hidden) = shown(vec![buy_now_picking(
            OTHER,
            "",
            Some("cheap pills at spam.example"),
            vec!["visit spam.example".into()],
        )]);
        assert_eq!(hidden, 0, "an unpaid Buy now's picks are not counted");
        let MailboxEntry::Readable {
            content:
                MessageContent::OrderRequest {
                    instant: Some(selection),
                    ..
                },
            ..
        } = &shown_entries[0]
        else {
            panic!("{shown_entries:?}")
        };
        assert_eq!(
            (selection.region.clone(), selection.choices.len()),
            (None, 0)
        );
        assert_eq!(selection.expected_total_sats, 12_000, "the terms stay");

        // A paid Buy now's conversation is open: all of it is shown.
        let entries = vec![buy_now(PAID, "gift wrap please"), decline(PAID, "sold out")];
        assert_eq!(shown(entries.clone()), (entries, 0));
    }

    /// Text in the seller's reply direction is shown in a conversation that
    /// is open (a verified voucher, a paid Buy now) and in no other: both
    /// parties hold both keys, so flipping the direction must not get a
    /// script past the gate, and an unpaid request to buy opens nothing.
    #[test]
    fn reply_direction_text_needs_an_open_conversation() {
        let (voucher, _, _) = vouch(&TAG);
        let (shown_entries, hidden) = shown(vec![
            vouched(TAG, &voucher),
            text(TAG, Addressing::ToBuyer),
            buy_now(PAID, ""),
            text(PAID, Addressing::ToBuyer),
            buy_now(OTHER, ""),
            text(OTHER, Addressing::ToBuyer),
            text([4; 32], Addressing::ToBuyer),
        ]);
        // Reply-direction text left out is not counted: it is as likely the
        // seller's own reply, after a reload, as a buyer's.
        assert_eq!(hidden, 0);
        assert_eq!(shown_entries.len(), 5);
        assert!(shown_entries
            .iter()
            .all(|e| !matches!(e, MailboxEntry::Readable { content: MessageContent::Text(_), conversation, .. }
                if conversation.as_slice() == OTHER || conversation.as_slice() == [4; 32])));
    }

    /// What this tab wrote itself is shown as written, in a conversation
    /// nothing opened. Mutated red by dropping the exemption.
    #[test]
    fn the_sellers_own_messages_are_shown() {
        let own_reply = text([AUTHORED; 32], Addressing::ToBuyer);
        let own_decline = decline([AUTHORED; 32], "sold out, sorry");
        let entries = vec![own_reply, own_decline];
        assert_eq!(shown(entries.clone()), (entries, 0));
    }

    #[test]
    fn the_hidden_count_line_says_how_many() {
        assert_eq!(
            hidden_unvouched_line(1),
            "1 message was held back: it came without a Ghost Key, and Harvest couldn't match it \
             to a paid order."
        );
        assert_eq!(
            hidden_unvouched_line(3),
            "3 messages were held back: they came without a Ghost Key, and Harvest couldn't \
             match them to a paid order."
        );
    }
}

#[cfg(test)]
mod unreadable_claims_tests {
    use super::*;

    /// Unreadable entries under fresh tags make no conversation to match
    /// orders against: the mailbox is open-write, and each claim costs a scan
    /// of the store's orders (review round 4 of #205). Red without the
    /// readable filter in `seller_claims`.
    #[test]
    fn unreadable_entries_make_no_claims() {
        let entries: Vec<MailboxEntry> = (1u8..=20)
            .map(|i| {
                let tag =
                    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([i; 32]))
                        .as_bytes();
                MailboxEntry::Unreadable {
                    conversation: tag.to_vec(),
                    nonce: [i; 24],
                    digest: [i; 32],
                    timestamp: chrono::DateTime::from_timestamp(1_790_000_000, 0).expect("t"),
                    why: "no key".to_string(),
                }
            })
            .collect();
        assert!(seller_claims(&entries, &[], |_| None).is_empty());
    }
}
