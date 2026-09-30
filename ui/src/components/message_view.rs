use dioxus::prelude::*;

use crate::gateway::APP_STATE;
use crate::messaging::{MailboxEntry, MessageContent};

/// Buyer-to-seller messaging: the buyer's "Ask the seller a question" card on
/// a store's page (this component), each conversation under the orders it
/// holds on Purchases ([`BuyerThread`]), and the seller's side on the Orders
/// tab, each conversation under its order card or among the questions
/// ([`seller_inbox`], [`SellerThreadToggle`], [`SellerQuestions`]).
///
/// # What this component may and may not claim
///
/// An earlier version told the buyer "Messages are end-to-end encrypted. The
/// seller cannot see who you are unless you choose to share identifying
/// information", offered a textarea and a Send button, and then -- on submit
/// -- logged a line and pushed a notification. Nothing was encrypted and
/// nothing was sent. The version after that removed the claim and disabled
/// the box, because the seller published no key to encrypt to.
///
/// A seller now publishes one ([`harvest_common::store::StoreInfoV1::
/// encryption_public_key`]) and the box works. The claims below are therefore
/// re-enabled -- but only the ones that are true, and each is stated at the
/// strength it actually holds:
///
/// * **Encrypted to the seller.** True. The message is sealed to the key
///   published in the store's signed details, and the matching secret never
///   leaves the seller's delegate.
/// * **Not anonymous against a network observer.** Writing to a mailbox
///   contract is a contract update, and the mailbox's address is derived from
///   the seller's identity. Anybody watching knows this node wrote to this
///   seller. The message CONTENT is hidden; the fact of contact is not.
/// * **Replies work, and survive a reload on THIS device.** The seller
///   answers into their own mailbox and the buyer reads it out of the same
///   contract. The key that reads it is kept by this node's harvest delegate,
///   because the browser has no durable storage at all here -- the gateway's
///   sandboxed iframe has no `allow-same-origin`, so `localStorage`,
///   `sessionStorage`, IndexedDB and cookies all throw. It does NOT follow
///   the buyer to another device, and that has to be on screen BEFORE they
///   send rather than discovered when they need the answer. See
///   `docs/buyer-conversation-persistence.md`.
/// * **Handed over, not delivered.** `update_contract` resolves when the
///   local node has taken the send (after it answered for the mailbox; see
///   `gateway::prime`). Nothing confirms the contract took it or that the
///   seller ever looks. The button is an action label and says "Send";
///   what must not claim delivery is the CONFIRMATION, and a message not yet
///   seen in the mailbox says "sending" instead. Once the delivery check
///   gives up (harvest#119) its bubble says which of three things is true --
///   it never reached the node, fresh reads show it is not in the mailbox,
///   or Harvest could not confirm either way -- each with a "Send again".
///
/// None of that is said as a caveat on screen any more (round-6 critique):
/// the one line under the box is "Only {store} can read this."
///
/// # Why a store can still be unmessageable
///
/// Two independent reasons, and the notice names whichever applies:
///
/// 1. The seller published no encryption key -- every store created before
///    the field existed, and any seller whose delegate has not minted one.
/// 2. The store's ghostkey certificate does not verify against this store, so
///    [`crate::ghostkey_cert::store_verifying_key`] yields nothing and the
///    mailbox address cannot be derived. This also covers a store published
///    by a NEWER build of Harvest, which is indistinguishable here from a
///    stolen certificate.
#[component]
pub fn MessageView(store_contract_id: Vec<u8>) -> Element {
    let app_state = APP_STATE.read();
    let store = app_state.browsing_stores.get(&store_contract_id);
    let info = store.and_then(|s| s.info.as_ref());
    let store_name = info
        .map(|i| i.store_name.as_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("this store")
        .to_string();

    // A seller does not message their own store: their buyers' messages are
    // under each order on the Orders tab, and questions below them
    // (`invoice_form::StorePayments`).
    if app_state
        .store_owner_fingerprint(&store_contract_id)
        .is_some()
    {
        return rsx! {};
    }

    let seller_key = info.and_then(|i| i.encryption_public_key);
    // Reached once, when the store's state arrived, rather than recomputed
    // here: recovering it verifies a certificate chain including a blind-RSA
    // notary signature, and this component re-renders on every keystroke in
    // the box below. See `state::BrowsingStore::seller_verifying_key`.
    let seller_identity = store.and_then(|s| s.seller_verifying_key);
    let has_thread = !app_state.conversation_thread(&store_contract_id).is_empty()
        || !app_state.unconfirmed_sent(&store_contract_id).is_empty();
    // What this node is keeping, which is what the buyer can ask it to
    // forget. Empty until the delegate answers, and empty for a store this
    // node has never written to.
    let kept: Vec<([u8; 32], i64, bool)> = store
        .map(|store| {
            store
                .conversations
                .iter()
                .map(|conversation| {
                    (
                        conversation.buyer_public_key,
                        conversation.created_at,
                        conversation.backed_up,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let loaded = info.is_some();
    drop(app_state);

    rsx! {
        div { class: "card",
            h3 { "Ask {store_name} a question" }

            match (loaded, seller_key, seller_identity) {
                (false, _, _) => rsx! {
                    p { class: "text-muted text-italic", "Loading this store's details..." }
                },
                (true, Some(key), Some(identity)) => rsx! {
                    Compose {
                        store_contract_id: store_contract_id.clone(),
                        seller_encryption_key: key,
                        seller_verifying_key: identity,
                        target: None,
                        label: "Your question".to_string(),
                        placeholder: "Ask about a listing.".to_string(),
                        hint: format!(
                            "Only {store_name} can read this. Their reply appears here and in \
                             Purchases, on this device."
                        ),
                    }
                },
                // The seller published no key. Nothing can be encrypted to
                // them, and putting plaintext into a world-readable contract
                // would be worse than sending nothing.
                (true, None, _) => rsx! {
                    Unavailable {
                        why: "This seller has not published an encryption key, so there is no \
                              way to send them a private message. Stores created before Harvest \
                              supported messaging are in this state until the seller publishes \
                              their details again.".to_string()
                    }
                },
                // A key was published, but this build cannot work out where
                // the seller's mailbox is -- see the component docs.
                (true, Some(_), None) => rsx! {
                    Unavailable {
                        why: "Harvest cannot confirm this store's identity, so it cannot work \
                              out where the seller's mailbox is. Either the store's ghostkey \
                              certificate does not check out, or the store was published by a \
                              newer version of Harvest than this one. A message sent anyway \
                              could land in a stranger's mailbox, so nothing is sent."
                              .to_string()
                    }
                },
            }

            if has_thread {
                h4 { "Your messages" }
                Thread { store_contract_id: store_contract_id.clone(), tag: None }
            }

            KeptConversations {
                store_contract_id: store_contract_id.clone(),
                kept: kept,
            }
        }
    }
}

/// What this node is keeping so the seller's replies stay readable, and the
/// control that removes it.
///
/// # Why this is on screen at all
///
/// Keeping the conversation is what makes a reply readable after the tab
/// closes, and the same record is a durable local note that this node
/// contacted this store. The buyer is the only person who can weigh those
/// against each other, so the control is theirs -- and a control only a
/// programmer can reach is not one.
///
/// It removes the record rather than emptying it (the delegate deletes the
/// key, and re-reads it afterwards to check), so what is claimed here is what
/// happens. It cannot be undone: the messages stay in the seller's mailbox
/// and become unreadable by everyone, including the buyer.
#[component]
fn KeptConversations(store_contract_id: Vec<u8>, kept: Vec<([u8; 32], i64, bool)>) -> Element {
    // Which one is a click away from being destroyed, if any. Two steps
    // because there is no undo and no second copy anywhere.
    let mut confirming = use_signal(|| Option::<[u8; 32]>::None);
    let unsaved = kept.iter().filter(|(_, _, backed_up)| !backed_up).count();

    rsx! {
        div { style: "margin-top: 1.5rem;",
            if !kept.is_empty() {
                h4 { "Kept on this device" }
                p { class: "text-muted", style: "font-size: 0.85rem;",
                    "This node is keeping the key that reads {kept.len()} conversation(s) with "
                    "this store, so a reply is still readable after you close this tab."
                }
                if unsaved > 0 {
                    p { class: "text-warning", style: "font-size: 0.85rem;",
                        "{unsaved} of them exist on this device and nowhere else. If you lose "
                        "this machine you lose the conversation, and anything the seller sent "
                        "you in it. Make a backup you can keep somewhere else."
                    }
                }
            }
            for (tag, created_at, backed_up) in kept.iter() {
                {
                    let tag = *tag;
                    let backed_up = *backed_up;
                    let when = chrono::DateTime::from_timestamp(*created_at, 0)
                        .map(|when| when.format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_else(|| "an unknown time".to_string());
                    let store_contract_id = store_contract_id.clone();
                    rsx! {
                        div { class: "card", style: "margin-top: 0.5rem;",
                            p { class: "text-muted", style: "font-size: 0.8rem;",
                                "Conversation {short_tag(&tag)}, started {when}"
                            }
                            if backed_up {
                                p { class: "text-muted", style: "font-size: 0.8rem;",
                                    "You have said you hold a copy of this elsewhere."
                                }
                            } else {
                                p { class: "text-warning", style: "font-size: 0.8rem;",
                                    "On this device only."
                                }
                            }
                            ConversationBackupControl {
                                store_contract_id: store_contract_id.clone(),
                                tag: tag,
                            }
                            if confirming() == Some(tag) {
                                p { class: "text-warning", style: "font-size: 0.85rem;",
                                    "Forget this conversation? Your messages and the seller's "
                                    "replies stay in the seller's mailbox and become unreadable "
                                    "by everyone, including you. This cannot be undone."
                                }
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| {
                                        APP_STATE.write().forget_conversation(&store_contract_id, &tag);
                                        confirming.set(None);
                                    },
                                    "Yes, forget it"
                                }
                                button {
                                    class: "btn",
                                    onclick: move |_| confirming.set(None),
                                    "Keep it"
                                }
                            } else {
                                button {
                                    class: "btn",
                                    onclick: move |_| confirming.set(Some(tag)),
                                    "Forget this conversation"
                                }
                            }
                        }
                    }
                }
            }

            Restore {}
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
fn ConversationBackupControl(store_contract_id: Vec<u8>, tag: [u8; 32]) -> Element {
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
                class: "btn",
                onclick: move |_| {
                    APP_STATE.write().conversation_backup_on_screen = None;
                },
                "Hide it"
            }
        } else {
            button {
                class: "btn",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    move |_| APP_STATE.write().export_conversation(&store_contract_id, &tag)
                },
                "Back up this conversation"
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
fn Restore() -> Element {
    let mut paste = use_signal(String::new);

    rsx! {
        div { style: "margin-top: 1rem;",
            h4 { "Restore a conversation" }
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "A backup is a single line of text holding the key to ONE conversation. Paste "
                "one here to read that conversation on this device; paste them one after "
                "another if you saved several."
            }
            div { class: "form-group",
                textarea {
                    class: "form-textarea",
                    rows: 3,
                    placeholder: "Paste a Harvest conversation backup here.",
                    value: "{paste}",
                    oninput: move |event| paste.set(event.value()),
                }
            }
            button {
                class: "btn",
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
fn Thread(store_contract_id: Vec<u8>, tag: Option<[u8; 32]>) -> Element {
    let (lines, unconfirmed) = {
        let state = APP_STATE.read();
        let messages = buyer_messages(&state, &store_contract_id, tag);
        let unconfirmed: Vec<crate::state::SentMessage> = state
            .unconfirmed_sent(&store_contract_id)
            .into_iter()
            .filter(|sent| tag.is_none_or(|tag| sent.sealed.sender_public_key == tag))
            .collect();
        (chat_lines(&messages, Role::Buyer), unconfirmed)
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
                                crate::state::NotArrived::Unconfirmed => "You \u{00b7} not confirmed",
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

/// How many messages a buyer's conversation `tag` with a store shows as
/// chat, sent-but-not-landed included: the count on its Messages button.
pub(crate) fn buyer_thread_count(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    tag: [u8; 32],
) -> usize {
    let messages = buyer_messages(state, store_contract_id, Some(tag));
    let unconfirmed = state
        .unconfirmed_sent(store_contract_id)
        .iter()
        .filter(|sent| sent.sealed.sender_public_key == tag)
        .count();
    chat_lines(&messages, Role::Buyer).len() + unconfirmed
}

/// One of a buyer's conversations with a store, under the orders it holds
/// (or on its own for a question), behind a Messages button: the thread and
/// the box to write in it. The box is open without a Ghost Key once an order
/// in it is paid (`AppState::paid_conversation`).
#[component]
pub(crate) fn BuyerThread(
    store_contract_id: Vec<u8>,
    tag: [u8; 32],
    #[props(default)] open: bool,
) -> Element {
    let mut shown = use_signal(move || open);
    let count = buyer_thread_count(&APP_STATE.read(), &store_contract_id, tag);
    let label = match (shown(), count) {
        (true, _) => "Hide messages".to_string(),
        (false, 0) => "Message the seller".to_string(),
        (false, n) => format!("Messages ({n})"),
    };
    rsx! {
        div { class: "thread-toggle",
            button {
                class: "btn btn-sm btn-outline",
                aria_expanded: if shown() { "true" } else { "false" },
                onclick: move |_| shown.toggle(),
                "{label}"
            }
        }
        if shown() {
            div { class: "thread",
                Thread { store_contract_id: store_contract_id.clone(), tag: Some(tag) }
                OrderCompose { store_contract_id: store_contract_id.clone(), tag }
            }
        }
    }
}

/// The box to write into a buyer's conversation `tag` with a store: open
/// without a Ghost Key where an order in it is paid, gated otherwise.
#[component]
pub(crate) fn OrderCompose(store_contract_id: Vec<u8>, tag: [u8; 32]) -> Element {
    let (keys, name) = {
        let state = APP_STATE.read();
        let store = state.browsing_stores.get(&store_contract_id);
        let key = store
            .and_then(|s| s.info.as_ref())
            .and_then(|i| i.encryption_public_key);
        let identity = store.and_then(|s| s.seller_verifying_key);
        (
            key.zip(identity),
            state.store_name_of(&store_contract_id).label(),
        )
    };
    match keys {
        Some((key, identity)) => rsx! {
            Compose {
                store_contract_id: store_contract_id.clone(),
                seller_encryption_key: key,
                seller_verifying_key: identity,
                target: Some(tag),
                label: "Message".to_string(),
                placeholder: "Message the seller.".to_string(),
                hint: format!("Only {name} can read this."),
            }
        },
        None => rsx! {
            p { class: "text-muted small",
                "This store can't be messaged from here right now. Open its page to see why."
            }
        },
    }
}

/// The compose box, shown only when a message can genuinely be sealed and
/// addressed.
///
/// `target` is the conversation it writes into: an order's own thread, or
/// (`None`) whichever conversation a new message continues. The gate is that
/// conversation's (`AppState::compose_gate_in`): open without a Ghost Key
/// where an order in it is paid, else a Ghost Key's.
#[component]
fn Compose(
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

    let (gate, signing, failure, name) = {
        let state = APP_STATE.read();
        (
            state.compose_gate_in(&store_contract_id, target),
            state.texts_awaiting_voucher(&store_contract_id),
            state.voucher_failure(&store_contract_id).cloned(),
            state.store_name_of(&store_contract_id).label(),
        )
    };
    // No Ghost Key and nothing paid, no compose box: the seller would not be
    // shown what was typed (`shown_to_seller`), so offering the box would be
    // a dead end.
    if gate == crate::voucher_flow::ComposeGate::NeedsGhostKey {
        return rsx! {
            GhostKeyGate { after_payment: target.is_some() }
        };
    }
    let vouched = matches!(gate, crate::voucher_flow::ComposeGate::Ready { .. });

    let can_send = !draft().trim().is_empty();

    rsx! {
        div { class: "form-group",
            label { class: "form-label", "{label}" }
            textarea {
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
/// that buying does not need one, and where to get one. In an order's own
/// thread (`after_payment`) it also says the box opens once the order is
/// paid.
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
fn Unavailable(why: String) -> Element {
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
pub(crate) const SOME_UNREADABLE: &str = "Some messages couldn't be read on this device.";

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

/// The name above a message, and whether it is drawn as this side's own.
///
/// By the direction key that sealed it: toward the other side is "You",
/// toward this side is "Buyer" (on the seller's screen) or "Seller" (on the
/// buyer's). Direction is not authorship -- both parties hold both keys, so
/// either can seal a message that reads as the other's (a seller's inbox once
/// showed "as agreed, I confess" as the seller's own reply, written by the
/// buyer). It is still the right label. Only the two parties can write a
/// readable entry at all, so the only person a mislabelled message can
/// deceive is one of the two who were there; nobody else ever sees it, and
/// Harvest has no arbiter to show it to. What needs real authenticity carries
/// its own signature (`harvest_common::mailbox::MessageDirection`). The
/// earlier wording ("Addressed to this buyer", a caveat per conversation)
/// told the reader that, eight times a screen, and helped nobody (round-6
/// critique 10-5).
fn who(role: Role, addressing: crate::messaging::Addressing) -> (&'static str, bool) {
    use crate::messaging::Addressing;
    match (role, addressing) {
        (Role::Buyer, Addressing::ToSeller) | (Role::Seller, Addressing::ToBuyer) => ("You", true),
        (Role::Buyer, Addressing::ToBuyer) => ("Seller", false),
        (Role::Seller, Addressing::ToSeller) => ("Buyer", false),
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
    who: &'static str,
    mine: bool,
    when: String,
    item: ChatItem,
}

/// A buyer's messages as chat lines, in the order given.
fn chat_lines(messages: &[crate::messaging::ConversationMessage], role: Role) -> Vec<ChatLine> {
    messages
        .iter()
        .filter_map(|message| {
            let item = chat_item(&message.content)?;
            let (who, mine) = who(role, message.addressing);
            Some(ChatLine {
                who,
                mine,
                when: when(message.timestamp),
                item,
            })
        })
        .collect()
}

/// A conversation, as bubbles (mockup `msgs()`).
#[component]
fn ChatLines(lines: Vec<ChatLine>) -> Element {
    rsx! {
        div { class: "bubbles",
            for line in lines.iter() {
                match &line.item {
                    ChatItem::Said(text) => rsx! {
                        div { class: if line.mine { "bubble mine" } else { "bubble" },
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
    }
}

/// One conversation in a seller's mailbox, as the seller is shown it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SellerThread {
    pub tag: [u8; 32],
    /// Whether it is open ([`open_conversations`]): a verified voucher or a
    /// paid order of the store's in it.
    pub open: bool,
    /// Its readable entries as [`shown_to_seller`] shows them, newest first.
    pub entries: Vec<MailboxEntry>,
    /// The store's orders that belong to it
    /// (`order_threads::order_in_conversation`), whatever their status: the
    /// order cards it is shown under.
    pub orders: Vec<harvest_common::payment::OrderId>,
}

impl SellerThread {
    /// Its chat lines, oldest first.
    fn lines(&self) -> Vec<ChatLine> {
        let mut lines: Vec<(chrono::DateTime<chrono::Utc>, ChatLine)> = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                MailboxEntry::Readable {
                    content,
                    addressing,
                    timestamp,
                    ..
                } => {
                    let item = chat_item(content)?;
                    let (who, mine) = who(Role::Seller, *addressing);
                    Some((
                        *timestamp,
                        ChatLine {
                            who,
                            mine,
                            when: when(*timestamp),
                            item,
                        },
                    ))
                }
                MailboxEntry::Unreadable { .. } => None,
            })
            .collect();
        lines.sort_by_key(|(at, _)| *at);
        lines.into_iter().map(|(_, line)| line).collect()
    }

    /// How many messages it shows as chat: the count on its button.
    pub(crate) fn chat_count(&self) -> usize {
        self.lines().len()
    }

    /// The newest thing a buyer wrote in it, for a question's row.
    fn latest_from_buyer(&self) -> Option<(String, chrono::DateTime<chrono::Utc>)> {
        self.entries.iter().find_map(|entry| match entry {
            MailboxEntry::Readable {
                content: MessageContent::Text(text) | MessageContent::VouchedText { text, .. },
                addressing: crate::messaging::Addressing::ToSeller,
                timestamp,
                ..
            } => Some((text.clone(), *timestamp)),
            _ => None,
        })
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
    pub(crate) fn for_order(&self, id: &harvest_common::payment::OrderId) -> Option<&SellerThread> {
        self.threads
            .iter()
            .find(|thread| thread.orders.contains(id))
    }
}

/// [`SellerInbox`] for one of our stores. The anti-spam gate's seller half
/// runs here, before anything is grouped: buyer text neither a Ghost Key nor
/// a paid order vouches for is taken out ([`shown_to_seller`]), and the
/// address of an order past its complaint window is hidden
/// ([`request_address_hidden`]).
pub(crate) fn seller_inbox(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
) -> SellerInbox {
    let Some(store) = state.browsing_stores.get(store_contract_id) else {
        return SellerInbox::default();
    };
    let all = state.mailbox_entries(store_contract_id);
    let unreadable = all
        .iter()
        .filter(|entry| matches!(entry, MailboxEntry::Unreadable { .. }))
        .count();
    let claims = seller_claims(&all, &store.listings, |tag| {
        state.conversation_keys.get(tag)
    });
    let paid: std::collections::HashSet<[u8; 32]> = claims
        .iter()
        .filter(|(_, claims)| {
            crate::order_threads::conversation_has_paid_order(&store.orders, claims)
        })
        .map(|(tag, _)| *tag)
        .collect();
    // `shown_to_seller` works the vouchers out again below; that is a cache
    // hit (`voucher_verifies` remembers each verdict), not a second chain
    // check.
    let open = open_conversations(
        &all,
        |voucher, tag| state.voucher_verifies(voucher, tag),
        |tag| paid.contains(tag),
    );
    let (shown, held_back) = shown_to_seller(
        all,
        |voucher, tag| state.voucher_verifies(voucher, tag),
        |tag| paid.contains(tag),
        |entry| {
            request_address_hidden(
                entry,
                &store.orders,
                state.conversation_keys.get(entry.conversation()),
                |order| state.address_retained_for(order),
            )
        },
        |digest| state.authored_here(store_contract_id, digest),
    );
    let threads = claims
        .iter()
        .map(|(tag, claims)| SellerThread {
            tag: *tag,
            open: open.contains(tag.as_slice()),
            entries: shown
                .iter()
                .filter(|entry| {
                    entry.conversation() == tag.as_slice()
                        && matches!(entry, MailboxEntry::Readable { .. })
                })
                .cloned()
                .collect(),
            orders: store
                .orders
                .iter()
                .filter(|order| crate::order_threads::order_in_conversation(order, claims))
                .map(|order| order.order.id.clone())
                .collect(),
        })
        .filter(|thread| !thread.entries.is_empty())
        .collect();
    SellerInbox {
        threads,
        unreadable,
        held_back,
    }
}

/// Which seller conversation is open on the Orders tab, and under which
/// order card (or none, a question): one at a time, so the guidance line
/// above its reply box is said once per screen.
pub(crate) type OpenThread = Option<([u8; 32], Option<harvest_common::payment::OrderId>)>;

/// The requests in `thread` the seller is offered a hand answer for.
fn offered_requests(
    state: &crate::state::AppState,
    thread: &SellerThread,
    listings: &[harvest_common::listing::AuthorizedListing],
    published: &[harvest_common::payment::AuthorizedOrder],
) -> Vec<PendingRequest> {
    unanswered_requests(
        &thread.entries,
        listings,
        published,
        state.conversation_keys.get(thread.tag.as_slice()),
    )
    .into_iter()
    .filter(|request| offered_by_hand(request, thread.open))
    .collect()
}

/// Whether a seller conversation with no order card of its own is worth a
/// row among the questions: something a person wrote, or a request waiting
/// for the seller's answer. An unpaid Buy now alone is neither: the store
/// answers it itself, and the seller hears of it once it is paid.
pub(crate) fn is_question(
    state: &crate::state::AppState,
    store_contract_id: &[u8],
    thread: &SellerThread,
) -> bool {
    if thread.chat_count() > 0 && thread.open {
        return true;
    }
    let Some(store) = state.browsing_stores.get(store_contract_id) else {
        return false;
    };
    !offered_requests(state, thread, &store.listings, &store.orders).is_empty()
}

/// The Messages button under an order card (or a question), and the
/// conversation it opens.
#[component]
pub(crate) fn SellerThreadToggle(
    store_contract_id: Vec<u8>,
    thread: SellerThread,
    under: Option<harvest_common::payment::OrderId>,
    open_thread: Signal<OpenThread>,
) -> Element {
    let me = (thread.tag, under.clone());
    let shown = open_thread().as_ref() == Some(&me);
    let count = thread.chat_count();
    let label = match (shown, count) {
        (true, _) => "Hide messages".to_string(),
        (false, 0) => "Message the buyer".to_string(),
        (false, n) => format!("Messages ({n})"),
    };
    rsx! {
        div { class: "thread-toggle",
            button {
                class: "btn btn-sm btn-outline",
                aria_expanded: if shown { "true" } else { "false" },
                onclick: move |_| {
                    let mut open_thread = open_thread;
                    let now = if shown { None } else { Some(me.clone()) };
                    open_thread.set(now);
                },
                "{label}"
            }
        }
        if shown {
            SellerConversation { store_contract_id: store_contract_id.clone(), thread: thread.clone() }
        }
    }
}

/// One conversation with one buyer, as the seller reads it: the messages,
/// any request still waiting for a hand answer (shown as the request it is,
/// with its accept control), the guidance line, and the reply box.
#[component]
fn SellerConversation(store_contract_id: Vec<u8>, thread: SellerThread) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);
    let (offered, availability) = {
        let state = APP_STATE.read();
        let store = state.browsing_stores.get(&store_contract_id);
        let offered = store
            .map(|store| offered_requests(&state, &thread, &store.listings, &store.orders))
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
    let lines = thread.lines();
    let tag = thread.tag;

    rsx! {
        div { class: "thread",
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
                    RequestDetails { thread: thread.clone(), digest: request.digest }
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
                label { class: "form-label", "Reply" }
                textarea {
                    class: "form-textarea",
                    value: "{draft}",
                    placeholder: "Reply to this buyer.",
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
            p { class: "text-muted small", "Only this buyer can read your reply." }
        }
    }
}

/// What a request still waiting for the seller asks for, read from its entry
/// in the conversation: the address (or why it is not shown), the buyer's
/// picks, and the note.
#[component]
fn RequestDetails(thread: SellerThread, digest: [u8; 32]) -> Element {
    let Some(MailboxEntry::Readable {
        content:
            MessageContent::OrderRequest {
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
    let region = instant.as_ref().and_then(|s| s.region.clone());
    let choices = instant
        .as_ref()
        .map(|s| s.choices.join(" \u{00b7} "))
        .unwrap_or_default();
    rsx! {
        p { class: "order-label", "Send to" }
        p { class: "order-ship-to", "{shipping}" }
        if let Some(region) = region {
            p { class: "text-muted small", "Delivery region: {region}" }
        }
        if !choices.is_empty() {
            p { class: "text-muted small", "{choices}" }
        }
        if !note.trim().is_empty() {
            p { class: "order-label", "Note from the buyer" }
            p { class: "order-ship-to", "{note}" }
        }
    }
}

/// The seller's conversations with no order card of their own: questions
/// from buyers with a Ghost Key, and requests waiting for a hand answer
/// ([`is_question`]). Under the orders on the Orders tab, each behind its own
/// Messages button (the mockup has no seller screen for questions; this is
/// the closest honest place, where the seller already reads buyers).
#[component]
pub(crate) fn SellerQuestions(
    store_contract_id: Vec<u8>,
    threads: Vec<SellerThread>,
    open_thread: Signal<OpenThread>,
) -> Element {
    rsx! {
        div { class: "card",
            h3 { "Questions" }
            for thread in threads.iter() {
                {
                    let summary = thread.latest_from_buyer();
                    rsx! {
                        div { key: "{bs58::encode(thread.tag).into_string()}", class: "question-row",
                            match summary {
                                Some((text, at)) => rsx! {
                                    p { class: "question-text", "{text}" }
                                    p { class: "text-muted small", "Buyer \u{00b7} {when(at)}" }
                                },
                                None => rsx! {
                                    p { class: "text-muted small", "A request waiting for your answer" }
                                },
                            }
                            SellerThreadToggle {
                                store_contract_id: store_contract_id.clone(),
                                thread: thread.clone(),
                                under: None,
                                open_thread,
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The line a seller sees about buyer text [`shown_to_seller`] held back:
/// messages left out, and notes and reasons blanked in a conversation that
/// is not open.
pub(crate) fn hidden_unvouched_line(hidden: usize) -> String {
    if hidden == 1 {
        "1 message was held back because it came without a Ghost Key or a paid order.".to_string()
    } else {
        format!(
            "{hidden} messages were held back because they came without a Ghost Key or a paid \
             order."
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
///   (`attribution`), so a script can flip the direction;
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
/// messages left out, and requests whose note or picks were blanked. Not
/// counted: a blanked address (a seller is not told about an unpaid Buy now
/// at all), a blanked decline (mostly the store's own answer to one), and
/// reply-direction text left out (as likely the seller's own, after a reload,
/// as anyone's).
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
    published: &[harvest_common::payment::AuthorizedOrder],
    keys: Option<&crate::messaging::ConversationKeys>,
    retained: impl Fn(&harvest_common::payment::AuthorizedOrder) -> bool,
) -> bool {
    let MailboxEntry::Readable {
        conversation,
        content:
            MessageContent::OrderRequest {
                listing_id,
                order_binding,
                instant,
                ..
            },
        ..
    } = entry
    else {
        return false;
    };
    let Ok(tag) = <[u8; 32]>::try_from(conversation.as_slice()) else {
        return false;
    };
    let answering = |order: &harvest_common::payment::AuthorizedOrder| match instant {
        Some(selection) => selection
            .answered_request(&tag)
            .is_some_and(|request| request.order_id() == order.order.id),
        None => {
            order.order.request_id.is_none()
                && order.order.order_binding == Some(*order_binding)
                && keys.is_some_and(|keys| {
                    order.order.listing_tag == Some(keys.listing_tag(listing_id))
                })
        }
    };
    published
        .iter()
        .any(|order| answering(order) && !retained(order))
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
                if !note.trim().is_empty() || picks == Some(true) {
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

/// Whether the seller's inbox offers to answer `request` by hand. A Buy now
/// only in an open conversation ([`open_conversations`]: a verified voucher
/// or a paid Buy now in it): elsewhere its picks are blanked, so the seller
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
/// against (`order_threads::ConversationClaims`), newest conversation first:
/// the requests to buy read in it, in either direction (only the two holders
/// of its keys can write a readable entry, and the order must still be the
/// store's own), and the store's current listings, under that conversation's
/// keys when this seller holds them.
pub(crate) fn seller_claims<'a>(
    entries: &[MailboxEntry],
    listings: &[harvest_common::listing::AuthorizedListing],
    keys_for: impl Fn(&[u8]) -> Option<&'a crate::messaging::ConversationKeys>,
) -> Vec<([u8; 32], crate::order_threads::ConversationClaims)> {
    let mut tags: Vec<[u8; 32]> = Vec::new();
    for entry in entries {
        if let Ok(tag) = <[u8; 32]>::try_from(entry.conversation()) {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
    tags.into_iter()
        .map(|tag| {
            let requests = entries.iter().filter_map(|entry| match entry {
                MailboxEntry::Readable {
                    conversation,
                    content:
                        MessageContent::OrderRequest {
                            listing_id,
                            instant,
                            ..
                        },
                    ..
                } if conversation.as_slice() == tag.as_slice() => {
                    Some((listing_id, instant.as_ref()))
                }
                _ => None,
            });
            let keys = keys_for(&tag);
            let claims = crate::order_threads::ConversationClaims::of(
                &tag,
                requests,
                listings.iter().map(|l| &l.listing.id),
                |listing| keys.map(|keys| keys.listing_tag(listing)),
            );
            (tag, claims)
        })
        .collect()
}

/// The conversations in a seller's inbox that one of the store's own paid
/// orders opens (`order_threads::conversation_has_paid_order`): what opens a
/// conversation to the seller without a voucher ([`shown_to_seller`]).
pub(crate) fn paid_conversations<'a>(
    entries: &[MailboxEntry],
    published: &[harvest_common::payment::AuthorizedOrder],
    listings: &[harvest_common::listing::AuthorizedListing],
    keys_for: impl Fn(&[u8]) -> Option<&'a crate::messaging::ConversationKeys>,
) -> std::collections::HashSet<[u8; 32]> {
    seller_claims(entries, listings, keys_for)
        .into_iter()
        .filter(|(_, claims)| crate::order_threads::conversation_has_paid_order(published, claims))
        .map(|(tag, _)| tag)
        .collect()
}

/// The request to buy this conversation is waiting on, if any.
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
fn unanswered_requests(
    entries: &[MailboxEntry],
    listings: &[harvest_common::listing::AuthorizedListing],
    published: &[harvest_common::payment::AuthorizedOrder],
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
            let id = request.order_id();
            if published.iter().any(|order| order.order.id == id) {
                continue;
            }
        }
        let answered = request.is_none()
            && keys.is_some_and(|keys| {
                let tag = keys.listing_tag(listing_id);
                let answers: Vec<&harvest_common::payment::AuthorizedOrder> = published
                    .iter()
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
    let mut conversations: Vec<(Vec<u8>, Vec<MailboxEntry>)> = Vec::new();
    for entry in entries {
        match conversations
            .iter_mut()
            .find(|(tag, _)| tag.as_slice() == entry.conversation())
        {
            Some((_, group)) => group.push(entry),
            None => conversations.push((entry.conversation().to_vec(), vec![entry])),
        }
    }
    conversations
        .iter()
        .map(|(tag, group)| {
            unanswered_requests(group, listings, published, keys_for(tag))
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
        let tag = [1u8; 32];
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
        let entries = [buy_now];
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
        let quote = request(id.clone(), 1, [2u8; 32]);
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
        assert!(request_address_hidden(
            &buy_now,
            &[own.clone()],
            Some(&k),
            |_| false
        ));
        assert!(!request_address_hidden(&buy_now, &[own], Some(&k), |_| {
            true
        }));
        let other = published(2, Some(BINDING), None);
        assert!(!request_address_hidden(
            &buy_now,
            &[other],
            Some(&k),
            |_| false
        ));

        let quote = request(id.clone(), 1, [2u8; 32]);
        let invoice = published(3, Some(BINDING), Some(k.listing_tag(&id)));
        assert!(request_address_hidden(
            &quote,
            std::slice::from_ref(&invoice),
            Some(&k),
            |_| false
        ));
        assert!(!request_address_hidden(
            &quote,
            std::slice::from_ref(&invoice),
            None,
            |_| false
        ));
        let mut elsewhere = invoice;
        elsewhere.order.order_binding = Some([0x11; 32]);
        assert!(!request_address_hidden(
            &quote,
            &[elsewhere],
            Some(&k),
            |_| false
        ));
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

    /// Bubbles are labelled by side, "You" for this side's direction, and
    /// never "Addressed to" with a caveat (round-6 critique 10-5).
    #[test]
    fn bubbles_are_labelled_by_side() {
        use crate::messaging::Addressing::{ToBuyer, ToSeller};
        assert_eq!(who(Role::Seller, ToSeller), ("Buyer", false));
        assert_eq!(who(Role::Seller, ToBuyer), ("You", true));
        assert_eq!(who(Role::Buyer, ToBuyer), ("Seller", false));
        assert_eq!(who(Role::Buyer, ToSeller), ("You", true));
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
        // The note; an address or a decline held back is not counted.
        assert_eq!(hidden, 1);

        // A Buy now's picks are the buyer's text too.
        let (shown_entries, hidden) = shown(vec![buy_now_picking(
            OTHER,
            "",
            Some("cheap pills at spam.example"),
            vec!["visit spam.example".into()],
        )]);
        assert_eq!(hidden, 1);
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
            "1 message was held back because it came without a Ghost Key or a paid order."
        );
        assert_eq!(
            hidden_unvouched_line(3),
            "3 messages were held back because they came without a Ghost Key or a paid order."
        );
    }
}
