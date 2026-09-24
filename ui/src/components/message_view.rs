use dioxus::prelude::*;

use crate::gateway::APP_STATE;
use crate::messaging::{MailboxEntry, MessageContent};

/// Buyer-to-seller messaging.
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
///   what must not claim delivery is the CONFIRMATION, and the list of what
///   was written says "handed to your Freenet node" instead. Once the
///   delivery check gives up (harvest#119) the card says which of three
///   things is true -- it never reached the node, fresh reads show it is not
///   in the mailbox, or Harvest could not confirm either way -- each with a
///   "Send again".
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

    // A store the connected identity owns is read, not written to: the
    // seller is the mailbox's audience, and there is nobody for them to
    // compose to.
    let owned = app_state
        .store_owner_fingerprint(&store_contract_id)
        .is_some();

    if owned {
        let entries = app_state.mailbox_entries(&store_contract_id);
        // The only authorship this client can establish: what it sent itself.
        let authored: Vec<[u8; 32]> = entries
            .iter()
            .map(|entry| entry.digest())
            .filter(|digest| app_state.authored_here(&store_contract_id, digest))
            .collect();
        let (listings, published) = store
            .map(|store| (store.listings.clone(), store.orders.clone()))
            .unwrap_or_default();
        drop(app_state);
        return rsx! {
            Inbox {
                store_contract_id: store_contract_id.clone(),
                entries: entries,
                authored: authored,
                listings: listings,
                published: published,
            }
        };
    }

    let seller_key = info.and_then(|i| i.encryption_public_key);
    // Reached once, when the store's state arrived, rather than recomputed
    // here: recovering it verifies a certificate chain including a blind-RSA
    // notary signature, and this component re-renders on every keystroke in
    // the box below. See `state::BrowsingStore::seller_verifying_key`.
    let seller_identity = store.and_then(|s| s.seller_verifying_key);
    let thread = app_state.conversation_thread(&store_contract_id);
    let unconfirmed = app_state.unconfirmed_sent(&store_contract_id);
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
    let authored_here: Vec<[u8; 32]> = thread
        .iter()
        .map(|message| message.digest)
        .filter(|digest| app_state.authored_here(&store_contract_id, digest))
        .collect();
    let loaded = info.is_some();
    drop(app_state);

    rsx! {
        div { class: "card",
            h3 { "Contact {store_name}" }

            match (loaded, seller_key, seller_identity) {
                (false, _, _) => rsx! {
                    p { class: "text-muted text-italic", "Loading this store's details..." }
                },
                (true, Some(key), Some(identity)) => rsx! {
                    Compose {
                        store_contract_id: store_contract_id.clone(),
                        seller_encryption_key: key,
                        seller_verifying_key: identity,
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

            if !thread.is_empty() || !unconfirmed.is_empty() {
                Thread {
                    store_contract_id: store_contract_id.clone(),
                    thread: thread,
                    unconfirmed: unconfirmed,
                    authored_here: authored_here,
                }
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
            // useless, and nothing would say so until it was needed.
            textarea {
                class: "form-textarea copy-field",
                readonly: true,
                spellcheck: false,
                aria_label: "Conversation backup, select to copy",
                rows: 3,
                value: "{backup}",
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

/// The buyer's conversation with one store: what they wrote, what came back,
/// and what has not been seen landing yet.
#[component]
fn Thread(
    store_contract_id: Vec<u8>,
    thread: Vec<crate::messaging::ConversationMessage>,
    unconfirmed: Vec<crate::state::SentMessage>,
    /// Entry digests this browser wrote. The ONLY authorship anything here
    /// can establish -- see `state::AppState::authored_here`. Digests rather
    /// than nonces because a nonce is public and a substitute shares it.
    authored_here: Vec<[u8; 32]>,
) -> Element {
    rsx! {
        div { style: "margin-top: 1.5rem;",
            h4 { "Your conversation" }
            p { class: "text-muted",
                style: "font-size: 0.85rem;",
                "This conversation survives a reload on this device: the key that reads it is "
                "kept by your Freenet node. It does not follow you to another browser or "
                "another device, where the same messages cannot be read by anyone."
            }
            p { class: "text-muted",
                style: "font-size: 0.85rem;",
                "Only messages this tab sent are marked as yours. Everything else is shown "
                "by which direction it was encrypted for, which is not proof of who wrote "
                "it -- both sides of a conversation hold both keys."
            }

            for message in thread.iter() {
                {
                    let when = message.timestamp.format("%Y-%m-%d %H:%M UTC").to_string();
                    let who = attribution(
                        authored_here.contains(&message.digest),
                        message.addressing,
                        Role::Buyer,
                    );
                    rsx! {
                        div { class: "card",
                            style: "margin-top: 0.5rem;",
                            p { class: "text-muted", style: "font-size: 0.8rem;", "{who}" }
                            p { style: "white-space: pre-wrap;", "{describe(&message.content)}" }
                            p { class: "text-muted",
                                style: "font-size: 0.8rem;",
                                "Sender's timestamp: {when}"
                            }
                        }
                    }
                }
            }

            // Handed to the node, not yet seen in the seller's mailbox. Kept
            // separate from the thread above rather than shown as sent,
            // because "the node accepted it" and "it is in the mailbox" are
            // different claims and only the second is evidence.
            //
            // Once the delivery check has given up (harvest#119) it says the
            // seller does not have it, and offers the one thing that helps.
            for message in unconfirmed.iter() {
                if let Some(why) = message.not_arrived {
                    {
                        let store_contract_id = store_contract_id.clone();
                        let digest = message.digest;
                        let explanation = match why {
                            crate::state::NotArrived::NeverReachedNode => {
                                "The seller has not received this. It never reached your Freenet \
                                 node, so nothing was sent."
                            }
                            crate::state::NotArrived::NotInMailbox => {
                                "The seller has not received this yet. Harvest sent it more than \
                                 once and it is still not in their mailbox. Sending it again \
                                 cannot deliver it twice."
                            }
                            crate::state::NotArrived::Unconfirmed => {
                                "Harvest could not confirm that this reached the seller's \
                                 mailbox. It may have arrived. Sending it again cannot deliver \
                                 it twice."
                            }
                        };
                        let label = match why {
                            crate::state::NotArrived::Unconfirmed => "You — not confirmed",
                            crate::state::NotArrived::NeverReachedNode
                            | crate::state::NotArrived::NotInMailbox => "You — not received",
                        };
                        rsx! {
                            div { class: "card",
                                style: "margin-top: 0.5rem;",
                                p { class: "text-muted", style: "font-size: 0.8rem;", "{label}" }
                                p { style: "white-space: pre-wrap;", "{message.text}" }
                                p { class: "text-warning",
                                    style: "font-size: 0.8rem;",
                                    "{explanation}"
                                }
                                button {
                                    class: "btn btn-sm",
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
                    div { class: "card",
                        style: "margin-top: 0.5rem;",
                        p { class: "text-muted", style: "font-size: 0.8rem;", "You — not yet visible" }
                        p { style: "white-space: pre-wrap;", "{message.text}" }
                        p { class: "text-warning",
                            style: "font-size: 0.8rem;",
                            "Handed to your Freenet node. It has not appeared in the seller's "
                            "mailbox yet, so Harvest cannot say it arrived."
                        }
                    }
                }
            }
        }
    }
}

/// The compose box, shown only when a message can genuinely be sealed and
/// addressed.
#[component]
fn Compose(
    store_contract_id: Vec<u8>,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);

    let can_send = !draft().trim().is_empty();

    rsx! {
        p { class: "text-muted",
            style: "margin-bottom: 1rem;",
            "Your message is encrypted to this seller's published key before it leaves your "
            "browser, and only they can read it -- the matching secret never leaves their "
            "Harvest delegate. Anyone watching the network can still see that you wrote to "
            "this store, just not what you said."
        }
        p { class: "text-muted",
            style: "margin-bottom: 1rem;",
            "The seller replies into the same mailbox and their answer appears here. Reading "
            "it needs a key your node keeps for you, so it survives closing this tab but does "
            "not follow you to another device -- come back to this one for the answer."
        }

        div { class: "form-group",
            label { class: "form-label", "Your Message" }
            textarea {
                class: "form-textarea",
                value: "{draft}",
                placeholder: "Ask about a listing, or arrange a trade.",
                oninput: move |event| draft.set(event.value()),
            }
        }

        if let Some(message) = problem() {
            p { class: "text-warning", "{message}" }
        }

        button {
            class: "btn btn-primary",
            disabled: !can_send,
            onclick: move |_| {
                let text = draft().trim().to_string();
                if text.is_empty() {
                    return;
                }
                match send(&store_contract_id, &seller_encryption_key, &seller_verifying_key, text) {
                    Ok(()) => {
                        draft.set(String::new());
                        problem.set(None);
                    }
                    Err(e) => problem.set(Some(e)),
                }
            },
            "Send to seller"
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
) -> Result<(), String> {
    let seller = ed25519_dalek::VerifyingKey::from_bytes(seller_verifying_key)
        .map_err(|e| format!("this store's identity key is unusable: {e}"))?;

    let sealed = APP_STATE.write().compose_to_seller(
        store_contract_id,
        seller_encryption_key,
        text.clone(),
    )?;
    deliver_to_seller(store_contract_id, seller, text, sealed)
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

/// The seller's own mailbox.
///
/// Unreadable entries are shown rather than hidden. The mailbox is
/// open-write, so anyone may deposit bytes in it, and a seller who saw only
/// the readable ones could not tell "nobody wrote" from "I cannot read what
/// they wrote".
#[component]
fn Inbox(
    store_contract_id: Vec<u8>,
    entries: Vec<MailboxEntry>,
    authored: Vec<[u8; 32]>,
    listings: Vec<harvest_common::listing::AuthorizedListing>,
    published: Vec<harvest_common::payment::AuthorizedOrder>,
) -> Element {
    if entries.is_empty() {
        return rsx! {
            div { class: "card",
                h3 { "Messages" }
                p { class: "text-muted text-italic", "No one has written to this store yet." }
            }
        };
    }

    let unreadable = entries
        .iter()
        .filter(|entry| matches!(entry, MailboxEntry::Unreadable { .. }))
        .count();

    // Grouped by conversation, newest conversation first, because a reply
    // belongs to a conversation rather than to a message -- and because an
    // ungrouped list of a busy mailbox gives the seller no way to see which
    // messages are one exchange.
    let mut conversations: Vec<(Vec<u8>, Vec<MailboxEntry>)> = Vec::new();
    for entry in entries.iter() {
        match conversations
            .iter_mut()
            .find(|(tag, _)| tag == entry.conversation())
        {
            Some((_, group)) => group.push(entry.clone()),
            None => conversations.push((entry.conversation().to_vec(), vec![entry.clone()])),
        }
    }

    rsx! {
        div { class: "card",
            h3 { "Messages" }
            p { class: "section-count",
                "{entries.len()} message(s) in {conversations.len()} conversation(s)"
            }
            if unreadable > 0 {
                p { class: "text-muted",
                    style: "font-size: 0.85rem;",
                    "{unreadable} of these cannot be read. Anyone can write to this mailbox, "
                    "so some entries are junk or were encrypted to a key you do not hold."
                }
            }
            for (tag, group) in conversations.iter() {
                Conversation {
                    key: "{bs58::encode(tag).into_string()}",
                    store_contract_id: store_contract_id.clone(),
                    tag: tag.clone(),
                    entries: group.clone(),
                    authored: authored.clone(),
                    listings: listings.clone(),
                    published: published.clone(),
                }
            }
        }
    }
}

/// One exchange with one buyer, and the box to answer it.
#[component]
fn Conversation(
    store_contract_id: Vec<u8>,
    tag: Vec<u8>,
    entries: Vec<MailboxEntry>,
    authored: Vec<[u8; 32]>,
    /// The store's own listings, so the accept control can NAME what it is
    /// about to price. The buyer's message carries a listing id and nothing
    /// readable; a seller typing a satoshi amount for an item the screen
    /// never names is being asked to sign for something they cannot see.
    listings: Vec<harvest_common::listing::AuthorizedListing>,
    /// What this store has already published, which is how an already-
    /// answered request is recognised after a reload.
    published: Vec<harvest_common::payment::AuthorizedOrder>,
) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);

    // A conversation with nothing readable in it cannot be replied to: the
    // reply has to name the conversation id, which only a decrypted message
    // carries. Saying so beside the exchange is better than a Send button
    // that refuses.
    let readable = entries
        .iter()
        .any(|entry| matches!(entry, MailboxEntry::Readable { .. }));

    rsx! {
        div { class: "card", style: "margin-top: 1rem;",
            p { class: "text-muted", style: "font-size: 0.8rem;",
                "Conversation {short_tag(&tag)}"
            }
            p { class: "text-muted", style: "font-size: 0.8rem;",
                "Only messages this tab sent are marked as yours. Everything else is shown by "
                "the direction it was encrypted for, which is not proof of who wrote it -- "
                "both sides of a conversation hold both keys."
            }
            for entry in entries.iter() {
                MessageCard {
                    entry: entry.clone(),
                    authored_here: authored.contains(&entry.digest()),
                }
            }

            // A request to buy is the one message in a seller's inbox that
            // has an action attached, so it gets the control rather than
            // leaving the seller to copy a listing id into the invoice form
            // by hand -- which is also how the reply-to tag would get lost.
            for request in unanswered_requests(
                &entries,
                &listings,
                &published,
                crate::gateway::APP_STATE.read().conversation_keys.get(&tag),
            ) {
                // The key sits on the first node of the loop body, the only
                // place dioxus reads a list key from, so each request keeps
                // its own accept control's state when an earlier one drops
                // out of the list.
                div { key: "{bs58::encode(request.digest).into_string()}",
                    // A request made before the listing sold out, or for a
                    // listing since replaced by an edit (harvest#70), can
                    // still be answered: the buyer asked while it was on
                    // sale. The seller is told, so they decide knowingly.
                    if !crate::gateway::APP_STATE
                        .read()
                        .listing_availability(&store_contract_id, &request.listing_id)
                        .is_buyable()
                    {
                        p { class: "text-muted small",
                            "{request.listing_title} is no longer on sale in your store. You can still \
                             invoice this buyer, since they asked while it was, or reply to say it has gone."
                        }
                    }
                    super::buy_view::AcceptRequest {
                        store_contract_id: store_contract_id.clone(),
                        tag: tag.clone(),
                        listing_id: request.listing_id.clone(),
                        listing_title: request.listing_title.clone(),
                        order_binding: request.order_binding,
                        buyer_receipt_key: request.buyer_receipt_key,
                        quantity: request.quantity,
                        instant: request.instant,
                    }
                }
            }

            if readable {
                div { class: "form-group", style: "margin-top: 0.5rem;",
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
                button {
                    class: "btn btn-primary",
                    disabled: draft().trim().is_empty(),
                    onclick: {
                        let store_contract_id = store_contract_id.clone();
                        let tag = tag.clone();
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
                    "Reply"
                }
                p { class: "text-muted", style: "font-size: 0.8rem;",
                    "Your reply goes into this mailbox encrypted to this buyer alone. They can "
                    "read it whenever they come back from the same device they wrote from -- "
                    "and never from a different one, so a buyer who has changed device will "
                    "not see it."
                }
            } else {
                p { class: "text-muted text-italic", style: "font-size: 0.85rem;",
                    "Nothing here can be read, so there is nothing to reply to."
                }
            }
        }
    }
}

/// Which side of a conversation this browser is on. Decides how an
/// unattributed message is described, and nothing else.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Buyer,
    Seller,
}

/// What to put above a message, given what is actually known about it.
///
/// # Why this is not "Seller" and "You"
///
/// It was, and it was wrong. `Addressing` says which direction key
/// authenticated a message, and BOTH parties hold both keys -- the buyer
/// needs the seller-to-buyer key to read replies at all. So a buyer can place
/// a message in the seller's mailbox that authenticates as though the seller
/// wrote it, and the seller's own screen would have shown it as their own
/// words. Verified: a seller's inbox displayed "as agreed, I confess" as the
/// seller's own reply, written by the buyer.
///
/// Only one thing here is knowable: what this browser sent itself. That gets
/// a name. Everything else is described by direction, in words that say
/// direction -- "addressed to", not "from" -- and the surrounding notice says
/// plainly that direction is not authorship.
///
/// Anything whose authenticity actually matters must carry its own signature;
/// see [`harvest_common::mailbox::MessageDirection`].
fn attribution(
    authored_here: bool,
    addressing: crate::messaging::Addressing,
    role: Role,
) -> &'static str {
    use crate::messaging::Addressing;
    if authored_here {
        return "You, from this tab";
    }
    match (role, addressing) {
        (Role::Buyer, Addressing::ToBuyer) => "Addressed to you",
        (Role::Buyer, Addressing::ToSeller) => "Addressed to the seller",
        (Role::Seller, Addressing::ToSeller) => "Addressed to you",
        (Role::Seller, Addressing::ToBuyer) => "Addressed to this buyer",
    }
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
        let answered = keys.is_some_and(|keys| {
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
            instant: instant.as_ref().and_then(|selection| {
                let tag: [u8; 32] = conversation.as_slice().try_into().ok()?;
                Some(InstantAnswer {
                    request_id: harvest_common::payment::request_id(&tag, &selection.nonce),
                    total_sats: selection.expected_total_sats,
                })
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
    pub request_id: [u8; 32],
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

#[component]
fn MessageCard(entry: MailboxEntry, authored_here: bool) -> Element {
    let when = entry.timestamp().format("%Y-%m-%d %H:%M UTC").to_string();
    let who = match &entry {
        MailboxEntry::Readable { addressing, .. } => {
            Some(attribution(authored_here, *addressing, Role::Seller))
        }
        MailboxEntry::Unreadable { .. } => None,
    };
    rsx! {
        div { class: "card", style: "margin-top: 0.5rem;",
            if let Some(who) = who {
                p { class: "text-muted", style: "font-size: 0.8rem;", "{who}" }
            }
            match &entry {
                MailboxEntry::Readable { content, .. } => rsx! {
                    p { style: "white-space: pre-wrap;", "{describe(content)}" }
                },
                MailboxEntry::Unreadable { why, .. } => rsx! {
                    p { class: "text-muted text-italic", "Cannot be read: {why}" }
                },
            }
            p { class: "text-muted",
                style: "font-size: 0.8rem;",
                // Chosen by whoever wrote the message and signed by nobody
                // (see `harvest_common::mailbox`), so it is labelled as a
                // claim rather than shown as a fact.
                "Sender's timestamp: {when}"
            }
        }
    }
}

/// What to show for one message's content.
///
/// Every variant is named rather than rendered as empty, so a reader is never
/// shown a blank message.
fn describe(content: &MessageContent) -> String {
    match content {
        MessageContent::Text(text) => text.clone(),
        MessageContent::Decline { reason } => format!("Declined: {reason}"),
        MessageContent::OrderRequest {
            quantity,
            shipping,
            note,
            instant,
            ..
        } => {
            let mut described = format!("Wants to buy {quantity}.\n\nShip to:\n{shipping}");
            // The buyer's instant-checkout picks, so a seller answering the
            // request by hand invoices the same terms their store would have.
            if let Some(selection) = instant {
                described.push('\n');
                if let Some(region) = &selection.region {
                    described.push_str(&format!("\nDelivery region: {region}"));
                }
                if !selection.choices.is_empty() {
                    described.push_str(&format!("\nChoices: {}", selection.choices.join(", ")));
                }
                described.push_str(&format!(
                    "\nInstant checkout total: {} sats",
                    selection.expected_total_sats
                ));
            }
            if !note.trim().is_empty() {
                described.push_str(&format!("\n\n{note}"));
            }
            described
        }
        MessageContent::OrderAccepted { order_id } => {
            format!("Accepted -- invoice {} is published.", order_id.short())
        }
    }
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

    /// A seller reading an instant request sees the region, the picks and the
    /// total the buyer was shown; a quote request shows none of them.
    #[test]
    fn an_instant_request_shows_its_terms_to_the_seller() {
        let request = |instant| MessageContent::OrderRequest {
            instant,
            listing_id: ListingId([9u8; 32]),
            quantity: 2,
            shipping: "12 Example St".into(),
            note: "Thanks".into(),
            order_binding: BINDING,
            buyer_receipt_key: None,
        };
        let shown = describe(&request(Some(crate::messaging::InstantSelection {
            nonce: [1u8; 16],
            region: Some("EU".into()),
            choices: vec!["Fig".into(), "Large".into()],
            expected_total_sats: 25_000,
        })));
        assert!(shown.contains("Delivery region: EU"), "{shown}");
        assert!(shown.contains("Choices: Fig, Large"), "{shown}");
        assert!(
            shown.contains("Instant checkout total: 25000 sats"),
            "{shown}"
        );
        assert!(shown.ends_with("Thanks"), "{shown}");

        let quote = describe(&request(None));
        assert!(!quote.contains("Instant checkout"), "{quote}");
    }
}
