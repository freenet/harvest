use dioxus::prelude::*;
use harvest_common::listing::Listing;

use super::listing_form::ListingForm;
use crate::gateway::APP_STATE;
use crate::state::{StoreDetails, StoreDetailsGap};

/// One store a seller owns, as the identity card shows it.
#[derive(Clone, PartialEq)]
struct StoreCard {
    contract_id: Vec<u8>,
    label: String,
    /// The store's code (harvest#52), `None` while the identity's key is not
    /// known.
    code: Option<String>,
    /// The link to share, built from the code: see `store_link::share_link`
    /// for why it names the default node rather than this page's.
    link: Option<String>,
    /// Set when another key holds this store's address: what to tell the
    /// seller. See `AppState::foreign_store_owner`.
    foreign_owner: Option<String>,
    /// Set when the store's published details need repairing.
    gap: Option<StoreDetailsGap>,
    /// Current values, to fill the form with when editing.
    details: StoreDetails,
    /// Whether we actually know what this store has published: its state has
    /// arrived, or the GET for it gave up. False means the form below would
    /// be filled with empty strings that look like lost details, and an edit
    /// submitted from it could not be given a version the contract accepts.
    /// See `state::AppState::store_details_are_resolved`.
    details_resolved: bool,
    /// The verdict a BUYER reaches about this store's ghostkey certificate.
    ///
    /// Shown to the seller because it is the one thing about their own store
    /// they cannot otherwise see. Nothing in the publishing path fails when
    /// the certificate is unusable -- the store publishes, the listings
    /// publish, and only the buyer's storefront says the identity is
    /// unbacked. Reading the same verdict here is what closes that gap.
    certificate: crate::ghostkey_cert::CertificateStatus,
    /// Whether a publish for this store is already on its way to the
    /// delegate or the network. Gates the `PublishNow` button so a second
    /// click can't queue a duplicate publish -- see
    /// `state::AppState::store_publish_in_flight`.
    publish_in_flight: bool,
    /// Whether this is a store made before stores had their own keys
    /// (harvest#93): owned by the Ghost Key itself, so this build cannot sign
    /// for it, and it is offered a move instead of the ordinary controls.
    legacy: bool,
}

#[component]
pub fn MyStore() -> Element {
    let app_state = APP_STATE.read();
    let in_flight = app_state.request_any_access_in_flight;

    rsx! {
        div {
            h2 { "My Store" }

            if app_state.ghostkeys.is_empty() {
                NoIdentity { in_flight: in_flight }
            } else {
                IdentityList {
                    ghostkeys: app_state.ghostkeys.clone(),
                    my_stores: app_state.my_stores.clone(),
                    has_harvest_delegate: app_state.harvest_delegate_key.is_some(),
                }
                ConnectAnother { in_flight: in_flight }
            }
        }
    }
}

#[component]
fn NoIdentity(in_flight: bool) -> Element {
    rsx! {
        div { class: "card empty-state",
            p {
                "Harvest needs a ghostkey identity to sign your store listings."
            }
            p {
                "If you've already created one, share it with Harvest below. "
                "Otherwise, visit the Ghostkey Vault to create one."
            }
            div { style: "margin-top: 16px;",
                button {
                    class: "btn btn-primary",
                    disabled: in_flight,
                    onclick: move |_| connect_ghostkey(),
                    if in_flight { "Waiting for vault…" } else { "Connect a ghostkey" }
                }
            }
        }
    }
}

/// Lets a user with one or more already-connected ghostkeys request
/// access to ANOTHER one. Without this, the empty-state's "Connect"
/// button disappears after the first successful share and there's no
/// path to add a second identity.
#[component]
fn ConnectAnother(in_flight: bool) -> Element {
    rsx! {
        div { style: "margin-top: 16px;",
            button {
                class: "btn",
                disabled: in_flight,
                onclick: move |_| connect_ghostkey(),
                if in_flight { "Waiting for vault…" } else { "Connect another ghostkey" }
            }
        }
    }
}

/// Send a `RequestAnyAccess` request to the ghostkey delegate. The
/// delegate emits a `RequestUserInput` that the gateway shell-page
/// renders as an overlay; the user picks one of their stored
/// ghostkeys (or denies). On approval the delegate replies with a
/// one-element `GhostKeyList` for the chosen key, which the response
/// handler folds into APP_STATE.ghostkeys -- our `IdentityList`
/// renders as soon as it appears.
pub(crate) fn connect_ghostkey() {
    use ghostkey_common::GhostkeyRequest;

    // Snapshot delegate key + check the in-flight flag in a single
    // borrow. If we're already mid-request, drop the click so rapid
    // double-clicks don't queue duplicate prompts (and overwrite each
    // other's GhostKeyList responses on completion).
    let key = {
        let state = APP_STATE.read();
        if state.request_any_access_in_flight {
            dioxus::logger::tracing::info!(
                "RequestAnyAccess already in flight; ignoring duplicate click"
            );
            return;
        }
        match state.ghostkey_delegate_key.clone() {
            Some(k) => k,
            None => {
                dioxus::logger::tracing::warn!(
                    "Ghostkey delegate not yet registered; cannot request access"
                );
                APP_STATE
                    .write()
                    .notifications
                    .push("Still connecting to the gateway — please try again in a moment.".into());
                return;
            }
        }
    };

    APP_STATE.write().request_any_access_in_flight = true;
    spawn(async move {
        let payload = match ghostkey_common::to_cbor(&GhostkeyRequest::RequestAnyAccess) {
            Ok(p) => p,
            Err(e) => {
                dioxus::logger::tracing::error!("Failed to encode RequestAnyAccess: {e}");
                APP_STATE.write().request_any_access_in_flight = false;
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&key, payload).await {
            dioxus::logger::tracing::error!("Failed to send RequestAnyAccess: {e}");
            APP_STATE.write().request_any_access_in_flight = false;
        }
    });
}

#[component]
fn IdentityList(
    ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,
    my_stores: std::collections::HashMap<String, Vec<harvest_common::StoreRegistration>>,
    has_harvest_delegate: bool,
) -> Element {
    rsx! {
        div {
            h3 { "Your Identities" }

            if !has_harvest_delegate {
                p { class: "text-warning",
                    "Harvest delegate not yet registered. Store creation will be available once the delegate is loaded."
                }
            }

            for gk in &ghostkeys {
                IdentityCard {
                    identity: gk.clone(),
                    stores: my_stores.get(&gk.fingerprint).cloned().unwrap_or_default(),
                    has_harvest_delegate: has_harvest_delegate,
                }
            }
        }
    }
}

#[component]
fn IdentityCard(
    identity: ghostkey_common::GhostKeyInfo,
    stores: Vec<harvest_common::StoreRegistration>,
    has_harvest_delegate: bool,
) -> Element {
    let mut show_listing_form = use_signal(|| false);
    let mut show_store_form = use_signal(|| false);
    // Which store's details form is open, if any. One signal rather than one
    // per store: hooks cannot be created inside a loop.
    let mut editing_store = use_signal(|| Option::<Vec<u8>>::None);
    let fp = identity.fingerprint.clone();
    // A store this device can sign for: one with a store key (harvest#93).
    // A store made before revision 2 does not count; it is offered a move.
    let has_store = stores
        .iter()
        .any(|store| store.store_verifying_key.is_some());
    let legacy_movable = APP_STATE
        .read()
        .legacy_store_to_move(&identity.fingerprint)
        .is_some();
    // Single-flight (harvest#93 review, Must Fix 3): set from the moment a
    // creation or move starts until it is published or fails.
    let creating =
        APP_STATE.read().store_creation_in_flight.as_deref() == Some(identity.fingerprint.as_str());
    // No Cancel once the PUTs have started (#98 re-check).
    let publishing = APP_STATE.read().store_publishing;
    // A creation this Ghost Key's existing backing refused, waiting on the
    // seller's answer (harvest#93 section 6.2).
    let second_store = APP_STATE
        .read()
        .second_store_offer
        .clone()
        .filter(|offer| offer.fingerprint == identity.fingerprint);
    // A store made before revision 2 that has not loaded yet: offering
    // "Create Store" now would make a second store instead of moving this
    // one (#98 review, L3).
    let legacy_loading = APP_STATE.read().legacy_store_loading(&identity.fingerprint);

    // Buyers can only reach a store through a link the seller sends them, so
    // the seller has to be able to see it. Built here rather than in rsx
    // because it needs the page URL, which native builds don't have.
    //
    // Each store is labelled: a seller with two stores otherwise gets two
    // 44-character links with nothing to tell them apart.
    // A store made before revision 2 was addressed by the Ghost Key's own
    // code; one since is addressed by its store key's (harvest#93).
    let ghost_code: Option<String> = identity
        .verifying_key_bytes
        .as_deref()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        .map(|key| harvest_common::store::store_code(&key));
    // Stores made before revision 2 are shown only while there is nothing
    // else: once a store has moved, the old one is the past, not a second
    // store to manage.
    let stores: Vec<harvest_common::StoreRegistration> = if has_store {
        stores
            .into_iter()
            .filter(|store| store.store_verifying_key.is_some())
            .collect()
    } else {
        stores
    };
    let store_cards: Vec<StoreCard> = {
        let app_state = APP_STATE.read();
        stores
            .iter()
            .filter_map(|store| {
                if store.store_contract_id.len() != 32 {
                    // Dropping this silently left the seller a link short
                    // with no indication which store was missing. Such a
                    // store cannot be updated either -- its contract key
                    // cannot be rebuilt -- so there is nothing to offer.
                    dioxus::logger::tracing::warn!(
                        "Store registration has a {}-byte contract id, not 32 -- no share link",
                        store.store_contract_id.len()
                    );
                    return None;
                }
                let browsing = app_state.browsing_stores.get(&store.store_contract_id);
                let info = browsing.and_then(|browsing| browsing.info.as_ref());
                let name = info.map(|info| info.store_name.clone());
                let code: Option<String> = match store.store_verifying_key {
                    Some(bytes) => ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                        .ok()
                        .map(|key| harvest_common::store::store_code(&key)),
                    None => ghost_code.clone(),
                };
                Some(StoreCard {
                    legacy: store.store_verifying_key.is_none(),
                    label: match code.as_deref() {
                        Some(code) => crate::store_link::store_label(code, name.as_deref()),
                        None => name.clone().unwrap_or_else(|| "Your store".to_string()),
                    },
                    code: code.clone(),
                    link: code.as_deref().map(crate::store_link::share_link),
                    foreign_owner: app_state.foreign_store_owner(&store.store_contract_id).map(
                        |held| {
                            crate::state::foreign_owner_message(
                                code.as_deref().unwrap_or_default(),
                                &held,
                            )
                        },
                    ),
                    // The seller can only be prompted to publish a key the
                    // delegate has actually produced -- see
                    // `state::store_details_gap`.
                    gap: crate::state::store_details_gap(
                        info,
                        app_state
                            .encryption_public_keys
                            .contains_key(&identity.fingerprint),
                    ),
                    details: StoreDetails {
                        store_name: info.map(|i| i.store_name.clone()).unwrap_or_default(),
                        description: info.map(|i| i.description.clone()).unwrap_or_default(),
                    },
                    details_resolved: app_state
                        .store_details_are_resolved(&store.store_contract_id),
                    certificate: browsing
                        .map(|browsing| browsing.certificate_status.clone())
                        .unwrap_or_default(),
                    publish_in_flight: app_state.store_publish_in_flight(&store.store_contract_id),
                    contract_id: store.store_contract_id.clone(),
                })
            })
            .collect()
    };

    rsx! {
        div { class: "identity-card",
            div {
                span { class: "identity-name",
                    if let Some(ref label) = identity.label {
                        "{label}"
                    } else {
                        "{truncate_fingerprint(&identity.fingerprint)}"
                    }
                }
                span { class: "identity-tier", "{describe_notary_info(&identity.notary_info)}" }
            }
            div {
                if has_store {
                    button {
                        class: if show_listing_form() { "btn btn-sm btn-outline" } else { "btn btn-sm btn-primary" },
                        onclick: move |_| show_listing_form.toggle(),
                        if show_listing_form() { "Cancel" } else { "Add Listing" }
                    }
                } else if creating {
                    span { class: "text-warning", "Creating contracts... " }
                    // A creation can stall on an answer that never comes
                    // (#98 review, L1). Cancelling keeps the store key and
                    // any signed backing, so trying again resumes it.
                    if !publishing {
                        button {
                            class: "btn btn-sm btn-outline",
                            onclick: move |_| APP_STATE.write().cancel_store_creation(),
                            "Cancel"
                        }
                    }
                } else if legacy_movable {
                    button {
                        class: "btn btn-sm btn-primary",
                        disabled: !has_harvest_delegate,
                        onclick: {
                            let fp = identity.fingerprint.clone();
                            move |_| move_legacy_store(fp.clone())
                        },
                        "Move this store"
                    }
                } else if legacy_loading {
                    span { class: "text-muted text-italic", "Loading your existing store…" }
                } else {
                    button {
                        class: if show_store_form() { "btn btn-sm btn-outline" } else { "btn btn-sm btn-primary" },
                        disabled: !has_harvest_delegate,
                        onclick: move |_| show_store_form.toggle(),
                        if show_store_form() { "Cancel" } else { "Create Store" }
                    }
                }
            }
        }

        if let Some(offer) = second_store {
            div { class: "store-share",
                p { class: "text-warning",
                    "This Ghost Key already backs {offer.other_store}. A Ghost Key backs one \
                     store at a time, so a buyer who has loaded both will treat BOTH as \
                     unbacked and will not pay either. This version has no way to undo that: \
                     use a different Ghost Key unless you mean it."
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| {
                        let started = APP_STATE.write().confirm_second_store();
                        match started {
                            Ok(request) => {
                                #[cfg(target_arch = "wasm32")]
                                send_store_creation_requests(
                                    APP_STATE
                                        .read()
                                        .pending_store_creation
                                        .as_ref()
                                        .map(|p| p.ghostkey_fingerprint.clone())
                                        .unwrap_or_default(),
                                    request,
                                );
                                #[cfg(not(target_arch = "wasm32"))]
                                let _ = request;
                            }
                            Err(e) => APP_STATE
                                .write()
                                .notifications
                                .push(format!("Could not create the store: {e}")),
                        }
                    },
                    "Open a second store under it anyway"
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| APP_STATE.write().second_store_offer = None,
                    "Not now"
                }
            }
        }

        if !store_cards.is_empty() {
            div { class: "store-share",
                p { class: "text-muted",
                    "Share this link so buyers can open your store:"
                }
                for card in store_cards.iter().cloned() {
                    div { class: "store-share-row",
                        span { class: "store-share-label", "{card.label}" }
                        if let Some(ref link) = card.link {
                            // Styled as a value to copy rather than a form
                            // field: it is readonly, and dressed as an input
                            // it read as something to edit.
                            input {
                                class: "copy-field",
                                readonly: true,
                                spellcheck: false,
                                // Named, because `aria-label` REPLACES the
                                // visible label beside it: a seller with two
                                // stores would otherwise hear the same string
                                // for both, which is the distinction the row
                                // above exists to draw.
                                aria_label: "{card.label} store link, select to copy",
                                value: "{link}",
                            }
                        }
                        if let Some(ref code) = card.code {
                            p { class: "text-muted",
                                "Store code: "
                                code { "{code}" }
                                ". The link opens Harvest on a buyer's own Freenet node at its \
                                 usual address. A buyer whose node runs elsewhere can open \
                                 Harvest and enter this code instead."
                            }
                        }
                        if let Some(ref refusal) = card.foreign_owner {
                            p { class: "text-warning", "{refusal}" }
                        }

                        // Nothing is offered until we know what the store
                        // has published. Before this, the button said "Edit
                        // details" and the form opened filled with empty
                        // strings -- which reads as details that have been
                        // lost, so the seller retypes them, and the edit is
                        // then published at a version the store contract
                        // discards as stale.
                        if card.legacy {
                            p { class: "text-warning",
                                "This store was made before stores had keys of their own, so this \
                                 version of Harvest cannot publish to it and buyers cannot pay it. \
                                 Moving it gives it a key, backed by this Ghost Key, and carries \
                                 its name, description and listings across. Its link changes, so \
                                 share the new one; open orders are not carried."
                            }
                        } else if !card.details_resolved {
                            p { class: "text-muted text-italic",
                                "Loading this store's published details…"
                            }
                        } else {
                            // The repair prompt. Says what is wrong and what
                            // publishing fixes, rather than offering a bare form
                            // and leaving the seller to guess why it is there.
                            if let Some(gap) = card.gap {
                                p { class: "text-warning", "{gap.message()}" }
                            }

                            // Editing the details will not fix this, so it is
                            // deliberately not phrased as a repair prompt: a
                            // certificate that does not verify is either an
                            // identity this build cannot read or one that is
                            // not the seller's, and both need looking at
                            // rather than republishing.
                            if !card.certificate.is_verified() {
                                p { class: "text-warning",
                                    "Buyers see this store as unbacked: {card.certificate.label()}."
                                    if let Some(why) = card.certificate.detail() {
                                        " ({why})"
                                    }
                                }
                            }

                            button {
                                class: if card.gap.is_some() { "btn btn-sm btn-primary" } else { "btn btn-sm btn-outline" },
                                // Only the `PublishNow` path can double-fire a
                                // real network request on a double-click --
                                // `ToggleForm` just flips a local signal, so
                                // it is left enabled. See
                                // `state::AppState::store_publish_in_flight`
                                // for why this can never get stuck disabled.
                                disabled: store_details_button_action(
                                        card.gap,
                                        editing_store() == Some(card.contract_id.clone()),
                                    ) == StoreDetailsAction::PublishNow
                                    && card.publish_in_flight,
                                onclick: {
                                    let id = card.contract_id.clone();
                                    let details = card.details.clone();
                                    let gap = card.gap;
                                    move |_| {
                                        let id = id.clone();
                                        // Recomputed at click time, not
                                        // captured from the render that drew
                                        // this button: `editing_store` can
                                        // change between renders, and this is
                                        // what keeps a store whose form is
                                        // open from being silently published
                                        // with the old, on-record details
                                        // when `NoEncryptionKey` appears while
                                        // the seller has unsaved edits open
                                        // (#80 review).
                                        let is_editing = editing_store() == Some(id.clone());
                                        match store_details_button_action(gap, is_editing) {
                                            // See `store_details_button_action`
                                            // for why this publishes instead
                                            // of opening the form (#78).
                                            StoreDetailsAction::PublishNow => {
                                                // Fresh read, not
                                                // `card.publish_in_flight`:
                                                // that was snapshotted when
                                                // this render started, and two
                                                // clicks can land before
                                                // Dioxus re-renders the
                                                // `disabled` attribute above
                                                // (#80 review).
                                                if APP_STATE.read().store_publish_in_flight(&id) {
                                                    return;
                                                }
                                                publish_store_details(id, details.clone());
                                            }
                                            StoreDetailsAction::ToggleForm => {
                                                if is_editing {
                                                    editing_store.set(None);
                                                } else {
                                                    editing_store.set(Some(id));
                                                }
                                            }
                                        }
                                    }
                                },
                                if store_details_button_action(
                                    card.gap,
                                    editing_store() == Some(card.contract_id.clone()),
                                ) == StoreDetailsAction::PublishNow
                                {
                                    "Publish details"
                                } else if editing_store() == Some(card.contract_id.clone()) {
                                    "Cancel"
                                } else if card.gap.is_some() {
                                    "Publish details"
                                } else {
                                    "Edit details"
                                }
                            }

                            // The invoice FORM sits under the store it
                            // issues on -- an invoice goes to one store's
                            // contract, and a seller with two stores has to be
                            // able to tell which. The payment KEY inside this
                            // panel is not per-store: it is one key and one
                            // derivation counter for the whole app, shown here
                            // because this is where it is needed. The panel
                            // says so rather than letting the placement imply
                            // otherwise.
                            super::invoice_form::StorePayments {
                                store_contract_id: card.contract_id.clone(),
                                seller_fingerprint: fp.clone(),
                            }

                            if editing_store() == Some(card.contract_id.clone()) {
                                StoreDetailsForm {
                                    heading: if card.gap.is_some() { "Publish Store Details" } else { "Edit Store Details" },
                                    submit_label: "Publish",
                                    initial: card.details.clone(),
                                    on_submit: {
                                        let id = card.contract_id.clone();
                                        move |details: StoreDetails| {
                                            editing_store.set(None);
                                            publish_store_details(id.clone(), details);
                                        }
                                    },
                                }
                            }
                        }
                    }
                }
            }
        }

        if show_store_form() {
            StoreDetailsForm {
                heading: "Create Your Store",
                submit_label: "Create Store",
                initial: StoreDetails::default(),
                on_submit: move |details: StoreDetails| {
                    show_store_form.set(false);
                    initiate_store_creation(identity.fingerprint.clone(), details, Vec::new());
                },
            }
        }

        if show_listing_form() {
            ListingForm {
                on_submit: move |listing: Listing| {
                    show_listing_form.set(false);
                    sign_and_submit_listing(fp.clone(), listing);
                },
            }
        }
    }
}

/// The store-details form, used both to create a store and to change or
/// repair the details of one that already exists. One component rather than
/// two: the fields are the same, and a second copy is how the two drift.
#[component]
fn StoreDetailsForm(
    heading: String,
    submit_label: String,
    initial: StoreDetails,
    on_submit: EventHandler<StoreDetails>,
) -> Element {
    let mut store_name = use_signal(|| initial.store_name.clone());
    let mut description = use_signal(|| initial.description.clone());

    rsx! {
        div { class: "card",
            h3 { "{heading}" }

            div { class: "form-group",
                label { class: "form-label", "Store Name" }
                input {
                    class: "form-input",
                    r#type: "text",
                    placeholder: "e.g. Mountain Valley Crafts",
                    value: "{store_name}",
                    oninput: move |e| store_name.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Description" }
                textarea {
                    class: "form-textarea",
                    placeholder: "Tell buyers about your store...",
                    value: "{description}",
                    oninput: move |e| description.set(e.value()),
                }
                // Said here because a feature nobody is told about is one
                // nobody uses, and this is the only field a store has.
                p { class: "text-muted", style: "font-size: 0.8rem;",
                    "Markdown works here: "
                    code { "# heading" }
                    ", "
                    code { "- list" }
                    ", "
                    code { "**bold**" }
                    ", and links."
                }
            }

            button {
                class: "btn btn-primary",
                disabled: store_name().trim().is_empty(),
                onclick: move |_| {
                    on_submit.call(StoreDetails {
                        store_name: store_name().trim().to_string(),
                        description: description().trim().to_string(),
                    });
                },
                "{submit_label}"
            }
        }
    }
}

/// What clicking the store-details button should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreDetailsAction {
    /// Publish the details already on record, unchanged.
    PublishNow,
    /// Open (or close) the edit/repair form so the seller can type something.
    ToggleForm,
}

/// Decide what the store-details button does, given the gap (if any) a
/// store's published details currently have.
///
/// # Why `NoEncryptionKey` is special (#78)
///
/// `StoreDetailsGap::NoEncryptionKey`'s own message says publishing "adds the
/// key your delegate already holds; nothing else about the store changes" --
/// the key comes from the delegate, not from anything the seller types, so
/// there is nothing to fill in and nothing to review. Before this fix every
/// gap opened the same edit form and made the seller click a SECOND,
/// undisclosed "Publish" button inside it to actually publish. For this one
/// gap that meant clicking the button labelled "Publish details" produced no
/// network call, no vault prompt, and no notification -- indistinguishable
/// from the button being broken, and exactly what was reported in #78.
///
/// Every other gap (`NeverPublished`, `NoName`) needs the
/// seller to actually provide something -- at minimum a store name -- so
/// those still open the form, as does an ordinary "Edit details" click
/// (`gap` is `None`).
///
/// # Why `is_editing` overrides the gap (PR #80 review)
///
/// `is_editing` is whether THIS store's edit/repair form is already open.
/// When it is, the button is always `ToggleForm` (closing it), regardless of
/// what `gap` says. Without this, the gap arriving or changing while the form
/// is open -- `EncryptionKeyReady` lands asynchronously, independent of
/// anything the seller is doing -- could flip a card from `None`/some other
/// gap to `NoEncryptionKey` while the seller has unsaved edits sitting in the
/// open form: the button would silently relabel to "Publish details" and, on
/// the next click, publish `card.details` -- the OLD, already-published
/// values read from the network, not what the seller typed -- discarding the
/// edit. Closing the form is always safe and always what the button's own
/// label ("Cancel") promises; it is the seller's job to reopen and resubmit
/// once done, at which point the gap is read fresh.
fn store_details_button_action(
    gap: Option<StoreDetailsGap>,
    is_editing: bool,
) -> StoreDetailsAction {
    if is_editing {
        return StoreDetailsAction::ToggleForm;
    }
    if gap == Some(StoreDetailsGap::NoEncryptionKey) {
        StoreDetailsAction::PublishNow
    } else {
        StoreDetailsAction::ToggleForm
    }
}

/// Publish new details for a store the seller owns.
///
/// Both the ordinary edit and the repair of a store whose details never
/// reached the network come through here -- they are the same operation, and
/// the only difference is which version it lands at.
fn publish_store_details(store_contract_id: Vec<u8>, details: StoreDetails) {
    let outcome = APP_STATE
        .write()
        .publish_store_details(&store_contract_id, details);
    match outcome {
        Ok(()) => APP_STATE
            .write()
            .notifications
            .push("Publishing your store's details…".into()),
        Err(e) => {
            dioxus::logger::tracing::error!("Could not publish store details: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Could not publish your store's details: {e}"));
        }
    }
}

/// Initiate the full store creation flow (see `crate::backing_flow` for the
/// whole of it):
/// 1. Record the pending creation, with `carried_listings` for a store being
///    moved from before revision 2 (empty otherwise).
/// 2. Ask the vault for the Ghost Key's certificate, and the Harvest delegate
///    for the reputation key, the messaging key and a new store key.
/// 3. When all but the messaging key have arrived, the Ghost Key backs the
///    new store key, the store key accepts it, and the contracts publish.
fn initiate_store_creation(
    _fingerprint: String,
    _details: StoreDetails,
    _carried_listings: Vec<Listing>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let details = _details;
        let carried_listings = _carried_listings;

        // The Ghost Key's verifying key, from the vault's own answer: the
        // backing names it.
        let vk_bytes = {
            let state = APP_STATE.read();
            state
                .ghostkeys
                .iter()
                .find(|k| k.fingerprint == fingerprint)
                .and_then(|k| k.verifying_key_bytes.as_deref())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
        };
        let Some(vk_bytes) = vk_bytes else {
            APP_STATE.write().notifications.push(
                "Store creation failed: the vault has not shared this Ghost Key's public key."
                    .into(),
            );
            return;
        };
        let started = APP_STATE.write().begin_store_creation(
            fingerprint.clone(),
            vk_bytes,
            details,
            carried_listings,
            false,
        );
        match started {
            Ok(store_key_request) => send_store_creation_requests(fingerprint, store_key_request),
            Err(e) => APP_STATE
                .write()
                .notifications
                .push(format!("Could not create the store: {e}")),
        }
    }
}

/// Move this Ghost Key's store made before revision 2 onto a store key of its
/// own. See `crate::backing_flow` for what is carried and what is not.
fn move_legacy_store(_fingerprint: String) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let vk_bytes = {
            let state = APP_STATE.read();
            state
                .ghostkeys
                .iter()
                .find(|k| k.fingerprint == fingerprint)
                .and_then(|k| k.verifying_key_bytes.as_deref())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
        };
        let Some(vk_bytes) = vk_bytes else {
            APP_STATE.write().notifications.push(
                "Could not move the store: the vault has not shared this Ghost Key's public key."
                    .into(),
            );
            return;
        };
        let started = APP_STATE.write().move_legacy_store(&fingerprint, vk_bytes);
        match started {
            Ok(store_key_request) => {
                APP_STATE
                    .write()
                    .notifications
                    .push("Moving your store to a key of its own…".into());
                send_store_creation_requests(fingerprint, store_key_request);
            }
            Err(e) => APP_STATE
                .write()
                .notifications
                .push(format!("Could not move the store: {e}")),
        }
    }
}

/// Send the four requests a store creation waits on. Each answer arrives
/// through the ordinary response handlers and fills the pending creation;
/// `AppState::start_store_creation_if_ready` decides when to go on.
#[cfg(target_arch = "wasm32")]
fn send_store_creation_requests(fingerprint: String, store_key_request: u64) {
    // Deliberate second store under this Ghost Key? The delegate applies the
    // same one-store rule across tabs, so it has to be told (harvest#93
    // section 6.2).
    let another_store = APP_STATE
        .read()
        .pending_store_creation
        .as_ref()
        .is_some_and(|p| p.another_store);
    wasm_bindgen_futures::spawn_local(async move {
        let fail = |why: String| {
            dioxus::logger::tracing::error!("{why}");
            APP_STATE.write().store_creation_failed(&why);
        };
        let (Some(delegate_key), Some(gk_delegate_key)) = ({
            let state = APP_STATE.read();
            (
                state.harvest_delegate_key.clone(),
                state.ghostkey_delegate_key.clone(),
            )
        }) else {
            fail("the Harvest delegate or the Ghost Key vault is not registered".into());
            return;
        };

        let cert_request = ghostkey_common::GhostkeyRequest::GetCertificate {
            fingerprint: fingerprint.clone(),
        };
        match ghostkey_common::to_cbor(&cert_request) {
            Ok(payload) => {
                if let Err(e) =
                    crate::gateway::send_delegate_message(&gk_delegate_key, payload).await
                {
                    fail(format!("could not ask the vault for the certificate: {e}"));
                    return;
                }
            }
            Err(e) => {
                fail(format!("serialize GetCertificate: {e}"));
                return;
            }
        }

        // The store key. Its record and inbox keys derive from it (harvest#93
        // phase 1b), and `on_store_key_created` asks for them, so creation no
        // longer mints a per-device reputation or messaging key. Sent with
        // the Ghost Key, so a retry of a creation that did not finish gets
        // the same store key back (#98 review, M1), and with `another_store`
        // when the seller has said a second store under this key is
        // deliberate (section 6.2).
        for request in [harvest_common::HarvestDelegateRequest::CreateStoreKey {
            request_id: store_key_request,
            ghostkey_fingerprint: Some(fingerprint.clone()),
            another_store,
        }] {
            let payload = match harvest_common::to_cbor(&request) {
                Ok(payload) => payload,
                Err(e) => {
                    fail(format!("serialize a delegate request: {e}"));
                    return;
                }
            };
            if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
                fail(format!("could not reach the Harvest delegate: {e}"));
                return;
            }
        }

        dioxus::logger::tracing::info!(
            "Sent GetCertificate + CreateStoreKey for {fingerprint} -- store creation pending"
        );
    });
}

/// Ask the harvest delegate for this identity's long-term X25519 key, so the
/// seller has one to publish: recall it, or with `recall_only: false` mint it
/// if there is none.
///
/// A Ghost Key connecting RECALLS (`ensure_encryption_key`); only a recall
/// that finds nothing leads to a mint, and that waits for the delegate secret
/// migration (`mint_encryption_key`, harvest#123).
#[cfg(target_arch = "wasm32")]
async fn request_encryption_key(fingerprint: String, recall_only: bool) {
    let Some(delegate_key) = APP_STATE.read().harvest_delegate_key.clone() else {
        dioxus::logger::tracing::error!(
            "Harvest delegate not registered -- cannot mint an encryption key"
        );
        return;
    };
    let request = harvest_common::HarvestDelegateRequest::InitEncryptionKey {
        ghostkey_fingerprint: fingerprint.clone(),
        recall_only,
    };
    let payload = match harvest_common::to_cbor(&request) {
        Ok(payload) => payload,
        Err(e) => {
            dioxus::logger::tracing::error!("Failed to serialize InitEncryptionKey: {e}");
            return;
        }
    };
    if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
        dioxus::logger::tracing::error!("Failed to send InitEncryptionKey: {e}");
    }
}

/// Recall this identity's key, spawned, for callers that are not already
/// async. Never mints; safe before the delegate migration has run.
#[cfg(target_arch = "wasm32")]
pub(crate) fn ensure_encryption_key(fingerprint: String) {
    wasm_bindgen_futures::spawn_local(async move {
        request_encryption_key(fingerprint, true).await;
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn ensure_encryption_key(_fingerprint: String) {}

/// Mint this identity's key if the delegate holds none, once the delegate
/// secret migration has reached every generation (so a key an earlier
/// generation held is imported, not replaced). Spawned; see
/// `gateway::delegate_migrate_ops::after_delegate_migration`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn mint_encryption_key(fingerprint: String) {
    crate::gateway::delegate_migrate_ops::after_delegate_migration(move || {
        wasm_bindgen_futures::spawn_local(async move {
            request_encryption_key(fingerprint, false).await;
        });
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn mint_encryption_key(_fingerprint: String) {}

/// Render a ghostkey's notary attestation as something a person can read.
///
/// `GhostKeyInfo::notary_info` is the raw certificate field, and it was being
/// printed verbatim -- so the UI showed
/// `First Ghostkey({"action":"freenet-donation","amount":1,"delegate-key-created":"2024-08-13 15:45:36"})`.
/// The surrounding CSS class is `identity-tier`, so a tier was always the
/// intent; the payload was just never unpacked.
///
/// This is worth doing properly rather than merely hiding, because the value is
/// real signal here: Harvest's own reputation model says a clean record with an
/// old, high-tier ghostkey is the best reputation a seller can have, so the
/// amount and the date are exactly what a buyer wants to weigh.
///
/// THREE shapes exist in the wild and all are handled, matching how the
/// ghostkeys vault itself presents them (`ui/src/components/ghostkey_list.rs`)
/// so the two apps do not disagree about the same key:
///
///   * JSON, current: `{"action":"freenet-donation","amount":1,
///     "delegate-key-created":"2024-08-13 15:45:36"}`
///   * legacy: `donation_amount:100`
///   * a plain string such as `Freenet Notary`, written by the vault's own
///     migration adapters
///
/// Anything unrecognised is passed through unchanged rather than replaced with
/// a guess: showing the raw field is ugly, but inventing a tier for a
/// certificate this build cannot read would misrepresent a seller's standing.
fn describe_notary_info(info: &str) -> String {
    let amount = extract_amount(info);
    let date = extract_created_date(info);
    match (amount, date) {
        (Some(a), Some(d)) => format!("${a} donated, {d}"),
        (Some(a), None) => format!("${a} donated"),
        (None, Some(d)) => format!("donated {d}"),
        // Not a shape we know. Keep whatever the certificate said.
        (None, None) => info.to_string(),
    }
}

/// The donation amount, from either the JSON or the legacy encoding.
fn extract_amount(info: &str) -> Option<u32> {
    if info.starts_with('{') {
        extract_json_field(info, "amount")?.parse().ok()
    } else {
        info.strip_prefix("donation_amount:")?.trim().parse().ok()
    }
}

/// The creation date, rendered as `13 August 2024`. JSON only; the legacy
/// encoding carries no date.
fn extract_created_date(info: &str) -> Option<String> {
    if !info.starts_with('{') {
        return None;
    }
    let raw = extract_json_field(info, "delegate-key-created")?;
    let ymd = raw.split(' ').next().unwrap_or(raw);
    let mut parts = ymd.split('-');
    let year = parts.next()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || year.len() != 4 {
        return None;
    }
    let month_name = match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => return None,
    };
    if !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{day} {month_name} {year}"))
}

/// A deliberately small reader for the one flat object this field ever holds.
///
/// Not `serde_json`: the value is a certificate field written by another
/// project, so the failure that matters is an unexpected shape, and every
/// caller here already treats "could not read it" as a normal outcome rather
/// than an error. A reader that returns `None` on anything surprising is the
/// right shape for that, and it cannot panic on a malformed certificate.
///
/// Matches the key only at the TOP LEVEL of the object. An earlier version
/// took the first textual match, so `{"nested":{"amount":42},"amount":7}`
/// answered 42 -- the wrong donation, reported confidently. The field is flat
/// in practice and notary-issued rather than seller-chosen, so that input is
/// not expected; it is refused anyway, because a wrong answer here misstates a
/// seller's standing while `None` merely declines to.
fn extract_json_field<'a>(info: &'a str, key: &str) -> Option<&'a str> {
    let bytes = info.as_bytes();
    let pat = format!("\"{key}\"");
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            '"' => {
                // A key sits at depth 1 and is followed by a colon.
                if depth == 1 && info[i..].starts_with(&pat) {
                    let after = info[i + pat.len()..].trim_start();
                    if let Some(after) = after.strip_prefix(':') {
                        let after = after.trim_start();
                        return if let Some(rest) = after.strip_prefix('"') {
                            rest.find('"').map(|end| &rest[..end])
                        } else {
                            let end = after.find(|c: char| !c.is_ascii_digit())?;
                            if end == 0 {
                                None
                            } else {
                                Some(&after[..end])
                            }
                        };
                    }
                }
                in_string = true;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Sign a new listing with the store key and publish it (harvest#93).
///
/// The store is the Ghost Key's first store this device holds a store key
/// for. A seller whose only store predates store keys is offered a move
/// instead of this form, so reaching here without one is reported rather than
/// signed for with the wrong key.
fn sign_and_submit_listing(fingerprint: String, listing: Listing) {
    let mut state = APP_STATE.write();
    let Some(store_contract_id) = state.signable_store_for(&fingerprint) else {
        state.notifications.push(format!(
            "Cannot add the listing: {}",
            crate::state::NO_STORE_KEY_MESSAGE
        ));
        return;
    };
    let title = listing.title.clone();
    match state.queue_listing_signature(store_contract_id, fingerprint, listing) {
        Ok(()) => dioxus::logger::tracing::info!("Queued listing for signing: {title}"),
        Err(e) => state
            .notifications
            .push(format!("Cannot add the listing: {e}")),
    }
}

fn truncate_fingerprint(fp: &str) -> String {
    if fp.len() > 12 {
        format!("{}...", &fp[..12])
    } else {
        fp.to_string()
    }
}

#[cfg(test)]
mod store_details_button_tests {
    use super::{store_details_button_action, StoreDetailsAction};
    use crate::state::StoreDetailsGap;

    /// The regression test for #78. Before the fix, this function did not
    /// exist -- the button always toggled the form open -- so clicking
    /// "Publish details" for a store missing only its encryption key never
    /// reached the delegate: no vault prompt, no notification, no change.
    /// Reverting the fix (making this always return `ToggleForm`) makes this
    /// fail.
    #[test]
    fn no_encryption_key_gap_publishes_immediately() {
        assert_eq!(
            store_details_button_action(Some(StoreDetailsGap::NoEncryptionKey), false),
            StoreDetailsAction::PublishNow
        );
    }

    /// Every other gap needs the seller to type something -- at minimum a
    /// store name -- so those still open the form rather than republishing
    /// blank or stale fields.
    #[test]
    fn gaps_needing_seller_input_open_the_form() {
        for gap in [StoreDetailsGap::NeverPublished, StoreDetailsGap::NoName] {
            assert_eq!(
                store_details_button_action(Some(gap), false),
                StoreDetailsAction::ToggleForm,
                "{gap:?} should still open the form"
            );
        }
    }

    /// An ordinary "Edit details" click (no gap at all) is unaffected: it
    /// still opens the form so the seller can change something on purpose.
    #[test]
    fn no_gap_opens_the_edit_form() {
        assert_eq!(
            store_details_button_action(None, false),
            StoreDetailsAction::ToggleForm
        );
    }

    /// The regression test for the PR #80 review finding. `EncryptionKeyReady`
    /// can arrive at any time, independent of the seller -- if the button
    /// ignored `is_editing` it would flip to `PublishNow` and, on the next
    /// click, publish the OLD on-record details over whatever the seller has
    /// typed into the still-open form. Reverting the `is_editing` check (so
    /// this only looks at `gap`) makes this fail.
    #[test]
    fn an_open_form_always_cancels_even_if_the_gap_is_now_no_encryption_key() {
        assert_eq!(
            store_details_button_action(Some(StoreDetailsGap::NoEncryptionKey), true),
            StoreDetailsAction::ToggleForm
        );
    }

    /// `is_editing` overrides every gap, not just `NoEncryptionKey` -- an
    /// open form is always closable.
    #[test]
    fn an_open_form_always_cancels_regardless_of_gap() {
        for gap in [
            None,
            Some(StoreDetailsGap::NeverPublished),
            Some(StoreDetailsGap::NoName),
            Some(StoreDetailsGap::NoEncryptionKey),
        ] {
            assert_eq!(
                store_details_button_action(gap, true),
                StoreDetailsAction::ToggleForm,
                "{gap:?} while editing should still be Cancel"
            );
        }
    }
}

#[cfg(test)]
mod notary_info_tests {
    use super::describe_notary_info;

    /// The exact string observed in the browser on 2026-09-06, which is what
    /// prompted this. Pinning the real value rather than a synthetic one:
    /// the whole bug was that nobody had looked at what the field contains.
    #[test]
    fn the_observed_certificate_reads_as_a_donation_and_a_date() {
        let info = r#"{"action":"freenet-donation","amount":1,"delegate-key-created":"2024-08-13 15:45:36"}"#;
        assert_eq!(describe_notary_info(info), "$1 donated, 13 August 2024");
    }

    #[test]
    fn a_larger_donation_keeps_its_amount() {
        let info = r#"{"action":"freenet-donation","amount":100,"delegate-key-created":"2023-01-01 00:00:00"}"#;
        assert_eq!(describe_notary_info(info), "$100 donated, 1 January 2023");
    }

    /// The pre-JSON encoding, still present in the vault's own fixtures. It
    /// carries no date, so only the amount is claimed.
    #[test]
    fn the_legacy_encoding_still_reads() {
        assert_eq!(describe_notary_info("donation_amount:20"), "$20 donated");
    }

    /// Written by the vault's migration adapters. Not a shape we can unpack,
    /// and inventing a tier for it would misstate a seller's standing -- so it
    /// passes through untouched.
    #[test]
    fn an_unrecognised_certificate_is_shown_verbatim_rather_than_guessed_at() {
        assert_eq!(describe_notary_info("Freenet Notary"), "Freenet Notary");
        assert_eq!(describe_notary_info(""), "");
    }

    /// A malformed certificate must not panic and must not be dressed up as a
    /// donation it does not attest.
    #[test]
    fn malformed_json_does_not_panic_or_invent_a_tier() {
        for info in [
            r#"{"amount":}"#,
            r#"{"amount":"not-a-number"}"#,
            r#"{"delegate-key-created":"not-a-date"}"#,
            r#"{"delegate-key-created":"2024-13-99 00:00:00"}"#,
            "{",
            r#"{"amount"#,
        ] {
            let shown = describe_notary_info(info);
            assert!(
                !shown.contains('$'),
                "{info:?} is not a readable donation but rendered as {shown:?}"
            );
        }
    }

    /// A nested object must not shadow the real field. An earlier version of
    /// the reader took the first textual match and answered 42 here -- the
    /// wrong donation, reported confidently, which is worse than declining.
    #[test]
    fn a_nested_amount_does_not_shadow_the_top_level_one() {
        let info = r#"{"nested":{"amount":42},"amount":7}"#;
        assert_eq!(describe_notary_info(info), "$7 donated");
    }

    /// A key that only appears nested has no top-level answer, so none is
    /// given -- the certificate passes through as-is rather than being
    /// described by a number lifted out of a sub-object.
    #[test]
    fn an_amount_that_exists_only_nested_is_not_claimed() {
        let info = r#"{"nested":{"amount":42}}"#;
        assert_eq!(describe_notary_info(info), info);
    }

    /// The key appearing inside a STRING value must not be mistaken for the
    /// key itself.
    #[test]
    fn the_key_inside_a_string_value_is_not_matched() {
        let info = r#"{"note":"beware \"amount\": 99","amount":3}"#;
        assert_eq!(describe_notary_info(info), "$3 donated");
    }

    /// A date without an amount still tells a buyer how old the identity is,
    /// which is half the reputation signal.
    #[test]
    fn a_date_alone_is_still_worth_showing() {
        let info = r#"{"delegate-key-created":"2024-08-13 15:45:36"}"#;
        assert_eq!(describe_notary_info(info), "donated 13 August 2024");
    }
}
