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
    /// `None` when the page URL is unavailable, as on a native build.
    link: Option<String>,
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
                    rsa_keys: app_state.rsa_public_keys.clone(),
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
    rsa_keys: std::collections::HashMap<String, Vec<u8>>,
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
                    has_rsa_key: rsa_keys.contains_key(&gk.fingerprint),
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
    has_rsa_key: bool,
    has_harvest_delegate: bool,
) -> Element {
    let mut show_listing_form = use_signal(|| false);
    let mut show_store_form = use_signal(|| false);
    // Which store's details form is open, if any. One signal rather than one
    // per store: hooks cannot be created inside a loop.
    let mut editing_store = use_signal(|| Option::<Vec<u8>>::None);
    let fp = identity.fingerprint.clone();
    let has_store = !stores.is_empty();

    // Buyers can only reach a store through a link the seller sends them, so
    // the seller has to be able to see it. Built here rather than in rsx
    // because it needs the page URL, which native builds don't have.
    //
    // Each store is labelled: a seller with two stores otherwise gets two
    // 44-character links with nothing to tell them apart.
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
                Some(StoreCard {
                    label: crate::store_link::store_label(
                        &store.store_contract_id,
                        name.as_deref(),
                    ),
                    link: crate::store_link::share_link(&store.store_contract_id),
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
                        payment_instructions: info
                            .map(|i| i.payment_instructions.clone())
                            .unwrap_or_default(),
                    },
                    details_resolved: app_state
                        .store_details_are_resolved(&store.store_contract_id),
                    certificate: browsing
                        .map(|browsing| browsing.certificate_status.clone())
                        .unwrap_or_default(),
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
                } else if has_rsa_key {
                    span { class: "text-warning", "Creating contracts..." }
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

        if !store_cards.is_empty() {
            div { class: "store-share",
                p { class: "text-muted",
                    "Share this link so buyers can open your store:"
                }
                for card in store_cards.iter().cloned() {
                    div { class: "store-share-row",
                        span { class: "store-share-label", "{card.label}" }
                        if let Some(ref link) = card.link {
                            input {
                                class: "form-input",
                                readonly: true,
                                value: "{link}",
                            }
                        }

                        // Nothing is offered until we know what the store
                        // has published. Before this, the button said "Edit
                        // details" and the form opened filled with empty
                        // strings -- which reads as details that have been
                        // lost, so the seller retypes them, and the edit is
                        // then published at a version the store contract
                        // discards as stale.
                        if !card.details_resolved {
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
                                onclick: {
                                    let id = card.contract_id.clone();
                                    move |_| {
                                        let id = id.clone();
                                        if editing_store() == Some(id.clone()) {
                                            editing_store.set(None);
                                        } else {
                                            editing_store.set(Some(id));
                                        }
                                    }
                                },
                                if editing_store() == Some(card.contract_id.clone()) {
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
                    initiate_store_creation(identity.fingerprint.clone(), details);
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
    let mut payment_instructions = use_signal(|| initial.payment_instructions.clone());

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
            }

            div { class: "form-group",
                label { class: "form-label", "Payment Instructions" }
                textarea {
                    class: "form-textarea",
                    placeholder: "How should buyers pay? e.g. BTC: bc1q..., or contact me to arrange",
                    value: "{payment_instructions}",
                    oninput: move |e| payment_instructions.set(e.value()),
                }
            }

            button {
                class: "btn btn-primary",
                disabled: store_name().trim().is_empty(),
                onclick: move |_| {
                    on_submit.call(StoreDetails {
                        store_name: store_name().trim().to_string(),
                        description: description().trim().to_string(),
                        payment_instructions: payment_instructions().trim().to_string(),
                    });
                },
                "{submit_label}"
            }
        }
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

/// Initiate the full store creation flow:
/// 1. Set pending_store_creation with store details
/// 2. Send InitReputationKeys to harvest delegate
/// 3. When RSA key arrives, state.rs triggers create_store_contracts
fn initiate_store_creation(_fingerprint: String, _details: StoreDetails) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let details = _details;

        wasm_bindgen_futures::spawn_local(async move {
            // First, we need the ghostkey's verifying key and certificate.
            // For now, we'll need the ghostkey delegate to provide these.
            // The certificate PEM and verifying key bytes come from
            // GhostkeyResponse::GhostKeyDetail or GhostkeyResponse::Certificate.
            //
            // For the initial implementation, we store the pending creation
            // with placeholder values -- the verifying key will come from
            // the ghostkey certificate when we have inter-delegate communication.
            //
            // TODO: Request GhostKeyDetail from ghostkey delegate to get
            // certificate_pem and extract verifying key bytes.

            let app_state = APP_STATE.read();
            let delegate_key = match &app_state.harvest_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!("Harvest delegate not registered");
                    return;
                }
            };
            drop(app_state);

            // Try to get the verifying key from the already-loaded ghostkeys
            let vk_bytes = {
                let state = APP_STATE.read();
                state
                    .ghostkeys
                    .iter()
                    .find(|k| k.fingerprint == fingerprint)
                    .and_then(|k| k.verifying_key_bytes.as_ref())
                    .and_then(|b| {
                        if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(b);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 32])
            };

            // Store the pending creation details
            APP_STATE.write().pending_store_creation = Some(crate::state::PendingStoreCreation {
                ghostkey_fingerprint: fingerprint.clone(),
                seller_verifying_key_bytes: vk_bytes,
                certificate_pem: String::new(),
                store_name: details.store_name,
                description: details.description,
                payment_instructions: details.payment_instructions,
                rsa_public_key_der: None,
                // Filled by `EncryptionKeyReady` below. Creation does not
                // wait for it -- see the field's own documentation.
                encryption_public_key: None,
            });

            // Step 1: Request the ghostkey certificate to get the verifying key
            let app_state = APP_STATE.read();
            let gk_delegate_key = match &app_state.ghostkey_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!("Ghostkey delegate not registered");
                    APP_STATE.write().pending_store_creation = None;
                    return;
                }
            };
            drop(app_state);

            let cert_request = ghostkey_common::GhostkeyRequest::GetCertificate {
                fingerprint: fingerprint.clone(),
            };
            let cert_payload = match ghostkey_common::to_cbor(&cert_request) {
                Ok(p) => p,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize cert request: {}", e);
                    return;
                }
            };

            if let Err(e) =
                crate::gateway::send_delegate_message(&gk_delegate_key, cert_payload).await
            {
                dioxus::logger::tracing::error!("Failed to request certificate: {}", e);
                return;
            }

            // Step 2: Send InitReputationKeys to harvest delegate (in parallel)
            let request = harvest_common::HarvestDelegateRequest::InitReputationKeys {
                ghostkey_fingerprint: fingerprint.clone(),
            };
            let payload = match harvest_common::to_cbor(&request) {
                Ok(p) => p,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize request: {}", e);
                    return;
                }
            };

            if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
                dioxus::logger::tracing::error!("Failed to send InitReputationKeys: {}", e);
                return;
            }

            // Step 3: and the messaging key, so the store publishes with one.
            //
            // Sent here rather than waited on: a store that publishes without
            // it is a store buyers cannot message, which `store_details_gap`
            // reports and re-publishing repairs. A store whose creation hangs
            // waiting for a third delegate answer has no name at all.
            request_encryption_key(fingerprint.clone()).await;

            dioxus::logger::tracing::info!(
                "Sent GetCertificate + InitReputationKeys + InitEncryptionKey for {} -- store \
                 creation pending",
                fingerprint
            );
        });
    }
}

/// Ask the harvest delegate to mint (or recall) this identity's long-term
/// X25519 key, so the seller has one to publish.
///
/// Idempotent at the delegate, which is what lets this be called both at
/// store creation and whenever a ghostkey is connected without either caller
/// having to know about the other.
#[cfg(target_arch = "wasm32")]
async fn request_encryption_key(fingerprint: String) {
    let Some(delegate_key) = APP_STATE.read().harvest_delegate_key.clone() else {
        dioxus::logger::tracing::error!(
            "Harvest delegate not registered -- cannot mint an encryption key"
        );
        return;
    };
    let request = harvest_common::HarvestDelegateRequest::InitEncryptionKey {
        ghostkey_fingerprint: fingerprint.clone(),
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

/// The same request, spawned, for callers that are not already async.
#[cfg(target_arch = "wasm32")]
pub(crate) fn ensure_encryption_key(fingerprint: String) {
    wasm_bindgen_futures::spawn_local(async move {
        request_encryption_key(fingerprint).await;
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn ensure_encryption_key(_fingerprint: String) {}

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

fn sign_and_submit_listing(_fingerprint: String, _listing: Listing) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let listing = _listing;

        wasm_bindgen_futures::spawn_local(async move {
            let listing_bytes = match harvest_common::to_cbor(&listing) {
                Ok(b) => b,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize listing: {}", e);
                    return;
                }
            };

            let app_state = APP_STATE.read();
            let gk_delegate_key = match &app_state.ghostkey_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!(
                        "Ghostkey delegate not registered -- cannot sign listing"
                    );
                    APP_STATE
                        .write()
                        .notifications
                        .push("Cannot sign listing: ghostkey delegate not available.".into());
                    return;
                }
            };
            drop(app_state);

            let sign_request = ghostkey_common::GhostkeyRequest::SignMessage {
                fingerprint: fingerprint.clone(),
                message: listing_bytes,
            };
            let payload = match ghostkey_common::to_cbor(&sign_request) {
                Ok(p) => p,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize sign request: {}", e);
                    return;
                }
            };

            // Find the store contract ID for this fingerprint
            let store_contract_id = {
                let state = APP_STATE.read();
                state
                    .my_stores
                    .get(&fingerprint)
                    .and_then(|stores| stores.first())
                    .map(|s| s.store_contract_id.clone())
            };

            let title = listing.title.clone();
            // Queue before sending. This used to be recorded afterwards, so
            // a `SignResult` that arrived before the send returned found
            // nothing waiting and the signed listing was dropped.
            APP_STATE.write().pending_signatures.push_back(
                crate::state::PendingSignature::Listing(crate::state::PendingListing {
                    fingerprint: fingerprint.clone(),
                    listing,
                    store_contract_id,
                }),
            );

            if let Err(e) = crate::gateway::send_delegate_message(&gk_delegate_key, payload).await {
                dioxus::logger::tracing::error!("Failed to send SignMessage: {}", e);
                // Nothing will answer this one, and leaving it queued would
                // make it consume the next signature that arrives.
                APP_STATE.write().pending_signatures.pop_back();
                return;
            }

            dioxus::logger::tracing::info!(
                "Sent listing for signing (fingerprint: {}, title: {})",
                fingerprint,
                title
            );
        });
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
