use dioxus::prelude::*;
use harvest_common::listing::Listing;

use crate::gateway::APP_STATE;
use crate::state::{AppState, StoreDetails, StoreDetailsGap};

/// The pages of My store (harvest#93 phase 2, entity model section 4).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Tab {
    Overview,
    Listings,
    Orders,
    Settings,
}

/// One store the seller can manage from this device: one with a store key
/// (harvest#93). A store made before revision 2 is not one of these; its
/// Ghost Key is offered a move instead (see [`StoreSetup`]).
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct SellerStore {
    pub contract_id: Vec<u8>,
    /// The Ghost Key this store is registered under on this device.
    pub fingerprint: String,
    /// The store's name, or "Store <code>" before it has one.
    pub label: String,
    /// The store's code (harvest#52).
    pub code: Option<String>,
    /// The link to share, built from the code: see `store_link::share_link`
    /// for why it names the default node rather than this page's.
    pub link: Option<String>,
    /// Set when another key holds this store's address: what to tell the
    /// seller. See `AppState::foreign_store_owner`.
    pub foreign_owner: Option<String>,
    /// Set when the store's published details need repairing.
    pub gap: Option<StoreDetailsGap>,
    /// Current values, to fill the form with when editing.
    pub details: StoreDetails,
    /// Whether we actually know what this store has published: its state has
    /// arrived, or the GET for it gave up. False means the form would be
    /// filled with empty strings that look like lost details, and an edit
    /// submitted from it could not be given a version the contract accepts.
    /// See `state::AppState::store_details_are_resolved`.
    pub details_resolved: bool,
    /// The verdict a BUYER reaches about this store's Ghost Key certificate.
    ///
    /// Shown to the seller because it is the one thing about their own store
    /// they cannot otherwise see. Nothing in the publishing path fails when
    /// the certificate is unusable: only the buyer's storefront says the
    /// store is unbacked. Reading the same verdict here closes that gap.
    pub certificate: crate::ghostkey_cert::CertificateStatus,
    /// Whether a publish for this store is already on its way. Gates the
    /// `PublishNow` button so a second click can't queue a duplicate publish;
    /// see `state::AppState::store_publish_in_flight`.
    pub publish_in_flight: bool,
    /// Listings not taken down.
    pub listings: usize,
    /// Buyers' requests still waiting for an invoice.
    pub requests: usize,
    /// The store's record as its badge reads (`RecordLoad::badge`): "Clean
    /// record" only once the record has been read, and complaints counted the
    /// way the store page counts them.
    pub record: String,
    /// Invoices this seller issued, unpaid and still open, whose anchor is
    /// too old for a buyer to start paying.
    pub expired_invoices: usize,
}

/// Requests waiting for an invoice across every store this device manages:
/// the number beside "My store" in the navigation.
pub(crate) fn requests_needing_seller(state: &AppState) -> usize {
    seller_stores(state).iter().map(|s| s.requests).sum()
}

/// Every store this device can manage, by name.
pub(crate) fn seller_stores(state: &AppState) -> Vec<SellerStore> {
    let mut stores: Vec<SellerStore> = state
        .my_stores
        .iter()
        .flat_map(|(fingerprint, registrations)| {
            registrations
                .iter()
                .map(move |registration| (fingerprint, registration))
        })
        .filter_map(|(fingerprint, registration)| {
            let store_key = registration.store_verifying_key?;
            if registration.store_contract_id.len() != 32 {
                // Such a store cannot be updated either -- its contract key
                // cannot be rebuilt -- so there is nothing to offer.
                dioxus::logger::tracing::warn!(
                    "Store registration has a {}-byte contract id, not 32 -- not shown",
                    registration.store_contract_id.len()
                );
                return None;
            }
            let id = &registration.store_contract_id;
            let browsing = state.browsing_stores.get(id);
            let info = browsing.and_then(|b| b.info.as_ref());
            let name = info.map(|info| info.store_name.clone());
            let code = ed25519_dalek::VerifyingKey::from_bytes(&store_key)
                .ok()
                .map(|key| harvest_common::store::store_code(&key));
            let expired_invoices = browsing
                .map(|b| {
                    b.orders
                        .iter()
                        .filter(|o| o.order.seller_fingerprint == *fingerprint)
                        .filter(|o| state.needs_reissue(o))
                        // Only while it is still open (harvest#53): once its
                        // window has closed it has lapsed, which needs nothing
                        // from the seller, and a cancelled one is settled.
                        .filter(|o| {
                            let tip = state
                                .bitcoin
                                .tips
                                .get(&o.order.network)
                                .and_then(|tip| tip.tip_height);
                            matches!(
                                crate::fulfilment::order_stage(
                                    o,
                                    state.despatch_of(o).as_ref(),
                                    tip,
                                    state.payment_sight(o),
                                ),
                                crate::fulfilment::OrderStage::AwaitingPayment { .. }
                            )
                        })
                        .count()
                })
                .unwrap_or(0);
            Some(SellerStore {
                contract_id: id.clone(),
                fingerprint: fingerprint.clone(),
                label: match code.as_deref() {
                    Some(code) => crate::store_link::store_label(code, name.as_deref()),
                    None => name.clone().unwrap_or_else(|| "Your store".to_string()),
                },
                link: code.as_deref().map(crate::store_link::share_link),
                foreign_owner: state.foreign_store_owner(id).map(|held| {
                    crate::state::foreign_owner_message(code.as_deref().unwrap_or_default(), &held)
                }),
                code,
                // The seller can only be prompted to publish a key the
                // delegate has actually produced -- see
                // `state::store_details_gap`.
                gap: crate::state::store_details_gap(
                    info,
                    state.encryption_public_keys.contains_key(fingerprint),
                ),
                details: StoreDetails {
                    store_name: info.map(|i| i.store_name.clone()).unwrap_or_default(),
                    description: info.map(|i| i.description.clone()).unwrap_or_default(),
                },
                details_resolved: state.store_details_are_resolved(id),
                certificate: browsing
                    .map(|b| b.certificate_status.clone())
                    .unwrap_or_default(),
                publish_in_flight: state.store_publish_in_flight(id),
                listings: browsing
                    .map(|b| {
                        b.listings
                            .iter()
                            .filter(|l| {
                                b.availability(&l.listing.id)
                                    != harvest_common::listing::ListingAvailability::Withdrawn
                            })
                            .count()
                    })
                    .unwrap_or(0),
                requests: super::message_view::requests_awaiting_invoice(state, id),
                record: browsing
                    .map(|b| b.record_badge().1)
                    .unwrap_or_else(|| crate::state::RecordLoad::Loading.badge(0).1),
                expired_invoices,
            })
        })
        .collect();
    stores.sort_by(|a, b| {
        a.label
            .to_lowercase()
            .cmp(&b.label.to_lowercase())
            .then_with(|| a.contract_id.cmp(&b.contract_id))
    });
    stores
}

#[component]
pub fn MyStore() -> Element {
    let app_state = APP_STATE.read();
    let in_flight = app_state.request_any_access_in_flight;
    let ghostkeys = app_state.ghostkeys.clone();
    let has_harvest_delegate = app_state.harvest_delegate_key.is_some();
    let stores = seller_stores(&app_state);
    drop(app_state);

    rsx! {
        div { class: "my-store",
            if ghostkeys.is_empty() {
                h2 { "My store" }
                NoIdentity { in_flight }
            } else if stores.is_empty() {
                h2 { "My store" }
                FirstStore { ghostkeys, has_harvest_delegate }
            } else {
                StoreDashboard { stores, has_harvest_delegate }
            }
        }
    }
}

#[component]
fn NoIdentity(in_flight: bool) -> Element {
    rsx! {
        div { class: "card",
            h3 { "Sell on Harvest" }
            p {
                "A store on Harvest is backed by a Ghost Key: a Freenet identity you get by "
                "donating. Buyers see the amount you donated as what you have at stake."
            }
            ol { class: "steps",
                li {
                    "Get a Ghost Key from the Ghost Key vault, if you do not have one yet."
                }
                li {
                    "Let Harvest use it. "
                    button {
                        class: "btn btn-sm btn-primary",
                        disabled: in_flight,
                        onclick: move |_| connect_ghostkey(),
                        if in_flight { "Waiting for the vault\u{2026}" } else { "Choose a Ghost Key" }
                    }
                }
            }
            p { class: "text-muted small", "Only buying? You do not need one. Go to Stores." }
        }
    }
}

/// Send a `RequestAnyAccess` request to the ghostkey delegate. The
/// delegate emits a `RequestUserInput` that the gateway shell-page
/// renders as an overlay; the user picks one of their stored
/// ghostkeys (or denies). On approval the delegate replies with a
/// one-element `GhostKeyList` for the chosen key, which the response
/// handler folds into APP_STATE.ghostkeys.
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
                    .push("Still connecting to the gateway. Please try again in a moment.".into());
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

fn ghost_key_name(identity: &ghostkey_common::GhostKeyInfo) -> String {
    match identity.label.as_deref().map(str::trim) {
        Some(label) if !label.is_empty() => format!("Ghost Key \u{201c}{label}\u{201d}"),
        _ => format!("Ghost Key {}", truncate_fingerprint(&identity.fingerprint)),
    }
}

/// A Ghost Key is connected and no store exists yet (wireframe B). With more
/// than one Ghost Key, one line picks which backs the store.
#[component]
fn FirstStore(
    ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,
    has_harvest_delegate: bool,
) -> Element {
    let mut chosen = use_signal(|| 0usize);
    let index = chosen().min(ghostkeys.len().saturating_sub(1));
    let identity = ghostkeys[index].clone();

    rsx! {
        div { class: "card",
            h3 { "Set up your store" }
            if ghostkeys.len() > 1 {
                div { class: "form-group",
                    label { class: "form-label", r#for: "backing-key", "Backed by" }
                    select {
                        id: "backing-key",
                        class: "form-select",
                        onchange: move |e| chosen.set(e.value().parse().unwrap_or(0)),
                        for (i , key) in ghostkeys.iter().enumerate() {
                            option { value: "{i}", selected: i == index,
                                "{ghost_key_name(key)} \u{00b7} {describe_notary_info(&key.notary_info)}"
                            }
                        }
                    }
                }
            } else {
                p { class: "text-muted",
                    "Backed by {ghost_key_name(&identity)} \u{00b7} {describe_notary_info(&identity.notary_info)}"
                }
            }
            StoreSetup {
                key: "{identity.fingerprint}",
                identity: identity.clone(),
                has_harvest_delegate,
            }
            UseAnotherKey {}
            p { class: "text-muted small",
                "You can move your store to a different Ghost Key later; it keeps its name, link "
                "and record. Next: add a payout wallet, add a listing, share your link."
            }
        }
    }
}

/// Ask the vault for another Ghost Key, with the in-flight guard.
#[component]
fn UseAnotherKey() -> Element {
    let in_flight = APP_STATE.read().request_any_access_in_flight;
    rsx! {
        button {
            class: "link-btn",
            disabled: in_flight,
            onclick: move |_| connect_ghostkey(),
            if in_flight { "Waiting for the vault\u{2026}" } else { "Use a different Ghost Key" }
        }
    }
}

/// Whatever one Ghost Key needs before it has a store this device can manage:
/// creating one, moving a store made before revision 2, or waiting on either.
#[component]
fn StoreSetup(identity: ghostkey_common::GhostKeyInfo, has_harvest_delegate: bool) -> Element {
    let mut show_store_form = use_signal(|| false);
    let fp = identity.fingerprint.clone();
    let legacy_movable = APP_STATE.read().legacy_store_to_move(&fp).is_some();
    // Single-flight (harvest#93 review, Must Fix 3): set from the moment a
    // creation or move starts until it is published or fails.
    let creating = APP_STATE.read().store_creation_in_flight.as_deref() == Some(fp.as_str());
    // No Cancel once the PUTs have started (#98 re-check).
    let publishing = APP_STATE.read().store_publishing;
    // A creation this Ghost Key's existing backing refused, waiting on the
    // seller's answer (harvest#93 section 6.2).
    let second_store = APP_STATE
        .read()
        .second_store_offer
        .clone()
        .filter(|offer| offer.fingerprint == fp);
    // A store made before revision 2 that has not loaded yet: offering
    // "Create store" now would make a second store instead of moving this
    // one (#98 review, L3).
    let legacy_loading = APP_STATE.read().legacy_store_loading(&fp);

    rsx! {
        if !has_harvest_delegate {
            p { class: "text-muted text-italic",
                "Connecting to Harvest\u{2019}s delegate. Store creation is available once it loads."
            }
        }
        if creating {
            div { class: "row-between",
                span { class: "text-muted text-italic", "Creating your store\u{2026}" }
                // A creation can stall on an answer that never comes (#98
                // review, L1). Cancelling keeps the store key and any signed
                // backing, so trying again resumes it.
                if !publishing {
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: move |_| APP_STATE.write().cancel_store_creation(),
                        "Cancel"
                    }
                }
            }
        } else if legacy_movable {
            p { class: "text-warning",
                "This Ghost Key has a store made before stores had keys of their own, so this \
                 version of Harvest cannot publish to it and buyers cannot pay it. Moving it gives \
                 it a key, backed by this Ghost Key, and carries its name, description and \
                 listings across. Its link changes, so share the new one; open orders are not \
                 carried."
            }
            button {
                class: "btn btn-sm btn-primary",
                disabled: !has_harvest_delegate,
                onclick: {
                    let fp = fp.clone();
                    move |_| move_legacy_store(fp.clone())
                },
                "Move this store"
            }
        } else if legacy_loading {
            p { class: "text-muted text-italic", "Loading your existing store\u{2026}" }
        } else if show_store_form() {
            StoreDetailsForm {
                heading: "",
                submit_label: "Create store",
                initial: StoreDetails::default(),
                on_cancel: move |_| show_store_form.set(false),
                on_submit: {
                    let fp = fp.clone();
                    move |details: StoreDetails| {
                        show_store_form.set(false);
                        initiate_store_creation(fp.clone(), details, Vec::new());
                    }
                },
            }
        } else {
            button {
                class: "btn btn-primary",
                disabled: !has_harvest_delegate,
                onclick: move |_| show_store_form.set(true),
                "Create a store"
            }
        }

        if let Some(offer) = second_store {
            div { class: "notice",
                p { class: "text-warning",
                    "This Ghost Key already backs {offer.other_store}. A Ghost Key backs one \
                     store at a time, so a buyer who has loaded both will treat BOTH as \
                     unbacked and will not pay either. This version has no way to undo that: \
                     use a different Ghost Key unless you mean it."
                }
                div { class: "form-actions",
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
        }
    }
}

/// The seller's dashboard: one store at a time, titled by its name, with a
/// switcher when there is more than one (entity model, wireframe C).
#[component]
fn StoreDashboard(stores: Vec<SellerStore>, has_harvest_delegate: bool) -> Element {
    // Pinned to the store first shown, so a store arriving later, or a name
    // arriving that reorders the list, does not switch the page under the
    // seller (and remount it, losing an open form).
    let mut selected = use_signal(|| Some(stores[0].contract_id.clone()));
    let tab = use_signal(|| Tab::Overview);
    let store = selected()
        .and_then(|id| stores.iter().find(|s| s.contract_id == id).cloned())
        .unwrap_or_else(|| stores[0].clone());

    // Counts what needs the seller, not everything there is: a request
    // waiting for an invoice.
    let orders_label = match store.requests {
        0 => "Orders".to_string(),
        n => format!("Orders ({n})"),
    };
    let listings_label = format!("Listings ({})", store.listings);
    let current = tab();

    rsx! {
        div { class: "dashboard",
        div { class: "dashboard-head",
            h2 { class: "dashboard-title", "{store.label}" }
            if stores.len() > 1 {
                select {
                    class: "form-select store-switcher",
                    aria_label: "Switch store",
                    onchange: {
                        let ids: Vec<Vec<u8>> = stores.iter().map(|s| s.contract_id.clone()).collect();
                        move |e: Event<FormData>| {
                            if let Some(id) = e.value().parse::<usize>().ok().and_then(|i| ids.get(i)) {
                                selected.set(Some(id.clone()));
                            }
                        }
                    },
                    for (i , s) in stores.iter().enumerate() {
                        option { value: "{i}", selected: s.contract_id == store.contract_id, "{s.label}" }
                    }
                }
            }
        }
        div { class: "tabs", role: "tablist",
            for (t , label) in [
                (Tab::Overview, "Overview".to_string()),
                (Tab::Listings, listings_label.clone()),
                (Tab::Orders, orders_label.clone()),
                (Tab::Settings, "Settings".to_string()),
            ]
            {
                button {
                    class: if current == t { "tab active" } else { "tab" },
                    role: "tab",
                    aria_selected: if current == t { "true" } else { "false" },
                    onclick: {
                        let mut tab = tab;
                        move |_| tab.set(t)
                    },
                    "{label}"
                }
            }
        }
        // One keyed item in a list, so switching stores REMOUNTS the body and
        // nothing per-store (an open form, its typed values, an edit in
        // progress) carries over to the other store. A key on a lone node is
        // not compared (dioxus diffs keys only in lists), which is why this
        // is a loop of one.
        for body in std::iter::once(store.clone()) {
            StoreBody {
                key: "{bs58::encode(&body.contract_id).into_string()}",
                store: body.clone(),
                tab,
                has_harvest_delegate,
            }
        }
        }
    }
}

/// The page of My store that is showing, for one store.
#[component]
fn StoreBody(store: SellerStore, tab: Signal<Tab>, has_harvest_delegate: bool) -> Element {
    // Whether the details form is open, shared by Overview (whose repair
    // prompt opens it) and Settings (where it lives). Per store, because this
    // component is remounted when the store changes.
    let editing_details = use_signal(|| false);
    rsx! {
        div { class: "tab-body",
            match tab() {
                Tab::Overview => rsx! { Overview { store: store.clone(), tab, editing_details } },
                Tab::Listings => rsx! {
                    super::seller_listings::SellerListings {
                        store_contract_id: store.contract_id.clone(),
                        fingerprint: store.fingerprint.clone(),
                    }
                },
                Tab::Orders => rsx! {
                    super::message_view::MessageView { store_contract_id: store.contract_id.clone() }
                    super::invoice_form::StorePayments {
                        store_contract_id: store.contract_id.clone(),
                        seller_fingerprint: store.fingerprint.clone(),
                    }
                },
                Tab::Settings => rsx! {
                    Settings { store: store.clone(), editing_details, has_harvest_delegate }
                },
            }
        }
    }
}

/// What needs the seller, what is left to set up, the link to share, and the
/// store's record (wireframe C).
#[component]
fn Overview(store: SellerStore, tab: Signal<Tab>, editing_details: Signal<bool>) -> Element {
    let has_wallet = APP_STATE.read().bitcoin.payment_xpub.is_some();
    let wallet_known = APP_STATE.read().bitcoin.payment_xpub_loaded;
    let details_done = store.details_resolved && store.gap.is_none();
    let setup_done = details_done && has_wallet && store.listings > 0;
    let mut go = move |t: Tab| tab.set(t);

    let instant_checkout = APP_STATE
        .read()
        .instant_checkout_notice(&store.contract_id, crate::state::now_ms());

    let needs: bool = store.foreign_owner.is_some()
        || (store.details_resolved && store.gap.is_some())
        || !store.certificate.is_verified()
        || store.expired_invoices > 0
        || store.requests > 0;

    rsx! {
        section { class: "card",
            h3 { "Needs you" }
            if let Some(ref refusal) = store.foreign_owner {
                p { class: "text-warning", "{refusal}" }
            }
            if !store.details_resolved {
                p { class: "text-muted text-italic", "Loading this store\u{2019}s published details\u{2026}" }
            } else if let Some(gap) = store.gap {
                // The repair prompt says what is wrong and what publishing
                // fixes, as a one-click action where nothing needs typing.
                div { class: "need",
                    p { class: "text-warning", "{gap.message()}" }
                    StoreDetailsButton { store: store.clone(), editing_details, on_open_form: move |_| go(Tab::Settings) }
                }
            }
            if store.details_resolved && !store.certificate.is_verified() {
                // Editing the details will not fix this, so it is not phrased
                // as a repair prompt: a certificate that does not verify is
                // either an identity this build cannot read or one that is
                // not the seller's, and both need looking at.
                p { class: "text-warning",
                    "Buyers see this store as unbacked: {store.certificate.label()}."
                    if let Some(why) = store.certificate.detail() {
                        " ({why})"
                    }
                }
            }
            if store.requests > 0 {
                div { class: "need row-between",
                    strong {
                        if store.requests == 1 {
                            "1 buyer is waiting for an invoice."
                        } else {
                            "{store.requests} buyers are waiting for an invoice."
                        }
                    }
                    button { class: "btn btn-sm btn-primary", onclick: move |_| go(Tab::Orders), "Open orders" }
                }
            }
            if store.expired_invoices > 0 {
                div { class: "need row-between",
                    span {
                        if store.expired_invoices == 1 {
                            "1 unpaid invoice is too old for a buyer to start paying. Issue it again if they still want it."
                        } else {
                            "{store.expired_invoices} unpaid invoices are too old for a buyer to start paying. Issue them again if the buyers still want them."
                        }
                    }
                    button { class: "btn btn-sm btn-outline", onclick: move |_| go(Tab::Orders), "Open orders" }
                }
            }
            if !needs && store.details_resolved {
                p { class: "text-muted", "Nothing needs you right now." }
            }
        }

        if let Some(notice) = instant_checkout {
            section { class: "card",
                h3 { "Instant checkout" }
                p { class: "text-muted", "{notice}" }
            }
        }

        if !setup_done {
            section { class: "card",
                h3 { "Set up" }
                ul { class: "checklist",
                    li { class: "done", "Store created" }
                    li { class: if details_done { "done" } else { "" },
                        "Name and description published"
                        if !details_done && store.details_resolved {
                            button { class: "link-btn", onclick: move |_| go(Tab::Settings), "Settings" }
                        }
                    }
                    li { class: if has_wallet { "done" } else { "" },
                        "Payout wallet"
                        if !has_wallet && wallet_known {
                            button { class: "link-btn", onclick: move |_| go(Tab::Settings), "Add one" }
                        }
                    }
                    li { class: if store.listings > 0 { "done" } else { "" },
                        "A listing"
                        if store.listings == 0 {
                            button { class: "link-btn", onclick: move |_| go(Tab::Listings), "Add one" }
                        }
                    }
                }
            }
        }

        section { class: "card",
            h3 { "Share your store" }
            if let Some(ref code) = store.code {
                div { class: "share-row",
                    span { class: "share-label", "Store code" }
                    code { class: "share-value", "{code}" }
                }
            }
            if let Some(ref link) = store.link {
                div { class: "share-row",
                    span { class: "share-label", "Link" }
                    // Styled as a value to copy rather than a form field: it
                    // is readonly, and dressed as an input it read as
                    // something to edit.
                    input {
                        class: "copy-field",
                        readonly: true,
                        spellcheck: false,
                        aria_label: "{store.label} store link, select to copy",
                        value: "{link}",
                    }
                }
            }
            p { class: "text-muted small",
                "Buyers need Freenet running. The link opens your store on their own node at its "
                "usual address; a buyer whose node runs elsewhere can enter the code in Stores."
            }
        }

        section { class: "card",
            h3 { "Your record" }
            p { "{store.record}" }
            button {
                class: "btn btn-sm btn-outline",
                onclick: {
                    let id = store.contract_id.clone();
                    move |_| super::app::open_store_page(id.clone())
                },
                "See your store as buyers do"
            }
        }
    }
}

/// The store-details button, with the repair logic `store_details_button_action`
/// decides: publish straight away when nothing needs typing, otherwise open the
/// form.
#[component]
fn StoreDetailsButton(
    store: SellerStore,
    editing_details: Signal<bool>,
    on_open_form: EventHandler<()>,
) -> Element {
    let is_editing = editing_details();
    let action = store_details_button_action(store.gap, is_editing);
    rsx! {
        button {
            class: if store.gap.is_some() { "btn btn-sm btn-primary" } else { "btn btn-sm btn-outline" },
            // Only the `PublishNow` path can double-fire a real network
            // request on a double-click -- `ToggleForm` just flips a local
            // signal, so it is left enabled. See
            // `state::AppState::store_publish_in_flight` for why this can
            // never get stuck disabled.
            disabled: action == StoreDetailsAction::PublishNow && store.publish_in_flight,
            onclick: {
                let id = store.contract_id.clone();
                let details = store.details.clone();
                let gap = store.gap;
                move |_| {
                    // Recomputed at click time, not captured from the render
                    // that drew this button: the form can open or close
                    // between renders, and this is what keeps a store whose
                    // form is open from being silently published with the
                    // old, on-record details when `NoEncryptionKey` appears
                    // while the seller has unsaved edits open (#80 review).
                    let is_editing = editing_details();
                    match store_details_button_action(gap, is_editing) {
                        // See `store_details_button_action` for why this
                        // publishes instead of opening the form (#78).
                        StoreDetailsAction::PublishNow => {
                            // Fresh read: two clicks can land before Dioxus
                            // re-renders the `disabled` attribute (#80 review).
                            if APP_STATE.read().store_publish_in_flight(&id) {
                                return;
                            }
                            publish_store_details(id.clone(), details.clone());
                        }
                        StoreDetailsAction::ToggleForm => {
                            editing_details.set(!is_editing);
                            if !is_editing {
                                on_open_form.call(());
                            }
                        }
                    }
                }
            },
            if action == StoreDetailsAction::PublishNow {
                "Publish details"
            } else if is_editing {
                "Cancel"
            } else if store.gap.is_some() {
                "Publish details"
            } else {
                "Edit"
            }
        }
    }
}

/// Store details, payout wallet, the Ghost Key behind the store, and other
/// stores (wireframe E).
#[component]
fn Settings(
    store: SellerStore,
    editing_details: Signal<bool>,
    has_harvest_delegate: bool,
) -> Element {
    let (identity, others, in_flight, busy) = {
        let state = APP_STATE.read();
        let identity = state
            .ghostkeys
            .iter()
            .find(|k| k.fingerprint == store.fingerprint)
            .cloned();
        // Connected Ghost Keys with no store this device can manage: each can
        // open one, or move one made before revision 2.
        let others: Vec<ghostkey_common::GhostKeyInfo> = state
            .ghostkeys
            .iter()
            .filter(|k| state.signable_store_for(&k.fingerprint).is_none())
            .cloned()
            .collect();
        // A key whose creation is under way, or waiting on the seller's
        // answer about a second store, stays open when the seller comes back
        // to this tab, so its progress, Cancel and question are not hidden.
        let busy: Vec<String> = state
            .store_creation_in_flight
            .iter()
            .cloned()
            .chain(
                state
                    .second_store_offer
                    .iter()
                    .map(|o| o.fingerprint.clone()),
            )
            .collect();
        (identity, others, state.request_any_access_in_flight, busy)
    };
    let mut other_open = use_signal(|| Option::<String>::None);

    rsx! {
        section { class: "card",
            div { class: "row-between",
                h3 { "Store details" }
                if store.details_resolved {
                    StoreDetailsButton { store: store.clone(), editing_details, on_open_form: move |_| {} }
                }
            }
            if !store.details_resolved {
                // Nothing is offered until we know what the store has
                // published: a form filled with empty strings reads as lost
                // details, and an edit from it would be published at a
                // version the contract discards as stale.
                p { class: "text-muted text-italic", "Loading this store\u{2019}s published details\u{2026}" }
            } else if editing_details() {
                StoreDetailsForm {
                    heading: "",
                    submit_label: "Publish",
                    initial: store.details.clone(),
                    on_cancel: move |_| editing_details.set(false),
                    on_submit: {
                        let id = store.contract_id.clone();
                        move |details: StoreDetails| {
                            editing_details.set(false);
                            publish_store_details(id.clone(), details);
                        }
                    },
                }
            } else {
                if let Some(gap) = store.gap {
                    p { class: "text-warning", "{gap.message()}" }
                }
                p { strong { "{store.details.store_name}" } }
                if !store.details.description.is_empty() {
                    crate::markdown::Markdown {
                        source: store.details.description.clone(),
                        class: "store-desc",
                    }
                }
            }
        }

        section { class: "card",
            h3 { "Payout wallet" }
            super::invoice_form::PayoutWallet {}
            p { class: "text-muted small",
                "Each invoice gets a new address from this wallet. Harvest can create addresses but "
                "can never spend your coins."
            }
        }

        section { class: "card",
            h3 { "Backed by" }
            if let Some(ref identity) = identity {
                p {
                    "{ghost_key_name(identity)} \u{00b7} {describe_notary_info(&identity.notary_info)}"
                }
            }
            p { class: if store.certificate.is_verified() { "text-muted small" } else { "text-warning" },
                "Buyers see: {store.certificate.label()}."
            }
            p { class: "text-muted small", "Buyers see this as what you have at stake." }
        }

        section { class: "card",
            h3 { "Another store" }
            p { class: "text-muted small",
                "A new store starts with its own name, link and an empty record. Use a different "
                "Ghost Key to keep the two apart."
            }
            for other in others {
                div { class: "other-key", key: "{other.fingerprint}",
                    div { class: "row-between",
                        span { "{ghost_key_name(&other)} \u{00b7} {describe_notary_info(&other.notary_info)}" }
                        if other_open() != Some(other.fingerprint.clone()) && !busy.contains(&other.fingerprint) {
                            button {
                                class: "btn btn-sm btn-outline",
                                onclick: {
                                    let fp = other.fingerprint.clone();
                                    move |_| other_open.set(Some(fp.clone()))
                                },
                                "Open a store with it"
                            }
                        }
                    }
                    if other_open() == Some(other.fingerprint.clone()) || busy.contains(&other.fingerprint) {
                        StoreSetup { identity: other.clone(), has_harvest_delegate }
                    }
                }
            }
            button {
                class: "btn btn-sm btn-outline",
                disabled: in_flight,
                onclick: move |_| connect_ghostkey(),
                if in_flight { "Waiting for the vault\u{2026}" } else { "Use another Ghost Key" }
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
    on_cancel: EventHandler<()>,
) -> Element {
    let mut store_name = use_signal(|| initial.store_name.clone());
    let mut description = use_signal(|| initial.description.clone());

    rsx! {
        div { class: "details-form",
            if !heading.is_empty() {
                h3 { "{heading}" }
            }

            div { class: "form-group",
                label { class: "form-label", "Store name" }
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

            div { class: "form-actions",
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
                button {
                    class: "btn btn-outline",
                    onclick: move |_| on_cancel.call(()),
                    "Cancel"
                }
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
    // Its "Publishing" notice is the state's to show and end (harvest#166).
    match outcome {
        Ok(()) => {}
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

#[cfg(test)]
mod seller_stores_tests {
    use super::*;
    use harvest_common::listing::{
        AuthorizedListing, ListingAvailability, ListingId, ListingKind, ListingStatus,
    };

    fn registration(id: u8, key: Option<[u8; 32]>) -> harvest_common::StoreRegistration {
        harvest_common::StoreRegistration {
            store_contract_id: vec![id; 32],
            reputation_contract_id: vec![0u8; 32],
            mailbox_contract_id: vec![0u8; 32],
            store_contract_key: None,
            store_verifying_key: key,
        }
    }

    fn listing(n: u8) -> AuthorizedListing {
        AuthorizedListing {
            listing: Listing {
                checkout: None,
                choices: Vec::new(),
                id: ListingId([n; 32]),
                title: format!("Item {n}"),
                description: String::new(),
                kind: ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            certificate_pem: String::new(),
        }
    }

    /// My store manages only stores this device holds a store key for, and
    /// counts listings a buyer can see, not ones taken down. Mutated red by
    /// dropping the key filter and the `Withdrawn` filter.
    #[test]
    fn only_keyed_stores_are_managed_and_taken_down_listings_do_not_count() {
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![
                registration(1, Some(crate::state::test_store_key())),
                registration(2, None),
            ],
        );
        let mut store = crate::state::BrowsingStore {
            listings: vec![listing(1), listing(2)],
            ..Default::default()
        };
        store.listing_statuses.insert(
            ListingId([2; 32]),
            ListingStatus {
                listing: ListingId([2; 32]),
                revision: 1,
                availability: ListingAvailability::Withdrawn,
            },
        );
        state.browsing_stores.insert(vec![1u8; 32], store);
        let stores = seller_stores(&state);
        assert_eq!(
            stores.len(),
            1,
            "a store made before store keys is offered a move instead"
        );
        assert_eq!(stores[0].contract_id, vec![1u8; 32]);
        assert_eq!(stores[0].fingerprint, "fp");
        assert_eq!(stores[0].listings, 1);
        assert_eq!(stores[0].requests, 0);
        assert!(stores[0].code.is_some() && stores[0].link.is_some());
        assert_eq!(requests_needing_seller(&state), 0);
    }
}
