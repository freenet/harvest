use dioxus::prelude::*;
use harvest_common::listing::Listing;

use crate::gateway::APP_STATE;
use crate::state::{AppState, StoreDetails, StoreDetailsGap};

/// The seller's pages for one store (harvest#93 phase 2, entity model
/// section 4), reached from the Stores page's "Your store" cards.
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
    /// The store's name, or "Loading…" before it has one: never its code
    /// (`state::StoreName`).
    pub label: String,
    /// The store's code (harvest#52).
    pub code: Option<String>,
    /// The link to share, built from the code: see `store_link::share_link`
    /// for why it goes through freenet.org/open rather than this page's URL.
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
    /// The store's record as its badge reads (`RecordLoad::badge`): "No
    /// complaints" only once the record has been read, and complaints counted
    /// the way the store page counts them.
    pub record: String,
    /// Invoices this seller issued, unpaid and still open, whose anchor is
    /// too old for a buyer to start paying. Never a Buy now: one nobody paid
    /// just goes away (`fulfilment::is_unpaid_buy_now`).
    pub expired_invoices: usize,
    /// Paid orders waiting to be sent: the moment a Buy now first needs the
    /// seller.
    pub to_send: usize,
    /// Payments withheld for the seller to confirm (`AppState::
    /// settlement_hold`).
    pub to_confirm: usize,
    /// Listings on show with no sats price (from before every listing had
    /// one): nobody can buy them until the seller gives them one.
    pub unpriced: usize,
    /// The store has closed for good (its key signed the closed flag).
    pub closed: bool,
    /// The same Ghost Key backs this store and others (harvest#181): a Ghost
    /// Key backs one store at a time, so all of them count for nothing.
    pub key_conflict: Option<crate::closure_flow::KeyConflict>,
}

/// Whether an order at `stage` is paid and waiting to be sent: the one rule
/// the "Needs you" count, the Overview's order cards and the Orders tab all
/// use. Past its send-by date and still unsent it needs the seller all the
/// more (`OrderStage::needs_attention`, codex on harvest#177), and so does a
/// Paid order this node cannot yet place against the chain (`Unknown`):
/// without it, such an order lost its card and Mark as sent (review of #190).
/// Never one whose despatch is on record (`despatched`): `Unknown` is
/// decided before the despatch is looked at, and a recorded despatch whose
/// terms this node cannot check still hides Mark as sent.
pub(crate) fn needs_sending(
    order: &harvest_common::payment::AuthorizedOrder,
    stage: crate::fulfilment::OrderStage,
    despatched: bool,
) -> bool {
    if despatched {
        return false;
    }
    match stage {
        crate::fulfilment::OrderStage::AwaitingDespatch { .. }
        | crate::fulfilment::OrderStage::DespatchWindowClosed { .. } => true,
        crate::fulfilment::OrderStage::Unknown => {
            order.status == harvest_common::payment::OrderStatus::Paid
        }
        _ => false,
    }
}

/// `fingerprint`'s orders that are paid and waiting to be sent, each judged
/// by `stage_of` (`fulfilment::order_stage` against this node's view).
pub(crate) fn orders_to_send(
    orders: &[harvest_common::payment::AuthorizedOrder],
    fingerprint: &str,
    stage_of: impl Fn(&harvest_common::payment::AuthorizedOrder) -> crate::fulfilment::OrderStage,
    despatched: impl Fn(&harvest_common::payment::AuthorizedOrder) -> bool,
) -> Vec<harvest_common::payment::AuthorizedOrder> {
    orders
        .iter()
        .filter(|o| o.order.seller_fingerprint == fingerprint)
        .filter(|o| needs_sending(o, stage_of(o), despatched(o)))
        .cloned()
        .collect()
}

impl SellerStore {
    /// What needs the seller at this store: requests waiting for an invoice,
    /// paid orders waiting to be sent, and payments to confirm. Never an
    /// unpaid Buy now. The count on its Orders tab and its card on Stores.
    pub(crate) fn needs_you(&self) -> usize {
        self.requests + self.to_send + self.to_confirm
    }
}

/// Whether this store's "Needs you" card (`Overview`) holds anything: what
/// [`SellerStore::needs_you`] counts, and the rest it lists (a listing with
/// no price, a wallet gap, another key on the store's address, details to
/// repair, a backing buyers do not believe, expired invoices, instant
/// checkout alerts). The store's card on Stores reads the same, so it never
/// says "up to date" over a card that lists something.
pub(crate) fn overview_needs(store: &SellerStore, state: &AppState) -> bool {
    store.needs_you() > 0
        || store.unpriced > 0
        || state.wallet_gap_note_due(&store.contract_id).is_some()
        || store.foreign_owner.is_some()
        || (store.details_resolved && store.gap.is_some())
        || (store.details_resolved && !store.certificate.is_verified() && !store.closed)
        || store.key_conflict.is_some()
        || store.expired_invoices > 0
        || !state.instant_checkout_alerts(&store.contract_id).is_empty()
}

/// The first store this device manages that something needs the seller at
/// (`SellerStore::needs_you`): where the header's "needs you" pill goes.
pub(crate) fn first_store_needing_seller(state: &AppState) -> Option<Vec<u8>> {
    seller_stores(state)
        .into_iter()
        .find(|s| s.needs_you() > 0)
        .map(|s| s.contract_id)
}

/// What needs the seller across every store this device manages
/// ([`SellerStore::needs_you`]): the number beside "Stores" in the
/// navigation, visible from every page.
pub(crate) fn requests_needing_seller(state: &AppState) -> usize {
    seller_stores(state)
        .iter()
        .map(SellerStore::needs_you)
        .sum()
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
            let code = ed25519_dalek::VerifyingKey::from_bytes(&store_key)
                .ok()
                .map(|key| harvest_common::store::store_code(&key));
            let expired_invoices = browsing
                .map(|b| {
                    b.orders
                        .iter()
                        .filter(|o| o.order.seller_fingerprint == *fingerprint)
                        .filter(|o| !crate::fulfilment::is_unpaid_buy_now(o))
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
            // A payment withheld for the seller to confirm needs them too:
            // its card is on their list (`invoice_form::invoices_issued_by`).
            let to_confirm = state
                .withheld_settlements
                .iter()
                .filter(|(_, (store, order))| {
                    store.as_slice() == id.as_slice()
                        && order.order.seller_fingerprint == *fingerprint
                })
                .count();
            let to_send = browsing
                .map(|_| state.seller_orders_to_send(id, fingerprint).len())
                .unwrap_or(0);
            Some(SellerStore {
                contract_id: id.clone(),
                fingerprint: fingerprint.clone(),
                label: match state.store_name_of(id) {
                    // Given up on: it is still the seller's store.
                    crate::state::StoreName::Unreachable => "Your store".to_string(),
                    name => name.label(),
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
                to_send,
                to_confirm,
                closed: browsing.is_some_and(|b| b.closed),
                key_conflict: state.key_conflict(id),
                unpriced: browsing
                    .map(|b| {
                        b.listings
                            .iter()
                            .filter(|l| {
                                b.availability(&l.listing.id)
                                    != harvest_common::listing::ListingAvailability::Withdrawn
                                    && !l.listing.offers_instant_checkout()
                            })
                            .count()
                    })
                    .unwrap_or(0),
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

/// The seller's pages, reached from the Stores page: a store's dashboard,
/// or opening a first or another store (`app::SellerPage`). The pages that
/// open a store have a way back to Stores; the dashboard is under the Stores
/// tab, which stays lit.
#[component]
pub fn MyStore() -> Element {
    let app_state = APP_STATE.read();
    let in_flight = app_state.request_any_access_in_flight;
    let ghostkeys = app_state.ghostkeys.clone();
    let has_harvest_delegate = app_state.harvest_delegate_key.is_some();
    let stores = seller_stores(&app_state);
    drop(app_state);
    let another = super::app::SELLER_PAGE() == super::app::SellerPage::AnotherStore;

    rsx! {
        div { class: "my-store",
            if ghostkeys.is_empty() {
                BackToStores {}
                h2 { "Open a store" }
                NoIdentity { in_flight }
            } else if stores.is_empty() {
                BackToStores {}
                h2 { "Open a store" }
                FirstStore { ghostkeys, has_harvest_delegate }
            } else if another {
                BackToStores {}
                h2 { "Open another store" }
                section { class: "card",
                    AnotherStore { has_harvest_delegate }
                }
            } else {
                StoreDashboard { stores }
            }
        }
    }
}

/// "‹ Stores", above a page reached from the Stores page.
#[component]
pub(crate) fn BackToStores() -> Element {
    rsx! {
        button {
            class: "crumb",
            onclick: move |_| *super::app::ROUTE.write() = super::app::Route::Stores,
            "\u{2039} Stores"
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
                    a {
                        href: "{ghost_key_create_url()}",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        "Get a Ghost Key on freenet.org"
                    }
                    ", if you do not have one yet. It is a donation to Freenet, from $1. When it "
                    "is done, press Import to Freenet on that page."
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
            GhostKeyAccessNote {}
            p { class: "text-muted small",
                "Have a Ghost Key saved in a file? Import it in your "
                a {
                    href: "{GHOST_KEY_VAULT_PATH}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    "Ghost Key vault"
                }
                " first."
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

    {
        let mut state = APP_STATE.write();
        state.request_any_access_in_flight = true;
        state.ghostkey_access_problem = None;
    }
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

/// Where a Ghost Key comes from: freenet.org's donation page, told to hand
/// the new key's owner back to Harvest (`return_to`, which the page carries
/// through the payment and passes to the vault's import link).
pub(crate) fn ghost_key_create_url() -> String {
    format!(
        "https://freenet.org/ghostkey/create/?return_to={}",
        harvest_common::HARVEST_WEBAPP_CONTRACT_ID
    )
}

/// The Ghost Key vault's page on the reader's own node, as a path: the app
/// is served from that node, so a path works on any port and on
/// try.freenet.org, where a `127.0.0.1:7509` link would not. The id is the
/// one freenet.org's "Import to Freenet" button opens
/// (`donation-success.js` in freenet/web).
pub(crate) const GHOST_KEY_VAULT_PATH: &str =
    "/v1/contract/web/DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N/";

/// Why the last ask for a Ghost Key came back with none, beside whichever
/// control asked. Nothing once a key is shared or the user asks again.
#[component]
pub(crate) fn GhostKeyAccessNote(
    /// Whether to link to freenet.org's create page. Not where the page
    /// already offers "Get another Ghost Key" beside the button (round 4 of
    /// #197: two links to one place).
    #[props(default = true)]
    link: bool,
) -> Element {
    let problem = APP_STATE.read().ghostkey_access_problem;
    match problem {
        None => rsx! {},
        Some(crate::state::GhostKeyAccessProblem::Denied) => rsx! {
            p { class: "text-warning",
                "Harvest wasn\u{2019}t given a Ghost Key. Try again, and approve the request when \
                 Freenet asks."
            }
        },
        Some(crate::state::GhostKeyAccessProblem::NoneInVault) if link => rsx! {
            p { class: "text-warning",
                "You don\u{2019}t have a Ghost Key yet. "
                a {
                    href: "{ghost_key_create_url()}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    "Get one on freenet.org"
                }
                ", then try again."
            }
        },
        Some(crate::state::GhostKeyAccessProblem::NoneInVault) => rsx! {
            p { class: "text-warning",
                "You don\u{2019}t have another Ghost Key yet. Get one with the link above, then \
                 try again."
            }
        },
    }
}

fn ghost_key_name(identity: &ghostkey_common::GhostKeyInfo) -> String {
    match identity.label.as_deref().map(str::trim) {
        Some(label) if !label.is_empty() => format!("Ghost Key \u{201c}{label}\u{201d}"),
        _ => format!("Ghost Key {}", short_fingerprint(&identity.fingerprint)),
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
                        class: "form-select field-fit",
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
                "One Ghost Key backs one store. Next: add a payout wallet, add a listing, share "
                "your link."
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
        GhostKeyAccessNote {}
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
    // Whether this Ghost Key may create a store yet: not until this device
    // knows what it already backs (harvest#181, section 6.2).
    let gate = identity
        .verifying_key_bytes
        .as_deref()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(|backer| APP_STATE.read().store_creation_gate(&fp, &backer))
        // A vault too old to share the key's public key: there is no index
        // to read, so it cannot be checked at all.
        .unwrap_or(crate::index_flow::CreationGate::Unconfirmed);
    // Moving a store made before revision 2 creates a store under this Ghost
    // Key too, so it waits for the same answer.
    let gate_open = matches!(
        gate,
        crate::index_flow::CreationGate::Ready | crate::index_flow::CreationGate::Unconfirmed
    );
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
        } else if legacy_movable && gate_open {
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
        } else if legacy_loading && gate_open {
            p { class: "text-muted text-italic", "Loading your existing store\u{2026}" }
        } else if show_store_form() && gate_open {
            if gate == crate::index_flow::CreationGate::Unconfirmed {
                p { class: "text-warning", "{UNCONFIRMED_WARNING}" }
            }
            StoreDetailsForm {
                heading: "",
                submit_label: "Create store",
                initial: StoreDetails::default(),
                on_cancel: move |_| show_store_form.set(false),
                on_submit: {
                    let fp = fp.clone();
                    move |details: StoreDetails| {
                        show_store_form.set(false);
                        initiate_store_creation(fp.clone(), details);
                    }
                },
            }
        } else {
            match gate {
                crate::index_flow::CreationGate::Checking => rsx! {
                    p { class: "text-muted text-italic",
                        "Checking whether this Ghost Key already has a store\u{2026}"
                    }
                },
                crate::index_flow::CreationGate::BacksStore(name) => rsx! {
                    p { class: "text-muted",
                        "This Ghost Key already has a store, {name}. One Ghost Key can back only \
                         one store, so to open another store, use a different Ghost Key."
                    }
                },
                crate::index_flow::CreationGate::ListsUnloadedStore(code) => rsx! {
                    p { class: "text-muted",
                        "This Ghost Key already has a store (code {code}) that Harvest hasn\u{2019}t \
                         been able to load yet. One Ghost Key can back only one store, so to open \
                         another store, use a different Ghost Key."
                    }
                },
                crate::index_flow::CreationGate::Ready => rsx! {
                    button {
                        class: "btn btn-primary",
                        disabled: !has_harvest_delegate,
                        onclick: move |_| show_store_form.set(true),
                        "Create a store"
                    }
                },
                crate::index_flow::CreationGate::Unconfirmed => rsx! {
                    p { class: "text-warning", "{UNCONFIRMED_WARNING}" }
                    button {
                        class: "btn btn-primary",
                        disabled: !has_harvest_delegate,
                        onclick: move |_| show_store_form.set(true),
                        "Create a store"
                    }
                },
            }
        }
    }
}

/// Said beside "Create a store" when the Ghost Key's index could not be read
/// in time (harvest#181).
const UNCONFIRMED_WARNING: &str = "Harvest couldn\u{2019}t check yet whether this Ghost Key \
     already has a store, for example one you made on another device. If it has, use a different \
     Ghost Key: one Ghost Key can back only one store, and buyers won\u{2019}t pay either store if \
     it backs two.";

/// One Ghost Key backs this store and another (harvest#181): name the stores
/// so they can be told apart (they often share a name), say what it costs,
/// and offer to close one for good, with a confirmation that says it is
/// permanent. See `crate::closure_flow` for why closing, not retiring alone,
/// is the way out.
#[component]
fn KeyBacksTwoStores(conflict: crate::closure_flow::KeyConflict) -> Element {
    // The store the seller has asked to close, waiting on their confirmation.
    let mut confirming = use_signal(|| Option::<crate::closure_flow::SharingStore>::None);
    let closable: Vec<Vec<u8>> = conflict
        .closable()
        .into_iter()
        .map(|s| s.contract_id)
        .collect();
    let stores: Vec<(crate::closure_flow::SharingStore, bool)> =
        std::iter::once((conflict.this.clone(), true))
            .chain(conflict.others.iter().cloned().map(|s| (s, false)))
            .collect();
    let none_closable = closable.is_empty() && conflict.closing.is_none();
    rsx! {
        div { class: "need",
            p { class: "text-warning",
                strong { "Buyers can\u{2019}t buy from this store right now." }
            }
            p {
                "Your Ghost Key backs two stores, and one Ghost Key can back only one, so \
                 buyers treat both as unbacked. Keep one store and close the other for good."
            }
            ul { class: "conflict-stores",
                for (s , this) in stores {
                    li { key: "{s.code}", class: "row-between",
                        span {
                            strong { "{s.name}" }
                            if this { " (this store)" }
                            br {}
                            span { class: "text-muted small",
                                "Code {s.code} \u{00b7} {count(s.listings, \"listing\")} \u{00b7} {count(s.orders, \"order\")}"
                            }
                        }
                        if confirming().is_none() && closable.contains(&s.contract_id) {
                            button {
                                class: "btn btn-sm btn-outline",
                                onclick: {
                                    let target = s.clone();
                                    move |_| confirming.set(Some(target.clone()))
                                },
                                "Close\u{2026}"
                            }
                        }
                    }
                }
            }
            if let Some(name) = conflict.closing.clone() {
                p { class: "text-muted text-italic",
                    "Closing {name}\u{2026} The store you kept takes orders again once the network has the close."
                }
            } else if let Some(target) = confirming() {
                p {
                    strong { "Close {target.name} (code {target.code}) for good?" }
                    " This can\u{2019}t be undone. Buyers won\u{2019}t be able to buy from it \
                     again, and it can\u{2019}t be reopened or moved to another Ghost Key. Its \
                     listings and orders stay readable."
                }
                div { class: "form-actions",
                    button {
                        class: "btn btn-sm btn-danger",
                        onclick: {
                            let id = target.contract_id.clone();
                            move |_| {
                                let result = APP_STATE.write().close_store_for_good(&id);
                                if let Err(e) = result {
                                    APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!("Could not close the store: {e}"));
                                }
                                confirming.set(None);
                            }
                        },
                        "Close {target.name} for good"
                    }
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: move |_| confirming.set(None),
                        "Keep it"
                    }
                }
            } else if none_closable {
                p { class: "text-muted",
                    "This device doesn\u{2019}t hold the key to either store. Open Harvest on the \
                     device where you made one of them and close it there."
                }
            }
        }
    }
}

/// "1 listing", "3 orders".
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// The store the dashboard opens on: the one the seller opened from Stores
/// (`SellerPage::Store`), or the first. `stores` is never empty here.
pub(crate) fn dashboard_store<'a>(
    stores: &'a [SellerStore],
    page: &super::app::SellerPage,
) -> &'a SellerStore {
    match page {
        super::app::SellerPage::Store(id) => stores.iter().find(|s| &s.contract_id == id),
        _ => None,
    }
    .unwrap_or(&stores[0])
}

/// The store a send to the seller pages names, if it names one
/// (`SellerPage::Store`): the dashboard moves to it, on its Overview.
pub(crate) fn seller_page_target(page: &super::app::SellerPage) -> Option<Vec<u8>> {
    match page {
        super::app::SellerPage::Store(id) => Some(id.clone()),
        _ => None,
    }
}

/// The seller's dashboard: one store at a time, titled by its name, with a
/// switcher when there is more than one (entity model, wireframe C).
#[component]
fn StoreDashboard(stores: Vec<SellerStore>) -> Element {
    // Pinned to the store first shown, so a store arriving later, or a name
    // arriving that reorders the list, does not switch the page under the
    // seller (and remount it, losing an open form). The store first shown is
    // the one the seller opened from Stores, if they opened one.
    let mut selected = use_signal(|| {
        Some(
            dashboard_store(&stores, &super::app::SELLER_PAGE.peek())
                .contract_id
                .clone(),
        )
    });
    #[allow(unused_mut)]
    let mut tab = use_signal(|| Tab::Overview);
    // And moved to a store sent here while the pages are already open (the
    // header's "needs you" pill, "Back to managing it"): each such send
    // writes `SELLER_PAGE`, which re-runs this, and lands on that store's
    // Overview, whose first card is "Needs you" (codex and skeptical on
    // #197 round 4: the pill did nothing on a seller page).
    use_effect(move || {
        if let Some(id) = seller_page_target(&super::app::SELLER_PAGE()) {
            selected.set(Some(id));
            tab.set(Tab::Overview);
        }
    });
    let store = selected()
        .and_then(|id| stores.iter().find(|s| s.contract_id == id).cloned())
        .unwrap_or_else(|| stores[0].clone());

    // Counts what needs the seller, not everything there is: a request
    // waiting for an invoice, or a paid order waiting to be sent. Never an
    // unpaid Buy now.
    let orders_needs = store.needs_you();

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
                // No count: beside the Orders tab's, which is what needs the
                // seller, a total read as one too (critique C-1).
                (Tab::Listings, "Listings".to_string()),
                (Tab::Orders, "Orders".to_string()),
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
                    // What needs the seller, in the one colour that means
                    // it, so it does not read as a count of orders beside
                    // "Listings (n)" (critique S9-10).
                    if t == Tab::Orders && orders_needs > 0 {
                        " "
                        span { class: "tab-needs", "({orders_needs})" }
                    }
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
            }
        }
        }
    }
}

/// The page of My store that is showing, for one store.
#[component]
fn StoreBody(store: SellerStore, tab: Signal<Tab>) -> Element {
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
                // Orders first: the tab is named for them, and the buyers'
                // messages under them can run to many screens (the
                // 2026-09-30 critique found the orders ~9,700px down).
                Tab::Orders => rsx! {
                    super::invoice_form::StorePayments {
                        store_contract_id: store.contract_id.clone(),
                        seller_fingerprint: store.fingerprint.clone(),
                    }
                    super::message_view::MessageView { store_contract_id: store.contract_id.clone() }
                },
                Tab::Settings => rsx! {
                    Settings { store: store.clone(), editing_details }
                },
            }
        }
    }
}

/// Said when a buyer paid an address past a run of 20 unused ones, which a
/// wallet with the usual gap limit does not look at (Ian's wording,
/// 2026-09-26).
pub(crate) fn wallet_gap_note(limit: u32) -> String {
    if limit == u32::MAX {
        // More than a thousand unused addresses in a row: the count stops
        // there, so no figure is given that might fall short.
        return "Your wallet may not be showing all your payments. In your wallet's settings, \
                set the gap limit as high as it goes, well over 1000."
            .to_string();
    }
    format!(
        "Your wallet may not be showing all your payments. In your wallet's settings, set the \
         gap limit to {limit}."
    )
}

/// What needs the seller, what is left to set up, the link to share, and the
/// store's record (wireframe C).
#[component]
fn Overview(store: SellerStore, tab: Signal<Tab>, editing_details: Signal<bool>) -> Element {
    let has_wallet = APP_STATE.read().bitcoin.payment_xpub.is_some();
    let (buyers_see, complaint_lines) = {
        let state = APP_STATE.read();
        let loaded = state
            .browsing_stores
            .get(&store.contract_id)
            .filter(|b| b.info.is_some());
        let tip_of = |network| state.tip_height(network);
        (
            loaded.map(super::store_view::trust_line),
            loaded
                .map(|b| {
                    super::reputation_view::counted_complaint_lines(
                        b,
                        tip_of,
                        crate::state::now_ms(),
                    )
                })
                .unwrap_or_default(),
        )
    };
    let wallet_known = APP_STATE.read().bitcoin.payment_xpub_loaded;
    let details_done = store.details_resolved && store.gap.is_none();
    let setup_done = details_done && has_wallet && store.listings > 0;
    let mut go = move |t: Tab| tab.set(t);

    // ONE status, saying what happens to a buyer (`presence_flow::
    // seller_status`). Only for a store that sells here.
    let status = {
        let state = APP_STATE.read();
        let now = crate::state::now_ms();
        state
            .instant_checkout_local(&store.contract_id, now)
            .map(|local| {
                crate::presence_flow::seller_status(
                    state.store_presence(&store.contract_id, now),
                    state.wakeups_seen_recently(now),
                    &local,
                )
            })
    };
    let alerts = APP_STATE.read().instant_checkout_alerts(&store.contract_id);
    // The paid orders to send, each on its own card with Mark as sent: the
    // same list the count and the Orders tab use (`orders_to_send`).
    let to_send = APP_STATE
        .read()
        .seller_orders_to_send(&store.contract_id, &store.fingerprint);

    let wallet_gap = APP_STATE.read().wallet_gap_note_due(&store.contract_id);
    let needs = overview_needs(&store, &APP_STATE.read());

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
            if store.closed {
                p { class: "text-muted",
                    "This store is closed for good. Buyers can\u{2019}t buy from it, and its orders \
                     stay here for you to read."
                }
            } else if let Some(conflict) = store.key_conflict.clone() {
                // One Ghost Key behind two stores (harvest#181): said to the
                // seller in their terms, with the way out.
                KeyBacksTwoStores { conflict }
            } else if store.details_resolved && !store.certificate.is_verified() {
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
            if let Some(limit) = wallet_gap {
                p { class: "text-warning", "{wallet_gap_note(limit)}" }
            }
            if store.unpriced > 0 {
                div { class: "need row-between",
                    span {
                        if store.unpriced == 1 {
                            "1 listing can\u{2019}t be bought until you give it a price. Use Edit to give it one."
                        } else {
                            "{store.unpriced} listings can\u{2019}t be bought until you give them a price. Use Edit to give each one a price."
                        }
                    }
                    button { class: "btn btn-sm btn-outline", onclick: move |_| go(Tab::Listings), "Open listings" }
                }
            }
            if store.to_confirm > 0 {
                div { class: "need row-between",
                    strong {
                        if store.to_confirm == 1 {
                            "1 payment needs you to confirm which order it is for."
                        } else {
                            "{store.to_confirm} payments need you to confirm which order each is for."
                        }
                    }
                    button { class: "btn btn-sm btn-primary", onclick: move |_| go(Tab::Orders), "Open orders" }
                }
            }
            // Each paid order to send is its own card here, with what to
            // pack, where, by when, and Mark as sent: no trip to Orders and
            // no hunt through messages for the address (the 2026-09-27
            // friction report).
            for order in to_send.iter() {
                super::invoice_form::SellerOrderCard {
                    key: "{order.order.id}",
                    store_contract_id: store.contract_id.clone(),
                    order: order.clone(),
                }
            }
            for alert in alerts.iter() {
                p { class: "text-warning", "{alert}" }
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
                            "1 unpaid invoice is too old for a buyer to start paying. Cancel it under Orders; the buyer can order again."
                        } else {
                            "{store.expired_invoices} unpaid invoices are too old for a buyer to start paying. Cancel them under Orders; the buyers can order again."
                        }
                    }
                    button { class: "btn btn-sm btn-outline", onclick: move |_| go(Tab::Orders), "Open orders" }
                }
            }
            if !needs && store.details_resolved {
                p { class: "text-muted", "Nothing needs you right now." }
            }
        }

        if let Some(status) = status {
            section { class: "card",
                div { class: "row-between",
                    h3 { "Your store" }
                    span { class: if status.open { "pill pill-open" } else { "pill" }, "{status.pill}" }
                }
                p { "{status.line}" }
                if let Some(why) = status.why_not {
                    p { class: "text-muted", "{why}" }
                }
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
            // Content-sized values with Copy, as on the pay card: the whole
            // link is visible (it wraps), where the old one-line field showed
            // only its first 80 or so characters and scrolled.
            if let Some(ref code) = store.code {
                super::pay_card::CopyField {
                    label: "Store code",
                    value: code.clone(),
                    salt: "share".to_string(),
                }
            }
            if let Some(ref link) = store.link {
                super::pay_card::CopyField {
                    label: "Link",
                    value: link.clone(),
                    salt: "share".to_string(),
                }
            }
            p { class: "text-muted small",
                "Anyone can open this link, with or without Freenet: it offers to open your "
                "store in Freenet or straight in their browser. Buyers can also type the store "
                "code into Stores."
            }
        }

        section { class: "card",
            h3 { "Your record" }
            // What buyers read, from the same function the store page says it
            // with, and each complaint that counts (critique 09-8).
            if let Some(ref buyers_see) = buyers_see {
                p { class: "text-muted small", "Buyers see: {buyers_see}" }
            } else {
                p { "{store.record}" }
            }
            // The latest few, and how many more (round 4 of #197).
            for line in complaint_lines.iter().rev().take(COMPLAINTS_SHOWN) {
                p { "Complaint: {line}" }
            }
            if complaint_lines.len() > COMPLAINTS_SHOWN {
                p { class: "text-muted small",
                    "and {complaint_lines.len() - COMPLAINTS_SHOWN} more, on your store\u{2019}s record"
                }
            }
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

/// How many complaints the seller's record card lists before "and n more".
const COMPLAINTS_SHOWN: usize = 3;

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

/// Store details, payout wallet and the Ghost Key behind the store
/// (wireframe E). Opening another store is its own page (`AnotherStore`).
#[component]
fn Settings(store: SellerStore, editing_details: Signal<bool>) -> Element {
    let buyers_see = APP_STATE
        .read()
        .browsing_stores
        .get(&store.contract_id)
        .filter(|b| b.info.is_some())
        .map(super::store_view::trust_line);
    let identity = APP_STATE
        .read()
        .ghostkeys
        .iter()
        .find(|k| k.fingerprint == store.fingerprint)
        .cloned();
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
            // Where a seller checks the Bitcoin side when payments seem slow
            // to show; it used to sit in every visitor's footer.
            button {
                class: "link-btn",
                onclick: move |_| *super::app::ROUTE.write() = super::app::Route::Diagnostics,
                "Check Harvest\u{2019}s connection to Bitcoin"
            }
        }

        section { class: "card",
            h3 { "Backed by" }
            if let Some(ref identity) = identity {
                p {
                    "{ghost_key_name(identity)} \u{00b7} {describe_notary_info(&identity.notary_info)}"
                }
            }
            // What buyers read on the store page, from the same function, so
            // this cannot say something else again (critique 12-2).
            // Said once the store's state is here, and only then with why it
            // matters (round 4 of #197: the second line sat alone while it
            // loaded, its "this" pointing at nothing).
            if let Some(ref buyers_see) = buyers_see {
                p { class: if store.certificate.is_verified() { "text-muted small" } else { "text-warning" },
                    "Buyers see: {buyers_see}. It is how they judge what you have at stake."
                }
            }
        }

    }
}

/// What tells one of the seller's stores from another across its
/// generations: its code, which a migration keeps
/// (`AppState::adopt_migrated_contract_id` changes the contract id, round 2
/// of #197), or its id if it has no code.
fn store_identity(store: &SellerStore) -> String {
    store
        .code
        .clone()
        .unwrap_or_else(|| bs58::encode(&store.contract_id).into_string())
}

/// The store in `now` whose identity (`store_identity`) was not in
/// `before`: one just opened, not one that moved to a new generation.
pub(crate) fn new_store(before: &[String], now: &[(String, Vec<u8>)]) -> Option<Vec<u8>> {
    now.iter()
        .find(|(identity, _)| !before.contains(identity))
        .map(|(_, id)| id.clone())
}

/// Opening another store: each connected Ghost Key that has no store here
/// can open one (or move one made before revision 2), and another key can
/// be connected. Its own page, reached from "Open another store" on Stores
/// (critique S12-10: it used to sit at the bottom of one store's Settings).
#[component]
fn AnotherStore(has_harvest_delegate: bool) -> Element {
    let (others, in_flight, busy) = {
        let state = APP_STATE.read();
        // Connected Ghost Keys with no store this device can manage: each can
        // open one, or move one made before revision 2.
        let others: Vec<ghostkey_common::GhostKeyInfo> = state
            .ghostkeys
            .iter()
            .filter(|k| state.signable_store_for(&k.fingerprint).is_none())
            .cloned()
            .collect();
        // A key whose creation is under way stays open when the seller comes
        // back to this page, so its progress and Cancel are not hidden.
        let busy: Vec<String> = state.store_creation_in_flight.iter().cloned().collect();
        (others, state.request_any_access_in_flight, busy)
    };
    let mut other_open = use_signal(|| Option::<String>::None);
    // The stores this device manages as the page opened. One that appears
    // after is the store just opened here, and the seller is taken to it
    // rather than left on this page with its row gone (review of #197).
    let before: Signal<Vec<String>> = use_signal(|| {
        seller_stores(&APP_STATE.peek())
            .iter()
            .map(store_identity)
            .collect()
    });
    use_effect(move || {
        let now: Vec<(String, Vec<u8>)> = seller_stores(&APP_STATE.read())
            .into_iter()
            .map(|s| (store_identity(&s), s.contract_id))
            .collect();
        if let Some(new) = new_store(&before.peek(), &now) {
            super::app::open_seller_page(super::app::SellerPage::Store(new));
        }
    });

    // Which Ghost Key backs which store already (mockup C4).
    let backed = {
        let state = APP_STATE.read();
        let backings: Vec<Backing> = seller_stores(&state)
            .into_iter()
            .map(|store| Backing {
                key: state
                    .ghostkeys
                    .iter()
                    .find(|k| k.fingerprint == store.fingerprint)
                    .map(ghost_key_name)
                    .unwrap_or_else(|| {
                        format!("Ghost Key {}", short_fingerprint(&store.fingerprint))
                    }),
                store: state
                    .store_name_of(&store.contract_id)
                    .name()
                    .map(str::to_string),
                fingerprint: store.fingerprint,
            })
            .collect();
        already_backs(&backings)
    };

    rsx! {
        // A rule, said as one where it applies (critique 14-2), with who
        // backs what.
        p { "Each store needs its own Ghost Key. {backed}" }
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
        // What the button does, and the way to get a key for someone who
        // has none, up front (critique 14-1, mockup C4).
        div { class: "form-actions",
            button {
                class: "btn btn-primary",
                disabled: in_flight,
                onclick: move |_| connect_ghostkey(),
                if in_flight { "Waiting for the vault\u{2026}" } else { "Use a Ghost Key I have" }
            }
            a {
                class: "link-btn",
                href: "{ghost_key_create_url()}",
                target: "_blank",
                rel: "noopener noreferrer",
                "Get another Ghost Key \u{2197}"
            }
        }
        GhostKeyAccessNote { link: false }
        p { class: "text-muted small",
            "A new store starts with its own name, link and an empty record."
        }
    }
}

/// One store of the seller's, and the Ghost Key behind it, for
/// [`already_backs`].
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Backing {
    /// Which Ghost Key: two with one name are still two keys.
    pub fingerprint: String,
    /// What the key is called (`ghost_key_name`, or its short fingerprint).
    pub key: String,
    /// The store's name, `None` while it is loading.
    pub store: Option<String>,
}

/// What each Ghost Key already backs, one sentence per key, grouped by the
/// key itself (round 4 of #197: grouped by name, two unknown keys merged into
/// one). "Alice already backs Pots." A key backing several stores (harvest#181,
/// which should not happen) is said as it is, without "already", so it does
/// not read as the rule it breaks: "Alice backs Pots and Cups." A store still
/// loading is "one of your stores", never "Loading…".
pub(crate) fn already_backs(backings: &[Backing]) -> String {
    let mut keys: Vec<(&str, &str, Vec<Option<&str>>)> = Vec::new();
    for backing in backings {
        match keys
            .iter_mut()
            .find(|(fp, _, _)| *fp == backing.fingerprint)
        {
            Some((_, _, stores)) => stores.push(backing.store.as_deref()),
            None => keys.push((
                &backing.fingerprint,
                &backing.key,
                vec![backing.store.as_deref()],
            )),
        }
    }
    let and_list = |items: Vec<String>| match items.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    keys.into_iter()
        .map(|(_, key, stores)| {
            let named: Vec<String> = stores.iter().flatten().map(|s| s.to_string()).collect();
            let loading = stores.iter().filter(|s| s.is_none()).count();
            let mut items = named.clone();
            match (named.is_empty(), loading) {
                (_, 0) => {}
                (true, 1) => items.push("one of your stores".to_string()),
                (true, n) => items.push(format!("{n} of your stores")),
                (false, 1) => items.push("one more store".to_string()),
                (false, n) => items.push(format!("{n} more stores")),
            }
            let verb = if stores.len() == 1 {
                "already backs"
            } else {
                "backs"
            };
            format!("{key} {verb} {}.", and_list(items))
        })
        .collect::<Vec<_>>()
        .join(" ")
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
                    class: "form-input field-name",
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
fn initiate_store_creation(_fingerprint: String, _details: StoreDetails) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let details = _details;

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
        // Gated again here: the form may have been opened under an earlier
        // answer (harvest#181).
        let started =
            APP_STATE
                .write()
                .begin_own_store_creation(fingerprint.clone(), vk_bytes, details);
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
        // The gate again, as for "Create store" (harvest#181).
        let gate = APP_STATE
            .read()
            .store_creation_gate(&fingerprint, &vk_bytes);
        if !matches!(
            gate,
            crate::index_flow::CreationGate::Ready | crate::index_flow::CreationGate::Unconfirmed
        ) {
            APP_STATE.write().notifications.push(format!(
                "Could not move the store: {}",
                crate::backing_flow::STILL_CHECKING_GHOST_KEY
            ));
            return;
        }
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
        // the same store key back (#98 review, M1). Never as a deliberate
        // second store: a Ghost Key backs one store at a time (section 6.2,
        // harvest#181), and the delegate refuses a second one on this device.
        for request in [harvest_common::HarvestDelegateRequest::CreateStoreKey {
            request_id: store_key_request,
            ghostkey_fingerprint: Some(fingerprint.clone()),
            another_store: false,
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

/// A Ghost Key's fingerprint, short: enough to tell one of the seller's
/// keys from another, not a key id to read out (critique 12-2).
fn short_fingerprint(fp: &str) -> String {
    match fp.char_indices().nth(6) {
        Some((cut, _)) => format!("{}\u{2026}", &fp[..cut]),
        None => fp.to_string(),
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
        // The one on show has no sats price (a quote-only listing from
        // before every listing had one); the one taken down is not counted.
        // Mutated red by dropping the price filter and the `Withdrawn`
        // filter.
        assert_eq!(stores[0].unpriced, 1);
        assert_eq!(stores[0].requests, 0);
        assert!(stores[0].code.is_some() && stores[0].link.is_some());
        assert_eq!(requests_needing_seller(&state), 0);
    }

    /// Every item the Overview's "Needs you" card can list makes a store's
    /// card on Stores say so (`overview_needs`, shared by both), and a store
    /// still loading is not flagged for what it has not read yet. Red if
    /// any branch is dropped. (The wallet-gap and instant-checkout alerts
    /// come from the delegate's status and are read, not set up here.)
    #[test]
    fn overview_needs_covers_every_item_the_needs_you_card_lists() {
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![registration(1, Some(crate::state::test_store_key()))],
        );
        let mut base = seller_stores(&state).remove(0);
        // A store whose details and backing have been read and hold nothing
        // to do.
        base.details_resolved = true;
        base.gap = None;
        base.certificate = crate::ghostkey_cert::CertificateStatus::Verified;
        assert!(!overview_needs(&base, &state), "nothing to do");

        type Change = fn(&mut SellerStore);
        let cases: [(&str, Change); 10] = [
            ("a request", |s| s.requests = 1),
            ("an order to send", |s| s.to_send = 1),
            ("a payment to confirm", |s| s.to_confirm = 1),
            ("an unpriced listing", |s| s.unpriced = 1),
            ("an expired invoice", |s| s.expired_invoices = 1),
            ("another key on the address", |s| {
                s.foreign_owner = Some("taken".into())
            }),
            ("details to repair", |s| {
                s.gap = Some(StoreDetailsGap::NoName)
            }),
            ("an unbacked store", |s| {
                s.certificate = crate::ghostkey_cert::CertificateStatus::Absent
            }),
            ("a backing that does not check out", |s| {
                s.certificate = crate::ghostkey_cert::CertificateStatus::Invalid("x".into())
            }),
            ("one Ghost Key behind two stores", |s| {
                let store = crate::closure_flow::SharingStore {
                    contract_id: vec![9; 32],
                    name: "Bean Shop".into(),
                    code: "abc".into(),
                    listings: 0,
                    orders: 0,
                    can_close: true,
                };
                s.key_conflict = Some(crate::closure_flow::KeyConflict {
                    this: store.clone(),
                    others: vec![store],
                    closing: None,
                })
            }),
        ];
        for (what, change) in cases {
            let mut store = base.clone();
            change(&mut store);
            assert!(overview_needs(&store, &state), "{what}");
        }

        // Until the store's details have been read, its certificate reads
        // Absent by default and its gap is unknown: neither is something
        // to do yet, as the Overview itself does not list them (so a card
        // does not say "Needs you" for every store still loading).
        let mut loading = base.clone();
        loading.details_resolved = false;
        loading.certificate = crate::ghostkey_cert::CertificateStatus::Absent;
        loading.gap = Some(StoreDetailsGap::NeverPublished);
        assert!(!overview_needs(&loading, &state));

        // A store closed for good has given up its backing, so "unbacked"
        // is how it should read, not something to do (harvest#181).
        let mut closed = base.clone();
        closed.closed = true;
        closed.certificate = crate::ghostkey_cert::CertificateStatus::Absent;
        assert!(!overview_needs(&closed, &state));
    }

    /// The header's "needs you" pill goes to the first store something
    /// needs the seller at, and the seller pages move to it even when they
    /// are already open on another store (`seller_page_target`, read by
    /// `StoreDashboard`'s effect). Red with a store needing nothing chosen.
    #[test]
    fn the_needs_you_pill_goes_to_the_store_that_needs_the_seller() {
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![
                registration(1, Some(crate::state::test_store_key())),
                registration(2, Some(crate::state::test_store_key())),
            ],
        );
        assert_eq!(first_store_needing_seller(&state), None, "nothing waits");
        let order = AuthorizedOrder {
            order: Order {
                request_id: Some([7; 32]),
                id: OrderId([7; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: "fp".into(),
                amount_sats: 1,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: vec![7],
                payment_address: String::new(),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: None,
                listing_tag: None,
                buyer_receipt_key: None,
                created_at: chrono::DateTime::UNIX_EPOCH,
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        };
        // A payment for the seller to confirm, at the second store.
        state
            .withheld_settlements
            .insert(OrderId([7; 32]), (vec![2u8; 32], order));
        assert_eq!(first_store_needing_seller(&state), Some(vec![2u8; 32]));
        assert_eq!(requests_needing_seller(&state), 1);

        use super::super::app::SellerPage;
        assert_eq!(
            seller_page_target(&SellerPage::Store(vec![2u8; 32])),
            Some(vec![2u8; 32])
        );
        assert_eq!(seller_page_target(&SellerPage::First), None);
        assert_eq!(seller_page_target(&SellerPage::AnotherStore), None);
    }

    /// "Open another store" says which Ghost Key backs which store, in one
    /// sentence, and a Ghost Key is named short, never by its whole id.
    #[test]
    fn the_open_another_store_page_says_who_backs_what() {
        let b = |fp: &str, key: &str, store: Option<&str>| Backing {
            fingerprint: fp.to_string(),
            key: key.to_string(),
            store: store.map(str::to_string),
        };
        assert_eq!(already_backs(&[]), "");
        assert_eq!(
            already_backs(&[b("a", "Alice", Some("Pots"))]),
            "Alice already backs Pots."
        );
        assert_eq!(
            already_backs(&[b("a", "Alice", Some("Pots")), b("b", "Bob", Some("Wool"))]),
            "Alice already backs Pots. Bob already backs Wool."
        );
        // Two keys that read alike are still two keys. Red grouping by name.
        assert_eq!(
            already_backs(&[
                b("x1", "Ghost Key", Some("Pots")),
                b("x2", "Ghost Key", Some("Wool"))
            ]),
            "Ghost Key already backs Pots. Ghost Key already backs Wool."
        );
        // One key behind two stores (harvest#181): said as it is, not as the
        // rule.
        assert_eq!(
            already_backs(&[b("a", "Alice", Some("Pots")), b("a", "Alice", Some("Cups"))]),
            "Alice backs Pots and Cups."
        );
        // Never "Loading…".
        assert_eq!(
            already_backs(&[b("a", "Alice", None)]),
            "Alice already backs one of your stores."
        );
        assert_eq!(
            already_backs(&[b("a", "Alice", Some("Pots")), b("a", "Alice", None)]),
            "Alice backs Pots and one more store."
        );
        assert_eq!(short_fingerprint("XpmTN6FBHAmQ9"), "XpmTN6\u{2026}");
        assert_eq!(short_fingerprint("Xpm"), "Xpm");
    }

    /// The store that appears after "Open another store" was pressed is
    /// the one just opened.
    #[test]
    fn the_store_just_opened_is_the_new_one() {
        let before = vec!["CodeA".to_string()];
        assert_eq!(new_store(&before, &[("CodeA".into(), vec![1u8; 32])]), None);
        // The same store moved to a new generation (a new contract id, the
        // same code) is not a new store. Red comparing contract ids.
        assert_eq!(new_store(&before, &[("CodeA".into(), vec![9u8; 32])]), None);
        assert_eq!(
            new_store(
                &before,
                &[
                    ("CodeA".into(), vec![1u8; 32]),
                    ("CodeB".into(), vec![2u8; 32])
                ]
            ),
            Some(vec![2u8; 32])
        );
    }

    /// An own store is named by its name, "Loading…" until it arrives, and
    /// never by its code (the 2026-09-30 Stores page); its card on Stores
    /// opens the seller pages on that store. Red with the old
    /// `store_label`, which fell back to "Store <code>".
    #[test]
    fn an_own_store_is_never_named_by_its_code_and_its_card_opens_it() {
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![
                registration(1, Some(crate::state::test_store_key())),
                registration(2, Some(crate::state::test_store_key())),
            ],
        );
        let stores = seller_stores(&state);
        assert_eq!(stores.len(), 2);
        for store in &stores {
            assert_eq!(store.label, "Loading\u{2026}");
            let code = store.code.as_deref().expect("a code");
            assert!(!store.label.contains(code));
        }
        state.store_state_unavailable.insert(vec![2u8; 32]);
        let stores = seller_stores(&state);
        let given_up = stores
            .iter()
            .find(|s| s.contract_id == vec![2u8; 32])
            .unwrap();
        assert_eq!(given_up.label, "Your store");

        use super::super::app::SellerPage;
        assert_eq!(
            dashboard_store(&stores, &SellerPage::Store(vec![2u8; 32])).contract_id,
            vec![2u8; 32],
            "the store whose card was pressed"
        );
        assert_eq!(
            dashboard_store(&stores, &SellerPage::First).contract_id,
            stores[0].contract_id
        );
        assert_eq!(
            dashboard_store(&stores, &SellerPage::Store(vec![9u8; 32])).contract_id,
            stores[0].contract_id,
            "a store no longer here falls back to the first"
        );
    }

    /// Paid orders waiting to be sent are what a Buy now first needs the
    /// seller for; only this seller's, and only at that stage. Mutated red by
    /// dropping each filter.
    #[test]
    fn paid_orders_to_send_are_counted() {
        use crate::fulfilment::OrderStage;
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
        let order = |seller: &str, n: u8| AuthorizedOrder {
            order: Order {
                request_id: Some([n; 32]),
                id: OrderId([n; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: seller.into(),
                amount_sats: 1,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: vec![n],
                payment_address: String::new(),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: None,
                listing_tag: None,
                buyer_receipt_key: None,
                created_at: chrono::DateTime::UNIX_EPOCH,
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: OrderStatus::Paid,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        };
        let orders = vec![
            order("fp", 1),
            order("fp", 2),
            order("other", 3),
            order("fp", 4),
            order("fp", 5),
        ];
        let stage = |o: &AuthorizedOrder| match o.order.id.0[0] {
            // Paid, but this node cannot place it against the chain yet: it
            // still needs sending (review of #190).
            5 => OrderStage::Unknown,
            1 | 3 => OrderStage::AwaitingDespatch {
                paid_at: 1,
                despatch_by: 2,
            },
            4 => OrderStage::DespatchWindowClosed {
                despatch_by: 2,
                complaint_until: 3,
            },
            _ => OrderStage::Despatched {
                despatched_at: 1,
                complaint_until: 2,
            },
        };
        assert_eq!(
            orders_to_send(&orders, "fp", stage, |_| false).len(),
            3,
            "overdue and not-yet-placed paid orders still count"
        );
        // One whose despatch is on record never counts, whatever its stage
        // (round 2 of #190: an Unknown stage is decided before the despatch
        // is read).
        assert_eq!(
            orders_to_send(&orders, "fp", stage, |o| o.order.id.0[0] == 5).len(),
            2
        );
    }

    /// The wallet-gap note is shown on the store it happened at, not on
    /// every store of the device. Mutated red by answering for any store.
    #[test]
    fn the_wallet_gap_note_is_per_store() {
        let mut state = AppState::default();
        let status = |gap: Option<u64>| harvest_common::delegate::AutoInvoiceStatus {
            armed_at_ms: 0,
            watched_remaining: 1,
            invoicing_until_ms: 0,
            last_background_run_ms: None,
            issued_last_day: 0,
            oversold: vec![],
            paused: None,
            wallet_gap_paid_at_ms: gap,
            wallet_gap_limit: 100,
            capped: None,
            last_wakeup_ms: None,
            watch_delegation: None,
        };
        state
            .auto_invoice
            .status
            .insert(vec![1; 32], Ok(status(Some(5))));
        state
            .auto_invoice
            .status
            .insert(vec![2; 32], Ok(status(None)));
        assert_eq!(state.wallet_gap_note_due(&[1; 32]), Some(100));
        assert_eq!(state.wallet_gap_note_due(&[2; 32]), None);
        assert_eq!(state.wallet_gap_note_due(&[3; 32]), None);
        assert!(wallet_gap_note(u32::MAX).contains("as high as it goes"));
        assert_eq!(
            wallet_gap_note(100),
            "Your wallet may not be showing all your payments. In your wallet's settings, set \
             the gap limit to 100."
        );
    }
}
