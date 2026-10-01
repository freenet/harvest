//! Opening a store (page structure S1): from nothing to a named store, one
//! step at a time. The payout wallet and the first listing come after, from
//! the store's Home checklist.

use dioxus::prelude::*;

use super::my_store::{
    connect_ghostkey, ghost_key_create_url, seller_stores, AnotherStore, FirstStore,
    GhostKeyAccessNote, GHOST_KEY_VAULT_PATH,
};
use super::router::{go, Page, SellerView};
use crate::gateway::APP_STATE;

/// S1. `another`: a seller with a store opening one more. Until this node
/// knows which stores are its own (after a reload, the store lists arrive
/// late) it says it is checking: a store of the seller's arriving then must
/// not be taken for one just opened here (review of #214).
#[component]
pub(crate) fn OpenStore(another: bool) -> Element {
    super::seller_pages::use_known_clock();
    let known = APP_STATE
        .read()
        .seller_known_or_waited(crate::state::now_ms());
    if !known {
        return rsx! {
            super::seller_pages::BackTo { label: "Stores".to_string(), page: Page::Stores }
            p { class: "text-muted text-italic", "Checking your stores\u{2026}" }
        };
    }
    rsx! {
        OpenStoreSteps { another }
    }
}

#[component]
fn OpenStoreSteps(another: bool) -> Element {
    let (ghostkeys, in_flight, has_harvest_delegate, stores) = {
        let state = APP_STATE.read();
        (
            state.ghostkeys.clone(),
            state.request_any_access_in_flight,
            state.harvest_delegate_key.is_some(),
            seller_stores(&state),
        )
    };
    // The store that appears while this page is open is the one just made:
    // the seller is taken to its Home, where the rest of setting up is.
    let before = use_signal(|| {
        seller_stores(&APP_STATE.peek())
            .iter()
            .map(|s| s.contract_id.clone())
            .collect::<Vec<_>>()
    });
    use_effect(move || {
        let now = seller_stores(&APP_STATE.read());
        if let Some(new) = now
            .iter()
            .find(|s| !before.peek().contains(&s.contract_id))
            .filter(|_| !another)
        {
            go(Page::Seller {
                store: Some(new.contract_id.clone()),
                view: SellerView::Home,
            });
        }
    });

    if another && !stores.is_empty() {
        return rsx! {
            super::seller_pages::BackTo { label: "Stores".to_string(), page: Page::Stores }
            h2 { class: "page-h", "Open another store" }
            AnotherStore { has_harvest_delegate }
        };
    }
    let have_key = !ghostkeys.is_empty();
    rsx! {
        super::seller_pages::BackTo { label: "Stores".to_string(), page: Page::Stores }
        h2 { class: "page-h", "Open a store" }
        p { class: "lede",
            "Payments go straight to your own wallet. No fees, no account, and no company can shut \
             your store down."
        }
        ol { class: "open-steps",
            li { class: if have_key { "done" } else { "current" },
                p { class: "step-head", "Get a Ghost Key" }
                p { class: "text-muted small",
                    "A one-off donation to Freenet, from $1. Buyers see that your store is backed by it."
                }
                if !have_key {
                    a {
                        class: "link-btn",
                        href: "{ghost_key_create_url()}",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        "Get one at freenet.org \u{2197}"
                    }
                }
            }
            li { class: if have_key { "done" } else { "current" },
                p { class: "step-head", "Let Harvest use it" }
                if !have_key {
                    p { class: "text-muted small",
                        "Freenet asks you which Ghost Key Harvest may use. "
                        "Have one saved in a file? Import it in your "
                        a {
                            href: "{GHOST_KEY_VAULT_PATH}",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            "Ghost Key vault"
                        }
                        " first."
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: in_flight,
                        onclick: move |_| connect_ghostkey(),
                        if in_flight { "Waiting for the vault\u{2026}" } else { "Choose a Ghost Key" }
                    }
                    GhostKeyAccessNote {}
                }
            }
            li { class: if have_key { "current" } else { "" },
                p { class: "step-head", "Name your store" }
                if have_key {
                    FirstStore { ghostkeys, has_harvest_delegate }
                } else {
                    p { class: "text-muted small", "Its name, and one line about what you sell." }
                }
            }
        }
        p { class: "text-muted small",
            "Next, from your store\u{2019}s Home: add a payout wallet, add a listing, share your link."
        }
        p { class: "text-muted small",
            "Only buying? You don\u{2019}t need any of this. "
            button { class: "link-btn", onclick: move |_| go(Page::Stores), "Back to Stores" }
        }
    }
}
