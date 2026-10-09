//! Which component draws each page (the IA's sitemap, `router::Page`).

use dioxus::prelude::*;

use super::router::Page;

/// The body of `page`, keyed by its fragment, so going from one order's page
/// to another's starts the second afresh (no form or open step carries over).
pub(crate) fn page_body(page: Page) -> Element {
    let key = page.fragment();
    let body = match page {
        Page::Stores => rsx! { super::store_view::StoresPage {} },
        Page::Store { store, tab } => rsx! { super::store_view::StorePage { store, tab } },
        Page::Item { store, listing } => rsx! { super::store_view::ItemPage { store, listing } },
        Page::Purchases => rsx! { super::purchases_view::PurchasesPage {} },
        Page::PurchaseMessages => rsx! { super::purchases_view::PurchaseMessagesPage {} },
        Page::Backup => rsx! { super::purchases_view::BackupPage {} },
        Page::Order { at, order } => rsx! { super::buyer_order::BuyerOrderPage { at, order } },
        Page::Report { at, order } => rsx! { super::buyer_order::ReportPage { at, order } },
        Page::Conversation { store, tag } => {
            rsx! { super::buyer_conversation::BuyerConversationPage { store, tag } }
        }
        Page::OpenStore { another } => rsx! { super::open_store::OpenStore { another } },
        Page::Seller { store, view } => rsx! { super::seller_pages::SellerPages { store, view } },
        Page::Diagnostics => rsx! { super::bitcoin_view::BitcoinView {} },
    };
    rsx! {
        for body in std::iter::once(body) {
            div { key: "{key}", class: "page", {body} }
        }
    }
}
