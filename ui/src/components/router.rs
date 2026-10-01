//! Which page is on screen, and its address in the URL fragment (the
//! 2026-10-01 page structure, "Harvest, page by page").
//!
//! Every page has its own fragment (`#/store/<id>/item/<listing>`, `#/sell/
//! <id>/orders`, ...), so the browser's Back works on every step and a page
//! can be reloaded or linked to. The page is held in [`PAGE`]; [`go`] changes
//! it, sets the iframe's fragment (a history entry, which is what Back walks)
//! and tells the gateway's shell, which puts the fragment on the top-level URL
//! so a reload lands on the same page. A Back or Forward fires `hashchange`
//! in the iframe, and [`follow_fragment`] puts the page it names on screen.
//!
//! A shared store link (`#store=<code>`, `store_link`) is not one of these:
//! it is read once at start and opens the store, whose page then takes the
//! fragment over.

use dioxus::prelude::*;
use harvest_common::listing::ListingId;
use harvest_common::payment::OrderId;

/// A store page's tabs (P2): what it sells, the whole description, its
/// record of complaints.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum StoreTab {
    #[default]
    Items,
    About,
    Record,
}

/// Where a buyer's order is read from: a store this device has loaded, or
/// only this node's kept copy (a store that cannot be reached, or one
/// re-keyed while its seller stays away), named by the store's key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum OrderAt {
    Store(Vec<u8>),
    Kept([u8; 32]),
}

/// The seller's orders, filtered by what has to happen next (S3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum OrderFilter {
    #[default]
    ToSend,
    Sent,
    Complete,
    All,
}

/// One of a seller's pages for one store (S2 to S9).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub(crate) enum SellerView {
    #[default]
    Home,
    Orders(OrderFilter),
    Order(OrderId),
    Messages,
    Conversation([u8; 32]),
    Listings,
    AddListing,
    EditListing(ListingId),
    Settings,
}

impl SellerView {
    /// The tab that reads as current on this page.
    pub(crate) fn tab(&self) -> SellerTab {
        match self {
            SellerView::Home => SellerTab::Home,
            SellerView::Orders(_) | SellerView::Order(_) => SellerTab::Orders,
            SellerView::Messages | SellerView::Conversation(_) => SellerTab::Messages,
            SellerView::Listings | SellerView::AddListing | SellerView::EditListing(_) => {
                SellerTab::Listings
            }
            SellerView::Settings => SellerTab::Settings,
        }
    }
}

/// The tabs under a seller's store header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SellerTab {
    Home,
    Orders,
    Messages,
    Listings,
    Settings,
}

impl SellerTab {
    pub(crate) const ALL: [SellerTab; 5] = [
        SellerTab::Home,
        SellerTab::Orders,
        SellerTab::Messages,
        SellerTab::Listings,
        SellerTab::Settings,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            SellerTab::Home => "Home",
            SellerTab::Orders => "Orders",
            SellerTab::Messages => "Messages",
            SellerTab::Listings => "Listings",
            SellerTab::Settings => "Settings",
        }
    }

    /// The page the tab opens.
    pub(crate) fn view(self) -> SellerView {
        match self {
            SellerTab::Home => SellerView::Home,
            SellerTab::Orders => SellerView::Orders(OrderFilter::ToSend),
            SellerTab::Messages => SellerView::Messages,
            SellerTab::Listings => SellerView::Listings,
            SellerTab::Settings => SellerView::Settings,
        }
    }
}

/// Every page (the IA's sitemap).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Page {
    /// P1: your stores, find a store, the stores you have visited.
    Stores,
    /// P2: a store as buyers see it.
    Store { store: Vec<u8>, tab: StoreTab },
    /// P3: one item, and the form to buy it.
    Item { store: Vec<u8>, listing: ListingId },
    /// P6: every order this device has placed.
    Purchases,
    /// P7: every conversation with a store.
    PurchaseMessages,
    /// P9: save and restore.
    Backup,
    /// P4: one of the buyer's orders.
    Order { at: OrderAt, order: OrderId },
    /// P5: the step to report a problem with one paid order.
    Report { at: OrderAt, order: OrderId },
    /// P8: the buyer's messages with one store: one conversation (`tag`),
    /// or (`None`) the one a new message would start or continue.
    Conversation {
        store: Vec<u8>,
        tag: Option<[u8; 32]>,
    },
    /// S1: opening a first store, or (`another`) another one.
    OpenStore { another: bool },
    /// S2 to S9: a seller's pages for one of their stores, or (`None`) for
    /// the first, or opening one when there is none.
    Seller {
        store: Option<Vec<u8>>,
        view: SellerView,
    },
    /// Harvest's connection to Bitcoin, reached from the footer.
    Diagnostics,
}

/// The two tabs in the header (decided 2026-09-29).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NavTab {
    Stores,
    Purchases,
}

impl Page {
    /// The header tab that reads as current: a store's pages and the
    /// seller's are reached from Stores; an order, a conversation and the
    /// backup from Purchases. `None` for the footer's diagnostics.
    pub(crate) fn nav_tab(&self) -> Option<NavTab> {
        match self {
            Page::Stores
            | Page::Store { .. }
            | Page::Item { .. }
            | Page::OpenStore { .. }
            | Page::Seller { .. } => Some(NavTab::Stores),
            Page::Purchases
            | Page::PurchaseMessages
            | Page::Backup
            | Page::Order { .. }
            | Page::Report { .. }
            | Page::Conversation { .. } => Some(NavTab::Purchases),
            Page::Diagnostics => None,
        }
    }

    /// The store whose state this page reads as a buyer, if any: opening the
    /// page asks for it if it is not here.
    pub(crate) fn buyer_store(&self) -> Option<&[u8]> {
        match self {
            Page::Store { store, .. }
            | Page::Item { store, .. }
            | Page::Conversation { store, .. } => Some(store),
            Page::Order {
                at: OrderAt::Store(store),
                ..
            }
            | Page::Report {
                at: OrderAt::Store(store),
                ..
            } => Some(store),
            _ => None,
        }
    }

    /// This page's fragment, `#/...`.
    pub(crate) fn fragment(&self) -> String {
        let b = |bytes: &[u8]| bs58::encode(bytes).into_string();
        let at = |at: &OrderAt| match at {
            OrderAt::Store(id) => format!("s/{}", b(id)),
            OrderAt::Kept(key) => format!("k/{}", b(key)),
        };
        let path = match self {
            Page::Stores => String::new(),
            Page::Store { store, tab } => match tab {
                StoreTab::Items => format!("store/{}", b(store)),
                StoreTab::About => format!("store/{}/about", b(store)),
                StoreTab::Record => format!("store/{}/record", b(store)),
            },
            Page::Item { store, listing } => format!("store/{}/item/{}", b(store), b(&listing.0)),
            Page::Purchases => "purchases".to_string(),
            Page::PurchaseMessages => "purchases/messages".to_string(),
            Page::Backup => "purchases/backup".to_string(),
            Page::Order { at: on, order } => format!("order/{}/{}", at(on), b(&order.0)),
            Page::Report { at: on, order } => format!("order/{}/{}/report", at(on), b(&order.0)),
            Page::Conversation { store, tag } => match tag {
                Some(tag) => format!("messages/{}/{}", b(store), b(tag)),
                None => format!("messages/{}", b(store)),
            },
            Page::OpenStore { another: false } => "open".to_string(),
            Page::OpenStore { another: true } => "open/another".to_string(),
            Page::Seller { store, view } => {
                let head = match store {
                    Some(id) => format!("sell/{}", b(id)),
                    None => "sell".to_string(),
                };
                let tail = match view {
                    SellerView::Home => String::new(),
                    SellerView::Orders(OrderFilter::ToSend) => "/orders".to_string(),
                    SellerView::Orders(OrderFilter::Sent) => "/orders/sent".to_string(),
                    SellerView::Orders(OrderFilter::Complete) => "/orders/complete".to_string(),
                    SellerView::Orders(OrderFilter::All) => "/orders/all".to_string(),
                    SellerView::Order(id) => format!("/order/{}", b(&id.0)),
                    SellerView::Messages => "/messages".to_string(),
                    SellerView::Conversation(tag) => format!("/messages/{}", b(tag)),
                    SellerView::Listings => "/listings".to_string(),
                    SellerView::AddListing => "/listings/new".to_string(),
                    SellerView::EditListing(id) => format!("/listings/{}", b(&id.0)),
                    SellerView::Settings => "/settings".to_string(),
                };
                // A seller page with no store named has no tail: it opens
                // the first store's Home.
                if store.is_none() {
                    head
                } else {
                    format!("{head}{tail}")
                }
            }
            Page::Diagnostics => "diagnostics".to_string(),
        };
        format!("#/{path}")
    }

    /// The page a fragment names, or `None` for one that is not a page's
    /// (a shared store link, `#store=...`, or nothing at all).
    pub(crate) fn from_fragment(fragment: &str) -> Option<Page> {
        let path = fragment.strip_prefix('#').unwrap_or(fragment);
        let path = path.strip_prefix('/')?;
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let bytes = |s: &str| bs58::decode(s).into_vec().ok().filter(|v| v.len() == 32);
        let arr = |s: &str| bytes(s).and_then(|v| <[u8; 32]>::try_from(v).ok());
        let order = |s: &str| arr(s).map(OrderId);
        let at = |kind: &str, s: &str| match kind {
            "s" => bytes(s).map(OrderAt::Store),
            "k" => arr(s).map(OrderAt::Kept),
            _ => None,
        };
        Some(match parts.as_slice() {
            [] => Page::Stores,
            ["store", id] => Page::Store {
                store: bytes(id)?,
                tab: StoreTab::Items,
            },
            ["store", id, "about"] => Page::Store {
                store: bytes(id)?,
                tab: StoreTab::About,
            },
            ["store", id, "record"] => Page::Store {
                store: bytes(id)?,
                tab: StoreTab::Record,
            },
            ["store", id, "item", listing] => Page::Item {
                store: bytes(id)?,
                listing: ListingId(arr(listing)?),
            },
            ["purchases"] => Page::Purchases,
            ["purchases", "messages"] => Page::PurchaseMessages,
            ["purchases", "backup"] => Page::Backup,
            ["order", kind, id, o] => Page::Order {
                at: at(kind, id)?,
                order: order(o)?,
            },
            ["order", kind, id, o, "report"] => Page::Report {
                at: at(kind, id)?,
                order: order(o)?,
            },
            ["messages", id] => Page::Conversation {
                store: bytes(id)?,
                tag: None,
            },
            ["messages", id, tag] => Page::Conversation {
                store: bytes(id)?,
                tag: Some(arr(tag)?),
            },
            ["open"] => Page::OpenStore { another: false },
            ["open", "another"] => Page::OpenStore { another: true },
            ["sell"] => Page::Seller {
                store: None,
                view: SellerView::Home,
            },
            ["sell", id, rest @ ..] => Page::Seller {
                store: Some(bytes(id)?),
                view: match rest {
                    [] => SellerView::Home,
                    ["orders"] => SellerView::Orders(OrderFilter::ToSend),
                    ["orders", "sent"] => SellerView::Orders(OrderFilter::Sent),
                    ["orders", "complete"] => SellerView::Orders(OrderFilter::Complete),
                    ["orders", "all"] => SellerView::Orders(OrderFilter::All),
                    ["order", o] => SellerView::Order(order(o)?),
                    ["messages"] => SellerView::Messages,
                    ["messages", tag] => SellerView::Conversation(arr(tag)?),
                    ["listings"] => SellerView::Listings,
                    ["listings", "new"] => SellerView::AddListing,
                    ["listings", l] => SellerView::EditListing(ListingId(arr(l)?)),
                    ["settings"] => SellerView::Settings,
                    _ => return None,
                },
            },
            ["diagnostics"] => Page::Diagnostics,
            _ => return None,
        })
    }
}

/// The page on screen: at start, the one the fragment names (a reload, or a
/// link to a page), else Stores. What the page needs from the network is
/// asked for once the websocket is up ([`start`]).
pub(crate) static PAGE: GlobalSignal<Page> =
    GlobalSignal::new(|| Page::from_fragment(&current_fragment()).unwrap_or(Page::Stores));

/// Once the websocket is up: if the fragment names a page, show it with what
/// it needs asked for (its store fetched, the store browsed) and return
/// `true`. `false` for anything else, a shared store link included, which
/// the caller opens.
pub(crate) fn start() -> bool {
    let Some(page) = Page::from_fragment(&current_fragment()) else {
        return false;
    };
    show(page);
    tell_shell(&current_fragment());
    true
}

/// Put `page` on screen: its fragment becomes a history entry, so Back
/// returns to the page before, and the shell is told, so a reload lands
/// here. Does nothing when `page` is already on screen.
pub(crate) fn go(page: Page) {
    if *PAGE.peek() == page {
        return;
    }
    let fragment = page.fragment();
    show(page);
    set_fragment(&fragment);
}

/// Put `page` on screen in place of the one there, leaving the history as
/// it is: for a page that stands in for another (a store link that opened
/// its store), where Back should not return to the one replaced.
pub(crate) fn replace(page: Page) {
    if *PAGE.peek() == page {
        return;
    }
    let fragment = page.fragment();
    show(page);
    replace_fragment(&fragment);
}

/// Show `page` without touching the fragment: what Back and Forward do, and
/// the first page at start.
fn show(page: Page) {
    // An empty id is the store page standing in for a link that named no
    // store it can open (`app::show_old_format_link`): nothing to ask for.
    if let Some(store) = page.buyer_store().filter(|store| !store.is_empty()) {
        let store = store.to_vec();
        // The store pages read the store being browsed
        // (`AppState::displayed_store`), so the page and the document title
        // agree on which one it is.
        if matches!(page, Page::Store { .. } | Page::Item { .. }) {
            crate::gateway::APP_STATE
                .write()
                .begin_browsing(store.clone());
        }
        super::app::load_store_for_page(&store);
    }
    *PAGE.write() = page;
    scroll_to_top();
}

/// Follow the iframe's fragment as it now reads (a Back, a Forward, or the
/// page's first load): show the page it names, if it names one and it is not
/// already on screen. Returns whether it named a page.
pub(crate) fn follow_fragment() -> bool {
    let Some(page) = Page::from_fragment(&current_fragment()) else {
        return false;
    };
    if *PAGE.peek() != page {
        show(page);
    }
    tell_shell(&current_fragment());
    true
}

fn current_fragment() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.location().hash().ok())
            .unwrap_or_default()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        String::new()
    }
}

fn set_fragment(fragment: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        if window.location().hash().ok().as_deref() != Some(fragment) {
            let _ = window.location().set_hash(fragment);
        }
    }
    tell_shell(fragment);
}

fn replace_fragment(fragment: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        // `location.replace` with only a new fragment navigates within the
        // document and replaces the current history entry.
        let href = window.location().href().unwrap_or_default();
        let base = href.split('#').next().unwrap_or_default().to_string();
        let _ = window.location().replace(&format!("{base}{fragment}"));
    }
    tell_shell(fragment);
}

/// Ask the gateway's shell to show `fragment` on the top-level URL (its
/// `hash` message, a `replaceState`), so a reload of the tab opens this
/// page. The shell takes only a fragment and adds no history of its own.
fn tell_shell(fragment: &str) {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = fragment;
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsValue;
        let Some(window) = web_sys::window() else {
            return;
        };
        let Some(parent) = window.parent().ok().flatten() else {
            return;
        };
        let msg = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &msg,
            &JsValue::from_str("__freenet_shell__"),
            &JsValue::TRUE,
        );
        let _ = js_sys::Reflect::set(&msg, &JsValue::from_str("type"), &JsValue::from_str("hash"));
        let _ = js_sys::Reflect::set(
            &msg,
            &JsValue::from_str("hash"),
            &JsValue::from_str(fragment),
        );
        // A sandboxed iframe does not know its parent's origin; the shell
        // checks the sender instead.
        let _ = parent.post_message(&msg, "*");
    }
}

/// Start following Back and Forward: a `hashchange` in the iframe shows the
/// page its new fragment names. Called once, when the app mounts.
pub(crate) fn listen_for_back() {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        let Some(window) = web_sys::window() else {
            return;
        };
        let on_change = Closure::<dyn FnMut()>::new(|| {
            follow_fragment();
        });
        if let Ok(add) = js_sys::Reflect::get(&window, &"addEventListener".into()) {
            if let Some(add) = add.dyn_ref::<js_sys::Function>() {
                let _ = add.call2(
                    &window,
                    &"hashchange".into(),
                    on_change.as_ref().unchecked_ref(),
                );
            }
        }
        // For the life of the page.
        on_change.forget();
    }
}

fn scroll_to_top() {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        use wasm_bindgen::JsCast;
        if let Ok(f) = js_sys::Reflect::get(&window, &"scrollTo".into()) {
            if let Some(f) = f.dyn_ref::<js_sys::Function>() {
                let _ = f.call2(&window, &0.into(), &0.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_page() -> Vec<Page> {
        let id = vec![7u8; 32];
        let order = OrderId([9u8; 32]);
        let mut pages = vec![
            Page::Stores,
            Page::Item {
                store: id.clone(),
                listing: ListingId([3u8; 32]),
            },
            Page::Purchases,
            Page::PurchaseMessages,
            Page::Backup,
            Page::Conversation {
                store: id.clone(),
                tag: None,
            },
            Page::Conversation {
                store: id.clone(),
                tag: Some([5u8; 32]),
            },
            Page::OpenStore { another: false },
            Page::OpenStore { another: true },
            Page::Seller {
                store: None,
                view: SellerView::Home,
            },
            Page::Diagnostics,
        ];
        for tab in [StoreTab::Items, StoreTab::About, StoreTab::Record] {
            pages.push(Page::Store {
                store: id.clone(),
                tab,
            });
        }
        for at in [OrderAt::Store(id.clone()), OrderAt::Kept([4u8; 32])] {
            pages.push(Page::Order {
                at: at.clone(),
                order: order.clone(),
            });
            pages.push(Page::Report {
                at,
                order: order.clone(),
            });
        }
        for view in [
            SellerView::Home,
            SellerView::Orders(OrderFilter::ToSend),
            SellerView::Orders(OrderFilter::Sent),
            SellerView::Orders(OrderFilter::Complete),
            SellerView::Orders(OrderFilter::All),
            SellerView::Order(order.clone()),
            SellerView::Messages,
            SellerView::Conversation([6u8; 32]),
            SellerView::Listings,
            SellerView::AddListing,
            SellerView::EditListing(ListingId([2u8; 32])),
            SellerView::Settings,
        ] {
            pages.push(Page::Seller {
                store: Some(id.clone()),
                view,
            });
        }
        pages
    }

    /// **Every page reads back from its own fragment**, so Back, a reload
    /// and a link all land on the page that was showing.
    #[test]
    fn every_page_round_trips_through_its_fragment() {
        for page in every_page() {
            let fragment = page.fragment();
            assert!(fragment.starts_with("#/"), "{fragment}");
            assert_eq!(
                Page::from_fragment(&fragment),
                Some(page.clone()),
                "{fragment}"
            );
        }
    }

    /// No two pages share a fragment.
    #[test]
    fn no_two_pages_share_a_fragment() {
        let pages = every_page();
        let fragments: std::collections::HashSet<String> =
            pages.iter().map(Page::fragment).collect();
        assert_eq!(fragments.len(), pages.len());
    }

    /// **A shared store link is not a page's fragment**: it is left to
    /// `store_link`, which opens the store it names.
    #[test]
    fn a_store_link_is_not_taken_for_a_page() {
        assert_eq!(Page::from_fragment("#store=Hyqno9kqmxYLezD1"), None);
        assert_eq!(Page::from_fragment(""), None);
        assert_eq!(Page::from_fragment("#"), None);
        assert_eq!(Page::from_fragment("#/store/not-base58!"), None);
        assert_eq!(Page::from_fragment("#/nowhere"), None);
        assert_eq!(Page::from_fragment("#/"), Some(Page::Stores));
    }
}
