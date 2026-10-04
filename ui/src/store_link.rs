//! Opening a store from a shared link, and building the link to share.
//!
//! Harvest has no discovery: a buyer reaches a seller's store because the
//! seller sent them a link (docs/design.md, "No built-in discovery").
//!
//! # What the link carries: a store CODE (harvest#52)
//!
//! `#store=<code>`, where the code is the first sixteen base58 characters of
//! the seller's verifying key. The code is the store contract's only
//! parameter, so any client turns it into the store's address with nothing
//! but the store contract it bundles -- no registry, no lookup, no round trip
//! (see [`crate::gateway::store_ops::store_instance_id`]). It used to be the
//! 44-character contract id.
//!
//! A code of any other length opens nothing. Not a truncation, not a padding:
//! a different length is a different address, and a typo in a shared link
//! should open nothing rather than something else.
//!
//! # What the rest of the link is (the part that must work for ANYONE)
//!
//! The link is Freenet's one share-link form (freenet.org/open, the Share
//! Links page of the Freenet manual, spec on freenet-core#5726):
//! `https://freenet.org/open#<Harvest's contract id>/#store=<code>`.
//!
//! That page is static and reads everything after its own `#` in the
//! reader's browser, so freenet.org never learns which store is opened. It
//! offers to open the target on the reader's own node, on try.freenet.org
//! with nothing to install, or through the `freenet:` handler, and it links
//! to the install guide for someone who has none of those. Each route lands
//! on `/v1/contract/web/<Harvest's contract id>/#store=<code>`, which
//! [`open_store_from_url`] reads as before.
//!
//! The link is still not built from the page URL. That URL names the
//! seller's own node and port -- `http://127.0.0.1:7651/...` in the
//! screenshot that found this (harvest#79) -- and inside the shell's iframe
//! it also carries `__sandbox=1`. Harvest's web container id is the same on
//! every node, so the link names nothing of the seller's.
//!
//! The link it replaced, `http://127.0.0.1:7509/...`, opened only for a
//! reader already running Freenet on the default port, and was a dead end
//! for every other buyer (the 2026-09-27 friction report). A pasted link of
//! that older form still opens the store (see [`parse_typed_store_code`]).
//!
//! # Why the fragment
//!
//! Freenet's web server normalizes webapp URLs -- a missing trailing slash is
//! redirected. Browsers carry a fragment across a redirect on their own; a
//! query string survives only if the server deliberately re-attaches it. And
//! the query string of the page Harvest runs in already carries `__sandbox=1`,
//! which a shared link must not (see [`share_link`]).
//!
//! An earlier version of this comment also said a fragment keeps the store
//! out of "the gateway's" access log. For the normal deployment that was not
//! a real property: the webapp is served by the reader's own node on
//! loopback, and a Freenet gateway is a UDP bootstrap peer that never sees an
//! HTTP URL. It holds only for a remote HTTP front end such as a hosted
//! proxy, which is a narrow case rather than a general one (harvest#52).
//!
//! A query string is still *accepted* on the way in, because a hand-written or
//! hand-edited `?store=...` is an easy mistake to make and there's no reason
//! to punish it.

use harvest_common::store::StoreParameters;

/// The parameter naming the store to open.
const STORE_PARAM: &str = "store";

/// Freenet's share page, which every shared link goes through. See the module
/// docs for why not the page's own address.
pub const SHARE_PAGE: &str = "https://freenet.org/open";

/// How long a linked store has to arrive before the user is told it could not
/// be opened. `get_contract` reports only failures to *send* the GET; one that
/// errors in the network, or that names a contract nobody holds, produces no
/// response at all, so a timeout is the only thing that ever ends the Browse
/// tab's "Loading store..." message.
///
/// Shared with `state::subscribe_to_own_store`, which needs the same
/// deadline for the same reason: a store whose state never arrives has to
/// become a known fact eventually, or "still loading" and "nothing there"
/// stay indistinguishable forever.
#[cfg(target_arch = "wasm32")]
pub(crate) const LINK_LOAD_TIMEOUT_MS: u32 = 30_000;

/// Look up `name` in an `a=1&b=2` parameter string, tolerating the leading
/// `#` or `?` that `location.hash()` / `location.search()` include.
fn param<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.trim_start_matches(['#', '?'])
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })
}

/// Parse the store code out of a URL fragment or query string.
///
/// `None` for anything that is not exactly a store code -- see
/// [`StoreParameters::from_code`], which is the one place that decides.
pub fn parse_store_code(raw: &str) -> Option<StoreParameters> {
    StoreParameters::from_code(param(raw, STORE_PARAM)?)
}

/// What a buyer is told when their link names a store the old way.
pub const OLD_FORMAT_LINK_MESSAGE: &str = "This is an old-format store link, from before \
    Harvest used store codes, and it cannot be opened any more. Ask the seller for \
    their store code, or a new link.";

/// Whether `raw` names a store the way links did before harvest#52: a whole
/// 32-byte contract id (43 or 44 base58 characters) rather than a code.
///
/// Such a link opens nothing -- the address it names is not one this build
/// derives from a link, and a store has moved generation since it was made
/// -- so it is recognised only to say so, rather than leaving the buyer on a
/// page that silently shows nothing.
pub fn is_old_format_link(raw: &str) -> bool {
    let Some(value) = param(raw, STORE_PARAM) else {
        return false;
    };
    // Checked before decoding: `bs58::decode` is quadratic in its input, and
    // a whole contract id is 43 or 44 characters, so nothing longer is worth
    // the work -- the bound the pre-#52 parser had for the same reason.
    (43..=44).contains(&value.len())
        && bs58::decode(value)
            .into_vec()
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// Parse a code the user typed or pasted: the bare code, or a whole link.
///
/// Surrounding whitespace is forgiven, since a code read out of a message
/// usually brings some with it. Nothing else is: a code of the wrong length
/// opens nothing.
///
/// Every fragment section of a pasted link is tried, not just the first: a
/// freenet.org/open link carries the store in a SECOND fragment
/// (`open#<id>/#store=<code>`), and a local link carries it in the first.
/// Fragments come before the query string, as for a followed link
/// ([`open_store_from_url`]).
pub fn parse_typed_store_code(typed: &str) -> Option<StoreParameters> {
    let typed = typed.trim();
    if let Some(params) = StoreParameters::from_code(typed) {
        return Some(params);
    }
    link_sections(typed).find_map(parse_store_code)
}

/// The parts of a pasted link a store could be named in, in the order they
/// are read: each `#` section (split again at any `?` inside it), then the
/// query string.
pub(crate) fn link_sections(typed: &str) -> impl Iterator<Item = &str> {
    let fragments = typed.split('#').skip(1).flat_map(|f| f.split('?'));
    let query = typed
        .split('#')
        .next()
        .and_then(|before| before.split_once('?'))
        .map(|(_, q)| q);
    fragments.chain(query)
}

/// The link a seller shares for the store `code` opens: Freenet's share page,
/// carrying Harvest's contract id and the store code in its fragment.
///
/// Built from [`SHARE_PAGE`] and Harvest's web container id, never from the
/// seller's page URL. That URL names the seller's node and port, and inside
/// the shell's iframe it also carries `__sandbox=1`, which makes a node serve
/// the raw contract HTML with no shell, no bridge and no websocket -- a dead
/// page for the buyer. Neither belongs in a link handed to somebody else.
pub fn share_link(code: &str) -> String {
    format!(
        "{SHARE_PAGE}#{}/#{STORE_PARAM}={code}",
        harvest_common::HARVEST_WEBAPP_CONTRACT_ID
    )
}

/// If this page was opened with a store link, start browsing that store.
///
/// Called once the websocket is up. It deliberately does not wait for the
/// delegates: fetching and subscribing to a store contract needs nothing from
/// them, and a buyer following a link has no reason to hold a ghostkey.
/// Remembering the store happens once its state has arrived, and needs the
/// harvest delegate, so it is queued until that is registered
/// (`AppState::remember_loaded_store`).
#[cfg(target_arch = "wasm32")]
pub fn open_store_from_url() {
    let Some(location) = web_sys::window().map(|window| window.location()) else {
        return;
    };
    let hash = location.hash().unwrap_or_default();
    let search = location.search().unwrap_or_default();
    let Some(params) = parse_store_code(&hash).or_else(|| parse_store_code(&search)) else {
        if is_old_format_link(&hash) || is_old_format_link(&search) {
            crate::components::show_old_format_link();
        }
        return;
    };
    // In place of the link's own fragment, so Back does not return to it.
    let Ok(store_id) = crate::gateway::store_ops::store_instance_id(&params) else {
        return;
    };
    crate::gateway::APP_STATE
        .write()
        .note_store_code(store_id.as_bytes().to_vec(), params.code().to_string());
    crate::components::router::replace(crate::components::router::Page::Store {
        store: store_id.as_bytes().to_vec(),
        tab: crate::components::router::StoreTab::Items,
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn open_store_from_url() {}

/// Open the store `params` names: show its page, fetch it, and remember it.
///
/// The one path for a followed link, a typed code and a row of the store
/// list, so all three resolve an address the same way, all three land on
/// the store's own page (`components::show_store`), and all three leave the
/// store remembered. Off wasm it does everything but the GET, so a test can
/// see where each lands.
pub fn open_store(params: StoreParameters) {
    use dioxus::prelude::WritableExt;

    let store_id = match crate::gateway::store_ops::store_instance_id(&params) {
        Ok(id) => id,
        Err(e) => {
            dioxus::logger::tracing::error!("Could not derive a store's address: {e}");
            return;
        }
    };
    let code = params.code().to_string();
    dioxus::logger::tracing::info!("Opening store {code} ({store_id})");
    // Remembered only once its state arrives (`AppState::
    // remember_loaded_store`), so a mistyped or unreachable code does not
    // stay in the list for good.
    crate::gateway::APP_STATE
        .write()
        .note_store_code(store_id.as_bytes().to_vec(), code);
    open_store_id(store_id);
}

/// Open the store with this address: show its page, which fetches it
/// (`components::app::load_store_for_page`, then [`fetch_store_id`]).
pub fn open_store_id(store_id: freenet_stdlib::prelude::ContractInstanceId) {
    crate::components::show_store(store_id.as_bytes().to_vec());
}

/// Fetch the store with this address with a subscription, giving up after
/// `LINK_LOAD_TIMEOUT_MS` so a page showing it never waits for good. For a
/// store whose code this node does not know, too. Called when a page that
/// shows the store opens (`components::app::load_store_for_page`).
pub fn fetch_store_id(store_id: freenet_stdlib::prelude::ContractInstanceId) {
    use dioxus::prelude::WritableExt;
    let contract_id = store_id.as_bytes().to_vec();
    // `false` when its GET is already out, with its own wait: only shown.
    let started = crate::gateway::APP_STATE
        .write()
        .begin_foreground_load(&contract_id);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = started;

    #[cfg(target_arch = "wasm32")]
    if started {
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = crate::gateway::get_contract(&store_id, true).await {
                let mut state = crate::gateway::APP_STATE.write();
                state.note_store_link_failed(
                    &contract_id,
                    &format!("Couldn't open that store: {e}"),
                );
                state.end_foreground_load(&contract_id);
                return;
            }

            // The GET is out. Nothing will report back if it dead-ends -- a
            // contract nobody holds simply never answers -- so give it a
            // deadline and say so if it passes.
            gloo_timers::future::TimeoutFuture::new(LINK_LOAD_TIMEOUT_MS).await;
            let mut state = crate::gateway::APP_STATE.write();
            state.note_store_link_failed(
                &contract_id,
                "That store didn't load. The code may be wrong, or the store may \
             not be reachable right now.",
            );
            state.end_foreground_load(&contract_id);
        });
    }
}

/// Load, in the background, every store this node remembers visiting that
/// is not loaded yet, so a page listing them can give each its own name
/// (the Stores page, `subscribe` false) or find this device's
/// conversations with it and follow its orders (Purchases, `subscribe`
/// true). `include_archived`: the ones removed from the list too, for when
/// they are being shown. Idempotent per store (`load_remembered_store`), and
/// cheap to call on every change of state.
pub fn load_visited_stores(include_archived: bool, subscribe: bool) {
    use dioxus::prelude::ReadableExt;
    let codes = crate::gateway::APP_STATE
        .read()
        .visited_store_codes(include_archived);
    for code in codes {
        load_remembered_store(&code, subscribe);
    }
}

/// Load a remembered store in the background without opening it (harvest#93
/// phase 2).
///
/// `subscribe` false (the Stores page's rows): one GET, no subscription, so
/// the row can show the store's name and whether it is open, and nothing
/// more is kept up (`AppState::light_stores`). `subscribe` true (Purchases):
/// a GET with a subscription, since a purchase's store has to stay current,
/// and what recalls this device's conversations with it; a store loaded
/// only for the list is loaded again this way.
///
/// Sent only when due (`AppState::background_load_due`). A GET that fails
/// to go out, or goes out and is never answered, is sent again on its own
/// timer after a growing wait, a few times, and the store reads as loading
/// until the last one gives up.
#[cfg(target_arch = "wasm32")]
pub fn load_remembered_store(code: &str, subscribe: bool) {
    use dioxus::prelude::WritableExt;

    let Some(params) = StoreParameters::from_code(code) else {
        return;
    };
    let Ok(store_id) = crate::gateway::store_ops::store_instance_id(&params) else {
        return;
    };
    let contract_id = store_id.as_bytes().to_vec();
    // Checked under a READ first: Stores and Purchases call this from an
    // effect that reads the app state, and a write, even one that changes
    // nothing, would re-run that effect for ever.
    {
        use dioxus::prelude::ReadableExt;
        if !crate::gateway::APP_STATE.read().background_load_due(
            &contract_id,
            crate::state::now_ms(),
            subscribe,
        ) {
            return;
        }
    }
    if !crate::gateway::APP_STATE.write().begin_background_load(
        contract_id.clone(),
        code.to_string(),
        subscribe,
    ) {
        return;
    }
    let code = code.to_string();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::get_contract(&store_id, subscribe).await {
            dioxus::logger::tracing::warn!("Could not load a remembered store: {e}");
            crate::gateway::APP_STATE
                .write()
                .end_background_load_failed(&contract_id);
        } else {
            gloo_timers::future::TimeoutFuture::new(LINK_LOAD_TIMEOUT_MS).await;
            crate::gateway::APP_STATE
                .write()
                .end_background_load_timed_out(&contract_id);
        }
        // Sent again on its own timer: the pages ask only when the state
        // changes, and nothing may change when the wait is over (codex on
        // #197). `None` once it has arrived or has no tries left, and not
        // for a store taken off the list meanwhile.
        let retry = {
            use dioxus::prelude::ReadableExt;
            let state = crate::gateway::APP_STATE.read();
            state
                .visited_store_codes(false)
                .contains(&code)
                .then(|| state.background_retry_after(&contract_id))
                .flatten()
        };
        if let Some(wait) = retry {
            // A little past the wait, so the check it meets is not a
            // millisecond early.
            let wait = wait.saturating_add(250).min(u64::from(u32::MAX)) as u32;
            gloo_timers::future::TimeoutFuture::new(wait).await;
            load_remembered_store(&code, subscribe);
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn load_remembered_store(_code: &str, _subscribe: bool) {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn code() -> String {
        StoreParameters::new(SigningKey::from_bytes(&[7u8; 32]).verifying_key())
            .code()
            .to_string()
    }

    #[test]
    fn parses_a_fragment_link() {
        let code = code();
        let parsed = parse_store_code(&format!("#store={code}")).expect("should parse");
        assert_eq!(parsed.code(), code);
    }

    #[test]
    fn parses_a_query_string_link() {
        let code = code();
        let parsed = parse_store_code(&format!("?store={code}")).expect("should parse");
        assert_eq!(parsed.code(), code);
    }

    #[test]
    fn finds_the_store_among_other_parameters() {
        let code = code();
        let parsed =
            parse_store_code(&format!("#tab=browse&store={code}&x=1")).expect("should parse");
        assert_eq!(parsed.code(), code);
    }

    #[test]
    fn ignores_a_url_with_no_store_parameter() {
        assert!(parse_store_code("").is_none());
        assert!(parse_store_code("#").is_none());
        assert!(parse_store_code("#tab=browse").is_none());
        assert!(parse_store_code("#store").is_none());
    }

    #[test]
    fn rejects_a_code_that_is_not_base58() {
        assert!(parse_store_code("#store=not a code at").is_none());
        assert!(parse_store_code("#store=0OIl0OIl0OIl").is_none());
    }

    /// A code of the wrong length must open nothing rather than a different
    /// store -- including the 44-character contract id the old links carried,
    /// which names an address this build no longer derives from a link.
    #[test]
    fn rejects_a_code_of_the_wrong_length() {
        let code = code();
        assert!(parse_store_code(&format!("#store={}", &code[..15])).is_none());
        assert!(parse_store_code(&format!("#store={code}x")).is_none());
        let old_style = bs58::encode([5u8; 32]).into_string();
        assert!(parse_store_code(&format!("#store={old_style}")).is_none());
        assert!(parse_store_code(&format!("#store={}", "1".repeat(100_000))).is_none());
    }

    #[test]
    fn a_shared_link_parses_back_to_the_same_store() {
        let code = code();
        assert_eq!(
            parse_typed_store_code(&share_link(&code)).map(|p| p.code().to_string()),
            Some(code)
        );
    }

    /// The link goes through freenet.org/open, in the form its spec gives
    /// (the Share Links page of the Freenet manual): Harvest's own contract
    /// id, then the store code in a second fragment. Nothing from the
    /// seller's page -- not their port, not the `__sandbox=1` the shell's
    /// iframe URL carries (harvest#79).
    #[test]
    fn a_shared_link_goes_through_the_share_page_and_names_nothing_of_the_sellers() {
        let code = code();
        assert_eq!(
            share_link(&code),
            format!(
                "https://freenet.org/open#{}/#store={code}",
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
            )
        );
        assert!(!share_link(&code).contains("__sandbox"));
        assert!(!share_link(&code).contains('?'));
        assert!(!share_link(&code).contains("127.0.0.1"));
    }

    /// What freenet.org/open hands on is the part after its own `#`, put
    /// after `/v1/contract/web/` on the reader's node (the spec's
    /// `local_path`). That lands on a page whose fragment is `#store=<code>`,
    /// which the page reads the way it always has.
    #[test]
    fn the_page_the_share_link_lands_on_opens_the_store() {
        let code = code();
        let link = share_link(&code);
        let target = link
            .strip_prefix("https://freenet.org/open#")
            .expect("the share page's own fragment");
        let local = format!("http://127.0.0.1:7509/v1/contract/web/{target}");
        let (_, fragment) = local.split_once('#').expect("the app's own fragment");
        assert_eq!(
            parse_store_code(&format!("#{fragment}")).map(|p| p.code().to_string()),
            Some(code)
        );
    }

    #[test]
    fn a_typed_code_or_a_pasted_link_both_open_the_store() {
        let code = code();
        for typed in [
            code.clone(),
            format!("  {code}\n"),
            share_link(&code),
            // The link Harvest shared before it went through freenet.org/open.
            format!(
                "http://127.0.0.1:7509/v1/contract/web/{}/#store={code}",
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
            ),
            format!("https://try.freenet.org/v1/contract/web/x/#store={code}"),
            format!("http://127.0.0.1:7651/v1/contract/web/x/?store={code}"),
            format!("http://127.0.0.1:7651/v1/contract/web/x/?__sandbox=1#store={code}"),
        ] {
            assert_eq!(
                parse_typed_store_code(&typed).map(|p| p.code().to_string()),
                Some(code.clone()),
                "{typed:?}"
            );
        }
        // A link naming a store in both places opens the fragment's, as a
        // followed link does.
        let other = bs58::encode([9u8; 32]).into_string()[..16].to_string();
        assert!(
            parse_typed_store_code(&other).is_some(),
            "a code on its own"
        );
        assert_eq!(
            parse_typed_store_code(&format!(
                "http://127.0.0.1:7651/v1/contract/web/x/?store={other}#store={code}"
            ))
            .map(|p| p.code().to_string()),
            Some(code.clone())
        );
        for typed in ["", &code[..15], "http://127.0.0.1:7509/", "#store=short"] {
            assert!(parse_typed_store_code(typed).is_none(), "{typed:?}");
        }
    }

    /// A link from before store codes is recognised, so the buyer is told
    /// to ask for a code instead of looking at a page that shows nothing;
    /// nothing else is mistaken for one.
    #[test]
    fn an_old_format_link_is_recognised_and_nothing_else_is() {
        let old = bs58::encode([5u8; 32]).into_string();
        assert!(is_old_format_link(&format!("#store={old}")));
        assert!(is_old_format_link(&format!("?x=1&store={old}")));
        assert!(!is_old_format_link(&format!("#store={}", code())));
        assert!(!is_old_format_link(&format!(
            "#store={}",
            &old[..old.len() - 2]
        )));
        assert!(!is_old_format_link(
            "#store=0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OI"
        ));
        assert!(!is_old_format_link(""));
        assert!(!is_old_format_link(&format!("#tab={old}")));
        // A long value is refused. That it is refused BEFORE decoding is a
        // cost bound, not an answer: without it the decode still says "not
        // 32 bytes", only later, so no assertion here can tell the two apart
        // except by timing, which is not worth a flaky test.
        assert!(!is_old_format_link(&format!(
            "#store={}",
            "z".repeat(50_000)
        )));
    }
}
