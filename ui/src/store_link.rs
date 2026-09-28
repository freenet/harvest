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

/// The label shown beside a store's share link and in the store list.
///
/// Prefer the store's own name; fall back to its code, which is what the
/// seller hands out and what the buyer's link carries. The fallback is not a
/// rare path: a store's state may not have arrived yet.
pub fn store_label(code: &str, store_name: Option<&str>) -> String {
    match store_name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => name.to_string(),
        None => format!("Store {code}"),
    }
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
            use dioxus::prelude::WritableExt;
            crate::gateway::APP_STATE.write().note_old_format_link();
        }
        return;
    };
    open_store(params);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn open_store_from_url() {}

/// Open the store `params` names: browse it, fetch it, and remember it.
///
/// The one path for a followed link, a typed code and a row of the store
/// list, so all three resolve an address the same way and all three leave
/// the store remembered.
#[cfg(target_arch = "wasm32")]
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
    {
        let mut state = crate::gateway::APP_STATE.write();
        state.begin_browsing(store_id.as_bytes().to_vec());
        // Remembered only once its state arrives (`AppState::
        // remember_loaded_store`), so a mistyped or unreachable code does not
        // stay in the list for good.
        state.note_store_code(store_id.as_bytes().to_vec(), code.clone());
    }

    wasm_bindgen_futures::spawn_local(async move {
        let contract_id = store_id.as_bytes().to_vec();
        if let Err(e) = crate::gateway::get_contract(&store_id, true).await {
            crate::gateway::APP_STATE
                .write()
                .note_store_link_failed(&contract_id, &format!("Couldn't open that store: {e}"));
            return;
        }

        // The GET is out. Nothing will report back if it dead-ends -- a
        // contract nobody holds simply never answers -- so give it a
        // deadline and say so if it passes.
        gloo_timers::future::TimeoutFuture::new(LINK_LOAD_TIMEOUT_MS).await;
        crate::gateway::APP_STATE.write().note_store_link_failed(
            &contract_id,
            "That store didn't load. The code may be wrong, or the store may \
             not be reachable right now.",
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn open_store(_params: StoreParameters) {}

/// Load a remembered store in the background without opening it (harvest#93
/// phase 2): My purchases lists a store only once its state has arrived,
/// because that is what recalls this device's conversations with it.
///
/// A store already in `browsing_stores` (loaded, or its GET already out) is
/// left alone. The placeholder entry this adds is what says a GET is out, and
/// it is taken back out if the GET fails to send, so a later visit retries. A
/// GET that goes out and is never answered leaves the placeholder for the
/// session, which only means the store is not asked about again until reload.
#[cfg(target_arch = "wasm32")]
pub fn load_remembered_store(code: &str) {
    use dioxus::prelude::WritableExt;

    let Some(params) = StoreParameters::from_code(code) else {
        return;
    };
    let Ok(store_id) = crate::gateway::store_ops::store_instance_id(&params) else {
        return;
    };
    let contract_id = store_id.as_bytes().to_vec();
    // Checked under a READ first: My purchases calls this from an effect
    // that reads the app state, and a write, even one that changes nothing,
    // would re-run that effect for ever.
    {
        use dioxus::prelude::ReadableExt;
        if crate::gateway::APP_STATE
            .read()
            .browsing_stores
            .contains_key(&contract_id)
        {
            return;
        }
    }
    if !crate::gateway::APP_STATE
        .write()
        .begin_background_load(contract_id.clone(), code.to_string())
    {
        return;
    }
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::get_contract(&store_id, true).await {
            dioxus::logger::tracing::warn!("Could not load a remembered store: {e}");
            crate::gateway::APP_STATE
                .write()
                .end_background_load_failed(&contract_id);
            return;
        }
        gloo_timers::future::TimeoutFuture::new(LINK_LOAD_TIMEOUT_MS).await;
        crate::gateway::APP_STATE
            .write()
            .end_background_load_timed_out(&contract_id);
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn load_remembered_store(_code: &str) {}

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

    #[test]
    fn a_store_is_labelled_by_its_name_when_it_has_one() {
        assert_eq!(store_label(&code(), Some("Bean Shop")), "Bean Shop");
    }

    #[test]
    fn a_nameless_store_is_labelled_by_its_code() {
        let code = code();
        let label = store_label(&code, None);
        assert_eq!(label, format!("Store {code}"));
        assert_eq!(store_label(&code, Some("   ")), label);
        assert_eq!(store_label(&code, Some("")), label);
    }
}
