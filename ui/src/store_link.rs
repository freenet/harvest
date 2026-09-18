//! Opening a store from a shared link, and building the link to share.
//!
//! Harvest has no discovery: a buyer reaches a seller's store because the
//! seller sent them a link (docs/design.md, "No built-in discovery").
//!
//! # What the link carries: a store CODE (harvest#52)
//!
//! `#store=<code>`, where the code is the first twelve base58 characters of
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
//! # What the rest of the link is (the part that must work on ANOTHER node)
//!
//! Harvest is served by the node the reader is running, at
//! `http://<that node>/v1/contract/web/<Harvest's contract id>/`. The seller's
//! page URL names the SELLER's node -- `http://127.0.0.1:7651/...` in the
//! screenshot that found this (harvest#79) -- and a buyer who opens that on
//! their own machine reaches their own loopback on the seller's port, which
//! is nothing, or someone else's service.
//!
//! So the shared link is not built from the page URL at all. It is
//! [`PORTABLE_BASE`] -- `127.0.0.1:7509`, the port every Freenet node listens
//! on by default, and the form the rest of the ecosystem hands out (`fdev`
//! prints it after a publish, and freenet.org's River invite button uses it)
//! -- plus Harvest's own web container id, which is the same on every node.
//! A buyer whose node runs on the default port opens the link and lands in
//! Harvest on their own node. A buyer on another port has the code itself,
//! which the seller's page shows beside the link and the Browse tab accepts.
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

/// The node address a shared link is built on: every Freenet node's default
/// HTTP port on loopback. See the module docs for why not the page's own.
pub const PORTABLE_BASE: &str = "http://127.0.0.1:7509";

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

/// Parse a code the user typed or pasted: the bare code, or a whole link.
///
/// Surrounding whitespace is forgiven, since a code read out of a message
/// usually brings some with it. Nothing else is: a code of the wrong length
/// opens nothing.
pub fn parse_typed_store_code(typed: &str) -> Option<StoreParameters> {
    let typed = typed.trim();
    if let Some(params) = StoreParameters::from_code(typed) {
        return Some(params);
    }
    let fragment = typed.split_once('#').map(|(_, f)| f);
    let query = typed
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(q));
    fragment
        .and_then(parse_store_code)
        .or_else(|| query.and_then(parse_store_code))
}

/// The link a seller shares for the store `code` opens: Harvest on the
/// reader's own node, with the code in the fragment.
///
/// Built from [`PORTABLE_BASE`] and Harvest's web container id, never from
/// the seller's page URL. That URL names the seller's node and port, and
/// inside the shell's iframe it also carries `__sandbox=1`, which makes a
/// node serve the raw contract HTML with no shell, no bridge and no
/// websocket -- a dead page for the buyer. Neither belongs in a link handed
/// to somebody else.
pub fn share_link(code: &str) -> String {
    format!(
        "{PORTABLE_BASE}/v1/contract/web/{}/#{STORE_PARAM}={code}",
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
/// Remembering the store does need the harvest delegate, so that is queued
/// and sent once the delegate is registered (`AppState::remember_store`).
#[cfg(target_arch = "wasm32")]
pub fn open_store_from_url() {
    let Some(location) = web_sys::window().map(|window| window.location()) else {
        return;
    };
    let hash = location.hash().unwrap_or_default();
    let search = location.search().unwrap_or_default();
    let Some(params) = parse_store_code(&hash).or_else(|| parse_store_code(&search)) else {
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
        state.note_store_code(store_id.as_bytes().to_vec(), code.clone());
        state.remember_store(&code);
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
        assert!(parse_store_code(&format!("#store={}", &code[..11])).is_none());
        assert!(parse_store_code(&format!("#store={code}x")).is_none());
        let old_style = bs58::encode([5u8; 32]).into_string();
        assert!(parse_store_code(&format!("#store={old_style}")).is_none());
        assert!(parse_store_code(&format!("#store={}", "1".repeat(100_000))).is_none());
    }

    #[test]
    fn a_shared_link_parses_back_to_the_same_store() {
        let code = code();
        let link = share_link(&code);
        let fragment = link.split_once('#').expect("link should have a fragment").1;
        assert_eq!(
            parse_store_code(fragment).map(|p| p.code().to_string()),
            Some(code)
        );
    }

    /// harvest#79: the link must work on the BUYER's node. It is built from
    /// the default node address and Harvest's own contract id, and nothing
    /// from the seller's page -- not their port, not the `__sandbox=1` the
    /// shell's iframe URL carries.
    #[test]
    fn a_shared_link_names_harvest_on_the_default_node_and_nothing_of_the_sellers() {
        let code = code();
        assert_eq!(
            share_link(&code),
            format!(
                "http://127.0.0.1:7509/v1/contract/web/{}/#store={code}",
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
            )
        );
        assert!(!share_link(&code).contains("__sandbox"));
        assert!(!share_link(&code).contains('?'));
    }

    #[test]
    fn a_typed_code_or_a_pasted_link_both_open_the_store() {
        let code = code();
        for typed in [
            code.clone(),
            format!("  {code}\n"),
            share_link(&code),
            format!("http://127.0.0.1:7651/v1/contract/web/x/?store={code}"),
            format!("http://127.0.0.1:7651/v1/contract/web/x/?__sandbox=1#store={code}"),
        ] {
            assert_eq!(
                parse_typed_store_code(&typed).map(|p| p.code().to_string()),
                Some(code.clone()),
                "{typed:?}"
            );
        }
        for typed in ["", &code[..11], "http://127.0.0.1:7509/", "#store=short"] {
            assert!(parse_typed_store_code(typed).is_none(), "{typed:?}");
        }
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
