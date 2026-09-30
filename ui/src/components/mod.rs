mod app;
pub(crate) mod bitcoin_view;
pub(crate) mod buy_view;
mod invoice_form;
mod listing_form;
pub(crate) mod message_view;
pub(crate) mod my_store;
pub(crate) mod pay_card;
pub(crate) mod purchases_view;
pub(crate) mod reputation_view;
mod seller_listings;
mod store_view;

pub use app::App;
// Where opening a store lands (`store_link::open_store`).
pub(crate) use app::{show_old_format_link, show_store};
// Minting the seller's messaging key. Lives beside the store-creation flow
// that first needs it; `state` calls it again whenever a ghostkey connects.
pub(crate) use my_store::{ensure_encryption_key, mint_encryption_key};

/// Select all of the field that has focus: the readonly copy fields (a share
/// link, a payment address, a backup) call it on focus and on click, so one
/// tap selects the whole value ready to copy. A click alone only places a
/// caret, which left a buyer pressing Ctrl+A, Ctrl+C (the 2026-09-27 friction
/// report). Selection works in the gateway's sandboxed iframe, where the
/// clipboard API may not be available, so a Copy button is only ever an
/// addition that falls back to selecting (`pay_card`'s `CopyField`), never
/// a replacement.
pub(crate) fn select_focused_field() {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let Some(field) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.active_element())
        else {
            return;
        };
        select_all_of(&field);
    }
}

/// Select the whole of `field`: an input or textarea by its own `select`,
/// anything else (a `.copy-value` box) by selecting its contents.
#[cfg(target_arch = "wasm32")]
fn select_all_of(field: &web_sys::Element) {
    use wasm_bindgen::JsCast;
    let call = |target: &wasm_bindgen::JsValue, name: &str, arg: Option<&wasm_bindgen::JsValue>| {
        js_sys::Reflect::get(target, &name.into())
            .ok()
            .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
            .map(|f| match arg {
                Some(arg) => f.call1(target, arg),
                None => f.call0(target),
            })
    };
    // `select` exists on inputs and textareas, so it is looked up rather
    // than cast to either.
    if call(field, "select", None).is_some() {
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    if let Some(Ok(selection)) = call(&window, "getSelection", None) {
        let _ = call(&selection, "selectAllChildren", Some(field));
    }
}

/// Grow the focused text area to fit what is typed, for a field that starts
/// one line tall (`.grow-textarea`). Browsers that support CSS
/// `field-sizing: content` do this themselves; this covers the rest.
pub(crate) fn grow_focused_textarea() {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let Some(window) = web_sys::window() else {
            return;
        };
        // Only where the browser cannot size the field itself: a height set
        // here would pin what `field-sizing: content` keeps live.
        let supported = js_sys::Reflect::get(&window, &"CSS".into())
            .ok()
            .and_then(|css| {
                let supports = js_sys::Reflect::get(&css, &"supports".into())
                    .ok()?
                    .dyn_into::<js_sys::Function>()
                    .ok()?;
                supports
                    .call2(&css, &"field-sizing".into(), &"content".into())
                    .ok()?
                    .as_bool()
            })
            .unwrap_or(false);
        if supported {
            return;
        }
        let Some(field) = window.document().and_then(|d| d.active_element()) else {
            return;
        };
        // Looked up rather than typed, as in `select_all_of`: the style
        // object would need another web-sys feature.
        let Some(style) = js_sys::Reflect::get(&field, &"style".into()).ok() else {
            return;
        };
        let set_height = |value: &str| {
            if let Some(set) = js_sys::Reflect::get(&style, &"setProperty".into())
                .ok()
                .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
            {
                let _ = set.call2(&style, &"height".into(), &value.into());
            }
        };
        set_height("auto");
        let number = |name: &str| {
            js_sys::Reflect::get(&field, &name.into())
                .ok()
                .and_then(|h| h.as_f64())
                .unwrap_or(0.0)
        };
        let height = number("scrollHeight");
        if height > 0.0 {
            // Plus the borders, which scrollHeight leaves out and the
            // border-box height includes.
            let borders = (number("offsetHeight") - number("clientHeight")).max(0.0);
            set_height(&format!("{}px", height + borders));
        }
    }
}

/// Scroll the element with this id into view, once the render that opens
/// it has happened: a pointer on one card opening a conversation shown under
/// another (msg1 critique MSG-5, MSG-13). Called by name through
/// `Reflect`, as `select_field_by_id` calls `focus`, so no web-sys feature
/// is added for it. Does nothing where the element is not found.
pub(crate) fn scroll_to_id(id: String) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        use wasm_bindgen::JsCast;
        // After the state change that opens it has rendered.
        gloo_timers::future::TimeoutFuture::new(50).await;
        let Some(element) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(&id))
        else {
            return;
        };
        if let Ok(f) = js_sys::Reflect::get(&element, &"scrollIntoView".into()) {
            if let Some(f) = f.dyn_ref::<js_sys::Function>() {
                let _ = f.call0(&element);
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = id;
}

/// Focus and select all of the field with this `id`, for a Copy button the
/// clipboard refused.
pub(crate) fn select_field_by_id(id: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let Some(field) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(id))
        else {
            return;
        };
        if let Ok(f) = js_sys::Reflect::get(&field, &"focus".into()) {
            if let Some(f) = f.dyn_ref::<js_sys::Function>() {
                let _ = f.call0(&field);
            }
        }
        select_all_of(&field);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = id;
}

#[cfg(test)]
mod css_spacing_tests {
    //! `harvest.css` puts a margin between stacked siblings, and switches it
    //! off inside flex and grid containers, where `gap` does that job and a
    //! margin would push one item out of line. The switch-off names each
    //! container, so a container made flex later without being added there
    //! silently gets misaligned children. This keeps the list complete.

    const CSS: &str = include_str!("../../assets/harvest.css");

    fn strip_comments(css: &str) -> String {
        let mut out = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(start) = rest.find("/*") {
            out.push_str(&rest[..start]);
            // An unterminated comment would silently drop the rest of the
            // file, and every container in it, from the check.
            let end = rest[start + 2..]
                .find("*/")
                .expect("unterminated /* comment in harvest.css");
            rest = &rest[start + 2 + end + 2..];
        }
        out.push_str(rest);
        out
    }

    /// Every innermost `selectors { declarations }` rule, including those
    /// nested in `@media`.
    fn rules(css: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut prelude_start = 0;
        let mut open: Option<usize> = None;
        for (i, c) in css.char_indices() {
            match c {
                '{' => {
                    // A brace inside an open one: the outer was an `@media`
                    // prelude, a block of rules, and this rule's selectors
                    // start after it.
                    if let Some(o) = open {
                        prelude_start = o + 1;
                    }
                    open = Some(i);
                }
                '}' => {
                    if let Some(o) = open.take() {
                        let prelude = css[prelude_start..o].trim().to_string();
                        found.push((prelude, css[o + 1..i].to_string()));
                    }
                    prelude_start = i + 1;
                }
                _ => {}
            }
        }
        found
    }

    fn normalise(selector: &str) -> String {
        selector.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Top-level commas only: `:where(a, b) > *` is one selector.
    fn split_selectors(list: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (i, c) in list.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(normalise(&list[start..i]));
                    start = i + 1;
                }
                _ => {}
            }
        }
        out.push(normalise(&list[start..]));
        out
    }

    #[test]
    fn every_flex_or_grid_container_opts_out_of_sibling_margins() {
        let css = strip_comments(CSS);
        let rules = rules(&css);

        let opt_out = rules
            .iter()
            .find(|(prelude, body)| {
                prelude.starts_with(":where(")
                    && prelude.ends_with(") > *")
                    && body.contains("margin-top: 0;")
                    && body.contains("margin-left: 0;")
            })
            .expect("the flex/grid opt-out rule is missing from harvest.css");
        let inner = &opt_out.0[":where(".len()..opt_out.0.len() - ") > *".len()];
        let listed = split_selectors(inner);
        assert!(listed.len() > 10, "opt-out list parsed as {listed:?}");

        let mut missing = Vec::new();
        for (prelude, body) in &rules {
            let is_container = body.split(';').any(|decl| {
                // `display:flex`, `display : flex !important` and the like
                // all count.
                let Some((property, value)) = decl.split_once(':') else {
                    return false;
                };
                let value = value.replace("!important", "");
                property.trim() == "display"
                    && ["flex", "grid", "inline-flex", "inline-grid"].contains(&value.trim())
            });
            if !is_container {
                continue;
            }
            for selector in split_selectors(prelude) {
                if !listed.contains(&selector) {
                    missing.push(selector);
                }
            }
        }
        assert!(
            missing.is_empty(),
            "flex/grid containers not in harvest.css's sibling-margin opt-out: {missing:?}"
        );
    }

    /// A container made flex or grid by an inline `style:` in the markup is
    /// invisible to the check above, and its children would get the sibling
    /// margins on top of its gap. Use a class (`form-actions`, `row-between`,
    /// ...) instead.
    /// The 1-based lines of every `style:` attribute whose string makes its
    /// element a flex or grid container. Reads the whole string literal
    /// after `style:`, which may span lines.
    fn inline_flex_or_grid_lines(source: &str) -> Vec<usize> {
        let mut lines = Vec::new();
        for (at, _) in source.match_indices("style:") {
            // Only a literal value: `style: "..."` or `style: format!("...")`.
            // Anything else (a variable, a call) is skipped rather than read
            // from whatever string happens to come next in the file.
            let rest = source[at + "style:".len()..].trim_start();
            let Some(body) = rest
                .strip_prefix('"')
                .or_else(|| rest.strip_prefix("format!(\""))
            else {
                continue;
            };
            let mut end = body.len();
            let mut escaped = false;
            for (i, c) in body.char_indices() {
                match c {
                    '\\' if !escaped => escaped = true,
                    '"' if !escaped => {
                        end = i;
                        break;
                    }
                    _ => escaped = false,
                }
            }
            let value: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
            if value.split(';').any(|decl| {
                decl.split_once(':').is_some_and(|(property, v)| {
                    property == "display"
                        && ["flex", "grid", "inline-flex", "inline-grid"]
                            .contains(&v.replace("!important", "").as_str())
                })
            }) {
                lines.push(1 + source[..at].matches('\n').count());
            }
        }
        lines
    }

    #[test]
    fn the_inline_detector_fires_on_what_it_is_meant_to_catch() {
        // Guards the guard below, which has nothing live to fire on.
        let caught = "div { style: \"display: flex; gap: 8px;\",\n\
                      div { style: \"margin-top: 12px;\n   display:grid !important;\",\n\
                      div { style: format!(\"color: red; display: inline-flex\"),";
        // The second attribute's string spans two lines, so the third is on line 4.
        assert_eq!(inline_flex_or_grid_lines(caught), vec![1, 2, 4]);
        let ignored = "div { style: \"display: block; font-display: flex;\",\n\
                       p { style: \"font-size: 0.8rem;\", \"display: flex\" }\n\
                       div { style: computed_style, \"display: flex\" }";
        assert!(inline_flex_or_grid_lines(ignored).is_empty());
    }

    #[test]
    fn no_markup_makes_a_flex_or_grid_container_inline() {
        // Every component file, read at test time so a new one is covered.
        // This file is skipped: its own needles would match.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/components");
        let mut sources = Vec::new();
        for entry in std::fs::read_dir(dir).expect("components dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with(".rs") && name != "mod.rs" {
                sources.push((
                    name,
                    std::fs::read_to_string(&path).expect("read component"),
                ));
            }
        }
        assert!(
            sources.len() >= 10,
            "found only {} component files",
            sources.len()
        );
        let mut offending = Vec::new();
        for (file, source) in &sources {
            for line in inline_flex_or_grid_lines(source) {
                offending.push(format!("{file}:{line}"));
            }
        }
        assert!(
            offending.is_empty(),
            "inline flex/grid containers (give them a class in harvest.css instead): {offending:?}"
        );
    }

    #[test]
    fn the_parser_sees_the_containers_it_is_meant_to_check() {
        // Guards the guard: a parser that found no containers would pass the
        // test above vacuously.
        let css = strip_comments(CSS);
        let containers: Vec<String> = rules(&css)
            .into_iter()
            .filter(|(_, body)| body.contains("display: flex") || body.contains("display: grid"))
            .flat_map(|(prelude, _)| split_selectors(&prelude))
            .collect();
        for expected in [
            ".form-actions",
            ".row-between",
            ".share-row",
            ".checklist li",
        ] {
            assert!(
                containers.iter().any(|c| c == expected),
                "{expected} not seen; parsed {containers:?}"
            );
        }
    }
}
