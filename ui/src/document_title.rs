//! Document title management for the Freenet gateway iframe.
//!
//! Since Harvest runs inside the gateway's sandboxed iframe,
//! document.setTitle() only sets the iframe's title. To update
//! the browser tab title, we postMessage to the parent shell.

use std::cell::RefCell;

const APP_NAME: &str = "Harvest";

thread_local! {
    static LAST_TITLE: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Set the document title, notifying the parent Freenet shell via postMessage.
pub fn set_title(title: &str) {
    // Everything below is wasm32-only; on the host build the parameter is
    // genuinely unused, and CI lints with -D warnings.
    #[cfg(not(target_arch = "wasm32"))]
    let _ = title;

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::prelude::*;

        if let Some(window) = web_sys::window() {
            if let Some(document) = window.document() {
                document.set_title(title);
            }

            // Only postMessage if the title changed
            let changed = LAST_TITLE.with(|last| {
                let mut last = last.borrow_mut();
                if *last == title {
                    return false;
                }
                last.clear();
                last.push_str(title);
                true
            });

            if changed {
                let msg = js_sys::Object::new();
                let _ = js_sys::Reflect::set(
                    &msg,
                    &JsValue::from_str("__freenet_shell__"),
                    &JsValue::TRUE,
                );
                let _ = js_sys::Reflect::set(
                    &msg,
                    &JsValue::from_str("type"),
                    &JsValue::from_str("title"),
                );
                let _ = js_sys::Reflect::set(
                    &msg,
                    &JsValue::from_str("title"),
                    &JsValue::from_str(title),
                );
                let target = window.parent().ok().flatten().unwrap_or(window);
                let _ = target.post_message(&msg, "*");
            }
        }
    }
}

/// Set the title to just the app name.
pub fn set_default_title() {
    set_title(APP_NAME);
}

/// Set the title to include a store name.
pub fn set_store_title(store_name: &str) {
    set_title(&format!("{APP_NAME} - {store_name}"));
}
