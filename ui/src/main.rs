// Gateway module items are only used in WASM builds; native cargo check
// reports them as unused, which is expected.
#![allow(dead_code, unused_imports)]

mod components;
mod document_title;
mod gateway;
mod ghostkey_cert;
mod messaging;
mod migrate;
mod state;
mod store_link;

fn main() {
    dioxus::logger::initialize_default();

    // Make wasm panics say what they were.
    //
    // Without a hook, a Rust panic compiled to wasm surfaces in the browser as
    // a bare `Uncaught RuntimeError: unreachable` with a stack of raw wasm
    // offsets and NO message -- the panic's own text, file and line are
    // discarded before anything can print them. That is not a small
    // inconvenience: it is the difference between a bug report that names its
    // cause and one that can only be guessed at.
    //
    // Observed 2026-09-06: the first ghostkey a user connected panicked the UI
    // immediately after the vault answered, and the console showed four
    // identical `unreachable` traces and nothing else. The migration path it
    // panicked in had never executed before -- it is wasm-only, so no test had
    // ever run it -- which is exactly the code most likely to panic and least
    // likely to explain itself.
    //
    // `initialize_default()` above sets up tracing, not a panic hook, so this
    // is not redundant with it. Routed through `tracing::error!` rather than
    // `console_error_panic_hook` so it needs no new dependency and lands in the
    // same log stream as everything else the app reports.
    #[cfg(target_arch = "wasm32")]
    std::panic::set_hook(Box::new(|info| {
        dioxus::logger::tracing::error!("PANIC: {info}");
    }));

    dioxus::launch(components::App);
}
