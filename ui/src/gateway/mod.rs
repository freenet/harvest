//! Gateway connection layer for communicating with the Freenet node.
//!
//! Handles WebSocket connection, delegate registration, and contract operations.

pub mod bitcoin_address;
pub mod bitcoin_config;
#[cfg(target_arch = "wasm32")]
pub mod bitcoin_generation_ops;
pub mod bitcoin_ops;
mod connection;
mod delegate_api;
// Buyer -> seller messaging. The address derivation and the delta shape are
// pure and host-testable; only the send itself needs a browser.
pub mod index_ops;
pub mod mailbox_ops;
// Secret-free one-line descriptions of delegate traffic: the only way a
// response reaches a log (harvest#94).
pub mod log_summary;
// The call-site guard for `log_summary` (test-only; see its module docs).
#[cfg(test)]
mod log_scan;
// The migration probe's I/O half. wasm-only: it exists to drive the gateway's
// shared response handler, which has no native counterpart. Every decision it
// makes lives in `crate::migrate`, which is target-independent and tested on
// the host.
#[cfg(target_arch = "wasm32")]
pub mod migrate_ops;
// The one decision `migrate_ops` makes that loses data when it is wrong: when
// a migration may declare itself done. NOT wasm-gated, deliberately -- it is
// pure, and keeping it here is what makes it reachable from `cargo test`,
// which nothing inside `migrate_ops` is.
pub mod migrate_gate;
pub mod migrate_seal;
pub mod response_handler;
pub mod store_ops;

pub use connection::{connect, ConnectionStatus};
pub use delegate_api::{
    get_contract, get_contract_by_id, put_contract, register_delegate, send_delegate_message,
    update_contract,
};

use dioxus::prelude::*;

use crate::state::AppState;

/// Global WebSocket connection to the Freenet node.
#[cfg(target_arch = "wasm32")]
pub static WEB_API: GlobalSignal<Option<freenet_stdlib::client_api::WebApi>> =
    GlobalSignal::new(|| None);

/// Current connection status.
pub static CONNECTION_STATUS: GlobalSignal<ConnectionStatus> =
    GlobalSignal::new(|| ConnectionStatus::Disconnected);

/// Application state -- updated by the response handler, read by UI components.
pub static APP_STATE: GlobalSignal<AppState> = GlobalSignal::new(AppState::default);
