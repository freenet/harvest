use futures::channel::mpsc;

/// Connection status for UI display.
#[derive(Clone, PartialEq, Debug)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting..."),
            Self::Connected => write!(f, "Connected"),
            Self::Error(e) => write!(f, "Error: {e}"),
        }
    }
}

/// Connect to the Freenet gateway via WebSocket.
///
/// Returns a receiver for host responses. The caller should spawn a task
/// to process these responses (contract updates, delegate responses, etc.).
#[cfg(target_arch = "wasm32")]
pub async fn connect(
) -> Result<mpsc::UnboundedReceiver<Result<freenet_stdlib::client_api::HostResponse, String>>, String>
{
    use dioxus::logger::tracing::{error, info, warn};
    use dioxus::prelude::*;
    use freenet_stdlib::client_api::{ClientError, HostResponse, WebApi};
    use wasm_bindgen_futures::spawn_local;

    use super::{CONNECTION_STATUS, WEB_API};

    *CONNECTION_STATUS.write() = ConnectionStatus::Connecting;

    let base_url = get_websocket_url();
    // What the log may say: the node's address with no query string. The
    // URL actually dialled carries `authToken=` for a node that requires one,
    // and `info!` survives release builds (harvest#96 review).
    let node_address = base_url.split('?').next().unwrap_or_default().to_string();
    let websocket_url = match get_auth_token() {
        Some(token) => {
            if base_url.contains('?') {
                format!("{}&authToken={}", base_url, token)
            } else {
                format!("{}?authToken={}", base_url, token)
            }
        }
        None => base_url,
    };

    info!("Connecting to Freenet node at: {node_address}");

    // Not the browser's error text: Chrome's SyntaxError quotes the whole
    // URL ("The URL '<url>' is invalid."), token included, and this string
    // is logged by the caller and shown as the connection status.
    let websocket = web_sys::WebSocket::new(&websocket_url)
        .map_err(|_| format!("could not open the websocket to {node_address}"))?;

    let (response_tx, response_rx) = mpsc::unbounded();
    let (ready_tx, ready_rx) = futures::channel::oneshot::channel();

    let response_tx_clone = response_tx.clone();

    let web_api = WebApi::start(
        websocket,
        // Result callback -- routes host responses to our channel
        move |result: Result<HostResponse, ClientError>| {
            // The one error the delegate migration needs typed: the node
            // saying a predecessor delegate is not registered. Offered before
            // it is flattened to a string; taken only if the migration was
            // waiting on exactly that delegate.
            if let Err(e) = &result {
                if super::delegate_migrate_ops::offer_error(e) {
                    return;
                }
            }
            let mapped = result.map_err(|e| e.to_string());
            let tx = response_tx_clone.clone();
            spawn_local(async move {
                if let Err(e) = tx.unbounded_send(mapped) {
                    error!("Failed to send API response: {}", e);
                }
            });
        },
        // Error callback
        move |error| {
            warn!("WebSocket error: {}", error);
        },
        // Connected callback
        move || {
            info!("WebSocket connected");
            let _ = ready_tx.send(());
        },
    );

    // Wait for connection to be ready
    ready_rx
        .await
        .map_err(|_| "Connection dropped before ready".to_string())?;

    *WEB_API.write() = Some(web_api);
    *CONNECTION_STATUS.write() = ConnectionStatus::Connected;

    info!("Connected to Freenet gateway");
    Ok(response_rx)
}

/// Non-WASM stub -- returns a dummy receiver.
#[cfg(not(target_arch = "wasm32"))]
pub async fn connect(
) -> Result<mpsc::UnboundedReceiver<Result<freenet_stdlib::client_api::HostResponse, String>>, String>
{
    let (_tx, rx) = mpsc::unbounded();
    Ok(rx)
}

/// Derive WebSocket URL from the current browser location.
#[cfg(target_arch = "wasm32")]
fn get_websocket_url() -> String {
    if let Some(window) = web_sys::window() {
        let location = window.location();
        let protocol = location.protocol().unwrap_or_default();
        let host = location.host().unwrap_or_default();
        let ws_protocol = if protocol == "https:" { "wss:" } else { "ws:" };
        format!(
            "{}//{}/v1/contract/command?encodingProtocol=native",
            ws_protocol, host
        )
    } else {
        "ws://localhost:7509/v1/contract/command?encodingProtocol=native".to_string()
    }
}

/// Get the auth token injected by the Freenet gateway into the page.
#[cfg(target_arch = "wasm32")]
fn get_auth_token() -> Option<String> {
    let window = web_sys::window()?;
    let token = js_sys::Reflect::get(&window, &"__FREENET_AUTH_TOKEN__".into()).ok()?;
    token.as_string().filter(|s| !s.is_empty())
}
