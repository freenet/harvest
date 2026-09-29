//! How a buyer pays an order: three numbered steps, with three labelled ways
//! to send the coins (Ian, 2026-09-25, "the pay-step standard"; README of the
//! launch lanes). Written for someone making their first bitcoin payment.
//!
//! 1. Open your bitcoin wallet.
//! 2. Send exactly the amount to this order's address, by whichever way is
//!    easiest: a `bitcoin:` link that opens the wallet with both filled in,
//!    a QR code carrying the same link, or by hand from two labelled fields.
//! 3. Harvest sees the payment by itself.
//!
//! Only ever rendered by [`super::bitcoin_view::OrderCard`], and only where
//! that card would otherwise have shown the bare address: after every check
//! that decides whether an address may be put in front of somebody to pay
//! (the order offers one, the address is the script that settles it). Those
//! checks stay in one place, the card, rather than being copied here.

use dioxus::prelude::*;
use freenet_bitcoin_common::BitcoinNetwork;

/// What a test coin is worth, said beside every test-network amount
/// (Ian, 2026-09-22: on every price and invoice, not only in a banner, so it
/// stays right once mainnet stores exist beside test ones).
pub(crate) const TEST_COIN_NOTE: &str = "test coins, no value";

/// Whether `network` pays in coins with no value.
pub(crate) fn is_test_network(network: BitcoinNetwork) -> bool {
    !matches!(network, BitcoinNetwork::Bitcoin)
}

/// The unit an amount on `network` is written in: `tBTC` for test coins.
pub(crate) fn coin_unit(network: BitcoinNetwork) -> &'static str {
    if is_test_network(network) {
        "tBTC"
    } else {
        "BTC"
    }
}

/// `sats` in bitcoin with all eight decimals, as a wallet takes it: 1100 is
/// "0.00001100". Integer arithmetic, so no amount is ever rounded.
pub(crate) fn btc_amount(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// "0.00001100 tBTC".
pub(crate) fn amount_text(sats: u64, network: BitcoinNetwork) -> String {
    format!("{} {}", btc_amount(sats), coin_unit(network))
}

/// The BIP21 link that opens a wallet with this payment filled in. The
/// amount is in bitcoin, as BIP21 requires.
pub(crate) fn payment_uri(address: &str, sats: u64) -> String {
    format!("bitcoin:{address}?amount={}", btc_amount(sats))
}

/// How long a payment usually takes to show as paid, for an order that
/// needs `confirmations` blocks: about ten minutes a block, and up to twenty
/// more for a slow block and for the node to hear of it. A Buy now order
/// needs one; an invoice issued by hand may ask for more.
pub(crate) fn confirmation_wait(confirmations: u32) -> String {
    let blocks = confirmations.max(1);
    format!("{} to {} minutes", blocks * 10, blocks * 10 + 20)
}

/// The QR code for `data` as the side length in modules and one SVG path
/// drawing every dark module. `None` only for data too long for any QR code,
/// which a payment link never is.
pub(crate) fn qr_path(data: &str) -> Option<(usize, String)> {
    let code =
        qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M).ok()?;
    let width = code.width();
    let mut path = String::new();
    for y in 0..width {
        for x in 0..width {
            if code[(x, y)] == qrcode::Color::Dark {
                path.push_str(&format!("M{x} {y}h1v1h-1z"));
            }
        }
    }
    Some((width, path))
}

/// The three steps, for one order's `address` and amount.
#[component]
pub(crate) fn PaySteps(
    address: String,
    amount_sats: u64,
    network: BitcoinNetwork,
    confirmations: u32,
    /// The order's short reference: keeps the copy fields' element ids apart
    /// when two orders on one page share an amount.
    order_ref: String,
) -> Element {
    let amount = amount_text(amount_sats, network);
    let wait = confirmation_wait(confirmations);
    let uri = payment_uri(&address, amount_sats);
    let qr = qr_path(&uri);
    let test = is_test_network(network);

    rsx! {
        div { class: "pay-steps-wrap",
            h4 { "How to pay" }
            ol { class: "pay-steps",
                li {
                    strong { "Open your bitcoin wallet." }
                    " A wallet is the app that holds and sends bitcoin, on your phone or computer."
                    if test {
                        p { class: "text-muted small",
                            "This store takes test coins, so the wallet has to be set to Bitcoin\u{2019}s "
                            "test network, {network.as_str()}. "
                            if network == BitcoinNetwork::Signet {
                                a {
                                    href: "https://signetfaucet.com/",
                                    target: "_blank",
                                    rel: "noopener noreferrer",
                                    "Get some free test coins"
                                }
                                "."
                            }
                        }
                    }
                }
                li {
                    strong { "Send exactly {amount} to this order\u{2019}s payment address." }
                    " Pick whichever way is easiest:"
                    div { class: "pay-ways",
                        div { class: "pay-way",
                            p { class: "pay-way-head", "On this device" }
                            a {
                                class: "btn btn-primary",
                                href: "{uri}",
                                target: "_blank",
                                rel: "noopener noreferrer",
                                "Open in my wallet"
                            }
                            p { class: "text-muted small",
                                "Opens your wallet with the address and amount filled in."
                            }
                        }
                        if let Some((width, path)) = qr {
                            div { class: "pay-way",
                                p { class: "pay-way-head", "With your phone" }
                                svg {
                                    class: "pay-qr",
                                    shape_rendering: "crispEdges",
                                    view_box: "-4 -4 {width + 8} {width + 8}",
                                    role: "img",
                                    "aria-label": "QR code for this payment",
                                    rect {
                                        x: "-4",
                                        y: "-4",
                                        width: "{width + 8}",
                                        height: "{width + 8}",
                                        fill: "#fff",
                                    }
                                    path { class: "pay-qr-modules", d: "{path}" }
                                }
                                p { class: "text-muted small",
                                    "Scan this in your wallet app. It carries the address and the amount."
                                }
                            }
                        }
                        div { class: "pay-way pay-way-wide",
                            p { class: "pay-way-head", "By hand" }
                            // The whole address is always visible, so it can be
                            // checked: one line at desktop width, wrapping to two
                            // on a phone, never scrolling sideways (a partial
                            // selection of a scrolled field pastes a truncated
                            // address).
                            CopyField {
                                label: "Payment address",
                                value: address.clone(),
                                salt: order_ref.clone(),
                            }
                            CopyField {
                                label: "Amount",
                                value: btc_amount(amount_sats),
                                salt: order_ref.clone(),
                            }
                            p { class: "text-muted small",
                                "Paste both into your wallet\u{2019}s Send screen. This address is only for "
                                "this order."
                            }
                        }
                    }
                    p { class: "text-muted small",
                        "Before you confirm in your wallet, check that the address and amount match. "
                        "A bitcoin payment can\u{2019}t be undone."
                    }
                }
                li {
                    strong { "That\u{2019}s it." }
                    " Harvest sees the payment by itself and shows this order as paid, usually "
                    "{wait} after you send. You can close Harvest while you wait."
                }
            }
        }
    }
}

/// One labelled value to copy: selected whole on a tap, with a Copy button
/// that uses the clipboard where the browser allows it and otherwise selects
/// the value and says so. The app runs in the gateway's sandboxed iframe, so
/// the clipboard may not be there; the value itself always works.
///
/// The value is a box sized to its text (`.copy-value`), not a form field
/// sized to the card: an amount is ten characters wide, and an address sits
/// on one line at desktop width and wraps to two on a phone instead of
/// scrolling in a tall text area (Ian, on the #187 screenshots).
/// `user-select: all` makes one tap select the whole of it.
#[component]
pub(crate) fn CopyField(
    label: &'static str,
    value: String,
    /// Makes the value's element id unique on the page.
    salt: String,
) -> Element {
    let mut said = use_signal(|| Option::<&'static str>::None);
    // An id for the field, so the Copy button can select it when the
    // clipboard refuses: the press has moved focus off the field by then.
    let id = format!(
        "copy-{}",
        &blake3::hash(format!("{salt}\0{label}\0{value}").as_bytes()).to_hex()[..12]
    );
    rsx! {
        div { class: "copy-row",
            // Tapping the label selects the value too, as a `label` wrapping
            // a field would.
            p {
                class: "copy-label",
                id: "{id}-label",
                onclick: {
                    let id = id.clone();
                    move |_| super::select_field_by_id(&id)
                },
                "{label}"
            }
            div { class: "copy-line",
                span {
                    id: "{id}",
                    class: "copy-value",
                    role: "textbox",
                    aria_readonly: "true",
                    aria_labelledby: "{id}-label",
                    tabindex: "0",
                    onfocus: |_| super::select_focused_field(),
                    "{value}"
                }
                button {
                        class: "btn btn-sm btn-outline",
                        r#type: "button",
                        onclick: {
                            let value = value.clone();
                            let id = id.clone();
                            move |_| {
                                let value = value.clone();
                                let id = id.clone();
                                spawn(async move {
                                    if copy_to_clipboard(&value).await {
                                        said.set(Some("Copied."));
                                    } else {
                                        super::select_field_by_id(&id);
                                        said.set(Some(
                                            "Selected: copy it with your keyboard or a long press.",
                                        ));
                                    }
                                });
                            }
                        },
                    "Copy"
                }
            }
            if let Some(what) = said() {
                p { class: "text-muted small", role: "status", "{what}" }
            }
        }
    }
}

/// Put `text` on the clipboard; `false` when the browser would not.
#[cfg(target_arch = "wasm32")]
async fn copy_to_clipboard(text: &str) -> bool {
    use wasm_bindgen::JsCast;
    // Looked up rather than typed: `navigator` would need another web-sys
    // feature, and only `clipboard.writeText` is used.
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Ok(navigator) = js_sys::Reflect::get(&window, &"navigator".into()) else {
        return false;
    };
    let clipboard = match js_sys::Reflect::get(&navigator, &"clipboard".into()) {
        Ok(c) if !c.is_undefined() && !c.is_null() => c,
        _ => return false,
    };
    let Some(write) = js_sys::Reflect::get(&clipboard, &"writeText".into())
        .ok()
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
    else {
        return false;
    };
    let Ok(promise) = write.call1(&clipboard, &text.into()) else {
        return false;
    };
    let Ok(promise) = promise.dyn_into::<js_sys::Promise>() else {
        return false;
    };
    wasm_bindgen_futures::JsFuture::from(promise).await.is_ok()
}

#[cfg(not(target_arch = "wasm32"))]
async fn copy_to_clipboard(_text: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_amount_is_written_the_way_a_wallet_takes_it() {
        assert_eq!(btc_amount(1_100), "0.00001100");
        assert_eq!(btc_amount(0), "0.00000000");
        assert_eq!(btc_amount(100_000_000), "1.00000000");
        assert_eq!(btc_amount(2_100_000_000_000_001), "21000000.00000001");
    }

    #[test]
    fn test_coins_say_so_and_real_ones_do_not() {
        assert_eq!(
            amount_text(1_100, BitcoinNetwork::Signet),
            "0.00001100 tBTC"
        );
        assert_eq!(
            amount_text(1_100, BitcoinNetwork::Testnet4),
            "0.00001100 tBTC"
        );
        assert_eq!(
            amount_text(1_100, BitcoinNetwork::Bitcoin),
            "0.00001100 BTC"
        );
        assert!(!is_test_network(BitcoinNetwork::Bitcoin));
        assert!(is_test_network(BitcoinNetwork::Regtest));
    }

    #[test]
    fn the_wait_follows_the_confirmations_the_order_needs() {
        assert_eq!(confirmation_wait(1), "10 to 30 minutes");
        assert_eq!(confirmation_wait(0), "10 to 30 minutes");
        assert_eq!(confirmation_wait(6), "60 to 80 minutes");
    }

    /// BIP21: the address, then the amount in bitcoin.
    #[test]
    fn the_wallet_link_carries_the_address_and_the_amount_in_bitcoin() {
        assert_eq!(
            payment_uri("tb1qexampleaddress", 1_100),
            "bitcoin:tb1qexampleaddress?amount=0.00001100"
        );
    }

    /// The QR code is a real one for the link: a square of the size the
    /// encoder chose, with the three finder patterns' dark corners.
    #[test]
    fn the_qr_code_draws_the_link() {
        let uri = payment_uri("tb1q27x5ls8wkw5mzxhdppejx5y2g7v0xlv3lcs50vwd", 1_100);
        let (width, path) = qr_path(&uri).expect("a payment link fits a QR code");
        let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
            .unwrap();
        assert_eq!(width, code.width());
        let dark = code
            .to_colors()
            .iter()
            .filter(|c| **c == qrcode::Color::Dark)
            .count();
        assert_eq!(
            path.matches('M').count(),
            dark,
            "one square per dark module"
        );
        for (x, y) in [(0, 0), (width - 1, 0), (0, width - 1)] {
            assert!(
                path.contains(&format!("M{x} {y}h1")),
                "finder corner {x},{y}"
            );
        }
    }
}
