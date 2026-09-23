use chrono::Utc;
use dioxus::prelude::*;
use harvest_common::listing::{Listing, ListingId, ListingKind, PriceInfo};

/// The form a seller fills in to publish a listing.
///
/// # It no longer takes the seller's fingerprint, and that is not a loss
///
/// It used to, solely to feed `ListingId::new`. The id now comes from the
/// listing's own terms, and a `Listing` carries no seller field -- so two
/// sellers publishing an identical listing share an id. That is harmless:
/// listings live in a store contract whose parameters bind the seller's key,
/// so the two are in different contracts, and `AuthorizedListing::verify`
/// checks each against its own store's key. A listing's authorship was never
/// carried by its id; it is the ghostkey signature over the terms.
#[component]
pub fn ListingForm(on_submit: EventHandler<Listing>) -> Element {
    let mut title = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut kind = use_signal(|| ListingKind::Sale);
    let mut price_amount = use_signal(String::new);
    let mut price_currency = use_signal(|| "BTC".to_string());

    rsx! {
        div { class: "card",
            h3 { "New Listing" }

            div { class: "form-group",
                label { class: "form-label", "Title" }
                input {
                    class: "form-input",
                    r#type: "text",
                    placeholder: "What are you offering?",
                    value: "{title}",
                    oninput: move |e| title.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Description" }
                textarea {
                    class: "form-textarea",
                    placeholder: "Describe your item or service...",
                    value: "{description}",
                    oninput: move |e| description.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Type" }
                select {
                    class: "form-select",
                    value: kind_value(&kind()),
                    onchange: move |e| {
                        kind.set(match e.value().as_str() {
                            "gift" => ListingKind::Gift,
                            "request" => ListingKind::Request,
                            _ => ListingKind::Sale,
                        });
                    },
                    option { value: "sale", "For Sale" }
                    option { value: "gift", "Gift / Free" }
                    option { value: "request", "Request / Wanted" }
                }
            }

            if matches!(kind(), ListingKind::Sale) {
                div { class: "form-group form-row",
                    div {
                        label { class: "form-label", "Price" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            placeholder: "0.001",
                            value: "{price_amount}",
                            oninput: move |e| price_amount.set(e.value()),
                        }
                    }
                    div { class: "form-narrow",
                        label { class: "form-label", "Currency" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            placeholder: "BTC",
                            value: "{price_currency}",
                            oninput: move |e| price_currency.set(e.value()),
                        }
                    }
                }
            }

            button {
                class: "btn btn-primary",
                disabled: title().trim().is_empty(),
                onclick: move |_| {
                        let now = Utc::now();
                        let listing_title = title().trim().to_string();
                        let listing = Listing {
                            checkout: None,
                            choices: Vec::new(),
                            // Stamped by `with_derived_id` below, out of the
                            // finished terms: a listing whose id is not the
                            // one its terms give is refused by every peer
                            // (see `ListingId::from_terms`), so a literal
                            // here would be a second place deciding identity.
                            id: ListingId([0u8; 32]),
                            title: listing_title,
                            description: description().trim().to_string(),
                            kind: kind(),
                            price: if matches!(kind(), ListingKind::Sale)
                                && !price_amount().trim().is_empty()
                            {
                                Some(PriceInfo {
                                    amount: price_amount().trim().to_string(),
                                    currency: price_currency().trim().to_string(),
                                })
                            } else {
                                None
                            },
                            created_at: now,
                        }
                        .with_derived_id();

                        title.set(String::new());
                        description.set(String::new());
                        price_amount.set(String::new());

                        on_submit.call(listing);
                },
                "Create Listing"
            }
        }
    }
}

fn kind_value(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "sale",
        ListingKind::Gift => "gift",
        ListingKind::Request => "request",
    }
}
