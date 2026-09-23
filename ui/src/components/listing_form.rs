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
///
/// # Editing, and the count
///
/// With `initial`, it edits that listing. A listing's terms cannot change in
/// place (its id is a hash of them, harvest#70), so an edit that changes any
/// term submits a NEW listing, which the caller publishes while taking the
/// old one down. An edit that changes only the count submits the ORIGINAL
/// listing unchanged, same id, so the caller publishes only its status.
/// Rebuilding it would give it a fresh `created_at`, and so a fresh id, and
/// turn a count change into a take-down and a new listing.
///
/// The count is optional: blank means the seller does not count, which is
/// what every listing was before counts existed.
#[component]
pub fn ListingForm(
    on_submit: EventHandler<(Listing, Option<u32>)>,
    initial: Option<Listing>,
    initial_quantity: Option<u32>,
    /// The listing being edited is sold out: a count puts it back on sale,
    /// and blank leaves it sold out.
    #[props(default)]
    sold_out: bool,
    on_cancel: EventHandler<()>,
) -> Element {
    let editing = initial.clone();
    let mut title = use_signal(|| {
        editing
            .as_ref()
            .map(|l| l.title.clone())
            .unwrap_or_default()
    });
    let mut description = use_signal(|| {
        editing
            .as_ref()
            .map(|l| l.description.clone())
            .unwrap_or_default()
    });
    let mut kind = use_signal(|| {
        editing
            .as_ref()
            .map(|l| l.kind.clone())
            .unwrap_or(ListingKind::Sale)
    });
    let mut price_amount = use_signal(|| {
        editing
            .as_ref()
            .and_then(|l| l.price.as_ref())
            .map(|p| p.amount.clone())
            .unwrap_or_default()
    });
    let mut price_currency = use_signal(|| {
        editing
            .as_ref()
            .and_then(|l| l.price.as_ref())
            .map(|p| p.currency.clone())
            .unwrap_or_else(|| "BTC".to_string())
    });
    let mut quantity = use_signal(|| initial_quantity.map(|q| q.to_string()).unwrap_or_default());
    let quantity_error = parse_quantity(&quantity()).is_err();

    rsx! {
        div { class: "card",
            h3 { if initial.is_some() { "Edit listing" } else { "New listing" } }

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

            div { class: "form-group",
                label { class: "form-label", r#for: "listing-quantity", "How many you have (optional)" }
                input {
                    id: "listing-quantity",
                    class: "form-input form-input-short",
                    r#type: "text",
                    inputmode: "numeric",
                    placeholder: "Leave blank if you don't count",
                    value: "{quantity}",
                    oninput: move |e| quantity.set(e.value()),
                }
                if quantity_error {
                    p { class: "text-warning", "A count is a whole number, like 3." }
                }
                if sold_out {
                    p { class: "text-muted small",
                        "This listing is sold out. Give a count to put it back on sale; leave it blank to keep it sold out."
                    }
                }
            }

            div { class: "form-actions",
            button {
                class: "btn btn-primary",
                disabled: title().trim().is_empty() || quantity_error,
                onclick: move |_| {
                        // Re-checked here, not only in `disabled`: two clicks
                        // can land before the button re-renders (#80), and the
                        // first clears the title.
                        if title().trim().is_empty() {
                            return;
                        }
                        let Ok(count) = parse_quantity(&quantity()) else {
                            return;
                        };
                        let price = if matches!(kind(), ListingKind::Sale)
                            && !price_amount().trim().is_empty()
                        {
                            Some(PriceInfo {
                                amount: price_amount().trim().to_string(),
                                currency: price_currency().trim().to_string(),
                            })
                        } else {
                            None
                        };
                        // Only the count changed: submit the original, so its
                        // id, and the listing buyers hold, stays the same.
                        if let Some(original) = editing.as_ref() {
                            if same_terms(original, &title(), &description(), &kind(), &price) {
                                on_submit.call((original.clone(), count));
                                return;
                            }
                        }
                        let now = Utc::now();
                        let listing_title = title().trim().to_string();
                        let listing = Listing {
                            // Stamped by `with_derived_id` below, out of the
                            // finished terms: a listing whose id is not the
                            // one its terms give is refused by every peer
                            // (see `ListingId::from_terms`), so a literal
                            // here would be a second place deciding identity.
                            id: ListingId([0u8; 32]),
                            title: listing_title,
                            description: description().trim().to_string(),
                            kind: kind(),
                            price,
                            created_at: now,
                        }
                        .with_derived_id();

                        title.set(String::new());
                        description.set(String::new());
                        price_amount.set(String::new());
                        quantity.set(String::new());

                        on_submit.call((listing, count));
                },
                if initial.is_some() { "Save changes" } else { "Publish listing" }
            }
            button {
                class: "btn btn-outline",
                onclick: move |_| on_cancel.call(()),
                "Cancel"
            }
            }
            if initial.is_some() {
                p { class: "text-muted small",
                    "Changing the title, description, type or price publishes a new listing and "
                    "takes this one down. A buyer who already asked about this one can still see it."
                }
            }
        }
    }
}

/// Whether what the form holds is the listing it was opened on, term for
/// term, compared the way the form would build a new one (trimmed text, no
/// price unless it is a sale). A mismatch that is only formatting would
/// otherwise turn a count change into a take-down and a new id.
///
/// Every term of `Listing` except `id` and `created_at` is compared, so a
/// field added to `Listing` must be added here, or an edit of it alone would
/// keep the old id.
pub(crate) fn same_terms(
    original: &Listing,
    title: &str,
    description: &str,
    kind: &ListingKind,
    price: &Option<PriceInfo>,
) -> bool {
    let Listing {
        id: _,
        title: original_title,
        description: original_description,
        kind: original_kind,
        price: original_price,
        created_at: _,
    } = original;
    let normalised = |p: &Option<PriceInfo>, k: &ListingKind| match (k, p) {
        (ListingKind::Sale, Some(p)) if !p.amount.trim().is_empty() => Some(PriceInfo {
            amount: p.amount.trim().to_string(),
            currency: p.currency.trim().to_string(),
        }),
        _ => None,
    };
    original_title.trim() == title.trim()
        && original_description.trim() == description.trim()
        && original_kind == kind
        && normalised(original_price, original_kind) == normalised(price, kind)
}

/// The count field: blank is "not counted", anything else a whole number.
fn parse_quantity(typed: &str) -> Result<Option<u32>, ()> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Ok(None);
    }
    typed.parse::<u32>().map(Some).map_err(|_| ())
}

fn kind_value(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "sale",
        ListingKind::Gift => "gift",
        ListingKind::Request => "request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Listing {
        Listing {
            id: ListingId([0u8; 32]),
            title: "Mug ".into(),
            description: "Blue".into(),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.001".into(),
                currency: "BTC".into(),
            }),
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    /// Each term, changed alone, is a different listing; formatting alone is
    /// not. Mutated red by dropping each comparison in turn.
    #[test]
    fn same_terms_notices_each_term_and_ignores_formatting() {
        let o = original();
        let price = o.price.clone();
        assert!(same_terms(&o, "Mug", " Blue ", &ListingKind::Sale, &price));
        assert!(!same_terms(&o, "Cup", "Blue", &ListingKind::Sale, &price));
        assert!(!same_terms(&o, "Mug", "Red", &ListingKind::Sale, &price));
        assert!(!same_terms(&o, "Mug", "Blue", &ListingKind::Gift, &None));
        let dearer = Some(PriceInfo {
            amount: "0.002".into(),
            currency: "BTC".into(),
        });
        assert!(!same_terms(&o, "Mug", "Blue", &ListingKind::Sale, &dearer));
        // The kind alone, with no price either side.
        let mut unpriced = o.clone();
        unpriced.price = None;
        assert!(!same_terms(
            &unpriced,
            "Mug",
            "Blue",
            &ListingKind::Gift,
            &None
        ));
        assert!(same_terms(
            &unpriced,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &None
        ));
        // A gift carrying a stale price is the same gift without one.
        let mut gift = o.clone();
        gift.kind = ListingKind::Gift;
        assert!(same_terms(&gift, "Mug", "Blue", &ListingKind::Gift, &None));
    }

    #[test]
    fn a_blank_count_is_uncounted_and_junk_is_refused() {
        assert_eq!(parse_quantity(""), Ok(None));
        assert_eq!(parse_quantity("  "), Ok(None));
        assert_eq!(parse_quantity(" 3 "), Ok(Some(3)));
        assert_eq!(parse_quantity("0"), Ok(Some(0)));
        assert!(parse_quantity("-1").is_err());
        assert!(parse_quantity("2.5").is_err());
        assert!(parse_quantity("lots").is_err());
    }
}
