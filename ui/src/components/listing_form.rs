use chrono::Utc;
use dioxus::prelude::*;
use harvest_common::listing::{
    ChoiceGroup, DeliveryPrice, FixedCheckout, Listing, ListingId, ListingKind, PriceInfo,
    RegionPrice,
};

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
    let mut terms = use_signal(|| {
        editing
            .as_ref()
            .map(TermsForm::from_listing)
            .unwrap_or_default()
    });
    let built_terms = terms().build(&kind());
    let terms_error = built_terms.as_ref().err().cloned();

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
                TermsEditor { terms }
                if let Some(problem) = terms_error.clone() {
                    p { class: "text-warning", "{problem}" }
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
                disabled: title().trim().is_empty() || quantity_error || terms_error.is_some(),
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
                        let Ok((checkout, choices)) = terms().build(&kind()) else {
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
                            if same_terms(
                                original,
                                &title(),
                                &description(),
                                &kind(),
                                &price,
                                &checkout,
                                &choices,
                            ) {
                                on_submit.call((original.clone(), count));
                                return;
                            }
                        }
                        let now = Utc::now();
                        let listing_title = title().trim().to_string();
                        let listing = Listing {
                            checkout,
                            choices,
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
                        terms.set(TermsForm::default());

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
                    "Changing the title, description, type, price or choices publishes a new listing and "
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
///
/// `checkout` and `choices` are compared as [`TermsForm::build`] gives them,
/// which is already the form the new listing would carry.
pub(crate) fn same_terms(
    original: &Listing,
    title: &str,
    description: &str,
    kind: &ListingKind,
    price: &Option<PriceInfo>,
    checkout: &Option<FixedCheckout>,
    choices: &[ChoiceGroup],
) -> bool {
    let Listing {
        id: _,
        title: original_title,
        description: original_description,
        kind: original_kind,
        price: original_price,
        created_at: _,
        checkout: original_checkout,
        choices: original_choices,
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
        && original_checkout == checkout
        && original_choices.as_slice() == choices
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

/// What the seller has typed for instant checkout and choices, before it is
/// parsed. Kept as text so a half-typed number is shown back as typed.
#[derive(Clone, PartialEq, Default, Debug)]
pub(crate) struct TermsForm {
    /// Whether the seller offers instant checkout at all.
    pub instant: bool,
    /// The price of one, in sats.
    pub unit_sats: String,
    /// Delivery priced per region, rather than included.
    pub by_region: bool,
    /// (region, sats) rows.
    pub regions: Vec<(String, String)>,
    /// (name, options separated by commas) rows.
    pub choices: Vec<(String, String)>,
}

impl TermsForm {
    /// The form as it would show `listing`, for editing it.
    fn from_listing(listing: &Listing) -> Self {
        let mut form = TermsForm {
            choices: listing
                .choices
                .iter()
                .map(|group| (group.name.clone(), group.options.join(", ")))
                .collect(),
            ..TermsForm::default()
        };
        if let Some(checkout) = &listing.checkout {
            form.instant = true;
            form.unit_sats = checkout.unit_sats.to_string();
            if let DeliveryPrice::ByRegion(rows) = &checkout.delivery {
                form.by_region = true;
                form.regions = rows
                    .iter()
                    .map(|row| (row.region.clone(), row.sats.to_string()))
                    .collect();
            }
        }
        form
    }

    /// The `checkout` and `choices` a listing of `kind` built from this form
    /// carries, or what is wrong with them.
    ///
    /// Only a sale carries either. Rows left entirely blank are ignored, so an
    /// added row the seller did not fill in does not block publishing. The
    /// result is checked with the same `checkout_problem` and
    /// `choices_problem` every reader applies, so the form refuses exactly
    /// what a buyer's app would treat as quote-only.
    pub(crate) fn build(
        &self,
        kind: &ListingKind,
    ) -> Result<(Option<FixedCheckout>, Vec<ChoiceGroup>), String> {
        if *kind != ListingKind::Sale {
            return Ok((None, Vec::new()));
        }
        let choices: Vec<ChoiceGroup> = self
            .choices
            .iter()
            .filter(|(name, options)| !name.trim().is_empty() || !options.trim().is_empty())
            .map(|(name, options)| ChoiceGroup {
                name: name.trim().to_string(),
                options: options
                    .split(',')
                    .map(str::trim)
                    .filter(|o| !o.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
            .collect();
        let checkout = if self.instant {
            let unit_sats = parse_sats(&self.unit_sats)
                .ok_or("Give the instant checkout price as a whole number of sats.")?;
            let delivery = if self.by_region {
                let mut rows = Vec::new();
                for (region, sats) in self
                    .regions
                    .iter()
                    .filter(|(r, s)| !r.trim().is_empty() || !s.trim().is_empty())
                {
                    let sats = parse_sats(sats).ok_or(
                        "Give each delivery price as a whole number of sats. Use 0 for free delivery.",
                    )?;
                    rows.push(RegionPrice {
                        region: region.trim().to_string(),
                        sats,
                    });
                }
                DeliveryPrice::ByRegion(rows)
            } else {
                DeliveryPrice::Included
            };
            Some(FixedCheckout {
                unit_sats,
                delivery,
            })
        } else {
            None
        };
        let probe = Listing {
            id: ListingId([0u8; 32]),
            title: String::new(),
            description: String::new(),
            kind: kind.clone(),
            price: None,
            created_at: chrono::DateTime::UNIX_EPOCH,
            checkout,
            choices,
        };
        if let Some(problem) = probe.checkout_problem().or_else(|| probe.choices_problem()) {
            return Err(sentence(&problem));
        }
        Ok((probe.checkout, probe.choices))
    }
}

/// A whole number of sats, or `None`.
fn parse_sats(typed: &str) -> Option<u64> {
    typed.trim().parse::<u64>().ok()
}

/// A problem from `harvest_common` as a sentence: capital first letter, full
/// stop at the end.
fn sentence(problem: &str) -> String {
    let mut chars = problem.chars();
    let mut out: String = chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default();
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// The instant checkout and choices part of the listing form.
#[component]
fn TermsEditor(terms: Signal<TermsForm>) -> Element {
    let form = terms();
    rsx! {
        div { class: "form-group",
            label { class: "form-label",
                input {
                    r#type: "checkbox",
                    checked: form.instant,
                    onchange: move |e| terms.with_mut(|t| t.instant = e.checked()),
                }
                " Instant checkout"
            }
            p { class: "text-muted small",
                "Buyers see a total in sats and can buy without waiting for you to name a price. "
                "Without it, buyers send a request and you reply with a total."
            }
        }
        if form.instant {
            div { class: "form-group",
                label { class: "form-label", r#for: "listing-unit-sats", "Price of one, in sats" }
                input {
                    id: "listing-unit-sats",
                    class: "form-input form-input-short",
                    r#type: "text",
                    inputmode: "numeric",
                    placeholder: "10000",
                    value: "{form.unit_sats}",
                    oninput: move |e| terms.with_mut(|t| t.unit_sats = e.value()),
                }
            }
            div { class: "form-group",
                label { class: "form-label", "Delivery" }
                select {
                    class: "form-select",
                    value: if form.by_region { "regions" } else { "included" },
                    onchange: move |e| terms.with_mut(|t| t.by_region = e.value() == "regions"),
                    option { value: "included", "Included in the price" }
                    option { value: "regions", "A price per region" }
                }
            }
            if form.by_region {
                div { class: "form-group",
                    p { class: "text-muted small",
                        "One price per order, not per item. Buyers outside these regions can still send a request."
                    }
                    for (i, (region, sats)) in form.regions.iter().cloned().enumerate() {
                        div { key: "region-{i}", class: "form-row",
                            input {
                                class: "form-input",
                                r#type: "text",
                                placeholder: "Region, like US or EU",
                                value: "{region}",
                                oninput: move |e| terms.with_mut(|t| t.regions[i].0 = e.value()),
                            }
                            input {
                                class: "form-input form-narrow",
                                r#type: "text",
                                inputmode: "numeric",
                                placeholder: "sats",
                                value: "{sats}",
                                oninput: move |e| terms.with_mut(|t| t.regions[i].1 = e.value()),
                            }
                            button {
                                class: "btn btn-sm btn-outline",
                                onclick: move |_| terms.with_mut(|t| {
                                    t.regions.remove(i);
                                }),
                                "Remove"
                            }
                        }
                    }
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: move |_| terms.with_mut(|t| t.regions.push(Default::default())),
                        "Add region"
                    }
                }
            }
        }
        div { class: "form-group",
            label { class: "form-label", "Choices (optional)" }
            p { class: "text-muted small",
                "Things the buyer picks one of, like a size. Separate the options with commas."
            }
            for (i, (name, options)) in form.choices.iter().cloned().enumerate() {
                div { key: "choice-{i}", class: "form-row",
                    input {
                        class: "form-input form-narrow",
                        r#type: "text",
                        placeholder: "Size",
                        value: "{name}",
                        oninput: move |e| terms.with_mut(|t| t.choices[i].0 = e.value()),
                    }
                    input {
                        class: "form-input",
                        r#type: "text",
                        placeholder: "S, M, L",
                        value: "{options}",
                        oninput: move |e| terms.with_mut(|t| t.choices[i].1 = e.value()),
                    }
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: move |_| terms.with_mut(|t| {
                            t.choices.remove(i);
                        }),
                        "Remove"
                    }
                }
            }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| terms.with_mut(|t| t.choices.push(Default::default())),
                "Add choice"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Listing {
        Listing {
            checkout: None,
            choices: Vec::new(),
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
        assert!(same_terms(
            &o,
            "Mug",
            " Blue ",
            &ListingKind::Sale,
            &price,
            &o.checkout,
            &o.choices
        ));
        assert!(!same_terms(
            &o,
            "Cup",
            "Blue",
            &ListingKind::Sale,
            &price,
            &o.checkout,
            &o.choices
        ));
        assert!(!same_terms(
            &o,
            "Mug",
            "Red",
            &ListingKind::Sale,
            &price,
            &o.checkout,
            &o.choices
        ));
        assert!(!same_terms(
            &o,
            "Mug",
            "Blue",
            &ListingKind::Gift,
            &None,
            &o.checkout,
            &o.choices
        ));
        let dearer = Some(PriceInfo {
            amount: "0.002".into(),
            currency: "BTC".into(),
        });
        assert!(!same_terms(
            &o,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &dearer,
            &o.checkout,
            &o.choices
        ));
        // The kind alone, with no price either side.
        let mut unpriced = o.clone();
        unpriced.price = None;
        assert!(!same_terms(
            &unpriced,
            "Mug",
            "Blue",
            &ListingKind::Gift,
            &None,
            &unpriced.checkout,
            &unpriced.choices
        ));
        assert!(same_terms(
            &unpriced,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &None,
            &unpriced.checkout,
            &unpriced.choices
        ));
        // Instant checkout added, or its price changed, is a different listing.
        let checkout = Some(FixedCheckout {
            unit_sats: 10_000,
            delivery: DeliveryPrice::Included,
        });
        assert!(!same_terms(
            &o,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &price,
            &checkout,
            &o.choices
        ));
        let mut instant = o.clone();
        instant.checkout = checkout.clone();
        let dearer_checkout = Some(FixedCheckout {
            unit_sats: 12_000,
            delivery: DeliveryPrice::Included,
        });
        assert!(same_terms(
            &instant,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &price,
            &checkout,
            &[]
        ));
        assert!(!same_terms(
            &instant,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &price,
            &dearer_checkout,
            &[]
        ));
        // So is a choice added.
        let sizes = vec![ChoiceGroup {
            name: "Size".into(),
            options: vec!["S".into(), "M".into()],
        }];
        assert!(!same_terms(
            &o,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &price,
            &None,
            &sizes
        ));
        // A gift carrying a stale price is the same gift without one.
        let mut gift = o.clone();
        gift.kind = ListingKind::Gift;
        assert!(same_terms(
            &gift,
            "Mug",
            "Blue",
            &ListingKind::Gift,
            &None,
            &gift.checkout,
            &gift.choices
        ));
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

    fn form() -> TermsForm {
        TermsForm {
            instant: true,
            unit_sats: " 10000 ".into(),
            by_region: true,
            regions: vec![
                (" US ".into(), "2000".into()),
                ("EU".into(), "5000".into()),
                (String::new(), String::new()),
            ],
            choices: vec![
                ("Flavour ".into(), "Fig, Plum ,".into()),
                (String::new(), " ".into()),
            ],
        }
    }

    /// The form builds trimmed terms, skips blank rows, and gives them back
    /// unchanged when the listing is edited.
    #[test]
    fn the_terms_form_builds_trimmed_terms_and_round_trips() {
        let (checkout, choices) = form().build(&ListingKind::Sale).expect("valid");
        assert_eq!(
            checkout,
            Some(FixedCheckout {
                unit_sats: 10_000,
                delivery: DeliveryPrice::ByRegion(vec![
                    RegionPrice {
                        region: "US".into(),
                        sats: 2000
                    },
                    RegionPrice {
                        region: "EU".into(),
                        sats: 5000
                    },
                ]),
            })
        );
        assert_eq!(
            choices,
            vec![ChoiceGroup {
                name: "Flavour".into(),
                options: vec!["Fig".into(), "Plum".into()],
            }]
        );

        let mut listing = original();
        listing.checkout = checkout.clone();
        listing.choices = choices.clone();
        let reopened = TermsForm::from_listing(&listing);
        assert_eq!(reopened.build(&ListingKind::Sale), Ok((checkout, choices)));
        // Only a sale carries them.
        assert_eq!(form().build(&ListingKind::Gift), Ok((None, Vec::new())));
    }

    /// What the form refuses: bad numbers here, and whatever the common
    /// checks refuse.
    #[test]
    fn the_terms_form_refuses_unusable_terms() {
        let mut junk = form();
        junk.unit_sats = "0.5".into();
        assert!(junk.build(&ListingKind::Sale).is_err());

        let mut zero = form();
        zero.unit_sats = "0".into();
        assert_eq!(
            zero.build(&ListingKind::Sale),
            Err("An instant-checkout price must be more than zero.".into())
        );

        let mut no_regions = form();
        no_regions.regions.clear();
        assert!(no_regions.build(&ListingKind::Sale).is_err());

        let mut twice = form();
        twice.regions[1].0 = "us".into();
        assert!(twice.build(&ListingKind::Sale).is_err());

        let mut no_options = form();
        no_options.choices[0].1 = " , ".into();
        assert!(no_options.build(&ListingKind::Sale).is_err());

        // Choices without instant checkout are fine: a quote-only listing.
        let mut quote = form();
        quote.instant = false;
        let (checkout, choices) = quote.build(&ListingKind::Sale).expect("valid");
        assert_eq!(checkout, None);
        assert_eq!(choices.len(), 1);
    }
}
