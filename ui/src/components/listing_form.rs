use chrono::Utc;
use dioxus::prelude::*;
use harvest_common::listing::{
    ChoiceGroup, DeliveryPrice, FixedCheckout, Listing, ListingId, ListingKind, PriceInfo,
    RegionPrice,
};
use harvest_common::listing_image::ListingImage;

/// What every listing this form publishes is: a sale at a fixed price, with
/// fixed delivery (Ian, 2026-09-26). There is no free-text price, no gift or
/// wanted listing, and no "ask the seller for a total": a buyer can always
/// press Buy now, and the seller's store answers with the total at once.
///
/// A listing published before this (a quote-only one, or a gift or request)
/// is still read, and editing it here gives it a price: the edit publishes a
/// new listing and takes the old one down, like any change of terms.
const KIND: ListingKind = ListingKind::Sale;

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
    let mut quantity = use_signal(|| initial_quantity.map(|q| q.to_string()).unwrap_or_default());
    let quantity_error = parse_quantity(&quantity()).is_err();
    let mut terms = use_signal(|| {
        editing
            .as_ref()
            .map(TermsForm::from_listing)
            .unwrap_or_default()
    });
    let built_terms = terms().build();
    let terms_error = built_terms.as_ref().err().cloned();

    rsx! {
        div { class: "card",
            h3 { if initial.is_some() { "Edit listing" } else { "New listing" } }

            div { class: "form-group",
                label { class: "form-label", "Title" }
                input {
                    class: "form-input field-title",
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

            TermsEditor { terms }
            if let Some(problem) = terms_error.clone() {
                p { class: "text-warning", "{problem}" }
            }

            div { class: "form-group",
                label { class: "form-label", r#for: "listing-quantity", "How many you have (optional)" }
                input {
                    id: "listing-quantity",
                    class: "form-input field-count",
                    r#type: "text",
                    inputmode: "numeric",
                    value: "{quantity}",
                    oninput: move |e| quantity.set(e.value()),
                }
                p { class: "text-muted small", "Leave it blank if you don\u{2019}t count." }
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
                        let Ok((checkout, choices)) = terms().build() else {
                            return;
                        };
                        // The price is the sats price in `checkout`; the old
                        // free-text one is never written again.
                        let price: Option<PriceInfo> = None;
                        // The photos the new listing carries. This form does not
                        // edit photos yet, so an edit keeps the ones the listing
                        // has; they are terms like any other and go into the id.
                        let images = photos_for_edit(editing.as_ref());
                        // Only the count changed: submit the original, so its
                        // id, and the listing buyers hold, stays the same.
                        if let Some(original) = editing.as_ref() {
                            if same_terms(
                                original,
                                &title(),
                                &description(),
                                &KIND,
                                &checkout,
                                &choices,
                                &images,
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
                            images,
                            // Stamped by `with_derived_id` below, out of the
                            // finished terms: a listing whose id is not the
                            // one its terms give is refused by every peer
                            // (see `ListingId::from_terms`), so a literal
                            // here would be a second place deciding identity.
                            id: ListingId([0u8; 32]),
                            title: listing_title,
                            description: description().trim().to_string(),
                            kind: KIND,
                            price,
                            created_at: now,
                        }
                        .with_derived_id();

                        title.set(String::new());
                        description.set(String::new());
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
                    "Changing the title, description, price, delivery or choices publishes a new listing and "
                    "takes this one down. A buyer who already ordered this one can still see it."
                }
            }
        }
    }
}

/// Whether what the form holds is the listing it was opened on, term for
/// term, compared the way the form would build a new one (trimmed text). A
/// mismatch that is only formatting would otherwise turn a count change into
/// a take-down and a new id.
///
/// Every term of `Listing` except `id`, `created_at` and `price` is
/// compared (`images` included), so a field added to `Listing` must be added here, or an edit of
/// it alone would keep the old id. `price` is the free-text price listings
/// carried before every listing had a sats price: the form no longer shows
/// or writes it, so it is not a term the seller can change here, and a
/// count-only edit of an old listing keeps it (and its id) as it was.
///
/// `checkout` and `choices` are compared as [`TermsForm::build`] gives them,
/// which is already the form the new listing would carry.
pub(crate) fn same_terms(
    original: &Listing,
    title: &str,
    description: &str,
    kind: &ListingKind,
    checkout: &Option<FixedCheckout>,
    choices: &[ChoiceGroup],
    images: &[ListingImage],
) -> bool {
    let Listing {
        id: _,
        title: original_title,
        description: original_description,
        kind: original_kind,
        price: _,
        created_at: _,
        checkout: original_checkout,
        choices: original_choices,
        images: original_images,
    } = original;
    original_title.trim() == title.trim()
        && original_description.trim() == description.trim()
        && original_kind == kind
        && original_checkout == checkout
        && original_choices.as_slice() == choices
        && original_images.as_slice() == images
}

/// The photos an edit publishes: the listing's own, since this form cannot
/// change them yet (the upload path will). None for a new listing.
pub(crate) fn photos_for_edit(editing: Option<&Listing>) -> Vec<ListingImage> {
    editing.map(|l| l.images.clone()).unwrap_or_default()
}

/// The count field: blank is "not counted", anything else a whole number.
fn parse_quantity(typed: &str) -> Result<Option<u32>, ()> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Ok(None);
    }
    typed.parse::<u32>().map(Some).map_err(|_| ())
}

/// What the seller has typed for the price, delivery and choices, before it
/// is parsed. Kept as text so a half-typed number is shown back as typed.
#[derive(Clone, PartialEq, Default, Debug)]
pub(crate) struct TermsForm {
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

    /// The `checkout` and `choices` a listing built from this form carries,
    /// or what is wrong with them.
    ///
    /// The checkout is never `None`: every listing has a sats price and fixed
    /// delivery, so a blank price is refused rather than published as a
    /// listing nobody can buy. Rows left entirely blank are ignored, so an
    /// added row the seller did not fill in does not block publishing. The
    /// result is checked with the same `checkout_problem` and
    /// `choices_problem` every reader applies, and with
    /// `offers_instant_checkout`, so the form refuses exactly what a buyer's
    /// app would not let them buy.
    pub(crate) fn build(&self) -> Result<(Option<FixedCheckout>, Vec<ChoiceGroup>), String> {
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
        let checkout = {
            if self.unit_sats.trim().is_empty() {
                return Err("Give a price.".into());
            }
            let unit_sats = parse_sats(&self.unit_sats)
                .ok_or("Give the price as a whole number of sats, like 25000.")?;
            if unit_sats == 0 {
                return Err("The price has to be more than zero.".into());
            }
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
        };
        let probe = Listing {
            id: ListingId([0u8; 32]),
            title: String::new(),
            description: String::new(),
            kind: KIND,
            price: None,
            created_at: chrono::DateTime::UNIX_EPOCH,
            checkout,
            choices,
            images: Vec::new(),
        };
        if let Some(problem) = probe.checkout_problem().or_else(|| probe.choices_problem()) {
            return Err(sentence(&problem));
        }
        // Belt and braces: whatever the checks above let through has to be
        // something a buyer can actually buy.
        if !probe.offers_instant_checkout() {
            return Err("Give a price.".into());
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
            label { class: "form-label", r#for: "listing-unit-sats", "Price, in sats" }
            input {
                id: "listing-unit-sats",
                class: "form-input field-num",
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
                class: "form-select field-fit",
                value: if form.by_region { "regions" } else { "included" },
                onchange: move |e| terms.with_mut(|t| t.by_region = e.value() == "regions"),
                option { value: "included", "Included in the price" }
                option { value: "regions", "A price per region" }
            }
        }
        if form.by_region {
            div { class: "form-group",
                p { class: "text-muted small",
                    "One delivery price per order, not per item. Buyers elsewhere can\u{2019}t buy this."
                }
                // Column heads, so the second box reads as a price and in
                // what unit (2026-09-30 critique); each input keeps its own
                // aria-label for a screen reader.
                if !form.regions.is_empty() {
                    div { class: "form-row form-row-fit form-row-head", aria_hidden: "true",
                        span { class: "field-short-text", "Region" }
                        span { class: "field-num", "Delivery, sats" }
                    }
                }
                for (i, (region, sats)) in form.regions.iter().cloned().enumerate() {
                    div { key: "region-{i}", class: "form-row form-row-fit",
                        input {
                            class: "form-input field-short-text",
                            r#type: "text",
                            aria_label: "Region",
                            placeholder: "Region, like US or EU",
                            value: "{region}",
                            oninput: move |e| terms.with_mut(|t| t.regions[i].0 = e.value()),
                        }
                        input {
                            class: "form-input field-num",
                            r#type: "text",
                            inputmode: "numeric",
                            aria_label: "Delivery price, in sats",
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
        div { class: "form-group",
            label { class: "form-label", "Choices (optional)" }
            p { class: "text-muted small",
                "Things the buyer picks one of, like a size. Separate the options with commas."
            }
            if !form.choices.is_empty() {
                div { class: "form-row form-row-fit form-row-head", aria_hidden: "true",
                    span { class: "field-short-text", "Choice" }
                    span { class: "field-grow", "Options" }
                }
            }
            for (i, (name, options)) in form.choices.iter().cloned().enumerate() {
                div { key: "choice-{i}", class: "form-row form-row-fit",
                    input {
                        class: "form-input field-short-text",
                        r#type: "text",
                        aria_label: "Choice",
                        placeholder: "Size",
                        value: "{name}",
                        oninput: move |e| terms.with_mut(|t| t.choices[i].0 = e.value()),
                    }
                    input {
                        class: "form-input field-grow",
                        r#type: "text",
                        aria_label: "Options, separated by commas",
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
            images: Vec::new(),
            checkout: Some(FixedCheckout {
                unit_sats: 10_000,
                delivery: DeliveryPrice::Included,
            }),
            choices: Vec::new(),
            id: ListingId([0u8; 32]),
            title: "Mug ".into(),
            description: "Blue".into(),
            kind: ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    fn a_photo(seed: u8) -> ListingImage {
        let blob = |s: u8, edge: u16| harvest_common::listing_image::ImageBlob {
            hash: harvest_common::store::Bytes32([s; 32]),
            len: 10_000,
            width: edge,
            height: edge,
        };
        ListingImage {
            full: blob(seed, 1600),
            thumb: Some(blob(seed + 100, 400)),
            colour: [1, 2, 3],
            alt: String::new(),
        }
    }

    /// Photos are a term: a different set is a different listing, so a
    /// photo-only change never takes the count-only path and republishes the
    /// original without them.
    #[test]
    fn same_terms_notices_the_photos() {
        let mut o = original();
        o.images = vec![a_photo(1)];
        let terms = |images: &[ListingImage]| {
            same_terms(
                &o,
                "Mug",
                "Blue",
                &ListingKind::Sale,
                &o.checkout,
                &o.choices,
                images,
            )
        };
        assert!(terms(&o.images));
        assert!(!terms(&[]));
        assert!(!terms(&[a_photo(2)]));
    }

    /// An edit keeps the listing's photos (this form cannot change them yet);
    /// a new listing has none.
    #[test]
    fn an_edit_keeps_the_listings_photos() {
        let mut o = original();
        o.images = vec![a_photo(1)];
        assert_eq!(photos_for_edit(Some(&o)), o.images);
        assert!(photos_for_edit(None).is_empty());
    }

    /// Each term, changed alone, is a different listing; formatting alone is
    /// not. Mutated red by dropping each comparison in turn.
    #[test]
    fn same_terms_notices_each_term_and_ignores_formatting() {
        let o = original();
        let same = |title: &str,
                    description: &str,
                    kind: &ListingKind,
                    checkout,
                    choices: &[ChoiceGroup]| {
            same_terms(&o, title, description, kind, checkout, choices, &o.images)
        };
        assert!(same(
            "Mug",
            " Blue ",
            &ListingKind::Sale,
            &o.checkout,
            &o.choices
        ));
        assert!(!same(
            "Cup",
            "Blue",
            &ListingKind::Sale,
            &o.checkout,
            &o.choices
        ));
        assert!(!same(
            "Mug",
            "Red",
            &ListingKind::Sale,
            &o.checkout,
            &o.choices
        ));
        assert!(!same(
            "Mug",
            "Blue",
            &ListingKind::Gift,
            &o.checkout,
            &o.choices
        ));
        // The price changed, or delivery priced by region, is a different
        // listing.
        let dearer = Some(FixedCheckout {
            unit_sats: 12_000,
            delivery: DeliveryPrice::Included,
        });
        assert!(!same(
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &dearer,
            &o.choices
        ));
        let by_region = Some(FixedCheckout {
            unit_sats: 10_000,
            delivery: DeliveryPrice::ByRegion(vec![RegionPrice {
                region: "US".into(),
                sats: 0,
            }]),
        });
        assert!(!same(
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &by_region,
            &o.choices
        ));
        // So is a choice added.
        let sizes = vec![ChoiceGroup {
            name: "Size".into(),
            options: vec!["S".into(), "M".into()],
        }];
        assert!(!same(
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &o.checkout,
            &sizes
        ));
    }

    /// An old listing's free-text price is not a term the form can change:
    /// a count-only edit of a listing that carries one keeps it, and its id.
    /// And an old quote-only listing is a different listing from the priced
    /// one its edit publishes, which is the whole migration: the edit takes
    /// the old one down and publishes the priced one.
    #[test]
    fn an_old_free_text_price_is_not_a_term_and_a_quote_only_listing_moves_on_edit() {
        let mut old = original();
        old.price = Some(PriceInfo {
            amount: "0.001".into(),
            currency: "BTC".into(),
        });
        assert!(same_terms(
            &old,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &old.checkout,
            &[],
            &[]
        ));

        let mut quote_only = old.clone();
        quote_only.checkout = None;
        let reopened = TermsForm::from_listing(&quote_only);
        // The form opens with no price, and will not publish without one.
        assert_eq!(reopened.build(), Err("Give a price.".into()));
        let mut priced = reopened.clone();
        priced.unit_sats = "10000".into();
        let (checkout, choices) = priced.build().expect("valid");
        assert!(!same_terms(
            &quote_only,
            "Mug",
            "Blue",
            &ListingKind::Sale,
            &checkout,
            &choices,
            &[]
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
        let (checkout, choices) = form().build().expect("valid");
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
        assert_eq!(reopened.build(), Ok((checkout, choices)));

        // Delivery included is the default.
        let mut included = form();
        included.by_region = false;
        let (checkout, _) = included.build().expect("valid");
        assert_eq!(
            checkout,
            Some(FixedCheckout {
                unit_sats: 10_000,
                delivery: DeliveryPrice::Included,
            })
        );
    }

    /// What the form refuses: no price, bad numbers here, and whatever the
    /// common checks refuse. Every listing it builds is one a buyer can buy
    /// at once. Mutated red by letting a blank price through as `None`.
    #[test]
    fn the_terms_form_refuses_unusable_terms() {
        let mut blank = form();
        blank.unit_sats = "  ".into();
        assert_eq!(blank.build(), Err("Give a price.".into()));

        let mut junk = form();
        junk.unit_sats = "0.5".into();
        assert!(junk.build().is_err());

        let mut zero = form();
        zero.unit_sats = "0".into();
        assert_eq!(
            zero.build(),
            Err("The price has to be more than zero.".into())
        );

        let mut no_regions = form();
        no_regions.regions.clear();
        assert!(no_regions.build().is_err());

        let mut twice = form();
        twice.regions[1].0 = "us".into();
        assert!(twice.build().is_err());

        let mut no_options = form();
        no_options.choices[0].1 = " , ".into();
        assert!(no_options.build().is_err());

        // Everything it does build offers instant checkout.
        let (checkout, choices) = form().build().expect("valid");
        let listing = Listing {
            checkout,
            choices,
            ..original()
        };
        assert!(listing.offers_instant_checkout());
    }
}
