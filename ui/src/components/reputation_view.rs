use dioxus::prelude::*;
use harvest_common::feedback::FeedbackCategory;
use harvest_common::reputation::Complaint;

use crate::fulfilment::{complaint_standing, ComplaintStanding};
use crate::gateway::APP_STATE;

/// One complaint as a reader sees it: what it says, and how it counts.
#[derive(Clone, PartialEq)]
struct ComplaintRow {
    complaint: Complaint,
    standing: ComplaintStanding,
    store_name: Option<String>,
}

#[component]
pub fn ReputationView() -> Element {
    let rows: Vec<ComplaintRow> = {
        let app_state = APP_STATE.read();
        app_state
            .browsing_stores
            .values()
            .flat_map(|store| {
                let store_name = store.info.as_ref().map(|i| i.store_name.clone());
                store.complaints.iter().map(move |c| ComplaintRow {
                    standing: complaint_standing(
                        c,
                        store.orders.iter().find(|o| o.order.id == *c.order_id()),
                        store.despatches.get(c.order_id()),
                    ),
                    complaint: c.clone(),
                    store_name: store_name.clone(),
                })
            })
            .collect()
    };
    let counted = rows.iter().filter(|r| r.standing.counts()).count();

    rsx! {
        div {
            h2 { "Reputation" }

            div { class: "info-box",
                p {
                    "A seller's record holds complaints only, as categories, with no free text. "
                    "Each one names an order that the order's own Bitcoin bridges say was paid, "
                    "and only that order's buyer can make it, so a stranger cannot make one up "
                    "and the seller cannot take one down."
                }
                p {
                    "What it cannot tell you: the seller chooses which bridges their orders "
                    "trust, so a seller who pays themselves through a bridge they run can put "
                    "orders, and complaints, on their own record. And a record with no "
                    "complaints says nothing about the orders nobody complained about."
                }
            }

            if rows.is_empty() {
                p { class: "text-muted text-italic",
                    "No complaints loaded. Browse a store to see its record."
                }
            } else {
                p { class: "section-count",
                    "{counted} complaint(s) counted, of {rows.len()} on record"
                }
                for row in rows.iter() {
                    ComplaintCard { row: row.clone() }
                }
            }
        }
    }
}

#[component]
fn ComplaintCard(row: ComplaintRow) -> Element {
    let ComplaintRow {
        complaint,
        standing,
        store_name,
    } = row;
    let short = complaint.order_id().short();
    let block = complaint.block_ref.height;
    let note = match standing {
        ComplaintStanding::Counts => None,
        ComplaintStanding::Late { closed_at } => Some(format!(
            "Made after the complaint window closed at block {closed_at}, so it is not counted."
        )),
        ComplaintStanding::PaymentReversed => Some(if standing.counts() {
            "Payment reversed on the Bitcoin chain since; still counted.".to_string()
        } else {
            "Payment reversed on the Bitcoin chain since, so it is not counted.".to_string()
        }),
    };
    rsx! {
        div { class: "feedback-card",
            div { class: "feedback-header",
                span { class: "feedback-category", "{category_label(&complaint.category)}" }
                span { class: "feedback-time", "order {short} \u{00b7} made at or after block {block}" }
            }
            if let Some(note) = note {
                p { class: "text-muted", "{note}" }
            }
            if let Some(ref name) = store_name {
                p { class: "feedback-store", "Store: {name}" }
            }
        }
    }
}

/// What a category is called wherever a complaint is shown or offered.
pub(crate) fn category_label(category: &FeedbackCategory) -> &'static str {
    match category {
        FeedbackCategory::NonDelivery => "Not delivered",
        FeedbackCategory::Misrepresented => "Not as described",
        FeedbackCategory::Counterfeit => "Counterfeit",
    }
}
