use dioxus::prelude::*;
use harvest_common::feedback::FeedbackCategory;
use harvest_common::reputation::Complaint;

use crate::fulfilment::ComplaintStanding;
use crate::gateway::APP_STATE;

/// One complaint as a reader sees it: what it says, and how it counts.
#[derive(Clone, PartialEq)]
struct ComplaintRow {
    complaint: Complaint,
    standing: ComplaintStanding,
    store_name: Option<String>,
}

/// One store's record: its complaints, and nothing else's (harvest#93 phase 2).
///
/// This replaces the old top-level Reputation tab, which pooled every browsed
/// store's complaints into one list. A record belongs to a store, so it is
/// shown on that store's page; the seller's overview shows its count. Each
/// complaint is counted the way the store's badge counts it
/// (`BrowsingStore::complaint_standings`), so the two cannot disagree.
#[component]
pub fn StoreRecord(store_contract_id: Vec<u8>) -> Element {
    let rows: Vec<ComplaintRow> = APP_STATE
        .read()
        .browsing_stores
        .get(&store_contract_id)
        .map(|store| {
            store
                .complaint_standings()
                .map(|(complaint, standing)| ComplaintRow {
                    standing,
                    complaint: complaint.clone(),
                    store_name: None,
                })
                .collect()
        })
        .unwrap_or_default();
    let counted = rows.iter().filter(|r| r.standing.counts()).count();

    rsx! {
        div { class: "store-record",
            if rows.is_empty() {
                p { class: "text-muted", "No complaints." }
            } else {
                p { class: "section-count",
                    "{counted} complaint(s) counted, of {rows.len()} on record"
                }
                for row in rows.iter() {
                    ComplaintCard { row: row.clone() }
                }
            }
            p { class: "text-muted small",
                "A record holds complaints only, as categories, with no free text. Each one "
                "names an order that the order's own Bitcoin bridges say was paid, and only that "
                "order's buyer can make it, so a stranger cannot make one up and the seller "
                "cannot take one down."
            }
            p { class: "text-muted small",
                "What it cannot tell you: the seller chooses which bridges their orders trust, so "
                "a seller who pays themselves through a bridge they run can put orders, and "
                "complaints, on their own record. And a record with no complaints says nothing "
                "about the orders nobody complained about."
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
    let block = complaint.block_height;
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
