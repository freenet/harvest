use dioxus::prelude::*;
use harvest_common::feedback::FeedbackCategory;
use harvest_common::reputation::Complaint;

use crate::fulfilment::ComplaintStanding;
use crate::gateway::APP_STATE;
use crate::state::RecordLoad;

/// One complaint as a reader sees it: what it says, and how it counts.
#[derive(Clone, PartialEq)]
pub(crate) struct ComplaintRow {
    pub(crate) complaint: Complaint,
    pub(crate) standing: ComplaintStanding,
    store_name: Option<String>,
}

/// A store's complaints, sorted the way its record shows them: the ones this
/// reader judges (counted or not, each with its reason), and apart from
/// them the ones about orders paid through a bridge this reader does not
/// recognise (harvest#144), which are never counted.
#[derive(Clone, PartialEq, Default)]
pub(crate) struct RecordSections {
    /// Complaints on orders a recognised bridge attested.
    pub(crate) judged: Vec<ComplaintRow>,
    /// Complaints on orders "paid, per a bridge you don't recognise".
    pub(crate) unrecognised: Vec<ComplaintRow>,
}

impl RecordSections {
    pub(crate) fn of(store: &crate::state::BrowsingStore) -> Self {
        let mut sections = RecordSections::default();
        for (complaint, standing) in store.complaint_standings() {
            let row = ComplaintRow {
                standing,
                complaint: complaint.clone(),
                store_name: None,
            };
            if standing == ComplaintStanding::BridgeNotRecognised {
                sections.unrecognised.push(row);
            } else {
                sections.judged.push(row);
            }
        }
        sections
    }

    /// How many complaints count against the seller: the same number the
    /// store's badge shows (`BrowsingStore::counted_complaints`).
    pub(crate) fn counted(&self) -> usize {
        self.judged.iter().filter(|r| r.standing.counts()).count()
    }
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
    let (sections, empty_text): (RecordSections, String) = APP_STATE
        .read()
        .browsing_stores
        .get(&store_contract_id)
        .map(|store| (RecordSections::of(store), empty_record_text(store.record)))
        .unwrap_or_else(|| {
            (
                RecordSections::default(),
                empty_record_text(RecordLoad::Loading),
            )
        });
    let counted = sections.counted();
    let judged = sections.judged.len();
    let unrecognised = sections.unrecognised.len();

    rsx! {
        div { class: "store-record",
            if judged == 0 && unrecognised == 0 {
                p { class: "text-muted", "{empty_text}" }
            } else if judged == 0 {
                p { class: "section-count", "No complaints counted" }
            } else {
                p { class: "section-count",
                    "{counted} complaint(s) counted, of {judged} on record"
                }
                for row in sections.judged.iter() {
                    ComplaintCard { row: row.clone() }
                }
            }
            if unrecognised > 0 {
                p { class: "section-count",
                    "Not counted: {unrecognised} paid, per a bridge you don't recognise"
                }
                p { class: "text-muted small",
                    "These complaints are about orders that a Bitcoin bridge this app does not "
                    "recognise says were paid. Anyone can run a bridge, the seller included, and "
                    "one run by the seller can say an order was paid when it was not. So these "
                    "are shown here, and not counted."
                }
                for row in sections.unrecognised.iter() {
                    ComplaintCard { row: row.clone() }
                }
            }
            p { class: "text-muted small",
                "A record holds complaints only, as categories, with no free text. Each one "
                "names an order that a Bitcoin bridge says was paid, and only that order's buyer "
                "can make it, so a stranger cannot make one up and the seller cannot take one "
                "down. A complaint is counted only if every bridge its order names is one this "
                "app recognises."
            }
            p { class: "text-muted small",
                "What it cannot tell you: a seller who pays themselves through a bridge this app "
                "recognises can still put orders, and complaints, on their own record. And a "
                "record with no complaints says nothing about the orders nobody complained about."
            }
        }
    }
}

/// What a record with no complaints to show says. "No complaints" only once
/// the record has been read; until then, the same words as the store's badge
/// (`RecordLoad::badge`), so opening the record never turns "Record
/// unavailable" into a clean reading (review round 1 of #143, P1-5).
fn empty_record_text(record: RecordLoad) -> String {
    match record {
        RecordLoad::Loaded => "No complaints.".to_string(),
        other => format!("{}.", other.badge(0).1),
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
        // Listed under its own heading, which says why (`StoreRecord`).
        ComplaintStanding::BridgeNotRecognised => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening an unread record never reads as clean: only a loaded record
    /// with nothing in it says "No complaints". Red if the empty text ignores
    /// the load state.
    #[test]
    fn an_unread_record_is_not_called_clean() {
        assert_eq!(empty_record_text(RecordLoad::Loaded), "No complaints.");
        for unread in [
            RecordLoad::Loading,
            RecordLoad::NotFound,
            RecordLoad::Unavailable,
        ] {
            let text = empty_record_text(unread);
            assert!(!text.contains("No complaints"), "{unread:?}: {text}");
            assert_eq!(text, format!("{}.", unread.badge(0).1));
        }
    }
}
