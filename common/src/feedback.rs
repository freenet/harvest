use serde::{Deserialize, Serialize};

/// What a buyer's complaint says went wrong (harvest#53 Phase C).
///
/// Categories only, and no `Other(String)`: that was a second free-text
/// field wearing a hat, and the record a complaint lands on is permanent,
/// public and unmoderatable (harvest#53 design, section 7, decision 2).
/// Adding a variant changes what every existing complaint's signed bytes can
/// mean to a reader, so it is a product decision, not a code change.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum FeedbackCategory {
    NonDelivery,
    Misrepresented,
    Counterfeit,
}

impl FeedbackCategory {
    /// Every category, in the order a form offers them.
    pub const ALL: [FeedbackCategory; 3] = [
        FeedbackCategory::NonDelivery,
        FeedbackCategory::Misrepresented,
        FeedbackCategory::Counterfeit,
    ];
}
