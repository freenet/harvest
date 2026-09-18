use serde::{Deserialize, Serialize};

/// Category of negative feedback.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum FeedbackCategory {
    NonDelivery,
    Misrepresented,
    Counterfeit,
    Other(String),
}

/// A feedback token: the plaintext that gets blind-signed by the seller.
///
/// The buyer creates this, blinds it, sends the blinded version to the seller for
/// signing, then unblinds the signature. The unblinded token + signature can later
/// be submitted to the seller's reputation contract as negative feedback.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FeedbackToken {
    /// Which reputation contract this token targets (ContractInstanceId bytes).
    pub target_reputation_contract: [u8; 32],
    /// Unique nonce to prevent replay. One token carries at most one piece of
    /// feedback, and this is how the reputation contract names that slot.
    pub nonce: [u8; 32],
    /// Ed25519 verifying key of a keypair the buyer generates fresh for this
    /// token and keeps the secret half of.
    ///
    /// The seller's blind signature covers the token, so it covers this key,
    /// and the key in turn signs the whole feedback entry (see
    /// [`crate::reputation::FeedbackEntry::entry_signature`]). That is what
    /// makes the category, the comment and the timestamp part of what was
    /// signed. Before this field existed the RSA signature covered the token
    /// alone, so anyone reading a published entry could re-submit the token
    /// with different words (harvest#22).
    ///
    /// Fresh per token so it links nothing: the seller never sees the token
    /// unblinded until the feedback is published, and a key reused across
    /// tokens would tie a buyer's feedback together.
    pub entry_key: [u8; 32],
}

/// Protocol messages for the feedback token exchange, sent via encrypted mailbox.
///
/// Flow:
/// 1. Buyer creates a `FeedbackToken`, blinds it, sends `Request` to seller
/// 2. Seller blind-signs it (can't see the actual token), sends `Response` back
/// 3. Buyer unblinds the signature -- now holds a valid signature the seller can't link
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum FeedbackTokenMsg {
    /// Buyer -> Seller: "Here's my blinded token for your reputation contract"
    Request {
        blinded_token: Vec<u8>,
        target_reputation_contract: [u8; 32],
    },
    /// Seller -> Buyer: "Here's my blind signature on your token"
    Response { blind_signature: Vec<u8> },
}
