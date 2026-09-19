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
///
/// `Debug` prints the target contract and redacts `nonce` and `entry_key`
/// (harvest#94): printed beside the blinded token the buyer sent the seller,
/// they undo the unlinkability blind signing provides. Until the entry is
/// published they are the buyer's private knowledge.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct FeedbackToken {
    /// Which reputation contract this token targets (ContractInstanceId bytes).
    pub target_reputation_contract: [u8; 32],
    /// Names the token's one feedback slot, and prevents replay. It is NOT
    /// chosen freely: it must be [`FeedbackToken::nonce_for`] the token's
    /// `entry_key`, and the reputation contract refuses any token where it is
    /// not. Build tokens with [`FeedbackToken::new`].
    ///
    /// # Why the slot is bound to the key (PR #82 review, Must Fix 1)
    ///
    /// The seller holds the RSA key, so the seller can blind-sign a token of
    /// its own at any time. While the nonce was free, the seller could mint a
    /// token carrying a buyer's PUBLISHED nonce and the seller's own
    /// `entry_key`, sign a neutered entry with it, and grind that key until
    /// the entry's encoding sorted first -- and the one-entry-per-slot
    /// tie-break would then pick the seller's entry on every peer. Deriving
    /// the nonce from the key makes the slot a function of the key: reaching
    /// a published slot with a different key needs a BLAKE3 preimage, so only
    /// the holder of the original key can put a second entry in it.
    ///
    /// Keying slots by the whole token's digest was the alternative. It closes
    /// the same hole, but it gives up "one token, one slot": the replay check
    /// and the tie-break would then apply only to byte-identical tokens,
    /// which is a weaker statement to reason about than a slot per key.
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

impl FeedbackToken {
    /// The nonce a token with this `entry_key` must carry: a domain-separated
    /// BLAKE3 of the key. See the `nonce` field.
    pub fn nonce_for(entry_key: &[u8; 32]) -> [u8; 32] {
        blake3::derive_key("harvest feedback token nonce v1", entry_key)
    }

    /// A token for `target_reputation_contract` whose slot is bound to
    /// `entry_key`.
    pub fn new(target_reputation_contract: [u8; 32], entry_key: [u8; 32]) -> Self {
        Self {
            target_reputation_contract,
            nonce: Self::nonce_for(&entry_key),
            entry_key,
        }
    }
}

// Keep this AFTER `impl FeedbackToken`. Rustc numbers a module's impl blocks
// in source order and the number is part of each method's symbol, so placing
// it first renames `nonce_for` in the reputation contract's WASM and re-keys
// that contract (measured on harvest#96).
impl core::fmt::Debug for FeedbackToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use crate::delegate::Redacted;
        f.debug_struct("FeedbackToken")
            .field(
                "target_reputation_contract",
                &self.target_reputation_contract,
            )
            .field("nonce", &Redacted)
            .field("entry_key", &Redacted)
            .finish()
    }
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
