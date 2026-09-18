//! Bitcoin payment types for Harvest orders.
//!
//! # Where the trust boundaries fall
//!
//! An [`Order`] is **shared marketplace state**. It lives in the seller's
//! store contract and is public, because decentralized payment verification
//! requires everyone to agree on what was owed and where it was to be paid.
//! That is a very different thing from a user's private list of addresses they
//! happen to be interested in, which never appears in any contract at all —
//! see the Harvest delegate.
//!
//! # How an order becomes Paid
//!
//! Not by the seller's say-so, and not by the buyer's. The transition carries
//! an [`OrderPaymentProof`]: the actual bridge-signed Bitcoin observations,
//! plus a bridge-signed chain tip to measure confirmations against. Any peer
//! can verify it, so any peer can submit it — the buyer's own client normally
//! does.
//!
//! # What the proof is trusted for
//!
//! **The bridges named in the order are trusted for chain state.** They assert
//! which blocks are on Bitcoin, what height each is at, and where the tip is,
//! and nothing in this verification checks any of that against the network.
//! Confirmation depth is arithmetic over two of those assertions — the claim's
//! `anchor.height` and the signed tip's height. A holder of a trusted bridge
//! key can therefore settle an order that was never paid, which is why the
//! trusted-bridge list is part of what the seller signs and why the UI flags
//! bridges the build does not recognise.
//!
//! The SPV evidence inside each claim is still doing real work: it fixes the
//! amount and the destination out of the transaction the txid commits to, and
//! the claim is bound to this order's script and network. So a bridge cannot
//! misreport what a real transaction paid, or to whom, and cannot repoint
//! somebody else's payment at this order. That is defence in depth against a
//! lying bridge, not a substitute for trusting one — see
//! `freenet_bitcoin_common::spv` for the boundary in full.
//!
//! ## Why the proof is embedded rather than fetched
//!
//! Harvest *does* use Freenet's related-contract mechanism to reach the
//! `BitcoinAddressContract` (see the store contract's `validate_state`), but
//! the authoritative gate is the embedded proof, and that is deliberate.
//!
//! A contract's verdict has to be a pure function of its own inputs, or
//! replicas that evaluate it at different moments reach different answers and
//! never converge. Related state is not under this contract's control: a peer
//! whose copy of the Bitcoin contract has not caught up yet would judge a
//! perfectly good order invalid. Embedding the signed claims makes validity
//! self-contained and monotonic — once a proof verifies it verifies forever,
//! on every peer, regardless of replication timing.
//!
//! The related contract is therefore used for **discovery and
//! cross-checking**, never as the thing that can make existing state invalid.
//!
//! ### What embedding costs
//!
//! Self-containment cuts both ways: the evidence a verifier sees is the
//! evidence the *submitter chose to send*, and no check inside a pure function
//! can distinguish a complete claim set from a curated one. That is a real,
//! currently-open gap, written up on [`OnChainPaymentProof`] along with why it
//! cannot be closed here and what would close it.
//!
//! ## What happens if the payment is later reorged out
//!
//! Nothing retroactively invalidates the order, because that would mean state
//! flipping from valid to invalid and replicas disagreeing about which. The
//! reorg is instead expressed as a *further* transition, [`OrderStatus::PaymentReversed`],
//! carried by its own evidence at a higher chain height. Status only ever
//! moves forward, which is what keeps the merge monotonic.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::{
    fold_outpoint_status, BitcoinAddressParameters, BitcoinNetwork, BlockAnchor, BridgeId, Claim,
    OutpointStatus, SignedClaim, SignedTipEntry,
};
use serde::{Deserialize, Serialize};

/// Unique order identifier: a hash of the order's own TERMS.
///
/// # Why the identity is the content
///
/// It used to be `BLAKE3(seller_fingerprint || listing_id || created_at_ms ||
/// buyer_fingerprint)` -- and **nothing else**. Not the amount, not the
/// script, not the payment address. So one seller could sign two
/// differently-termed, individually valid orders that shared an id, and they
/// collided on one key of [`crate::store::OrdersV1`]'s map.
///
/// The collision was not a draw. `merge_order` resolves an equal-rank tie by
/// keeping the lexicographically SMALLER CBOR encoding, which is
/// deterministic -- and directional. A seller could publish the larger
/// encoding, let it propagate and be read, then publish the smaller one,
/// which wins on every replica and permanently. Applied to the buy flow that
/// reads: show the buyer an order at address A, wait for them to pay it, then
/// replace the terms with address B. The public record ends up describing a
/// destination that never received anything, so the payment is unprovable and
/// the declared debt the buyer relied on describes a different transaction.
///
/// The smaller-CBOR rule is not the defect and must not be changed to fix
/// this -- it exists so that a third party cannot win a tie by PADDING a
/// payment proof, and it is correct for that. The defect is that two
/// different things were allowed to be one thing. Deriving the id from the
/// terms makes them two orders, so there is no tie to resolve, and it is the
/// same remedy the mailbox needed when message identity moved to
/// `entry_digest`: **identity is the content, or something will eventually
/// change under it.**
///
/// # What it covers, and why there is no list
///
/// The whole encoded struct, with the id blanked. Written that way rather
/// than as a chosen list of fields because a list is a thing somebody adds a
/// field beside -- which is exactly how the old preimage came to omit the
/// amount and the address. A field added to [`Order`] tomorrow is inside the
/// preimage without anybody remembering to put it there.
///
/// **With one exception, which is the way to break this.** `#[serde(skip)]`
/// omits a field from `to_cbor` entirely, so it would be outside both this
/// preimage AND the signature comparison in
/// [`AuthorizedOrder::verify_terms`] -- a field free to vary under a fixed id
/// and a valid signature, which is the swap attack again. `serde(default)`
/// and `skip_serializing_if` are both fine: they still encode when set, so
/// they are inside the digest. Do not put `#[serde(skip)]` on a field of
/// [`Order`]. The compiler will not stop you; the guard one level up
/// (`verify_unused_fields_absent`, which destructures without `..`) covers
/// `AuthorizedOrder` and not this struct.
///
/// # Why 32 bytes and not 16
///
/// It was 16, and the residual was recorded rather than fixed. That was the
/// wrong call and it is corrected here, because of what the attack actually
/// needs. Finding a SECOND PREIMAGE for an id a buyer already holds is 2^128
/// and out of reach -- but the swap above needs only a COLLISION between two
/// orders the SELLER chooses, and at 16 bytes that is ~2^64. Expensive, not
/// impossible for a motivated party over months, against a payoff of a
/// stolen payment sitting behind a public record that says unpaid. The
/// buyer-side binding does not help: a seller can put the buyer's
/// [`Order::order_binding`] on both halves of a collision.
///
/// At 32 bytes the collision cost is 2^128 and the question closes.
///
/// **The width was changed here because this is the one moment it is free.**
/// The branch re-keys every contract, so every published order is already
/// crossing a migration boundary; afterwards the same change would cost a
/// re-key plus a migration of its own. What it costs at this boundary is
/// recorded honestly in `docs/untested-invariants.md`: an order published at
/// the old width does not decode into this type at all, so it does not
/// survive the re-key. Orders are short-lived by construction -- they expire
/// after [`MAX_ANCHOR_AGE_BLOCKS`] -- which is what makes that acceptable
/// for orders and NOT what makes it acceptable for listings; see
/// [`ListingId`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct OrderId(pub [u8; 32]);

impl OrderId {
    /// The id these terms give.
    ///
    /// Idempotent: the id field is blanked before hashing, so computing this
    /// on an order that already carries the answer gives the same answer --
    /// which is what lets [`AuthorizedOrder::verify`] demand that they match.
    pub fn from_terms(order: &Order) -> Self {
        let mut probe = order.clone();
        probe.id = Self([0u8; 32]);
        // Infallible for the same reason as `order_content_digest`: `Order`
        // derives `Serialize` over plain data with no custom fallible
        // encoding.
        let terms = crate::to_cbor(&probe).expect("Order always serializes to CBOR");
        let mut h = blake3::Hasher::new();
        h.update(b"harvest/order-id/v2");
        h.update(&terms);
        Self(*h.finalize().as_bytes())
    }

    /// Short, human-quotable form for the UI ("Order 3xK9…").
    pub fn short(&self) -> String {
        bs58::encode(&self.0[..4]).into_string()
    }
}

impl std::fmt::Display for OrderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

/// Where an order stands. Transitions only ever move forward.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum OrderStatus {
    /// Created; the buyer has not paid, or the payment is not yet visible.
    AwaitingPayment,
    /// A qualifying payment has been proven on chain.
    Paid,
    /// A previously-proven payment was reorged out of the chain.
    ///
    /// This exists so a reorg is a forward transition rather than a
    /// retroactive invalidation. Making the order *invalid* instead would mean
    /// a peer's verdict changing under it, which is precisely what stops
    /// replicas converging.
    PaymentReversed,
    /// Cancelled by the seller before payment.
    Cancelled,
}

impl OrderStatus {
    /// Rank used to keep status monotonic under merge. A merge takes the
    /// higher rank, so two peers that saw transitions in different orders
    /// still agree.
    ///
    /// # The invariant this ordering has to hold
    ///
    /// **No status a party can assert by signature may outrank one that is
    /// evidenced by Bitcoin.** Rank is permanent -- a merge never comes back
    /// down -- so whatever sits at the top is what the order says forever,
    /// and putting a self-signed status there hands one party a veto over the
    /// chain.
    ///
    /// There used to be a `Fulfilled` at rank 4, above `PaymentReversed`, and
    /// it was seller-signed. A seller could therefore bury a genuine reorg
    /// under a status they issued themselves, and a scammer could mark every
    /// order fulfilled and read as carrying no outstanding exposure at all --
    /// which is what the bond in `docs/design/incentive-mechanism.md` is
    /// measured against. It is deleted rather than demoted: below `Paid` it
    /// would be unreachable in practice, since it is only ever meaningful
    /// after payment, and a status that cannot survive its own merge is worse
    /// than no status.
    ///
    /// `Cancelled` is seller-signed too, but it outranks only
    /// `AwaitingPayment` and is beaten by `Paid`, so a payment always
    /// overrides a cancellation. That is the right direction.
    pub fn rank(self) -> u8 {
        match self {
            OrderStatus::AwaitingPayment => 0,
            OrderStatus::Cancelled => 1,
            OrderStatus::Paid => 2,
            OrderStatus::PaymentReversed => 3,
        }
    }
}

/// How far behind the tip an order's [`Order::anchor`] may be and still be
/// treated as fresh by a buyer about to pay.
///
/// # Why a buyer checks this at all
///
/// A block hash proves the commitment was signed *no earlier than* that
/// block. It is a lower bound and nothing more, and every past block hash is
/// public -- so a seller can anchor a fresh commitment to an old block and
/// have readers count it as already closed, reading as zero outstanding
/// exposure while taking money. `docs/design/incentive-mechanism.md` argues
/// this cannot happen; it is wrong, and GitHub issue 8 records the
/// correction. The rule that neutralises it is this one, applied by the buyer
/// before they pay.
///
/// # Why the reader applies it and not the contract
///
/// "Is this recent?" is a question about now, and a contract has no clock. A
/// merge that consulted one would not be a function of its inputs and
/// replicas would diverge. The network stores the anchor; the reader forms
/// the verdict.
///
/// # It is also the order's LIFETIME, which is what sets the number
///
/// This was 6, by analogy with Bitcoin's customary confirmation depth. Review
/// pointed out that the analogy is the wrong one, because the anchor is
/// stamped when the seller signs and is immutable under their signature -- so
/// the rule is not only a backdating guard, it is how long an accepted order
/// stays payable. At 6 blocks an honest buyer who came back after lunch found
/// their order refused, with no way for either party to see why and no way to
/// reissue.
///
/// So the number is set by the SHORTER of two requirements:
///
/// * **Long enough to buy something.** A person is offered a Bitcoin address
///   and has to reach a wallet. An hour is not that; a working day is.
/// * **Short enough that backdating buys nothing.** A seller who anchors an
///   old block gets readers to stop counting the order that much earlier.
///   What that is measured against is the complaint window, which Phase 2
///   sets and which is certainly days rather than hours -- so a few hours of
///   slack is noise, while an hour of buyer patience is not.
///
/// 48 blocks is about eight hours and satisfies both. Nothing here depends on
/// the exact number, and everything that reads it derives from it rather than
/// repeating it -- see `harvest_ui::state::RECENT_BLOCKS_KEPT`.
///
/// **It cannot exceed the tip contract's retention.** A reader checks the
/// anchor is on their chain by looking the height up in the block summaries
/// the tip contract keeps, and that is `TIP_RETAIN` deep. A tolerance wider
/// than the retention would accept anchors nobody can check, which is the
/// unverified-reads-as-verified direction. Held by the assertion below rather
/// than by this paragraph.
pub const MAX_ANCHOR_AGE_BLOCKS: u32 = 48;

/// A fresh anchor must be one a reader can still check against their own
/// chain.
///
/// A build failure rather than a test, because the two constants live in
/// different crates and the failure it prevents is silent: an anchor inside
/// the tolerance but outside the retained window reads as unverifiable, which
/// refuses payment for a reason no user or seller could act on.
const _: () = assert!(
    (MAX_ANCHOR_AGE_BLOCKS as usize) < freenet_bitcoin_common::TIP_RETAIN,
    "the freshness tolerance must fit inside the tip contract's retained window"
);

/// How long after an order's anchor a buyer's payment may take to confirm and
/// still be this order's payment, beyond the time the buyer has to send it.
///
/// Two weeks of blocks, because that is Bitcoin Core's default mempool expiry
/// (`-mempoolexpiry=336` hours): a transaction still unconfirmed after that is
/// dropped from default mempools, so an honest payment either confirms within
/// it or has, for practical purposes, stopped trying. A low-fee payment during
/// congestion can genuinely take days, and a payment refused for landing
/// late is the buyer's money arriving with nothing on the public record to
/// say so, which is why this is generous rather than tight.
pub const PAYMENT_CONFIRMATION_SLACK_BLOCKS: u32 = 2016;

/// How many blocks after an order's anchor a payment may confirm and still
/// settle it: see [`Order::payment_window`].
///
/// [`MAX_ANCHOR_AGE_BLOCKS`] is how long a buyer will still SEND to the order
/// (their software refuses older anchors), and
/// [`PAYMENT_CONFIRMATION_SLACK_BLOCKS`] is how long a payment sent at the
/// last moment may take to confirm.
///
/// # What it costs, stated plainly
///
/// The window is also the span over which a REUSED address is dangerous: two
/// orders on one address whose anchors are closer than this can both be
/// settled by one payment that confirms inside both windows (harvest#83
/// review, Must Fix 1). Narrowing it shrinks that span and strands more
/// honest late payments; the address recovery and the address-contract check
/// in the UI are what make reuse rare enough to take the generous side.
pub const PAYMENT_WINDOW_BLOCKS: u32 = MAX_ANCHOR_AGE_BLOCKS + PAYMENT_CONFIRMATION_SLACK_BLOCKS;

/// The immutable terms of an order, as agreed and published by the seller.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Order {
    pub id: OrderId,
    // No listing id: anyone who can read the store could join it to the
    // store's public listings and read off a per-product sales record
    // (harvest#57). `listing_tag` below says which listing it is, to the two
    // parties only.
    /// Ghostkey fingerprint of the buyer this invoice was issued to.
    pub buyer_fingerprint: String,
    pub seller_fingerprint: String,
    pub amount_sats: u64,
    pub network: BitcoinNetwork,
    /// Canonical `scriptPubKey` the payment must reach.
    ///
    /// Public, and necessarily so: without it no third party could verify the
    /// payment, which is the entire point. This is why it is not a privacy
    /// regression — it is application semantics requiring publication, not a
    /// watch list being leaked.
    pub payment_script_pubkey: Vec<u8>,
    /// Human-readable address form, carried for display only. Verification
    /// always uses `payment_script_pubkey`; several address encodings can
    /// denote the same script, and only the script appears on chain.
    pub payment_address: String,
    /// Confirmations required before this order counts as paid. On-chain only;
    /// a Lightning payment is final the moment the preimage exists.
    pub required_confirmations: u32,
    /// For a Lightning order, the invoice's payment hash.
    ///
    /// Public for the same reason a scriptPubKey is: without it nobody but the
    /// two parties could verify the payment, which defeats the purpose.
    /// `#[serde(default)]` so orders written before this field existed still
    /// decode.
    #[serde(default)]
    pub payment_hash: Option<[u8; 32]>,
    /// The Bitcoin bridges whose observations settle *this* invoice.
    ///
    /// # Why this is per-order and not a store parameter
    ///
    /// It used to be `StoreParameters::trusted_bitcoin_bridges`. A contract's
    /// parameters are hashed into its address, so that list was immutable for
    /// the store's whole life: a store created with an empty list could never
    /// accept an on-chain payment, ever, and a bridge that went away could
    /// never be replaced. Every store the UI creates was in exactly that
    /// state.
    ///
    /// Moving it to *mutable state* would have been worse. `OrdersV1::verify`
    /// re-checks every order against the list on every state validation, so
    /// rotating a mutable list would retroactively invalidate the entire
    /// historical order book — a peer's verdict changing under it, which is
    /// precisely what stops replicas converging.
    ///
    /// Per-order, both problems go away at once. An order is verified forever
    /// against the bridge set that was in force when the seller signed it, and
    /// a new order can name a new set. A bridge going dark costs the orders
    /// already open against it, not the store.
    ///
    /// # What authenticates it
    ///
    /// Nothing new. `AuthorizedOrder::verify_terms` checks a ghostkey-scoped
    /// seller signature over the CBOR of this whole struct, so the bridge set
    /// is signed by the same signature as the amount and the payment address.
    /// A buyer who accepts an invoice is accepting its bridges along with its
    /// price, which is why the UI shows them (see `OrderCard`).
    ///
    /// Empty means no payment can ever be proven — `verify_payment_proof`
    /// returns `NoTrustedBridges` outright — so an order that names no bridge
    /// fails closed rather than accepting an unattested claim.
    ///
    /// `#[serde(default)]` so orders written before this field existed still
    /// decode; they come back with no bridges, i.e. unpayable, which is the
    /// safe direction.
    #[serde(default)]
    pub trusted_bridges: Vec<BridgeId>,
    /// BLAKE3 hash of the `BitcoinAddressContract` WASM whose instance
    /// observes this order's payment address.
    ///
    /// Used only for the store contract's related-contract cross-check, which
    /// is additive-only (see that file's `validate_state`). The store contract
    /// never holds the Bitcoin contract's WASM, so it has to be told the hash;
    /// `None` simply skips the cross-check for this order and forfeits nothing
    /// else, since the embedded [`OrderPaymentProof`] stays authoritative
    /// either way.
    ///
    /// Per-order for the same reason as `trusted_bridges`: as a store
    /// parameter it was frozen at the store's address, so a rebuild of the
    /// Bitcoin contract could never be reflected.
    #[serde(default)]
    pub bitcoin_address_code_hash: Option<[u8; 32]>,
    /// A recent Bitcoin block this commitment is anchored to.
    ///
    /// # What it is for
    ///
    /// The order commitment is the anti-exit-scam mechanism
    /// (`docs/design/incentive-mechanism.md` Part 5, step 2): it makes a
    /// seller's outstanding exposure countable by strangers, so a buyer can
    /// see that more is staked than they are about to risk. Counting requires
    /// deciding which commitments are still open, and that is a question
    /// about time.
    ///
    /// **A contract cannot read a clock**, and a timestamp the writer chooses
    /// is not a clock either -- it is an assertion by the one party with a
    /// motive to lie about it. `created_at` is exactly that, which is why it
    /// is not used for this. A block hash is the substitute: it proves the
    /// commitment was signed *no earlier than* that block, and the reader's
    /// own clock supplies the rest.
    ///
    /// # What it does NOT prove, and the direction it fails in
    ///
    /// It is a lower bound only. Every past block hash is public, so a seller
    /// can anchor a fresh commitment to an old block and have readers close
    /// it immediately -- reading as zero exposure while taking orders. The
    /// design document is wrong where it argues otherwise, and issue 8
    /// records the correction.
    ///
    /// The rule that neutralises it lives in the READER, because only a
    /// reader has a clock: a buyer pays only if the anchor is canonical on
    /// the chain they see and is within [`MAX_ANCHOR_AGE_BLOCKS`] of the tip.
    /// See `harvest_ui::state::AppState::payment_blockers`. This field
    /// carries the fact; the verdict is not a contract's to form.
    ///
    /// # The one thing the contract DOES use it for
    ///
    /// A comparison between two heights, which needs no clock: a payment that
    /// confirmed at or below this block was made before the order, so it does
    /// not settle it (harvest#77, and `verify_on_chain_proof`). Backdating the
    /// anchor only widens what the SELLER's own order accepts, so the seller
    /// has no reason to; the rule protects the seller from their own address
    /// being issued twice, not the buyer from the seller.
    ///
    /// # Why `Option`, and why it skips when absent
    ///
    /// `None` for every order signed before this field existed.
    /// [`AuthorizedOrder::verify_terms`] re-serializes this struct and
    /// compares the result against the payload inside the signed
    /// `ScopedPayload`, so a field that serialized when absent would change
    /// the preimage of every earlier signature and the store contract would
    /// reject the seller's own published invoices. Pinned by
    /// `order_wire_compat_tests::an_order_that_predates_the_anchor_re_encodes_unchanged`,
    /// which was observed red against the naive `#[serde(default)]`-only
    /// form.
    ///
    /// A buyer refuses to pay an order with no anchor, and an on-chain proof
    /// for one is refused (`ProofError::NoAnchor`), so absence is the safe
    /// direction rather than a silent downgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<BlockAnchor>,
    /// What makes this commitment ONE buyer's rather than anyone's.
    ///
    /// # The hole this closes
    ///
    /// Nothing else here names a particular buyer -- `buyer_fingerprint` is
    /// empty for every order the buy flow produces, because a buyer has no
    /// identity. So without this a seller could accept one order, publish one
    /// commitment, and send its id down any number of conversations: every
    /// buyer's software found it published, signed, fresh and for a listing
    /// they had asked about, and showed them all the same payment address.
    /// One declared debt collecting unbounded money inverts the mechanism the
    /// commitment exists for, since a count that does not bound the money is
    /// not a count.
    ///
    /// This is `H(n)` from `docs/design/incentive-mechanism.md` and issue 8:
    /// the buyer sends it with the request, the seller copies it here, and
    /// the buyer refuses to pay a commitment that does not carry the value
    /// their own node derives. See
    /// [`crate::mailbox::order_binding_from_secret`] for where `n` comes
    /// from, why the seller cannot compute it, and why publishing `H(n)`
    /// reveals nothing.
    ///
    /// # Why `Option`, and why it skips when absent
    ///
    /// Exactly as for [`Self::anchor`], and for the same signature reason:
    /// [`AuthorizedOrder::verify_terms`] re-serializes this struct, so a
    /// field that encoded when absent would break every signature taken
    /// before it existed.
    ///
    /// A buyer refuses an unbound commitment, so `None` fails closed rather
    /// than matching everyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_binding: Option<[u8; 32]>,
    /// Which listing this order is for, as only its buyer and seller can tell:
    /// [`crate::mailbox::listing_tag`] over the conversation's key and the
    /// listing id. `None` for an invoice that answers no request.
    ///
    /// Published and signed, like `order_binding` beside it, because "which
    /// request does this order answer" has to rest on the seller's published
    /// record: a mailbox message can be lost or evicted, and a seller who could
    /// not see their own answer would be offered to publish a second order.
    ///
    /// `#[serde(default, skip_serializing_if)]` for the same reason as the
    /// fields above: an order without it must encode exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_tag: Option<[u8; 32]>,
    pub created_at: DateTime<Utc>,
}

impl Order {
    /// Stamp this order with the id its own terms give.
    ///
    /// Every producer of an `Order` must go through this, because
    /// [`AuthorizedOrder::verify_terms`] refuses a record whose id is not the
    /// one its terms give -- so an order built any other way is one no peer
    /// will accept. Taking `self` and returning it makes the stamping part of
    /// construction rather than a step a caller can forget after filling the
    /// struct in.
    #[must_use]
    pub fn with_derived_id(mut self) -> Self {
        self.id = OrderId::from_terms(&self);
        self
    }

    /// The block heights at which a confirmation can be this order's payment:
    /// strictly after the anchor, and at most [`PAYMENT_WINDOW_BLOCKS`] after
    /// it. `None` for an order with no anchor, which no on-chain payment can
    /// settle.
    ///
    /// # Why each edge is where it is
    ///
    /// **The lower edge excludes the anchor block itself.** The seller signs
    /// only after seeing the anchor block, and the buyer learns the address
    /// only from the signed order, so an honest payment confirms at
    /// `anchor + 1` at the earliest; anything at or below the anchor was
    /// broadcast before the order existed and paid for something else. That
    /// is harvest#77: a reissued address already held an old invoice's
    /// confirmed payment. The one honest payment this refuses needs a reorg
    /// that replaces the anchor block with one carrying the buyer's
    /// transaction; the order then names a block no longer on the chain. That
    /// buyer HAS paid, so refusing strands their payment rather than merely
    /// costing a reissue, and it is accepted only because it needs a reorg at
    /// exactly the anchor height within minutes of the order.
    ///
    /// **The upper edge exists so one payment cannot settle two orders.**
    /// Without it, an OLDER order on a reused address would be settled by the
    /// NEWER order's payment, since that payment also confirmed after the old
    /// order's anchor. A per-order bound is the merge-safe way to say this: a
    /// rule across orders ("no outpoint settles two") would let two peer
    /// states that are each valid become invalid when merged, and a `Paid`
    /// record cannot be demoted under the max-rank merge.
    ///
    /// Used by the verifier and by the UI's own reading of an address, so the
    /// card a seller reads and the rule that settles the order agree.
    pub fn payment_window(&self) -> Option<std::ops::RangeInclusive<u32>> {
        let anchor = self.anchor?.height;
        Some(anchor.saturating_add(1)..=anchor.saturating_add(PAYMENT_WINDOW_BLOCKS))
    }

    /// The instance id of the `BitcoinAddressContract` that observes this
    /// order's payment destination, or `None` when the order names no
    /// contract build.
    ///
    /// # Why this is HERE and not at either call site
    ///
    /// Two things need it and they are in different crates: the store
    /// contract, to cross-check an order against the address contract's own
    /// state, and the UI, so a buyer can see what has already arrived at the
    /// address they are about to pay. A hand-maintained second copy of a
    /// contract-address derivation is the defect this repository ranks first
    /// in `docs/untested-invariants.md` -- `create_store_contracts` held one
    /// for the store's own parameters, and when the copies drifted every
    /// derived id named a contract that was never published, reported as a
    /// clean "nothing to migrate" over a seller's entire store.
    ///
    /// `BLAKE3(code_hash || cbor(parameters))` is not a convention this crate
    /// may choose: it is how Freenet forms a contract's address. A drift
    /// leaves the UI subscribed to an address that does not exist, reporting
    /// "no payment seen" forever.
    ///
    /// `None` rather than a guess when `bitcoin_address_code_hash` is absent.
    /// A default hash would name some other contract, and a buyer would be
    /// shown its balance under their own order.
    pub fn bitcoin_address_instance_id(&self) -> Option<[u8; 32]> {
        let code_hash = self.bitcoin_address_code_hash?;
        // Infallible: `BitcoinAddressParameters` is plain data with a derived
        // `Serialize`.
        let params = crate::to_cbor(&self.bitcoin_params())
            .expect("BitcoinAddressParameters always serializes to CBOR");
        let mut hasher = blake3::Hasher::new();
        hasher.update(&code_hash);
        hasher.update(&params);
        Some(*hasher.finalize().as_bytes())
    }

    /// Parameters of the `BitcoinAddressContract` that observes this order's
    /// payment destination.
    pub fn bitcoin_params(&self) -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: self.network,
            script_pubkey: self.payment_script_pubkey.clone(),
            trusted_bridges: self.trusted_bridges.clone(),
            // Derived from the network rather than carried in the order, so a
            // seller cannot weaken the work floor for their own invoices.
            pow_floor: self.network.default_pow_floor(),
        }
    }
}

/// Bridge-signed evidence that an order's payment reached the *chain*.
///
/// # KNOWN GAP: the claim set is chosen by whoever submits it
///
/// Everything below is checked: each claim carries a bridge signature over a
/// body naming this script and an `as_of` chain position, and the verifier
/// re-runs the same fold the address contract would. What is **not** checked,
/// and cannot be checked with the evidence this type carries, is whether the
/// set is *complete*.
///
/// A submitter who holds a bridge-signed confirmation from before a reorg and
/// the bridge-signed retraction that followed it can present the first and
/// omit the second. Every remaining check passes: the confirmation is
/// genuinely signed, genuinely about this script, and genuinely deep enough
/// against the supplied tip. The fold has nothing to fold it against, so the
/// order validates as `Paid` on a payment that is no longer on the chain.
///
/// The same omission runs in the other direction, and that one is worse
/// because `PaymentReversed` is permanent under merge. If a payment was
/// confirmed, reorged out, and then re-confirmed on the new chain, the bridge
/// has published three claims for that outpoint; a submitter can present the
/// first two and withhold the re-confirmation, and the fold then reads a live
/// payment as reversed. `verify_on_chain_proof` requires a reversal to show
/// confirmations covering the order that were themselves retracted, so this
/// is no longer reachable for an order that was never paid -- but for one
/// that WAS paid and survived a reorg, it still is. **That residual is real
/// and is not closed here**; see `verify_on_chain_proof` for exactly what the
/// precondition does and does not buy, and
/// `store::order_tests::a_withheld_reconfirmation_still_reads_as_a_reversal`
/// for the case pinned as a known gap.
///
/// ## Why it cannot be fixed inside this function
///
/// - **The contract may not consult the address contract as an authority.**
///   That is the convergence argument in this module's header, and it is not
///   negotiable: related state replicates on its own schedule, so gating on it
///   would let two peers holding byte-identical state disagree about whether
///   it is valid. The store contract does fetch it (`validate_state`), but
///   only ever to log a discrepancy.
/// - **It cannot be fixed in the merge either**, which is the tempting place,
///   since `merge_order` holds both records and could demand that a reversal's
///   claims be a superset of the `Paid` record's. That breaks convergence in
///   the other direction: a peer that already holds the `Paid` record would
///   reject what a peer holding only `AwaitingPayment` accepts, and the two
///   would never agree.
/// - **A freshness rule is unavailable.** A contract has no clock, so "this
///   tip is recent" is not a question it can ask.
///
/// ## The shape of the real fix
///
/// The missing ingredient is a bridge-signed **commitment to the complete
/// claim set**, which belongs upstream in `freenet-bitcoin` rather than here.
/// `Claim::ScannedTo` already means "I have published everything I found for
/// this script as of `as_of`" and carries no payload; giving it a root over
/// the digests of every claim the bridge holds for that script would make the
/// assertion checkable. Verification here would then require:
///
/// 1. a `ScannedTo` from a trusted bridge whose `as_of.height` is at least the
///    supplied tip's height -- so a current tip cannot be paired with a stale
///    claim set, which is precisely the split this attack relies on; and
/// 2. that recomputing the root over exactly the supplied claims reproduces
///    the signed one -- so omitting any claim is detectable.
///
/// That needs no change to this type's wire format, since `ScannedTo` travels
/// in `claims` like any other claim. It does not close everything: a submitter
/// can still present a matched stale pair (old tip AND old set), but then
/// depth is measured against the old tip, so a reorg shallower than
/// `required_confirmations` no longer suffices.
///
/// Until then, a party acting on `Paid` -- shipping goods, say -- should
/// cross-check the live `BitcoinAddressContract` in its own client rather than
/// trusting the embedded proof alone. That check is unavailable to the
/// contract but perfectly available to an application.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OnChainPaymentProof {
    /// The claims the submitter has chosen to present about the qualifying
    /// outpoints.
    ///
    /// The intent is the bridges' whole published history, not merely the
    /// favourable subset, because the verifier re-runs the same fold the
    /// address contract would and a fold given a curated subset reaches a more
    /// optimistic answer. But nothing here can tell a complete set from a
    /// curated one -- see this type's doc comment.
    ///
    /// Bounded on submission by [`MAX_PROOF_CLAIM_BYTES`] and, after
    /// deduplication, by [`MAX_PROOF_CLAIMS`]. Those bounds sit in tension
    /// with "whole published history": a payment script whose genuine history
    /// runs past 32 distinct claims has no representable proof, and the order
    /// against it cannot be settled. That is the intended trade -- a
    /// per-invoice script that busy is not a payment destination -- but it is
    /// a real edge, and it is the reason the cap is not tighter still.
    pub claims: Vec<SignedClaim>,
    /// A bridge-signed chain tip, so confirmation depth is itself attested
    /// rather than asserted by whoever submitted the proof.
    pub tip: SignedTipEntry,
}

/// Proof that an order was paid, by whichever rail carried the payment.
///
/// # Why this is an enum today rather than when Lightning arrives
///
/// A contract's state format is frozen at publish: changing it produces new
/// WASM, a new contract key, and orphaned state. Adding a second payment rail
/// later would therefore be a migration, not an edit. Shaping the type for it
/// now costs nothing and removes that migration from the future.
///
/// # The two rails verify very differently, and it is worth knowing how
///
/// **On-chain** payments are publicly observable, so proof is a set of
/// bridge-signed observations, each carrying SPV evidence a reader checks
/// against the transaction and the block headers. That check binds the amount
/// and destination to a real transaction; which blocks are on Bitcoin stays
/// the bridges' assertion.
///
/// **Lightning** payments are, by design, *not* publicly observable — there is
/// no on-chain record of a routed payment, so no bridge can watch for one and
/// the entire SPV apparatus has nothing to look at. What Lightning provides
/// instead is the **preimage**: the payer ends up holding `r` where
/// `SHA256(r) == payment_hash`. The order publishes the payment hash (exactly
/// where an on-chain order publishes its scriptPubKey) and the proof is `r`.
/// Verification is a single hash, with no bridge in the picture at all.
///
/// That makes the Lightning path *simpler* to verify, not harder, and it
/// sidesteps the watch-list privacy problem entirely since there is nothing to
/// watch. The genuinely hard part of Lightning is operational — a seller needs
/// an always-on node with inbound liquidity — and none of that difficulty
/// lives in this file.
///
/// ## What the preimage does and does not prove
///
/// It proves the invoice with that hash was settled. It does **not** identify
/// who paid, and the seller who issued the invoice knows `r` from the outset,
/// so a seller can always mark their own order paid. That asymmetry is
/// harmless here because it runs against the seller's own interest: the
/// dispute that actually matters is a seller falsely claiming they were *not*
/// paid, and the buyer refutes that by presenting `r`, which they could only
/// have obtained by settling the invoice.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum OrderPaymentProof {
    OnChain(OnChainPaymentProof),
    Lightning(LightningPaymentProof),
}

impl OrderPaymentProof {
    /// Convenience for the common on-chain case.
    pub fn on_chain(claims: Vec<SignedClaim>, tip: SignedTipEntry) -> Self {
        OrderPaymentProof::OnChain(OnChainPaymentProof { claims, tip })
    }
}

/// The preimage settling a Lightning invoice.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LightningPaymentProof {
    /// `r` such that `SHA256(r)` equals the order's `payment_hash`.
    pub preimage: [u8; 32],
}

/// Why a payment proof was rejected. Distinguished so the UI can say something
/// useful rather than "invalid".
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProofError {
    NoTrustedBridges,
    BadTip(String),
    BadClaim(String),
    /// The tip is for one network and the order for another.
    NetworkMismatch,
    /// The claims are about a script that is not this order's destination.
    WrongScript,
    /// Confirmed, but not deeply enough yet.
    InsufficientConfirmations {
        have: u32,
        need: u32,
    },
    /// Not enough value reached the script.
    InsufficientValue {
        have_sats: u64,
        need_sats: u64,
    },
    /// The most recent evidence says the payment is no longer on chain.
    Reversed,
    /// A Lightning proof was offered for an order that has no payment hash,
    /// or an on-chain proof for one that has no script.
    WrongRail,
    /// `SHA256(preimage)` does not equal the order's payment hash.
    PreimageMismatch,
    /// More distinct claims than [`MAX_PROOF_CLAIMS`], each of which would
    /// cost a signature verification.
    TooManyClaims {
        have: usize,
        cap: usize,
    },
    /// The submitted claims exceed [`MAX_PROOF_CLAIM_BYTES`].
    ClaimsTooLarge {
        have_bytes: usize,
        budget: usize,
    },
    /// An on-chain order with no [`Order::anchor`]: nothing says when it was
    /// made, so no payment can be shown to have come after it.
    NoAnchor,
    /// The value that reached the script confirmed in a block at or below
    /// the order's anchor, i.e. before the order existed. See
    /// [`verify_on_chain_proof`] for why that payment cannot be this order's.
    PaymentPredatesOrder {
        /// The highest block height, among the refused outpoints, at which
        /// one of them confirmed.
        confirmed_at: u32,
        order_anchor: u32,
    },
    /// The value that reached the script confirmed after the order's payment
    /// window closed ([`Order::payment_window`]), so it is not taken as this
    /// order's payment.
    PaymentAfterWindow {
        /// The lowest block height, among the refused outpoints, at which one
        /// of them confirmed.
        confirmed_at: u32,
        window_end: u32,
    },
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::NoTrustedBridges => {
                write!(
                    f,
                    "this store trusts no Bitcoin bridge, so no payment can be proven"
                )
            }
            ProofError::BadTip(e) => write!(f, "chain tip evidence invalid: {e}"),
            ProofError::BadClaim(e) => write!(f, "payment evidence invalid: {e}"),
            ProofError::NetworkMismatch => write!(f, "evidence is for a different Bitcoin network"),
            ProofError::WrongScript => write!(f, "evidence is for a different payment address"),
            ProofError::InsufficientConfirmations { have, need } => {
                write!(f, "payment has {have} confirmations, needs {need}")
            }
            ProofError::InsufficientValue {
                have_sats,
                need_sats,
            } => {
                write!(
                    f,
                    "payment of {have_sats} sats is short of {need_sats} sats"
                )
            }
            ProofError::Reversed => write!(f, "the payment was reorganized off the chain"),
            ProofError::WrongRail => {
                write!(
                    f,
                    "the evidence is for a different payment method than the order"
                )
            }
            ProofError::PreimageMismatch => {
                write!(f, "the preimage does not settle this order's invoice")
            }
            ProofError::TooManyClaims { have, cap } => {
                write!(
                    f,
                    "payment evidence holds {have} distinct claims, cap is {cap}"
                )
            }
            ProofError::ClaimsTooLarge { have_bytes, budget } => {
                write!(
                    f,
                    "payment evidence is {have_bytes} bytes, budget is {budget}"
                )
            }
            ProofError::NoAnchor => write!(
                f,
                "the order names no Bitcoin block it was made at, so no payment can be shown \
                 to have come after it"
            ),
            ProofError::PaymentPredatesOrder {
                confirmed_at,
                order_anchor,
            } => write!(
                f,
                "the payment at this address confirmed in block {confirmed_at}, at or before \
                 block {order_anchor} when this order was made, so it paid for something else"
            ),
            ProofError::PaymentAfterWindow {
                confirmed_at,
                window_end,
            } => write!(
                f,
                "the payment at this address confirmed in block {confirmed_at}, after this \
                 order's payment window closed at block {window_end}, so it is not taken as \
                 this order's payment"
            ),
        }
    }
}

/// Verify that `proof` establishes payment of `order`.
///
/// This is the function the store contract runs, so it must be a pure function
/// of its arguments: no clock, no network, no ambient state. Everything it
/// needs is either in the order or in the proof — including which bridges to
/// believe, which the seller fixed when they signed the order.
/// Build the on-chain proof that settles `order`, out of the claims a node
/// holds for its payment address and the chain tip it can see.
///
/// # Why this exists at all
///
/// The verifier, the bridge-signed claims and the fold were all here; nothing
/// CONSTRUCTED the thing they verify. So an order stayed `AwaitingPayment`
/// forever however much had been paid, and the public record permanently
/// misstated what happened -- which matters beyond the buyer's screen,
/// because every later mechanism reads that record and Phase 2's whole
/// argument is arithmetic over an order's status.
///
/// # It verifies before it returns, and that is the contract
///
/// An order published as `Paid` carrying a proof that does not verify is a
/// state every peer refuses. On the buyer's screen that looks like the
/// payment simply not registering, with nothing anywhere saying why. So this
/// returns the verifier's own complaint instead, and a caller that gets `Ok`
/// has something the network will accept.
///
/// # What it selects, and what it refuses
///
/// Claims about THIS order's script, and no others: a foreign claim makes
/// `verify_on_chain_proof` refuse the whole proof, so including one would
/// turn a provable payment into an unprovable one.
///
/// Beyond [`MAX_PROOF_CLAIMS`] it refuses rather than truncating. Dropping
/// the excess would be curating which of a bridge's claims the network sees
/// -- the omission [`OnChainPaymentProof`] documents as undetectable
/// downstream -- and doing it on the buyer's behalf, in the buyer's favour.
/// Refusing says so.
///
/// # What it does NOT establish
///
/// That the claims it was handed are the complete history. They are whatever
/// the node's subscription to the address contract has delivered, and a
/// retraction that has not arrived is invisible here exactly as it is to the
/// verifier. See [`OnChainPaymentProof`]'s doc comment; this function inherits
/// that gap whole and does not widen it.
pub fn assemble_on_chain_proof(
    order: &Order,
    claims: &[SignedClaim],
    tip: &SignedTipEntry,
) -> Result<OrderPaymentProof, String> {
    let expected_script = order.bitcoin_params().script_id();
    // Filtered on the SIGNED body rather than on anything a caller says about
    // the claim, so a claim that does not verify is dropped here rather than
    // poisoning the proof.
    let addr_params = order.bitcoin_params();
    let mine: Vec<SignedClaim> = claims
        .iter()
        .filter(|claim| {
            claim
                .verify(&addr_params)
                .is_ok_and(|body| body.script_id == expected_script)
        })
        .cloned()
        .collect();

    if mine.is_empty() {
        return Err(
            "no bridge has published anything about this order's payment address yet".to_string(),
        );
    }
    let distinct = distinct_claims(&mine).len();
    if distinct > MAX_PROOF_CLAIMS {
        return Err(format!(
            "this address has {distinct} distinct claims and a payment proof may carry \
             {MAX_PROOF_CLAIMS}; a proof cannot be assembled without leaving some out, which \
             would be choosing what the network gets to see"
        ));
    }

    let proof = OrderPaymentProof::on_chain(mine, tip.clone());
    verify_payment_proof(order, &proof).map_err(|e| e.to_string())?;
    Ok(proof)
}

pub fn verify_payment_proof(order: &Order, proof: &OrderPaymentProof) -> Result<u64, ProofError> {
    match proof {
        OrderPaymentProof::OnChain(p) => verify_on_chain_proof(order, p),
        OrderPaymentProof::Lightning(p) => verify_lightning_proof(order, p),
    }
}

/// Verify a Lightning payment: one hash, no bridge, no chain.
///
/// Note there is no confirmation depth to check. A settled Lightning payment
/// is final immediately; there is no reorg that can undo it, which is why
/// `required_confirmations` does not appear here.
pub fn verify_lightning_proof(
    order: &Order,
    proof: &LightningPaymentProof,
) -> Result<u64, ProofError> {
    let Some(expected) = order.payment_hash else {
        return Err(ProofError::WrongRail);
    };
    let got: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(proof.preimage);
        h.finalize().into()
    };
    if got != expected {
        return Err(ProofError::PreimageMismatch);
    }
    Ok(order.amount_sats)
}

/// Hard cap on the number of DISTINCT claims one payment proof may carry.
///
/// This is the bound on the expensive work: each distinct claim costs an
/// Ed25519 verification plus, for a `ConfirmedOutput`, full SPV verification
/// (SHA256d over a transaction of up to `MAX_RAW_TX` = 64 KB, a Merkle branch,
/// and up to 25 block headers). `OrdersV1::verify` re-runs every order's proof
/// on every state validation, and a store may hold `MAX_ORDERS` orders, so
/// this multiplies.
///
/// 32 is generous for what a legitimate proof needs. An order's payment script
/// is a destination for one invoice: it sees one payment, occasionally two,
/// plus whatever retraction/re-confirmation churn a reorg produces and one
/// `ScannedTo` per trusted bridge. The address contract's own set is capped at
/// `freenet_bitcoin_common::address_state::MAX_CLAIMS` = 512, but that cap is
/// sized for a REUSED address; a per-order script that needed 32 claims to
/// prove one payment is not a payment destination.
///
/// This counts distinct claims, not submitted ones, because it is the
/// signature verifications it exists to bound and duplicates never reach one.
/// `MAX_PROOF_CLAIM_BYTES` is what bounds the submitted vector.
pub const MAX_PROOF_CLAIMS: usize = 32;

/// Byte budget for a payment proof's claims, measured on their actual CBOR
/// encoding.
///
/// # Why a byte budget as well as a count
///
/// A count cap *reads* like a memory bound and is not one: claim size is set
/// by whoever made the Bitcoin transaction, not by us, and a single
/// `ConfirmedOutput` claim can carry a 64 KB raw transaction. The same
/// reasoning is written up at length on
/// `freenet_bitcoin_common::address_state::MAX_CLAIM_BYTES`, whose value this
/// matches deliberately: a proof is drawn from one address contract's claim
/// set, so it has no business being larger than that whole set.
///
/// It also does a job the count cap cannot. The count cap is applied to
/// *distinct* claims, so on its own it would let a submitter send an unbounded
/// vector of duplicates and pay only for the dedup. This budget bounds the
/// submitted vector, and therefore the dedup itself: at a floor of roughly 160
/// bytes for the smallest possible claim, it admits under ~1,700 submitted
/// claims, i.e. that many BLAKE3 hashes over small inputs, which is nothing
/// next to one signature verification.
pub const MAX_PROOF_CLAIM_BYTES: usize = 256 * 1024;

/// A claim's cost against [`MAX_PROOF_CLAIM_BYTES`], measured on the encoding
/// that actually travels rather than on the fields' logical sizes.
///
/// An unencodable claim is charged the maximum, so it is refused rather than
/// admitted for free.
fn claim_cost(claim: &SignedClaim) -> usize {
    crate::to_cbor(claim).map(|b| b.len()).unwrap_or(usize::MAX)
}

/// The distinct claims in `claims`, in submission order, keyed by
/// [`SignedClaim::digest`].
///
/// `digest` is a BLAKE3 over the bridge id, the signed body bytes and the
/// signature, so two claims share one only if they are byte-identical -- there
/// is no way to smuggle a differing claim past it.
fn distinct_claims(claims: &[SignedClaim]) -> Vec<&SignedClaim> {
    let mut seen = std::collections::BTreeSet::new();
    claims
        .iter()
        .filter(|c| seen.insert(c.digest()))
        .collect::<Vec<_>>()
}

fn verify_on_chain_proof(order: &Order, proof: &OnChainPaymentProof) -> Result<u64, ProofError> {
    if order.payment_script_pubkey.is_empty() {
        return Err(ProofError::WrongRail);
    }
    if order.trusted_bridges.is_empty() {
        return Err(ProofError::NoTrustedBridges);
    }
    // The block the seller signed this order at. Required, because the
    // payment window in the fold below has nothing to measure against without
    // it. Fails closed: a buyer already refuses to pay an order with no
    // anchor (`harvest_ui::state::AppState::payment_blockers`), and every
    // order the UI issues carries one (`order_for_invoice` refuses to build
    // one without), so the only orders this refuses are ones nobody would pay.
    let order_anchor_height = order.anchor.ok_or(ProofError::NoAnchor)?.height;

    // Bound the work BEFORE doing any crypto at all -- see
    // `MAX_PROOF_CLAIM_BYTES` and `MAX_PROOF_CLAIMS` for what each bounds and
    // why one of them is not enough on its own. The byte budget comes first
    // because everything after it, dedup included, is linear in the submitted
    // bytes.
    let mut submitted_bytes: usize = 0;
    for c in &proof.claims {
        submitted_bytes = submitted_bytes.saturating_add(claim_cost(c));
        if submitted_bytes > MAX_PROOF_CLAIM_BYTES {
            return Err(ProofError::ClaimsTooLarge {
                have_bytes: submitted_bytes,
                budget: MAX_PROOF_CLAIM_BYTES,
            });
        }
    }
    let distinct = distinct_claims(&proof.claims);
    if distinct.len() > MAX_PROOF_CLAIMS {
        return Err(ProofError::TooManyClaims {
            have: distinct.len(),
            cap: MAX_PROOF_CLAIMS,
        });
    }

    let tip_params = freenet_bitcoin_common::BitcoinTipParameters {
        network: order.network,
        trusted_bridges: order.trusted_bridges.clone(),
    };
    let tip = proof.tip.verify(&tip_params).map_err(ProofError::BadTip)?;
    if tip.network != order.network {
        return Err(ProofError::NetworkMismatch);
    }
    let tip_height = tip.anchor.height;

    let addr_params = order.bitcoin_params();
    let expected_script = addr_params.script_id();

    // Verify every DISTINCT claim's signature and that it is about THIS
    // script. A claim about some other address would otherwise let an
    // attacker prove payment with somebody else's transaction.
    //
    // Iterating `distinct_claims` rather than `proof.claims` is what keeps a
    // duplicate from ever reaching `SignedClaim::verify`: there is no path in
    // this function that verifies a claim outside this loop. A bridge's
    // claims are public, so anyone can harvest genuine ones and resubmit them
    // hundreds of times; each one costs an Ed25519 verify plus SHA256d over
    // up to 64 KB of transaction, and `OrdersV1::verify` re-runs the lot on
    // every single state validation, for up to `MAX_ORDERS` orders. Deduping
    // first makes a duplicate cost one BLAKE3 hash instead.
    let mut bodies = Vec::with_capacity(distinct.len());
    for c in distinct {
        let body = c.verify(&addr_params).map_err(ProofError::BadClaim)?;
        if body.script_id != expected_script {
            return Err(ProofError::WrongScript);
        }
        bodies.push(body);
    }

    // Re-run exactly the fold the address contract would: group by outpoint,
    // then defer to `fold_outpoint_status` itself rather than restating its
    // rule here. Broadly it is "highest `as_of` wins", but how it settles a
    // tie at equal height is upstream's to decide and has changed there, and a
    // second copy of the rule in this comment is a copy that goes stale
    // without anything failing.
    //
    // Note what this does and does not establish: given the full history it
    // reaches the address contract's own answer, but the history is whatever
    // the submitter supplied, and a withheld retraction is invisible here. See
    // `OnChainPaymentProof`'s doc comment.
    let mut by_outpoint: std::collections::BTreeMap<_, Vec<_>> = std::collections::BTreeMap::new();
    for b in &bodies {
        if let Some(op) = b.claim.outpoint() {
            by_outpoint.entry(op).or_default().push(b.clone());
        }
    }

    let mut confirmed_total: u64 = 0;
    let mut shallowest: Option<u32> = None;
    // Value this proof shows was confirmed at SOME point, whether or not it
    // still is. This is what distinguishes a reversal from an order that was
    // simply never paid: see the `Reversed` test below.
    let mut ever_confirmed_total: u64 = 0;
    // Whether any outpoint this proof shows as retracted was also shown
    // CONFIRMED by it. A retraction of something never confirmed -- a dust
    // sighting, an evicted mempool transaction -- reverses nothing.
    let mut retracted_a_confirmed_outpoint = false;
    // The heights among outpoints refused below for confirming outside this
    // order's window, kept only so the error can say what happened.
    let mut predating: Option<u32> = None;
    let mut too_late: Option<u32> = None;
    // Checked for `Some` at the top of this function; the window exists.
    let window = order.payment_window().ok_or(ProofError::NoAnchor)?;

    for claims in by_outpoint.values() {
        // # Only a payment that confirmed inside the order's window is its payment
        //
        // A payment's evidence is scoped to a SCRIPT, not to an order, so
        // whatever has ever been paid to this order's address is presented
        // here as if it were for this order. Normally each order has a fresh
        // address and that is the same thing. It stops being the same thing
        // the moment an address is issued twice -- which a seller reinstalling
        // Harvest and re-entering the same wallet key used to do from index 0
        // (harvest#77): the new invoice named an address that already held a
        // confirmed payment for an old one, and settled itself with nobody
        // paying anything. See [`Order::payment_window`] for the two edges of
        // the window and why each is where it is.
        //
        // An outpoint outside the window is dropped from this order's fold
        // entirely: it adds nothing to what was paid, and -- because
        // `ever_confirmed` below counts only in-window confirmations -- a
        // later retraction of it cannot read as this order's payment being
        // reversed either.
        //
        // ## Judged by the fold's WINNING confirmation, not by every one
        //
        // An outpoint's claims can disagree about where it confirmed: a
        // bridge that briefly followed a stale fork, or a reorg that re-mined
        // the transaction at another height. The fold already decides which
        // claim is current (`fold_outpoint_status`), and the window is
        // applied to that one. An earlier version refused an outpoint if ANY
        // of its confirmations fell at or below the anchor. That let a single
        // stale-fork claim veto an honest payment forever (claims are
        // grow-only, and `assemble_on_chain_proof` has to include them all),
        // while protecting nothing against a dishonest submitter, who can
        // simply leave the stale claim out of an unsigned proof. What this
        // concedes is a transaction that confirmed before the order, was
        // reorged out, and was re-mined inside the window: a reorg deep
        // enough to cross an order's anchor, landing on a reused address.
        //
        // ## What the window does NOT bound
        //
        // The anchor is a lower bound on when the order was made, set by the
        // seller's own view of the tip. A tip that lags reality makes the
        // anchor older than the order, so a payment that confirmed inside that
        // lag still reads as after it; a buyer refuses anchors more than
        // [`MAX_ANCHOR_AGE_BLOCKS`] behind, which caps that but does not close
        // it. A payment broadcast before the order but still unconfirmed when
        // it was made confirms inside the window and is counted. And two
        // orders on one address whose windows overlap can both be settled by
        // one payment that lands in the overlap. All three need an address
        // issued twice, which is why the UI also recovers its derivation index
        // and checks the address contract before publishing; this rule is the
        // backstop, not a substitute for not reusing addresses.
        let ever_confirmed: Option<u64> = claims
            .iter()
            .filter_map(|b| match &b.claim {
                // Spelled out rather than `..` for the same reason as the
                // fold match below: this value decides `ever_confirmed_total`,
                // which gates whether a retraction reads as a REVERSAL, so a
                // field added to `ConfirmedOutput` upstream must stop the
                // build rather than arrive here unexamined.
                //
                // Only confirmations inside this order's window count as the
                // order ever having been covered: a retracted payment that
                // confirmed before the order was never this order's payment,
                // so its retraction reverses nothing here.
                Claim::ConfirmedOutput {
                    outpoint: _,
                    value_sats,
                    anchor,
                    spv: _,
                } if window.contains(&anchor.height) => Some(*value_sats),
                _ => None,
            })
            // The minimum is the conservative direction for a value that will
            // be used to ADMIT a reversal; in practice moot, because
            // `SignedClaim::verify` checks each `ConfirmedOutput` against an
            // SPV proof binding `value_sats` to that exact txid and vout.
            .min();
        if let Some(v) = ever_confirmed {
            ever_confirmed_total = ever_confirmed_total.saturating_add(v);
        }

        match fold_outpoint_status(claims.iter()) {
            // Destructured WITHOUT `..`, and the `_` binding below is
            // deliberate rather than lazy.
            //
            // No `..`, because that is the only reason the arrival of
            // `attested_depth` was noticed at all: the upstream bump failed
            // here with E0027 instead of compiling and quietly declining a
            // security fix. A `..` would let the next field arrive silently.
            //
            // `attested_depth` is bound to `_` because the depth is computed
            // by `confirmations_at`, which uses it together with `anchor` --
            // it caps the tip-derived count at the depth the BRIDGE attested
            // inside its own signature. Do not re-derive the cap here:
            // `confirmations(&anchor, tip)` is the uncapped observed depth,
            // which grows with the chain, so a submitter presenting a
            // pre-reorg confirmation against a fresh tip can make an assertion
            // the bridge made at depth 1 read as arbitrarily deep. `anchor`
            // itself is read only for the window check.
            Some(
                status @ OutpointStatus::Confirmed {
                    value_sats,
                    anchor,
                    attested_depth: _,
                },
            ) => {
                if anchor.height < *window.start() {
                    predating = Some(predating.map_or(anchor.height, |p| p.max(anchor.height)));
                    continue;
                }
                if anchor.height > *window.end() {
                    too_late = Some(too_late.map_or(anchor.height, |p| p.min(anchor.height)));
                    continue;
                }
                let confs = status.confirmations_at(tip_height);
                confirmed_total = confirmed_total.saturating_add(value_sats);
                shallowest = Some(shallowest.map_or(confs, |s: u32| s.min(confs)));
            }
            Some(OutpointStatus::Retracted) => {
                if ever_confirmed.is_some() {
                    retracted_a_confirmed_outpoint = true;
                }
            }
            // Mempool-only outputs never count toward a paid order.
            Some(OutpointStatus::Unconfirmed { .. }) | None => {}
        }
    }

    // A reversal is a reversal OF something, and all three of these have to
    // hold:
    //
    //   1. the proof shows this order was AT SOME POINT covered;
    //   2. a bridge has retracted one of the very outpoints that covered it;
    //   3. what is still confirmed no longer covers the order.
    //
    // (3) alone was the original test, and (3) alone is trivially true of
    // every order nobody has paid yet -- the current total is zero. Combined
    // with (2) in its weaker "any retraction at all" form, that made a
    // retraction of ANY output on this script sufficient evidence that a
    // payment which never happened had been undone. The order's payment
    // address is public in the store state, so an attacker could send dust to
    // it, or broadcast a low-fee transaction and let it be evicted, and
    // submit the resulting retraction. `PaymentReversed` outranks `Paid` and
    // merge is monotonic, so the order would then be poisoned permanently.
    //
    // (1) is measured over `ConfirmedOutput` claims only. A `MempoolOutput`
    // sighting is not a payment, and it is the cheap attacker-controlled
    // path: causing a confirmed output to be retracted needs a reorg, while
    // causing a mempool one to be retracted needs only a low fee.
    //
    // Testing (3) only for a total of zero was too narrow: an order paid
    // across two outpoints, one of which is later reorged out, is genuinely
    // reversed while the other outpoint's value is still confirmed -- and
    // that case used to surface as `InsufficientValue`. Which is precisely
    // why `AuthorizedOrder::verify` accepted `InsufficientValue` as evidence
    // of a reversal, and why an empty claim set (`InsufficientValue
    // { have: 0 }`, no bridge involved at all) could poison any order in the
    // store. Report the reversal here, so that arm can require the reversal
    // error itself.
    //
    // The `== 0` limb covers the degenerate zero-sats order. It no longer
    // admits a reversal on its own, because (1) and (2) still have to hold,
    // and (2) needs a genuine confirmed-then-retracted outpoint.
    let was_ever_covered = ever_confirmed_total >= order.amount_sats;
    let no_longer_covered = confirmed_total < order.amount_sats || confirmed_total == 0;
    if retracted_a_confirmed_outpoint && was_ever_covered && no_longer_covered {
        return Err(ProofError::Reversed);
    }
    if confirmed_total < order.amount_sats {
        // Said as its own error when refusing an out-of-window payment is
        // what left the order short, because "short of the amount" is not what a
        // seller looking at a funded address needs to be told.
        if let Some(confirmed_at) = predating {
            return Err(ProofError::PaymentPredatesOrder {
                confirmed_at,
                order_anchor: order_anchor_height,
            });
        }
        if let Some(confirmed_at) = too_late {
            return Err(ProofError::PaymentAfterWindow {
                confirmed_at,
                window_end: *window.end(),
            });
        }
        return Err(ProofError::InsufficientValue {
            have_sats: confirmed_total,
            need_sats: order.amount_sats,
        });
    }
    let depth = shallowest.unwrap_or(0);
    if depth < order.required_confirmations {
        return Err(ProofError::InsufficientConfirmations {
            have: depth,
            need: order.required_confirmations,
        });
    }
    Ok(confirmed_total)
}

/// An order plus its current status, signed where a signature is meaningful.
///
/// The order *terms* are signed by the seller: only they may issue an invoice
/// against their own store. The `Paid` transition is not signed by anybody —
/// it is authorized by [`OrderPaymentProof`], which any peer can verify, so
/// neither party has to be taken at their word about payment.
///
/// The order's trusted bridges do have to be taken at their word about chain
/// state; see this module's docs.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedOrder {
    pub order: Order,
    /// CBOR `ScopedPayload` from the ghostkey delegate, over `order`.
    pub scoped_payload: Vec<u8>,
    /// Seller's Ed25519 signature over `scoped_payload`.
    pub signature: Vec<u8>,
    pub status: OrderStatus,
    /// Evidence for `Paid` / `PaymentReversed`. Absent while awaiting payment.
    pub payment_proof: Option<OrderPaymentProof>,
    /// Seller's signature over `(order.id, status)` for the transitions only
    /// the seller may make -- today just `Cancelled`.
    pub status_scoped_payload: Option<Vec<u8>>,
    pub status_signature: Option<Vec<u8>>,
}

impl AuthorizedOrder {
    /// Verify the order terms are genuinely the seller's.
    pub fn verify_terms(&self, seller_key: &VerifyingKey) -> Result<(), String> {
        crate::listing::verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            seller_key,
            &self.order,
        )?;
        // The id has to be the one these terms give, or two differently-termed
        // orders could share a key and the later one would displace the
        // earlier under `merge_order`'s tie-break -- see [`OrderId`] for the
        // attack that made this necessary.
        //
        // AFTER the signature, and that ordering is about the message rather
        // than about security -- both are refusals. A record with terms
        // altered since signing fails both checks, and "the seller did not
        // sign this" is the more useful of the two things to be told; the id
        // check is what catches a record that is genuinely self-consistent
        // and self-signed but filed under somebody else's id, which is the
        // case only this check can see.
        let expected = OrderId::from_terms(&self.order);
        if self.order.id != expected {
            return Err(format!(
                "order id {} is not the id these terms give ({expected})",
                self.order.id
            ));
        }
        Ok(())
    }

    /// Which of the optional fields each status actually consults.
    ///
    /// # Do not give this match a wildcard arm
    ///
    /// It is exhaustive on purpose, and that is load-bearing rather than
    /// stylistic. A new status stops this compiling until somebody decides
    /// what it authorizes, and that decision is what
    /// [`Self::verify_unused_fields_absent`] enforces and what
    /// `store::merge_order`'s tie-break argument rests on: at an equal rank
    /// the only field an attacker may vary is one this table marks as used.
    ///
    /// This is only HALF the guard, and it is the half that fires on the less
    /// likely change. A struct grows a field more often than an enum grows a
    /// variant, and a new FIELD is caught by the `..`-free destructuring in
    /// [`Self::verify_unused_fields_absent`], not here. Neither half is
    /// sufficient alone; do not weaken either.
    ///
    /// A `_ => (false, false)` arm would compile, would silently pin the new
    /// status's own fields to absent, and would break the record it was added
    /// to describe. A `_ => (true, true)` arm would compile, would leave the
    /// new status's fields unchecked, and would hand the tie-break straight
    /// back to whoever wanted to win it -- see
    /// `store::order_tests::a_field_the_status_does_not_use_is_rejected` for
    /// what that costs. Both failures are silent; the compile error is the
    /// only thing that is not.
    fn fields_used(status: OrderStatus) -> (bool, bool) {
        match status {
            // Nothing is asserted yet, so nothing may be attached.
            OrderStatus::AwaitingPayment => (false, false),
            // The seller's signature over `(id, status)`, and nothing else.
            OrderStatus::Cancelled => (false, true),
            // Bitcoin evidence, and nothing else. `Cancelled` ranks BELOW
            // `Paid`, so a paid order never reaches `Cancelled` under merge
            // and a proof on one of these is not a record of anything.
            OrderStatus::Paid | OrderStatus::PaymentReversed => (true, false),
        }
    }

    /// Reject a record carrying evidence or authorization its status does not
    /// use.
    ///
    /// # Why an unchecked field is not harmless
    ///
    /// `verify`'s `Paid` arm never reads `status_scoped_payload` or
    /// `status_signature`, and its `AwaitingPayment` arm reads nothing at all.
    /// Left unchecked, those fields are bytes any third party may set on a
    /// record that still verifies — and `store::merge_order` breaks an
    /// equal-rank tie on the full CBOR encoding, keeping the smaller. In CBOR
    /// `None` is `0xf6` and *every* `Some(..)` here begins with an array
    /// header of `0x80..=0x9b`, so `Some(anything)` sorts BELOW `None`.
    ///
    /// A third party could therefore take a genuine `Paid` record, set
    /// `status_scoped_payload: Some(vec![])` — a field nothing reads — and
    /// permanently displace the honest record, because merge is a monotonic
    /// maximum. Nothing about the order changed; the attacker simply owns the
    /// copy every replica keeps.
    ///
    /// Pinning the unused fields to `None` closes that, and it is the reason
    /// `merge_order`'s soundness argument can talk about `payment_proof` as
    /// the only field an attacker may vary at an equal rank. Do not relax this
    /// without redoing that argument.
    ///
    /// Safe to add: both production constructors
    /// (`state::authorize_new_order` and the one in `gateway::store_ops`)
    /// already build `AwaitingPayment` with every optional field `None`, and
    /// `orders` did not exist in V1 — the only generation ever published — so
    /// no deployed state contains an order at all.
    fn verify_unused_fields_absent(&self) -> Result<(), String> {
        // Destructured WITHOUT `..`, and that is the point of writing it this
        // way. `fields_used` makes ADDING A STATUS a compile error; this makes
        // ADDING A FIELD one. Both are needed, and the second is the more
        // likely change: a struct grows a field far more often than an enum
        // grows a variant.
        //
        // Every binding below must be accounted for. `order`, `scoped_payload`
        // and `signature` are pinned by `verify_terms`, which has already run;
        // `status` selects the rules. The remaining three are the optional
        // ones this function exists to police. A new optional field arriving
        // here stops the crate compiling until somebody decides which statuses
        // consult it -- because if the answer is "none of them", it is an
        // unchecked field a third party may set on a record that still
        // verifies, and `store::merge_order` breaks an equal-rank tie on the
        // full CBOR encoding. That is not a hypothetical: it is exactly the
        // attack this function was added to close.
        //
        // Do NOT silence this with `..`. Doing so compiles, changes no
        // behaviour today, and quietly removes the only thing that will make
        // the next field's author think about it.
        let Self {
            order: _,
            scoped_payload: _,
            signature: _,
            status,
            payment_proof,
            status_scoped_payload,
            status_signature,
        } = self;

        let (uses_proof, uses_status_signature) = Self::fields_used(*status);
        if !uses_proof && payment_proof.is_some() {
            return Err(format!(
                "{status:?} carries payment evidence, which nothing checks for that status"
            ));
        }
        if !uses_status_signature && (status_scoped_payload.is_some() || status_signature.is_some())
        {
            return Err(format!(
                "{status:?} carries a status signature, which nothing checks for that status"
            ));
        }
        Ok(())
    }

    /// Verify the whole record: terms, and whatever authorizes the status.
    ///
    /// The bridges the payment evidence is judged against come from
    /// `self.order.trusted_bridges`, which `verify_terms` has just established
    /// is genuinely the seller's — so this needs no bridge argument and cannot
    /// be called with a set the seller did not sign for.
    pub fn verify(&self, seller_key: &VerifyingKey) -> Result<(), String> {
        self.verify_terms(seller_key)?;
        self.verify_unused_fields_absent()?;
        match self.status {
            OrderStatus::AwaitingPayment => Ok(()),
            OrderStatus::Paid => {
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "order marked Paid without payment evidence".to_string())?;
                verify_payment_proof(&self.order, proof)
                    .map(|_| ())
                    .map_err(|e| format!("payment proof rejected: {e}"))
            }
            OrderStatus::PaymentReversed => {
                // A reversal must be evidenced by a bridge-signed retraction,
                // and by nothing weaker.
                //
                // `PaymentReversed` outranks `Paid` and merge is a monotonic
                // maximum on rank, so this status is effectively permanent:
                // once a peer accepts it, no later proof of payment can ever
                // displace it. It is also, deliberately, unsigned -- evidenced
                // by Bitcoin rather than by authority -- so anyone who can read
                // the public order can submit one. Those two facts together
                // mean the evidence test here is the ONLY thing standing
                // between a public order and permanent poisoning.
                //
                // So it accepts `ProofError::Reversed` and nothing else.
                // Every other rejection means "this evidence does not
                // demonstrate payment", which is not the same claim as
                // "payment was demonstrated and then undone". An empty
                // `claims` vector fails with `InsufficientValue { have: 0 }`
                // and costs an attacker nothing to build; accepting that as a
                // reversal, as this once did, let anyone permanently poison
                // any order in any store. Absence of proof is not proof of
                // absence.
                //
                // `Reversed` requires the proof to show confirmations
                // covering the order that a trusted bridge has since
                // retracted -- see `verify_on_chain_proof`. A retraction on
                // its own is not enough, and neither is a retraction of dust
                // or of an evicted mempool sighting, because a reversal has
                // to be a reversal OF something.
                //
                // Residual, and it is NOT small -- tracked as the
                // selective-omission gap in the `OnChainPaymentProof` doc
                // comment. The submitter still picks which claims to show. So
                // for an order whose payment WAS confirmed, reorged out, and
                // re-confirmed on the new chain, a submitter can exhibit the
                // confirmation and the retraction while withholding the
                // re-confirmation; the precondition above is then satisfied
                // by genuine claims, and a live payment reads as reversed.
                // What the precondition removes is the case where no payment
                // ever happened at all, which needed no reorg and no
                // cooperation from anyone. Closing the rest needs a
                // bridge-signed commitment to the complete claim set, not a
                // change here.
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "reversal without evidence".to_string())?;
                match verify_payment_proof(&self.order, proof) {
                    Err(ProofError::Reversed) => Ok(()),
                    Ok(_) => Err("reversal claimed, but the evidence still proves payment".into()),
                    Err(e) => Err(format!("reversal evidence invalid: {e}")),
                }
            }
            OrderStatus::Cancelled => {
                let (sp, sig) = self
                    .status_scoped_payload
                    .as_ref()
                    .zip(self.status_signature.as_ref())
                    .ok_or_else(|| format!("{:?} requires the seller's signature", self.status))?;
                crate::listing::verify_scoped_signature(
                    sp,
                    sig,
                    seller_key,
                    &(self.order.id.clone(), self.status),
                )
            }
        }
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    /// Who gets to assert a status.
    #[derive(PartialEq, Debug)]
    enum Authority {
        /// The order's initial state; nobody asserts it.
        Initial,
        /// A signature from the seller, and nothing else, makes it true.
        SellerSignature,
        /// Bridge-signed Bitcoin observations make it true, and any peer can
        /// check them.
        BitcoinEvidence,
    }

    /// The classification `AuthorizedOrder::verify` actually implements.
    ///
    /// Written as a `match` on purpose: adding a status to `OrderStatus`
    /// stops this compiling until somebody decides which side of the line it
    /// belongs on, which is the decision that was got wrong.
    fn authority(status: OrderStatus) -> Authority {
        match status {
            OrderStatus::AwaitingPayment => Authority::Initial,
            OrderStatus::Cancelled => Authority::SellerSignature,
            OrderStatus::Paid | OrderStatus::PaymentReversed => Authority::BitcoinEvidence,
        }
    }

    const ALL: [OrderStatus; 4] = [
        OrderStatus::AwaitingPayment,
        OrderStatus::Cancelled,
        OrderStatus::Paid,
        OrderStatus::PaymentReversed,
    ];

    /// Rank is a permanent, monotonic maximum under merge, so whichever
    /// status sits highest is what the order says forever. A status one party
    /// can assert with their own signature must therefore never outrank one
    /// evidenced by Bitcoin -- otherwise that party holds a veto over the
    /// chain.
    ///
    /// `Fulfilled` was seller-signed and sat at the very top, above
    /// `PaymentReversed`, so a seller could bury a genuine reorg under a
    /// status they issued themselves. It is deleted; this is what stops it
    /// (or anything like it) coming back.
    #[test]
    fn no_seller_signed_status_outranks_a_bitcoin_evidenced_one() {
        for signed in ALL
            .iter()
            .filter(|s| authority(**s) == Authority::SellerSignature)
        {
            for evidenced in ALL
                .iter()
                .filter(|s| authority(**s) == Authority::BitcoinEvidence)
            {
                assert!(
                    signed.rank() < evidenced.rank(),
                    "{signed:?} is asserted by the seller's own signature but outranks                      {evidenced:?}, which is evidenced by Bitcoin -- the seller can then                      bury the chain's verdict permanently"
                );
            }
        }
    }

    /// Ranks must be distinct, or merge's tie-break falls through to raw CBOR
    /// bytes between two statuses that mean different things.
    #[test]
    fn every_status_has_its_own_rank() {
        let mut ranks: Vec<u8> = ALL.iter().map(|s| s.rank()).collect();
        ranks.sort_unstable();
        let before = ranks.len();
        ranks.dedup();
        assert_eq!(ranks.len(), before, "two statuses share a rank");
    }

    /// Deleting a variant is a wire-format change, and the only safe way for
    /// it to fail is loudly.
    ///
    /// Ciborium encodes a fieldless variant as its NAME, not its index, so
    /// removing `Fulfilled` from the middle of the enum does not renumber
    /// `PaymentReversed` or `Cancelled` -- old bytes for those still mean
    /// what they always meant, and old bytes for `Fulfilled` fail to decode
    /// rather than silently becoming some other status. That distinction is
    /// the whole safety argument for the deletion, so it is pinned here.
    #[test]
    fn a_deleted_status_fails_to_decode_rather_than_becoming_another_one() {
        let fulfilled = crate::to_cbor(&"Fulfilled").unwrap();
        assert!(
            crate::from_cbor::<OrderStatus>(&fulfilled).is_err(),
            "an order written as Fulfilled must not decode as anything at all"
        );

        for status in ALL {
            let bytes = crate::to_cbor(&status).unwrap();
            assert_eq!(
                crate::from_cbor::<OrderStatus>(&bytes).unwrap(),
                status,
                "{status:?} must round-trip"
            );
            // The encoding is the variant's name. If this ever became an
            // index, deleting a variant would silently reinterpret every
            // status above it.
            assert_eq!(
                bytes,
                crate::to_cbor(&format!("{status:?}")).unwrap(),
                "{status:?} must encode as its own name"
            );
        }
    }
}

#[cfg(test)]
mod lightning_tests {
    use super::*;
    use freenet_bitcoin_common::BitcoinNetwork;

    fn sha256(b: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().into()
    }

    fn lightning_order(payment_hash: Option<[u8; 32]>) -> Order {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: "buyer".into(),
            seller_fingerprint: "seller".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Bitcoin,
            // A Lightning order has no on-chain destination at all.
            payment_script_pubkey: Vec::new(),
            payment_address: String::new(),
            payment_hash,
            required_confirmations: 0,
            // Lightning needs no observer at all, which is exactly why these
            // tests pass an empty bridge set: a preimage settles the invoice
            // with no bridge in the picture.
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at: ts,
        }
        .with_derived_id()
    }

    #[test]
    fn a_correct_preimage_settles_a_lightning_order() {
        let preimage = [42u8; 32];
        let order = lightning_order(Some(sha256(&preimage)));
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof { preimage });
        // No bridge is consulted: the trusted-bridge list is irrelevant here,
        // which is the point -- a Lightning payment needs no observer.
        assert_eq!(verify_payment_proof(&order, &proof).unwrap(), 50_000);
    }

    #[test]
    fn a_wrong_preimage_is_rejected() {
        let order = lightning_order(Some(sha256(&[42u8; 32])));
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [7u8; 32],
        });
        assert_eq!(
            verify_payment_proof(&order, &proof),
            Err(ProofError::PreimageMismatch)
        );
    }

    #[test]
    fn a_lightning_proof_cannot_settle_an_on_chain_order() {
        // Rails must not be interchangeable: presenting a preimage for an
        // order that expects an on-chain payment would otherwise be a way to
        // mark it paid with no payment at all.
        let mut order = lightning_order(None);
        order.payment_script_pubkey = vec![0x00, 0x14, 0xaa, 0xbb];
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [42u8; 32],
        });
        assert_eq!(
            verify_payment_proof(&order, &proof),
            Err(ProofError::WrongRail)
        );
    }

    #[test]
    fn an_on_chain_proof_cannot_settle_a_lightning_order() {
        let order = lightning_order(Some(sha256(&[1u8; 32])));
        let proof = OrderPaymentProof::on_chain(vec![], dummy_tip());
        assert_eq!(
            verify_payment_proof(&order, &proof),
            Err(ProofError::WrongRail)
        );
    }

    fn dummy_tip() -> SignedTipEntry {
        SignedTipEntry {
            body_cbor: Vec::new(),
            bridge: freenet_bitcoin_common::BridgeId([0u8; 32]),
            signature: Vec::new(),
        }
    }

    /// The wire format must be able to represent both rails, so that adding
    /// Lightning support later is a code change rather than a state migration.
    #[test]
    fn both_rails_round_trip_through_cbor() {
        let ln = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [9u8; 32],
        });
        let bytes = crate::to_cbor(&ln).unwrap();
        assert_eq!(crate::from_cbor::<OrderPaymentProof>(&bytes).unwrap(), ln);
    }

    /// An order written before `payment_hash` existed must still decode.
    #[test]
    fn orders_without_a_payment_hash_still_decode() {
        #[derive(serde::Serialize)]
        struct OldOrder {
            id: OrderId,
            listing_id: crate::listing::ListingId,
            buyer_fingerprint: String,
            seller_fingerprint: String,
            amount_sats: u64,
            network: BitcoinNetwork,
            payment_script_pubkey: Vec<u8>,
            payment_address: String,
            required_confirmations: u32,
            created_at: chrono::DateTime<chrono::Utc>,
        }
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // Orders once carried the listing (harvest#57 removed it). An old
        // record that still has it must decode, the extra field ignored.
        let listing_id = crate::listing::ListingId::from_label("Widget");
        let old = OldOrder {
            id: OrderId([3u8; 32]),
            listing_id,
            buyer_fingerprint: "buyer".into(),
            seller_fingerprint: "seller".into(),
            amount_sats: 1,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14],
            payment_address: "tb1q".into(),
            required_confirmations: 1,
            created_at: ts,
        };
        let bytes = crate::to_cbor(&old).unwrap();
        let decoded: Order = crate::from_cbor(&bytes).expect("old orders must still decode");
        assert_eq!(decoded.payment_hash, None);
    }
}

#[cfg(test)]
mod order_wire_compat_tests {
    use super::*;

    /// A real `Order` from before `OrderId` was widened to 32 bytes, as CBOR.
    ///
    /// `id` and `listing_id` are 16-element arrays (`0x90`); today's types
    /// want 32 (`0x98 0x20`). Kept as a literal so the boundary this branch
    /// crosses is pinned by a test rather than described in prose -- see
    /// [`an_order_from_before_the_id_was_widened_does_not_decode`], which is
    /// the honest statement of what the re-key costs.
    const NARROW_ID_ORDER_CBOR: &[u8] = &[
        0xad, 0x62, 0x69, 0x64, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x6c, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x5f,
        0x69, 0x64, 0x90, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x71, 0x62, 0x75, 0x79, 0x65, 0x72, 0x5f, 0x66, 0x69, 0x6e, 0x67,
        0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x60, 0x72, 0x73, 0x65, 0x6c, 0x6c, 0x65, 0x72,
        0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x69, 0x73, 0x65,
        0x6c, 0x6c, 0x65, 0x72, 0x2d, 0x66, 0x70, 0x6b, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x5f,
        0x73, 0x61, 0x74, 0x73, 0x19, 0xc3, 0x50, 0x67, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
        0x66, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x74, 0x75, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
        0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x82,
        0x18, 0x51, 0x18, 0x20, 0x6f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64,
        0x64, 0x72, 0x65, 0x73, 0x73, 0x6b, 0x74, 0x62, 0x31, 0x71, 0x65, 0x78, 0x61, 0x6d, 0x70,
        0x6c, 0x65, 0x76, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6e,
        0x66, 0x69, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x01, 0x6c, 0x70, 0x61, 0x79,
        0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0xf6, 0x6f, 0x74, 0x72, 0x75, 0x73,
        0x74, 0x65, 0x64, 0x5f, 0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x73, 0x80, 0x78, 0x19, 0x62,
        0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f,
        0x63, 0x6f, 0x64, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0xf6, 0x6a, 0x63, 0x72, 0x65, 0x61,
        0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x74, 0x32, 0x30, 0x32, 0x33, 0x2d, 0x31, 0x31, 0x2d,
        0x31, 0x34, 0x54, 0x32, 0x32, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x30, 0x5a,
    ];

    /// **An order published before the id was widened does not decode, and
    /// that is what the re-key costs.**
    ///
    /// This test exists to be READ, not merely to pass. The migration folds a
    /// predecessor generation by decoding its state and verifying every
    /// record; an order at the old width fails at the first step, so the
    /// generation is treated as absent. There is no compatibility path and
    /// none is attempted: a type that accepted both widths would have to
    /// decide which one an id is, which is the ambiguity the width exists to
    /// remove.
    ///
    /// Orders are what makes this acceptable. One expires after
    /// [`MAX_ANCHOR_AGE_BLOCKS`] -- about eight hours -- so an order old
    /// enough to be in a predecessor generation is an order nobody can pay
    /// anyway. The same is NOT true of a listing, and
    /// `docs/untested-invariants.md` says so where it records what this
    /// boundary costs in full.
    #[test]
    fn an_order_from_before_the_id_was_widened_does_not_decode() {
        let refused = crate::from_cbor::<Order>(NARROW_ID_ORDER_CBOR)
            .expect_err("a 16-byte id must not decode into a 32-byte one");
        assert!(
            refused.contains("invalid length 16"),
            "the refusal should name the width: {refused}"
        );
    }

    /// The same order at today's width, as CBOR, written out byte by byte.
    ///
    /// Twelve fields; `payment_hash` and `bitcoin_address_code_hash`
    /// present and null; `anchor`, `order_binding` and `listing_tag` ABSENT,
    /// which is the property this pins. Regenerated when harvest#57 removed `listing_id`,
    /// which also moved the id.
    ///
    /// ```text
    /// ac                                  map(12)
    ///   62 "id"                    98 20 ..  32-element array (serde encodes
    ///                                        [u8; 32] as a tuple, i.e. an
    ///                                        array of numbers, NOT a byte
    ///                                        string) -- the id these terms
    ///                                        give
    ///   71 "buyer_fingerprint"     60        empty -- an anonymous buyer,
    ///                                        which is what the buy flow makes
    ///   ... amount, network, script, address, confirmations ...
    ///   6c "payment_hash"          f6        null
    ///   6f "trusted_bridges"       80        empty seq
    ///   78 19 "bitcoin_address_code_hash" f6 null
    ///   6a "created_at"            74 ..     "2023-11-14T22:13:20Z"
    /// ```
    const ORDER_WITHOUT_OPTIONAL_FIELDS_CBOR: &[u8] = &[
        0xac, 0x62, 0x69, 0x64, 0x98, 0x20, 0x18, 0x46, 0x18, 0x69, 0x18, 0xdc, 0x18, 0x78, 0x18,
        0x62, 0x18, 0xe6, 0x18, 0x84, 0x18, 0xdb, 0x18, 0xb7, 0x18, 0x85, 0x18, 0xc2, 0x18, 0x3f,
        0x18, 0x4c, 0x18, 0x46, 0x18, 0xc4, 0x18, 0x98, 0x18, 0xbc, 0x18, 0x9a, 0x17, 0x18, 0x35,
        0x0b, 0x18, 0x72, 0x18, 0x85, 0x18, 0xec, 0x18, 0x1a, 0x07, 0x18, 0x3c, 0x18, 0x30, 0x18,
        0x1d, 0x18, 0x91, 0x18, 0xf4, 0x18, 0x26, 0x71, 0x62, 0x75, 0x79, 0x65, 0x72, 0x5f, 0x66,
        0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x60, 0x72, 0x73, 0x65, 0x6c,
        0x6c, 0x65, 0x72, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74,
        0x69, 0x73, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x2d, 0x66, 0x70, 0x6b, 0x61, 0x6d, 0x6f, 0x75,
        0x6e, 0x74, 0x5f, 0x73, 0x61, 0x74, 0x73, 0x19, 0xc3, 0x50, 0x67, 0x6e, 0x65, 0x74, 0x77,
        0x6f, 0x72, 0x6b, 0x66, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x74, 0x75, 0x70, 0x61, 0x79, 0x6d,
        0x65, 0x6e, 0x74, 0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x5f, 0x70, 0x75, 0x62, 0x6b,
        0x65, 0x79, 0x82, 0x18, 0x51, 0x18, 0x20, 0x6f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
        0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x6b, 0x74, 0x62, 0x31, 0x71, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x76, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x5f,
        0x63, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x01, 0x6c,
        0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0xf6, 0x6f, 0x74,
        0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x73, 0x80,
        0x78, 0x19, 0x62, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65,
        0x73, 0x73, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0xf6, 0x6a, 0x63,
        0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x74, 0x32, 0x30, 0x32, 0x33, 0x2d,
        0x31, 0x31, 0x2d, 0x31, 0x34, 0x54, 0x32, 0x32, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x30, 0x5a,
    ];

    /// **An order carrying neither optional field re-encodes to the bytes its
    /// signature was taken over.**
    ///
    /// [`AuthorizedOrder::verify_terms`] does not compare stored bytes: it
    /// re-serializes this struct and checks the result against the payload
    /// inside the signed `ScopedPayload`. A field that serializes when absent
    /// therefore changes the preimage of every signature taken before it
    /// existed, and the store contract rejects the seller's own published
    /// invoices with "order signature invalid".
    ///
    /// That is why `anchor` and `order_binding` carry `skip_serializing_if`
    /// rather than `serde(default)` alone -- observed red against the naive
    /// form, as `0xae` map(14) with `"anchor": null` against the `0xad`
    /// map(13) the signature covered (before harvest#57 removed a field). The literal is what keeps the next
    /// optional field honest.
    ///
    /// The fixture is at the CURRENT id width. The one that predates the
    /// widening is above, and it does not decode at all.
    #[test]
    fn an_order_without_the_optional_fields_re_encodes_unchanged() {
        let order: Order = crate::from_cbor(ORDER_WITHOUT_OPTIONAL_FIELDS_CBOR).expect("decodes");
        assert_eq!(order.anchor, None);
        assert_eq!(order.order_binding, None);
        assert_eq!(order.amount_sats, 50_000);
        // And the id is the one these terms give, so the fixture is a record
        // the contract would actually accept rather than a plausible fiction.
        assert_eq!(order.id, OrderId::from_terms(&order));

        assert_eq!(
            crate::to_cbor(&order).expect("re-encodes"),
            ORDER_WITHOUT_OPTIONAL_FIELDS_CBOR,
            "an order with no optional fields must re-encode to the bytes its signature was \
             taken over"
        );
    }
}

#[cfg(test)]
mod order_identity_tests {
    use super::*;

    fn terms(address: &str, amount_sats: u64) -> Order {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: address.as_bytes().to_vec(),
            payment_address: address.to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at,
        }
    }

    /// A commitment whose id is the one its own terms give.
    fn commitment(order: Order, signing_key: &ed25519_dalek::SigningKey) -> AuthorizedOrder {
        use ed25519_dalek::Signer;
        use freenet_stdlib::prelude::ContractInstanceId;

        let mut order = order;
        order.id = OrderId::from_terms(&order);
        let message = crate::to_cbor(&order).expect("serialize");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                crate::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = crate::to_cbor(&scoped).expect("serialize scoped");
        let signature = signing_key.sign(&scoped_payload).to_bytes().to_vec();
        AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// **A seller cannot swap the payment address under one order id.**
    ///
    /// The hole this closes, found in review. `OrderId` used to hash
    /// `(seller, listing, created_at_ms, buyer)` and nothing else -- not the
    /// amount, not the script, not the address -- so one seller could sign
    /// two differently-termed, individually valid orders sharing one id.
    /// `merge_order` resolves an equal-rank collision by smaller-CBOR-wins,
    /// which is deterministic and DIRECTIONAL: publish the larger encoding,
    /// let the buyer read and pay it, then publish the smaller, which wins
    /// everywhere and permanently. The public record then shows an order
    /// whose payment destination never received anything.
    ///
    /// Deriving the id from the terms makes the two orders two DIFFERENT
    /// orders, so there is no collision to resolve and nothing to displace.
    #[test]
    fn two_differently_termed_orders_cannot_share_an_id() {
        let shown = terms("tb1q_shown_to_the_buyer", 50_000);
        let swapped = terms("tb1q_swapped_afterwards", 50_000);
        assert_ne!(
            OrderId::from_terms(&shown),
            OrderId::from_terms(&swapped),
            "two payment destinations must be two orders"
        );

        let dearer = terms("tb1q_shown_to_the_buyer", 500_000);
        assert_ne!(
            OrderId::from_terms(&shown),
            OrderId::from_terms(&dearer),
            "two amounts must be two orders"
        );
    }

    /// **The id covers every field of the terms, by construction.**
    ///
    /// Written as a serialization of the whole struct with the id blanked,
    /// rather than as a list of fields to hash: a list is a thing somebody
    /// adds a field beside. So this test does not enumerate fields either --
    /// it asserts the property that makes enumeration unnecessary, that two
    /// orders with identical ids have identical encodings.
    #[test]
    fn an_id_determines_the_terms_it_was_derived_from() {
        let one = terms("tb1q", 1);
        let mut two = one.clone();
        two.id = OrderId::from_terms(&one);
        let mut three = two.clone();
        three.anchor = Some(freenet_bitcoin_common::BlockAnchor {
            height: 1,
            hash: freenet_bitcoin_common::BlockHash([2u8; 32]),
        });
        assert_ne!(
            OrderId::from_terms(&two),
            OrderId::from_terms(&three),
            "a field added since this test was written must still change the id"
        );
    }

    /// **The id does not depend on what it currently holds.**
    ///
    /// The derivation blanks the id before hashing, so computing it twice --
    /// once on a fresh order and once on the order carrying the result --
    /// gives the same answer. Without that it would not be a fixed point and
    /// `verify` could never be satisfied.
    #[test]
    fn deriving_an_id_is_idempotent() {
        let mut order = terms("tb1q", 1);
        let first = OrderId::from_terms(&order);
        order.id = first.clone();
        assert_eq!(OrderId::from_terms(&order), first);
    }

    /// **The order id derivation is pinned.**
    ///
    /// Same instrument and same reason as
    /// `listing::listing_identity_tests::the_listing_id_derivation_is_pinned`,
    /// which carries the full argument: a change here makes every order a
    /// previous generation published fail `verify`, and the migration's fold
    /// discards that generation whole rather than the offending record.
    ///
    /// Milder for orders than for listings, because an order expires after
    /// [`MAX_ANCHOR_AGE_BLOCKS`] and one old enough to be in a predecessor
    /// generation is one nobody could pay. It is still the same class of
    /// change, and it still takes the store's listings with it, because the
    /// fold refuses the generation rather than the record.
    ///
    /// **`docs/design/migratability.md` is the requirement and the procedure.**
    /// The first question it asks is whether the new version can accept old
    /// state after all, because that is the only option costing nobody
    /// anything -- and it is what keeps ANY UI able to migrate a contract.
    /// Owner-assisted re-issue buys the data back and spends that property.
    /// Accepting the old format in `verify` is not available; the document
    /// says why, twice over.
    #[test]
    fn the_order_id_derivation_is_pinned() {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let order = Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa],
            payment_address: "tb1qexample".to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at,
        };
        assert_eq!(
            hex::encode(OrderId::from_terms(&order).0),
            // Moved by harvest#57, which removed `listing_id` from the terms.
            // Was a9fca6b22ee60ee36880d5b1ae447b0ab13a9d5a4b5d5f11e62a0987e334f1c8.
            "89c3b624f76472b58e280eb62d42f12ad6216412524e5510a5766022c65ee61f",
        );
    }

    /// **The id is the WHOLE digest, not a prefix of one.**
    ///
    /// The width is the point of the change that widened it: at 16 bytes a
    /// collision between two orders the seller chooses costs ~2^64, and at 32
    /// it costs 2^128. A derivation that kept the old truncation while the
    /// type grew would leave 16 bytes of zeroes and the old cost, and nothing
    /// else here would notice -- the ids would still be distinct, still
    /// deterministic, still refuse a mismatched record.
    ///
    /// Asserted against the components rather than against a copy of the
    /// function, so a change to the truncation fails while a change to the
    /// domain separator or the preimage fails somewhere more specific.
    #[test]
    fn the_id_is_the_whole_digest() {
        let order = terms("tb1q", 1);
        let mut probe = order.clone();
        probe.id = OrderId([0u8; 32]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"harvest/order-id/v2");
        hasher.update(&crate::to_cbor(&probe).expect("serialize"));

        assert_eq!(OrderId::from_terms(&order).0, *hasher.finalize().as_bytes());
    }

    /// **A record whose id is not its terms' id is rejected.**
    ///
    /// This is what makes the property hold on the network rather than only
    /// in the issuer: the store contract runs `verify` on every order in
    /// every state it validates, so a hand-built record filed under somebody
    /// else's id never becomes state anywhere.
    #[test]
    fn a_record_whose_id_is_not_its_terms_is_rejected() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let honest = commitment(terms("tb1q", 1), &signing_key);
        honest
            .verify(&signing_key.verifying_key())
            .expect("an order carrying its own terms' id verifies");

        // Re-sign a record whose id names a different order's terms, so the
        // signature is genuine and the ID is the only thing wrong.
        let mut forged = terms("tb1q", 1);
        forged.id = OrderId::from_terms(&terms("tb1q_elsewhere", 1));
        let forged = {
            use ed25519_dalek::Signer;
            use freenet_stdlib::prelude::ContractInstanceId;
            let message = crate::to_cbor(&forged).expect("serialize");
            let scoped = ghostkey_common::ScopedPayload {
                requestor: ghostkey_common::SignatureRequestor::WebApp(
                    crate::HARVEST_WEBAPP_CONTRACT_ID
                        .parse::<ContractInstanceId>()
                        .expect("canonical webapp id"),
                ),
                payload: message,
            };
            let scoped_payload = crate::to_cbor(&scoped).expect("serialize scoped");
            AuthorizedOrder {
                signature: signing_key.sign(&scoped_payload).to_bytes().to_vec(),
                order: forged,
                scoped_payload,
                status: OrderStatus::AwaitingPayment,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            }
        };
        let refused = forged
            .verify(&signing_key.verifying_key())
            .expect_err("an order whose id is not its terms' id must be refused");
        assert!(
            refused.contains("id"),
            "the refusal should say what is wrong: {refused}"
        );
    }
}

#[cfg(test)]
mod address_instance_tests {
    use super::*;

    fn terms(code_hash: Option<[u8; 32]>) -> Order {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa],
            payment_address: "tb1q".to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: code_hash,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at,
        }
        .with_derived_id()
    }

    /// **An order with no code hash names no address contract.**
    ///
    /// `bitcoin_address_code_hash` is optional, and the honest answer for an
    /// order that omits it is "I cannot say", not a guess. A caller that got
    /// an id anyway would subscribe to, and read a balance from, whatever
    /// contract a default hash happened to name.
    #[test]
    fn an_order_with_no_code_hash_names_no_address_contract() {
        assert_eq!(terms(None).bitcoin_address_instance_id(), None);
    }

    /// **The id is a function of the code hash and the order's own payment
    /// terms.**
    ///
    /// Both halves asserted, because either one alone would be satisfied by
    /// a derivation that ignored the other -- and a derivation that ignored
    /// the script would show a buyer the balance of a different address under
    /// their own order.
    #[test]
    fn the_address_contract_id_covers_the_code_hash_and_the_script() {
        let one = terms(Some([7u8; 32]));
        let mut other_script = one.clone();
        other_script.payment_script_pubkey = vec![0x00, 0x14, 0xbb];
        let other_script = other_script.with_derived_id();

        assert_ne!(
            one.bitcoin_address_instance_id(),
            terms(Some([8u8; 32])).bitcoin_address_instance_id(),
            "a different contract build is a different instance"
        );
        assert_ne!(
            one.bitcoin_address_instance_id(),
            other_script.bitcoin_address_instance_id(),
            "a different destination is a different instance"
        );
    }

    /// **It is the derivation Freenet itself performs.**
    ///
    /// `BLAKE3(code_hash || cbor(parameters))` is not a convention this crate
    /// is free to choose -- it is how a contract's address is formed, and a
    /// second derivation that drifted would have the UI subscribing to an
    /// address that does not exist and reporting "no payment seen" forever.
    /// Asserted against the components rather than against a copy of the
    /// code.
    #[test]
    fn the_derivation_is_blake3_over_the_code_hash_and_the_parameters() {
        let order = terms(Some([7u8; 32]));
        let params = crate::to_cbor(&order.bitcoin_params()).expect("parameters always serialize");
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[7u8; 32]);
        hasher.update(&params);

        assert_eq!(
            order.bitcoin_address_instance_id(),
            Some(*hasher.finalize().as_bytes())
        );
    }
}

#[cfg(test)]
mod proof_assembly_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_bitcoin_common::spv::testing::payment_proof;
    use freenet_bitcoin_common::{BlockHash, ClaimBody, SignedTipEntry, TipEntryBody};

    fn bridge() -> SigningKey {
        SigningKey::from_bytes(&[61u8; 32])
    }

    fn order_for(amount_sats: u64, required_confirmations: u32) -> Order {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            payment_address: "tb1qexample".to_string(),
            required_confirmations,
            payment_hash: None,
            trusted_bridges: vec![BridgeId(bridge().verifying_key().to_bytes())],
            bitcoin_address_code_hash: Some([4u8; 32]),
            // One below the lowest height a fixture here confirms at, so each
            // payment reads as made after its order (see `verify_on_chain_proof`).
            anchor: Some(BlockAnchor {
                height: 99,
                hash: BlockHash([0x99; 32]),
            }),
            order_binding: None,
            listing_tag: None,
            created_at,
        }
        .with_derived_id()
    }

    /// One bridge-signed confirmation of `value_sats` to this order's script,
    /// included at `confirmed_at` and attested by a bridge that has scanned
    /// as far as `scanned_to`.
    ///
    /// # The two heights are not the same thing, and it took a red test to
    /// see it
    ///
    /// The depth a claim attests is capped by the BRIDGE's own watermark
    /// (`as_of`), not by the chain tip: a bridge that has only scanned to the
    /// block a payment landed in is attesting one confirmation, however high
    /// the tip has since climbed. That is deliberate upstream -- otherwise a
    /// submitter could pair a pre-reorg confirmation with a fresh tip and
    /// claim any depth they liked.
    ///
    /// A fixture that moved only the tip therefore reported "1 confirmation"
    /// forever, which is what the first version of the depth test did.
    fn confirmation(
        order: &Order,
        value_sats: u64,
        confirmed_at: u32,
        scanned_to: u32,
    ) -> SignedClaim {
        let (spv, txid, block_hash) =
            payment_proof(&order.payment_script_pubkey, value_sats, 1, [7u8; 32]);
        SignedClaim::sign(
            &bridge(),
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: BlockAnchor {
                    height: scanned_to,
                    hash: BlockHash([5u8; 32]),
                },
                claim: Claim::ConfirmedOutput {
                    outpoint: freenet_bitcoin_common::OutPoint { txid, vout: 0 },
                    value_sats,
                    anchor: BlockAnchor {
                        height: confirmed_at,
                        hash: block_hash,
                    },
                    spv,
                },
            },
        )
        .expect("sign")
    }

    fn tip_at(order: &Order, height: u32) -> SignedTipEntry {
        SignedTipEntry::sign(
            &bridge(),
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height,
                    hash: BlockHash([9u8; 32]),
                },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .expect("sign")
    }

    /// **A confirmed payment assembles into a proof that verifies.**
    ///
    /// The whole point: `verify_payment_proof` and the bridge claims existed
    /// already, and nothing constructed the thing they verify -- so a
    /// published order sat `AwaitingPayment` forever however much had been
    /// paid, and the public record permanently misstated what happened.
    #[test]
    fn a_confirmed_payment_assembles_into_a_proof_that_verifies() {
        let order = order_for(50_000, 1);
        let claims = vec![confirmation(&order, 50_000, 100, 100)];

        let proof = assemble_on_chain_proof(&order, &claims, &tip_at(&order, 100))
            .expect("a confirmed payment of the full amount must assemble");

        assert_eq!(
            verify_payment_proof(&order, &proof).expect("and must verify"),
            50_000
        );
    }

    /// **The assembler verifies before it returns, so a caller cannot publish
    /// a proof that will be refused.**
    ///
    /// Asserted through the cases a caller would otherwise have to know to
    /// check for itself. Each is the assembler declining rather than handing
    /// back something the contract rejects -- an order published as `Paid`
    /// with a proof that does not verify is a state every peer refuses, which
    /// on the buyer's screen looks like the payment simply not registering.
    #[test]
    fn the_assembler_declines_what_would_not_verify() {
        let order = order_for(50_000, 6);

        // Nothing seen at all.
        assert!(assemble_on_chain_proof(&order, &[], &tip_at(&order, 100)).is_err());

        // Seen, but the bridge has not scanned deep enough to attest the six
        // confirmations this order asks for.
        let shallow = vec![confirmation(&order, 50_000, 100, 102)];
        assert!(
            assemble_on_chain_proof(&order, &shallow, &tip_at(&order, 102)).is_err(),
            "three confirmations is not the six this order asks for"
        );
        // The same payment, once the bridge has scanned on.
        let deep = vec![confirmation(&order, 50_000, 100, 105)];
        assert!(assemble_on_chain_proof(&order, &deep, &tip_at(&order, 105)).is_ok());

        // Deep enough, but short of the amount.
        let short = vec![confirmation(&order, 49_999, 100, 105)];
        assert!(
            assemble_on_chain_proof(&order, &short, &tip_at(&order, 105)).is_err(),
            "an underpayment is not a payment"
        );
    }

    /// **A claim about somebody else's address is not carried into the
    /// proof.**
    ///
    /// The claims a node holds come from whatever address contracts it has
    /// subscribed to, and there is no reason a caller cannot hand over the
    /// wrong set. `verify_on_chain_proof` refuses a foreign claim outright --
    /// so including one would turn a perfectly provable payment into an
    /// unprovable one, which is the failure a buyer could not diagnose.
    #[test]
    fn a_claim_about_another_address_is_left_out() {
        let order = order_for(50_000, 1);
        let mut elsewhere = order_for(50_000, 1);
        elsewhere.payment_script_pubkey = vec![0x00, 0x14, 0xcc, 0xdd];
        let elsewhere = elsewhere.with_derived_id();

        let claims = vec![
            confirmation(&elsewhere, 50_000, 100, 100),
            confirmation(&order, 50_000, 100, 100),
        ];

        let proof = assemble_on_chain_proof(&order, &claims, &tip_at(&order, 100))
            .expect("the order's own claim is enough");
        match &proof {
            OrderPaymentProof::OnChain(on_chain) => assert_eq!(
                on_chain.claims.len(),
                1,
                "only the claim about this order's script belongs in its proof"
            ),
            other => panic!("expected an on-chain proof, got {other:?}"),
        }
    }

    /// **More claims than a proof may carry is refused, not truncated.**
    ///
    /// [`MAX_PROOF_CLAIMS`] is what the verifier will accept. Silently
    /// dropping the excess would be choosing which of a bridge's claims the
    /// network gets to see -- the curation the `OnChainPaymentProof` doc
    /// comment says nothing downstream can detect -- and choosing it on a
    /// buyer's behalf, in their own favour. Refusing says so instead.
    ///
    /// The fixture is sized from the constant, so raising the cap moves the
    /// test with it.
    #[test]
    fn more_claims_than_a_proof_may_carry_is_refused() {
        let order = order_for(50_000, 1);
        let claims: Vec<SignedClaim> = (0..=MAX_PROOF_CLAIMS)
            .map(|i| confirmation(&order, 50_000 + i as u64, 100, 100))
            .collect();
        assert!(claims.len() > MAX_PROOF_CLAIMS);

        let refused = assemble_on_chain_proof(&order, &claims, &tip_at(&order, 100))
            .expect_err("more claims than the verifier accepts must be refused");
        assert!(
            refused.contains("claims"),
            "the refusal should name what is wrong: {refused}"
        );
    }
}
