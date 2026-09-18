# Harvest: A Decentralized Marketplace for Freenet

*Design document -- April 2026*

> **The accountability mechanism described here is superseded, and so is its
> account of payment.** This document's account of stores, listings, messaging
> and the overall shape of the application is still accurate. Payment is no
> longer out of band and no longer payment-agnostic: Harvest bills in on-chain
> Bitcoin, one fresh address per invoice, and a bridge publishes signed
> evidence of the payment into Freenet (see the Open Questions entry below, and
> `bitcoin-integration-status.md`). Every "whatever method the seller
> specifies" below is the original design, kept as history. Its
> **blind-signature feedback tokens are not** — see
> [design/incentive-mechanism.md](design/incentive-mechanism.md), whose Part 3
> shows that design fails in three independent ways, and which replaces it with
> seller standing and complaints-as-withdrawals. GitHub issue #8 records the
> superseded design too.

Harvest is a decentralized marketplace application for [Freenet](https://freenet.org), joining the family of Freenet apps alongside **River** (group chat) and **Delta** (wiki/CMS). It enables peer-to-peer commerce with anonymous, donation-backed identities and a novel accountability mechanism based on blind-signature feedback tokens.

## Overview

Harvest lets users create **stores** (analogous to River's chat rooms) where they list products or services. Buyers discover stores via shared links, negotiate purchases through encrypted messaging, and pay an invoice in Bitcoin, which a bridge attests on chain so neither party has to be taken at their word. A cryptographic feedback system holds both parties accountable without revealing their identities.

The system is built on two layers:

1. **Ghostkeys** -- anonymous identities backed by Freenet donations, providing Sybil-resistant pseudonyms with verifiable economic stake
2. **Harvest** -- the marketplace application, including stores, encrypted communication, and a blind-signature feedback mechanism

## Ghostkeys: Identity with Stake

A ghostkey is an anonymous identity created through a Freenet donation. The creation process uses **RSA blind signatures (RFC 9474)** so the signing server never learns which identity it helped create. The result is an Ed25519 keypair with a certificate chain back to the Freenet master key.

### Trust Chain

```
Freenet Master Key --(Ed25519 sign)--> Delegate Certificate --(RSA blind sign)--> Ghost Key Certificate
```

Any verifier can check the full chain. The blind signature ensures unlinkability between the donation event and the resulting identity.

### The Donation Tier as Cryptographic Stake

Each ghostkey's donation tier (\$1, \$5, \$20, \$50, \$100, \$500, \$1000) is encoded in the delegate certificate's `info` field, signed by the Freenet master key. **It can't be forged.** This creates a verifiable economic stake:

- A seller's ghostkey tier signals how much they have at risk
- If their reputation is damaged through negative feedback, abandoning the identity costs them the donation amount
- Convention: buyers should prefer sellers whose ghostkey tier is in the ballpark of the transaction value

A \$100 ghostkey selling \$10 items has strong incentive alignment. A \$100 ghostkey selling \$95 items is riskier -- a single scam nearly pays for a replacement identity.

### Concurrent Transaction Risk

If Alice has a \$100 ghostkey and runs 5 concurrent \$50 transactions, she could scam all 5 buyers, collect \$250, and burn the \$100 ghostkey (net profit \$150). Buyers should check the tier-to-price ratio and be cautious of sellers with many concurrent transactions relative to their stake.

### Ghostkey Delegate

The ghostkey delegate is a general-purpose Freenet component (not Harvest-specific) that stores ghostkey certificates and signing keys locally. Any Freenet app can use it.

**Operations:**
- Import a ghostkey (certificate + signing key from the web creation flow)
- List/label/delete stored ghostkeys
- Sign messages (the Ed25519 private key never leaves the delegate)
- Verify signed messages

## Harvest: The Marketplace

### Core Concepts

- **Stores** -- each store is a Freenet contract listing products from a seller, including the seller's ghostkey certificate and reputation contract key
- **Mailboxes** -- encrypted communication contracts for buyer-seller negotiation
- **Reputation contracts** -- per-identity, append-only records of negative feedback
- **No built-in discovery** -- stores are shared via links, the same way River rooms are shared today

### How a Transaction Works

*As originally designed. Payment steps 3, 5 and 6 are superseded: an invoice
names a fresh Bitcoin address and a bridge attests the payment, rather than the
seller handing over instructions and watching their own wallet.*

**Setup:** Alice is a seller with a \$100 ghostkey. She runs a Harvest store listing handmade goods. Bob is a buyer with a \$50 ghostkey.

**Step 1 -- Bob checks Alice's reputation.** Bob browses Alice's store. Her listing includes her ghostkey certificate (verifiable \$100 tier) and reputation contract key. Bob's client checks: tier >= product price? Any negative feedback? How old is the ghostkey?

**Step 2 -- Bob initiates contact.** Bob sends an encrypted message to Alice's mailbox: "I'd like to buy item X. Here's my blinded feedback token for your reputation."

**Step 3 -- Alice responds.** Alice's delegate blind-signs Bob's feedback token (she can't see the actual token content due to blinding). She replies with:
- The blind signature on Bob's token
- Her own blinded feedback token for Bob's reputation
- Payment instructions (e.g., a cryptocurrency address and amount, with a time limit)

The exchange of feedback tokens doubles as the transaction handshake -- it signals both parties are committing.

**Step 4 -- Bob completes the token exchange.** Bob blind-signs Alice's feedback token and sends the signature back. Now both parties hold a feedback token for the other's reputation.

**Step 5 -- Payment.** Bob pays using whatever method Alice specified. This happens entirely outside Freenet -- the marketplace is payment-agnostic. Could be Bitcoin, another cryptocurrency, or any other payment method.

**Step 6 -- Fulfillment.** Alice sees the payment arrive (she checks her own wallet -- out of band) and fulfills the order.

**Step 7 -- Resolution.** If everything goes well, neither party uses their feedback token. If something goes wrong, the aggrieved party submits their token with negative feedback to the other's reputation contract.

### The Feedback Mechanism

The feedback system provides anonymous, unforgeable, uncensorable accountability.

#### Why Only Negative Feedback

Positive feedback is meaningless in this system. Because feedback tokens are blind-signed, a seller could sign a token for themselves, submit positive feedback, and nobody could detect it. The seller issues the blind signatures, so they can create a token, blind it, sign the blinded version, unblind it, and submit it to their own reputation contract -- indistinguishable from legitimate positive feedback.

**Only negative feedback carries information** -- nobody would voluntarily damage their own reputation. This eliminates an entire class of manipulation (fake reviews, astroturfing) by making it structurally impossible to game.

Reputation is therefore an append-only list of negative feedback entries. A clean record (zero negatives, old ghostkey, high tier) is the best possible reputation.

#### Blind Signatures for Anonymity

The feedback token exchange uses the same RSA blind signature mechanism as ghostkey creation:

1. Bob creates a feedback token (containing a target reputation contract, a unique nonce, and the public half of an Ed25519 key he generates for this token alone)
2. Bob **blinds** the token and sends the blinded version to Alice
3. Alice signs the blinded token -- she can't see what she's signing
4. Bob **unblinds** the signature -- now he has Alice's valid RSA signature on a token Alice has never seen in cleartext
5. When Bob later submits this token with feedback, he signs the whole entry (token, Alice's signature, category, comment, timestamp) with the token's key. Alice sees the feedback appear but **cannot link it to Bob**, and nobody but Bob can change what it says (harvest#22: before this, the signature covered the token alone and anyone could re-submit it with different words)

The reputation contract validates: (a) the RSA signature is from the contract owner, (b) the token targets this contract, (c) the nonce hasn't been used before, (d) the token's key signed the entry. If Bob signs two entries for one token, the contract keeps the one with the smaller encoding, so every peer keeps the same one.

#### Mutual Accountability

Both parties exchange feedback tokens. If Bob pays but Alice doesn't deliver, Bob can ding Alice's reputation. If Alice delivers but the product isn't as described, Bob can ding Alice. If Bob makes a fraudulent claim, Alice can ding Bob. This creates mutual deterrence.

### Reputation Contract

Each ghostkey identity has its own reputation contract on the Freenet network. The contract state includes:

- The owner's ghostkey certificate
- An RSA public key for verifying blind-signed feedback tokens
- An append-only list of negative feedback entries (token + signature + content + timestamp)
- A set of used nonces for replay prevention

The feedback content format is defined by the application (Harvest defines categories like "non-delivery", "misrepresented item", etc.), not by the reputation contract itself.

The contract satisfies Freenet's commutative monoid requirement: feedback entries form a grow-only set, where adding entries in any order produces the same result.

## Architecture

### Freenet Component Model

Freenet applications have three component types:

- **Contracts** -- shared state on the network. Pure validation logic (validate, update, summarize, delta). Cannot hold secrets. All data is public.
- **Delegates** -- local agents on the user's node. Store secrets, perform crypto, mediate access. Can read/write contract state. Can talk to other local delegates.
- **UIs** -- web applications in sandboxed iframes, communicating via WebSocket to the local Freenet node.

**Critical constraint:** Delegates on different nodes cannot communicate directly. All cross-node communication goes through contracts. `DelegateMessage` is for local delegate-to-delegate communication on the same node only.

### Freenet API Surface (Key Details)

#### ContractInterface Trait
```rust
pub trait ContractInterface {
    fn validate_state(parameters, state, related) -> Result<ValidateResult, ContractError>;
    fn update_state(parameters, state, data) -> Result<UpdateModification, ContractError>;
    fn summarize_state(parameters, state) -> Result<StateSummary, ContractError>;
    fn get_state_delta(parameters, state, summary) -> Result<StateDelta, ContractError>;
}
```

#### DelegateInterface Trait
```rust
pub trait DelegateInterface {
    fn process(
        ctx: &mut DelegateCtx,          // host functions for secrets, contract access
        parameters: Parameters,
        origin: Option<MessageOrigin>,   // attested by runtime: WebApp(contract_id)
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError>;
}
```

#### DelegateCtx Host Functions
- **Secrets (persistent):** `get_secret()`, `set_secret()`, `has_secret()`, `remove_secret()`
- **Context (temporary batch state):** `read()`, `write()`, `clear()`
- **Contract access (V2):** `get_contract_state()`, `put_contract_state()`, `update_contract_state()`, `subscribe_contract()`
  - Note: V2 put/update are local-only, don't propagate to network
  - For network-visible updates, use V1 `UpdateContractRequest` outbound message

#### Message Types
- **UI to delegate:** `DelegateRequest::ApplicationMessages` via WebSocket
- **Delegate to UI:** `OutboundDelegateMsg::ApplicationMessage`
- **Local delegate to delegate:** `DelegateMessage` (sender field overwritten by runtime for attestation)
- **Delegate to contract (V1):** `OutboundDelegateMsg::GetContractRequest`, `UpdateContractRequest`, etc.
- **Contract updates to delegate:** `InboundDelegateMsg::ContractNotification` (for subscribed contracts)

#### Origin Attestation
- `MessageOrigin::WebApp(ContractInstanceId)` -- runtime attests which web app sent the message
- `DelegateMessage::sender` -- runtime overwrites with actual sender key, preventing spoofing
- These are the security mechanisms that prevent rogue apps from accessing delegate secrets

### Components

| Component | Type | Purpose |
|-----------|------|---------|
| Ghostkey Delegate | Delegate (local) | Stores ghostkey certs + signing keys. General-purpose, used by any app. |
| Harvest Delegate | Delegate (local) | RSA keypair for feedback tokens. Transaction state. Encrypted messaging. |
| Harvest UI | Web container | Store browsing, store management, purchase flow, reputation display. |
| Store Contract | Contract (network) | Product listings, seller ghostkey, reputation link. One per seller. |
| Mailbox Contract | Contract (network) | Encrypted buyer-seller messages. |
| Reputation Contract | Contract (network) | Append-only negative feedback. One per ghostkey identity. |

### Communication Paths

- **UI to local delegate:** `ApplicationMessage` via WebSocket. Runtime cryptographically attests which contract the UI belongs to.
- **Local delegate to local delegate:** `DelegateMessage` with runtime-attested sender. Harvest delegate calls ghostkey delegate for signing.
- **Cross-node (buyer to seller):** Through contracts only. Encrypted messages on the mailbox contract.
- **Feedback submission:** Buyer's delegate writes to seller's reputation contract via the network.

### Feedback Token Protocol Messages

These message types are embedded in whatever encrypted communication channel the app provides (for Harvest, the mailbox contract):

```rust
struct FeedbackToken {
    target_contract: ContractKey,  // which reputation contract this targets
    nonce: [u8; 32],               // unique, prevents replay
    entry_key: [u8; 32],           // Ed25519 key, fresh per token, signs the entry
}

enum FeedbackTokenMsg {
    Request {
        blinded_token: Vec<u8>,
        target_reputation_contract: ContractKey,
    },
    Response {
        blind_signature: Vec<u8>,
    },
}
```

### Reputation Contract State

```rust
struct ReputationState {
    owner: GhostkeyCertificateV1,
    token_verifying_key: RSAVerifyingKey,   // for blind-signed feedback tokens
    feedback: Vec<FeedbackEntry>,            // append-only
    used_nonces: BTreeSet<[u8; 32]>,         // replay prevention
}

struct FeedbackEntry {
    token: FeedbackToken,
    signature: RSASignature,
    content: Vec<u8>,        // format defined by app, not reputation system
    timestamp: u64,
    entry_signature: Ed25519Signature,  // by token.entry_key, over everything above
}
```

### Ghostkey Delegate Message Types

```rust
enum GhostkeyRequest {
    ImportGhostKey { certificate_pem: String, signing_key_pem: String },
    ListGhostKeys,
    GetGhostKey { fingerprint: String },
    DeleteGhostKey { fingerprint: String },
    SetLabel { fingerprint: String, label: String },
    SignMessage { fingerprint: String, message: Vec<u8> },
    VerifySignedMessage { signed_message_pem: String },
}

enum GhostkeyResponse {
    ImportResult { fingerprint: String, delegate_info: String },
    GhostKeyList { keys: Vec<GhostKeyInfo> },
    GhostKeyDetail { fingerprint: String, certificate_pem: String,
                     label: Option<String>, delegate_info: String },
    SignResult { signed_message_pem: String },
    VerifyResult { valid: bool, signer_fingerprint: Option<String>,
                   delegate_info: Option<String>, message: Option<Vec<u8>> },
    Deleted { fingerprint: String },
    LabelSet { fingerprint: String, label: String },
    Error { message: String },
}
```

### Ghostkey Delegate Secret Storage

| Key | Value | Purpose |
|-----|-------|---------|
| `gk:cert:{fingerprint}` | CBOR bytes | GhostkeyCertificateV1 |
| `gk:sk:{fingerprint}` | 32 bytes | Ed25519 signing key |
| `gk:label:{fingerprint}` | UTF-8 string | User-assigned label |
| `gk:index` | CBOR list | All fingerprints |

Fingerprint = first 8 bytes of `BLAKE3(verifying_key_bytes)`, base58-encoded.

## Reference Implementation: River

River (decentralized group chat) demonstrates all Freenet dApp patterns and should be used as the reference:

- **Repository:** `freenet/river`
- **Chat delegate:** `delegates/chat-delegate/` -- `DelegateInterface` implementation, secret storage, signing operations, origin validation
- **Room contract:** `contracts/room-contract/` -- composable state, cryptographic verification, commutative updates
- **UI:** `ui/` -- Dioxus app, WebSocket connection, delegate communication, contract synchronization
- **Common types:** `common/` -- shared request/response enums between delegate and UI
- **Key patterns:** Origin-based key namespacing, CIBORIUM serialization, request/response correlation via oneshot channels

## Build Plan

### Phase 1: Ghostkey Management

General-purpose ghostkey delegate and management UI. Usable by any Freenet app, not Harvest-specific.

- Common types crate (request/response enums)
- Delegate implementation (import, list, sign, verify, delete)
- Dioxus UI (import via PEM paste/file upload, list with labels, sign/verify messages)
- Web container contract for hosting the UI
- Local testing with `freenet local`
- Depends on `gklib` (crates.io v0.1.4) for certificate deserialization and verification

### Phase 2: Harvest Marketplace

The marketplace application built on top of ghostkeys.

- Reputation contract (append-only feedback, blind signature validation)
- Store contract (product listings)
- Mailbox contract (encrypted communication)
- Harvest delegate (RSA keypair management, blind-signing, transaction state)
- Harvest UI (store browsing, store management, purchase flow, reputation display)

## Open Questions

- **Payment integration:** ANSWERED, and no longer out of band. Harvest bills in on-chain Bitcoin: each invoice takes a fresh address derived from the seller's account public key, and a bridge publishes signed evidence of the payment into Freenet, which is what moves an order to Paid. Neither the delegate nor the page needs an external network call for it, because the watch request reaches the bridge through a Freenet contract. What stays out of band is the buyer's wallet: Harvest holds no keys and broadcasts no transactions, and does not want to. One limit is still open: freenet-bitcoin#7, a payment mined before the bridge reads the watch request is not backfilled.
- **Transaction count visibility:** Can we make the number of issued feedback tokens verifiable without revealing counterparties? This lets observers distinguish "2 negatives out of 500 transactions" from "2 out of 3."
- **Token expiry:** Should feedback tokens have a time limit?
- **Dispute resolution:** No mechanism for resolving honest disagreements. Is mutual deterrence sufficient?
- **Shipping/delivery coordination:** How much of the fulfillment flow should Harvest standardize vs. leave to free-form encrypted messages?
- **Ghostkey tier granularity:** Current tiers go up to \$100. Will need \$500 and \$1000 for higher-value transactions.
- **Feedback protocol definition:** JSON schema, Lua validator, or WASM validator for structured feedback content? TBD.

## Privacy and Information Leakage

All Freenet contract state is public. A passive observer who subscribes to Harvest contracts can learn the following:

### What is visible

- **Store contract:** Listings, prices, descriptions, seller ghostkey certificate and donation tier. This is public by design.
- **Reputation contract:** Number of negative feedback entries (lower bound on failed transactions), feedback categories, comments, timestamps.
- **Mailbox contract:** Number of messages, message sizes (padded to bucket boundaries: 1KB/4KB/16KB/64KB), timestamps, sender public keys, conversation IDs.
- **Cross-contract timing correlation:** A burst of mailbox activity followed by a reputation entry can narrow down which conversation led to the feedback, partially undermining blind signature unlinkability.

### Mitigations in place

- **Conversation IDs are random**, not derived from party identities. An observer who knows the seller's fingerprint cannot confirm whether a suspected buyer is communicating with that seller.
- **Buyers use fresh ephemeral keys per store** to prevent cross-store linkability. A buyer shopping at two different stores cannot be linked by their sender public key.
- **Ciphertext padding** to fixed size buckets (1KB, 4KB, 16KB, 64KB) reduces size-based message classification.
- **Feedback tokens are blind-signed (RFC 9474)**: the seller signs tokens they cannot read, so feedback cannot be linked to a specific buyer by the seller or anyone else.

### What cannot be prevented

- **Transaction volume:** The number of reputation entries reveals a lower bound on failed transactions. The total number of mailbox messages reveals approximate buyer traffic.
- **Temporal patterns:** When a seller is active (listing updates), when buyers are messaging (mailbox activity), and when transactions fail (reputation entries) are all visible.
- **Network-level analysis:** Which Freenet nodes subscribe to which contracts reveals interest. This is a Freenet platform concern, not Harvest-specific.
- **Seller identity linkage:** A seller's store, reputation, and mailbox contracts are publicly linked via the seller's ghostkey certificate.

## Beyond Commerce: Non-Monetary Exchange

Harvest is pitched as a marketplace, but the underlying primitives -- ghostkey identities, encrypted mailboxes, stores with listings, and blind-signed negative feedback -- are payment-agnostic and do not require money to change hands. A listing schema extension adding a `kind` field (`sale`, `gift`, `loan`, `trade`, `request`) would let the same protocol carry gift-economy, mutual-aid, tool-library, and barter exchanges with no change to the trust layer: the payment step is simply skipped, and the mutual negative-feedback ceremony still disciplines both parties against failure modes like no-shows, misrepresentation, or reselling donated goods.

This is explicitly out of scope for the initial Harvest release. The marketplace story is the focus, and non-commercial use cases raise their own UX, cultural, and abuse-resistance questions (e.g. how to surface active generosity as positive signal without reintroducing astroturfing) that deserve their own design pass. Noted here so the protocol is not accidentally designed in a way that forecloses a sibling application later.
