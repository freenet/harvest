# The receipted complaint: threat model

harvest#53 Phase C, PR #143. This is the document the complaint code is checked against. When a
change to the complaint, the kept purchase or the payment blockers seems to need an exception to
it, change this document first, in the same PR, and say why.

Why it exists: three review rounds on #143 each introduced the next round's P1s. Round 2's four
new P1s all came from round-1 fixes. The common cause was that whether a complaint was valid
kept depending on state the SELLER controls: the store's order list, the order envelope, the
bridge choice. So every patch opened another way around it. The model below removes that
dependency instead of guarding each route to it.

## 1. The invariant

> **Once a buyer has paid a genuine order, they can file exactly one complaint about it that
> readers will count, and nothing the seller does afterwards can prevent it or erase it.**

- **Genuine** means the order passed every payment blocker on the buyer's own node before any
  payment details were shown. That includes the complaint preconditions in section 4, and the
  delegate confirming that it keeps a copy (section 3). Genuineness is decided **once, by the
  buyer, before payment**. Nothing decided later can revoke it.
- **Paid** means a payment proof that verifies against the order's own terms: its bridges, its
  script, its amount, its window and its confirmations. The proof is assembled from the
  freenet-bitcoin address contract, which is public and not the seller's, and the buyer's
  delegate keeps it.
- **Readers count** means the reputation contract accepts the complaint, and a reader's standing
  rule (`fulfilment::complaint_standing`) returns `Counts`.
- **Exactly one** means the record's slot is keyed by order id, so there is one per paid order.
  The buyer's UI refuses a second complaint once one is on record.

## 2. Parties and their powers

### The seller (holds the store key)

The seller can do any of these, at any time, including after payment:

| Power | What it could break if the design leaned on it |
|---|---|
| Re-sign an order with a different envelope encoding (same terms, same id) | anything that requires a canonical order envelope (R2-1) |
| Evict orders from the store by flooding it, or with an old `created_at` (`enforce_order_cap`) | anything that reads the paid order from `store.orders` (P1-2, R2-2) |
| Replace the store copy with a lower-ranked one in a new store generation | anything that prefers the store copy (R2-6) |
| Close the store, retire the backing, back a second store | anything gated on `store_verifying_key`, `payment_blockers`, or backing state (P1-1) |
| Name any bridges in an order, including one it runs | anything that trusts an order's own bridge list |
| Publish orders at 0 sats, or needing 0 confirmations | "a complaint costs a real payment" |
| Mint any number of orders into a conversation carrying the buyer's binding, receipt key and listing tag (it copies all three from the request) | any cap filled by orders the buyer did not choose (R2-3) |
| Publish fabricated `Paid` orders naming the buyer's receipt key, backed by its own bridge or by paying itself | anything that treats "a Paid order naming my key" as "my purchase" (R2-3) |
| Pad the order's signed envelope, or list the same recognised bridge thousands of times | any size cap on the buyer's copy or on the complaint (R2-4) |
| Publish a backdated despatch | the complaint window (P2-10) |
| Publish `PaymentReversed` from genuine claims, withholding a later re-confirmation, after a real reorg of the buyer's payment | reader standing (see 5.3) |
| Submit the buyer's own complaint to the record with a different copy of the order or proof | the record's tie-break |
| Never open Harvest again | anything that needs the seller to act: migrating the record at a future re-key, or publishing `Paid` |
| Self-deal: pay its own orders and complain about them, or count them as history | the meaning of the record (#144) |

### A third party (anyone)

- Can send dust, or large transactions, to an order's public payment address. That bloats the
  claim set (`assemble_on_chain_proof` refuses more than 32 distinct claims or 256 KiB). It also
  makes the address contract prune the lowest `as_of` claims first.
- Can submit any valid complaint variant to the record (as the seller can), and junk that fails
  verification.
- Can read everything public: orders, payment addresses, complaints.

### The buyer

- Controls its own node: the delegate, the UI it runs, and the conversation secret, from which
  the order binding and the receipt key both derive.
- Chooses which orders to pay, and when.
- Can state any `block_height` in its complaint (section 7).

### Trusted, and named as such

- **Recognised bridges** (the build's list): for availability and chain selection, and for
  retractions, which SPV cannot prove. They cannot mint a payment (SPV).
- **The Harvest webapp** the buyer runs: published under Harvest's contract key, not the
  seller's.

## 3. What the buyer holds, and from when

**The kept purchase** is a delegate record, one per order id: `KeptPurchase { store_key,
conversation, receipt_seed, order, complaint }`.

1. **Keep, then reveal.** An order that passes every other blocker shows a *Pay this order*
   control, and no payment details. Pressing it sends `KeepPurchase` with the seller-signed
   `AwaitingPayment` copy. The delegate:
   - verifies the copy under `store_key`;
   - checks the complaint preconditions;
   - derives the receipt seed from the conversation it holds, and checks that its key is the
     order's `buyer_receipt_key` (so a copy cannot be misfiled);
   - stores the copy.

   Payment details appear only once the delegate's list holds the copy. The blocker
   `PurchaseNotKept` holds until then.

   So before any money moves, the buyer holds seller-signed terms that the complaint will
   verify against. Every later seller act on the store is irrelevant to them.
2. **Upgrade to Paid.** Once a proof for the kept order verifies, the UI sends the `Paid` copy
   with the **minimal covering proof** (5.2). The proof can come from the address contract's
   claims, which the UI watches for every kept order, or from any store copy.

   Delegate rules:
   - a kept `AwaitingPayment` copy is replaced by a verifying `Paid` copy of the same id;
   - a kept `Paid` copy is never replaced, except when the held record does not decode or
     verify;
   - a record without a complaint gains one exactly once, and it must verify.
3. **Complain.** The complaint is built from the kept `Paid` copy and signed with the kept
   `receipt_seed`. It is PUT to the record addressed by `store_key`, then kept in the record.
4. **Re-assert.** Whenever the UI loads the current reputation record of a store it holds a
   filed complaint for, and the record lacks that order id, it PUTs the complaint again. The
   buyer's node is the durable copy, and the public record is a replica of it. This covers:
   - a lost first PUT;
   - a record nobody hosts;
   - the next reputation re-key when the seller never opens Harvest to migrate. Every change
     to `harvest-common` re-keys the reputation contract.

**Why the record carries the receipt seed.** It is self-sufficient: forgetting or evicting the
conversation (256 are kept, oldest out) does not lose the ability to complain (R2-5). Forgetting
a conversation does not forget purchases, and the UI says so.

**What the complaint carries**, so the contract verifies it from the complaint alone plus its
parameters (`ReputationParameters { store_key }`, i.e. the record's own address):

- the seller-signed order;
- the `Paid` status and its proof;
- the buyer-signed `ComplaintTerms { tag, order_id, category, block_height }` in the exact
  envelope.

The contract reads no store state, no backing, no bridge list other than the order's own, and
no clock.

## 4. The complaint preconditions: one predicate, checked in three places

`payment::complaint_preconditions(&AuthorizedOrder)`:

- `amount_sats > 0`;
- an on-chain order needs at least one confirmation;
- the order's signed envelope is at most `MAX_ORDER_ENVELOPE_BYTES`.

It is used by:

- the contract (`Complaint::verify`);
- the buyer before payment (`PaymentBlocker::UnfitForComplaint`);
- the delegate before keeping.

Because the buyer refuses to pay anything the contract would refuse, **any order the buyer
paid is one the contract takes a complaint about.** Nothing about the envelope's *encoding* is
checked (R2-1), because the buyer's kept bytes are what get verified, and those are whatever
the seller signed.

## 5. Resource bounds that cannot be turned against the buyer

### 5.1 The delegate

- `MAX_KEPT_PURCHASES` = 1024 per node. **Only the buyer's own *Pay* press consumes a slot**, so
  a seller's minted or fabricated orders never take one.
- At the cap the delegate answers with a typed `KeepPurchaseRefused { order_id, reason }`. The
  UI releases its marker, keeps the payment details hidden and shows why. Refusing to pay is
  the safe failure.
- An upgrade or a complaint on an already-kept record never needs a new slot.

### 5.2 Proof size

- **The minimal covering proof.** Fold every verified claim for the script (retractions
  included). Take the in-window `Confirmed` outpoints, largest value first, until the amount is
  covered. For each outpoint, keep only the one claim whose fold is the outpoint's fold.
- This verifies whenever the full proof does, because the verifier's result per outpoint is the
  same. It still verifies when the full set is over the 32-claim or 256 KiB bound because of
  third-party dust. Dust never enters it.
- `MAX_KEPT_PURCHASE_BYTES` is **derived from the verifier's own limits**:
  `2 × MAX_ORDER_ENVELOPE_BYTES + MAX_PROOF_CLAIM_BYTES +` a fixed allowance for the tip, the
  complaint and framing. So any copy that verifies fits, whether or not it was trimmed (R2-4).
  A test holds this at the maximum.

### 5.3 The record

- No count cap, so nothing can be displaced.
- Growth needs a paid order per complaint: a real payment through the order's named bridges.
- Verification work from minted variants is the class dismissed in round 1 (#14).

## 6. Reader rules (no re-key needed to change any of them)

- **Standing is read from the complaint.** The window runs from the paid height in the
  complaint's own proof: `paid + DESPATCH_WINDOW + COMPLAINT_WINDOW`. The seller's despatch can
  only extend it (`max`). A complaint within that floor always counts, whatever the store holds.
- **A reversal counts only on the union of the evidence.** A store `PaymentReversed` discounts a
  complaint only if the union of the reversal's claims and the complaint's claims still folds to
  `Reversed`. So a reversal built by withholding a re-confirmation the complaint shows does not
  erase it.
- **Counting never consults closure, retirement or backing.** A seller could backdate a closure
  anchor, so no rule of the form "discount orders after closure" is safe. Complaints are counted
  on the store key's record, whatever the store's status.
- **Self-dealing (#144, Ian's open call).**
  - Every complaint carries its order's `trusted_bridges`. A reader MAY later discount complaints
    (and paid-order history) whose bridges it does not recognise, as a reader-side filter with
    no re-key.
  - The buyer already refuses to pay orders naming a bridge it does not recognise, so a genuine
    buyer's complaint passes any such filter that uses the same list.
  - Today readers count every complaint the contract accepts.

## 7. Residuals (stated, not closed)

- **Buyer-stated `block_height`.** It is not a clock. A buyer can state an in-window height after
  the window, so the window binds only the honest. It was the same before this PR (P2-10).
- **Reorg choice.** After a genuine reorg of the payment, the seller (or anyone) can pick which
  genuine confirmation a complaint copy shows. That moves the paid height within the reorg's
  depth.
- **Address reuse** lets someone complain on another's payment to a reused address (round 1,
  #15).
- **Channels in seller-signed or payer-chosen bytes:**
  - the seller's order text on the seller's own record (#144);
  - `OP_RETURN` and witness bytes in SPV transactions;
  - the certificate's ground `verifying_key` (R2-8).
- **Upstream (freenet-bitcoin): the address contract prunes the lowest `as_of` claims first.**
  A third party flooding a paid address with later large transactions can push the buyer's
  claims out before the buyer's node has kept its proof. The buyer's keep happens as soon as it
  sees the payment, and the bridge re-attests deeper rungs at higher `as_of`, so the window is
  short. Closing it belongs upstream: filed as freenet/freenet-bitcoin#25.
- **Another device.** A conversation restored from a backup string on another device does not
  carry the kept purchase. There, the complaint rests on the store's copy (the fallback in
  section 8) until the store drops it.
- **A buyer who never returns after a re-key.** Their complaint stays on the old record, and
  readers look at the new one. A reader-driven legacy walk would close this; the follow-up
  issue is #145.

## 8. How the UI decides "a paid purchase of mine"

In order:

1. **A kept `Paid` copy.** It is always preferred over any store copy (R2-6).
2. **A kept `AwaitingPayment` copy, plus a verifying `Paid` copy of the same id** from the
   store, or assembled from claims. The kept copy is then upgraded.
3. **Fallback:** a store `Paid` copy with nothing kept (paid on another device, or before this
   build). It is shown, and offered the complaint, only if:
   - it verifies under the store's owner key;
   - it names this conversation's receipt key;
   - every bridge it names is recognised;
   - it meets the preconditions.

   It is not auto-kept, because a seller paying itself could otherwise fill the cap. A
   fabricated order that passes these checks is a real payment through a recognised bridge on
   the seller's own record. Complaining about it only harms the seller who made it.

Everything in 1 and 2 is independent of the store's liveness, backing, closure and order list.

## 9. Findings checked against this model

"Model" means the model removes the premise, and the code must follow it. "Code" means a change
is needed. "Residual" means section 7.

| Finding | Status |
|---|---|
| r1 P1-1 control gated on backing/blockers | Model (8): eligibility from the kept copy. The UI code is reworked. |
| r1 P1-2 eviction after Paid | Model (3.1): kept before payment. Code. |
| r1 P1-3 complaint envelope exact | Kept, for the complaint half only. |
| r1 P1-4 certificate | Fixed; unaffected. |
| r1 P1-5 unloaded record reads clean; self-dealing | Fixed (`RecordLoad`); self-dealing per 6 / #144. |
| r1 P1-6, P2-7, P2-8, P2-9, P2-11, P2-12, P2-13 | Fixed; unaffected. |
| r1 P2-10 backdated despatch | Model (6): floor from the complaint's own proof. Residual for late despatch only. |
| r1 #14 variant verification work | Dismissed (5.3). |
| r1 #15 address reuse | Residual. |
| R2-1 order envelope exactness | Model (4): dropped; preconditions shared, envelope bounded by size. Code. |
| R2-2 eviction before Paid seen | Model (3.1): keep before reveal; upgrade from claims. Code. |
| R2-3 fakes counted as paid, fill the cap | Model (5.1, 8): only the buyer's press keeps; the fallback requires recognised bridges and preconditions. Code. |
| R2-4 size bound below a genuine proof; untyped refusal | Model (5.2): bound derived from the verifier, minimal proof, typed refusal. Code. |
| R2-5 conversation loss | Model (3): the record carries the receipt seed. Code. |
| R2-6 store copy hides kept Paid | Model (8.1). Code. |
| R2-7 `block_ref.hash` free text | Code: `block_height: u32`. |
| R2-8 residual channels | Residual rows (7). |
| R2 P3: `complaint_checks` should run `Complaint::verify` | Code. |
| R2 P3: cheap buyer signature before SPV | Code. |
| R2 P3: delegate binds the receipt key | Model (3.1). Code. |
| R2 P3: damaged first copy blocks later ones | Model (3.2). Code. |
| R2 P3: `ListPaidPurchases` never retried | Code. |
| R2 P3: certificate re-verified on every update | Code. |
| R2 P3: armour label from `type_name` | Pin test; raise with ghostkey_lib. |
| R2 P3: eviction drops the despatch | Model (6): the floor does not need it. Residual row. |
| R2 P3: `RecordLoad` orphan arm untested | Code (test). |
| R2 tests/docs items | Code/docs. |
| codex round 2 | Did not finish; no findings. Round 3 runs codex afresh. |
| **New from the model:** closure/retirement never discounts | Check and test (6). |
| **New:** a reversal needs the union of the evidence | Code (6). |
| **New:** the buyer re-asserts its complaint | Code (3.4). |
| **New:** minimal covering proof | Code (5.2). |
| **New:** keep on the buyer's press, not on display | Code (3.1). |
