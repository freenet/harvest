# The receipted complaint: threat model

harvest#53 Phase C, PR #143. This is the document the complaint code is checked against. When a
change to the complaint, the kept purchase or the payment blockers seems to need an exception to
it, change this document first, in the same PR, and say why.

**Why it exists.** Three review rounds on #143 each introduced the next round's P1s. Round 2's
four new P1s all came from round-1 fixes. The common cause was that whether a complaint was
valid kept depending on state the SELLER controls: the store's order list, the order envelope,
the bridge choice. So every patch opened another way around it. The model below removes that
dependency instead of guarding each route to it.

**Revision 2** takes in an independent adversarial review of revision 1 (the overseer's lens,
2026-09-23). It found that revision 1 held on binding, the receipt key and the tie-break, but was
under-specified on how the evidence is OBTAINED. Its findings are labelled TM-A to TM-H in
section 10.

**Revision 3** takes in review round 3 of the code built to revision 2 (labelled R3-*). Its
P1s were again in NEW mechanisms, so revision 3 removes one mechanism rather than guarding it:

- **Auto-keep is gone.** A slot is taken only by a buyer's own press: *Pay this order*, or
  *File a complaint* about a paid copy the node has not kept.
- **No screen shows a buyer a payment address except the purchase card**, once the copy is kept.
- **A kept paid copy tracks the freshest evidence until a complaint is filed**, so a reorg
  before the complaint cannot strand it.
- **The seller's power to reuse one address across many orders** is named in section 2.

**Revision 4** takes in review round 4 (labelled R4-*) and codex round 4. Both round-4 P1s
were again in mechanisms revision 3 added, and both judged a purchase by what the buyer's node
had NOT seen. Revision 4 removes them, and adds nothing that decides anything:

- **The lapsed-unpaid check is gone.** It read "unpaid" from the node's own address view, which
  is empty after a reload, so a buyer who paid, closed the tab and came back after the last
  settling block lost the purchase for good. Every kept unpaid order is now watched and shown
  until it is paid (3.2).
- **The fresher-evidence rule is gone.** A kept `Paid` copy is frozen at its upgrade. It only
  mattered for a reorg deeper than the order's confirmations, it worked only within one tab,
  and it gave the seller a way to move the paid height and grow the copy. That reorg is now a
  stated mainnet residual (7.2).
- Fixes that remove a way the node forgets what it holds, not new mechanisms: the upgrade also
  runs when the tip advances; a kept order's address answers are unioned under both builds;
  a never-kept copy's proof uses the same union as an upgrade; a failed re-assert is retried
  on the existing watch tick.

**Scope.** Harvest launches on signet. The invariant below is claimed for signet. On mainnet
it additionally needs the reorg residual in 7.2 closed, and mainnet is gated on harvest#134.

## 1. The invariant

> **Once a buyer has paid a genuine order, they can file exactly one complaint about it that
> readers will count, and nothing the seller does afterwards can prevent it or erase it.**
>
> **Conditional** on freenet/freenet-bitcoin#25 (section 7.1): until the address contract's
> pruning cannot be driven by a flood, a seller can erase the buyer's payment claims while the
> buyer's node is offline, before it has kept its proof.

- **Genuine** means the order passed every payment blocker on the buyer's own node before any
  payment details were shown. That includes the complaint preconditions (section 4), the
  address-contract check (section 3.1), and the delegate confirming that it keeps a copy.
  Genuineness is decided **once, by the buyer, before payment**. Nothing decided later can
  revoke it.
- **Paid** means a payment proof that verifies against the order's own terms: its bridges, its
  script, its amount, its window and its confirmations. It must be reachable in bounded time, so
  "paid" cannot be put out of reach by definition:
  - `required_confirmations` is at most `MAX_REQUIRED_CONFIRMATIONS` (section 4);
  - at reveal the anchor is at most `MAX_ANCHOR_AGE_BLOCKS` old, so at least
    `PAYMENT_CONFIRMATION_SLACK_BLOCKS` (2016) of the payment window remain for the payment to
    confirm (`PaymentBlocker::AnchorStale`, already enforced).
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
| Evict orders from the store by flooding it, or with an old `created_at` | anything that reads the paid order from `store.orders` (P1-2, R2-2) |
| Replace the store copy with a lower-ranked one in a new store generation | anything that prefers the store copy (R2-6) |
| Close the store, retire the backing, back a second store | anything gated on `store_verifying_key`, `payment_blockers` or backing state (P1-1) |
| Name any bridges in an order, including one it runs | anything that trusts an order's own bridge list |
| Name any `bitcoin_address_code_hash`, so the order points at an address contract nobody writes to | anything that watches the contract the order names (TM-A) |
| Publish orders at 0 sats, or needing 0 or 50,000 confirmations | "a complaint costs a real payment"; "paid" being reachable (TM-C) |
| Mint any number of orders into a conversation carrying the buyer's binding, receipt key and listing tag (it copies all three from the request) | any cap filled by orders the buyer did not choose (R2-3) |
| Publish fabricated `Paid` orders naming the buyer's receipt key, backed by its own bridge or by paying itself | anything that treats "a Paid order naming my key" as "my purchase" (R2-3) |
| Pad the order's signed envelope, list one recognised bridge thousands of times, or submit non-minimal proofs | any size cap: the buyer's copy, the complaint, the record (R2-4, TM-E) |
| Pay its own order address: early or late (to move the paid height), or repeatedly with large transactions (a flood that makes the address contract prune) | the window's start (TM-D); the buyer's claims (TM-B) |
| Reuse one payment address across many orders, so one payment settles all of them (their windows overlap) | any rule that equates one paid order with one payment (R3: cap filling, record growth) |
| Show the buyer a payment address anywhere else: the store's invoice list, the Payments tab (matched on the seller-written `buyer_fingerprint`), a message | keep-then-reveal, if any screen but the purchase card shows an address (R3) |
| Publish a backdated despatch | the complaint window (P2-10) |
| Publish `PaymentReversed` from genuine claims, withholding a later re-confirmation, after a real reorg of the buyer's payment | reader standing (section 6) |
| Submit the buyer's own complaint to the record with a different copy of the order or proof | the record's tie-break |
| Serve readers a stale copy of the record from hosts it runs | "readers count" (section 7) |
| Never open Harvest again | anything that needs the seller to act: migrating the record at a future re-key, or publishing `Paid` |
| Self-deal, or have sockpuppets buy and complain | the meaning of the record (#144; section 6) |

### A third party (anyone)

- Can send dust, or large transactions, to an order's public payment address. That bloats the
  claim set (`assemble_on_chain_proof` refuses more than 32 distinct claims or 256 KiB), and it
  makes the address contract prune the lowest `as_of` claims first.
- Can submit any valid complaint variant to the record, as the seller can, and junk that fails
  verification.
- Can read everything public: orders, payment addresses, complaints.

### The buyer

- Controls its own node: the delegate, the UI it runs, and the conversation secret, from which
  the order binding and the receipt key both derive. The seller cannot compute the receipt key.
- Chooses which orders to pay, and when.
- Can state any `block_height` in its complaint (section 7), and chooses which of its genuine
  in-window payments its proof shows (section 5.2).

### Trusted, and named as such

- **Recognised bridges** (the build's list): for availability and chain selection, for
  retractions (which SPV cannot prove), and for the address-contract generation pointer. They
  cannot mint a payment (SPV).
- **The Harvest webapp** the buyer runs: published under Harvest's contract key, not the
  seller's.
- **freenet-bitcoin's address contract**, for keeping a paid address's claims long enough for
  the buyer to take them. This is the conditional in section 1.

## 3. What the buyer holds, and from when

**The kept purchase** is a delegate record, one per order id: `KeptPurchase { store_key,
conversation, receipt_seed, order, complaint }`.

### 3.1 Keep, then reveal

An order that passes every other blocker shows a *Pay this order* control, and no payment
details. The blockers include two added in revision 2:

- `UnfitForComplaint`: the order fails the complaint preconditions (section 4).
- `AddressContractNotCurrent`: the order's `bitcoin_address_code_hash` is not the address
  contract generation that the recognised bridges' signed pointer names. This is the same
  pointer the seller's UI issues orders from, so an honest order matches until the bridges
  redeploy. An unpaid order issued before a redeploy is then refused, and the buyer asks for it
  again. Orders are payable for at most `MAX_ANCHOR_AGE_BLOCKS` anyway (TM-A).

Pressing the control sends `KeepPurchase` with the seller-signed `AwaitingPayment` copy. The
delegate:

- verifies the copy under `store_key`;
- checks the preconditions;
- derives the receipt seed from the conversation it holds, and checks that its key is the
  order's `buyer_receipt_key` (so a copy cannot be misfiled);
- stores the copy.

Payment details appear only once the delegate's list holds the copy (blocker `PurchaseNotKept`).
So before any money moves, the buyer holds seller-signed terms that a complaint will verify
against, and every later seller act on the store is irrelevant to them.

### 3.2 Watching and upgrading

For **every** kept order still `AwaitingPayment`, the UI watches, and periodically re-reads,
the address contract under the order's code hash **and** under the current generation
pointer's hash, and shows the purchase card. The pointer follows the bridges' redeploys; the
order's hash is fixed at issue. It stops at the upgrade to `Paid`, or once the bridge-signed
tip passes the last block any complaint about the order could count at
(`last_settling_block + DESPATCH_WINDOW_BLOCKS + COMPLAINT_WINDOW_BLOCKS`), after which
nothing is lost by not watching (R5). The node never decides an order lapsed from what it has
not seen, because an empty or stale view is not evidence of non-payment (R4-1). That is at most
1,024 orders, all from the buyer's own presses (5.1). The card shows no address once the payment window has closed
(`offers_payment_address`, `PaymentBlocker::AnchorStale`).

Answers for those watches are unioned with the claims already held, under either build, never
substituted (codex r4): the node resolves the address parameters from its kept orders as well
as from the stores it has loaded.

Once the claims it holds prove the order paid, the UI builds the **minimal covering proof**
(section 5.2) over the **union** of every claim it holds for the order: the watched address
contracts' claims and any store copy's. It then sends the `Paid` copy. It checks on every
event that can make an order provable: a store's state, an address's claims, the kept list,
and the chain tip (codex r4: for an evicted order the tip can be the only one). The union
matters, because a store copy carries only the claims the seller chose (R3). Delegate rules:

- a kept `AwaitingPayment` copy is replaced by a verifying `Paid` copy of the same id;
- **a kept `Paid` copy is never replaced** (revision 4 removed the fresher-evidence rule;
  7.2 says what that leaves);
- a kept `Paid` copy's complaint signs its paid height;
- a record without a complaint gains one exactly once, and it must verify;
- a held record that no longer decodes or verifies is overwritten.

### 3.3 A paid order this node never kept (TM-F; auto-keep removed in revision 3)

Revision 2 auto-kept any store `Paid` copy naming this conversation's receipt key. Round 3
showed that a seller can then fill every slot on the node with one payment. It mints orders
on one reused address, pays it once, and publishes them `Paid`. The node can then never buy
again. So nothing is kept without a press.

A store `Paid` copy that the node never kept is still shown as this buyer's paid purchase if
it passes all of the fallback checks:

- it names this conversation's receipt key;
- it verifies under the store's owner key;
- it names only recognised bridges;
- it meets the preconditions.

Such a copy comes from a payment made on another device, before this build, or outside the
app's flow. **Filing a complaint about it is the press that keeps it.** The complaint action
sends the paid copy together with the complaint, in one `KeepPurchase`. Its minimal proof is
built over the union of the store's claims and the order's own address contract's, when that
union proves it paid (R4-4); otherwise the store copy's own proof is used. Only the order's
own build is watched for such a copy, not the current generation's, so for an order naming a
contract nobody writes to the union is the store's claims alone.
Until then, the copy is only as durable as the store's.

### 3.4 Complain, then re-assert

The complaint is built from the kept `Paid` copy (or, for 3.3, the fallback copy) and signed with
the kept receipt seed (or the conversation's). **It is kept first, then PUT.** The complaint
goes to the delegate in a `KeepPurchase`, and the PUT is sent once the delegate's list holds
it. So a lost PUT, or a tab closed mid-PUT, is covered by the re-assert. A complaint cannot be
on the record without being kept.

While a kept copy is still `AwaitingPayment`, and its upgrade is on its way, the complaint
waits. Built from a paid copy computed on the fly, it could name a different paid height from
the upgrade the delegate keeps. The delegate would then refuse to keep the complaint, and the
re-assert would never cover it.

**On every load**, the UI PUTs every kept complaint again, once per complaint per session,
whether or not the store is being viewed (TM-H). This runs on every arrival of the kept list,
not only the first: the first list of a session can arrive from a freshly re-keyed delegate
before the migration has imported the predecessor's records (R3). A failed PUT is tried again
on the next arrival and on the watch tick, so it does not wait for a list that may not come this
session (R4-6). The retry backs off, doubling from a minute to an hour, so a record that keeps
refusing is not sent a PUT a minute (R5). A PUT to an existing record is merged by the contract's
`update_state`, which keeps one complaint per order under a total order, so the re-PUT is
idempotent. The buyer's node is the durable copy, and the public record is a replica of it.
This covers:

- a lost first PUT;
- a record nobody hosts;
- a stale or partial replica;
- the next reputation re-key when the seller never opens Harvest to migrate. Every change to
  `harvest-common` re-keys the reputation contract.

**Why the record carries the receipt seed.** It is self-sufficient: forgetting or evicting the
conversation (256 are kept, oldest out) does not lose the ability to complain (R2-5). Forgetting
a conversation does not forget purchases.

### 3.5 What the complaint carries

The contract verifies a complaint from the complaint alone plus its parameters
(`ReputationParameters { store_key }`, i.e. the record's own address). It carries:

- the seller-signed order;
- the `Paid` status and its **canonical minimal proof**;
- the buyer-signed `ComplaintTerms { tag, order_id, category, block_height, paid_height }` in
  the exact envelope.

The contract reads no store state, no backing, no bridge list other than the order's own, and
no clock.

## 4. The complaint preconditions: one predicate, checked in three places

`payment::complaint_preconditions(&AuthorizedOrder)`:

- `amount_sats > 0`;
- an on-chain order needs at least 1 and at most `MAX_REQUIRED_CONFIRMATIONS` confirmations
  (TM-C);
- the order's signed envelope, and its terms' own encoding, are each at most
  `MAX_ORDER_ENVELOPE_BYTES`.

It is used by:

- the contract (`Complaint::verify`);
- the buyer before payment (`PaymentBlocker::UnfitForComplaint`);
- the delegate before keeping.

Because the buyer refuses to pay anything the contract would refuse, **any order the buyer paid
is one the contract takes a complaint about.** Nothing about the envelope's *encoding* is
checked (R2-1), because the buyer's kept bytes are what get verified, and those are whatever
the seller signed.

The address-contract check (3.1) is buyer-side only. The contract does not care where the
claims were read from, only that they verify.

## 5. Evidence and resource bounds

### 5.1 The delegate

- `MAX_KEPT_PURCHASES` = 1024 per node.
- A slot is consumed only by the buyer's own press: *Pay this order*, or *File a complaint*
  about a paid copy the node never kept (3.3). Nothing the seller mints, fabricates or pays
  for ever takes one.
- A slot taken by a *Pay* press that was never paid is held for the node's lifetime, and its
  address watched until no complaint about it could count (3.2). That is bounded by the buyer's own presses, 1,024 of them (about 2,048
  address watches). Releasing a lapsed unpaid keep needs positive evidence that it was never
  paid, which the node does not have, so revision 4 removed the attempt rather than guessing
  (R4-1).
- At the cap the delegate answers with a typed `KeepPurchaseRefused { order_id, reason }`. The
  UI releases its marker, keeps the payment details hidden and shows why. Refusing to pay is
  the safe failure.
- An upgrade, or a complaint on an already-kept record, never needs a new slot.
- `MAX_KEPT_PURCHASE_BYTES` is derived from the verifier's own limits:
  `2 × MAX_ORDER_ENVELOPE_BYTES + MAX_PROOF_CLAIM_BYTES + 16 KiB`. So any copy that verifies
  fits (R2-4). Pinned at the maximum by a test.

### 5.2 The minimal covering proof, and the signed paid height (TM-D, TM-E)

**Building it.** `payment::minimal_on_chain_proof`:

1. Fold every verified claim for the script, retractions included.
2. Take the in-window `Confirmed` outpoints: those already deep enough first, then the latest
   confirmation first, then the largest value.
3. Accumulate until the amount is covered, then drop any outpoint the rest already covers.
4. For each outpoint, keep only the one claim whose fold is the outpoint's fold.

Properties:

- It verifies whenever the full proof does.
- Third-party dust never enters it, so the 32-claim or 256 KiB bound on the full set is
  irrelevant.
- Latest first means the buyer's own payment is chosen over a seller's earlier self-payment.
  The buyer may pick among its genuine in-window payments, which moves the window by at most
  the payment window (a buyer-side choice, bounded, like `block_height`).

**The contract requires it** (`payment::verify_minimal_proof`, called by `Complaint::verify`):

- one claim per outpoint;
- no claim without an outpoint;
- every outpoint confirmed in the window;
- none that the rest already covers.

Padding a complaint therefore costs real transaction fees, not free duplicate claims. So the
record's growth is bounded by paid orders times genuine transaction sizes, not by 256 KiB per
complaint.

**The buyer signs the paid height.** `ComplaintTerms.paid_height` must equal
`payment::paid_height(order)` over the complaint's own proof (earliest-first accumulation,
which for a minimal proof is its latest needed confirmation). So a seller or third party who
re-submits the buyer's complaint with another proof cannot move the window's start. Any
substitute must show the same paid height.

### 5.3 The record

- No count cap, so nothing can be displaced.
- freenet-core's state size limit (50 MiB) bounds it. **With a reused address (section 2), one
  payment can back many complaints**, so the seller and sockpuppets complaining about their own
  orders can make the record costly to host, or too big to load: about 700 complaints with a
  64 KB transaction, or about 200 at 256 KiB each. That record then reads "record unavailable",
  never "clean record" (but see R5-C in 8a: one kept just under the limit loads). It is a residual (7.3): the seller spends it to make its own record
  unreadable, which is itself a warning to a reader. The original sentence for scale: without
  reuse, filling it takes
  thousands of paid orders, each one a complaint the seller made against itself.
- A record that does not load reads "record not loaded", never "clean record" (`RecordLoad`).

## 6. Reader rules (no re-key needed to change any of them)

- **Standing is read from the complaint.** The window floor is
  `paid_height + DESPATCH_WINDOW + COMPLAINT_WINDOW`, with `paid_height` from the complaint's
  own signed terms. The seller's despatch can only extend it (`max`). A complaint within that
  floor always counts, whatever the store holds.
- **A reversal counts only on the union of the evidence.** A store `PaymentReversed` discounts
  a complaint only if the union of the reversal's claims and the complaint's claims still folds
  to `Reversed`. So a reversal built by withholding a re-confirmation the complaint shows does
  not erase it.
- **Counting never consults closure, retirement or backing.** A seller could backdate a closure
  anchor, so no rule of the form "discount orders after closure" is safe. Complaints are counted
  on the store key's record, whatever the store's status.
- **Self-dealing and sockpuppets (#144, Ian's open call).**
  - Every complaint carries its order's `trusted_bridges`. A reader MAY later discount complaints
    (and paid-order history) whose bridges it does not recognise, as a reader-side filter with
    no re-key.
  - Such a filter must use an **append-only list of every bridge ever recognised**, not the
    current one, or a key rotation would discount honest complaints made under the old key
    (TM-G).
  - It cannot catch self-payment through a recognised bridge. Complaints by sockpuppets are
    bounded only by what the orders cost, which is decision 1's premise (payment guards the
    complaint).
- **A buyer attestation, if Ian wants one, needs no reputation re-key.** An attestation would be
  a separate signed statement: a Ghost Key certificate plus a signature over the order id and
  receipt key. It would be published in its own record or alongside, and readers could weight
  complaints by it. `docs/design/incentive-mechanism.md` assumed a complaint publishes a Ghost
  Key; these carry none (TM-G). That design decision is either superseded by the receipted
  design, or met later by such a separate attestation. This is Ian's call (section 9).

## 7. Residuals (stated, not closed)

### 7.1 The conditional: address-contract pruning (freenet/freenet-bitcoin#25, TM-B)

The address contract prunes the lowest `as_of` claims first. A seller can pay its own order
address repeatedly with large transactions: that costs only fees, and nothing on signet. That
flood pushes out the buyer's `ConfirmedOutput` claims, including the rung that attests the
required depth, while the buyer's tab is closed (a delegate cannot subscribe). The buyer's node
then never sees a proof, and the invariant fails for that purchase.

The fix belongs in freenet-bitcoin, and Harvest does not work around it:

- either an eviction policy a zero-cost flood cannot drive, e.g. keep each outpoint's deciding
  claim before any non-deciding one;
- or a targeted attestation for the buyer's outpoint from a recognised bridge.

Until one lands, the invariant is conditional. The window is from confirmation to the buyer's
next load of Harvest.

### 7.2 Reorgs deeper than the order's confirmations (mainnet; gated on harvest#134)

The kept copy is upgraded to `Paid` once the payment is `required_confirmations` deep, and is
frozen from then on (revision 4). If a reorg deeper than that later retracts the buyer's
payment and it is re-confirmed in another block:

- the kept copy, and any complaint built from it, shows only the pre-reorg claim;
- a seller's `PaymentReversed` built from {that claim, the retraction}, withholding the
  re-confirmation, folds to `Reversed` on the union of the evidence (section 6), so it
  discounts the complaint.

The same holds for a reorg after the complaint is filed. The record's tie-break among copies of
one buyer statement keeps the highest `as_of` (`canonical_rank`); with several outpoints a copy
with one outpoint stale can tie with the honest one (R4-3). That also matters only here.

Revision 3's fresher-evidence rule addressed the pre-complaint half, but only while one tab
stayed open, and it cost a way for the seller to move the paid height and grow the kept copy.
It was removed. Signet is produced by a single signer and does not reorg this deep in
practice, so this does not block the signet launch. Closing it for mainnet, if it is closed in
Harvest at all, needs the buyer's node to follow the payment's re-confirmation across
sessions, and belongs with the reorg model freenet-bitcoin already has (`PaymentReversed`,
retractions), not with a Harvest-local copy of it.

### 7.3 Others

- **Buyer-stated `block_height`.** It is not a clock. A buyer can state an in-window height after
  the window, so the window binds only the honest (P2-10, unchanged).
- **The paid height a buyer's proof shows.** It is fixed at the upgrade. The selection takes
  payments already deep enough first, then the latest, so a seller can move it either way: a
  self-payment that confirmed earlier and is deep enough while the buyer's is still shallow is
  chosen, moving it EARLIER by up to `required_confirmations - 1` blocks plus the buyer's own
  confirmation delay (R5 P3), which shortens every window by that much; a self-payment after
  the buyer's, before the upgrade, moves it later. That delays when the complaint can be
  filed (the `AwaitingDespatch` stage), by at most the payment window, and costs the buyer no
  time, because every window moves with it.
- **Record growth through a reused address** (5.3).
- **An address-contract generation missed** when the bridges redeploy twice while the buyer is
  away. Only the order's and the current generation are watched.
- **Address reuse** lets someone complain on another's payment to a reused address (round 1,
  #15).
- **Channels in seller-signed or payer-chosen bytes:**
  - the seller's order text on the seller's own record (#144);
  - `OP_RETURN` and witness bytes in SPV transactions;
  - the certificate's ground `verifying_key` (R2-8).
- **A payment made outside the app's flow** (an address from a message) is never kept until
  the buyer files a complaint about it (3.3). Until then it lasts only as long as the store
  keeps it. The app itself shows no address outside the purchase card.
- **A stale record.** A reader served a stale copy by hosts the seller runs sees fewer
  complaints until its subscription catches up. The buyer's re-assert (3.4) pushes its
  complaint back into the network on every load.
- **Another device.** A conversation restored from a backup string on another device does not
  carry the kept purchase. There, the complaint rests on the store's copy (the fallback in 3.3)
  until the buyer files, which keeps it, or the store drops it.
- **A buyer who never returns after a re-key.** Their complaint stays on the old record, and
  readers look at the new one. A reader-driven legacy walk (#145) would close this.
- **Kept-purchase list size.** 1,024 records at the derived bound would be about 290 MiB. That
  is reachable only by the buyer's own 1,024 presses, each on an order whose genuine claims
  are about 256 KiB. With auto-keep removed, nothing else can add a record, and with the
  fresher-evidence rule removed a kept copy does not grow after its upgrade. A minimal proof
  for an ordinary payment is a few kilobytes, so the list stays one response, and it is not
  paged (TM P3).
- **A complaint's evidence is decoded before its size bound is checked.** `Complaint::verify`
  runs `verify_minimal_proof` and `paid_height` before `AuthorizedOrder::verify` enforces
  `MAX_PROOF_CLAIMS` and `MAX_PROOF_CLAIM_BYTES` (codex r4 P1). Both are single linear passes
  over a delta the contract has already decoded in full, and a delta that fails is refused
  with no change to the state. So this is proportional work on junk anyone may submit
  (section 2), not an amplification, and moving the bound earlier would re-key every contract
  for no change to what is accepted. Recorded, not changed.

## 8. Compatibility requirements this creates (TM-H)

- **The complaint format is append-only.** Any future reputation contract must accept every
  complaint format an earlier one accepted, including the order inside it. The OrderId widening,
  which dropped old orders, must never happen to complaints: old orders dropping out of a store
  is acceptable, and complaints dropping out of a record is the erasure this model forbids. New
  fields are `#[serde(default)]` and are skipped when absent.
- **`KeptPurchase` travels with the delegate.** The kept-purchase import family is part of the
  delegate migration walk (`import::Family::KeptPurchase`). The imported record is re-checked
  with the seed it carries, so it does not wait for its conversation.
- **The merge semantics of a PUT to an existing record** are the contract's own `update_state`
  (a merge). The re-assert relies on that, and the E2E walk-through checks it.
- **Everything `Complaint::verify` and the delegate's `check` depend on must never tighten**
  for records already made (R3). A later build that refuses an old complaint erases it at the
  next re-key: the re-assert is refused, and the kept purchase fails to import. That covers:
  - freenet-bitcoin's `ClaimBody` and SPV encoding, `fold_outpoint_status`, and its proof-of-work
    floor. The revision is pinned in `Cargo.lock`, and bumping it is a change to review under
    this rule;
  - `paid_height`'s definition;
  - every `MAX_*` bound;
  - `LEGACY_HARVEST_WEBAPP_CONTRACT_IDS` (append-only);
  - the `ScopedPayload` format.

  A frozen-bytes complaint fixture (`tests/fixtures/reputation-state-complaint-v1.cbor`),
  decoded, re-encoded and verified by `Complaint::verify` in every build, pins it
  (`a_complaint_from_the_first_build_still_verifies`).

## 8a. Open after review round 5 (these block the merge)

Round 5 attacked this model directly and found three ways a paid buyer on signet can lose the
complaint. None is in a mechanism added in rounds 3 to 5; each is a dependency the model did
not name. Recorded here so the next revision addresses them rather than rediscovering them.

- **R5-A: the seller decides whether the bridge ever observes the payment.** A bridge scans
  only addresses it has been asked to watch (`ui/src/bitcoin_inbox.rs`), and only the
  seller's node asks (`watches_wanted`). A seller that never registers the watch, or
  unwatches after the buyer's transaction appears, leaves the buyer with no claim at depth, so
  the kept copy never upgrades and the complaint is never offered. Candidate fix: keep, watch,
  then reveal, with the buyer's own node registering interest before the address is shown.
  That is a freenet-bitcoin interaction (who may register a watch, and under what policy), so
  it is decided with that layer, not built as a Harvest-local copy. **Needs a design decision.**
- **R5-B: filing needs the store's current state.** `complaint_checks` and the purchase card
  read `browsing_stores[..].owner`, and only the current build's store address is loaded. A
  store re-key while the seller never returns, or a store nobody hosts, leaves no complaint
  control. Candidate fix, which removes a dependency: file from the kept record alone
  (`store_key`, receipt seed and paid copy are all in it; the record's address derives from
  `store_key`), in a view that does not need the store, with the despatch optional.
- **R5-C: the record can be filled with complaints that never count.** `Complaint::verify` does
  not relate `block_height` to `paid_height`, so a seller with sockpuppet orders on a reused
  address can fill its record with `Late` complaints to just under freenet-core's state limit.
  They verify and do not count, and an honest complaint's merge is then refused. So 5.3's
  "reads unavailable, never clean" is false for a record kept just under the limit. Candidate
  fix: the contract refuses a `block_height` past the window. That makes the window a contract
  rule, reversing decision 4 of the #53 design ("reader-side, tunable without a re-key"), and
  a contract window cannot include the despatch extension, which readers take from the
  store's current copy (and which a seller can also withdraw after a buyer files in it:
  R5 P2). **Needs Ian's call.**

## 9. For Ian (does not block this PR; the code works for either answer)

- **#144, bridge trust and self-dealing:** open. Readers count every complaint the contract
  accepts; a discount filter can be added later (section 6).
- **TM-G: a Ghost Key on complaints.** `incentive-mechanism.md` assumed one. Recommendation:
  record that assumption as superseded by the receipted design, since payment is the cost of a
  complaint. Keep an optional separate attestation as a later addition if sockpuppet complaints
  show up in practice. Either answer needs no reputation re-key.
- **The conditional in 7.1** needs freenet-bitcoin#25 fixed before a mainnet launch. It does not
  block signet.
- **The reorg residual in 7.2** also needs deciding before mainnet (harvest#134).

## 10. Findings checked against this model

"Model" means the model removes the premise, and the code must follow it. "Code" means a change
is needed. "Residual" means section 7.

| Finding | Status |
|---|---|
| r1 P1-1 control gated on backing/blockers | Model (3): eligibility comes from the kept copy. The UI code is reworked. |
| r1 P1-2 eviction after Paid | Model (3.1): kept before payment. Code. |
| r1 P1-3 complaint envelope exact | Kept, for the complaint half only. |
| r1 P1-4 certificate | Fixed; unaffected. |
| r1 P1-5 unloaded record reads clean; self-dealing | Fixed (`RecordLoad`); self-dealing per 6 / #144. |
| r1 P1-6, P2-7, P2-8, P2-9, P2-11, P2-12, P2-13 | Fixed; unaffected. |
| r1 P2-10 backdated despatch | Model (6): the floor comes from the signed paid height. Residual for late despatch only. |
| r1 #14 variant verification work | Dismissed; minimal proofs (5.2) also cap the variants. |
| r1 #15 address reuse | Residual. |
| R2-1 order envelope exactness | Model (4): dropped; preconditions shared; envelope bounded by size. Code. |
| R2-2 eviction before Paid seen | Model (3.1): keep before reveal; upgrade from claims. Code. |
| R2-3 fakes counted as paid, fill the cap | Model (3.3, 5.1). Code. |
| R2-4 size bound below a genuine proof; untyped refusal | Model (5.1, 5.2). Code. |
| R2-5 conversation loss | Model (3.4): the record carries the receipt seed. Code. |
| R2-6 store copy hides kept Paid | Model (3): kept copy first. Code. |
| R2-7 `block_ref.hash` free text | Code: `block_height: u32`. |
| R2-8 residual channels | Residual (7.3). |
| R2 P3 items (verify in `complaint_checks`, signature before SPV, delegate binds the key, damaged copy, list retry, certificate re-verify, armour pin, despatch eviction, `RecordLoad` test) | Code, or a residual row. |
| codex round 2 | Did not finish; no findings. Round 3 runs codex afresh. |
| **TM-A** seller names the watched address contract | Code: `AddressContractNotCurrent` blocker; watch under the pointer's hash too (3.1, 3.2). |
| **TM-B** pruning flood while offline | Conditional (1, 7.1) on freenet-bitcoin#25. No Harvest workaround. |
| **TM-C** unbounded confirmations; paying near the window's end | Code: `MAX_REQUIRED_CONFIRMATIONS` in the shared predicate. The window end is already covered by `AnchorStale` (section 1). |
| **TM-D** paid height movable | Code: `ComplaintTerms.paid_height`, checked by the contract; latest-first selection (5.2). |
| **TM-E** record bounded by bytes | Code: the contract requires the canonical minimal proof (5.2); an unloadable record reads "not loaded" (5.3). |
| **TM-F** out-of-band payment skips the keep | Revision 3 removed auto-keep: the complaint press keeps it (3.3). Residual until then (7.3). |
| **TM-G** #144 neutrality, sockpuppets, Ghost Key assumption | Model (6, 9): ever-recognised list; attestation as a separate record; Ian's call. |
| **TM-H** format compatibility, migration walk, stale GET, re-assert sweep, PUT semantics | Model (3.4, 7.3, 8). Code: sweep on load; import family. |
| **TM P3** list size; selection vs `paid_height` | Residual (7.3); fixed by 5.2 (one rule for both). |
| New in revision 1: closure/retirement never discounts; reversal needs the union of evidence; re-assert; minimal proof; keep on the press | Code (3, 5, 6). |
| **R4-1** (P1) the lapsed-unpaid check suppressed its own input | Model (3.2, 5.1): check removed; every kept unpaid order watched and shown until paid. Code. |
| **R4-2** (P1) a stale kept copy after a reorg, fixed only within one tab | Model (3.2, 7.2): fresher-evidence rule removed; mainnet residual. Code. |
| R4-3 freshness is the maximum `as_of` with several outpoints | Residual (7.2): only the record's tie-break still uses it, and only reorgs reach it. |
| R4-4 the never-kept copy's proof from store claims only | Code (3.3): the same union as an upgrade. |
| R4-5 the delegate's complaint arm against a fresher offered copy | Moot: no fresher copy is ever offered or kept. |
| R4-6 a failed re-assert waits for a list arrival | Code (3.4): retried on the watch tick. |
| R4 P3 items (refusal digest over the tip, per-step refusal, keep-timeout repaint, `upgrades_due` forever, owned-store-only views, tests passing for the wrong reason, import cases, `despatch_of`, `ConversationForgotten`, list-size claim) | Code, except: per-step refusal and `ConversationForgotten` are answered on the PR; the list-size claim holds again (7.3). |
| codex r4 P1 proof bounds after decoding | Residual (7.3), with the reason. |
| codex r4 P1 lapse from an empty cache | Same as R4-1. |
| codex r4 P1 no upgrade on a tip | Code (3.2). |
| codex r4 P2 paid copies not watched after reload | Moot: a kept paid copy is frozen, so there is nothing to watch for (7.2). |
| codex r4 P2 no parameters for current-generation ids | Code (3.2): resolved from kept orders under both builds. |
