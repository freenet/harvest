# Migratability is a requirement, not a nicety

**Status: a requirement and an unbuilt fallback. Written 2026-09-06 on
`feat/buy-flow`, immediately after that branch demonstrated the cost of not
having it. Nothing under "The escape hatch" exists.**

## The requirement

**A new contract version must be migratable from every version that has ever
held user data.**

Ian, 2026-09-06: *migratability from old contract versions should be a
requirement for any new contract version once an app has actual users.*

A change to how a record's identity is derived is **a breaking change to
users' data**, not an internal refactor. It reads like one — a few lines in
one function, every test green, nothing in the type system moving — and that
is exactly why it needs writing down.

The threshold is "once an app has actual users". Harvest does not have them
yet, which is the only reason the loss below was acceptable when it happened.

## The default, and the property it buys

Ian's framing, which is the crux of this whole document:

> Any UI should be able to upgrade a contract, because the state just needs to
> be transferred from old to new — the assumption being that new contracts
> always accept old contract state.

**Preserve this if you possibly can.** When a new version accepts old state,
migration is *pure data transfer*: nobody needs a key, because every record
already carries its own signature. Harvest's own forwarding step is exactly
that — `migrate_ops::encode_forward` re-encodes the merged state and PUTs it,
and there is no signing anywhere in it.

What that property buys is not convenience. It is that **a seller who never
opens Harvest again still has their store carried forward**, by whoever does
open it. Migration stops depending on the continued participation of the
person whose data it is.

Harvest today triggers migration per identity, from that identity's
`GhostKeyList` — but that is a choice about *when* it runs, not a requirement
that the owner be present. The capability is intact. It is what the next
section spends.

## A derivation change breaks that default by construction

Not by carelessness. The two things are in genuine conflict and cannot both be
had for data that already exists:

* **Content-derived identity is correct.** An id that does not cover a
  record's terms lets one seller sign two different records under one id. For
  `ListingId` that meant two prices for one listing and, because
  `ListingsV1::apply_delta` is first-writer-wins, *permanent* divergence —
  each peer keeps whichever it saw first, each one's summary already names the
  id, so neither can ever tell the other.
* **Every record derived the old way becomes unverifiable the moment the rule
  changes.** There is no version of "new accepts old" that survives it,
  because the id IS the thing that changed.

So a derivation change is not a needlessly destructive choice. It is a real
conflict between a correct property and an existing dataset, and the whole of
this document is about who pays for it.

## What it cost here, so none of this is abstract

On `feat/buy-flow`, `ListingId` and `OrderId` became derived from their own
terms. The consequence, unnoticed until it was probed:

1. Every listing published by a previous generation carries an old-style id.
2. `AuthorizedListing::verify` refuses any listing whose id is not the one its
   terms give.
3. `ListingsV1::apply_delta` returns on the **first** refusal.
4. So `fold_or_keep_primary` discards the predecessor **in full** — listings,
   orders, and the store's own name, description and certificate with them.
5. It was reported by a `probe_warn`: a browser console line.
6. The migration then **sealed** (at the time). There was no second attempt.
   It no longer seals (harvest#121), but the refusal is deterministic, so a
   second attempt refuses the same bytes.

A seller upgrading lost their entire shop, and the only trace was a log nobody
reads. It passed `cargo fmt`, `cargo clippy` on both targets, the full test
suite, and a review round.

**Why no test saw it:** every fixture in this repository builds its records
with the *current* derivation. Not one could hold what a predecessor produced.
That trap is general — it applies wherever old bytes and new code have to
meet, not just to ids.

## The escape hatch: owner-assisted re-issue

**This is a fallback, not the answer.** Reach for it only once "new accepts
old" has genuinely been ruled out, and know what it costs before you do.

Where a derivation change makes old records unverifiable, the migration can
re-issue them instead of discarding them. It is available today and simply has
not been built. The migration runs **client-side, in the owner's own browser**,
for the owner's own stores, and their signing key is in the ghostkey delegate,
reachable by the same `SignMessage`/`SignResult` round trip the app already
uses to publish a listing.

So the client can:

1. accept the old-format record from the predecessor generation, as data;
2. recompute its id under the current rules (`ListingId::from_terms`);
3. ask the delegate to re-sign it, **as the same owner, over the same terms**;
4. publish that.

The contract only ever sees new-format records, so the hole the derivation
change closed stays closed. Nothing is forged: the owner re-signs their own
data, and every record still carries a signature by the key the store's
parameters name.

### What it costs, and this is the part to weigh

**It gives up "any UI can migrate."** Recomputing an id and re-signing needs
the owner's key. So only the owner's browser can perform the migration, and
only while they still hold that identity. A seller who has stopped using
Harvest, or who has lost their delegate, is **not migrated by anyone** — where
under "new accepts old" they would have been carried forward by the next
person to open the app.

That is a regression in the model, not a detail. It converts migration from a
property of the data into a property of the owner's continued participation.

### What it would take to build

`merge_store` is a pure function with no delegate access, and that is
deliberate — it is why the fold is testable at all. So the fold cannot do the
re-signing itself:

* the fold surfaces the records it refused, as *needs re-issuing* rather than
  as *discarded*, alongside the ones it carried;
* the UI layer takes that list, asks the delegate to sign each, and publishes
  the re-issued generation.

It also has to survive a seal, if one is ever turned on: Harvest's contract
migration does not seal today (harvest#121, `migrate_ops::successor_reference_is_durable`),
and a fold that refuses everything still reports `Recovered`, so any future
seal must leave a lineage with a refused generation unsealed for the re-issue.

### Two complications worth knowing before starting

**An order's id changing breaks the buyer's pointer.** The buyer learns which
commitment is theirs from an `OrderAccepted` message naming an `OrderId`
(`ui/src/messaging.rs`). Re-issuing an order under a new id leaves that
pointer naming an order that no longer exists. Listings have no such problem.
Either orders are exempt — they expire after `MAX_ANCHOR_AGE_BLOCKS`, about
eight hours, so a predecessor's orders are unpayable anyway — or the re-issue
has to reach the buyer, which is a protocol question rather than a migration
one.

**A payment proof survives an id change**, which is not obvious. An
`OnChainPaymentProof`'s claims bind to the `ScriptId` from
`Order::bitcoin_params()` — network, script, bridges, work floor — and not to
the order's id. So a re-issued `Paid` order keeps a valid proof. Worth knowing
so nobody exempts paid orders unnecessarily.

## Why accepting the old format in `verify` is NOT the answer

This is the obvious first idea — it looks like it preserves "new accepts old"
— and it is wrong for two independent reasons. The first alone sounds
surmountable, which is why both are here.

**It reopens the hole the change closed.** The old `ListingId` covered
`(seller_fingerprint, created_at_ms, title)` and not the price. Accepting that
form means a seller can still mint two listings with one id at different
prices, and first-writer-wins turns that into permanent divergence. The point
of the change was to make those two listings two listings.

**And it cannot be scoped to old data, because a contract has no history.**
The tempting patch is "accept the old form only for records that predate the
change". A contract validating state sees the state and its parameters and
nothing else — no clock, no write times, no predecessor. It cannot distinguish
a genuinely old record from a new one shaped to look old. Any acceptance of
the old form is acceptance for everybody, forever.

A third, smaller reason: re-stamping inside the fold is unavailable without
the owner's key anyway, because the id is inside what the seller signed. That
is precisely why the escape hatch goes through the delegate.

## The real move is not needing either of them

Once an app has users, "new accepts old" stops being a preference and becomes
a **hard constraint on which bugs are fixable at all**.

Play tonight's finding forward past a launch. The old `ListingId` did not
cover price; that is a real defect with a real consequence — two listings
under one id, diverging permanently across peers. The correct fix destroys
every seller's shop. The escape hatch requires every affected seller to still
hold their identity and open the app. And accepting the old format reopens the
defect.

There is no fourth option. **We would have carried the defect**, indefinitely,
because every way of fixing it costs users their data.

That is the argument for spending deliberate effort **now**, while Harvest has
no users and changing these things is free, on:

* **ids** — what each one covers, and whether it covers everything a reader
  will later need it to bind;
* **parameter structs** — they are hashed into a contract's address, so a
  field added later re-keys every generation's derivation (`legacy/README.md`
  records where that has already bitten);
* **state shapes** — every optional field needs `skip_serializing_if` if a
  signature covers the encoding, and a hand-written byte-literal test of the
  old shape.

Getting these right before launch is not polish. It is the difference between
a defect being fixable and being permanent.

## What is honestly unknown

Whether this case is an exception or the first of many. One derivation was
wrong, in a way that was worth fixing and could only be fixed destructively.
There may be others of the same shape not yet found; there may not.

What is **not** the reason we found it: Harvest being in development. That is
why the cost was a test store rather than somebody's business. It was found
because the fold was probed directly rather than trusted to the test suite —
and the suite was green, on a branch that had already passed a review round.

## What is in place today

Not the fallback — the disclosure, and the alarm.

* **The seller is told.** A discarded predecessor produces a notification
  naming the store, what specifically is gone, that this was **expected** as
  part of an upgrade, and that they need to republish
  (`migrate::describe_lost_store`). It drains in `migrate_ops::finish`
  *before* the nothing-was-recovered early return, which is the case it exists
  for. Pinned by `migrate::uncarried_tests`.
* **The next derivation change fails a test.**
  `listing::listing_identity_tests::the_listing_id_derivation_is_pinned` and
  `payment::order_identity_tests::the_order_id_derivation_is_pinned` are
  known-answer tests over each derivation's output, and their doc comments
  point here.
* **A first attempt at that pin did not work**, and the failure is
  instructive: it built a record with a hard-coded *old* id, which is refused
  whatever the derivation is, so simulating a future change failed zero tests.
  A fixture that pins the old algorithm cannot detect a change to the current
  one. Only a fixture depending on the current derivation's own output fires.

## The rule, for someone about to change a derivation

If the change makes previously-published records unverifiable:

1. **Try to avoid it.** Can the new version accept old state? That is the
   default and it is worth real effort, because it is the only option that
   costs nobody anything.
2. If not, it is a data-breaking change. Say so in the PR.
3. Either build the owner-assisted re-issue path — knowing it gives up "any UI
   can migrate" — or establish that no published generation holds data anyone
   would miss, **and record who established it, dated**.
4. If the answer is "the data goes", the person who loses it must be told in
   the app, in language saying the loss was expected rather than that
   something broke.

Tonight the answer was (3)-by-decision: Ian, 2026-09-06, no published store
held data worth preserving, sellers republish. **That answer does not survive
Harvest having users**, which is what makes (1) worth the effort now rather
than later.
