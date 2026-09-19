# Harvest design documents

## Reading order

**[incentive-mechanism.md](incentive-mechanism.md) is the current design.** It is
the most recent and most complete of these documents, and where the two below
disagree with it, it wins. Start there.

It answers one question: how do you make fraud unprofitable in a marketplace with
no operator, no arbitration, no reversible payments, and no way to observe whether
a parcel arrived? The answer is a seller's *standing* — cumulative money burned by
donating to Freenet, bound to their ghostkey — against which complaints act as
withdrawals rather than as evidence about character.

The other two are earlier, longer treatments the explainer condenses. They are kept
because each still contains material the explainer cut for length:

- **[transaction-walkthrough.html](transaction-walkthrough.html)** — the Alice-and-Bob
  purchase in full, step by step, with what each party sees at each point.
- **[privacy-analysis.html](privacy-analysis.html)** — what the design publishes to
  the world, and what that means for real people. The transparency is load-bearing:
  it is what makes the exit-scam protection work, so it cannot be optimised away
  without giving up the protection.

## The entity model (revision 2)

- **[entity-model.md](entity-model.md)** is the approved design for what a
  store, a Ghost Key, a backing and a record are, and how the UI shows them
  (freenet/harvest#93). It is implemented in phases; each phase's choices are
  recorded at the end of the file. Where it and the documents above disagree
  about who owns a store, it wins: a store has its own key, and Ghost Keys
  back it.

## Engineering notes

These are about the code rather than the mechanism.

- **[migratability.md](migratability.md)** — **a requirement**: a new contract
  version must be migratable from every version that has ever held user data.
  Read it before changing how any record's identity is derived, or any
  parameter struct or state shape.

  The property it protects is that *any UI can migrate a contract*, because
  new versions accept old state and migration is therefore pure data transfer
  — so a seller who never opens Harvest again is still carried forward by
  whoever does. A derivation change breaks that by construction, and the
  owner-assisted re-issue fallback buys the data back at the price of that
  property. The document's real argument is the third option: once an app has
  users, "new accepts old" stops being a preference and becomes a constraint
  on which bugs are fixable at all. It records what one such change cost here
  — a seller's entire shop, to a console line, on a migration that sealed.
- **[migrate-ops-testability.md](migrate-ops-testability.md)** — why nothing
  automated executes `ui/src/gateway/migrate_ops.rs`, what that has cost in
  found-by-hand defects, and a staged plan to fix it. Deferred deliberately,
  with the reasoning recorded.

## Relationship to the older documents

`../design.md` describes Harvest's overall shape — stores, listings, reputation,
mailboxes — and remains accurate for those. Its account of the *incentive mechanism*
is superseded: it describes buyer-authored feedback tokens with blind signatures,
which `incentive-mechanism.md` Part 3 shows fails in three independent ways.

GitHub issue #8 has the same problem. It was filed as the v1 epic but records the
superseded design, not this one.

## Two things the explainer says that are now out of date

**Lightning is not required.** The explainer states that proof of payment needs a
Lightning preimage, because "an on-chain Bitcoin payment produces no such secret".
That was true when it was written. Since then `freenet-bitcoin` has grown a working
SPV implementation — a pure function checking a claimed Bitcoin payment against the
raw transaction, a Merkle branch, and the target each block header names. Combined
with the unique per-order address each order already gets, an on-chain payment now
yields a proof close enough to what the design needs: it cannot exist unless a
trusted bridge signed it, and it fixes the amount and destination against a real
transaction rather than against the bridge's word. It is not trustless — nothing
anchors a header to Bitcoin, so a trusted bridge could assert a payment that never
happened — but it does not require the seller's cooperation, which is the property
the mechanism actually rests on.

What is genuinely lost is that a preimage is *secret* while an on-chain proof is
*public*, so Lightning additionally protects against a leaked confession. That is a
narrower risk than the latency and fee costs of requiring Lightning for every sale.

**Order commitments must be identity-level, not per-store.** The explainer says
commitments go into "Alice's public record", which is right. The implementation puts
them in the per-store contract, and one ghostkey may create unlimited stores — so a
buyer counting a seller's outstanding orders sees a fraction of what the bond backs,
which defeats the exposure cap entirely.

**The block anchor can be backdated.** The explainer argues that a commitment cannot
be made to look old, "because looking old requires having published early, which is
exactly the behaviour being forced". This is wrong, and it matters, because the
complaint window rests on it. A block hash proves a commitment was signed *no earlier*
than that block — a lower bound only — and every past block hash is public. So a
seller can anchor a fresh commitment to an old block, have readers close it
immediately, and read zero exposure while taking orders.

Two rules neutralise it. A buyer pays only if the anchor is within about six blocks of
the tip. And a *paid* order takes its clock from the payment's own block height, which
comes from the bridge-signed claim rather than from the seller; the anchor then governs
only unpaid orders, where backdating merely closes a phantom nobody paid for. Note the
height is the bridge's assertion, not something the SPV proof establishes — a block
header does not carry its own height — so this moves the trust from the seller to the
bridge rather than removing it.

See issue #8 for the full contract topology this implies.
