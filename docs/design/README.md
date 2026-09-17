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
  Rewritten 9 September 2026 for on-chain payment; it no longer describes the
  Lightning flow.
- **[privacy-analysis.html](privacy-analysis.html)** — what the design publishes to
  the world, and what that means for real people. The transparency is load-bearing:
  it is what makes the exit-scam protection work, so it cannot be optimised away
  without giving up the protection.

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

## Corrections that used to live here

This file used to carry three corrections to `incentive-mechanism.md`: that
Lightning is not required, that order commitments must be identity-level rather
than per-store, and that a block anchor can be backdated. **All three are now
folded into `incentive-mechanism.md` itself**, at the steps they affect.

They were moved on 9 September 2026 because keeping a correction in a different
file from the claim it corrects does not work. Anyone reading the design of
record in order got the superseded design, and the file that would have told
them otherwise is one they had no reason to open. That failure is the reason
this section now says where the corrections went instead of repeating them.
