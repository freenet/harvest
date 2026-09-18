# What a watcher learns from Harvest messaging

Written 2026-09-05, alongside the reply path (`feat/messaging`). It records
what is **visible to anyone at all**, because the mailbox is a public contract
and nothing about reading it is privileged. It is not a threat model for the
marketplace as a whole; it covers the messaging mechanism only.

## The shape of the thing

One mailbox contract per store, addressed at
`BLAKE3(BLAKE3(mailbox_wasm) || cbor(MailboxParameters { owner_verifying_key }))`.
Open-write by necessity: a buyer must be able to reach a seller they have no
prior relationship with, so there is nobody to authenticate.

Each entry is `EncryptedMessage { conversation_id, sender_public_key,
ciphertext, timestamp, nonce }`. Only `ciphertext` is encrypted.
`conversation_id` is *inside* it and therefore not visible; everything else in
that struct is.

## Visible to anyone

* **That the store has a mailbox, and where.** Derived from the seller's
  ghostkey, which is published in the store's own details.
* **How many messages it holds**, up to `MAX_MESSAGES` (512).
* **When each arrived** — not from `timestamp`, which is unsigned and
  self-asserted, but from observing the contract change.
* **Each message's padded size**, one of 1 KiB / 4 KiB / 16 KiB / 64 KiB.
  Every message that lands has been padded to one of those; see the size-bound
  section below for why that is now true of all of them rather than only of
  those under 64 KiB.
* **The conversation tag** (`sender_public_key`): the buyer's ephemeral X25519
  public key, carried on every message of that conversation **in both
  directions**. So an observer can group a mailbox into conversations, count
  the messages in each, and see the order they arrived in.
* **That an entry was written by the same party that wrote another entry in
  the same conversation** — the tag is shared, but the direction is not
  visible. An observer cannot tell a reply from a question by inspection, only
  by inference from timing.

## Not forgeable, and it was

Every field of an entry except the ciphertext is authenticated as AES-GCM
associated data (`harvest_common::mailbox::message_aad`). Before that, only
the ciphertext was protected, and three things followed that a reader of this
document should know were once true:

* **Replay.** The mailbox dedupes on the full 24-byte nonce, but only the
  first 12 are the AES-GCM nonce. Randomising bytes 12..24 resubmitted the
  same ciphertext as a new message. Verified working.
* **Re-dating.** `timestamp` is the primary key of the eviction ranking, so a
  genuine message could be moved up or down the order that decides what
  survives a flood.
* **Re-tagging and re-labelling.** The routing tag and the cleartext
  conversation id could be edited freely.

None of these needed a key or any relationship with either party, because
anybody can read the mailbox and anybody can write to it.

## Authorship is NOT established by anything here

Direction separation stops a third party reflecting a copied message. It does
not, and cannot, stop the counterparty: both parties derive both direction
keys from the same symmetric Diffie-Hellman secret, because the buyer needs
the seller-to-buyer key in order to read replies at all. So either party can
encrypt in either direction, and a buyer can place a message in the seller's
mailbox that authenticates exactly as the seller's own reply would.

Only a per-message signature could distinguish two holders of one secret, and
that is a different mechanism from this one. **Anything whose authenticity
matters must carry its own signature and must not rest on which key decrypted
it.** The UI reports which direction a message was addressed, names only what
the current tab sent as authored, and says on screen that direction is not
proof of authorship.

"What the current tab sent" is recognised by a digest of the whole mailbox
entry, not by its nonce. The distinction is the subject of the next section
and it is not a detail: the nonce is public and the counterparty can put their
own words under it.

## The counterparty could DELETE a message you sent — FIXED

Found by review on 2026-09-05, demonstrated by execution, and closed the same
day by moving what the contract treats as identity. The account below is kept
because the reasoning that led there is worth more than the conclusion, and
because the fix is only obvious once the failed attempt is visible.

**Why it was worth fixing rather than documenting.** The residual was first
described as "the counterparty can grief a conversation they are already
inside". That is wrong, and Phase 2 is where it shows: the seller's reply
carries a pre-signed confession which is the buyer's SOLE capability to file
against the seller's bond, it travels as an ordinary message in the seller's
own mailbox, and the seller knows its nonce. So the bonded seller could send
the confession, wait for payment, and then retract it at a moment of their
choosing. That is not griefing a conversation; it is the bonded party being
able to withdraw the instrument the bond rests on. Telling the buyer to store
it on receipt does not help -- it makes the guarantee a race between the
buyer's client persisting and the seller substituting, and a race is not a
foundation for "the buyer has recourse".

The mailbox keeps **one entry per nonce**: `MailboxStateV1::verify` rejects a
state holding a duplicate, and a summary is a set of nonces. The nonce is
public, the contract is open-write, and the counterparty holds the
conversation key. So they can take a message you sent, encrypt *different*
plaintext under the same key with the **same nonce**, date it one second
later, and submit it. `dedupe_by_nonce` keeps one of the two by a total order
over content, and every field in that order is theirs to choose.

Three things happened at once: your message was gone from a public contract,
the substitute read as a normal message of the conversation, and your own
screen labelled it as something you wrote, because `authored_here` matched on
the nonce.

**Why no tiebreak fixed it, which is what pointed at the real answer.** The
dedup rule must be a pure function of the SET of messages, or two peers that
saw them in different orders keep different bytes forever. A function of the
set has no notion of which arrived first, so it cannot protect the incumbent.
Ranking by content instead of timestamp only changed the attacker's cost from
"add one second" to "try a few ciphertexts until one sorts first" — they
choose the whole plaintext, so they win about half of any comparison on the
first attempt.

The conclusion to draw from that is not "pick a better tiebreak". It is that
**there should be no collision to resolve**, which is what the fix does.

**What closed it, and the wrong answer that came first.** The first answer
written here was wrong and is kept rather than deleted, because the mistake is
instructive: it said to derive the nonce deterministically from the message
(an SIV-style construction), so that two different plaintexts could not share
a nonce.

**That does not work, because nothing can enforce it.** The nonce is a field
the writer fills in, and the reader takes it from the entry
(`decrypt_message`, `ui/src/messaging.rs`). The contract cannot check a keyed
derivation — it has no key — and the reader checking it comes too late,
because the displacement already happened at the contract. An attacker who
holds the conversation key simply does not follow the derivation rule. A rule
only honest clients obey is not a defence against a dishonest one.

What closed it is making the identity **the contract itself computes**: the
summary, the delta, the duplicate check and the dedup are all keyed on
[`entry_digest`] over the whole entry rather than on the writer's nonce. Two
entries that differ in any byte are two entries; there is no collision to
resolve, so there is nothing to displace. It needs no key, so the contract
enforces it — which is exactly what the derivation rule could not do.

Four consequences, all deliberate:

* **A substitute now sits BESIDE the original.** The mailbox is open-write, so
  an attacker could always ADD an entry; what they can no longer do is remove
  one **by submitting a colliding message**. The buyer sees both, their own
  marked as theirs and the other unattributed.

  **This is not "a message can never be removed", and the difference matters
  for Phase 2.** A funded flood still evicts it: 512 entries dated later fill
  the count cap and take every honest message with them, measured at about
  122 KiB in a single update — see `known_gap_a_funded_flood_still_evicts_every_honest_message`
  and "The flood, and what bounds it" below. What changed is that retraction
  went from **free, targeted and silent** (one message's worth of bytes, aimed
  at one entry, leaving no trace) to **expensive, indiscriminate and loud** (a
  full cap's worth of bytes, destroying the seller's whole mailbox with it,
  which for a bonded seller is self-incriminating).

  **"Loud" was overstated, and the correction matters for Phase 2.**
  `apply_delta` merges a whole `MailboxDelta`, so the flood is ONE update and
  there is no partially-completed state for anyone to observe. What is loud is
  the aftermath -- the seller's own mailbox is destroyed, which for a bonded
  seller is self-incriminating -- not the act. Nothing is interruptible, so
  there is no window a quick client could win.

  A second correction, in the other direction: the byte-budget route was
  briefly measured as a cheaper way to the same result (64 maximum-size entries
  rather than 512 small ones). It is not one any more. Since harvest#85
  `enforce_message_cap` meets the byte bound with a count cap per size class
  (`SIZE_CLASS_CAPS`) rather than a shared byte budget, which it had to for
  the merge to be associative, so a flood of maximum-size entries fills only
  the top class and cannot reach a small honest message
  (`the_byte_route_no_longer_evicts_a_small_honest_message`). The count route
  within the smallest class still works and is cheaper anyway, so the flood is
  narrowed, not closed.

  A buyer's recourse must survive a seller willing to spend that, so the
  confession needs a home outside the mailbox. **That is now settled** (Ian,
  2026-09-05): in Phase 2 the buyer persists the confession itself in their own
  delegate store on receipt, not merely the conversation keys, so the mailbox
  becomes the channel that delivered it rather than custody of it. **And the
  buy flow is ordered so the remaining race cannot matter: persist the
  confession, confirm the write, and only then pay.** An eviction after that
  point achieves nothing, because the buyer already holds the capability in a
  store the seller cannot reach. Written up in
  `docs/buyer-conversation-persistence.md`, "Phase 2 stores the confession
  here, not just the keys", including the correction above -- an earlier
  version of that section argued storing-on-receipt was sufficient *because*
  the flood was slow and visible, which the measurement above refutes. Not
  built.

* **`MailboxSummary` became `MailboxSummaryV2`** and carries 32-byte digests
  instead of 24-byte nonces. A change of payload is a change of name.

  **Two claims first made here were false, and are corrected rather than
  deleted, because a later decision is exactly the kind of thing that gets
  built on a premise like this.** It said no mailbox contract carrying the old
  shape had ever been published; `legacy/mailbox_contract.toml` records seven
  published generations, and every one shipped the 24-byte summary. It said
  the two shapes "cannot be confused on the wire"; measured through this
  crate's own `to_cbor`/`from_cbor`, that holds in one direction only — a
  non-empty 24-byte summary read as 32-byte fails with "invalid length 24", an
  EMPTY one decodes cleanly as an empty set, and a 32-byte summary read by old
  code is silently TRUNCATED to 24-byte prefixes, so it would answer "I hold
  these" for digests it has never seen. What actually makes the old shape
  unreachable is neither of those: the contract is **content-addressed**, so
  this change re-keys it, and a V7 peer and a V8 summary are never talking
  about the same contract.
* **`verify` rejects a repeated ENTRY, not a repeated nonce.** The old check
  made a legal pair permanently invalid, and that is what turned a collision
  into a way of destroying a message.
* **The client's "your message was replaced" report was DELETED**, not
  repointed. The state it described can no longer arise, and the nearest
  surviving signal — "an entry shares your message's nonce" — is forgeable by
  any third party, since the mailbox is open-write and the nonce is public. A
  tampering notice an outsider can trigger against a seller they have never
  dealt with is worse than none.

**What was done at the client, before the contract fix landed**, and what
survives it:

* `authored_here` matches on `entry_digest` — every field of the entry — so a
  substitute is not credited to you. The counterparty cannot reproduce it
  without sending the identical message, which is not a substitution. This
  still matters after the contract fix: they can still WRITE, so their words
  still appear; what they cannot do is have them appear as yours.
* There was also an `AppState::replaced_sent`, reporting a message whose nonce
  was present under a different digest — it had arrived and been displaced.
  **That was deleted when the contract fix landed**, because the state can no
  longer arise. It was not repointed at "an entry shares your nonce", because
  that signal is forgeable by any third party: the mailbox is open-write and
  the nonce is public, so an outsider could plant an unreadable entry under it
  and trigger a "somebody tampered" notice against a seller they have never
  dealt with.

It works in both directions. A buyer could put a confession in a seller's own
inbox under the seller's nonce, and the seller's own screen showed it as their
words until `authored_here` moved to the digest.

## A deliberate nonce collision is also AES-GCM nonce reuse

The same act reuses an AES-GCM (key, nonce) pair across two different
plaintexts, which is a cryptographic problem in its own right and not only a
UX one. Pinned as an executable fact by
`known_limit_a_nonce_collision_reuses_the_keystream`, which asserts
`C1 xor C2 == P1 xor P2`.

Who it exposes what to:

* **Not the counterparty.** They hold the conversation key, so they could
  already read and write everything in that conversation. The reuse gives them
  nothing new — which is why it is not a way *in*.
* **A third party watching the mailbox** sees both entries (the original is
  public until the substitute displaces it) and learns `P1 xor P2` **without
  any key**. The substitute's plaintext is attacker-chosen, so anyone who
  knows or guesses it recovers your original message. `pad_to_bucket` puts
  both in the same size bucket, so the xor typically covers the whole message.
* **A third party who obtains either plaintext** recovers the keystream for
  that nonce; the repeated-nonce pair additionally permits GHASH-subkey
  recovery, so they can forge further entries under that nonce without holding
  the key. They cannot decrypt anything under a different nonce.

**How much this actually matters, stated after a second look.** Every path
requires a key holder to create the collision deliberately — and a key holder
can already decrypt the buyer's message and publish the plaintext directly.
So the xor leak grants the counterparty nothing they lack; it is a more
deniable route to a disclosure they could make anyway. The one genuinely
additional capability is narrow: recovering the GHASH subkey lets them hand a
third party the ability to FORGE entries in that conversation without handing
over the ability to READ it. In a two-party conversation whose counterparty
can already forge anything, that is exotic.

An earlier version of this section stopped at "a third party learns `P1 xor
P2` without any key", which is true and, on its own, overstates the
consequence. It is recorded here in corrected form rather than quietly
rewritten.

**And it is not closable at this layer.** A deterministic nonce would stop
honest clients colliding, which they were never going to do with 24 random
bytes; it does nothing about a key holder who chooses to collide, for the same
reason it does nothing about displacement. Nothing short of removing the
counterparty's key removes this, and the counterparty must hold the key to
read replies at all.

**The content-identity fix above does not close this either, and does not
claim to.** It stops a collision destroying a message; it cannot stop one
being created, because creating one needs only a key the counterparty must
have. The two entries now coexist, which is if anything a slightly better
position for an observer — both ciphertexts are durably in the mailbox rather
than one displacing the other. That changes nothing about the analysis above:
the party who can create the collision could publish the plaintext instead.

## NOT visible

* **What was said.** AES-256-GCM under a key derived from an X25519 exchange
  the observer cannot perform.
* **Who the buyer is.** The tag is freshly random per conversation and is tied
  to no identity, no ghostkey, and no payment. Harvest gives a buyer no
  identity to leak.
* **Whether two conversations with the same store are the same buyer.** A
  fresh keypair per conversation is what buys this, and it is the property a
  reasonable-looking optimisation (one keypair per store, reused) would
  silently delete. Pinned by `each_conversation_carries_a_fresh_tag`.
* **Whether two conversations with *different* stores are the same buyer.**
  Same reason.

## The tag is a deliberate trade, and here is the other side of it

Echoing the buyer's key on the seller's replies is what lets a buyer find
their own thread cheaply. The alternative — a tag nobody can link — would hide
the thread structure but force the buyer to attempt decryption against every
entry in the mailbox.

Measured on this machine (x86-64, hardware AES, `--release`, 2026-09-05), a
buyer reading a mailbox filled to the enforced budget with entries all
carrying their tag:

| Mailbox | Per read |
|---|---|
| 512 entries at the 1 KiB bucket (632 KiB — the count cap binds) | **3.2 ms** |
| 63 entries at the top bucket (3.95 MiB — the byte budget binds) | **20.7 ms** |

Since harvest#85 the top size class is capped at 24 entries (about 1.5 MiB),
and a mailbox at every class cap is about 3.7 MiB, so the second row is now an
upper bound rather than a reachable state; it was not re-measured.

Both are measured at the real cap, through the real pruning, rather than
extrapolated. The second figure was **193 ms** before `MAX_MAILBOX_BYTES`
existed, when 512 top-bucket entries were admissible; bounding the mailbox in
bytes bounds this too, which is the second reason the budget is worth having.

**Caveat on those numbers, stated because it is the half that could be wrong:**
they are native x86-64 with AES-NI. The UI runs on `wasm32-unknown-unknown`,
where the `aes` crate uses a constant-time software backend and no hardware
instruction. An attempt to force the software path with
`--cfg aes_force_soft` produced numbers within noise of the hardware ones,
which almost certainly means the flag did not take effect rather than that
the backends perform alike — so **the wasm cost is unmeasured**, and a 5-20x
multiple on the figures above would not be surprising. At that multiple 3.2 ms
stays comfortable and 20.7 ms becomes noticeable but not pathological; before
the byte budget, the same multiple on 193 ms would not have been survivable.

No timing assertion is committed anywhere. A wall-clock bound in CI is a flaky
test, and this repository treats a flaky test as a broken one.

## The flood, and what bounds it

The tag is in the clear, so **an attacker can read a buyer's tag out of the
mailbox and stamp it on entries of their own**. Those entries do not
authenticate — the AEAD is what decides, and the tag is only a fast path — but
they do force the buyer to attempt decryption. A full cap's worth is the worst
case, which is what the table above measures. `read` still returns the buyer's
real thread and nothing else; pinned by
`a_full_cap_flood_tagged_with_the_buyers_key_does_not_hide_their_thread`.

The same flood evicts the honest traffic, which is a pre-existing and
separately-pinned gap: see
`harvest_common::mailbox::known_gap_a_funded_flood_still_evicts_every_honest_message`.

## The size bound, and the shape of it

`MailboxStateV1::verify` bounds the mailbox by **message count** and nothing
else — a count cap over entries holding contract-controlled `ciphertext` and
`sender_public_key`, which reads like a memory bound and is not one. That was
found while writing this document and is now fixed, but the SHAPE of the fix
is the part worth recording.

**Pruning, not rejection.** `MAX_MAILBOX_BYTES` (4 MiB) is met by
`enforce_message_cap` dropping the lowest-ranked messages, exactly as the
count cap is. `verify` deliberately does **not** check it, and that is not an
oversight: mailboxes already on the network were produced by an honest
`apply_delta` under the old rules and may exceed the new budget, so a `verify`
that rejected them would make them permanently invalid — never convergeable
again, with no way back. This repository has already been bitten by exactly
that once, when a TTL check rejected a whole mailbox because one message had
aged out. Pruning can only ever produce a smaller valid state.

The count cap IS checked in `verify`, and the difference is worth stating: it
has been enforced since the mailbox existed, so no honest state was ever over
it. A cap added later has no such guarantee. Pinned by
`verify_accepts_an_over_budget_state_so_an_existing_mailbox_is_never_stranded`.

**One oversized message is refused on the way in.** Pruning keeps a prefix of
the ranking, so if the highest-ranked message did not fit, nothing behind it
would be reached and the mailbox would prune to nothing — and an attacker can
put their message at the top of that ranking for free, because timestamps are
unsigned. So `MAX_MESSAGE_BYTES` is set well below the total budget and
`apply_delta` drops anything over it. Refusing an incoming message is
recoverable; invalidating existing state is not.

**The residual:** between arriving and the next merge, a peer may hold an
over-budget state. Nothing here bounds that; the node's own maximum state size
does.

**And a cost this change also fixes:** `MAX_MESSAGE_BYTES` is exactly a full
top-bucket message, so a message built from data `pad_to_bucket` declined to
pad cannot fit. Every message a reader can see has therefore been padded, and
the size privacy the buckets claim now holds for everything rather than for
everything under 64 KiB.

## What the byte budget costs — corrected

An earlier version of this section said the budget "makes a flood **cheaper
for the attacker**", that filling the count cap "took 512 contract updates"
against about 63 for the byte budget, and that the same eviction was available
"for an eighth of the updates".

**All of that was wrong, and measurement is what showed it.**

* A `MailboxDelta` is a bare `Vec<EncryptedMessage>` and `apply_delta` merges
  the whole vector, so neither route is a *number of contract updates*. Both
  are **one**.
* In the currency that actually costs — bytes on the wire — the byte-budget
  route is far more expensive:

| Route | Messages | Wire bytes | Honest survivors |
|---|---|---|---|
| Fill the count cap with the smallest messages | 512 | **124,883** | 0 |
| Fill the byte budget with the largest | 64 | **4,207,018** | 0 |

The count cap still binds first for small messages, so **the cheapest total
eviction is unchanged by the byte budget** — it was one ~122 KiB update before
this change and it still is. The budget conceded a downside it does not have.

What it does buy is a bound on what a flood costs everyone else: without it,
512 top-bucket entries were admissible and the mailbox had no size limit at
all.

The eviction ranking is unchanged and still grindable — `(timestamp, nonce)`,
both sender-chosen. Closing that needs admission control (payment,
proof-of-work, or a per-sender quota) and not a retuned cap. Pinned by
`known_gap_the_byte_budget_did_not_make_a_flood_cheaper`, which now measures
both routes so the prose cannot drift from the fixture again — that drift is
exactly how the wrong claim survived, because the test measured message COUNT
while its comment drew a conclusion about COST.

**One flood is also permanent, not a recurring cost.** Far-future timestamps
rank above all honest traffic for as long as they sit there, so a single
paid-for flood holds the mailbox indefinitely with no further spend.

## The one that limits the mechanism rather than leaking from it

**A buyer's conversation used to die with the browser tab, and no longer
does.** That paragraph stood here until 2026-09-05, when the harvest delegate
started keeping the buyer's per-conversation secret; the full design is in
`buyer-conversation-persistence.md`. The limitation it described was real and
sharp: if a seller's reply is later made to carry something the buyer *needs*
— an authorization, a receipt, a signed statement — then losing the key loses
that thing, silently, with the ciphertext still visibly present.

Two limits replace it, and one of them is a new privacy cost rather than a
leftover.

### The new cost: a durable local record of who this node messaged

The delegate now holds, per conversation, a secret keyed by store id and
routing tag. So "this node has a conversation with store X" **persists**,
where before it did not. It is on the buyer's own node, in the delegate's
secret store (encrypted at rest by the node), and reachable only by the
Harvest webapp — but a buyer's pseudonymity gains a local artefact, and a node
inspected or seized reveals which stores its owner contacted.

Nothing about this leaks to the network. It is a trade between two things the
buyer cares about, and it was made in the direction of recourse: losing the
key loses the ability to complain about a seller they paid, and that is worse.

**The buyer can undo it, and the control does what it says.** "Forget this
conversation" DELETES the record rather than emptying it. That distinction is
the whole point: emptying the value would stop the conversation being readable
while leaving a key that still names the store, so the control would be a lie.
The delegate re-reads the key afterwards and reports a failure rather than a
success it cannot stand behind, and the UI keeps the thread on screen until
the node says the record is gone. Forgetting cannot be undone: the messages
stay in the seller's mailbox and become unreadable by everyone, including the
buyer.

What is NOT verified from this repository is that the node performs the
deletion. `DelegateCtx::remove_secret` is a stub off wasm32, so the tests
drive an in-memory store; the node's own implementation is read from
freenet-core's source (`wasm_runtime/secrets_store/store.rs::remove_secret`,
which removes the blob, its snapshots, the index entry and the enumeration
registry entry). See `docs/untested-invariants.md`.

### The new surface: a backup is a portable capability

A buyer can now export their conversations with a store as a single string and
paste it into Harvest on another machine. That string holds the X25519 secrets
themselves, which is what makes it work — and what makes it worth exactly as
much as the conversations it restores. **Anyone holding it can read them, and
once a seller's reply carries a pre-signed statement, can file the complaint
that statement authorizes, as though they were the buyer.**

It is not a password. There is nothing to rotate: the secret IS the
conversation, so a leaked backup cannot be revoked, only forgotten — and
forgetting it makes the conversation unreadable to the buyer too.

Three things follow, and all three are on screen rather than in a doc:

* the string is shown only when asked for, and hidden again on request;
* what holding it means is stated beside it, before the buyer copies it,
  because that is the basis on which a person decides where to put it;
* a conversation with no copy anywhere else is **warned about**, and only the
  buyer saying they have saved it clears the warning. Exporting is not saving.

The warning's marker is gated to the Harvest web app for its own reason,
separate from the export's: silencing a warning costs the silencer nothing and
costs the buyer everything. See `buyer-conversation-persistence.md`.

**The export is per conversation**, so one string covers exactly one thread
with one seller -- the smallest blast radius available, and the granularity at
which the "saved elsewhere" marker means something checkable rather than
"some snapshot was taken at some point".

### The remaining limit: a different device is a different node

The secret is in ONE node's delegate. A buyer who writes from a laptop and
later opens the same store on a phone has a different node and ciphertext
nobody can read — **unless they carried a backup across**, which is what the
section above is for. Nothing happens by itself, and a buyer who saved nothing
is in the same position as one who closed the tab used to be.

It is said on screen before the buyer sends rather than left to be discovered
when they need the answer.

Automatic sync between a user's own peers would remove the step. Whether that
belongs in freenet-core or in each delegate is unsettled and is not attempted
here.
