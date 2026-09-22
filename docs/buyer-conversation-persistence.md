# How a buyer's conversation survives the tab

**Status: built.** Written as a proposal on 2026-09-05 at `ee0f41f`, and
rewritten on the same day to describe what was actually built, on
`feat/messaging`. Where the built thing differs from the proposal, the
difference is called out rather than quietly edited away. The **Backup**
section below was added after the rest, at Ian's direction, and is the reason
the "Cross-device recovery" section is now a correction rather than a
limitation.

## The problem, stated at its cost

A buyer's conversation keys lived in the browser tab and nowhere else. Close
the tab and they were gone; the ciphertext stayed in the seller's mailbox and
became unreadable by anyone, including the buyer who wrote it.

Today that costs a conversation. Once the seller's reply carries a pre-signed
statement — the buyer's only capability to complain against the seller's bond,
since on-chain payment proof is public and authorizes nothing by itself — it
costs the buyer **all recourse**, silently, and they do not find out until they
need it.

So the secret has to outlive the tab.

## Constraint 1: there is no browser-side storage at all

Verified in `freenet-core` rather than inherited. `crates/core/src/server/
path_handlers/assets/shell.html:11`:

```html
<iframe id="app" sandbox="allow-scripts allow-forms allow-popups
        allow-popups-to-escape-sandbox allow-downloads allow-modals" ...>
```

No `allow-same-origin`, so the app document has an **opaque origin**. Two
independent pieces of evidence that this throws rather than degrading:

* freenet-core says so in prose — `shell_bridge.js:82`, "opaque origin, so
  localStorage throws and the per-user token can't be read".
* freenet-core **acts on it**: every `localStorage` access in
  `shell_bridge.js` is wrapped in `try { ... } catch (e) {}` with an in-memory
  fallback (`contractHasConsent`, `setContractConsent`, and the token path).
  Code written to survive a throw is stronger evidence than a comment
  asserting one.

**The constraint is broader than "localStorage".** An opaque origin denies
`sessionStorage`, IndexedDB and cookies by the same rule. There is no
browser-side option to weigh, so this is not a trade-off between storage
mechanisms — the delegate is the only durable store this application has.

## Constraint 2: the buyer has no identity

No ghostkey, no fingerprint, no account. Their Bitcoin payment is their whole
commitment. Every other secret the harvest delegate holds is keyed by ghostkey
fingerprint, so this is a genuinely new shape for it.

## What was built

### The key

```
harvest:buyer_conv:{store_id_b58}:{buyer_public_key_b58}
```

Identity-free, and both halves are recoverable after a reload:

* **The store id** comes from the URL. `store_link::open_store_from_url()` is
  how a buyer reaches a store at all, so a buyer returning to a conversation is
  by definition returning to a link that carries it.
* **The routing tag** is the buyer's ephemeral public key, which every message
  in the conversation carries in the clear, in both directions. So a recovered
  secret can be matched against what is actually in the mailbox.

The `:` terminator is load-bearing: it is not in the base58 alphabet, so one
store's prefix cannot be a prefix of another store's keys and a recall cannot
return a neighbouring store's conversations. Pinned by
`conversations_are_scoped_to_their_store`.

Recovery: reopen the store link, ask the delegate to list secrets under
`harvest:buyer_conv:{store_id}:`, derive both direction keys from each stored
secret, read the mailbox. A stored conversation whose tag is absent from the
mailbox simply yields nothing.

**Why not the order id**, which was the other candidate: an order does not
exist when the first message is sent. The seller issues invoices
(`AppState::issue_invoice`), so at the moment the secret must be stored there
is nothing to key by.

**A 32-byte store id is required, and a wrong length is refused.** The id is
base58-encoded into the key, so a caller-sized id would be a caller-sized key
— and then the cap below would bound entries while bounding no bytes, which is
exactly the count-cap-over-variable-values trap this codebase has been bitten
by. Pinned by `a_store_id_that_is_not_a_contract_id_is_refused`.

### What is stored

The 32-byte X25519 secret, the 32-byte seller public key the conversation was
opened against, the 32-byte conversation id, and an 8-byte creation timestamp.
No variable-length field.

**The seller public key is a deviation from the proposal**, which stored only
the secret, the conversation id and the timestamp. It is stored because recall
derives with THAT key rather than with one a caller supplies: a recall path
that took the peer key as an argument would be a Diffie-Hellman oracle against
every secret the node holds, reachable by anything that got past the origin
gate.

**There is no `buyer_public_key` field, and that is deliberate.** The routing
tag is the public half of the stored secret, so the delegate derives it. A
stored copy would be a second source for one value, and the two could disagree
— filing a conversation under a tag no message in the mailbox carries, which
nothing downstream could detect. Pinned across the crate boundary by
`the_delegate_files_a_conversation_under_the_tag_the_mailbox_carries` (UI
side) and `a_stored_conversation_comes_back_with_usable_keys` (delegate side).

**The timestamp comes from the browser, not the delegate.**
`freenet_stdlib::time::now()` is a `MaybeUninit` transmute off wasm32
(`time.rs:7`), so a delegate that called it could not be exercised by `cargo
test` without undefined behaviour. The value orders nothing but the caller's
own records, so a skewed clock costs the caller an eviction of their own
choosing.

`BuyerConversation::open` used to **discard** the ephemeral secret, and its
doc said that was deliberate — "keeping the secret would only widen what a
leak costs". That comment is now corrected in place rather than quietly
falsified: the reasoning traded a small leak surface for the silent, total
loss of the buyer's recourse.

### What bounds it

**256 records per node, across every store.** What goes first is what the
buyer can get back:

1. an entry that does not decode, which recalls nothing;
2. a conversation that arrived by IMPORT, which the buyer demonstrably holds a
   string for;
3. any other conversation the buyer holds a backup of;
4. a conversation that exists on this node and nowhere else;
5. within each, oldest first, then lowest key so the choice is deterministic
   rather than dependent on listing order.

**`backed_up` before age is not a refinement, it is the fix for a real
hole**, found in review. The cap is global across every store and `created_at`
comes off the wire -- from the browser when a conversation is opened, and from
the BACKUP STRING on the import path, where nothing signs it. A buyer handed a
backup by somebody else could paste 253 records dated `i64::MAX`, fill the
store to its cap, and have the next conversation they opened silently destroy
one of their own. Ranking on `backed_up` composes with import marking what it
restores as backed up -- which is true, since the buyer is holding the string
-- and that is exactly what makes the attacker's records the eligible ones.
Pinned by `a_conversation_that_exists_only_here_outlives_an_imported_one`.

**The IMPORT tier is not a refinement of the backed-up one.** `created_at`
travels inside the backup string and nothing signs it, so ordering by age
alone lets the other side decide which of the buyer's records goes first --
the same defect shape as the mailbox TTL that one forged timestamp emptied,
and as the fold tie-break. Each time the fix was to rank on something the
other side cannot choose, and `imported` is that: the delegate sets it from
which CALL arrived, so no string can claim it. Once a buyer has backed up
their own conversations too, `backed_up` alone stops separating them and this
tier is what still does. Pinned by
`an_imported_conversation_is_evicted_before_one_opened_here`.

**And an eviction is now reported.** `BuyerConversationStored` carries what it
discarded and whether that was backed up, so the UI can say either "you can
restore it" or "it can no longer be read by anyone, including you". The
expensive direction named below is silence, and a response that could not
express a discard was that silence.

The repository's count-cap-over-contract-controlled-values pattern does **not**
apply here, and the reason is the whole point of that pattern: it bites when a
count caps entries whose values are *contract-controlled and variable* — the
mailbox case, where `ciphertext` was attacker-supplied and unbounded. Here the
value is three 32-byte arrays and an `i64`, and the KEY is bounded by the
32-byte store-id refusal above. So the count IS a byte bound: roughly 60 KiB
at the cap.

A count cap is still required, because a page can open conversations in a
loop. Eviction rather than refusal: refusing would mean the conversation the
buyer is having *right now* is the one that cannot be saved.

Two details that only show up once it is built:

* **An entry whose value does not decode is evicted first.** It recalls
  nothing, so discarding it costs nothing — and it still occupies a key, so
  something has to reclaim it or the cap slowly fills with rubbish.
* **Re-storing a conversation the delegate already holds evicts nothing.** The
  UI re-sends the same conversation whenever the buyer writes into a thread it
  already has, so without this a full store would shed one real conversation
  per message sent.

### When one is discarded

Two triggers, and deliberately no third:

1. **Cap eviction**, oldest-first.
2. **The buyer explicitly forgetting a conversation.**

**No age-based expiry.** That would repeat the mailbox TTL mistake at a higher
cost: the thing it discards is precisely the capability the buyer needs later,
and the buyer has no way to know when they will need it.

The two failure directions are not symmetric:

* **Discarded too early** — the confession becomes unreadable and the buyer has
  no recourse. This is the expensive direction, so the cap is set well above
  plausible use, eviction prefers what the buyer can restore, and the discard
  is REPORTED rather than silent. The "well above plausible use" reasoning
  assumed records only ever arrive one per store from the buyer's own
  messaging; import broke that assumption, which is why the ranking above
  matters more than the size of the cap.
* **Kept forever** — a bounded store of a few tens of KiB, plus the durable
  local record discussed below. This is the cheap direction, which is why the
  bound is generous.

## "Forget" genuinely deletes, and that took finding

The first design keyed the record by store and tag, and the first
implementation could only ever EMPTY the value, because
`freenet_migrate::SecretStore` is `list`/`get`/`has`/`set` with no removal. That
made the privacy control a lie: emptying the value stops the conversation
being readable while leaving a key that says, durably, that this node held a
conversation with that store.

The intermediate answer was to key by an opaque slot number so the key said
nothing. That was abandoned once the platform was actually checked:

* `DelegateCtx::remove_secret` exists (freenet-stdlib 0.8.5,
  `delegate_host.rs:424`), reaching `__frnt__delegate__remove_secret`.
* The node implements it as a real deletion (freenet-core
  `wasm_runtime/secrets_store/store.rs::remove_secret`): it removes the
  encrypted blob, removes its snapshot history, drops the key from the
  persistent index, and de-registers the raw key from the enumeration registry
  that backs `list_secrets`.
* The host function has been registered since freenet-core `c61a5ca8d`
  (2026-02-11), so calling it does not add an import a deployed node cannot
  resolve.

So the delegate deletes, through a small crate-local `RemovableSecrets` trait
that carries the one capability `SecretStore` lacks. It then **re-reads the key
and reports a failure if it is still there**, because a buyer stops being
careful on the strength of a control like this. The UI drops the conversation
from view only when the delegate says the record is gone; a refused removal
leaves the thread on screen and says so.

**What is NOT verified here:** that the node performs the deletion. Every
`DelegateCtx` secret method is a `false`-returning stub off wasm32, so the
tests drive an in-memory stand-in. What they state is that this crate asks for
removal and reports honestly on the answer. The node's own behaviour is read
from its source, cited above, and would need `tests/rehearsal/` and a live node
to observe.

## Backup: the buyer can carry a conversation to another machine

Added after the persistence above, at Ian's direction: *"a purchase is not
something a person should lose because they changed laptop"*, and *"similar to
how GhostKey lets you make a backup"*.

The shape follows the ghostkey vault deliberately, so a future common backup
system across delegates has two consistent examples to generalise from rather
than two inventions. What is NOT attempted is sync between a user's own peers
-- whether that belongs in freenet-core or in each delegate is unsettled and
explicitly out of scope.

### The string

```
harvest-conv-backup-v2:<base58check of CBOR>
```

CBOR of `{store_contract_id, conversation: {secret, seller_public_key,
conversation_id, created_at, backed_up, imported}}`, base58check-encoded,
behind a named prefix. About 210 characters, and it covers **one
conversation**.

The version is v2 because v1 carried a whole store's conversations and this
carries one: a change of payload is a change of name, so a v1 string is
refused as "not one of ours" rather than decoding into something that no
longer means what it says. There is deliberately no v1-reading code -- no v1
string was ever produced outside this repository's tests, and a compatibility
path for an artefact that never existed would be untested code asserting a
scenario that cannot happen.

* **The prefix, not a bare blob**, so a paste that is not a Harvest backup --
  a ghostkey PEM, a store link, half a string -- is refused with a sentence
  the buyer can act on instead of a decoding error. The version lives in the
  prefix, so a later format changes it and this one still recognises its own.
* **Base58Check, not base58**, so a string that lost its tail in a copy is
  refused rather than restoring a conversation with a corrupt secret at the
  moment the buyer believes they have their recourse back. Pinned by
  `a_truncated_backup_is_refused`.
* **The store id is inside it**, so import needs nothing else. A buyer
  restoring onto a new node has the string and nothing to relate it to.
* **The format lives entirely in the delegate.** The UI shows the string and
  hands it back; it never parses it. So the one component that reads and
  writes the format owns it, and `harvest-common` -- compiled into all three
  contracts -- gains nothing.
* **A paste over 4 KiB is refused before it is decoded.** Base58 decoding is
  quadratic in the length, so an unbounded paste is an unbounded amount of the
  node's CPU; this was found by a test taking 72 seconds rather than by
  reading the code. 4 KiB is roughly twenty times an honest backup, which
  carries one conversation, and the restore flow is "paste what you saved", so
  what someone else hands the buyer is equally paste-able.

### The three questions that were settled, and why

**Per conversation, not per store. This reverses the original answer, and
both arguments are recorded because the reversal is the interesting part.**

The original answer was per STORE, on this reasoning: a buyer normally has one
conversation with a store, because a new message continues the last one, so
the two options differ mainly in how many actions a complete backup takes --
and a backup that silently omits a conversation is the expensive failure,
which is the same asymmetry that governs eviction.

Ian's objection, which wins: a per-store backup is too easy to leave out of
date. Take it on Monday, start a new conversation on Tuesday, and the buyer
holds a snapshot they believe is complete and which silently is not.

The first argument was right about which failure is expensive and wrong about
when it happens. It optimises for completeness **at export time**; what
actually bites is completeness **over time**, and a per-store export makes
staleness invisible because nothing about the artefact says which
conversations existed when it was taken.

**The marker settles it, and it is about the marker rather than the export.**
A `backed_up` marker attached to a store-wide export would falsely cover a
conversation created after that export. That is precisely the "a third-party
app cannot silence a warning about a key it has no backup of" property copied
from the ghostkey vault -- reintroduced through the GRANULARITY rather than
through the permission. Per conversation the marker means something checkable:
*this* secret exists in more than one place. Per store it would mean "some
snapshot was taken at some point", which is not a fact anyone can act on.

That the marker was already a field of the record rather than a separate keyed
secret is what makes this cheap: the marker was per-conversation structurally
before it needed to be, for the unrelated reason that a keyed marker would
outlive the conversation it describes.

**Import takes one string at a time**, and a buyer restoring a machine pastes
several in a row. Nothing is stateful between them, so the order does not
matter and a failure part-way leaves what already landed.

**Importing a conversation the node already holds KEEPS the held one.** Not
refuse, not overwrite:

* Refusing would break the obvious "paste my whole backup back" gesture, which
  is the flow a frightened user actually performs.
* Overwriting is worse than it looks. The routing tag is the public half of
  the secret, so an imported record sharing a tag can only *disagree* with the
  held one if it was hand-built -- and a different `conversation_id` under the
  same tag would make a readable thread stop reading, silently. The held
  record is the one this node's thread is being read with.

So the held one wins, and the outcome is reported as `already_held` rather
than as an error. The single exception is a held entry whose value does not
decode: it reads nothing, so keeping it would refuse a restore in favour of
rubbish. Pinned by `importing_a_held_conversation_keeps_the_held_one` and
`importing_over_an_undecodable_entry_restores_it`.

**At the cap, an import REFUSES and names what it refused.** This inverts what
storing does, and the inversion is the point: the conversation being imported
is provably backed up, because the buyer is holding the string it came from,
while the conversation eviction would take may exist only on this node.
Refusing is the safe direction here for exactly the reason evicting is the
safe direction there. The refusal names the conversation and says the node is
full, so the buyer can forget something and paste again -- a count would leave
them to work out which one did not land. Pinned by
`an_import_at_the_cap_refuses_rather_than_evicting`.

### The backed-up marker, and why it is gated

`RecalledConversation::backed_up` is `false` when the secret exists in exactly
one place. The UI warns on it, and **only the buyer saying they have saved the
backup clears it** -- exporting is not saving, and a buyer who opens the
panel, reads the string and closes the tab has saved nothing.

It is set for ONE conversation, matching the export. A request that marked a
set would let one saved string clear the warning on a conversation it does not
contain; see the granularity argument above.

The marker is behind `origin::authorize` **for its own reason, not because it
sits beside the export**. The export's reason is obvious: it answers secrets.
The marker writes no secret and answers none, so it reads as harmless -- and
what it does is stop the UI saying "this exists only on this device" about a
conversation nobody has a copy of. Silence costs the buyer everything and
costs the app nothing, which is the shape that needs a gate. This is the
property worth copying from the ghostkey vault, where `MarkBackedUp` is gated
on the `Export` scope that only the vault is ever granted
(`ghostkey-delegate/src/handlers.rs::handle_mark_backed_up`). Pinned by
`another_web_app_cannot_export_or_silence_a_buyers_backup_warning`.

**Where the marker lives is a deliberate deviation from ghostkey.** The vault
keeps it as a separate secret, `gk:backedup:{fingerprint}`. Here it is a field
of the record, because a marker keyed by store and tag would OUTLIVE the
conversation it describes -- forgetting a conversation would leave a key still
naming the store, which is precisely the durable local record
`forget_buyer_conversation` exists to remove. Inside the value it is deleted
with the thing it describes, counts against the same cap, and cannot drift out
of step with it. Pinned by
`forgetting_a_conversation_leaves_no_backup_marker_behind`, which fails when
the marker is written as a key of its own.

An **imported** conversation is marked backed up on arrival: the buyer is
demonstrably holding the string it came from, and warning about it would teach
them to ignore the warning.

### What the buyer is told

Beside the string, before they copy it: it holds the keys themselves, anyone
who has it can read the conversation and can complain about the seller as
though they were the buyer, and it is not a password that can be changed --
it is the conversation. That is the basis on which a person decides where to
put it, so it is on screen rather than in a tooltip.

## Cross-device recovery: NOT AUTOMATIC

**Corrected.** This section said cross-device recovery was impossible and had
no fix within the design. That was true of the persistence alone, and the
backup above is exactly the "recovery string" it named as its deliberate
omission -- built later the same day, once Ian asked for it.

What remains true is that **nothing happens by itself**. The secret is in one
node's delegate. A buyer who messages from a laptop and later opens the store
on a phone has a different node and ciphertext nobody can read *unless they
carried a backup across*. The question that was deferred -- whether a buyer
should be asked to save a string at all -- has been answered: they are offered
one, and told what it is worth.

So the limitation is now a step the buyer must take, not a wall. It is on
screen rather than left to be discovered: the compose box, the thread, the
"kept on this device" panel and the seller's reply box all say the
conversation does not follow the buyer to another device on its own.

Sync between a user's own peers would remove the step. Whether that belongs in
freenet-core or in each delegate is unsettled, and it is explicitly not
attempted here.

## Two consequences that were weighed, and stand

**A durable local record of who this node messaged.** "This node has a
conversation with store X" now persists, where before it did not. It is on the
buyer's own node, in the delegate's secret store (encrypted at rest by the
node), reachable only by the Harvest webapp — but a buyer's pseudonymity gains
a local artefact, and a node inspected or seized reveals which stores its owner
contacted. The trade is worth making, because losing recourse is worse, and it
is why "forget this conversation" exists and why it had to be a real deletion.
Also recorded in `messaging-privacy.md`.

**The migration export grows.** These records sit under `harvest:`, so a
delegate re-key CAN carry them -- which is necessary, since otherwise a re-key
destroys every buyer's recourse. It means export size now scales with
conversations rather than being roughly constant. Pinned by
`buyer_conversations_are_under_the_exported_prefix`.

(Correction, harvest#123: this paragraph said a re-key "carries them" when
nothing yet asked a predecessor to export, so every re-key until then dropped
every conversation. The prefix made them exportable; `ui/src/delegate_migrate.rs`
is what now exports them, on the first load after a delegate re-key, from any
earlier generation from V5 on that the buyer's node still has registered. It
cannot reach a conversation kept only under V1 to V4, or under a generation
this node never ran.)

## The shape of the change, as built

Six request families on the harvest delegate, behind the same
`origin::authorize` gate every other family passes through:
`StoreBuyerConversation`, `ListBuyerConversations`, `ForgetBuyerConversation`,
and then `ExportBuyerConversations`, `ImportBuyerConversations`,
`MarkConversationsBackedUp`. The cap is **in the delegate**, not the UI: a cap
enforced by the caller is not a cap.

`ListBuyerConversations` carries a request id and the UI files the answer
under the store IT asked about rather than the one the answer echoes. That is
not decoration: it is the same lesson as the echoed conversation tag on the
seller's side, where trusting position instead of the echo handed one buyer's
key to another buyer's messages. Here the equivalent mistake would put one
store's conversation keys against another store's mailbox.

On the UI side:

* `BuyerConversation` keeps its ephemeral secret, and
  `AppState::compose_to_seller` asks the delegate to keep it on the path that
  opens the conversation — not left to a caller to remember.
* `BrowsingStore::conversations` is a list, oldest first. Every one of them is
  read, so a reply to a question asked last week is still readable; the LAST is
  the one a new message continues, so a returning buyer resumes their thread
  rather than forking a second one beside it.
* Recall is issued when a store's state arrives, once per store — and NOT
  before the harvest delegate is registered, because `components::app` opens a
  store link before registering it. A store marked as asked on a request that
  was never sent would be a buyer whose conversations are never recalled.
  `recall_conversations_for_known_stores`, called when the delegate registers,
  covers the other ordering.
* A non-empty recall **re-subscribes to the seller's mailbox**. Browsing a
  storefront deliberately does not, since a subscription advertises a standing
  interest; a non-empty recall is exactly the evidence that this node has
  already written to that seller, so it tells the network nothing new.
* The backup panel sits under the thread: the warning for conversations that
  exist in one place only, "Show my backup" and "I have saved this", and a
  paste box that is offered **even on a device holding nothing**, since
  restoring onto a new machine is the case the whole thing exists for and
  there is nothing there to hang the control off.
* Marking and importing both **re-ask the delegate** rather than updating the
  screen from what they assume happened. The delegate is the only thing that
  knows whether a record was written; a refused write leaves the warning in
  place, which is the safe direction and exactly what a local guess gets
  wrong.

## Phase 2 stores the confession here, not just the keys

**Settled by Ian on 2026-09-05; recorded so Phase 2 starts from it. Nothing
below is built.**

The mailbox re-key on 2026-09-05 made a message unretractable *by
substitution*: identity is `entry_digest` over the whole entry, so a seller can
no longer submit a different message under a sent message's nonce and displace
it. It did **not** make a message permanently un-removable. A funded flood
still evicts one, and the cost is lower than it first appears -- see below.

That distinction is only academic until Phase 2. There the seller's reply
carries a **pre-signed confession**, which is the buyer's SOLE capability to
file against the seller's bond. It travels as an ordinary message in the
seller's own mailbox. A bonded seller facing a claim has a direct, priced
incentive to spend a cap's worth of bytes to destroy it.

**The resolution: the buyer persists the confession itself, in this delegate
store, on receipt.** Not merely the conversation keys, which is what a
`BuyerConversationRecord` holds today. Once the confession is in the delegate,
the mailbox stops being custody of the buyer's recourse and becomes only the
channel that delivered it, and mailbox eviction stops mattering to the claim.

Two things make this the right home rather than a workaround:

* The delegate store is **private and durable, and outside the seller's
  reach**. It is the buyer's own secret store; nothing the seller can submit to
  a public contract touches it. That is the property the mailbox cannot offer
  for an open-write contract with a cap.
* The buyer already carries it across machines. Per-conversation export
  (`harvest-conv-backup-v2:`) is the mechanism, so a confession the buyer
  backed up survives a lost laptop the same way the conversation keys do.

### The race, and why the ORDERING closes it rather than the speed

**An earlier version of this section argued that storing-on-receipt is
sufficient because a flood "needs 512 entries, not a single well-timed write".
The second half was wrong, and it was the load-bearing half.** A `MailboxDelta`
is a bare `Vec` and `apply_delta` merges the whole of it, so **a flood is a
SINGLE update** (`known_gap_a_funded_flood_still_evicts_every_honest_message`).
There is no partially-completed flood for anyone to notice and nothing to be
quick enough for, so an argument resting on the buyer winning a race was
resting on a race that does not exist in the shape it assumed.

So storing-on-receipt narrows the window -- from unbounded and at the seller's
convenience down to whatever a local delegate write takes -- but it does not
eliminate it. A narrower race is still a race, and "the buyer has recourse" is
not a claim that should rest on one.

*A footnote, because it changed twice in one day and someone will otherwise
re-derive it:* the byte-budget route was briefly measured as a cheaper path,
64 maximum-size entries rather than 512 small ones. It is not one any more.
Since harvest#85 `enforce_message_cap` caps each size class by count instead
of the mailbox by bytes -- changed so the merge is associative, not for this --
and a maximum-size flood therefore fills only the top class and cannot reach a
small honest message (`the_byte_route_no_longer_evicts_a_small_honest_message`).
The count route still works, is cheaper anyway at about 122 KiB, and is still
one update. **None of that changes the argument below**, which depends only on
the flood being one update, and would hold even if every route were closed.

**What eliminates it is the order of the buy flow, not the speed of the
write.** In the incentive design the confession arrives with the invoice at
step 4, and the buyer pays at step 5. So:

> **The buyer persists the confession, confirms the persistence, and only then
> pays.**

An eviction after that point achieves nothing: the buyer already holds their
capability, in a store the seller cannot reach, and the seller has no way to
take it back. The race stops mattering because nothing of value happens after
it. It is not "store it fast enough" -- it is **do not part with money until
you hold the thing that protects you**.

Two consequences that are constraints on other work, not observations:

* **The client MUST confirm the delegate write before treating the reply as
  usable.** This was left open as a question of preference; it is not one. A
  silently-refused write leaves the buyer paying for a confession they do not
  have, which is the exact loss the whole design is avoiding. The delegate can
  already report a refused write rather than counting it as "not stored"
  (`marking_reports_a_failure_when_the_node_refuses_the_write` is the same
  shape on the marking path).
* **Persisting the confession is a precondition of payment.** That is a
  constraint on the Buy button. A Buy flow that pays first and stores after
  satisfies every test in this repository and defeats the entire argument
  above.

  **Built, for the thing that exists today** (`feat/buy-flow`, 2026-09-05).
  The Buy flow now exists, and payment is gated on
  `state::AppState::payment_blockers`, which answers a list of
  `state::PaymentBlocker` rather than a bool. One of them is
  `ConversationNotKept`: the buyer's software shows no payment address until
  the DELEGATE has answered `Ok` to keeping the conversation -- not until a
  request was sent, which is the distinction that matters, since a refused
  write would otherwise read exactly like a successful one.

  The confession does not exist, so there is no `ConfessionNotPersisted`
  variant yet. Adding it is one variant and one check in `payment_blockers`.
  What makes that safe rather than hopeful is that
  `components::buy_view::is_temporary` matches the enum with no wildcard arm,
  so a new blocker does not compile until somebody has said whether it means
  "wait" or "walk away" -- which is the sentence the buyer is shown. That
  fired for real while the buy flow was being written.

### Receiving a confession must CLEAR the backed-up flag

`make_room` prefers to evict conversations marked `backed_up`, on the sound
reasoning that the buyer can get those back. Once a record can hold a
confession, that preference **inverts into a hazard**: a record marked
backed-up becomes the *preferred* eviction victim, while the backup string that
justified the mark may predate the confession entirely. The flag says
"recoverable", the string does not contain it, and the record is first out.

**So receiving a confession must clear `backed_up` on that record.** The
connection worth recording is that this is exactly Ian's own argument for
per-conversation export, one level down. He moved export from per-store to
per-conversation because **a per-store backup goes stale the moment a new
conversation starts**. The same staleness applies within a conversation: **a
per-conversation backup goes stale the moment new content arrives in that
conversation**. The mark describes a string, and the string describes a moment.

This is easy to miss precisely because the eviction preference is correct in
isolation. Someone re-deriving it will check that shedding recoverable records
before unrecoverable ones is right, find that it is, and not notice that it
depends on the record's contents not changing after the mark. Today they do not
change; in Phase 2 they will.

### What Phase 2 still has to decide, and this note does not

* **What is persisted.** The confession bytes as received, or a
  verified-and-normalised form. Storing what arrived is the safer default,
  since a normaliser is a second place the claim can be broken.
* **Size.** `MAX_BACKUP_STRING_BYTES` bounds the backup string at 4 KiB against
  an honest backup of just under 400 characters, and a record carrying a
  confession is larger than one carrying keys. Both that cap and the eviction
  ranking in `make_room` assume today's record size.

## What this does not do

* **It does not persist `authored_here`.** The entry digests of messages this
  tab sent are the only authorship this browser can establish, and they are
  not kept. After a reload the buyer's own messages are described by direction
  ("Addressed to the seller") rather than as "You, from this tab". Both are
  truthful; the second is less specific. What is at stake in this change is the
  ability to READ the thread, which is unaffected.
* **It does not stop a pasted backup becoming the active thread.** A restored
  conversation is sorted by its own `created_at`, which came from the string,
  so a backup somebody else supplied can be the one the buyer's next message
  continues -- and its secret is known to whoever supplied it. Nothing can
  distinguish a backup the buyer made from one they were handed, so the buyer
  is told: an import that restores anything says that messages from now on may
  continue a restored conversation, and that whoever gave them the backup can
  read those. Import is a deliberate act, which is why this is a warning
  rather than a refusal.
* **It does not close the race** where a buyer sends a first message before the
  recall answer arrives. They get a second conversation with the same store;
  the older one is still recalled and still readable, and the thread view shows
  both in time order.
* **It does not sync between a buyer's own devices.** A backup is a string
  the buyer moves by hand. Automatic sync between a user's peers is a real
  question and an unsettled one -- whether it belongs in freenet-core or in
  each delegate -- and is deliberately not attempted here.
* **It does not make a common backup format across delegates.** It follows
  the ghostkey vault's shape closely enough that a future common system has
  two consistent examples to generalise from, which is as far as this goes.
