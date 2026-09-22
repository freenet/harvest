# Untested invariants

Safety and correctness properties that the code asserts in a comment, are
**true as of the commit below**, and that **no test would catch becoming
false**.

Compiled 2026-09-05, against `feat/bitcoin-payments`, after a review that found
eleven comments asserting protections that either did not exist or described a
mechanism that had moved. In every one of those cases the comment read as
authoritative. This file exists because the reviewed fix for that is not more
comments.

Scope: `common/src/{store,payment,mailbox,reputation,listing,address}.rs`,
`contracts/*/src/lib.rs`, `ui/src/migrate.rs`, `ui/src/state.rs`. It did not
originally cover `delegates/` or `ui/src/gateway/`, which were held by other
people during the review and are collected separately -- but the messaging
section below does, because that change touched both and there is no reason to
leave a fresh gap for a later review to find.

A note on what CI does and does not compile, because it was got wrong twice
during this review in the pessimistic direction. `ui/src/gateway/` **is**
type-checked and linted on every PR, by the `clippy the UI for wasm32` step;
it is never EXECUTED, which is the real gap. `tests/rehearsal/` was reached by
nothing at all until 2026-09-05 and is now compile-checked; it still cannot be
run without a live node.

**This list is not a to-do list.** Most entries are cheap to leave uncovered.
The four that are not are named at the end, and that section is the point of
the document.

## How to read an entry

* **Claim** — what the comment asserts, not what the code does.
* **Caught?** — would any existing test fail if the claim stopped holding?
  "No" means the guard can be deleted, or the property broken, with
  `cargo test --workspace` still green.

Entries are recorded per claim, not per line: several claims below rest on one
guard, and that is noted where it happens.

## A test can be red-verified and still not observe its own claim

The failure this document exists for has a second form, found on 2026-09-05
and worth naming because it defeats the usual check. A test can be honestly
written, honestly red at the time, and still be unable to see the thing it
describes -- because the FIXTURE makes the mutation cancel itself out.

`re_storing_a_held_conversation_evicts_nothing` re-stored the OLDEST held
conversation. The oldest is also the eviction victim, so with the guard
deleted the eviction removed exactly the record about to be re-written: the
count was unchanged, the record was present, the test passed. Its own doc
comment described the failure it could not observe.

**So "I watched it fail" is necessary and not sufficient.** The additional
question is whether the fixture puts the guard's subject and the mutation's
effect in the same place. Ask it whenever a test fills a bounded structure and
then acts on a member of it: the member you choose decides whether the test
can see anything. Choose the one the code path is actually about -- here, the
thread the buyer is writing into, which is the newest.

---

## A doc comment outlives the design it described

`entry_digest`'s doc comment said, in the same commit that made the digest the
contract's identity, that identity is the writer's NONCE and that a colliding
substitute displaces the original -- the exact inverse of the security
property the commit established. Nothing was wrong when it was written. The
digest existed first as a client-side convenience for recognising your own
messages, and that paragraph described the world it lived in truthfully. When
the digest was PROMOTED to the contract's definition of identity, the code
moved and the comment did not, because the promotion touched `verify`,
`summarize`, `delta` and the dedup -- and not the function whose meaning had
changed underneath them all.

**The general shape: a symbol whose ROLE changes without its BODY changing is
the one whose documentation goes stale silently.** A rename or a signature
change drags the comment into the diff and a reviewer reads it. A promotion
does not: `entry_digest`'s body is byte-for-byte what it was, so the diff
offered nothing to read. Every reviewer looked at the call sites, which is
where the change was.

It is also the worst possible direction of staleness. A comment that merely
lags is a nuisance; this one asserted the *negation* of a property the code
now guarantees, in the doc comment of the function that guarantees it, which
is the first thing anyone touching identity would read. A later change could
have been justified by it in good faith.

The check that would have caught it costs one question, asked at the moment a
helper is promoted rather than at review: **"which comments described this
thing in its old role?"** Grep for the symbol before promoting it, not after.

---

## Attribution: the same error, got right and got wrong in one commit

The convergence comments in `common/src/mailbox.rs` are careful about
attribution -- they name both mechanisms, say that either alone suffices, and
say what fails when both go. In the same commit, the register row for the
AES-GCM nonce limitation credited the invariant to a test whose body referenced
no Harvest symbol at all, while the three tests that actually pin nonce
freshness went uncredited. One commit, the correct form in one place and the
error in the other.

**The difference was not care, it was the forcing function.** The convergence
claim came out of a mutation matrix: deleting each mechanism in turn produced
a table, and a table with two rows reading "passes" makes it impossible to
write "this one carries it" without noticing you cannot support that. The
register row had no such table. It was written from the belief that a test with
a matching name must be pinning the thing the row describes -- and the name
matched because the row and the test were written in the same sitting, for each
other.

**So the practice worth generalising is not "attribute carefully".** It is:
*run the mutation before writing the attribution, and let the result name the
mechanism.* Where that is too expensive, write the weaker claim the evidence
supports. Both rows now name the mutation that produced them.

---

## Three doc comments have attached to the wrong item, all by a missing blank line

`decode_probed_state`, `enforce_message_cap`, and
`known_limit_the_counterparty_can_write_in_either_direction`. In each case a
new doc block was inserted directly above an existing one with no blank line
between them; Rust merges consecutive `///` lines into a single doc comment, so
the compiler is content, `rustfmt` is content, and the combined block silently
documents whichever item comes last. The item that lost its documentation is
left bare.

Three instances on one branch is a mechanism, not bad luck, and the last one
cost the most: it stripped the doc from a test whose entire value is telling a
future reader that a red result means **inverting the assertion, not repairing
the code**. A bare `known_limit_*` test is one somebody fixes.

**Is there a cheap check? Yes, for the consequence rather than the cause.** The
cause is undetectable: a merged doc block is syntactically identical to a long
one, and no lint can know where you meant the boundary. `clippy` catches only
the neighbouring shape -- `empty_line_after_doc_comment`, which is what caught
the `enforce_message_cap` instance -- and that fires on a blank line where
there should be none, the opposite defect.

The consequence is detectable and is the same in all three cases: **an item
silently loses its documentation.** A source scrape asserting that every
`#[test] fn` (and every `pub fn`) is immediately preceded by a `///` line, or
by attributes that are themselves preceded by one, catches every instance of
this class, because the absorbed doc always leaves its owner bare. It is the
same shape as `no_production_code_compares_message_nonces_for_identity` and
would reuse its file walker. Filed, not built.

---

## A citation is a claim, and this file makes hundreds of them

Four rows in the tables below cited tests by names that did not exist:
`a_backup_is_filed_under_the_store_that_was_asked_about` (renamed when export
became per-conversation), `an_import_asks_for_the_restored_conversations`
(plural, the test is singular), `known_limit_a_nonce_collision_reuses_the_\
keystream` (asserted as a pin for a day before anyone wrote it), and the
handler `on_conversations_exported` (also singular). All four are fixed above;
the keystream one was fixed by writing the test, because the claim was worth
pinning and the pin was short.

The third is the one to learn from. That row was read as evidence in the
nonce-reuse analysis that led to the entry-digest change -- an argument
resting, in part, on a test nobody had written. **A "Yes -- `test_name`" in
this file is a load-bearing claim, and an unresolvable name is a claim that
was never checked.**

**A cheap way to make a dead citation fail the build, not yet built.** A
single `#[test]` in `harvest-common` that reads this file, extracts every
snake_case identifier appearing in a "Yes"/"Pinned" cell, greps the workspace
`.rs` sources for `fn <name>`, and asserts every one resolves. It is the same
shape as `no_production_code_compares_message_nonces_for_identity`, which
already reads sources from `CARGO_MANIFEST_DIR`, so the machinery exists. Two
details decide whether it is worth having: it must skip cells marked **No** or
**Partly** (which legitimately name things that do not exist), and it must
tolerate non-test identifiers like `skip_serializing_if` and `conversation_id`
-- most cheaply by requiring an explicit opt-out marker rather than by
guessing. Filed here rather than built, because the decision to spend a test
on documentation-integrity is the lead's.

## `common/src/store.rs`

| Line | Claim | Caught? |
|---|---|---|
| 470 | `OrdersV1::verify` rejects a state holding more than `MAX_ORDERS` entries. | **No.** `enforce_order_cap` is well tested, but nothing tests the `verify` guard. Delete it and the suite stays green. Contrast `common/src/mailbox.rs`, whose identical guard *is* tested by `an_over_cap_state_is_rejected`. |
| 476 | A record filed under a key that is not its own `order.id` is rejected. | **No.** No test constructs a mis-keyed state. `merge_order` always keys by `incoming.order.id`, so this is unreachable from any honest path and reachable only from a hand-built state — which is exactly what a hostile peer submits. |
| 439 | The summary is "capped at `MAX_ORDERS` entries", and so is bounded. | **No.** True only because line 470 rejects over-cap states. Inherits that gap; not independently covered. |
| 272 | The `to_cbor` here is "Infallible … cannot fail", justifying an `expect` inside contract code. | **No**, and not straightforwardly testable — it is a claim about the shape of the type, and a breach is a panic inside the contract rather than a wrong answer. |
| 388 | `enforce_order_cap`'s ranking is "a pure function of the *content* of `orders`, not of the sequence in which entries were inserted". | **Yes** — `pruning_is_order_independent`. Listed because three neighbouring claims cite it. |

`ListingsV1` has no cap and no `verify` guard of either kind, and claims none.
Orders are capped at 4096 and mailbox messages at 512, both with a `verify`
guard; listings are bounded only by the seller's own signature being required
on each one. That asymmetry is deliberate as far as the code shows, but it is
stated nowhere, so a reader who generalises from `MAX_ORDERS` will be wrong.

## `common/src/payment.rs`

| Line | Claim | Caught? |
|---|---|---|
| 526 | `verify_payment_proof` "must be a pure function of its arguments: no clock, no network, no ambient state". | **No.** True today. Nothing enforces it, and nothing would fail if a clock were added — the divergence it prevents only appears between peers. A source-scrape pin test is the only practical form. |
| 628 | — | Not a claim: `verify_on_chain_proof` carries **no doc comment at all**, while every claim about it lives in its callers' and its types' comments. The only undocumented private item in `common/`. |
| 306 | The claim-set completeness gap "cannot be fixed inside this function", in the merge, or via the related contract. | **Partly.** `a_withheld_retraction_is_not_currently_detected` and `a_withheld_reconfirmation_still_reads_as_a_reversal` pin the two *symptoms* as known gaps. Nothing pins the argument that they cannot be closed locally. |

## `common/src/mailbox.rs`

| Line | Claim | Caught? |
|---|---|---|
| 121 | `enforce_message_cap`'s ranking "has to be *total* and a pure function of message content", so two replicas holding the same messages keep the same subset. | **Yes** — `merging_is_order_independent`, `merging_is_batch_independent`. |
| 194 | `verify` must "be a pure function of its inputs or two peers evaluating identical bytes at different moments disagree and never converge". | **Partly.** `an_old_message_does_not_invalidate_the_whole_mailbox` and `age_alone_never_drops_a_message` cover the time-dependence that actually broke this once. Purity in general is not enforced. |
| 8 | The count cap "is the mailbox's only retention rule". | **Yes** — `age_alone_never_drops_a_message`, `a_mailbox_under_the_cap_keeps_everything`. |

This file is the best-covered in the review scope: 14 tests, including one
(`known_gap_a_funded_flood_still_evicts_every_honest_message`) that pins a
residual so closing it fails loudly. It is the model the other entries are
measured against.

## `common/src/reputation.rs`

| Line | Claim | Caught? |
|---|---|---|
| 34 | Feedback is "naturally commutative: adding feedback entries in any order produces the same final set". | **Yes, since harvest#22** -- the claim was FALSE until then (see the messaging section's reputation row). Now pinned by `two_signed_entries_for_one_token_converge` and `peers_holding_different_entries_for_one_token_exchange_them`, and the doc comment says what actually holds it: one entry per token, resolved by a total order over the entry's bytes. |
| 40 | The feedback list is "append-only" — no removal path. | **No.** No test asserts absence of a removal path. Load-bearing for `ui/src/migrate.rs:620`, which selects `FoldAll` on the strength of it. |

## `common/src/listing.rs`

| Line | Claim | Caught? |
|---|---|---|
| 394 | A signature produced for "some other webapp must NOT verify, even though the signature itself is genuine". | **Yes** — `test_authorized_listing_wrong_requestor_fails`, `test_authorized_listing_delegate_requestor_fails`, `test_authorized_store_info_wrong_requestor_fails`. |

Nine tests, and the claims that matter are pinned. No gaps found.

## `common/src/address.rs`

| Line | Claim | Caught? |
|---|---|---|
| 116 | "The whole guard rests on this: the same source must encode to the same bytes." | **Yes** — `placeholders_are_deterministic`. |
| 156 | "Distinct structs must not collide, or a field moved from one to another would not register as a change." | **Yes** — `placeholders_differ_between_structs`. |
| 168 | `placeholder_verifying_key` is a real curve point, so the encoding is representative. | **Yes** — `placeholder_verifying_key_is_canonical`. |

This module is the parameter-drift guard that the V1/V2 encoding change should
have tripped. Its own claims are covered.

## `contracts/store-contract/src/lib.rs`

| Line | Claim | Caught? |
|---|---|---|
| — | The contract asks for no related contracts: validity is a pure function of the state and parameters. | **Yes** -- `a_paid_order_validates_without_asking_for_related_contracts`, for a paid order with and without a code hash. The three rows that stood here described the related-contract cross-check (additive-only, one request round); that code was removed, so they no longer describe anything. |

## `contracts/mailbox-contract/src/lib.rs`, `contracts/reputation-contract/src/lib.rs`

| Line | Claim | Caught? |
|---|---|---|
| — | Neither file asserts a safety property in a comment. | **Out of date: both have tests now.** The mailbox gained its own during the messaging work, and the reputation contract gained summary-stability tests with #54 and the zero-byte `get_state_delta` tests with #55. The `InvalidUpdate` paths are still untested in both. |

## `ui/src/migrate.rs`

| Line | Claim | Caught? |
|---|---|---|
| 190 | `store_params` is the one place a store's parameters are derived. | **Not a test — the compiler.** The parameter structs' fields are `pub(crate)`, so outside `harvest-common` the only way to build one is its `new`, and a second derivation does not compile whatever it is spelled. `contract_parameter_fields_stay_crate_private` guards the one step that would silently give that up (a field made `pub` again); it is a substring match and says so. |
| 615 | Listings are "grow-only … the contract has no removal path at all, so absence is never a deletion" — the soundness precondition for `FoldAll`. | **No.** True (verified by inspection: `ListingsV1::apply_delta` only pushes). Nothing asserts it, and `common/src/store.rs:152` asserted the opposite until 2026-09-05. |
| 620 | Reputation is "a grow-only set keyed by nonce with no removal path whatsoever" — same precondition. | **No.** Same shape as above. |
| 300 | Candidates are ordered "by the registry's declared generation, never by slice order". | **Yes** — `superseded_store_generations_are_probed_under_their_own_parameter_encoding`. |
| 231 | The legacy parameter band is `V2..=V5`, a middle band a threshold cannot express. | **Yes** — `each_store_generation_is_derived_under_the_encoding_it_shipped_with`, which takes its expectation from the artifacts rather than from the predicate under test. |

## `ui/src/state.rs`

Outside the list this review was asked for; included because it was covered and
belongs in the durable record.

| Line | Claim | Caught? |
|---|---|---|
| 1249 | `withdraw_pending_signature` matches on signed bytes, "so this cannot withdraw a different request that happens to sit at the same position". | **No.** The function is host-compilable, but both call sites are `#[cfg(target_arch = "wasm32")]` and no test calls it. The sibling claim about matching an *answer* is tested (`an_answer_goes_to_the_request_whose_bytes_it_carries`); withdrawal is not. |
| 834 | The migration map is kept flat, so "resolving is a single lookup and can never chase a cycle". | **Partly.** The single-hop case is tested. Chained hops (A→B then B→C) and the degenerate case (B→A) are not. |
| 881 | "never lose a locally-known registration" — the delegate's answer only adds. | **Yes** — `a_store_list_answer_never_drops_a_store_it_does_not_name`, `a_store_list_answer_keeps_a_locally_known_contract_key`. |

## Buyer-to-seller messaging (added on `feat/messaging`, 2026-09-05)

Recorded at the time the code was written rather than by a later review, which
is the only way this file stays a record rather than an archaeology exercise.

| Where | Claim | Caught? |
|---|---|---|
| `ui/src/gateway/mailbox_ops.rs::send_message` | A client GET primes the local node's store, so issuing one before the update gives the node the contract it is about to run. | **No, and it cannot be here.** Nothing in this repository can reach a node. The doc comment says so in those words rather than asserting the send works; the whole path is unexercised against a live node. |
| same | The GET-then-update race is tolerable. | **No.** Both calls resolve on WebSocket send, so the ordering at the node is not observable from here. The call site now records what is known, what is not, what the failure looks like when the race is lost (message stays permanently in `unconfirmed_sent`, seller never receives it, buyer is not told), and why a sleep or retry must not be added. Characterising it needs `tests/rehearsal/` and a node. |
| `ui/src/components/message_view.rs::send` | The buyer's subscription to the seller's mailbox actually delivers replies. | **No.** The subscribe is a wasm-gated `register_store_mailbox` and the delivery is the network's. What IS tested is everything either side of it: that a reply the buyer *receives* is read correctly (`a_seller_replies_into_their_own_mailbox_and_the_buyer_reads_it`, at both the `messaging` and `AppState` levels). |
| `ui/src/gateway/mailbox_ops.rs::reply_to_mailbox` | The seller's reply reaches the same mailbox the buyer is reading. | **Partly.** `the_two_ways_to_address_a_mailbox_agree` pins that the derived key and the rebuilt-from-id key are identical in instance AND code hash -- the second assertion added after the first version of that test survived the mutation, because `ContractKey`'s `PartialEq` ignores the code hash. What is untested is the send itself. |
| `harvest_common::mailbox::MessageDirection` | A copy of the buyer's own message cannot read as a reply from the seller. | **Yes** -- `a_copy_of_the_buyers_own_message_does_not_read_as_a_reply`, mutated red by deriving both keys under `BuyerToSeller`, which also turned two neighbouring tests red. Note the first version of that test mutated the WHOLE 24-byte nonce, so it passed because decryption failed for an unrelated reason; it now mutates only the dedup padding, which is the mutation an attacker would make. |
| `harvest_common::mailbox::message_aad` | Every field of a message except the ciphertext is authenticated, so it cannot be replayed, re-dated, re-tagged or re-labelled. | **Yes** -- `a_replayed_message_with_fresh_padding_does_not_authenticate` and `the_whole_envelope_is_authenticated`, both observed red before the associated data existed. The replay was verified working: bytes 12..24 of the nonce fed deduplication and nothing else. |
| `harvest_common::mailbox::MailboxStateV1::apply_delta` | It never produces a state `verify` rejects. | **Yes** -- five tests in `dedup_tests`, all observed red against the shipped snapshot-before-the-loop form. This is the claim `verify`'s own doc comment rested on and that nothing checked; the defect was live on `main`. |
| `harvest_common::mailbox::dedupe_identical_entries` | Two different messages sharing a nonce converge AND both survive. | **Yes** -- `two_different_messages_sharing_a_nonce_converge_and_both_survive` and `a_nonce_collision_inside_one_delta_converges_and_keeps_both`. Both were renamed on 2026-09-05 when identity moved to `entry_digest`: convergence alone had stopped being the whole claim, because two peers agreeing to DISCARD the same message converges perfectly and is exactly the retraction the change forbids. |
| `harvest_common::mailbox::apply_delta` | The merged state's byte order is deterministic when NEITHER cap binds. | **Yes, since 2026-09-05** -- `merging_converges_when_neither_cap_binds`. It was not before: all four earlier convergence tests use over-cap fixtures, so every one of them exercised `enforce_message_cap`'s ordering and none exercised the under-cap path. Deleting BOTH ordering mechanisms left those four green and only this one red. The row below is corrected accordingly. |
| `ui/src/state.rs::on_conversation_keys` | The delegate's answers are paired with the questions by echoed tag, not by position. | **Yes, since 2026-09-05** -- `a_short_answer_does_not_hand_one_buyers_key_to_another` and `a_reordered_answer_still_decrypts_both_buyers`. It was not before, and the gap has a shape worth naming: the delegate had a test proving it ECHOES the tag, whose comment called the positional case "the mutation that matters" -- but a test that proves a producer emits something cannot prove the consumer uses it, and the consumer is the only side that could correlate positionally. The guard was on the wrong side of the boundary from the thing it guarded. |
| `ui/src/state.rs::on_delegate_response` (`EncryptionKeyReady`) | The key is filed under the identity the delegate named. | **Yes, since 2026-09-05** -- `an_encryption_key_is_filed_under_the_identity_the_delegate_named`, found by applying the same producer/consumer question to the other messaging response. Worse than the `ConversationKeys` case if it went wrong: a misfiled encryption key is PUBLISHED in that identity's signed store details, so every buyer thereafter encrypts to a key the seller cannot read -- permanently, in a record they cannot retract. |
| `ui/src/state.rs::on_delegate_response` (`ReputationKeysInitialized`, `RsaPublicKey`, `StoreList`) | Each answer is filed under the identity the delegate named. | **Yes, since 2026-09-05** -- `delegate_correlation_tests`, four tests, each mutated red by filing under `pending_store_creation`'s fingerprint instead. Pre-existing sites, hardened after the same shape produced a real gap in `on_conversation_keys`. The RSA one is the sharpest: `ReputationParameters` carries the RSA key, so a contract's ADDRESS is derived from it, and a misfiled key points a signed store at a reputation contract nobody owns. |
| `ui/src/state.rs::conversation_keys_to_request` | A tag the delegate declined is never asked about again. | **Yes** -- `a_tag_the_delegate_declined_is_not_asked_about_again`. The previous behaviour re-asked forever, on the reasoning that a short answer might be transient; the delegate's omissions are deterministic, so one message with an unusable tag looped the tab for its lifetime. |
| `ui/src/messaging.rs::BuyerConversation::read` | A buyer sees their own conversation and nobody else's, and a flood tagged with their key does not hide it. | **Yes** -- `a_buyer_sees_only_their_own_conversation` and `a_full_cap_flood_tagged_with_the_buyers_key_does_not_hide_their_thread`. The COST of that flood is measured rather than asserted (see `docs/messaging-privacy.md`); no timing assertion was added, because a wall-clock bound in CI is a flaky test. |
| `harvest_common::mailbox::enforce_message_cap` | The mailbox is bounded in bytes, and two peers prune to byte-identical state. | **Yes for the bound**, `the_mailbox_is_bounded_in_bytes_and_not_only_in_count`, red against the count-only predecessor. **Partly for the convergence**, and the qualification matters: `merging_is_order_independent_across_the_byte_budget` is red against a rule that sorted only when the COUNT cap bound, but the batch-independence test is NOT -- chunks arrive in the same relative order, so the two do not bite equally. And all four convergence tests use over-cap fixtures, so what they pin is `enforce_message_cap`'s ordering rather than convergence in general; the under-cap path was untested until `merging_converges_when_neither_cap_binds`. |
| same | Pruning cannot empty a mailbox. | **Yes**, structurally and behaviourally: a `const _: () = assert!(...)` beside the constants makes the corner a BUILD failure, and `an_oversized_message_is_refused_rather_than_emptying_the_mailbox` drives it through `apply_delta` with a message dated past the honest traffic. |
| `harvest_common::mailbox::message_bytes` | The byte charge is a bound and not a proxy. | **Yes** -- `the_byte_charge_is_never_less_than_the_encoded_size`, checked against real CBOR across empty, small, top-bucket, long-timestamp and empty-tag shapes. |
| `harvest_common::mailbox::MailboxStateV1::verify` | It deliberately does NOT check the byte budget, so a mailbox that was legal when written is never stranded. | **Superseded by harvest#85**: `verify` now refuses anything `apply_delta` would change (over a size-class cap, over `MAX_MESSAGE_BYTES`, out of canonical order), because such a state is not equal to itself merged with itself. The stranding argument was about state held at the SAME address; the harvest#85 re-key starts every mailbox empty and the fold fills it through `apply_delta`. The test that pinned the old rule is inverted as `verify_refuses_an_over_budget_state_now_the_rekey_starts_empty`. |
| `harvest_common::mailbox::MessageDirection` (second entry) | Direction separation defends against a third party and **NOT** against the counterparty. | **Pinned as a LIMITATION** -- `known_limit_the_counterparty_can_write_in_either_direction`. Both parties derive both keys from one symmetric secret, so either can encrypt in either direction; a buyer's message was verified appearing in a seller's inbox addressed as the seller's own. Not fixable at this layer: only a per-message signature distinguishes two holders of one secret. The UI therefore reports direction, and names only what this browser sent itself as authored. |
| `ui/src/messaging.rs::seal` | A message the compose box accepts is one a mailbox accepts. | **Yes** -- `a_message_too_large_for_a_mailbox_is_refused_at_the_compose_box`. Found by accident: a measurement fixture had every message silently dropped by `apply_delta`, which from the sender's side is indistinguishable from the write race and never resolves. |
| `ui/src/gateway/store_ops.rs::create_store_contracts` | The store is published carrying the seller's encryption key. | **No.** The function is `#[cfg(target_arch = "wasm32")]`, so `cargo test` never reaches it -- the same blind spot as entry 1 below, and the same reason: it is the counterparty of a derivation, not the derivation itself. What IS tested is that `PendingStoreEdit::store_info` carries the key on the *edit* path, which is the path a seller uses to repair a store. |
| `ui/src/state.rs::ask_for_conversation_keys` | The request actually reaches the delegate. | **No.** The decision half (`conversation_keys_to_request`) is host-tested to eight assertions; the send is a wasm-gated `spawn_local`. |
| `ui/src/components/message_view.rs` | Everything the component says on screen. | **No.** There are no component tests in this repository at all. This is the file whose *previous* version claimed "messages are end-to-end encrypted" beside a button that encrypted nothing, so it is worth being explicit: the claims were re-enabled on the strength of the crypto tests below, and nothing checks that the words on screen still match them. A future change that makes messaging conditional again will not fail any test by leaving the reassuring paragraph in place. |
| `common/src/mailbox.rs::conversation_key_from_dh` | Buyer and seller derive the same key. | **Yes**, three ways: a known-answer test against `b3sum` (`the_conversation_key_derivation_is_pinned`), the delegate's `the_seller_derives_the_key_the_buyer_derived`, and the UI's `a_sealed_message_is_readable_by_the_seller_who_holds_the_secret`, which reconstructs the seller from a bare X25519 secret rather than from the UI's own code. |
| `common/src/store.rs::StoreInfoV1::encryption_public_key` | `skip_serializing_if` keeps every pre-existing ghostkey signature verifying. | **Yes** -- `a_store_info_re_encodes_to_its_signed_bytes_but_for_the_removed_field`, observed red against the naive `#[serde(default)]`-only form. It is byte-exact but for the field V13 removed. |
| `ui/src/ghostkey_cert.rs::store_verifying_key` | A stolen certificate yields no key, so a buyer cannot be routed to the victim's mailbox. | **Yes** -- `a_stolen_certificate_yields_no_key_to_derive_a_mailbox_from`, mutated red by trusting any certificate that parses and chains. |
| `ui/src/state.rs::BrowsingStore::seller_verifying_key` | A store the buyer is told is unverified is never one the compose box is offered for, because both come from one call. | **Yes** -- `an_unverified_store_yields_no_key_to_message_it_with`, mutated red by setting the key unconditionally. It pins the wiring; the check itself is the `ghostkey_cert` row above. |
| `delegates/harvest-delegate/src/messaging.rs` | Everything the delegate writes is under the exported prefix. | **Yes** -- `everything_this_module_writes_is_under_the_exported_prefix`, which drives the real writer. The pre-existing `every_secret_the_delegate_writes_is_under_the_exported_prefix` stayed GREEN under the same mutation, because it reads a hand-maintained list; that is the gap the new test closes. |

### Buyer conversation persistence (added 2026-09-05, same branch)

| Where | Claim | Caught? |
|---|---|---|
| `delegates/harvest-delegate/src/secrets.rs::RemovableSecrets` | The node genuinely deletes a removed secret -- blob, snapshots, index entry and enumeration-registry entry. | **No, and it cannot be here.** `DelegateCtx::remove_secret` is a `false`-returning stub off wasm32, like every other secret method, so the tests drive `MemSecrets`. The claim is read from freenet-core's own source (`wasm_runtime/secrets_store/store.rs::remove_secret`) and cited in the trait's doc comment; the doc comment also says, in those words, what the tests do and do not establish. Observing it needs `tests/rehearsal/` and a live node. What IS tested is that this crate asks for removal, re-reads the key, and reports a failure rather than an `Ok` when the key is still there (`a_refused_removal_is_not_reported_as_forgotten`). |
| `delegates/harvest-delegate/src/messaging.rs::forget_buyer_conversation` | Forgetting leaves nothing behind, not an emptied value. | **Yes** -- `a_forgotten_conversation_leaves_nothing_behind`, observed red against the emptied-value form, which left `harvest:buyer_conv:{store}:{tag}` in the store with the store id still in it. That red run is the reason the key is named rather than an opaque slot: the slot design existed only to work around a deletion the platform turned out to have. |
| `delegates/harvest-delegate/src/messaging.rs::MAX_BUYER_CONVERSATIONS` | The count cap is a byte bound, because both the key and the value are bounded. | **Yes for both halves.** The cap itself: `the_cap_bounds_the_store_and_evicts_the_oldest`, red with the cap deleted. The key half: `a_store_id_that_is_not_a_contract_id_is_refused` -- without that refusal the key is caller-sized and the cap bounds entries while bounding no bytes, which is this repository's own named trap. |
| same | An undecodable entry is evicted before a real conversation. | **Yes** -- `an_undecodable_entry_is_evicted_before_a_real_one`, red when the ordering sorts undecodable entries last. |
| `ui/src/state.rs::compose_to_seller` | Sending a message is what asks the node to keep the key. | **Yes** -- `sending_a_message_asks_the_node_to_keep_the_conversation`, red when the call is removed from the send path. Worth its own test because every other test around it calls `conversation_to_keep` directly and would have stayed green. |
| `ui/src/state.rs` / `delegates/.../messaging.rs` | The tag the delegate files a conversation under is the tag the mailbox carries. | **Yes, from both sides, which is the point.** The delegate derives the tag from the secret it is sent (`a_stored_conversation_comes_back_with_usable_keys` asserts the recalled tag and both keys against a seller derived independently); the UI asserts that what it SENDS has that same public half (`the_delegate_files_a_conversation_under_the_tag_the_mailbox_carries`). The seam between the two crates is `harvest_common::mailbox::conversation_key_from_dh`, which both call and which is separately pinned by a known-answer test. The UI crate cannot depend on the delegate crate, so this pair is the strongest available statement. |
| `ui/src/state.rs::on_buyer_conversations` | A recalled conversation reads the reply that arrived while the tab was closed. | **Yes** -- `a_reply_is_readable_after_the_tab_that_asked_is_gone`, which builds the delegate's answer from the real crypto and drives a fresh `AppState`. Red when the recall handler is inert. |
| `ui/src/state.rs::conversation_thread` | Every conversation this node has had with the store is read, not just the active one. | **Yes** -- `every_conversation_with_a_store_is_read`, red when only the last is read. It drives the documented race (the buyer writes before the recall answers, so they hold two conversations with one store) and asserts the older thread still appears. |
| same | A non-empty recall re-subscribes to the seller's mailbox, and an empty one subscribes to nothing. | **Yes** -- `recalling_conversations_subscribes_to_the_sellers_mailbox` and `recalling_nothing_subscribes_to_nothing`. The second is the privacy half: a reader who never wrote to a seller must not advertise an interest in their mailbox. |
| `ui/src/state.rs::buyer_conversations_to_recall` | A store is not marked as asked before the delegate is registered. | **Yes** -- `a_store_is_not_marked_asked_before_the_delegate_is_registered` and `registering_the_delegate_asks_about_stores_already_on_screen`, both red with the guard removed. `components::app` opens a store link BEFORE registering the harvest delegate, so this ordering is the common one, not the exotic one. |
| `ui/src/state.rs::on_buyer_conversation_forgotten` | A conversation leaves the buyer's view only when the node says the record is gone. | **Yes** -- `a_conversation_is_dropped_only_when_the_node_says_it_is_gone`, which drives the refusal first and the success second, plus `an_unasked_forget_answer_drops_nothing`. |
| `harvest_common::delegate::ConversationSecret` | The buyer's secret does not print itself, in the `Debug`-deriving request it travels in. | **Yes** -- `a_conversation_secret_does_not_print_itself`, observed red against a derived `Debug`, which printed all 32 bytes. `a_conversation_secret_encodes_as_its_bytes` pins that the newtype is not a wire change. |
| `ui/src/components/message_view.rs::KeptConversations` | The buyer can reach the forget control at all, and the panel says what it does. | **No.** There are still no component tests in this repository -- the same gap as the row above about everything this component says on screen. The state transition behind the button is tested; the button is not. |
| `delegates/.../messaging.rs::decode_backup` | A truncated or foreign paste is refused rather than half-imported. | **Yes** -- `a_truncated_backup_is_refused` (base58check catches the lost tail) and `a_paste_that_is_not_a_backup_is_refused_by_name`, which drives four shapes of wrong paste including a next-version prefix. |
| same, `import_buyer_conversations` | Importing a conversation this node already holds keeps the HELD one, and never overwrites it. | **Yes** -- `importing_a_held_conversation_keeps_the_held_one`, which pastes both an honest backup and a hand-built one naming the same routing tag with a different `conversation_id`, and asserts the held record is what the node still reads its thread with. The one exception is pinned separately: `importing_over_an_undecodable_entry_restores_it`. |
| same | At the cap an import refuses and names what it refused, rather than evicting. | **Yes** -- `an_import_at_the_cap_refuses_rather_than_evicting`, which also asserts the oldest held conversation is still there. This inverts the eviction rule for storing, so the two tests are the record of a deliberate asymmetry rather than an inconsistency. |
| same, `mark_conversations_backed_up` | The backup marker is deleted with the conversation it describes. | **Yes** -- `forgetting_a_conversation_leaves_no_backup_marker_behind`, observed red against the ghostkey vault's own shape (a marker key of its own), which left `harvest:conv_backedup:...` behind naming the store. This is why the marker is a field of the record here and not a separate secret. |
| `delegates/.../handlers.rs` | A foreign web app can neither export a buyer's secrets NOR silence the warning that they exist in one place only. | **Yes** -- `another_web_app_cannot_export_or_silence_a_buyers_backup_warning`, red with the `authorize` call removed. The marker half is the one worth the test: it writes no secret and answers none, so it reads as harmless, and what it does is stop a warning about a conversation nobody has a copy of. |
| `harvest_common::ImportedConversations` / `ui/src/state.rs::on_conversations_imported` | A conversation that could not be restored is NAMED with its reason, not folded into a count. | **Yes** -- `a_refused_import_says_which_and_why`, which asserts both the reason and the shortened tag survive into what the buyer is told. |
| `ui/src/state.rs::on_conversations_marked_backed_up` / `on_conversations_imported` | The screen is refreshed by re-asking the delegate, not by assuming what it did. | **Yes** -- `marking_asks_the_delegate_again_rather_than_assuming`, `an_import_asks_for_the_restored_conversation`, and `a_recall_refreshes_whether_a_held_conversation_is_backed_up`, which drives the whole marking round trip and would fail if a recall only ADDED conversations instead of refreshing held ones. |
| `ui/src/state.rs::on_buyer_conversations` | An answer is filed under the store this browser ASKED about, and one nothing asked for is ignored. | **Yes, since the backup work** -- `conversations_are_filed_under_the_store_that_was_asked_about` and `a_recall_answer_nothing_asked_for_is_ignored`, both red against the obvious implementations (file by the echoed id; act on any answer). The recall carried no request id until this change, so neither guard could exist; the defect it would have caused is a buyer reading, and composing into, a thread against the wrong seller's mailbox. |
| `ui/src/state.rs::ConversationBackup` | A backup does not print itself. | **Yes** -- `a_backup_on_screen_does_not_print_itself`, red against a derived `Debug`. More at stake than the single secret it shares this guard's reasoning with: this one is a complete portable copy of every conversation with a store. |
| `ui/src/state.rs::authored_here` | "What this tab sent" is recognised by something the counterparty cannot reproduce. | **Yes, since the review** -- `a_substituted_message_is_not_shown_as_the_buyers_own` and `a_seller_is_not_credited_with_a_substituted_reply`, both red against the shipped nonce-matching. It was NOT true before: the nonce is public, the counterparty holds the key, and `dedupe_by_nonce` keeps whichever entry ranks highest under attacker-chosen fields -- so their words appeared under "You, from this tab" in both directions. The tests drive the REAL `MailboxStateV1::apply_delta`, so the displacement is the contract's own, not a fixture's. |
| `ui/src/state.rs::unconfirmed_sent` | "Landed" means THIS message is in the mailbox, not that its nonce is. | **Yes, since the final review** -- `a_message_absent_from_the_mailbox_is_unconfirmed_even_if_its_nonce_is_there`, red when landed-ness is decided by nonce. The neighbouring test could not see it: it puts both entries in the mailbox, so the nonce rule and the digest rule agree -- the same fixture shape that let the re-store guard go unpinned. `replaced_sent`, which this row used to cite, was DELETED when the contract fix made displacement impossible; see `docs/messaging-privacy.md`. |
| `harvest_common::mailbox::entry_digest` | Every field is covered, and a substitute sharing a nonce differs. | **Yes** -- four tests, two of them red under mutation (dropping the ciphertext; dropping the length prefixes). |
| `contracts/mailbox-contract` `UpdateData::State` arm, `ui/src/migrate.rs::merge_mailbox` | "Already held" is decided by the same identity `verify` enforces. | **Yes, since the final review** -- neither site decides it any more: both hand everything to `apply_delta`, which dedups by `entry_digest`. Pinned behaviourally by `a_state_merge_keeps_a_message_whose_nonce_something_else_shares` and `folding_keeps_a_message_whose_nonce_the_newer_generation_shares` (both red first), and structurally by `no_production_code_compares_message_nonces_for_identity`, a source scrape, which found the migration fold that review had not. **The scrape is a tripwire, not a proof, and for one round it was far weaker than this row said.** Review planted six rewrites of the identical defect at that same site and it caught one; separately, its `#[cfg(test)]` cut was a truncation at the FIRST occurrence, so an attribute on a helper 40 lines into `handlers.rs` hid the other 1,098 lines, and the control-form defect planted below it was invisible. Both are fixed (brace-matched stripping, widened patterns, waivered reputation sites, workspace-derived directory list) and all seven plants are now caught -- but it reads no types, so a comparison behind a helper or spread across lines still passes. The behavioural tests are what carry the property; every one of the seven plants was caught by those. |
| `ui/src/migrate.rs::merge_mailbox` | The fold is commutative, so `FoldAllAck`'s precondition holds. | **Yes, since 2026-09-05, and it did NOT hold before.** `apply_delta` refuses a message over `MAX_MESSAGE_BYTES` on the INCOMING side, and `merge_generations(newer, older)` puts the predecessor there -- so the same message survived from the successor and vanished from the predecessor, silently, during the one operation whose purpose is to preserve messages. `fold_all_preconditions_hold_for_the_mailbox_state` was green throughout because all three of its samples were small. Now pinned by `folding_is_commutative_across_the_message_size_bound` and `an_oversized_message_is_dropped_from_whichever_side_it_is_on` (both red first, the second via the crate's own `assert_merge_commutative`), and the refusal is applied to both sides with what it could not carry reported. |
| same | The mailbox merge is **normalising**, so strict `merge(a, a) == a` is false for un-normalised input. | **Yes, since 2026-09-05** -- `fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising`. Found while fixing the row above and worth more than it: `policy_check::assert_merge_idempotent` asserts the strict form, and the mailbox merge has never satisfied it -- hand it 517 messages and `merge(a, a)` returns 512, because `enforce_message_cap` runs on every call. So the `FoldAllAck` token was minted against a sample set too small to meet ANY normalisation, not just the size bound. What fold-all actually needs is asserted instead: commutativity and order-invariance on raw samples, idempotence on the merge's own output, and absorption (`merge(merge(a, b), b) == merge(a, b)`), which nothing checked at all. |
| `contracts/mailbox-contract::validate_state` | A state the contract hands back is one it would accept. | **Yes, since 2026-09-05.** It was vacuous: stubbing `validate_state` to return `Valid` unconditionally failed ZERO tests across the workspace, and `a_merged_state_validates` was the only test of it anywhere. What it pinned was that `update_state`'s output CBOR-decodes. It now also asserts a rejection (`a_merged_state_validates_and_an_invalid_one_does_not`) and is killed by that mutation. |
| `contracts/mailbox-contract::summarize_state` | The summary reports what the state holds. | **Yes, since 2026-09-05** -- `a_summary_of_what_a_peer_holds_asks_only_for_what_it_lacks`, found by mutation while re-checking the tests added the same day: stubbing `summarize_state` to answer a non-empty state with an empty summary failed nothing, because the two empty-summary tests drive `get_state_delta` and take the summary as given. The producer/consumer split again -- the consumer was covered and the producer was not. |
| `common/src/reputation.rs::ReputationStateV1` | "Feedback is naturally commutative: adding entries in any order produces the same final set." | **FIXED by harvest#22; the claim was FALSE until then.** The RSA signature covered `entry.token` alone while `category`, `comment` and `submitted_at` rode alongside it unsigned, so anyone could re-submit a published token with different words and each peer kept whichever it saw first, and a seller could push a neutered variant to peers that did not yet hold the real one. The token now carries a per-token Ed25519 `entry_key` and the entry an `entry_signature` over every other field; see the harvest#22/#26/#55 section below for what pins it. |
| `harvest_common::mailbox` convergence for a same-nonce pair | Which mechanism carries it. | **The JOINT property IS pinned; no SINGLE mutation observes it.** Both halves matter and the first is the one that gets lost: three tests fail when both mechanisms are removed, so the suite does defend convergence -- what it cannot do is tell you which mechanism to keep. Corrected after review, because the first version of this row stated a measurement that does not reproduce. The matrix: an order-dependent dedup alone passes (the final `(nonce, entry_digest)` sort re-normalises); removing the final sort's tiebreak alone passes (dedup already ordered them); doing BOTH fails three tests. `enforce_message_cap`'s digest tiebreak is a third mechanism and is redundant to both. The earlier inference -- "the tiebreaks survive their own mutation, so the property lives in the dedup sort" -- was invalid, since the dedup sort survives its own mutation too. Each comment now says it is one of two and that removing both is what breaks; two comments each truthfully saying "no test fails without me" would together authorise deleting both, which is the only real exposure here. |
| `harvest_common::mailbox` identity | The counterparty can delete a message you sent. | **FIXED on 2026-09-05, not a limitation any more.** Identity is `entry_digest` over the whole entry, computed by the contract, so there is no collision to resolve. Pinned by `a_message_cannot_be_retracted_by_submitting_another_under_its_nonce` and four neighbours, plus the contract's own `a_state_merge_keeps_a_message_whose_nonce_something_else_shares`. **What remains is narrower and is still a live gap:** a funded flood evicts it under the COUNT cap (`known_gap_a_funded_flood_still_evicts_every_honest_message`), so retraction is expensive and indiscriminate rather than impossible. It is NOT interruptible: `apply_delta` merges a whole delta, so the flood is one update. The byte-budget route was briefly recorded here as a cheaper path to the same result; it stopped being one when `enforce_message_cap` began skipping rather than stopping (`the_byte_route_no_longer_evicts_a_small_honest_message`). This row previously told a reader that deletion was an accepted live limitation of the shipped contract, which was true when written and false by the end of the same day. |
| `ui/src/messaging.rs::encrypt_message` | The mailbox nonce is FRESH per message, so an honest client never collides. | **Yes** -- and credited here only after review pointed out this file named the wrong test. Three tests die when `encrypt_message` derives the nonce deterministically instead of drawing it from `getrandom`: `each_conversation_carries_a_fresh_tag`, `a_mailbox_is_read_with_the_keys_on_hand_and_says_so_when_it_cannot_be`, and `state::conversation_tests::a_second_message_continues_the_same_conversation`. Verified by that mutation. This is the invariant that makes the row below a limitation rather than a defect. |
| `ui/src/messaging.rs` (AES-GCM) | A deliberate nonce collision reuses the keystream, and Harvest's AAD does not prevent it. | **Pinned as a LIMITATION, since 2026-09-05** -- `known_limit_a_nonce_collision_reuses_the_keystream` asserts `C1 xor C2 == P1 xor P2`, red under a mutation that separates the two nonces. **What it establishes, precisely:** the xor assertion is a property of AES-GCM and holds for any key, so it is not evidence about Harvest's crypto specifically; the first version of this test used a bare key and bare `aes_gcm` call and would have passed with all of Harvest's construction deleted. It now derives the key with `conversation_key_from_dh`, pads with `pad_to_bucket` and binds `message_aad` exactly as `encrypt_message` does, so a change to any of those reaches the test -- and it makes the non-obvious Harvest claim explicit: the mailbox nonce IS bound into the AAD, and that authenticates without randomising, so it does nothing about keystream reuse. This row asserted the pin for a day before the test existed, and was cited in the nonce-reuse analysis that led to the entry-digest change -- an argument resting in part on a test nobody had written. |
| `delegates/.../messaging.rs::make_room` | A conversation that exists only on this node is the last thing evicted. | **Yes** -- `a_conversation_that_exists_only_here_outlives_an_imported_one`, red when the ranking ignores `backed_up`. The reproduction is the reviewer's: a pasted backup fills the store, and the next conversation the buyer opens destroys one of their own. |
| same | An eviction is reported. | **Yes** -- `an_eviction_is_reported` and `storing_without_evicting_reports_no_eviction` (so the report is evidence rather than noise), plus `a_conversation_discarded_to_make_room_is_reported` and `discarding_a_backed_up_conversation_says_it_can_be_restored` on the consumer side, all red under mutation. |
| same, `decode_backup` | An oversized paste is refused before it is decoded. | **Yes** -- `a_backup_string_longer_than_the_cap_is_refused_without_decoding_it`, which also asserts the refusal is fast. Found by measurement, not by reading: base58 is quadratic, and a 253-conversation round trip took 72 seconds in a debug build with nothing bounding the length. |
| same, `import_buyer_conversations` | A record whose keys cannot be derived is refused rather than silently occupying a slot. | **Yes, since the review** -- `a_record_whose_keys_cannot_be_derived_is_refused_and_stores_nothing`. It was one of the two guards the sweep section did not cover. |
| same, `store_buyer_conversation` | Re-storing a held conversation evicts nothing. | **Yes, since the review.** The test existed and could not observe its own claim: it re-stored the OLDEST held conversation, which is also the eviction victim, so with the guard deleted the eviction cancelled itself out and the suite stayed green. It now re-stores the NEWEST -- the thread the buyer is actually writing into, which is what the UI re-sends -- and is red under that mutation. |
| same, `mark_conversations_backed_up` | A refused write is reported rather than counted as "not marked". | **Yes, since the review** -- `marking_reports_a_failure_when_the_node_refuses_the_write`. The response could not express a failure before, which made the UI's error path dead code. |
| `ui/src/state.rs::on_conversation_exported` | A backup is filed under the CONVERSATION that was ASKED about, and one nothing asked for is ignored. | **Yes, since the review** -- `a_backup_is_filed_under_the_conversation_that_was_asked_about` and `a_backup_nothing_asked_for_does_not_reach_the_screen`. Both the handler and the test were named for the STORE until export became per-conversation; this row kept the old names for a day, which is the citation drift the note at the end of this file is about. This file states the principle for `BuyerConversationList` and did not follow it here; a backup on screen under the wrong heading invites the buyer to save it as that store's. |
| `ui/src/state.rs::on_buyer_conversations` (sort) | The NEWEST recalled conversation is the one a new message continues. | **Yes, since the review** -- `a_new_message_continues_the_newest_of_several_recalled_conversations`, red with the sort deleted. The two existing tests could not see it: one had a single recalled conversation, the other had two but only asserted both were readable. |
| `ui/src/state.rs::on_conversations_imported` | An imported conversation may become the active thread, and its secret may be known to whoever supplied the string. | **No, and it is a residual rather than a claim.** The notification says so; nothing tests the wording, and nothing prevents it -- a backup the buyer was handed is indistinguishable from one they made. Recorded here rather than left in the commit message. |
| `delegates/.../messaging.rs` (backup format) | One backup string covers ONE conversation. | **Yes** -- `a_backup_carries_one_conversation`, which holds two conversations with one store and a third with another, and asserts the restore brings back exactly the one that was asked for. The granularity is the whole point of the change: a store-wide string is silently incomplete the moment the next conversation is opened. |
| same, `mark_conversation_backed_up` | Marking clears the warning on that conversation and no other. | **Yes** -- `marking_a_conversation_clears_its_warning_and_no_others` and, on the request side, `marking_names_only_the_conversation_that_was_saved`. This is the "cannot silence a warning about a key it has no backup of" property at the granularity level rather than the permission level. |
| same, `make_room` | An imported conversation is evicted before one opened here, even when both are backed up. | **Yes** -- `an_imported_conversation_is_evicted_before_one_opened_here`, red when the import tier is dropped from the ranking. This is the half `backed_up` alone does not cover: once the buyer has saved their own conversations, both sit in one tier and the order falls to `created_at`, which travels inside the backup string. `imported` is set by the delegate from which call arrived, so no string can claim it. |
| same, `decode_backup` | A v1 (store-wide) string is refused rather than read as something it is not. | **Yes** -- `a_paste_that_is_not_a_backup_is_refused_by_name` drives `harvest-conv-backup-v1:` alongside a ghostkey PEM and a v3 string. No v1 artefact was ever produced outside tests, so there is deliberately no v1-reading path. |
| same | An honest backup is far inside the length cap. | **Yes** -- `an_honest_backup_is_far_inside_the_length_cap`, which asserts four times the real size still fits. Worth pinning because the cap was tightened from 64 KiB to 4 KiB when the format went from a store's worth to one conversation, and a cap that refused real backups would be worse than no cap. |
| `ui/src/state.rs::on_conversation_exported` | A backup is filed under the conversation that was ASKED about. | **Yes** -- `a_backup_is_filed_under_the_conversation_that_was_asked_about` and `an_exported_backup_reaches_the_screen_under_its_own_conversation`, both red when the answer's own tag is trusted. Stronger than the store-level version it replaces: one string covers one conversation, so showing it under the wrong one invites the buyer to save it as that conversation's. |
| `ui/src/components/message_view.rs::ConversationBackupControl` | Everything the backup panel says, and that "I have saved this" is a separate action from revealing the string. | **No.** Still no component tests. The state transitions behind both buttons are tested and the delegate refuses to be told a backup exists by anything but the Harvest app -- but nothing checks that the UI actually makes the buyer press the second button, which is the whole basis of the marker meaning anything. This is the most load-bearing untested claim added by the backup work. |
| `ui/src/state.rs::send_to_harvest_delegate` | Any of these requests actually reach the delegate. | **No.** The same wasm-gated `spawn_local` gap as `ask_for_conversation_keys`, which this now shares one implementation with. Every decision is host-tested; the send is not. |

### The guard sweep, 2026-09-05 — **scope: the messaging change only**

**This section covers the guards in `683feb0` and its neighbours, NOT the
buyer-conversation persistence or backup work in the tables above and below.**
It was written before either existed and sits after them by accident of
ordering, which a reviewer read — correctly — as a claim of completeness it
does not have. Two guards added by the persistence work were found unpinned by
exactly that misreading (the re-store guard and import's low-order refusal);
both are now pinned, and their rows say so.

Every guard the messaging change touched or added was deleted, one at a time,
and the suite re-run. A guard whose removal leaves the suite green is one a future
refactor removes silently, and this branch had already produced two of them
(the routing-tag filter, and a `ContractKey` comparison that ignored the code
hash because `PartialEq` does).

**Pinned (16):** the mailbox's oversize refusal, byte budget, `verify`
over-count guard and `verify` duplicate-nonce guard; `ListingsV1`'s delta
dedup and `reputation`'s intra-delta dedup; the buyer's `conversation_id`
check, low-order refusal and compose-time size check; the delegate's low-order
refusal; `compose_reply`'s ownership check; `conversation_keys_to_request`'s
ownership gate and in-flight dedup; `EncryptionKeyReady`'s length check; and
the two `mailbox_ops` key derivations.

**Unpinned (2):** both `OrdersV1::verify` guards, which entry 3 below already
named. The sweep did not find anything entry 3 had missed, which is the useful
result -- it says the document was accurate rather than optimistic.

**Newly pinned during the sweep (1):** the routing-tag filter, which no
assertion about output could catch, because correctness genuinely does not
depend on it. It is pinned by measuring the work instead
(`reading_a_thread_costs_the_thread_and_not_the_mailbox`): removing it takes a
buyer's read from 3 decryption attempts to 1023.

Three things follow that are worth saying plainly rather than leaving as a
pattern in the table. First, **every read path is fully host-tested and every
write path is not**, because a write ends at a node and a read ends in a pure
function. Second, **the component is the least-covered file in the change and
is the one that makes claims to users**, which is the exact shape of the
defect that produced this document. Third, **the sharpest limitation was not
in this table at all**, because it was not a claim that could become false: a
buyer's conversation keys died with the browser tab, so a reply arriving after
a reload was unreadable by anyone forever.

That third one was closed later the same day -- the delegate now keeps the
buyer's per-conversation secret, and the rows added below cover it. What
replaces it is narrower and is stated wherever it matters: the secret is in
ONE node's delegate, so a buyer who changes device still loses the
conversation, and the keyed record is a durable local note of which stores this
node contacted (removable, and the removal is a real deletion). See
`docs/buyer-conversation-persistence.md`.

---

### The buy flow (added on `feat/buy-flow`, 2026-09-05)

Recorded while the code was written, for the same reason the section above
was. Two of these are design gaps rather than test gaps, and they are here
because a reader of the code would otherwise take the comments around them as
covering more than they do.

| Where | Claim | Caught? |
|---|---|---|
| `ui/src/state.rs::AppState::payment_blockers` | A buyer will not pay a commitment that is unpublished, not the seller's, not theirs, for a listing they never asked about, not awaiting payment, unanchored, off-chain, stale, unbridgeable, or paying an address that is not its own script. | **Yes** -- `buy_flow_tests`, one test per blocker, each mutated red by deleting the guard it names. **This list was shorter, and the missing entries were the two HIGH findings below plus the bridge and destination checks that were card footnotes rather than blockers.** The mutations were run and the failures recorded: dropping the kept-conversation check, the staleness check, the canonicality check, the direction filter, the signature check and the listing check each turned exactly the intended test red. |
| same, `ConversationNotKept` | The buyer does not part with money before their node has confirmed it is keeping the key that reads the conversation. | **Yes** -- `a_buyer_does_not_pay_before_the_node_confirms_it_kept_the_conversation`, and the other half, `only_the_delegates_answer_marks_a_conversation_kept`, which drives a refusal and then a success through `on_delegate_response`. This is the Phase 2 ordering constraint from `buyer-conversation-persistence.md` applied to the thing that exists today; the confession does not exist, so nothing here holds a confession. |
| `ui/src/state.rs::PaymentBlocker` | Adding the Phase 2 blocker is one variant and one check, and no screen can quietly ignore it. | **Yes, structurally.** `components::buy_view::is_temporary` matches the enum without a wildcard, so a new variant does not compile until somebody has said whether it means "wait" or "walk away" -- which is the sentence the buyer is shown. This fired for real while the change was being written: adding `CommitmentNotRequested` failed the build until that question was answered. |
| `harvest_common::payment::Order::anchor` | `skip_serializing_if` keeps every pre-existing order signature verifying. | **Yes** -- `order_wire_compat_tests::an_order_that_predates_the_anchor_re_encodes_unchanged`, observed red against the naive `#[serde(default)]`-only form: `0xae` map(14) with `"anchor": null` against the `0xad` map(13) the signature was taken over. Same trap, and the same fix, as `StoreInfoV1::encryption_public_key`. |
| `ui/src/state.rs::order_for_invoice` | A seller who cannot see the chain publishes no commitment at all. | **Yes** -- `a_seller_who_cannot_see_the_chain_cannot_issue_an_invoice`, mutated red by falling back to `anchor: None`. Without it the seller would show a bill that every buyer's software silently refuses, which is the shape of the bridge-less invoices that made every early store permanently unable to take money. |
| `ui/src/state.rs::AppState::acceptance_for` | The buyer can read the acceptance and it names the published commitment. | **Yes** -- `accepting_a_request_tells_the_buyer_which_commitment_is_theirs`, read back through the BUYER's conversation keys rather than by inspecting what the seller composed. |
| `ui/src/state.rs::AppState::announce_acceptance` | The acceptance actually reaches the seller's mailbox. | **No.** The dispatch is a wasm-gated `spawn_local`, the same blind spot as every other send in this repository. What is tested is everything either side: that the message is composed and recorded as the seller's own (`accepting_records_the_acceptance_as_the_sellers_own_message`), and that a buyer who receives one reads it correctly. |
| same | The commitment is published before the buyer is told about it. | **No, and deliberately not attempted.** The two are independent fire-and-forget dispatches and may land in either order. The buy flow does not depend on the order: a buyer holding an acceptance for a commitment that has not arrived reads `CommitmentNotPublished` and does not pay, which is the same answer a seller who never published would produce. |
| `ui/src/state.rs::PaymentBlocker::CommitmentNotRequested` | The order is for something this conversation asked about. Since harvest#57 the published order carries a listing TAG keyed by the conversation (`harvest_common::mailbox::listing_tag`), which the buyer recomputes for each listing they asked for; an untagged order for a conversation that asked is refused. | **Yes for the case it closes** -- `a_commitment_for_a_listing_never_requested_is_refused` and its converse, `an_untagged_order_for_a_conversation_that_asked_is_refused`, and `a_listing_tag_from_another_conversation_is_refused`. **The claim is narrower than it looks**, and the doc comment says so rather than overstating it: the request it compares against sits in the buyer's own thread, and direction is not authorship (`messaging::Addressing`), so a seller can insert a request the buyer never sent. What the check closes is the seller answering a cheap listing's request with a commitment against an expensive one; what it does not close is a forged request, which shows up instead as a line in the buyer's own thread they do not recognise. |
| `ui/src/components/buy_view.rs` | Everything the buy form, the purchases panel and the accept control say on screen. | **No.** There are no component tests in this repository at all -- the same row as `message_view` above, and worth repeating here because this is the screen that tells a buyer an order is safe to pay. The *decisions* behind the words are all in `AppState` and tested; the words are not. |

#### What the review round changed, and what it left open

Two HIGH findings, both single-seller attacks reachable through the ordinary
UI, both defeating properties this section previously claimed. They are
recorded here rather than only in the commit log because the first one falsifies
a sentence this document used to carry.

| Where | Claim | Caught? |
|---|---|---|
| `harvest_common::mailbox::order_binding_from_secret` | Two buyers never share a binding, and the seller cannot compute one. | **Yes** -- a known-answer test against `b3sum --derive-key`, plus `two_conversations_do_not_share_a_binding` and the delegate's `recall_answers_the_binding_the_shared_derivation_gives`, which also asserts the binding is NOT the one the shared secret would give. That second assertion is the load-bearing one: deriving from the DH shared secret would look identical and would hand the seller the ability to compute any buyer's binding. |
| `ui/src/state.rs::AppState::payment_blockers` (`CommitmentNotForThisBuyer`) | One published commitment is payable by exactly one buyer. | **Yes** -- `one_commitment_is_payable_by_exactly_one_buyer` drives two independent `AppState`s with separate ephemeral secrets at one commitment. Mutation-verified twice: deleting the check, and -- the one that matters -- changing it to compare against the binding in the mailbox request instead of the locally-derived one, which is the wrong version a reasonable person would write. |
| same | The binding this browser computes is the same value the delegate answers on recall. | **Yes, in two halves, and it cannot be one test.** They are different crates on different machines, so each side is pinned to the shared derivation (`the_browsers_binding_is_the_shared_derivation` in the UI, `recall_answers_the_binding_the_shared_derivation_gives` in the delegate) and the derivation itself has the known-answer test. A drift on either side turns one of the three red. The failure it prevents is silent: a returning buyer would simply find their own commitment unrecognisable and could never pay it. |
| `harvest_common::payment::OrderId::from_terms` | Two differently-termed orders cannot share an id, so a seller cannot swap the payment address under one after the buyer has seen it. | **Yes** -- `two_differently_termed_orders_cannot_share_an_id` and `an_id_determines_the_terms_it_was_derived_from`, both mutated red by restoring the old four-field preimage. `a_record_whose_id_is_not_its_terms_is_rejected` covers the enforcement half and is mutated red by dropping the check from `verify_terms`. |
| `harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS` | The freshness tolerance fits inside the tip contract's retained window. | **Yes, as a BUILD failure** -- a `const _: () = assert!(...)` against `freenet_bitcoin_common::TIP_RETAIN`, verified by raising the constant to 96 and watching the build fail. A test would have been the wrong instrument: the two constants live in different crates and the failure is silent, since an anchor inside the tolerance but outside the retained window reads as unverifiable and refuses payment for a reason nobody can act on. |
| `ui/src/state.rs::AppState::needs_reissue` | A seller learns when one of their own orders has aged out. | **Yes** -- `a_seller_is_told_which_of_their_orders_need_reissuing` covers fresh, expired, never-anchored and settled, and `a_seller_with_no_chain_view_is_told_to_reissue_nothing` covers the no-clock case. The screen that renders it is not tested; see the component row above. |
| `ui/src/components/buy_view.rs::remedy` | Every blocker is classified as wait, ask-the-seller, or walk-away. | **Yes, structurally** -- wildcard-free match, so a new blocker does not compile until classified. The specific case review found is pinned by `an_expired_order_sends_the_buyer_back_to_the_seller`, which asserts both the classification and that the sentence no longer accuses the seller of backdating. |
| `ui/src/state.rs::payment_blocker_wording_tests::every_blocker` | Every variant has a sentence. | **Yes, since the review round.** It was NOT before, and the way it failed is worth keeping: the test held a hand-written `vec!` with an exhaustive `match` NEXT TO it, and its own comment claimed that made a missing variant a compile error. The match forced only itself; a variant could be added to it and omitted from the list, and the test would silently stop covering it. It now matches over each element of the list, so the list is the only way to reach the match, plus a count assertion. Verified by removing one variant from the list. |

**And one the sweep for the same shape found elsewhere.**

The review asked whether any other id in this flow had the order id's shape.
One did. `ListingId` hashed `(seller_fingerprint, created_at_ms, title)` --
not the price, the description or the kind -- so a seller could sign two
listings with one id at different prices.

The symptom is different and arguably worse than the order case.
`ListingsV1::apply_delta` is first-writer-wins: a listing whose id is already
held is SKIPPED. So nothing is displaced; instead a peer that saw the cheap
copy first keeps it and thereafter excludes that id from every delta it sends
and every delta it asks for, a peer that saw the dear copy keeps that, and
**neither can ever tell the other**, because each one's summary already names
the id. Two readers see two prices for one listing, permanently. Fixed the
same way and pinned by `listing::listing_identity_tests`, including a merge in
both orders through the real `apply_delta`.

Fixing it exposed a second thing, in a test rather than in the code:
`migrate::tests::store_with` assigned an arbitrary `Vec` to
`ListingsV1::listings`, building a state no peer could hold, since the only
order a merged state is ever in is sorted by id. It passed while the fixture's
hand-chosen ids happened to ascend with its own argument order, and the
commutativity check went red the moment derived ids reordered them. The
fixture now sorts. **The underlying gap was left open here**: `ListingsV1::verify`
did not require sortedness, so a peer that deserialized an unsorted state
from the network would merge to different bytes than one that reached the same
set through deltas. Pre-existing, not touched by this branch, recorded here
because this is where it was found. Closed by harvest#26; see the section on
that change below.

**And the tell the buy flow had none of.**

Review named it beside H1 and it is the half that makes the rule checkable by
a person: nothing registered a payment watch for a purchase, so a card read
"Awaiting payment" however much had already arrived at the address. So it was
not only that N buyers could pay one commitment -- none of them could see that
anyone else had.

| Where | Claim | Caught? |
|---|---|---|
| `harvest_common::payment::Order::bitcoin_address_instance_id` | The address contract an order names is derived from the code hash and the payment parameters the seller signed. | **Yes** -- `payment::address_instance_tests`, including that the id changes with the build AND with the script, and that it is `BLAKE3(code_hash \|\| cbor(parameters))` asserted against the components rather than against a copy of the code. It replaces a hand-written second copy in the store contract: a duplicated contract-address derivation is the shape ranked first in this document, where the copies drifted and every derived id named a contract that had never been published. |
| `ui/src/components/bitcoin_view::live_address_for_order` | A buyer sees the state of the address they are about to pay, holding no watch. | **Yes** -- `live_address_tests`, mutated red by removing the derived-id lookup. The same change also fixed an identity mismatch: the old lookup matched a watch on `(network, script_pubkey)` and then trusted the `contract_id` STRING the watch carried, so where the two disagreed a buyer was shown some other address's balance under this order. Pinned by `a_watch_pointing_elsewhere_does_not_override_the_orders_own_terms`, and the watch fallback is pinned as still working for an order that names no build. |
| `ui/src/state.rs::AppState::address_contracts_to_watch` | Only orders this node is party to are subscribed. | **Yes** -- `somebody_elses_order_is_not_watched`, mutated red by watching every order in the store. A store contract carries every order it ever issued, so subscribing to all of them would advertise this node's interest in every one of a busy seller's payment addresses -- the private-watch-list-as-public-record shape `harvest_common::bitcoin_delegate` refuses to build. |
| same, dispatch | The subscription actually happens. | **No.** `watch_purchase_addresses` ends in a wasm-gated `spawn_local`, like every other send here. What is tested is which ids it asks for. |
| `ui/src/state.rs::AppState::due_address_rereads` | An order still awaiting payment keeps asking for its payment address, so a node that served a stale copy and later healed is noticed. | **Yes** -- `an_unsettled_order_asks_for_its_payment_address_again` and four siblings, mutated red by deleting the unsettled/payable filter, the spacing, the registration, and the send loop. `a_re_read_answer_is_routed_and_settles_the_order` drives real `BitcoinAddressStateV1` bytes through `on_contract_state`, so the routing is tested and not just the map entry. |
| `ui/src/state.rs::AppState::due_tip_rereads` | While some order is unsettled, the network's chain-tip contract keeps being asked for, so a node serving a stale tip is noticed; and nothing else is asked for -- not a network with no unsettled order, not a retired generation, and not a tab that is only browsing. | **Yes** (harvest#74) -- `an_unsettled_order_asks_for_the_chain_tip_again`, `only_a_live_tip_for_a_network_with_an_unsettled_order_is_asked_about` and `a_settled_order_stops_the_tip_being_asked_about`, mutated red by deleting the unsettled-network bound, the retired-generation exclusion, and the record-the-ask. Why it matters as much as the address row above: `settled_orders` returns NOTHING without a `signed_tip`, and `assemble_on_chain_proof` measures depth against it, so a stale tip REFUSES a payment that is deep enough -- #67's exact symptom with the address contract perfectly fresh. The bound is the address re-read's own `wanted` list rather than a second copy of the rule, so an order settling silences both. **What is untested:** the tick that calls it (`gateway::bitcoin_generation_ops`) is wasm-gated, the same gap the address row carries; the spacing itself is `address_reread`'s and is tested there. |
| `ui/src/state.rs::AppState::on_contract_state` (tip arm) | A fresher chain tip publishes the settlement it unblocks, rather than waiting for some later unrelated arrival. | **Yes** (harvest#74, external review P2) -- `a_fresher_tip_settles_the_order_it_unblocks`, mutated red by dropping the publish. Driven through `on_contract_state` with real CBOR rather than by calling `apply_tip_state`, because the defect was in the ARM and not in the fold: a test calling the fold directly would have passed against the broken code. Without it the re-read is very nearly inert -- `assemble_on_chain_proof` measures depth against the tip, so claims can be in hand for an hour with only a newer tip missing, and the only other publisher was the address arm. |
| `ui/src/state.rs::AppState::apply_tip_state` | A chain-tip state that is BEHIND the one already held never moves the view backwards. | **Yes** (harvest#74, external review P2) -- `a_chain_tip_that_is_behind_does_not_move_the_view_backwards`, mutated red, asserting through both the fold and the real arrival path. Introduced by #74's own mechanism: this view was fed only by the subscription stream before the periodic GETs, so replacing it outright was safe enough; a delayed GET answer can now land after a newer update, and a regressed tip refuses a payment that is deep enough -- the exact symptom #74 removes. **Stated residual:** a genuine reorg lowers the real tip, and this then holds a signed tip the bridge has moved past until the chain grows beyond it. `PaymentReversed` is what handles a reorg and has no producer anywhere yet, so this trades an unhandled case for a live one rather than the reverse. |
| same, the timer | Anything asks at all. | **No.** The `ADDRESS_REREAD` interval in `ui/src/gateway/bitcoin_generation_ops.rs` is one registration in a file that is type-checked and never executed, so deleting the whole block leaves the suite green -- measured, not assumed. Everything it calls is tested; that it is called is not. The tick rate is pinned against `address_reread::FIRST_RETRY_MS` by a `const` assertion, so at least the constant cannot silently drift out from under the spacing. |
| `ui/src/state.rs::AppState::settlement_publish_failed` | A settlement update that did not reach the node is published again rather than abandoned for the session, and the seller is told once rather than once per retry. | **Yes** -- `a_settlement_that_failed_to_send_is_published_again`, mutated red. **The gap this used to record is CLOSED (harvest#75):** publishing was attempted only from a tab that owns the store, because `store_ops::owned_store_key` resolved the contract key from `my_stores`, so a buyer's attempt had never once succeeded and a paid order reached `Paid` on the network only when the seller opened the app. The key is now rebuilt from the store contract id (`store_ops::reconstruct_store_key`), which needs no registration, and the owner comes from the store's loaded state (`settlement_owner_key`) -- pinned by `a_buyers_tab_publishes_the_settlement` and `a_settlement_names_the_owner_the_stores_own_state_names`, both mutated red. **What is still untested:** `settlement_store_key` and `submit_settled_order_by_id` are wasm-gated, so the key a buyer's send actually carries is not exercised off-target; what IS tested is that the reconstruction agrees with `store_contract_key`'s own reconstructed answer in instance AND code hash (`a_store_can_be_addressed_without_owning_it`). |
| `ui/src/state.rs::AppState::apply_address_state` | A copy of an address contract that is behind the one already held cannot take anything away: claims are FOLDED into what is held, not substituted for it. | **Yes** -- `a_stale_answer_cannot_erase_what_is_known` (a copy missing a retraction cannot un-retract) and `a_copy_missing_a_payment_does_not_erase_it` (a copy missing a payment cannot drop one, at the same watermark, which is the case no ordering could have caught), both mutated red by folding back to a wholesale replace. Claims are signed and additive, and `from_claims` re-verifies each against the contract's parameters, so the fold cannot admit anything the bridge did not sign. An earlier version of this row claimed a watermark comparison made a wrong settlement impossible; it did not, and the comparison is gone. |

This narrows, but does not close, the "nothing takes over after payment" gap
recorded below: the buyer can now SEE a payment arrive at the order's address,
because the address contract is subscribed and the card reads its state.
Nothing still constructs an `OrderPaymentProof`, so the published order never
advances to `Paid`.

#### The id widening, and what it costs at the migration boundary

`OrderId` and `ListingId` are 32 bytes as of the third round, widened at the
team lead's direction while the wire was open. The argument is that this branch
re-keys every contract, so every published record is already crossing a
migration boundary: the change is free exactly once and costs a re-key plus a
migration of its own afterwards. The threat it closes is specific -- the swap
attack needs a COLLISION between two orders the seller chooses rather than a
second preimage, so 16 bytes cost ~2^64 rather than 2^128, which is expensive
rather than impossible against a payoff of a stolen payment behind a public
record that says unpaid.

| Where | Claim | Caught? |
|---|---|---|
| `OrderId::from_terms` / `ListingId::from_terms` | The id is the whole digest, not a prefix. | **Yes** -- `the_id_is_the_whole_digest` in both modules, mutated red by restoring the 16-byte truncation zero-extended into the wider type. Worth having as its own test: under that mutation every OTHER identity test still passed, because the ids stayed distinct, deterministic and enforced -- only the collision cost changed, and nothing else could see it. |
| `Order` wire shape | An order published at the old id width does not decode. | **Yes, deliberately** -- `an_order_from_before_the_id_was_widened_does_not_decode`, asserting on the `invalid length 16` the decoder gives. That is the honest statement of what the re-key costs, pinned rather than described. Orders expire after `MAX_ANCHOR_AGE_BLOCKS`, so one old enough to be in a predecessor generation is one nobody could pay anyway. |
| same | An order carrying neither optional field re-encodes to the bytes its signature covered. | **Yes** -- `an_order_without_the_optional_fields_re_encodes_unchanged`, a hand-written literal at the current width. It replaces the pre-anchor fixture, which can no longer decode; the property it protects (a future optional field must not change an old signature's preimage) is unchanged. |

#### KNOWN GAP, and it needs a decision rather than a fix

**A predecessor generation's store is discarded in full, and the seller is
told only in a console log.** Pinned by
`migrate::predecessor_generation_tests::known_gap_a_predecessor_generations_store_is_discarded_in_full`.

Making a listing's id a function of its terms is right, and it is what stops
two differently-priced listings sharing an id and diverging permanently. It
also means every listing published under a previous generation carries an id
`AuthorizedListing::verify` now refuses. `ListingsV1::apply_delta` returns on
the first refusal, so `fold_or_keep_primary` keeps the newer generation and
drops the predecessor **entirely** -- the listings, the orders, and the
store's own info with them. A seller upgrading loses their shop.

Three things make it worse than the loss:

* it is reported by `probe_warn`, a browser console line, not something a user
  sees;
* the fold's own message says the migration then **seals**, so the generation
  is never looked at again;
* every other test in this repository builds its fixtures with the NEW
  derivation, so not one of them could see it. It passed all four gates.

**The requirement this produced lives in
[`docs/design/migratability.md`](design/migratability.md).** A new contract
version must be migratable from every version that has ever held user data;
that document carries the argument, the unbuilt re-issue path, and why
accepting the old format in `verify` is wrong. What follows is what this
branch actually did.

**RESOLVED 2026-09-06, by decision rather than by repair.** Ian's answer: no
published store holds data worth preserving, sellers republish. So the loss
stands, and what changed is that it is now a decision the affected person is
TOLD about:

* `migrate::describe_lost_store` names the store, its details, and how many
  listings and orders went with it, and says to publish them again --
  "migration incomplete" is not something a seller can act on.
* It reaches `AppState::notifications` rather than a console line, drained in
  `migrate_ops::finish` **before** the nothing-was-recovered early return.
  That ordering is the whole of it: draining after that return would mean the
  one message that matters is the one never sent.
* Pinned by `migrate::uncarried_tests`, including that a fold which carries
  everything reports nothing -- a notification on every successful migration
  is one a seller learns to dismiss, which costs exactly the case it exists
  for.

**And the structural half, which is worth more than the rest.** The reason
neither the author nor the review saw this is that **every fixture in this
repository builds its records with the CURRENT derivation**, so none of them
could hold what a predecessor generation produced. The fix is a known-answer
test on each derivation --
`listing::listing_identity_tests::the_listing_id_derivation_is_pinned` and its
order counterpart -- whose doc comments carry the consequence and say to read
the migration tests before changing the constant.

A first attempt at this pin did not work and the failure is worth recording:
it built a record with a hard-coded foreign id, which is refused whatever the
derivation is, so simulating a future derivation change (`v2` to `v3`) failed
**zero** tests. What fires is a fixture that depends on the derivation's
actual output. Verified by making that change and watching the KAT go red,
and again by adding a field to the order id's preimage.

**The original difficulty, for a reader who reaches this by a different
route:**
The id is inside what the seller signed, so the fold cannot re-stamp a record
without invalidating its signature. Accepting the old form in `verify` works
mechanically -- the seller's fingerprint is derivable from the verifying key
`verify` already holds -- but reopens exactly the hole the change closed, since
a seller could still mint two listings under one old-form id. So the options
are to accept the loss loudly, or not to make the change, and both are
decisions about whether any published store holds listings worth preserving.

The asymmetry worth carrying into that decision: an ORDER expiring is fine,
because orders expire anyway. A LISTING is a seller's shop and does not.

**One thing the round did not close, and one it did.**

**`OrderId` was 16 bytes, and that is CLOSED.** It is recorded here because
this section is where a reader looks for open gaps and this one was left
listed as open after it had been fixed -- which costs the same as overstating
a gap, since a reader cannot tell which sentence is current.

Deriving the id from the terms means an attacker needs two orders that hash to
one id. Second-preimage against an id a buyer already holds is 2^128 and out
of reach, but the swap attack needs only a COLLISION between two orders the
SELLER chooses, which at 16 bytes was ~2^64. Both ids are now 32 bytes, so it
is 2^128 either way. See "The id widening, and what it costs at the migration
boundary" above, and `docs/design/migratability.md` for what the widening cost
at the re-key.

**One binding per conversation, not per order.** Two orders a buyer places in
one thread carry the same binding, so the binding does not distinguish them
from each other -- their distinct ids and the buyer's own request list do. It
distinguishes BUYERS, which is the hole. A consequence on the seller's side:
`unanswered_requests` treats a request as answered when a published order
carries its binding AND its listing tag (the tag replaces the listing id,
harvest#57, and only this conversation's keys compute it), so a buyer who asks
twice for the same listing in one conversation sees the second ask read as
already answered. Per
order it would need a durable per-order counter in the delegate, which Phase 2
can add if filing turns out to need it.

#### Two design gaps this change does NOT close

Neither is a missing test. Both are Phase 2 work recorded in issue 8, and both
are named here because the surrounding comments would otherwise read as
covering them.

**The commitment is not private.** `docs/design/incentive-mechanism.md` Part 5
step 2 says an order commitment reveals "a scrambled order number, the amount,
and a recent Bitcoin block hash" and "nothing about who Bob is or what he
bought". What is actually published is an `AuthorizedOrder`, which carries the payment
address and its `scriptPubKey`, so the address links the order to a chain
transaction. It no longer carries the `listing_id` (harvest#57). It carries a
listing TAG keyed by the conversation, which only the buyer and seller can
compute, so a reader of the store cannot test a listing against it. **What can
still be inferred, or is lost:**

- The amount is public, and amount is price times quantity, so an order whose
  amount is a multiple of a uniquely priced listing (a BTC price exactly, a
  fiat price approximately at the anchor's exchange rate) still reveals the
  listing. Only bucketed amounts or the ledger contract below would close that.
- Orders from one conversation share a binding, and two of them with equal
  tags were for the same listing, so a repeat buyer's pattern (same item again
  or something else) is visible, though not which item.
- Which listing an order was for is now checkable by its two parties only. It
  used to be a public, signed claim. Either party can still show it to a third
  party by revealing the conversation's tag key
  (`harvest_common::mailbox::listing_tag_key`), which decrypts nothing.
- What to ship is read from the buyer's request, which lives in the mailbox. A
  seller whose copy of that request is lost or evicted still sees the order is
  answered, but has only the tag, testable against their listings with the
  conversation keys, to recover which listing it was. An unprompted invoice
  (no request) records no listing at all.
- The buyer's `CommitmentNotRequested` check compares against the requests in
  their own thread; if those have been evicted (a funded flood, see the mailbox
  gaps) the check has nothing to compare and does not fire.

Who bought is not published -- `buyer_fingerprint` is empty for every order
the buy flow produces, and the buyer has no identity to name -- and the
shipping address never leaves the AEAD. The commitment now also carries
`order_binding`, which cannot be linked to a person: it is a hash of a value
only the buyer holds (see `harvest_common::mailbox::order_binding_from_secret`).
It does link orders to each other, though: every order from one conversation
carries the same binding, so a reader can group one pseudonymous buyer's
purchases from that conversation. But the design's claim about the whole
commitment is stronger than the code, and the difference is real.

Two further seller-chosen fields are published per order and are not on the
design's list either: `required_confirmations` and `trusted_bridges`. They
make the bridge set a per-order fingerprint of the seller's configuration.
Minor, but the accept panel's enumeration is written to be exact and this is
the honest full list.

It is not fixable here: the payment address must be public, because a stranger
being able to verify the payment is the entire point of the on-chain rail.
Closing it means separating the countable commitment from the payable invoice,
which is what issue 8's per-seller ledger contract does.

**The commitment is per-store, not per-identity.** Issue 8, point 3: one
ghostkey may create unlimited stores, so a buyer counting a seller's
outstanding orders from one store's state sees a fraction of what the bond
would back. The exposure cap that makes the whole mechanism work is therefore
not yet countable, and nothing in this change counts it -- the buy flow checks
that the buyer's OWN commitment is published, which is the half that forces
the seller to publish at all, and stops there. There is no bond to count
against yet, which is why this is Phase 2 rather than a defect.

#### The payment proof: what now takes over after payment, and what still does not

The gap this document recorded twice -- "nothing takes over after payment" --
is closed for the transition itself. `harvest_common::payment::
assemble_on_chain_proof` builds the proof out of the claims a node holds and
the tip it can see, and `AppState::settled_orders` publishes the `Paid`
record.

| Where | Claim | Caught? |
|---|---|---|
| `assemble_on_chain_proof` | A confirmed payment assembles into a proof the verifier accepts. | **Yes** -- `proof_assembly_tests`, built on GENUINE bridge-signed claims and SPV proofs (`freenet_bitcoin_common::spv::testing`, added to `harvest-ui`'s dev-dependencies for the same reason `harvest-common` takes it). Not stubs: the thing being tested is whether real evidence verifies. |
| same | It verifies before returning, so a caller cannot publish a proof the network refuses. | **Yes** -- `the_assembler_declines_what_would_not_verify`, mutated red by deleting the `verify_payment_proof` call. Also caught on the state side by `an_unpaid_order_is_not_settled`, but only after that test was fixed: see below. |
| same | A claim about another address is left out, and more claims than a proof may carry is refused rather than truncated. | **Yes** -- two tests. The refusal matters more than it looks: silently dropping the excess would be curating which of a bridge's claims the network sees, which `OnChainPaymentProof` documents as undetectable downstream, and doing it in the buyer's favour. |
| `AppState::settled_orders` | An order already past `AwaitingPayment` is not settled again. | **Yes** -- mutated red by deleting the status guard. |
| `AppState::publish_settled_orders` | A settlement is dispatched once per tab, not once per notification. | **Yes, after a correction.** See below. |
| same, dispatch | The update reaches the contract. | **No.** Wasm-gated `spawn_local`, like every send here. What is tested is which records it would publish. |
| the ordering constraint from `buyer-conversation-persistence.md` | Settling does not stop the node keeping the conversation. | **Yes** -- `settling_leaves_the_conversation_record_alone`, which checks the conversation is still held and still marked kept after the order goes `Paid`. Payment is exactly the moment a buyer's software might conclude the transaction is over; in Phase 2 the confession lives in that record and must be persisted BEFORE payment, so treating payment as a reason to stop caring about it inverts the argument. |

**Two of these tests initially reported success while measuring nothing, and
both were found by mutation rather than by reading.** Recorded because the
second is the exact shape this document exists for.

* `an_unpaid_order_is_not_settled` passed a claim set that was EMPTY, so it
  took the assembler's early "nothing seen" refusal and never reached the
  verify. Deleting `verify_payment_proof` from the assembler left it green. It
  now also drives a genuine, verifying, correctly-scripted claim that is one
  satoshi short -- evidence that exists and does not carry the transition.
* `a_settlement_is_published_once_per_tab` asserted on the length of the
  in-flight `settlements_submitted` SET. A set insert is idempotent, so the
  length was one whether the guard skipped the second send or not; deleting
  the guard left it green. `publish_settled_orders` now returns what it
  actually dispatched, and the test counts that. **The dispatch being
  wasm-gated is what made the wrong thing the only observable thing** -- which
  is the general trap, not a detail of this test.

**What still does not happen.** Nothing constructs a `PaymentReversed`
transition, so a reorg that undoes a settled payment leaves the order reading
`Paid`. The evidence rule for it is stricter than for `Paid` -- a reversal has
to show confirmations that were themselves retracted -- and the claims to do
it arrive by the same subscription, so the shape is available; it is simply
not built. `Paid` is the transition the buy flow needs and the one that was
missing.

#### And one thing the buy flow does not do at all

**It does not send money.** Step 5 of the design is a person opening a wallet.
Harvest shows the address and the amount once the checks pass, watches the
address, and publishes the settled order once the payment verifies -- but the
paying itself is a person and a wallet, and nothing here moves coin.

An earlier version of this paragraph said "nothing takes over once it is
sent", which was true when written and is no longer. What was missing then,
and is recorded above now:

An earlier version of this paragraph said "the existing on-chain verification
path takes over from there", which review showed was false in both halves, in
a document whose whole purpose is not claiming more than the code does:

* **No watch is registered.** *(Closed.)* `live_address_for_order` resolved only through
  `bitcoin.watches`, and the only thing that creates one is the manual "Watch
  address" form. So `live` was `None` for every purchase and the card read
  "Awaiting payment" however much had arrived. **Closed** -- the lookup now
  derives the address contract from the order's own signed terms and the buy
  flow subscribes to it; see the round-2 section above.
* **Nothing constructs an `OrderPaymentProof`.** *(Closed.)* Every
  `payment_proof` site in `ui/` was `None`, so a published order never
  advanced to `Paid` and `NotAwaitingPayment` never fired for a real
  settlement. `assemble_on_chain_proof` and `settled_orders` are what changed
  it; `PaymentReversed` is still unbuilt.

The verification machinery exists and is tested (`verify_payment_proof`, the
bridge claims, the fold); what does not exist is anything in the buy flow that
drives it. That is the honest boundary of this change.

### Address reuse and the payment window (harvest#77, 2026-09-18)

A fresh install restarted the delegate's derivation counter at 0, re-issued an
address that already held a confirmed payment, and the new invoice settled
itself. Three mechanisms and a local backstop were added, revised over two PR #83 review rounds, and
this is what each one does and does not have behind it.

| Where | Claim | Caught? |
|---|---|---|
| `harvest_common::payment::verify_on_chain_proof` with `Order::payment_window` | A payment settles an order only if the fold's WINNING confirmation of its outpoint is strictly after the order's anchor and at most `PAYMENT_WINDOW_BLOCKS` after it; anything outside neither settles the order nor, through a later retraction, reverses it. Enforced by the store contract because `AuthorizedOrder::verify` calls it. | **Yes** -- `store::order_tests` (the reported case also through `OrdersV1::verify`, both window edges, old payment not topping up a new one, winning-vs-stale confirmation in both directions, retracted old payment cannot reverse, a new order's payment not settling an older order anchored a window earlier, anchorless order), the contract-level `refuses_an_order_settled_by_a_payment_older_than_the_order` (through `validate_state`) and the UI-level `a_payment_older_than_the_order_does_not_settle_it`. Mutations run, each red: no upper edge (two tests); upper edge off by one; lower edge admitting the anchor block; restoring the every-confirmation rule (`a_payment_is_judged_by_its_winning_confirmation`); counting out-of-window confirmations as ever-covered (`a_retracted_pre_order_payment_cannot_reverse_a_new_order`); missing anchor as height 0. |
| same | One payment settles at most one order. | **No, by design, and pinned as a known limit** -- `known_limit_overlapping_windows_on_a_reused_address_both_settle`. Two orders on one address whose anchors are less than `PAYMENT_WINDOW_BLOCKS` apart are both settled by one payment in the overlap. A cross-order rule would close it and is not merge-safe: two peer states each valid on its own could become invalid when merged, and `Paid` cannot be demoted. Reaching it needs an address reissued within the window past both UI layers below. Also not closed: a payment broadcast before the order but still unconfirmed when it was signed; one confirming inside the lag of a stale anchor; and a pre-order transaction reorged out and re-mined inside the window (conceded by judging the winning confirmation). |
| `ui/src/components/bitcoin_view.rs::AddressReading`, `status_pill` | The order card counts only value inside the order's window as "Payment seen on chain", and says when the address holds a payment from before the invoice or after its window. | **Yes** -- `address_reading_tests`, three tests, mutated red by counting every confirmed transaction. What renders the note inside `OrderCard` is a component, and no component is tested in this repository. |
| `ui/src/state.rs::AppState::check_address_before_signing` | An address whose bridge contract holds any claim is skipped and another derived; absence, an empty state and a timeout sign. | **Yes** -- the reuse-check tests in `invoice_tests`, mutated red by inverting the used/unused branch, by treating an undecodable state as unused, by removing the skip limit, by bypassing the check, and by removing the already-watched shortcut. **Not executed:** `spawn_address_reuse_check` (the GET, the 15 s timer) and the `NotFound` delivery in `gateway::response_handler`, both wasm-only. The timeout fails OPEN on purpose (a fresh address's usual answer is silence), so a used address whose contract is not found in time is signed; the payment window is what bounds that. The check sees only reuse under the same bridge set and address-contract build, since both are part of the contract id. |
| `delegates/harvest-delegate/src/bitcoin.rs::apply_published_floor` | The counter is raised past every index of this key whose script the store has published, never lowered, and orders from another key move nothing. | **Yes** -- the recovery tests in `bitcoin::tests` and the handler-level `a_fresh_install_does_not_reissue_a_published_address` and `a_stale_device_re_entering_the_same_key_takes_the_published_count`. Mutations run, each red: removing the floor from `DeriveOrderAddress`, and separately from `SetPaymentXpub`; scanning from 0 and assigning; not extending the window on a match. |
| same | It recovers the highest index ever HANDED OUT. | **No, and it cannot.** It recovers the highest index ever PUBLISHED. An index burned by an invoice abandoned before publishing, on a device that is gone, is invisible to it, as is an order pruned at `MAX_ORDERS` and one more than `PUBLISHED_INDEX_GAP` past the last match (pinned by `a_published_order_beyond_the_gap_is_not_found`). The address-contract check above catches any of those that were registered with the bridge. |
| `ui/src/state.rs::AppState::order_address_request`, `set_payment_xpub_request` | The requests carry the published scripts: every script on setting a key, and on a derivation those the delegate has not MATCHED, with unmatched ones offered again once the counter has advanced by half of `PUBLISHED_INDEX_GAP`. The record is cleared when the delegate reports a lower count, another key, or no key. | **Yes** -- `the_address_request_carries_the_published_scripts`, `only_scripts_the_delegate_matched_are_not_sent_again`, `a_new_or_cleared_key_forgets_what_was_accounted`, and the delegate's `the_delegate_reports_only_the_scripts_it_matched`. Mutated red: sending `Vec::new()`; marking every sent script accounted; no reset on a falling count; the delegate reporting everything it was sent as matched. |
| `ui/src/state.rs::AppState::settlement_hold`, `publish_settled_orders`, `confirm_paid` | A provable payment is auto-published as Paid only when nothing is ambiguous: no other own, uncancelled order on the same address and network with an overlapping window (a Paid twin counts), and everything owned loaded: a store list answered for every Ghost Key the vault lists, and every owned store's state arrived (a store the node gave up on is still counted, and named as not answering, since auto-publishing past a possible twin cannot be taken back). Otherwise it is withheld and the card shows the reason, this invoice's amount, the confirmed value in its window, each twin's amount and status (Paid marked), and a "Confirm paid" button that publishes the same assembled, verified proof. A confirmed one is not offered again, withheld entries for a store that migrated away are dropped, and every store with a withheld entry is published again when a store list or store state arrives, so a hold that clears is acted on at once. No payment is attributed between twins. A Paid order gets an informational note only when its own in-window payment height falls inside another own order's window. | **Yes** -- `an_unambiguous_payment_is_auto_published`, `a_twin_withholds_the_settlement_and_the_seller_can_confirm_it` (a Paid twin and an abandoned awaiting twin both withhold; confirm publishes the assembled proof and it verifies; a cancelled twin does not count), `an_owned_store_not_loaded_withholds_the_settlement`, `the_confirm_copy_names_the_amounts_and_a_paid_twin`, `an_unanswered_store_list_holds_until_it_arrives_then_publishes`, `a_store_that_did_not_answer_is_named`, `a_confirmed_settlement_is_not_offered_again_and_migration_drops_entries`, and `an_order_is_ambiguous_with_any_overlapping_uncancelled_own_twin` (partial overlap, both window boundaries, paid, cancelled, other network, stranger). **Limits, stated plainly:** UI-only. It used to hold only because only the seller's tab published Paid, so #75 (letting a buyer's tab publish) would have bypassed it: `refresh_same_address_orders` scanned OWN STORES only, and a buyer's two purchases from one address-reusing seller both sit in that seller's store. #75 widened it to OUR orders -- ones our identities issued and ones we bought (`our_orders`) -- across every store on screen, which keeps the property the narrower rule protected (an order this node is not party to still cannot stall anything). Pinned by `one_payment_does_not_settle_two_of_a_buyers_orders_on_one_address`, mutated red against the own-stores-only scan. **What that leaves:** a buyer whose settlement IS withheld has no way to confirm it -- the "Confirm paid" control is on the seller's order card -- so an ambiguous buyer-side payment waits for the seller, which is what happened before #75 in every case rather than in this one. **And a second residual, raised by the external reviewer on #115 and tracked as harvest#116:** the scan sees only stores in `browsing_stores`, which for a buyer is the stores opened this session, so two purchases in DIFFERENT stores sharing one reused address are twins only if both are open. Not closed there because the buyer's equivalent of `unloaded_stores`' enumerable `my_stores` is `remembered_stores`, whose state nothing fetches -- so gating on it would withhold every buyer settlement forever, which is the dead end #75 exists to remove. A twin in a store that has not loaded is not seen, which is why an unloaded store withholds everything. The card wiring (button, notes) is a component and is not tested. |
| Concession: `AppState::refresh_same_address_orders` | A Cancelled order is not counted as a twin, even if somebody paid it anyway, so its payment could let a same-address order auto-publish. | **Not closed**, by choice: only a foreign client can cancel today (the UI has no cancel action), and counting cancelled orders would withhold settlements forever behind orders nobody can pay. Pinned by `an_order_is_ambiguous_with_any_overlapping_uncancelled_own_twin` and the cancelled case of `a_twin_withholds_the_settlement_and_the_seller_can_confirm_it`. |
| Concession: `AppState::dispatch_settlement` / `settlements_submitted` | A settlement whose submit returned `Ok` but whose `Paid` record never comes back (the update was accepted by the local node and lost further on) stays in `settlements_submitted` for the rest of the session, so the order shows neither the hold text nor "Confirm paid" again, and is not re-sent until a reload. Only a submit that returns an error is retried (`settlement_publish_failed`). | **Not closed**, accepted: telling "sent and slow" from "sent and lost" needs an acknowledgement the update path does not give. A reload clears it. |
| `ui/src/state.rs::AppState::on_address_reuse_absent` | "Not found" signs, like the timeout, and logs that it did. It is not proof the address is unused: a dead-ended GET reports `NotFound` for a contract that exists, and nothing asks again afterwards. | **Partly** -- `a_fresh_or_unanswered_address_is_signed` covers that it signs; the log line is not asserted. **Measured once, 2026-09-18**, on a throwaway peer (`freenet network`, WS port 7661, connected to the nova gateways) with `fdev execute get` on eight random never-existing instance ids: seven answered `NotFound` in 4.3-7.1 s, one took 80.8 s. One peer, one sitting, eight samples: a spot check, not a distribution. The reuse-check timer is keyed to its own check (`a_stale_timer_does_not_end_a_newer_check_on_the_same_address`). |
| `ui/src/components/bitcoin_view.rs::status_pill` | The paid style needs the full amount inside the window; less reads "Partial payment seen". | **Yes** -- `dust_inside_the_window_reads_as_partial_not_paid`, mutated red by lighting it for any in-window value. |
| Concession: `verify_on_chain_proof` | A `Paid` order whose winning confirmation is later reorged OUT of its window (re-mined after the window closes) cannot be moved to `PaymentReversed`: the outpoint is then out of the window and not a retraction, so the reversal precondition never holds, and the embedded proof keeps the `Paid` record valid. | **Not closed.** Needs a reorg that carries the transaction more than two weeks forward. |
| Concession: `Order::payment_window` | The window saturates at `u32::MAX` rather than refusing an anchor within `PAYMENT_WINDOW_BLOCKS` of it; a `checked_add` would say so more honestly. | **Not closed**, as unreachable for any real block height; changing it re-keys the store for no practical gain. |
| Concession: `AddressReading` vs the verifier | The card reads the address view's folded transactions, while the verifier reads the claims, which the view caps at `MAX_PROOF_CLAIMS` (32). On an address with more history than that, the pill and the verifier can disagree. | **Not closed.** A per-invoice address with 32 distinct claims is already outside what a proof can carry. |
| `ui/src/state.rs::AppState::issue_invoice` | No address is derived until the store being invoiced has been read from the network. | **Yes** -- `an_invoice_waits_for_the_store_to_load`. It is NOT evidence the copy read is current: a re-created store's first state can be its own fresh PUT. The address-contract check covers that case. |

### Canonical contract state: harvest#22, #26, #55 and #85 (added 2026-09-18)

One re-key for three contract fixes, and the first change here checked with
`fdev verify-merge` against the built WASM as well as with `cargo test`. The
merge-law run is manual: nothing in CI builds a corpus and runs it, so the
property it checked is carried in CI only by the in-process tests named below.

| Where | Claim | Caught? |
|---|---|---|
| `common/src/reputation.rs::FeedbackEntry::verify` | Nobody but the holder of `token.entry_key` can change any field of an entry. | **Yes** -- `a_third_party_cannot_rewrite_an_entry` (red with the Ed25519 check skipped) and `every_field_of_an_entry_is_signed`, one mutation per field, red with the comment and with the RSA signature each dropped from `signing_bytes`. The RSA signature is covered because the SELLER can mint new PSS signatures on a token at will. |
| `common/src/reputation.rs::ReputationStateV1::apply_delta` | Two entries the key holder signed for one token resolve to the same survivor whichever arrives first. | **Yes** -- `two_signed_entries_for_one_token_converge`, red when the tie-break is replaced by first-writer-wins. `fdev verify-merge` on the built WASM: no violation with two such entries in the corpus. |
| `common/src/reputation.rs::ReputationStateV1::summarize` | Two peers holding different entries for one token send each other something. | **Yes** -- `peers_holding_different_entries_for_one_token_exchange_them`, red when the summary is keyed on the nonce again. |
| `common/src/reputation.rs::ReputationStateV1::verify` | Feedback is strictly ascending by nonce and `used_nonces` is exactly its nonces. | **Yes** -- `verify_refuses_non_canonical_state`, red with either check removed. |
| `common/src/reputation.rs::ReputationStateV1::merge` | Merging normalises even when the other side brings nothing. | **Yes** -- `apply_delta_normalises_the_state_it_is_applied_to`, red when `merge` skips `apply_delta` for an empty other side. |
| `common/src/store.rs::ListingsV1::verify` | Listings are strictly ascending by id (#26). | **Yes** -- `verify_refuses_unsorted_or_repeated_listings`, red with the check removed and with `>=` weakened to `>`. |
| `ListingsV1::normalize`, called from `apply_delta`, the store contract's `update_state` and `ui/src/migrate.rs::merge_store_reporting_discard` | Nothing this code writes is non-canonical, including when the scaffold skips `apply_delta` because a merge brought nothing. | **Yes, per call site** -- `merging_normalises_a_non_canonical_state` and `listing_merge_is_commutative_including_non_canonical_inputs` (dedup and sort each removed), `update_state_writes_canonical_listings_when_the_merge_brings_nothing` (contract call removed), `a_fold_normalises_a_non_canonical_base` (fold call removed). |
| `contracts/{reputation,store}-contract` `get_state_delta` and the `update_state` `State` arm | Zero bytes means no state here: an empty summary gets everything held, an empty state answers with an empty delta, and merging a zero-byte state changes nothing (#55). | **Yes** -- `an_empty_summary_is_answered_with_everything_held`, `an_empty_state_answers_with_an_empty_delta` and `merging_a_zero_byte_state_changes_nothing` in each contract, each red with its guard removed. The `State` arm was found by the `fdev verify-merge` empty corpora after the first round: `get_state_delta` alone did not clear them. |
| `common/src/feedback.rs::FeedbackToken::entry_key` | The buyer keeps the entry key's secret half. | **No, and nothing does yet.** Feedback submission is unwired (#53): the delegate's `TransactionRecord` stores the token but not the secret. Whoever wires it has to add that, or no buyer can ever sign an entry. |
| `contracts/*/src/lib.rs` `update_state` | Zero bytes merged with nothing but zero bytes stays zero bytes, so the empty state is idempotent; anything non-empty arriving, as a state or a delta, is encoded (harvest#55). | **Yes** -- `the_empty_state_is_idempotent_and_the_rule_is_commutative` and `a_delta_applied_to_the_empty_state_is_encoded` in each contract, red under three mutations each (flag never set, never cleared by a state, never cleared by a delta). |
| `common/src/store.rs::enforce_order_cap` | The order cap is associative: its ranking (signed `created_at`, then id) is invariant under the per-key status merge (harvest#85). | **Yes** -- `the_order_cap_is_associative_when_a_status_changes_at_the_cap` (the verify-merge counterexample) and `the_order_cap_obeys_the_merge_laws_at_the_cap`, both red against the terminal-first ranking. Pinned at the `merge_order` + cap layer, not through `OrdersV1::apply_delta`, because the fixtures are unsigned. |
| `common/src/store.rs::enforce_order_cap` (policy) | Pruning keeps what a buyer needs. | **No, and the seller can defeat it.** The cap keeps the newest `MAX_ORDERS` by `Order::created_at`, which the SELLER signs and nothing bounds (the contract has no clock). So the seller can (a) flood `MAX_ORDERS` new orders, Cancelled or not, and evict every older order including Paid ones that are a buyer's evidence of payment, and (b) date orders far in the future to pin slots against later honest orders. Only the seller can create orders (`ui/src/components/buy_view.rs` sends the buyer's request; the seller signs the order), so this is the seller erasing records about itself, not a third party. Ranking by `Order::anchor` height was considered and does not help: the contract cannot check an anchor against the chain either, so an unpaid order's anchor is as free as `created_at`; only a Paid order's anchor is bounded (its payment must confirm within `PAYMENT_WINDOW_BLOCKS` of it), and those are the orders a flood evicts. Status cannot take part in the ranking at all without breaking associativity (harvest#85). What a buyer should rely on is its own copy of the order and proof, not the store keeping it. |
| `common/src/feedback.rs::FeedbackToken::nonce_for`, checked in `FeedbackEntry::verify` | A token's slot belongs to its entry key: the nonce must be a domain-separated BLAKE3 of `entry_key`, so the seller (who can blind-sign any token) cannot mint a token for a buyer's published slot with a key of its own and win the tie-break (PR #82 review, Must Fix 1). | **Yes** -- `the_rsa_key_holder_cannot_mint_a_token_for_a_published_slot`, which grinds a seller key that sorts first; red with the derivation check removed. |
| `contracts/*/src/lib.rs` `validate_state` | A state is valid only in its canonical encoding: the bytes must be exactly what re-encoding the decoded value gives (no trailing bytes, unknown keys, or non-minimal encodings) (PR #82 review, Should Fix 2). | **Yes** -- `validate_state_refuses_non_canonical_bytes` in each contract (trailing byte, unknown key), red with the check removed. Non-minimal integer encodings are covered by the same comparison but not by a test of their own. |
| `common/src/lib.rs::merge_laws` and the `seeded_random_*` tests | Commutativity, associativity and idempotence hold byte for byte over random states, for the mailbox, reputation, store, and the order set at `MAX_ORDERS`. | **Yes, within what a random pool reaches** -- red under the prefix byte walk, the status-ranked order cap, first-writer-wins feedback and an unsorted listing normalise. The skipping byte walk survives it (its counterexample needs a precise fill), so `the_byte_bound_is_associative_at_the_budget` stays the guard for that. Fixed seeds, no new dependency. |
| `common/src/store.rs::AuthorizedStoreInfoV1::verify` at version 0; `ui/src/state.rs::on_contract_state`; `ui/src/migrate.rs::merge_store_reporting_discard`; `ui/src/gateway/response_handler.rs::check_for_reputation_link` | Version-0 store info carries nothing: the contract refuses anything but the default; the buyer side resets version 0 to the default (and keeps it `Some`, so the seller's NeverPublished repair stays reachable); the migration fold resets it too, so a predecessor holding injected version-0 content still carries its listings; and an unsigned reputation link is never followed (PR #82 re-review and round 3). | **Yes** -- `version_zero_info_must_be_the_default`, `version_zero_store_details_are_not_believed`, `a_version_zero_store_is_resolved_and_prompts_to_publish` (red against the round-2 `None`), `a_fold_drops_unsigned_version_zero_details` and `every_fold_order_with_injected_version_zero_details_moves_the_listings` (the four fold orders the round-3 review reproduced, through the real fold; their forward states validate in the built WASM), `only_a_signed_reputation_link_is_followed`, each red with its guard removed. The store-v0 `fdev verify-merge` corpus went from 6 violations to 0. |
| `common/src/reputation.rs::FeedbackEntry::verify` (`verify_strict`) | An entry under a small-order or non-canonical entry key cannot be forged. | **Yes** -- `an_entry_under_a_small_order_key_is_refused`, which checks the non-strict check DOES accept the forgery (R = identity, s = 0) and the contract does not; red with `verify_strict` swapped for `verify`. |
| `common/src/store.rs::Bytes32` in the order summary | The summary's id and digest encode as CBOR byte strings, so a summary at `MAX_ORDERS` is about 280 KiB (70 bytes an entry) rather than about 512. | **Yes** -- `the_order_summary_at_the_cap_is_byte_strings`, red with integer-array encoding. `OrderId` itself is unchanged, since it is inside every signed order. |
| `common/src/mailbox.rs::enforce_message_cap` | The byte bound is met by count caps per size class (`SIZE_CLASS_CAPS`, a laminar matroid), so the greedy pick is path independent and the merge associative (harvest#85). | **Yes** -- `the_byte_bound_is_associative_at_the_budget`, the verify-merge counterexample, red against the skipping byte walk. `the_byte_bound_is_associative_with_a_large_message_mid_ranking` is the shape that defeats a PREFIX walk; it passes under the skipping walk and exists to stop a revert to the prefix rule. That the class caps fit in `MAX_MAILBOX_BYTES` is a compile-time assertion. |
| `common/src/mailbox.rs::MailboxStateV1::verify` | The state is exactly what `apply_delta` would leave: every message within `MAX_MESSAGE_BYTES`, every size class within its cap, strictly ascending in `canonical_order` (harvest#85). | **Yes** -- `verify_refuses_non_canonical_order`, `verify_refuses_an_oversized_message`, `verify_refuses_a_state_the_cap_would_prune`, each red with its check removed. |
| Merge laws across the three contracts | Two peers holding valid states converge. | **Not in general.** `fdev verify-merge` still reports `state_commutativity` for an unsigned listing `certificate_pem`, the reputation `owner_certificate_pem`, and two different store details at one version. The mailbox and order caps were not associative either until harvest#85; see the rows above. Recorded as harvest#81 rather than fixed, because a byte tie-break over an unsigned field hands the choice to whoever grinds the smallest value. |

### Store codes and the store's owner: harvest#52 (added 2026-09-18)

The store contract's parameter became a sixteen-character base58 prefix of the
seller's key, and the full key moved into the state as `StoreStateV1::owner`.
Mutation results below were each observed red with the named guard removed
or inverted, unless the row says otherwise.

| Where | Claim | Caught? |
|---|---|---|
| `common/src/store.rs::StoreStateV1::merge` (via `delta` / `apply_delta`, `outranks`) | Two owners of one code resolve to the smaller key by bytes, whichever state is held and whichever arrives, and the result obeys the merge laws. | **Yes** -- `claim_tests::the_smaller_key_wins_a_shared_code_whichever_way_round`, `two_owners_sharing_a_code_obey_the_merge_laws` (random states of two owners, closed form checked), and the contract-level `update_state_keeps_the_smaller_key_whichever_state_it_holds`. The pair is ground to a TWO-character code, since sixteen cannot be ground; the contract accepts any code length for exactly this reason. `fdev verify-merge` on the built WASM with a two-owner corpus (12 states, 5 transitions, 8 delta steps), and the PR #91 review's three-owner corpora (`store-triad`, `store-triadcap`): 0 violations, every property run; the same corpus against a build with the outranked arm made first-writer-wins gives 62 violations (commutativity, associativity, reconciliation, transition paths), so the check can fail. **Found by mutation:** the test fixture first ordered the ground pair with `outranks` itself, so flipping the rule survived every test; it now orders by raw bytes. |
| `StoreStateV1::apply_delta` | An update from an owner the held one outranks changes nothing and is NOT an error; one from an outranking owner replaces the store with only its records. | **Yes** -- `an_update_from_an_outranked_owner_changes_nothing`, `an_update_from_an_outranking_owner_replaces_the_store`; red with the outranked arm removed. |
| `StoreStateV1::delta` | Across owners a delta is everything (measured against the empty store) or nothing, never a difference against another key's records. | **Yes** -- `a_delta_across_owners_is_everything_or_nothing`, whose owners share listing ids (ids are content-derived), red when the requester's summary is used across owners and when the loser sends. |
| `StoreStateV1::verify` / `apply_delta` | The owner must begin with the code; an owner arrives only with something it signed; records need an owner. | **Yes** -- `verify_binds_every_record_to_an_owner_the_code_admits`, `an_update_naming_a_key_the_code_does_not_admit_is_refused`, `an_update_naming_an_owner_but_carrying_nothing_signed_cannot_claim`, `an_ownerless_update_cannot_put_records_in_an_unowned_store`. The top-level "no owner cannot hold signed records" check is also enforced by every part's `owner_key`, so it is pinned by its message rather than by behaviour. |
| `StoreParameters::from_code`, `admits` | A code of any length but sixteen, or outside the base58 alphabet, opens nothing; an empty code admits nobody. | **Yes** -- `a_code_of_any_other_length_or_alphabet_is_refused`, `a_code_admits_only_keys_that_begin_with_it`, and `store_link`'s `rejects_a_code_of_the_wrong_length`. |
| Policy: smaller key wins | An established store cannot be taken over. | **No, by design.** A key sharing the seller's code with smaller bytes takes the address even after the seller has published. That is the same keypair search as pre-empting a seller, and first-writer-wins, which would prevent it, does not converge (decided on harvest#52). The price is set by the code length: 16 characters, about 2^94 against one chosen seller and about 2^80 against any one of 10,000 stores at once, because a grinder checks each key against every live code. 12 characters was about 2^57 at 10,000 stores, which is why the code was lengthened after the PR #91 review. The seller is told (next row). |
| `StoreStateV1::apply_delta` during an owner switch | A replica that switches owner holds the winner's whole store. | **No, transiently.** A delta computed against a summary of the same owner can reach a replica that has meanwhile switched to a different, outranked owner; it then switches to the incoming owner holding only that delta's records, a subset, until the next summary exchange sends the rest. Needs two keys sharing a code. The merge laws are unaffected: they are over whole states. |
| `StoreStateV1` merge laws | Replicas converge whatever the order or grouping. | **For honestly signed content.** The per-owner merge still has the unsigned-field tie cases of harvest#81 (`store-adv` shows the same findings as before this change); the owner rule neither fixes nor worsens them. |
| `ui/src/state.rs::AppState::foreign_store_owner` and its notification | A seller whose store's address another key holds is told, once, and the My Store card keeps saying so. | **Partly** -- `a_seller_is_told_when_another_key_holds_their_store`, `nothing_is_said_about_our_own_key_an_unclaimed_store_or_someone_elses`, red with the comparison inverted and with the once-only guard removed. The card's rendering is a component and is not tested. |
| `ui/src/ghostkey_cert.rs::verify_store_certificate_against` | At the current generation a certificate verifies only if its key IS the state's owner, since the address now pins only the code. | **Superseded by harvest#93 phase 1a**: the function is gone, and the question is now whether the current BACKING's certificate certifies the backing key. See the harvest#93 section below. |
| `ui/src/migrate.rs::store_param_shape`, `store_candidate_ids` | V1 and V6..=V16 are probed under the whole-key encoding, V2..=V5 under the three-field one, later generations under the code. | **Yes** -- `each_store_generation_is_derived_under_the_encoding_it_shipped_with` (per-generation table from the artifacts), red with the boundary moved by one. |
| `ui/src/migrate.rs::name_whole_key_owner` | A whole-key generation's state, which names no owner, is carried forward owned by the seller its address was derived from, and the result is one the new contract accepts; a state that already names an owner is never reassigned. | **Yes** -- `a_whole_key_store_is_found_and_carried_into_the_code_addressed_contract`, red with the naming removed, and `the_owner_fill_in_does_not_reassign_a_store_another_key_owns`, red with the `is_none()` guard dropped (which survived every test before it). Not exercised against a live node: `tests/rehearsal` is compile-checked only. |
| `delegates/harvest-delegate/src/known_stores.rs` | Remembered stores are keyed by a validated code under `harvest:`, capped at `MAX_KNOWN_STORES`, never un-archived by a visit, never deleted, and gated to the Harvest web app. | **Yes** -- the module's tests and `another_web_app_cannot_read_or_change_the_remembered_stores`, red with each of: the code check, the cap, the keep-archived arm, the prefix changed (caught by the migration prefix test), and the gate bypassed. |
| `ui/src/store_link.rs::share_link` | The shared link names Harvest on the default node address (`127.0.0.1:7509`) and nothing of the seller's page. | **Yes** -- `a_shared_link_names_harvest_on_the_default_node_and_nothing_of_the_sellers`. **Limit:** a buyer whose node is not on port 7509 cannot use the link as-is; they enter the code, which the seller's card shows beside it. |
| `ui/src/state.rs::AppState::remember_loaded_store`; `store_link::is_old_format_link` | A store is remembered only once its state has arrived, once per session, so a mistyped or unreachable code never joins the list; a pre-#52 link (a whole contract id) gets an "old-format link, ask the seller for their code" notice instead of a blank page. | **Yes** -- `a_store_is_remembered_only_once_it_has_loaded` and `an_old_format_link_is_recognised_and_nothing_else_is`, red with the store-state call removed, the once-per-session guard removed, and the recogniser disabled. The recogniser's 43..=44 length check is a bound on decode cost, and removing it changes no answer, so it is not mutation-tested. The wasm-only call sites are compile-checked, not run. |
| `delegates/harvest-delegate/src/known_stores.rs` archive | A remembered store is never deleted, and a visit does not un-archive an unreadable record. | **Yes** -- `nothing_here_can_delete_a_record` (structural: the module is generic over `SecretStore` alone, which has no removal, and the test stops compiling if a removal bound is added; behavioural: the key count never falls), `a_visit_does_not_guess_about_an_unreadable_record`. The list is per node, not per Ghost Key. |
| `ui/src/components/store_view.rs::StoreList` | Stores opened from a link are listed after a reload, and archive / unarchive / show archived work. | **Partly** -- the delegate side and `AppState::store_list_rows` / `remembered_store_requests` are tested (`store_code_tests`); the component, and the startup call that sends the queued `RememberStore`, are wasm-only and untested. |

### Store keys, backings and the closed flag: harvest#93 phase 1a (added 2026-09-18)

A store is owned by its own store key; Ghost Keys back it. Mutation results
below were each observed red with the named guard removed or inverted, by a
scripted run over 41 mutations (`cargo test` filtered to the named test,
original file restored after each), unless the row says otherwise.

| Where | Claim | Caught? |
|---|---|---|
| `common/src/backing.rs::AuthorizedBacking::verify` | A backing holds only if the Ghost Key it names signed it, the store key accepted it, it names this store, and its certificate is at most 4 KiB. | **Yes** -- `a_backing_signed_by_the_wrong_ghost_key_is_refused`, `a_backing_the_store_key_did_not_accept_is_refused`, `a_backing_for_another_store_is_refused` (the store key countersigning another store's statement, so only the store check can refuse it), `a_backing_whose_certificate_is_too_large_is_refused`; each red with its check removed. |
| `AuthorizedRetirement::verify`, `AuthorizedClosure::verify` | Only the store key retires a backing or closes the store, and a closure names this store. | **Yes** -- `a_retirement_or_closure_not_signed_by_the_store_key_is_refused`, `a_whole_state_with_a_forged_record_is_refused`; red with each signature check and the closure's store check removed. |
| `StoreStateV1::normalize_backings`, `verify`; `SignedSetV1::verify` | Every merge of valid states succeeds, in any arrival order: past 64 Ghost Keys with a backing or a retirement the smallest are kept, a key's backing and retirement are kept or cut together, a retirement arriving before its backing still retires it, the closed flag and everything else in the update always lands, and a cut backing never returns un-retired. Every record sits in its own slot; a refused (badly signed) delta leaves the state unchanged. | **Yes** -- `a_union_past_the_bound_keeps_the_smallest_keys_and_everything_else` (red with the largest kept and with the normalisation skipped), `seeded_merges_past_the_bound_obey_the_merge_laws_and_drop_nothing_else` (24 states over 72 backings, 150 pair/triple cases, closure and listing survival asserted on every merge, plus 150 delta-order cases with stale-summary deltas; red with the old retain-with-backing rule), `a_retirement_arriving_before_its_backing_still_retires_it` (red with the old rule), `retired_keys_count_toward_the_bound` (red with backings ranked alone), `a_cut_backing_takes_its_retirement_and_never_returns_unretired`, `a_record_under_someone_elses_slot_is_refused`, `a_refused_record_leaves_the_state_unchanged`. `fdev verify-merge` with corpora whose unions pass the bound, with delta steps: see the PR. **History:** the first version refused past the bound (Must Fix 1 of the PR #98 review); `fdev` counted that as inconclusive, not as a violation. The second dropped a retirement with no held backing, which un-retired a key when the retirement arrived first; `fdev`'s `delta_permutation_invariance` found 18 violations over `store-r98race` and `store-r98retire` (the #98 merge-law re-check). |
| `SignedSetV1` merge (`merge_record`, `delta`) | Union by slot, the smaller encoding on a clash, no removal path; the merge is idempotent, commutative and associative, and only grows. | **Yes** -- `seeded_random_backing_sets_obey_the_merge_laws` (61 states with a same-slot clash, a retirement of a never-backing key and the closed flag, 400 pair/triple cases, byte-level, plus an inflation check), `two_records_for_one_slot_resolve_to_the_smaller_encoding_either_way` (red with the tie-break flipped and with the summary's digest comparison removed), `nothing_removes_a_backing_a_retirement_or_the_closed_flag`. `fdev verify-merge` on the built WASM: see the verify-merge note below. |
| Merge beyond the bound | No backing is ever removed. | **No, by design, past 64.** The bound drops the backings with the largest Ghost Keys (and their retirements) to keep the merge total. Certificates are not checked by the contract, so the store key's holder can reach it for free; nobody else can add a backing. A store in the wrong hands is closed, and the closed flag is never touched by the bound. |
| `StoreStateV1::verify`, `holds_signed_content` | The whole state is checked (a PUT with a forged backing, retirement or closure is refused), and a countersigned backing alone can claim a store. | **Yes** -- `a_whole_state_with_a_forged_record_is_refused` (red with each of the three `verify` calls removed), `a_countersigned_backing_claims_the_store_and_verifies` (red with backings dropped from `holds_signed_content`). |
| `backing::current_backing` | The current backing is the unretired one with the highest block height (backing key breaking a tie), leaving out one dated above a known tip. | **Yes** -- `the_current_backing_is_the_most_recent_unretired_one`, `a_tie_on_height_is_broken_by_the_backing_key`, `a_future_dated_backing_is_not_current_once_the_tip_is_known`; red with the retirement filter removed, the tip filter removed, and max turned to min. |
| `backing::keys_backing_several_stores`; `ui/src/state.rs::refresh_backing_verdicts` | A Ghost Key that is the current backing of two loaded stores counts for neither, and each counts again once the other moves on. | **Yes** -- `a_key_backing_two_stores_is_found_and_one_backing_one_store_is_not`, `a_key_backing_two_stores_counts_for_neither`; red with the count check weakened and with the conflict arm skipped. **Limit:** a reader knows only the stores it has loaded, so the rule is only as complete as that until phase 1c's Ghost Key record. |
| `backing::classify_store_key_message`, `sign_with_store_key`; `delegates/.../store_keys.rs::sign` | The store key signs only a store's own records, exactly (no trailing bytes, never a bare backing statement, a wrap message or an inbox entry). | **Yes** -- `the_store_key_signs_only_a_stores_own_records`, `it_refuses_to_sign_anything_that_is_not_a_store_record`; red with the canonical check removed, the refusal removed, and the delegate bypassing it. |
| `delegates/harvest-delegate/src/store_keys.rs` | A store key is kept under `harvest:`, never loaded for another store's name, not created when the write fails, capped at 64, and minted and used only for the Harvest web app. | **Yes** -- the module's tests and `another_web_app_can_neither_mint_nor_use_a_store_key`; red with the key check, the write check and the cap removed. The prefix is held by `all_secret_key_shapes`. |
| Store keys across a delegate re-key | A store key survives the delegate being rebuilt. | **No, and not true; recoverable since phase 1b.** Nothing drives the export handshake, so a delegate re-key loses every store key. Phase 1b's custody recovers it from the copy wrapped to the backing Ghost Key, on a device with that Ghost Key connected (see the phase 1b rows below). |
| `ui/src/state.rs::on_signature`, `store_key_signature_failed`, `drop_vault_signatures` | An answer settles only a request asked of its own signer; a store-key refusal withdraws exactly its own request; a vault refusal leaves store-key requests alone. | **Yes** -- `an_answer_from_the_wrong_signer_settles_nothing`, `a_refused_store_key_signature_withdraws_its_own_request_only`, `a_denied_prompt_clears_what_the_vault_was_asked_and_nothing_else`; each red with its guard removed. |
| `ui/src/backing_flow.rs` single-flight and section 6.2; `delegates/.../store_keys.rs::create`, `finish_creation` | A second creation or move is refused while one is under way, whatever stage it has reached; a retry, from any tab or after a reload, gets the same store key until the store is registered, and within a session reuses the backing both keys signed, so it re-publishes the same store; a Ghost Key that already backs a loaded store cannot back another, but a retry is not refused by the store it is re-creating; a delegate error while waiting for the key, or Cancel, releases the creation; while a pre-revision-2 store has not loaded, "Create Store" is held back; no store key is minted without a block to date the backing to. | **Yes** -- `a_second_creation_is_refused_until_the_first_finishes`, `a_retried_creation_gets_the_same_store_key_until_registered`, `registering_a_store_ends_its_resumable_creation`, `a_retry_after_a_failed_publish_reuses_the_key_and_the_backing`, `a_ghost_key_that_already_backs_a_store_cannot_back_another`, `a_retry_is_not_refused_by_the_store_it_is_re_creating`, `a_stalled_creation_can_be_released` (also: no Cancel once the PUTs run), `an_unloaded_legacy_store_holds_back_creation`, `a_repeated_registration_naming_the_key_ends_the_creation`; the delegate refuses a NEW store key to a Ghost Key with a registered store-key store unless `another_store` is set (`registering_a_store_ends_its_resumable_creation`), which makes section 6.2 hold across every tab of a device; `a_refused_store_key_abandons_the_creation_and_says_so`, `with_no_block_no_creation_starts`; nine mutations over the M1, L1 and L3 guards, all red. **Limits:** after a reload the signed backing is gone, so a retry signs a new one (same store key, same contract id; the two backings share a slot and merge). Checking section 6.2 only once the key is known can mint one store key that then goes unused until the Ghost Key's next creation, which reuses it. A pre-revision-2 store that never loads holds "Create Store" back until it does. |
| `ui/src/backing_flow.rs` creation | Creation waits for its own store key, dates the backing six blocks behind the newest known block (or does not start without one), and publishes only a backing the contract would accept; every loaded store's verdict is recomputed when the tip moves. | **Yes** -- `a_tip_update_makes_a_backing_dated_ahead_of_it_current` (Should Fix 5, through the real `apply_tip_state`), `creation_waits_for_the_store_key_then_asks_the_ghost_key_to_back_it` (red with the gate's store-key condition removed and with the request-id match removed), `with_no_block_loaded_nothing_is_backed`, `a_backing_that_would_not_verify_is_not_published` (red with the check removed). `create_store_contracts` and the vault and delegate round trips are wasm-only and compile-checked, not run. |
| `ui/src/backing_flow.rs` move of a pre-revision-2 store | Offered only for a loaded Ghost-Key-owned store with nothing newer; carries its details and listings with their ids. | **Yes** -- `a_move_is_offered_only_for_a_loaded_legacy_store_with_nothing_newer` (red with the "nothing newer" check removed), `moving_a_legacy_store_carries_its_details_and_listings`. The button and the re-signing of each carried listing run only in the browser. |
| `ui/src/state.rs::payment_blockers`, `BrowsingStore::payable`, `components/store_view.rs::buyable`, `components/bitcoin_view.rs::my_orders` | A closed store is refused before anything else and offers no Buy control; neither a closed nor an unbacked store shows a payment address anywhere (its invoices on the store page, its awaiting orders under "Your orders"); a commitment is checked against the store key, not the Ghost Key. | **Yes** -- `a_closed_store_is_refused_before_anything_else`, `a_closed_store_cannot_be_bought_from`, `an_awaiting_order_at_a_store_not_to_be_paid_is_not_listed` (Must Fix 2), `a_commitment_is_checked_against_the_store_key_not_the_ghost_key`; each red with its check removed or pointed at the Ghost Key. The store page's `if store.payable()` around `StoreInvoices` and the closed banner are components and are not tested. |
| `ui/src/state.rs::store_owner_key`, `delta_owner_key`, `merge_store_registrations` | Anything signed for our store is signed by the registration's store key, never the Ghost Key; a settlement (unsigned) to a pre-revision-2 store still names the owner its loaded state names, so a paid legacy invoice can reach Paid; a store list answer never takes a known store key away. | **Yes** -- `the_owner_of_our_store_is_the_key_every_update_names` (Should Fix 6 half included), `a_store_list_answer_keeps_a_locally_known_store_key`; red with a fallback key substituted and with the carry-over removed. |
| `delegates/.../migration.rs::WithoutStoreKeys` | A store key's seed is never exported to a successor delegate generation. | **Yes** -- `a_store_key_is_never_exported` (Should Fix 4), red with the export reading the raw store. |
| Retiring a backing from the client | A seller can undo a backing. | **No, and deliberately not built** (harvest#104). A control existed on this branch and was removed before merge: retirement is the second half of a swap whose first half -- attaching a backing to an existing store -- does not exist, so on its own it permanently unbacked the store rather than moving it. The claim above previously read "a seller can ALWAYS undo a backing" and was tested; the tests passed and the claim was false, because the undo left the store unbackable by any key. The contract still accepts `Retirement` and its tombstone semantics, which `common/` tests cover; nothing in the client produces one. |
| `backing_flow::offer_second_store`, `confirm_second_store` | A creation refused under section 6.2 is offered to the seller as a deliberate second store, and confirming carries `another_store` past both this tab's check and the delegate's. | **Yes** -- `a_refused_second_store_can_be_confirmed`; red without the offer, without the flag, and with the flag ignored. **Limit:** both stores then read as unbacked to a reader that has loaded BOTH (`keys_backing_several_stores`, which is only as complete as what that reader has loaded -- see #103), and this build has no way to undo it, since there is no retire control (#104). The prompt says so. |
| Phase 2 deferrals | The seller can close their store, and Settings says when a Ghost Key already backs another store. | **No, not built.** Recorded in `docs/design/entity-model.md`, "What phase 1a leaves where it was". |
| `ui/src/ghostkey_cert.rs::certificate_naming_one_of` | A certificate vouches for a backing only if it certifies the backing key, and for a listing only if it certifies one of the store's backers. | **Yes** -- `a_genuine_certificate_for_another_key_does_not_vouch_for_this_backing`, `a_record_certificate_verifies_against_any_of_the_stores_backers`; red with the key comparison removed. |
| `ui/src/migrate.rs` V18 | The last Ghost-Key-owned generation is probed under the code encoding, carried forward as it is, and arrives unbacked. | **Yes** -- `a_ghost_key_owned_store_is_carried_forward_and_arrives_unbacked`, red with `LAST_WHOLE_KEY_STORE_PARAM_GENERATION` moved to 18. |
| `ui/src/gateway/migrate_ops.rs::start_store_key_migration` | A store owned by a store key is probed at the addresses its own key derives, so the next re-key finds it. | **Partly** -- `a_store_keys_candidates_are_its_own_and_not_its_ghost_keys` pins the derivation; the wasm-only start from the `StoreList` answer is compile-checked, not run. |
| Mailbox and record addresses | Changing a store's backing keeps its mailbox. | **No, and not true yet.** The mailbox is still addressed by the backing Ghost Key and the record by the Ghost Key and the per-device RSA key; phases 1b and 1d re-address them by the store key. Phase 1a therefore ships no "change Ghost Key" or "retire" control. |

### Store key custody: harvest#93 phase 1b (added 2026-09-19)

Every device a seller uses holds the same store key, recoverable from a
backing Ghost Key. Mutation results below were each observed red with the
named guard removed or inverted, by a scripted run over 28 mutations
(`cargo test` filtered to the named test, original file restored after
each), unless the row says otherwise. The first run left five survivors
(the unbacked-copy filter, the copy's store check, the recovered-seed check,
the recovery cap, the in-flight guard); each now has a test, and the rerun
killed all five.

| Where | Claim | Caught? |
|---|---|---|
| `common/src/store.rs::normalize_copies`, `verify` | A wrapped copy is kept unless its backer is retired (the custody tombstone) or its slot is cut by the store-wide bound, in any arrival order: a copy arriving before its backing is kept, one arriving after its backer's retirement is dropped; at most four scopes per backer, the smallest kept; a state holding a copy for a retired key is refused; every merge of valid states succeeds. | **Yes** -- `retiring_a_backer_tombstones_every_copy_it_had_or_will_have`, `a_copy_arriving_before_its_backing_is_kept_and_a_retired_one_never_is` (red with the old held-backing rule), `a_cut_backing_takes_its_copies_with_it`, `a_wrapped_copy_is_the_store_keys_for_a_backer_it_holds`, `a_backer_keeps_its_smallest_scopes_past_the_bound`, `seeded_random_stores_with_copies_obey_the_merge_laws` (with stores that hold no backing, and 300 stale-summary delta-order cases; red with the old rule); red with the retired filter and the verify check removed, and with the bound shifted and reversed. `fdev verify-merge` on `store-copies` and `store-copies-bad`: see the PR. |
| `common/src/custody.rs::AuthorizedCopy::verify` | A copy holds only if the store key signed it, it names this store, and its ciphertext has the v1 shape. | **Yes** -- `a_wrapped_copy_is_the_store_keys_for_a_backer_it_holds`, `a_copy_naming_another_store_is_refused`; red with the store check and the shape check removed. |
| `common/src/custody/crypto.rs::WrapSecret::from_sign_result` | Only the vault's signature over this store's wrap message, under Harvest's scope, verifying under the backer, is ever used as a wrapping secret. | **Yes** -- `a_signature_for_another_purpose_is_not_a_wrap_secret`, `another_apps_signature_over_the_wrap_message_is_refused`, `a_tampered_or_foreign_signature_is_refused`; red with the payload, requestor and signature checks removed. |
| `wrap_store_key`, `unwrap_store_key` | Only this store's key is sealed, and what a copy opens to is kept only if it is this store's key. | **Yes** -- the `custody::` tests and `a_copy_that_opens_to_another_key_is_refused`; red with each key check removed. |
| `WrapSecret`'s `Debug`, `delegate::WrapSignature` | The wrap signature never prints. | **Yes** -- `a_wrap_secret_never_prints_its_signature`; red with the redaction removed. The browser console does not see it either: since harvest#96 (#94), now on `main` beneath this stack, a vault `SignResult` is logged as its bare name (`gateway::log_summary::ghostkey_response_summary`, pinned by `a_vault_response_summary_prints_no_secret`), and #96's exhaustive classification marks `WrapStoreKeyFor` and `UnwrapStoreKey` as secret-bearing (`no_delegate_message_prints_a_secret`). **Limit:** the Harvest origin is trusted: it supplies the wrap signature, so a UI built to could open a copy; this UI does not. |
| `delegates/.../store_keys.rs::wrap_for`, `unwrap` | The delegate wraps only a key it holds, keeps a recovered key only after the seed checks out, and never past 64 store keys. | **Yes** -- `a_device_with_a_backing_ghost_key_recovers_the_store_key`, `a_signature_that_is_not_this_stores_wrap_signature_is_refused`, `a_copy_that_does_not_open_keeps_nothing`, `recovery_stops_at_the_cap_unless_the_key_is_already_held`; red with the keep and cap checks removed. |
| `delegates/.../messaging.rs::derive_conversation_keys` | A store with a store key reads with the inbox key that key derives; a device without that key is refused, never answered with the per-device key. | **Yes** -- `a_store_key_reads_with_the_inbox_key_it_derives`; red with `store_verifying_key` ignored. |
| `ui/src/state.rs` `SignResult` arm, `custody_flow::on_wrap_signature` | A wrap signature goes to the Harvest delegate and nowhere else, never consumes a signature something else waits for, and one nobody asked for is dropped. | **Yes** -- `a_wrap_signature_goes_to_the_delegate_and_never_to_the_signing_queue`, `an_unrequested_wrap_signature_is_dropped`; red with the routing removed and with an unrequested signature forwarded. The wasm-only vault request (`spawn_wrap_signature_request`) is compile-checked, not run. |
| `custody_flow::custody_needed` | Wrap when this device holds the key and the current backer has no copy under the current scope; recover when it does not and a copy exists; nothing otherwise, nothing without the backer connected, and each (store, backer) at most once per session. | **Yes** -- `custody_wraps_a_held_key_and_recovers_a_lost_one`, `custody_needs_the_backer_connected_and_asks_once`, `a_store_with_a_request_in_flight_gets_no_second_one`, `a_store_with_no_current_backing_needs_no_custody`; red with the arms swapped, the scope ignored, and each guard removed. |
| `custody_flow::on_store_key_recovered` | A recovered store is registered again with its store key, its published record and its backer's mailbox; a failed recovery registers nothing. | **Yes** -- `a_recovered_store_is_registered_again`, `a_failed_recovery_registers_nothing`; red with the merge skipped. The re-registration with the delegate is wasm-only. |
| `ui/src/state.rs::start_store_edit_if_ready`, `conversation_keys_to_request`; `custody_flow::on_store_subkeys` | A store with a store key publishes the keys it derives, and an edit waits for them rather than publishing the per-device key; its conversation keys are asked for by store key. | **Yes** -- `an_edit_publishes_the_keys_the_store_key_derives`, `a_conversation_key_request_names_the_stores_key`; red with the wait removed, the per-device key substituted, and the store key dropped from the request. |
| `custody_flow::check_published_record_key` | A device whose derived record key differs from the published one says so. | **Yes** -- `a_record_key_that_disagrees_with_the_published_one_is_reported`; red with the comparison removed. **Limit:** it warns; it does not stop a publish. |
| Record key stability across an `rsa` bump | The same store key gives the same record key on every device and every build. | **Partly.** A known-answer test (`the_record_key_derives_from_the_store_key_with_a_known_answer`) turns red on a bump that changes the output, and the published key is checked by every device, but nothing guarantees it. |
| `custody_flow::custody_needed`, `start_custody_where_needed`; `state.rs::user_signature_under_way` (#99 review) | Recovery can use any unretired backer that has a copy, the current one first; custody starts only while nothing else waits on the vault, counts as the seller's own vault work while it waits, and is decided again when the Ghost Key list, the store list or a vault answer arrives; with no Harvest delegate a wrap signature is dropped and the seller told. | **Yes** -- `recovery_can_use_any_unretired_backer`, `custody_is_the_only_vault_prompt_while_it_waits`, `a_ghost_key_list_starts_custody`, `a_store_list_starts_custody`, `with_no_harvest_delegate_custody_is_dropped_and_said`. **Limit:** a refusal names no request, so if the seller starts signing while a custody prompt is open, a refusal drops both. |
| `custody_flow::check_published_record_key`, `start_store_edit_if_ready` (#99 review) | A device whose derived record key differs from the published one publishes no store details, and a recovered key is checked before anything is published from it. | **Yes** -- `a_record_key_that_disagrees_with_the_published_one_is_reported` (asserts the block), `a_recovered_store_is_registered_again` (asserts the check is requested). |
| `delegates/.../store_keys.rs::unwrap` against the wrong store | A copy presented for another store key opens nothing and keeps nothing. | **Yes** -- `recovering_against_the_wrong_store_key_keeps_nothing`. |
| `delegates/.../handlers.rs::handle_blind_sign` | A feedback token for a store created since phase 1b is blind-signed with the key its record is addressed by. | **No, not built.** It still signs with the Ghost Key's per-device RSA key, while a new store's record is addressed by the store-derived record key. Unreachable today: feedback submission is not wired (#53); the store-key path belongs with that work. |
| `backing_flow::on_store_key_created`, `custody_flow::fill_creation_from_subkeys` (#99 re-check) | A retry of a store creation in the same session uses the subkeys the session already derived, rather than waiting on a delegate that is asked once per session. | **Yes** -- `a_retry_after_a_failed_publish_reuses_the_key_and_the_backing`, which now answers `GetStoreSubkeys` through the real path instead of hand-filling the record key; red before the fix and with the cache ignored. |
| `custody_flow::expire_custody`, `take_custody`, `spawn_custody_request` (#99 re-check, #101 review) | A custody request nothing answers is given up after `CUSTODY_TIMEOUT_MS`, and one whose send fails is given up at once; a request that finishes takes its timestamp with it, and one with no timestamp is not expired on sight; the seller is told and the vault is free again. | **Partly** -- `an_unanswered_custody_request_times_out`, `a_finished_custody_request_leaves_no_timestamp_behind`, `filling_a_creation_answers_whether_it_filled_one`. The send-failure paths and the timer are wasm-only and compile-checked; the timer re-checks while the request is pending rather than firing once. A send failure is no longer wasm-only state: `on_subkeys_request_failed` holds it and is covered by `a_subkeys_send_failure_releases_the_creation` and `a_subkeys_send_failure_without_a_creation_only_reports` (red with the release or the marker clearing dropped). Only the send itself is wasm-only. |
| `custody_flow::on_store_key_wrapped`, `on_store_key_recovered` (#101 re-review) | Custody runs one store at a time, and the next store's custody starts when the current one answers, success or failure. | **Yes** -- `the_next_store_s_custody_starts_when_the_first_answers`; red with the restart removed from `on_store_key_wrapped`. The recovery path restarts from a wrapper around the whole body, so no exit can forget it; the wrap-signature branch in `state.rs` is not driven by a test. |
| `custody_flow::recheck_record_key`, `start_store_edit_if_ready` (#99 re-check) | Store details that arrive after the subkeys are checked too, the block lifts when a later check agrees, and a pending edit is refused while it holds. | **Yes** -- `a_record_key_block_follows_the_published_details`, `an_edit_is_refused_while_the_record_key_disagrees`. The call from the store-state path is not driven by a test. |
| `StoreStateV1::backing_slots` with copies (#99 re-check) | More copy-only backers than the bound keep the smallest slots, and every merge stays within it. | **Yes** -- `copy_only_backers_past_the_bound_keep_the_smallest_slots` (72 backers; red with copies left out of the ranking). |
| `custody_flow::recovered_registration` mailbox | A recovered store registers the mailbox the store actually uses. | **No, not always.** It derives the mailbox from the RECOVERING backer; the store's mailbox is the founding Ghost Key's. They agree until a store has a second backer, which no UI control makes yet. Phase 1d re-addresses the mailbox by the store key. |
| Mailbox address | Changing a store's backing keeps its mailbox. | **No, and not true yet.** Phase 1b moves the mailbox's encryption key to the store key, not its address, which is still derived from the backing Ghost Key. Phase 1d re-addresses it. |

### The Ghost Key index: harvest#93 phase 1c (added 2026-09-19)

A contract addressed by the Ghost Key alone, listing the stores it has
backed. Mutation results below were each observed red with the named guard
removed or inverted, by a scripted run (`cargo test` filtered to the named
test, original file restored after each), unless the row says otherwise.

| Where | Claim | Caught? |
|---|---|---|
| `common/src/ghostkey_index.rs::IndexEntry::verify`, `GhostKeyIndexV1::verify` | An entry is the Ghost Key's own backing statement, signed by it, in its store key's slot, with a bounded certificate; an index holds at most `MAX_INDEX_ENTRIES`; a refused delta leaves the index unchanged. | **Yes** -- `an_entry_is_the_ghost_keys_own_signed_statement`, `an_entry_under_another_slot_is_refused`, `the_certificate_is_bounded`, `past_the_bound_the_smallest_store_keys_are_kept`; red with the backer, signature, slot, certificate and bound checks removed, and with the verify-before-merge removed. |
| `GhostKeyIndexV1::apply_delta`, `merge`, `normalize` | Grow-only, smaller encoding on a clash, the smallest store keys past the bound; idempotent, commutative, associative, and order-independent for stale-summary deltas. | **Yes** -- `a_clash_resolves_to_the_smaller_encoding_either_way`, `seeded_indexes_obey_the_merge_laws_and_delta_order` (past the bound, 200 law and 200 delta-order cases), `a_delta_brings_the_receiver_up_to_the_sender`; red with the tie-break flipped, the largest kept, and the bound skipped. `fdev verify-merge` on `index`, `index-cap` (unions past the bound, delta steps) and `index-bad`: see the PR. |
| An index entry | Proves the Ghost Key backs the store. | **No, by design.** The Ghost Key alone signs it, so it can name any store key. Readers follow it to the store, whose backing needs the store key's acceptance. |
| `ui/src/index_flow.rs` reading | Only the index of a Ghost Key the USER HOLDS is read, and then every store it lists is loaded; a store never leads this tab to a stranger's index; an index that does not verify is not used at all; it is read once per session, and asking again does not discard what arrived; an index is routed by its id, never taken for a store. | **Yes** -- `a_ghost_keys_index_leads_to_every_store_it_lists`, `a_loaded_store_does_not_lead_to_a_strangers_index`, `an_index_that_does_not_verify_is_ignored`, `an_index_is_read_once_per_session`; red with the user-holds-the-key check, the following, the verify, the routing, the `GhostKeyList` hook and the dedup removed. |
| `index_flow::ensure_indexed` against a FULL index | A store whose key sorts after every entry of a full index is not published again every session, the seller is told once, and a slot freed later in the same session IS taken. | **Yes** -- `a_store_that_cannot_fit_a_full_index_is_not_republished`, which also asserts the freed slot; red with the "said once" marker folded back into `index_entries_published` (#101 re-review S1). **Limit:** while it does not fit, the store is absent from the index, so another device does not find it through that Ghost Key; it still resolves from its own link. Nothing frees a slot today -- the index is grow-only and never reads retirements -- so in practice this needs a different Ghost Key, and it takes 64 stores under one key to reach. |
| `common/src/ghostkey_index.rs::apply_delta` bound | A delta (or a whole state) carrying more than the index can hold is refused BEFORE any signature is checked, so an oversized one costs nothing. | **Yes** -- `an_oversized_delta_is_refused_before_it_is_verified` (duplicate slots and distinct ones); red with the cap removed. |
| `contracts/index-contract` entry points | A non-canonical encoding is refused even when it decodes and verifies; an update that is neither a state nor a delta is refused rather than ignored. | **Yes** -- `a_non_canonical_encoding_is_refused`, `an_unexpected_update_kind_is_refused`. |
| `gateway/index_ops::publish_entry` | A PUT of an existing index contract merges through `update_state` rather than replacing it or being refused. | **Measured, not tested here.** Against a throwaway local node on 2026-09-19 (freenet 0.2.135, stdlib 0.10.0): PUT A then PUT B returned the union, and the node answered the second PUT with `UpdateResponse`. The evidence is recorded on `publish_entry`. A contract needing related contracts during `update_state` is a documented exception in freenet-core; the index requests none. |
| `index_flow::ensure_indexed` | Our store, backed by a connected Ghost Key, is published into that key's index once per session, and not while the index lists it; a store this device cannot sign for is never published by it. | **Yes** -- `our_store_is_added_to_its_backers_index_once`, `a_store_we_do_not_hold_is_not_published`; red with each guard removed. The PUT itself is wasm-only. |
| `state.rs::on_certificate_request_failed` | A certificate request that fails to SEND releases the store edit parked on its answer, so the vault is not blocked for the session. | **Yes** -- `a_failed_certificate_request_releases_the_parked_edit`; red with the release dropped. Asserts another identity's failure does not touch it. The send is wasm-only. |
| `custody_flow::on_custody_send_failed` | A custody request that fails to SEND is retried a bounded number of times, then stops and tells the seller once. | **Yes** -- `a_custody_send_failure_retries_a_bounded_number_of_times`; red with the `custody_attempted` release dropped and with the cap removed. |
| `index_flow::on_index_publish_failed` bound | A publish that keeps failing stops being retried and is reported once, rather than retrying at the store's update rate. | **Yes** -- asserted inside `a_failed_index_publish_is_retried`; red with the cap removed. |
| `index_flow::on_indexed_store_load_failed` placeholder | A `browsing_stores` PLACEHOLDER entry (no details) does not count as arrived state, so the release still happens for a store a link had touched. | **Yes** -- asserted inside `a_failed_index_or_store_get_is_retried`; red with the `contains_key` test restored. |
| `index_flow::on_index_watch_failed`, `on_indexed_store_load_failed` | A GET that fails to send does not leave the Ghost Key index marked as followed, nor the store marked as subscribed, so a later attempt retries; state that has already ARRIVED wins over a late send failure. | **Yes** -- `a_failed_index_or_store_get_is_retried`; red with each `remove` dropped. Found by two independent reviewers (#101 re-review); the GETs themselves are wasm-only. |
| `index_flow::on_index_publish_failed` | A publish that FAILS is not remembered as one, so a later store or index update tries again. | **Yes** -- `a_failed_index_publish_is_retried`; red with the `remove` dropped. Only the call from the failed PUT is wasm-only. |
| `index_flow::follow_indexed_store` predecessors | A store found through an index, and still living under an older store-contract generation, is probed at its predecessor addresses like a registered one. | **No, not driven by a test** (#101 re-review S4). `start_store_key_migration` is wasm-only, as is the whole probe; the call is compile-checked and mirrors the registered-store path in `state.rs`'s `StoresForGhostkey` handler. The live store-move E2E is what exercises it. |
| `gateway/index_ops::index_contract_key` | The index address this build derives is the one the node computes. | **Yes** -- `the_derived_index_key_is_the_one_the_node_computes`. |
| Decision 6.2 before the backer's index arrives | A reader shows a key's stake as still being checked until it has the key's index. | **No, not built.** It shows the verdict from the stores it has loaded. |

## The four that matter

Ranked by what breaks if the claim turns out to be false, not by how easy the
test would be.

### 1. `ui/src/migrate.rs:190` — parameters are derived in one place — **CLOSED STRUCTURALLY 2026-09-05**

**Data survival.** Ranked first when this list was compiled, and fixed rather
than left listed. `create_store_contracts` held a second, hand-maintained copy
of all three parameter structs. If the copies drifted, every derived instance
id named a contract that was never published: the migration probe would walk
addresses that do not exist, take `NotFound` at each, and report a clean
"nothing to migrate" over a seller's entire store — listings, reputation and
mailbox. Silent at every layer: no error, no log, no failing test, green CI.

It ranked first because **it had already happened once in this exact shape** —
a parameter-derivation mismatch is the defect this whole review opened with,
and fixing that symptom had left the structural cause standing. It was also
the only entry whose counterparty is invisible to every automated check in the
repository, `create_store_contracts` being wasm-gated.

There is now one derivation *in the code as written*. The duplication was
worse than recorded: three production copies (store, mailbox, reputation), not
one, plus a fourth in that file's own test module which meant the test could
pass against parameters the real PUT would never produce.
`common/src/delegate.rs` was checked and is already a single shared const.

**This entry was marked CLOSED on 2026-09-05 and that was wrong.** A third
review round mutation-tested the scrape meant to hold the line and beat both
halves of it. Both mutations were reproduced before this correction was
written:

* **The negative half** matches the literal `"StoreParameters {"`. A type
  alias evades it entirely — `use harvest_common::store::StoreParameters as
  SP; let p = SP { seller_verifying_key: vk };` reintroduces the second
  derivation, passes the test, and passes `cargo fmt --check`. That is an
  ordinary refactor, not a contrived evasion.
* **The positive half** asserts the file contains `"migrate::store_params"`.
  It is satisfied by a COMMENT at `ui/src/gateway/store_ops.rs:176` and by the
  `#[cfg(test)]` module, so deleting the production call does not trip it.

One mutation beats both at once, which is how it should have been tested when
it was written. Writing a test to confirm a fix, rather than to attack it, is
the failure this whole document exists to record, and it happened here in the
document itself.

**A wrong "CLOSED" is worse than an open item**, because it stops the next
person looking. That is why this note is longer than the entry it corrects,
and why it stays here now that the entry really is closed.

**The repair, and why it counts as closed this time.** The fields are now
`pub(crate)` with a `new` on each struct, so the invariant is held by the
compiler rather than by a test: outside `harvest-common` a second derivation
does not compile. The aliased mutation that beat the scrape was re-run and
now fails with E0451. This was judged too large when the scrape was chosen —
it edits `harvest-common`, which re-keys every contract — but the committed
WASM is already stale by ten `common/` commits on this branch, so the re-key
and its `contract-rekey-acknowledged` label were pending regardless.

Residual, stated so it is not discovered later as a surprise: nothing stops
someone making a field `pub` again. `contract_parameter_fields_stay_crate_
private` is a substring scrape over three files and catches the ordinary
form of that change; a rename, unusual spacing, or a fourth parameter struct
added elsewhere slips past it. It is a guard on a review-visible change, not
the thing that makes the invariant true.

### 2. `contracts/store-contract/src/lib.rs:100` — the cross-check is additive only — **CLOSED BY REMOVAL 2026-09-18**

**Convergence, and therefore money.** The risk was that a future edit to the
related-contract section would return `Invalid` on a populated, contradicting
Bitcoin address state, so two peers holding byte-identical `StoreStateV1`
could disagree about its validity depending on which had fetched it. Nothing
tested that half; a comment was the whole enforcement.

The section is gone. It never affected validity and existed only to log a line
when an address contract held no claims, while every peer paid up to ten
fetches per validation for it. With no related-contract request in
`validate_state` there is no related state for an edit to gate on, which is a
stronger guard than a test of the absence would be.

### 3. `common/src/store.rs:470` and `:476` — the `OrdersV1::verify` guards
### **CONFIRMED BY EXECUTION 2026-09-05, still open**

**Money, then resource exhaustion.** These two guards are the only thing
standing between a hostile peer's hand-built state and the rest of the order
machinery. The mis-keyed check (`:476`) is the sharper of the pair: every
honest path keys by `record.order.id`, so a mismatch can only arrive from a
constructed state, and downstream code looks orders up by map key while
verifying the record inside — so a record filed under someone else's id is
checked as itself but found as another order.

Both were deleted, one at a time, on 2026-09-05, and `cargo test -p
harvest-common` stayed green for each -- so this entry is now a measurement
rather than a reading. They were the ONLY two hits in a sweep of every guard
this branch touched or added; the sixteen others all failed at least one test
when removed. The sweep is summarised at the end of the messaging section
above. `MAX_ORDERS`
(`:470`) additionally carries the bound that three other comments cite as
established, so one deletion silently falsifies four claims. The equivalent
guard in `mailbox.rs` is tested; this is the same guard, in the state that
holds payment evidence rather than messages.

### 4. `ui/src/migrate.rs:615` and `:620` — no removal path, so `FoldAll` is sound

**Data survival, in the direction that looks like success.** `fold_all_policy`
selects `FoldAll`, which resurrects anything deleted by mere absence, and its
entire soundness argument is that neither listings nor feedback can be deleted.
Add a removal path — a plausible, well-motivated feature — without a tombstone,
and folding an older generation silently reinstates every listing a seller
removed and every retracted piece of feedback. There is no error state: the
migration reports success, and the resurrected data looks like recovered data.

This ranks fourth only because it requires someone to add a feature rather than
to make a mistake. It ranks *this high* because `common/src/store.rs:152`
asserted the opposite — "grow-only with removal by signed deletion", describing
a mechanism that never existed — until it was corrected on 2026-09-05. Someone
reading that line would have concluded a removal path already existed and that
`FoldAll` was already unsound. The two claims contradicted each other across
files for as long as both existed, and nothing brought them together.

### Not in the four, and why

`common/src/payment.rs:526` (purity of `verify_payment_proof`) is the most
severe claim in the file — a clock there diverges the network — but it is
comfortably the least likely to break by accident: the function takes no
capability that would let it, and adding one is a deliberate act. It wants a
source-scrape pin test, not a behavioural one, and it is cheap enough to be
worth doing anyway.

`common/src/store.rs:272` (`to_cbor` is infallible) is unfalsifiable by test
and would surface as a panic rather than a wrong answer.

## A defect class: the optimistic marker (added 2026-09-20)

Written down because it was found **nine times in one change**, and because
the way it was found is the point.

**The shape.** A set-membership or `Option` "already did this / in flight"
marker is claimed BEFORE the operation it guards has succeeded, and the
failure path does not release it. One transient failure then disables a
capability for the rest of the session, with no timeout and no recovery but a
page reload.

**The tells, so it can be grepped for:**

- `.insert(x)` used as a gate through its `bool` return -- "if this returns
  false we already did it".
- Any `spawn_local` whose failure arm only calls `warn!`/`error!` and does not
  clear what the success path clears.
- `self.x = Some(..)` set as an in-flight guard before an async send.

**Why it is in this file.** Native tests are structurally blind to most of it:
the failure arms live in `#[cfg(target_arch = "wasm32")]` blocks, so a green
`cargo test --workspace` is not evidence that any marker is released. The fix
that makes it testable is to split the state change out of the spawned send,
as `on_subkeys_request_failed`, `on_index_publish_failed`,
`on_index_watch_failed`, `on_indexed_store_load_failed`,
`on_certificate_request_failed`, `on_custody_send_failed`,
`on_tip_subscribe_failed`, `on_mailbox_subscribe_failed`,
`on_own_store_subscribe_send_failed`, `on_address_subscribe_failed`,
`on_conversation_key_request_failed`, `on_buyer_conversations_recall_failed`
and `on_store_remember_failed` all now do -- then the release is reachable
off-target and can be mutation-checked.

**How it was found, which is the part worth copying.** Three instances turned
up during the #93 phase-1 review, each spotted by a DIFFERENT reviewer, each
by chance. Treating three-by-accident as a lower bound rather than a closed
set, a deliberate sweep for the shape then found **nine more**. No reviewer
had found the worst of them: `store_state_unavailable` being recorded from a
send that never reached the network, which makes `publish_store_details` read
"nothing is published", publish at version 1, and have the contract silently
drop it as stale -- the exact silent loss of a seller's edit that field exists
to prevent. A defect found repeatedly by accident is a class that has not been
looked for.

**The model to copy: `ui/src/gateway/migrate_ops.rs`.** It registers before
every send too, but gives each registration BOTH a failure deliverer AND a
timeout, and it is the only module in this codebase that does. Everything else
claims a marker and hopes. Its `SESSION_WALKS` claim is never released, and
that is argued in the type's own docs and pinned by tests -- a deliberate
never-release with a written reason is fine; an accidental one is this class.

**Clearing the marker is not automatically the fix.** A marker that gates work
driven by a frequent event turns, when cleared, into an unbounded retry with
no backoff and nothing said. One fix in this round introduced exactly that --
`ensure_indexed` runs on every store-state arrival -- and had to be bounded
afterwards. Cap the attempts and surface the failure at the cap:
`MAX_INDEX_PUBLISH_ATTEMPTS`, `MAX_CUSTODY_SEND_ATTEMPTS`.

**All six instances tracked in harvest#107 are now fixed.** The three that
block a purchase -- the Bitcoin tip contract subscribe, the mailbox
subscribe, and the `store_state_unavailable` inverse described above -- were
fixed in the PR immediately after the phase-1 stack (`on_tip_subscribe_failed`,
`on_mailbox_subscribe_failed`, `on_own_store_subscribe_send_failed`). The
remaining three -- `bitcoin.subscribed`'s watch-contract flavor
(`register_watch_contract`, `watch_purchase_addresses`), conversation key
requests (`ask_for_conversation_keys`), and buyer conversation recalls /
`stores_remembered` (`recall_buyer_conversations`, `remember_store`, and the
queued `RememberStore` path in `sync_remembered_stores`) -- were fixed in the
follow-on PR (`on_address_subscribe_failed`, `on_conversation_key_request_failed`,
`on_buyer_conversations_recall_failed`, `on_store_remember_failed`).
`pending_conversation_key_requests` is a deliberate exception to the bounded-cap
shape: it is released unconditionally on any send failure, mirroring the
delegate-`Err`-answer path that already existed for the same marker, because it
is an ephemeral per-attempt map rather than a persistent "asked once ever"
latch like the other five.
