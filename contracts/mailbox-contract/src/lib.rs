#![allow(unexpected_cfgs)]

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use harvest_common::mailbox::{MailboxDelta, MailboxParameters, MailboxStateV1, MailboxSummaryV2};

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(ValidateResult::Valid);
        }

        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        if !harvest_common::is_canonical_cbor(&mailbox_state, bytes) {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: "State verification failed: state is not in canonical CBOR encoding \
                         (trailing bytes, an unknown key, or a non-minimal encoding)"
                    .into(),
            });
        }

        mailbox_state
            .verify()
            .map(|_| ValidateResult::Valid)
            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("State verification failed: {e}"),
            })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        // Zero bytes in and nothing but zero bytes merged in is zero bytes
        // out, not the encoded default: the two are one state, and answering
        // one with the other made `merge(A, A) != A` for the empty state
        // (`fdev verify-merge`, harvest#55). Anything non-empty arriving
        // switches this off, so merging an encoded default in is still that
        // encoding, whichever side it is on.
        let mut nothing_here = state.as_ref().is_empty();
        let mut mailbox_state = if state.as_ref().is_empty() {
            MailboxStateV1::default()
        } else {
            from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    // Zero bytes means "there is no state here", the same
                    // convention `validate_state`, `summarize_state` and
                    // `get_state_delta` all use, and the same one the `Delta`
                    // arm below already applied. This arm was the odd one out
                    // and answered an empty state with `Deser(UnexpectedEof)`.
                    if new_state.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let new_state = from_reader::<MailboxStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    // Everything, and `apply_delta` decides what is already
                    // held.
                    //
                    // # This arm used to answer that question itself, and got
                    // it wrong
                    //
                    // It filtered on `existing.nonce == m.nonce`, which was
                    // right while the nonce WAS the identity and silently
                    // wrong after `verify`, `summarize`, `delta` and the dedup
                    // moved to `entry_digest`. A PUT or a resync arrives here,
                    // so a peer merging a full state discarded a message
                    // because something else shared its nonce -- which is the
                    // retraction the re-key exists to prevent, by a different
                    // door.
                    //
                    // The fix is not a corrected comparison. It is that this
                    // arm no longer HAS a comparison: `apply_delta` dedups by
                    // `entry_digest`, so handing it everything is both correct
                    // and idempotent, and there is one definition of "the same
                    // message" rather than two that can drift apart.
                    // `no_production_code_compares_message_nonces_for_identity`
                    // is a tripwire for a fifth site answering it again -- read
                    // its own doc for what it does and does not catch, because
                    // it claimed more than it did for a whole round.
                    mailbox_state
                        .apply_delta(&Some(new_state.messages))
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    nothing_here = false;
                    let delta = from_reader::<MailboxDelta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    mailbox_state.apply_delta(&Some(delta)).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        }
                    })?;
                }
                _ => {
                    return Err(ContractError::InvalidUpdate);
                }
            }
        }

        if nothing_here {
            return Ok(UpdateModification::valid(State::from(vec![])));
        }

        let mut updated_state = vec![];
        into_writer(&mailbox_state, &mut updated_state)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        Ok(UpdateModification::valid(updated_state.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let summary = mailbox_state.summarize();
        let mut summary_bytes = vec![];
        into_writer(&summary, &mut summary_bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(summary_bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // Both empties are the SAME convention `summarize_state` above uses
        // and `validate_state` uses: zero bytes means "there is no state
        // here yet", not a malformed encoding. Decoding either as CBOR gives
        // `UnexpectedEof`, so before this the very first exchange a new
        // subscriber makes -- it summarizes its absent state, which is zero
        // bytes, and asks a holder for the difference -- was answered with a
        // decode error rather than the mailbox.
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let old_summary = if summary.as_ref().is_empty() {
            MailboxSummaryV2::default()
        } else {
            from_reader::<MailboxSummaryV2, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        match mailbox_state.delta(&old_summary) {
            Some(delta) => {
                let mut delta_bytes = vec![];
                into_writer(&delta, &mut delta_bytes)
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(delta_bytes))
            }
            None => Ok(StateDelta::from(vec![])),
        }
    }
}

/// The contract's own entry points, which had no tests until 2026-09-05.
///
/// That absence is why the state-merge arm below kept deciding "already
/// held" by nonce for a whole review round after `verify`, `summarize`,
/// `delta` and the dedup had all moved to `entry_digest`: nothing exercised
/// it.
#[cfg(test)]
mod tests {
    use super::*;
    use harvest_common::mailbox::{ConversationId, EncryptedMessage};

    fn message(nonce: [u8; 24], ciphertext: &[u8], seconds: i64) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![2u8; 32],
            ciphertext: ciphertext.to_vec(),
            timestamp: chrono::DateTime::from_timestamp(seconds, 0).expect("timestamp"),
            nonce,
        }
    }

    fn encoded(state: &MailboxStateV1) -> Vec<u8> {
        let mut bytes = vec![];
        into_writer(state, &mut bytes).expect("encode");
        bytes
    }

    fn parameters() -> Parameters<'static> {
        let mut bytes = vec![];
        let owner = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        into_writer(&MailboxParameters::new(owner), &mut bytes).expect("encode");
        Parameters::from(bytes)
    }

    /// Put `data` through the contract and read back the state it produced.
    fn update(state: &MailboxStateV1, data: Vec<UpdateData<'static>>) -> MailboxStateV1 {
        let modification = <Contract as ContractInterface>::update_state(
            parameters(),
            State::from(encoded(state)),
            data,
        )
        .expect("the contract must accept this update");
        let bytes = match modification {
            UpdateModification {
                new_state: Some(s), ..
            } => s.as_ref().to_vec(),
            other => panic!("expected a new state, got {other:?}"),
        };
        from_reader::<MailboxStateV1, &[u8]>(bytes.as_ref()).expect("decode")
    }

    /// **A whole-state merge must not drop a message because something else
    /// shares its nonce.**
    ///
    /// This is the same defect as the one the re-key fixed, at the one site
    /// the re-key missed. A PUT and a resync both arrive as
    /// `UpdateData::State`, so a peer merging a full state would silently
    /// discard the confession and keep the retraction -- the contract's
    /// identity rule says they are two messages, and this arm said they were
    /// one.
    #[test]
    fn a_state_merge_keeps_a_message_whose_nonce_something_else_shares() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        // A peer that already holds the retraction merges a state carrying
        // the confession.
        let held = MailboxStateV1 {
            messages: vec![retraction.clone()],
        };
        let incoming = MailboxStateV1 {
            messages: vec![confession.clone()],
        };

        let merged = update(
            &held,
            vec![UpdateData::State(State::from(encoded(&incoming)))],
        );

        assert!(
            merged.messages.contains(&confession),
            "a whole-state merge dropped a message because another shared its nonce"
        );
        assert!(merged.messages.contains(&retraction));
        merged
            .verify()
            .expect("the contract must accept its own result");
    }

    /// And the same in the other direction, since a merge is not symmetric in
    /// its inputs.
    #[test]
    fn a_state_merge_keeps_the_held_message_too() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let held = MailboxStateV1 {
            messages: vec![confession.clone()],
        };
        let incoming = MailboxStateV1 {
            messages: vec![retraction.clone()],
        };

        let merged = update(
            &held,
            vec![UpdateData::State(State::from(encoded(&incoming)))],
        );
        assert!(merged.messages.contains(&confession));
        assert!(merged.messages.contains(&retraction));
    }

    /// A merge of a state this peer already holds entirely changes nothing,
    /// and in particular does not duplicate anything.
    #[test]
    fn merging_a_state_already_held_changes_nothing() {
        let held = MailboxStateV1 {
            messages: vec![
                message([7u8; 24], b"one", 1_700_000_000),
                message([8u8; 24], b"two", 1_700_000_001),
            ],
        };

        let merged = update(&held, vec![UpdateData::State(State::from(encoded(&held)))]);
        assert_eq!(merged.messages.len(), 2);
        merged.verify().expect("valid");
    }

    /// The delta arm carries whole messages and always did; this is here so
    /// the two arms are covered by the same fixture rather than one of them
    /// being assumed.
    #[test]
    fn a_delta_keeps_a_message_whose_nonce_something_else_shares() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let held = MailboxStateV1 {
            messages: vec![retraction.clone()],
        };
        let mut delta_bytes = vec![];
        into_writer(&vec![confession.clone()], &mut delta_bytes).expect("encode");

        let merged = update(
            &held,
            vec![UpdateData::Delta(StateDelta::from(delta_bytes))],
        );
        assert!(merged.messages.contains(&confession));
        assert!(merged.messages.contains(&retraction));
    }

    /// The state the contract hands back is one it would itself accept -- and
    /// `validate_state` is capable of NOT accepting one.
    ///
    /// **The second half is the load-bearing one, and it was missing.** As
    /// first written this test asserted only that a merged state validates,
    /// which a `validate_state` stubbed to return `Valid` unconditionally
    /// satisfies identically -- verified: that mutation failed zero tests
    /// across the whole workspace, and this is the ONLY test of this
    /// contract's `validate_state` anywhere. What it actually pinned was that
    /// `update_state`'s output CBOR-decodes. A test at an entry point that had
    /// no tests at all, reporting success while measuring nothing, is the
    /// exact shape those tests were added to end.
    ///
    /// The rejection case is a state carrying the same entry twice, which
    /// `MailboxStateV1::verify` refuses -- and which is unreachable through
    /// `update_state`, so `validate_state` is the only thing standing between
    /// it and the network.
    #[test]
    fn a_merged_state_validates_and_an_invalid_one_does_not() {
        let held = MailboxStateV1 {
            messages: vec![message([7u8; 24], b"one", 1_700_000_000)],
        };
        let incoming = MailboxStateV1 {
            messages: vec![message([7u8; 24], b"two", 1_700_000_001)],
        };
        let merged = update(
            &held,
            vec![UpdateData::State(State::from(encoded(&incoming)))],
        );

        let verdict = <Contract as ContractInterface>::validate_state(
            parameters(),
            State::from(encoded(&merged)),
            RelatedContracts::default(),
        )
        .expect("validate");
        assert!(matches!(verdict, ValidateResult::Valid));

        let duplicated = message([7u8; 24], b"one", 1_700_000_000);
        let invalid = MailboxStateV1 {
            messages: vec![duplicated.clone(), duplicated],
        };
        assert!(
            <Contract as ContractInterface>::validate_state(
                parameters(),
                State::from(encoded(&invalid)),
                RelatedContracts::default(),
            )
            .is_err(),
            "validate_state accepted a state holding the same entry twice, which verify \
             rejects -- so it is not consulting verify at all, and the assertion above \
             means nothing"
        );
    }

    /// **A peer that holds nothing yet can still be sent everything.**
    ///
    /// `summarize_state` answers a zero-byte state with a zero-byte summary
    /// -- that is the "I have nothing" summary, and it is the FIRST thing a
    /// new subscriber sends. If the holder cannot decode it, the new
    /// subscriber is answered with an error instead of the mailbox, and it
    /// never bootstraps at all.
    #[test]
    fn a_holder_answers_the_empty_summary_with_everything_it_has() {
        let held = MailboxStateV1 {
            messages: vec![
                message([7u8; 24], b"one", 1_700_000_000),
                message([8u8; 24], b"two", 1_700_000_001),
            ],
        };
        let empty_summary = <Contract as ContractInterface>::summarize_state(
            parameters(),
            State::from(Vec::<u8>::new()),
        )
        .expect("summarizing an absent state must succeed");

        let delta = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            State::from(encoded(&held)),
            empty_summary,
        )
        .expect("a holder must answer the empty summary rather than erroring");

        let carried = from_reader::<MailboxDelta, &[u8]>(delta.as_ref())
            .expect("the delta must be a decodable message list");
        assert_eq!(
            carried.len(),
            2,
            "the empty summary means 'I have nothing', so the answer is everything"
        );
    }

    /// The mirror: a peer that holds nothing has nothing to send, which is an
    /// empty delta and not an error.
    #[test]
    fn a_holder_of_nothing_answers_with_an_empty_delta() {
        let delta = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            State::from(Vec::<u8>::new()),
            StateSummary::from(Vec::<u8>::new()),
        )
        .expect("a peer holding no state must answer, not error");
        assert!(delta.as_ref().is_empty());
    }

    /// **An empty state in an update is "nothing", not a malformed encoding.**
    ///
    /// The `Delta` arm guarded this and the `State` arm did not, so the same
    /// zero bytes were "nothing to merge" through one and
    /// `Deser(UnexpectedEof)` through the other. A small asymmetry, but it is
    /// the same convention `validate_state`, `summarize_state` and
    /// `get_state_delta` follow, and the one inconsistent arm is where the
    /// next reader forms the wrong idea of what zero bytes mean here.
    #[test]
    fn an_empty_state_in_an_update_merges_nothing_rather_than_erroring() {
        let held = MailboxStateV1 {
            messages: vec![message([7u8; 24], b"one", 1_700_000_000)],
        };
        let merged = update(
            &held,
            vec![UpdateData::State(State::from(Vec::<u8>::new()))],
        );
        assert_eq!(
            merged.messages, held.messages,
            "an empty state must leave the mailbox exactly as it was"
        );
    }

    /// **The summary reports what the state actually holds.**
    ///
    /// Found by mutation while re-checking the six tests added with this
    /// module: stubbing `summarize_state` to return an empty summary for a
    /// NON-empty state failed nothing. The empty-summary tests above drive
    /// `get_state_delta` and take the summary as given, so between them they
    /// covered the consumer and left the producer unobserved -- the same
    /// producer/consumer split that let `on_conversation_keys` correlate
    /// positionally for a whole round.
    ///
    /// Asserted as the round trip, because that is the thing the network
    /// performs: a peer summarizes what it has, a holder answers with the
    /// difference, and the difference must be exactly what the asker lacks.
    #[test]
    fn a_summary_of_what_a_peer_holds_asks_only_for_what_it_lacks() {
        let one = message([7u8; 24], b"one", 1_700_000_000);
        let two = message([8u8; 24], b"two", 1_700_000_001);

        let partial = MailboxStateV1 {
            messages: vec![one.clone()],
        };
        let complete = MailboxStateV1 {
            messages: vec![one, two.clone()],
        };

        let summary = <Contract as ContractInterface>::summarize_state(
            parameters(),
            State::from(encoded(&partial)),
        )
        .expect("summarize");

        // Against a holder of both: exactly the one message it lacks.
        let delta = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            State::from(encoded(&complete)),
            summary.clone(),
        )
        .expect("delta");
        let carried = from_reader::<MailboxDelta, &[u8]>(delta.as_ref()).expect("decode");
        assert_eq!(
            carried,
            vec![two],
            "the delta must carry exactly what the summary says is missing -- an empty \
             summary here would ask for the whole mailbox on every sync, and a summary \
             naming everything would ask for nothing and never converge"
        );

        // Against a holder of the same state: nothing.
        let nothing = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            State::from(encoded(&partial)),
            summary,
        )
        .expect("delta");
        assert!(
            nothing.as_ref().is_empty(),
            "a peer that holds exactly what the summary describes has nothing to send"
        );
    }

    /// **No production code decides "the same message" by comparing nonces.**
    ///
    /// A source scrape, because the sites that drifted did so one at a time
    /// over separate changes -- `dedupe_by_nonce`, `summarize`, this
    /// contract's state-merge arm, and `ui/src/migrate.rs::merge_mailbox`.
    /// The first three were each found by a person; the fourth was found by
    /// this scrape, which is the only reason it is here. `entry_digest` is the
    /// one definition of identity. The next one would be the fifth.
    ///
    /// # What it catches, what it does not, and what it used to not catch
    ///
    /// **Read this before trusting it.** For one round this test was cited in
    /// four places as failing "when a site starts answering the question for
    /// itself", and it did nothing of the kind: it matched two literal strings
    /// (`.nonce ==`, `== m.nonce`) over the part of each file preceding its
    /// FIRST `#[cfg(test)]`. Review planted six rewrites of the identical
    /// defect at the exact site the scrape is famous for finding, and it
    /// caught one. Two of the five it missed were not hypothetical: the
    /// `HashSet` + `contains` form is what `summarize` actually was, and the
    /// `sort_by_key` + `dedup_by_key` form is what `dedupe_by_nonce` actually
    /// was.
    ///
    /// Worse, the `#[cfg(test)]` cut was wrong rather than merely leaky.
    /// `#[cfg(test)]` marks individual items, not only a trailing module:
    /// `delegates/harvest-delegate/src/handlers.rs` puts one on a helper 40
    /// lines in, so 1,098 of its 1,138 lines counted as test code and were
    /// never read. The control-form defect, planted below that line, was
    /// invisible; the same line planted above it was caught.
    ///
    /// It now:
    ///
    /// * strips `#[cfg(test)]` items by **brace matching** rather than
    ///   truncating the file at the first one, and skips whole files declared
    ///   as test modules (`#[cfg(test)] mod tests;` pulls in `tests.rs`);
    /// * matches equality on either side of `.nonce` regardless of spacing,
    ///   `.eq`/`.ne`, a set or map keyed on `[u8; 24]`, a `dedup*` on a line
    ///   mentioning a nonce, and a `contains` on one;
    /// * derives the crates to scan from the workspace `Cargo.toml` instead of
    ///   a hardcoded list, and **fails if a directory is missing** rather than
    ///   silently scanning nothing.
    ///
    /// **What it still cannot do.** It is a text scrape. It reads no types, so
    /// a comparison spread across two lines, one hidden behind a helper
    /// (`fn same(a, b) -> bool { a.nonce == b.nonce }` called elsewhere), or
    /// one written through an alias will pass. Its brace matching does not
    /// understand braces inside string literals. It is a tripwire for the
    /// obvious rewrite, not a proof, and the behavioural tests are what
    /// actually carry the property -- every one of the six planted rewrites
    /// was caught by those.
    ///
    /// # Waivers
    ///
    /// There are none. The reputation contract used to carry five, for
    /// deciding feedback identity by `token.nonce` while its signature covered
    /// the token alone (issue #22). Its re-key cut that to one --
    /// `FeedbackEntry::verify` checking that the nonce was DERIVED from the
    /// entry key -- and harvest#53 Phase C deleted feedback entries, tokens
    /// and nonces altogether: a complaint's slot is its order id. The count
    /// is still asserted, so a new site cannot join quietly -- which is the
    /// whole difference between a documented gap and a spreading one.
    ///
    /// A waiver marks a LINE, not a function: it applies to the next line that
    /// is not blank or a comment. That is deliberate, so a waiver written for
    /// one comparison cannot silently cover a second one added below it.
    #[test]
    fn no_production_code_compares_message_nonces_for_identity() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();

        let mut offenders = Vec::new();
        let mut waived = Vec::new();
        let mut scanned = 0usize;

        let files = workspace_rust_files(&root);
        let test_modules = declared_test_modules(&files);

        for path in &files {
            if test_modules.contains(path) {
                continue;
            }
            let text = std::fs::read_to_string(path).expect("read");
            scanned += 1;
            let mut waiver_pending = false;
            for (number, line) in strip_test_items(&text).lines().enumerate() {
                let line = line.trim();
                if line.contains("nonce-identity-waiver:") {
                    waiver_pending = true;
                    continue;
                }
                if line.starts_with("//") {
                    continue;
                }
                let found = decides_identity_by_nonce(line);
                if line.is_empty() {
                    continue;
                }
                if found {
                    let at = format!("{}:{}: {line}", path.display(), number + 1);
                    if waiver_pending {
                        waived.push(at);
                    } else {
                        offenders.push(at);
                    }
                }
                waiver_pending = false;
            }
        }

        assert!(scanned > 40, "the scrape found almost no files: {scanned}");
        assert!(
            offenders.is_empty(),
            "these decide identity by nonce rather than by `entry_digest`. If one is a \
             deliberate, documented gap, add a `nonce-identity-waiver:` comment on the line \
             above naming it, and update the expected waiver count in this test:\n{}",
            offenders.join("\n")
        );
        assert_eq!(
            waived.len(),
            0,
            "the number of waived nonce-identity sites changed. A waiver parks the same \
             defect the mailbox re-key fixed; a new one must be a deliberate decision, not \
             a quiet addition:\n{}",
            waived.join("\n")
        );
    }

    /// Whether one line decides "the same thing" by comparing nonces.
    ///
    /// Whitespace is removed first, so `a.nonce == b` and `a.nonce==b` are one
    /// case -- the shipped version treated them as two and caught only the
    /// first.
    ///
    /// `.cmp(` is deliberately NOT matched: `apply_delta`'s final sort and
    /// `enforce_message_cap`'s rank both order by nonce legitimately, and a
    /// scrape that flagged them would be turned off within a week.
    fn decides_identity_by_nonce(line: &str) -> bool {
        let dense: String = line.chars().filter(|c| !c.is_whitespace()).collect();

        // Equality with `.nonce` on the left.
        if dense.contains(".nonce==")
            || dense.contains(".nonce!=")
            || dense.contains(".nonce.eq(")
            || dense.contains(".nonce.ne(")
        {
            return true;
        }

        // Equality with `.nonce` on the right: walk back from each `.nonce`
        // over the path expression and see what precedes it.
        for (at, _) in dense.match_indices(".nonce") {
            let before = &dense[..at];
            let head = before.trim_end_matches(|c: char| {
                c.is_alphanumeric() || c == '_' || c == '.' || c == '&'
            });
            if head.ends_with("==") || head.ends_with("!=") {
                return true;
            }
        }

        // A set or map keyed on the 24-byte nonce -- what `summarize` was.
        for shape in [
            "HashSet<[u8;24]>",
            "BTreeSet<[u8;24]>",
            "Vec<[u8;24]>",
            "HashMap<[u8;24],",
        ] {
            if dense.contains(shape) {
                return true;
            }
        }

        // Deduplicating or membership-testing on a nonce -- what
        // `dedupe_by_nonce` was, and the shape a `HashSet` built on an earlier
        // line is used through.
        if dense.contains("nonce")
            && (dense.contains("dedup_by_key(")
                || dense.contains("dedup_by(")
                || dense.contains("dedup(")
                || dense.contains(".contains("))
        {
            return true;
        }

        false
    }

    /// Blank out every `#[cfg(test)]` item, by brace matching.
    ///
    /// NOT a truncation at the first occurrence: `#[cfg(test)]` marks
    /// individual functions and `use`s as well as trailing modules, and
    /// truncating there hid 97% of one file.
    ///
    /// Test lines are replaced by empty ones rather than removed, so the line
    /// numbers this test reports are the file's real ones. Removing them
    /// shifted every subsequent number, which sends the reader to the wrong
    /// line of a file they have been told contains a security defect.
    fn strip_test_items(text: &str) -> String {
        let mut kept = String::new();
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("#[cfg(test)]") else {
                kept.push_str(line);
                kept.push('\n');
                continue;
            };
            // The attribute's own line, blanked, so numbering survives.
            kept.push('\n');
            // Consume the attributed item. A braced item ends when its braces
            // balance; an unbraced one (`mod tests;`, `use ...;`) at its
            // semicolon.
            let mut depth = 0i32;
            let mut opened = false;
            let mut pending = if rest.trim().is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            loop {
                let current = match pending.take() {
                    Some(held) => held,
                    None => match lines.next() {
                        Some(next) => next.to_string(),
                        None => break,
                    },
                };
                kept.push('\n');
                depth += current.matches('{').count() as i32;
                depth -= current.matches('}').count() as i32;
                if current.contains('{') {
                    opened = true;
                }
                if opened && depth <= 0 {
                    break;
                }
                if !opened && current.trim_end().ends_with(';') {
                    break;
                }
            }
        }
        kept
    }

    /// Every `.rs` file under the workspace members' `src/`, plus the
    /// rehearsal harness, which is in the repository but not a member.
    ///
    /// Derived from `Cargo.toml` rather than hardcoded, because the shipped
    /// version carried a fixed list of six directories and swallowed a missing
    /// one: a renamed or added crate contributed nothing and the file-count
    /// guard still passed on the rest.
    fn workspace_rust_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let manifest =
            std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
        let members = manifest
            .split("members = [")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("workspace members");
        let mut dirs: Vec<String> = members
            .split(',')
            .filter_map(|entry| {
                let entry = entry.trim().trim_matches('"');
                (!entry.is_empty()).then(|| format!("{entry}/src"))
            })
            .collect();
        assert!(
            dirs.len() >= 6,
            "parsed {} workspace members, which is fewer than exist -- the manifest format \
             changed and this scrape is now reading almost nothing",
            dirs.len()
        );
        dirs.push("tests/rehearsal/src".to_string());

        let mut found = Vec::new();
        for dir in dirs {
            let path = root.join(&dir);
            assert!(
                path.is_dir(),
                "{dir} is not a directory; the scrape would have skipped it in silence"
            );
            collect_rust_files(&path, &mut found);
        }
        found
    }

    /// Files pulled in as test modules by a `#[cfg(test)] mod name;`.
    ///
    /// `ui/src/migrate.rs` declares one, so `ui/src/migrate/tests.rs` is
    /// entirely test code with no `#[cfg(test)]` of its own inside it.
    fn declared_test_modules(
        files: &[std::path::PathBuf],
    ) -> std::collections::HashSet<std::path::PathBuf> {
        let mut modules = std::collections::HashSet::new();
        for path in files {
            let text = std::fs::read_to_string(path).expect("read");
            // The module directory for `foo.rs` is `foo/`; for `mod.rs`,
            // `lib.rs` and `main.rs` it is the file's own directory.
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let dir = match stem {
                "mod" | "lib" | "main" => path.parent().map(|p| p.to_path_buf()),
                _ => path.parent().map(|p| p.join(stem)),
            };
            let Some(dir) = dir else { continue };
            for (at, _) in text.match_indices("#[cfg(test)]") {
                let after = text[at..].lines().nth(1).unwrap_or_default().trim();
                if let Some(name) = after
                    .strip_prefix("mod ")
                    .and_then(|rest| rest.strip_suffix(';'))
                {
                    modules.insert(dir.join(format!("{}.rs", name.trim())));
                    modules.insert(dir.join(name.trim()).join("mod.rs"));
                }
            }
        }
        modules
    }

    fn collect_rust_files(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("{} could not be read: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rust_files(&path, found);
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
}

#[cfg(test)]
mod empty_state_tests {
    use super::*;
    use harvest_common::mailbox::MailboxStateV1;

    fn parameters() -> Parameters<'static> {
        let owner = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        let mut bytes = vec![];
        into_writer(&MailboxParameters::new(owner), &mut bytes).expect("encode");
        Parameters::from(bytes)
    }

    /// **The empty state merged with itself is the empty state** (harvest#55,
    /// found by `fdev verify-merge`). `update_state` answered zero bytes with
    /// the encoded default, so `merge(A, A) != A` for the empty state. And an
    /// encoded default merged in from either side stays that encoding, so
    /// the rule does not break commutativity instead.
    #[test]
    fn the_empty_state_is_idempotent_and_the_rule_is_commutative() {
        let merge = |state: Vec<u8>, other: Vec<u8>| -> Vec<u8> {
            <Contract as ContractInterface>::update_state(
                parameters(),
                State::from(state),
                vec![UpdateData::State(State::from(other))],
            )
            .expect("merge")
            .unwrap_valid()
            .as_ref()
            .to_vec()
        };
        assert!(
            merge(vec![], vec![]).is_empty(),
            "merge(empty, empty) must be empty"
        );
        let mut default = vec![];
        into_writer(&MailboxStateV1::default(), &mut default).expect("encode");
        assert_eq!(merge(vec![], default.clone()), default);
        assert_eq!(merge(default.clone(), vec![]), default);
    }

    /// A non-empty delta applied to the empty state is an update, so the
    /// result is the encoded state, not zero bytes. Without this the
    /// empty-state rule above would swallow a delta's content.
    #[test]
    fn a_delta_applied_to_the_empty_state_is_encoded() {
        let mut delta = vec![];
        into_writer(
            &Vec::<harvest_common::mailbox::EncryptedMessage>::new(),
            &mut delta,
        )
        .expect("encode");
        let out = <Contract as ContractInterface>::update_state(
            parameters(),
            State::from(vec![]),
            vec![UpdateData::Delta(StateDelta::from(delta))],
        )
        .expect("update")
        .unwrap_valid()
        .as_ref()
        .to_vec();
        let mut default = vec![];
        into_writer(&MailboxStateV1::default(), &mut default).expect("encode");
        assert_eq!(out, default);
    }

    /// **`validate_state` refuses a state that is not byte-canonical (PR
    /// #82 review, Should Fix 2).** Each of these decoded to a valid state
    /// and was accepted, then rewritten by the next merge, while its summary
    /// matched a canonical peer's so no delta ever repaired it.
    #[test]
    fn validate_state_refuses_non_canonical_bytes() {
        let validate = |bytes: Vec<u8>| {
            <Contract as ContractInterface>::validate_state(
                parameters(),
                State::from(bytes),
                RelatedContracts::new(),
            )
        };
        let mut canonical = vec![];
        into_writer(
            &harvest_common::mailbox::MailboxStateV1::default(),
            &mut canonical,
        )
        .expect("encode");
        assert!(
            matches!(validate(canonical.clone()), Ok(ValidateResult::Valid)),
            "the canonical encoding validates"
        );

        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert!(
            validate(trailing).is_err(),
            "a trailing byte must be refused"
        );

        #[derive(serde::Serialize)]
        struct WithExtraKey<T> {
            #[serde(flatten)]
            state: T,
            unknown: u8,
        }
        let mut extra = vec![];
        into_writer(
            &WithExtraKey {
                state: harvest_common::mailbox::MailboxStateV1::default(),
                unknown: 1,
            },
            &mut extra,
        )
        .expect("encode");
        assert!(validate(extra).is_err(), "an unknown key must be refused");
    }
}
