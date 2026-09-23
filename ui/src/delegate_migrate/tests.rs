//! The walk, driven through the real `freenet_migrate` driver against a
//! scripted node: old delegates that answer, go missing or go silent, and a
//! current delegate that keeps secrets and markers the way the harvest
//! delegate does. The delegate's own per-family import rules are tested in
//! `delegates/harvest-delegate/src/import.rs`; this is the part in between.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};

use super::*;

/// How an old delegate behaves.
#[derive(Clone)]
enum Old {
    /// Registered, and holds these secrets.
    Holds(Vec<(Vec<u8>, Vec<u8>)>),
    /// Registered, answers the cheap read, never answers the export.
    SilentOnExport,
    /// Registered, answers nothing at all.
    Silent,
}

#[derive(Default)]
struct Node {
    /// Old delegates this node has registered. Anything else is `Missing`.
    old: HashMap<[u8; 32], Old>,
    /// The current delegate's secrets.
    secrets: BTreeMap<Vec<u8>, Vec<u8>>,
    markers: HashMap<[u8; 32], PredecessorMarkerState>,
    /// Every delegate key a message was sent to, in order.
    asked: Vec<[u8; 32]>,
    /// The current delegate refuses every marker write.
    refuse_markers: bool,
    /// The current delegate answers every import with something else.
    garbled_imports: bool,
    /// Travelling records carried by each predecessor, staged until it is
    /// sealed.
    staged: HashMap<[u8; 32], Vec<Vec<u8>>>,
    /// A key the current delegate refuses, permanently.
    reject_key: Option<Vec<u8>>,
    /// A key the current delegate refuses for now (a retry may take it).
    retry_key: Option<Vec<u8>>,
}

fn folded(predecessor: &[u8; 32]) -> Vec<u8> {
    let hex: String = predecessor.iter().map(|b| format!("{b:02x}")).collect();
    format!("harvest:folded:{hex}").into_bytes()
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Node>>);

const CURRENT: [u8; 32] = [0xCC; 32];

fn key(bytes: [u8; 32]) -> DelegateKey {
    DelegateKey::new(bytes, CodeHash::new([0; 32]))
}

fn cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    harvest_common::to_cbor(v).expect("encode")
}

impl DelegateCalls for Fake {
    async fn call(
        &mut self,
        delegate: &DelegateKey,
        payload: Vec<u8>,
        _expect: Expect,
    ) -> Result<Reply, CallError> {
        let mut node = self.0.borrow_mut();
        let target: [u8; 32] = delegate.bytes().try_into().expect("32-byte key");
        node.asked.push(target);
        if target == CURRENT {
            let request: HarvestDelegateRequest =
                harvest_common::from_cbor(&payload).expect("a harvest request");
            let response = match request {
                // As the real delegate: a travelling "folded" record counts as
                // done, and sealing writes one.
                HarvestDelegateRequest::GetPredecessorMarker { predecessor } => {
                    let marker = node.markers.get(&predecessor).copied().or_else(|| {
                        node.secrets
                            .contains_key(&folded(&predecessor))
                            .then_some(PredecessorMarkerState::Done { had_data: true })
                    });
                    HarvestDelegateResponse::PredecessorMarker {
                        predecessor,
                        marker,
                    }
                }
                HarvestDelegateRequest::RecordPredecessorMarker {
                    predecessor,
                    marker,
                } => {
                    let recorded = !node.refuse_markers;
                    if recorded {
                        node.markers.insert(predecessor, marker);
                        if matches!(marker, PredecessorMarkerState::Done { .. }) {
                            // Promote what this predecessor carried, then
                            // write its own travelling record.
                            let carried: Vec<Vec<u8>> =
                                node.staged.remove(&predecessor).unwrap_or_default();
                            for key in carried {
                                node.secrets.insert(key, b"1".to_vec());
                            }
                            node.secrets.insert(folded(&predecessor), b"1".to_vec());
                        }
                    }
                    HarvestDelegateResponse::PredecessorMarkerRecorded {
                        predecessor,
                        marker,
                        recorded,
                    }
                }
                // A carried travelling record is staged until its carrier is
                // sealed, as the real delegate does.
                HarvestDelegateRequest::ImportMigratedSecret {
                    predecessor, key, ..
                } if key.starts_with(b"harvest:folded:")
                    && !node.garbled_imports
                    && node.retry_key.as_ref() != Some(&key) =>
                {
                    node.staged
                        .entry(predecessor)
                        .or_default()
                        .push(key.clone());
                    HarvestDelegateResponse::MigratedSecretImported {
                        predecessor,
                        key,
                        outcome: SecretImport::Written,
                    }
                }
                HarvestDelegateRequest::ImportMigratedSecret {
                    predecessor, key, ..
                } if node.retry_key.as_ref() == Some(&key) => {
                    HarvestDelegateResponse::MigratedSecretImported {
                        predecessor,
                        key,
                        outcome: SecretImport::Retryable("full".into()),
                    }
                }
                HarvestDelegateRequest::ImportMigratedSecret {
                    predecessor, key, ..
                } if node.reject_key.as_ref() == Some(&key) => {
                    HarvestDelegateResponse::MigratedSecretImported {
                        predecessor,
                        key,
                        outcome: SecretImport::Permanent("refused".into()),
                    }
                }
                HarvestDelegateRequest::ImportMigratedSecret { predecessor, .. }
                    if node.garbled_imports =>
                {
                    HarvestDelegateResponse::PredecessorMarker {
                        predecessor,
                        marker: None,
                    }
                }
                HarvestDelegateRequest::ImportMigratedSecret {
                    predecessor,
                    key,
                    value,
                } => {
                    // Never-clobber, as the real delegate's standalone arm.
                    let outcome = if node.secrets.contains_key(&key) {
                        SecretImport::AlreadyAuthoritative
                    } else {
                        node.secrets.insert(key.clone(), value.0);
                        SecretImport::Written
                    };
                    HarvestDelegateResponse::MigratedSecretImported {
                        predecessor,
                        key,
                        outcome,
                    }
                }
                other => panic!("the walk sent the current delegate {other:?}"),
            };
            return Ok(Reply::Payloads(vec![cbor(&response)]));
        }
        let Some(old) = node.old.get(&target).cloned() else {
            return Ok(Reply::Missing);
        };
        if matches!(old, Old::Silent) {
            return Err(CallError::Timeout);
        }
        if let Ok(HarvestMigrationRequest::ExportSecrets { source_generation }) =
            harvest_common::from_cbor::<HarvestMigrationRequest>(&payload)
        {
            return match old {
                Old::SilentOnExport | Old::Silent => Err(CallError::Timeout),
                Old::Holds(secrets) => {
                    Ok(Reply::Payloads(vec![freenet_migrate::ExportedSecrets {
                        source_generation,
                        secrets,
                    }
                    .to_bytes()
                    .expect("encode export")]))
                }
            };
        }
        // The cheap read.
        Ok(Reply::Payloads(vec![cbor(
            &HarvestDelegateResponse::StoreList {
                ghostkey_fingerprint: String::new(),
                stores: Vec::new(),
                held_store_keys: None,
            },
        )]))
    }
}

fn generation(n: u32) -> [u8; 32] {
    exporting_predecessors()
        .iter()
        .find(|e| e.generation == n)
        .unwrap_or_else(|| panic!("no V{n} in the registry"))
        .delegate_key
}

fn run(fake: &Fake) -> DelegateMigrationReport {
    outcome(fake).report
}

fn outcome(fake: &Fake) -> Outcome {
    futures::executor::block_on(migrate(fake.clone(), key(CURRENT)))
}

fn secret(fake: &Fake, k: &str) -> Option<Vec<u8>> {
    fake.0.borrow().secrets.get(k.as_bytes()).cloned()
}

/// **The point of harvest#123.** A predecessor's secrets arrive at the
/// current delegate, the predecessor is sealed, and a second load imports
/// nothing again. Mutated red by never calling `migrate` from the transport
/// side (no import), and by dropping the `Done` marker write.
#[test]
fn a_predecessors_secrets_arrive_and_the_walk_seals_it() {
    let fake = Fake::default();
    fake.0.borrow_mut().old.insert(
        generation(18),
        Old::Holds(vec![
            (b"harvest:rsa_sk:fp1".to_vec(), b"sk".to_vec()),
            (b"harvest:buyer_conv:s:t".to_vec(), b"conv".to_vec()),
        ]),
    );
    let report = run(&fake);
    assert!(imported_anything(&report), "{}", summarize(&report));
    assert_eq!(
        secret(&fake, "harvest:rsa_sk:fp1").as_deref(),
        Some(&b"sk"[..])
    );
    assert_eq!(
        secret(&fake, "harvest:buyer_conv:s:t").as_deref(),
        Some(&b"conv"[..])
    );
    assert_eq!(
        fake.0.borrow().markers.get(&generation(18)),
        Some(&PredecessorMarkerState::Done { had_data: true })
    );

    let again = run(&fake);
    assert!(
        !imported_anything(&again),
        "a sealed predecessor is not re-imported"
    );
    assert!(again.predecessors.iter().any(|p| matches!(
        p,
        PredecessorMigration::AlreadyMigrated { generation: 18, .. }
    )));
}

/// A generation the node never ran must not hide an older one's secrets:
/// every release the user skipped is `Missing`. Mutated red by switching the
/// policy to `NewestSnapshotWins`.
#[test]
fn a_skipped_generation_does_not_hide_an_older_one() {
    let fake = Fake::default();
    // V18 and V17 were never registered on this node; V16 was.
    fake.0.borrow_mut().old.insert(
        generation(16),
        Old::Holds(vec![(b"harvest:rsa_pk:fp1".to_vec(), b"pk".to_vec())]),
    );
    run(&fake);
    assert_eq!(
        secret(&fake, "harvest:rsa_pk:fp1").as_deref(),
        Some(&b"pk"[..])
    );
}

/// The newest generation's value wins a key two generations share, because
/// they are offered newest first and the current delegate never overwrites.
#[test]
fn the_newest_generations_value_wins() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.old.insert(
            generation(18),
            Old::Holds(vec![(b"harvest:rsa_sk:fp1".to_vec(), b"newer".to_vec())]),
        );
        node.old.insert(
            generation(12),
            Old::Holds(vec![(b"harvest:rsa_sk:fp1".to_vec(), b"older".to_vec())]),
        );
    }
    run(&fake);
    assert_eq!(
        secret(&fake, "harvest:rsa_sk:fp1").as_deref(),
        Some(&b"newer"[..])
    );
}

/// A predecessor that runs but never answers the export is not sealed: an
/// unanswered export is not an empty one. Mutated red by mapping a timeout in
/// `fetch_secrets` to `Ok(vec![])`.
#[test]
fn a_silent_export_is_never_sealed() {
    let fake = Fake::default();
    fake.0
        .borrow_mut()
        .old
        .insert(generation(18), Old::SilentOnExport);
    let report = run(&fake);
    assert!(
        !fake.0.borrow().markers.contains_key(&generation(18)),
        "{}",
        summarize(&report)
    );
    assert!(report.any_unresponsive());
}

/// The successor's own value stands.
#[test]
fn a_secret_the_current_delegate_holds_is_kept() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.secrets
            .insert(b"harvest:rsa_sk:fp1".to_vec(), b"minted-here".to_vec());
        node.old.insert(
            generation(18),
            Old::Holds(vec![(b"harvest:rsa_sk:fp1".to_vec(), b"old".to_vec())]),
        );
    }
    run(&fake);
    assert_eq!(
        secret(&fake, "harvest:rsa_sk:fp1").as_deref(),
        Some(&b"minted-here"[..])
    );
}

/// V1 to V4 cannot export, so they are never asked. Mutated red by removing
/// the generation filter in `exporting_predecessors`.
#[test]
fn generations_without_an_export_handler_are_not_asked() {
    let fake = Fake::default();
    run(&fake);
    let asked = fake.0.borrow().asked.clone();
    let registry = crate::migrate::delegate_lineage();
    for entry in registry
        .iter()
        .filter(|e| e.generation < FIRST_EXPORTING_GENERATION)
    {
        assert!(
            !asked.contains(&entry.delegate_key),
            "V{} was asked, and cannot answer",
            entry.generation
        );
    }
    assert!(asked.contains(&generation(FIRST_EXPORTING_GENERATION)));
}

/// Every way an export answer can fail to be one is an error, never an empty
/// export, which would seal. Mutated red by returning `Ok(vec![])` from the
/// fall-through, and by dropping the generation check.
#[test]
fn only_an_answered_export_for_the_asked_generation_counts() {
    let export = |g: u32, secrets: Vec<(Vec<u8>, Vec<u8>)>| {
        freenet_migrate::ExportedSecrets {
            source_generation: g,
            secrets,
        }
        .to_bytes()
        .unwrap()
    };
    assert_eq!(
        interpret_export(Reply::Payloads(vec![export(7, vec![])]), 7),
        Ok(vec![]),
        "an answered empty export is the one genuine empty"
    );
    assert!(interpret_export(Reply::Payloads(vec![export(6, vec![])]), 7).is_err());
    assert!(interpret_export(Reply::Missing, 7).is_err());
    assert!(interpret_export(Reply::Payloads(vec![b"not an export".to_vec()]), 7).is_err());
    assert!(interpret_export(Reply::Payloads(vec![]), 7).is_err());
}

/// An answer from the current delegate is taken only if it is the one asked
/// for: the same delegate answers the whole app. Mutated red by matching on
/// the variant alone.
#[test]
fn an_answer_about_another_predecessor_or_key_is_not_taken() {
    let expect = Expect::SecretImported {
        predecessor: [1; 32],
        key: b"harvest:a".to_vec(),
    };
    let answer = |p: [u8; 32], k: &[u8]| HarvestDelegateResponse::MigratedSecretImported {
        predecessor: p,
        key: k.to_vec(),
        outcome: SecretImport::Written,
    };
    assert!(expect.matches(&answer([1; 32], b"harvest:a")));
    assert!(!expect.matches(&answer([2; 32], b"harvest:a")));
    assert!(!expect.matches(&answer([1; 32], b"harvest:b")));
    assert!(!Expect::PredecessorMarker([1; 32]).matches(
        &HarvestDelegateResponse::PredecessorMarker {
            predecessor: [2; 32],
            marker: None,
        }
    ));
}

/// A retryable refusal must not become `AlreadyAuthoritative`, which the
/// crate seals on.
#[test]
fn a_refusal_is_never_reported_as_authoritative() {
    assert!(matches!(
        to_item_write(SecretImport::Retryable("full".into())),
        ItemWrite::Failed {
            retry: freenet_migrate::RetryAdvice::Retryable,
            ..
        }
    ));
    assert!(matches!(
        to_item_write(SecretImport::Permanent("no".into())),
        ItemWrite::Failed {
            retry: freenet_migrate::RetryAdvice::Permanent,
            ..
        }
    ));
}

/// **A newer generation that is registered but silent stops the walk**, so
/// an older generation cannot land its values first and then stand for good
/// (the import never overwrites). When the newer one answers on a later load,
/// ITS value wins. Mutated red by not halting on a silent export, and by
/// halting on `Missing` too (which `a_skipped_generation_does_not_hide_an_older_one`
/// catches).
#[test]
fn a_silent_newer_generation_stops_the_walk_until_it_answers() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.old.insert(generation(18), Old::SilentOnExport);
        node.old.insert(
            generation(12),
            Old::Holds(vec![(b"harvest:x25519_sk:fp1".to_vec(), b"older".to_vec())]),
        );
    }
    let first = outcome(&fake);
    assert!(first.walk.halted);
    assert!(!first.complete());
    assert_eq!(
        secret(&fake, "harvest:x25519_sk:fp1"),
        None,
        "nothing older lands first"
    );
    assert!(!fake.0.borrow().markers.contains_key(&generation(12)));

    fake.0.borrow_mut().old.insert(
        generation(18),
        Old::Holds(vec![(b"harvest:x25519_sk:fp1".to_vec(), b"newer".to_vec())]),
    );
    let second = outcome(&fake);
    assert!(second.complete(), "{}", summarize(&second.report));
    assert_eq!(
        secret(&fake, "harvest:x25519_sk:fp1").as_deref(),
        Some(&b"newer"[..])
    );
}

/// **A deletion made on the new generation survives the NEXT re-key.** V17
/// sealed V16 and travels a record of it; a later walk that imports V17 then
/// treats V16 as done instead of re-importing what V17 no longer holds.
/// Mutated red by not honouring the travelling record in the marker lookup.
#[test]
fn a_generation_folded_into_a_newer_one_is_not_walked_again() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        // V17 had already folded V16 in, and the buyer then forgot the
        // conversation V16 still holds.
        node.old.insert(
            generation(17),
            Old::Holds(vec![
                (b"harvest:rsa_pk:fp1".to_vec(), b"pk".to_vec()),
                (folded(&generation(16)), b"1".to_vec()),
            ]),
        );
        node.old.insert(
            generation(16),
            Old::Holds(vec![(
                b"harvest:buyer_conv:s:forgotten".to_vec(),
                b"conv".to_vec(),
            )]),
        );
    }
    run(&fake);
    assert_eq!(
        secret(&fake, "harvest:rsa_pk:fp1").as_deref(),
        Some(&b"pk"[..])
    );
    assert_eq!(
        secret(&fake, "harvest:buyer_conv:s:forgotten"),
        None,
        "the conversation forgotten on V17 stays forgotten"
    );
}

/// A marker write the current delegate refuses leaves the predecessor
/// unsealed, and the walk incomplete. Mutated red by returning `Ok(())` from
/// `record_marker` whatever the answer.
#[test]
fn a_refused_marker_leaves_the_predecessor_unsealed() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.refuse_markers = true;
        node.old.insert(
            generation(18),
            Old::Holds(vec![(b"harvest:rsa_pk:fp1".to_vec(), b"pk".to_vec())]),
        );
    }
    let out = outcome(&fake);
    assert!(!fake.0.borrow().markers.contains_key(&generation(18)));
    assert!(!out.complete(), "{}", summarize(&out.report));
}

/// An import answered with something else is a retry, never a success the
/// crate would seal on.
#[test]
fn an_unexpected_import_answer_is_never_success() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.garbled_imports = true;
        node.old.insert(
            generation(18),
            Old::Holds(vec![(b"harvest:rsa_pk:fp1".to_vec(), b"pk".to_vec())]),
        );
    }
    let out = outcome(&fake);
    assert!(!matches!(
        fake.0.borrow().markers.get(&generation(18)),
        Some(PredecessorMarkerState::Done { .. })
    ));
    assert!(!out.complete());
}

/// The recorded-marker answer is matched on its predecessor, and the export
/// expectation takes only an export.
#[test]
fn the_other_expectations_match_only_their_own_answer() {
    let recorded = |p: [u8; 32]| HarvestDelegateResponse::PredecessorMarkerRecorded {
        predecessor: p,
        marker: PredecessorMarkerState::Done { had_data: true },
        recorded: true,
    };
    assert!(Expect::PredecessorMarkerRecorded([1; 32]).matches(&recorded([1; 32])));
    assert!(!Expect::PredecessorMarkerRecorded([1; 32]).matches(&recorded([2; 32])));
    assert!(!Expect::PredecessorMarkerRecorded([1; 32]).matches(
        &HarvestDelegateResponse::PredecessorMarker {
            predecessor: [1; 32],
            marker: None,
        }
    ));
    let export = freenet_migrate::ExportedSecrets {
        source_generation: 5,
        secrets: vec![],
    }
    .to_bytes()
    .unwrap();
    assert!(Expect::Export.accepts_payload(&export));
    assert!(
        !Expect::Export.accepts_payload(&cbor(&HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: String::new(),
            stores: Vec::new(),
            held_store_keys: None,
        }))
    );
}

/// Imported RSA public keys are named by fingerprint, so the app asks for
/// exactly those and no others.
#[test]
fn only_imported_rsa_keys_are_asked_for() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.secrets
            .insert(b"harvest:rsa_pk:held".to_vec(), b"pk".to_vec());
        node.old.insert(
            generation(18),
            Old::Holds(vec![
                (b"harvest:rsa_pk:held".to_vec(), b"old".to_vec()),
                (b"harvest:rsa_pk:new".to_vec(), b"pk".to_vec()),
                (b"harvest:rsa_sk:new".to_vec(), b"sk".to_vec()),
            ]),
        );
    }
    assert_eq!(
        outcome(&fake).imported_rsa_fingerprints(),
        vec!["new".to_string()]
    );
}

/// The gate runs deferred work only after a walk that reached every
/// generation, and drops it for this load otherwise; there is no "go ahead
/// anyway". Mutated red by releasing on an incomplete walk.
#[test]
fn deferred_work_waits_for_a_complete_walk() {
    let mut gate = SettleGate::default();
    assert_eq!(gate.defer(1), None, "queued while the walk runs");
    assert_eq!(gate.settle(true), vec![1]);
    assert_eq!(gate.defer(2), Some(2), "runs at once after a complete walk");
    assert!(
        gate.settle(false).is_empty(),
        "a second settle changes nothing"
    );
    assert_eq!(gate.defer(3), Some(3));

    let mut gate = SettleGate::default();
    assert_eq!(gate.defer(1), None);
    assert!(
        gate.settle(false).is_empty(),
        "an incomplete walk releases nothing"
    );
    assert_eq!(
        gate.defer(2),
        None,
        "and later work is dropped for this load"
    );
}

/// The same, when the newer generation does not even answer the probe: a
/// timeout is not `Missing`, so it halts too. Mutated red by not halting on
/// a probe timeout.
#[test]
fn a_newer_generation_silent_to_the_probe_stops_the_walk() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.old.insert(generation(18), Old::Silent);
        node.old.insert(
            generation(12),
            Old::Holds(vec![(b"harvest:x25519_sk:fp1".to_vec(), b"older".to_vec())]),
        );
    }
    let out = outcome(&fake);
    assert!(out.walk.halted);
    assert_eq!(secret(&fake, "harvest:x25519_sk:fp1"), None);
}

/// Halting alone makes a walk incomplete, even when no later predecessor is
/// left to fail: here the silent generation is the oldest one walked.
/// Mutated red by dropping `!halted` from `Outcome::complete`.
#[test]
fn a_halt_on_the_last_generation_still_leaves_the_walk_incomplete() {
    let fake = Fake::default();
    fake.0
        .borrow_mut()
        .old
        .insert(generation(FIRST_EXPORTING_GENERATION), Old::Silent);
    let out = outcome(&fake);
    assert!(out.walk.halted);
    assert!(!out.complete(), "{}", summarize(&out.report));
}

/// A travelling record carried by a predecessor that did NOT finish is not
/// in effect: the generation it names is still walked. Mutated red by
/// honouring staged records.
#[test]
fn a_record_carried_by_an_unfinished_generation_is_not_in_effect() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        // V17 carries "V16 folded", but one of its items is refused, so V17
        // is not sealed.
        node.reject_key = Some(b"harvest:broken".to_vec());
        node.old.insert(
            generation(17),
            Old::Holds(vec![
                (folded(&generation(16)), b"1".to_vec()),
                (b"harvest:broken".to_vec(), b"x".to_vec()),
            ]),
        );
        node.old.insert(
            generation(16),
            Old::Holds(vec![(b"harvest:x25519_sk:fp1".to_vec(), b"v16".to_vec())]),
        );
    }
    run(&fake);
    assert_eq!(
        secret(&fake, "harvest:x25519_sk:fp1").as_deref(),
        Some(&b"v16"[..]),
        "V16 was still walked"
    );
}

/// **A carrier that did not finish for a reason a retry fixes stops the
/// walk**, rather than letting the generation it folded in be walked in the
/// same run -- which would bring back whatever the carrier had deleted since,
/// for good. (A carrier that failed only permanently lets the walk go on:
/// `a_record_carried_by_an_unfinished_generation_is_not_in_effect`.) Mutated
/// red by not halting on a blocked carrier.
#[test]
fn a_retryably_unfinished_carrier_stops_the_walk() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.retry_key = Some(b"harvest:busy".to_vec());
        node.old.insert(
            generation(17),
            Old::Holds(vec![
                (folded(&generation(16)), b"1".to_vec()),
                (b"harvest:busy".to_vec(), b"x".to_vec()),
            ]),
        );
        node.old.insert(
            generation(16),
            Old::Holds(vec![(
                b"harvest:buyer_conv:s:forgotten".to_vec(),
                b"conv".to_vec(),
            )]),
        );
    }
    let out = outcome(&fake);
    assert!(out.walk.halted, "{}", summarize(&out.report));
    assert_eq!(
        secret(&fake, "harvest:buyer_conv:s:forgotten"),
        None,
        "V16, folded into V17, is not walked while V17 is only waiting on a retry"
    );
}

/// The same when it is the travelling record's OWN write that is waiting on
/// a retry. Mutated red by counting only a written record as staged.
#[test]
fn a_carrier_whose_travelling_record_is_waiting_on_a_retry_stops_the_walk() {
    let fake = Fake::default();
    {
        let mut node = fake.0.borrow_mut();
        node.retry_key = Some(folded(&generation(16)));
        node.old.insert(
            generation(17),
            Old::Holds(vec![(folded(&generation(16)), b"1".to_vec())]),
        );
        node.old.insert(
            generation(16),
            Old::Holds(vec![(
                b"harvest:buyer_conv:s:forgotten".to_vec(),
                b"conv".to_vec(),
            )]),
        );
    }
    let out = outcome(&fake);
    assert!(out.walk.halted, "{}", summarize(&out.report));
    assert_eq!(secret(&fake, "harvest:buyer_conv:s:forgotten"), None);
}
