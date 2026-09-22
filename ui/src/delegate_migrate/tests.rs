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
                HarvestDelegateRequest::GetPredecessorMarker { predecessor } => {
                    HarvestDelegateResponse::PredecessorMarker {
                        predecessor,
                        marker: node.markers.get(&predecessor).copied(),
                    }
                }
                HarvestDelegateRequest::RecordPredecessorMarker {
                    predecessor,
                    marker,
                } => {
                    node.markers.insert(predecessor, marker);
                    HarvestDelegateResponse::PredecessorMarkerRecorded {
                        predecessor,
                        marker,
                        recorded: true,
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
        if let Ok(HarvestMigrationRequest::ExportSecrets { source_generation }) =
            harvest_common::from_cbor::<HarvestMigrationRequest>(&payload)
        {
            return match old {
                Old::SilentOnExport => Err(CallError::Timeout),
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
