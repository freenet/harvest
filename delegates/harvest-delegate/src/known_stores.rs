//! The stores this node has visited, so a buyer's store list outlives the tab
//! (harvest#52).
//!
//! # Why here and not in the browser
//!
//! The Harvest page runs in an iframe with an opaque origin, where
//! `localStorage` and every other browser store throw (see
//! `docs/buyer-conversation-persistence.md`, "Constraint 1"). The delegate is
//! the only durable store the app has, and it is also the only one that a
//! buyer's other devices could ever share, which is where archiving a store
//! on a laptop and finding it archived on a phone would have to come from.
//!
//! # The key
//!
//! `harvest:known_store:{code}`, one secret per store, holding whether it is
//! archived. It starts with `harvest:` for the reason `handlers.rs` gives:
//! a key outside that prefix is silently left behind by every future
//! delegate migration. `handlers::all_secret_key_shapes` lists it so the
//! migration tests hold that to account.
//!
//! The code is the store's [`StoreParameters`] code, validated here, so every
//! key is the same length and [`MAX_KNOWN_STORES`] bounds bytes as well as
//! entries.
//!
//! # Archive, never delete
//!
//! There is deliberately no request that removes one of these. See
//! `HarvestDelegateRequest::SetStoreArchived` for why the operation a buyer
//! is offered is "archive". Held structurally: every function here is
//! generic over `SecretStore` alone, which has no removal, so deleting a
//! record would need a new bound -- and `tests::nothing_here_can_delete_a_record`
//! stops compiling with one.
//!
//! # One list per node, not per Ghost Key
//!
//! The list is keyed by nothing but the code, so it is shared by everyone
//! using this node's Harvest delegate, whichever Ghost Key they hold (and a
//! buyer needs none). It is a record of stores this DEVICE opened.

use freenet_migrate::SecretStore;
use harvest_common::delegate::{HarvestDelegateResponse, RememberedStore};
use harvest_common::store::StoreParameters;
use harvest_common::{from_cbor, to_cbor};
use serde::{Deserialize, Serialize};

/// Where every remembered store's secret lives.
pub(crate) const KNOWN_STORE_PREFIX: &str = "harvest:known_store:";

/// How many stores one node remembers.
///
/// Each record is a fixed-size key (a validated sixteen-character code) and a
/// one-field value, so this is a bound on bytes as well: about 50 bytes a
/// store. Past it, a new store is refused out loud rather than an old one
/// dropped, because which of a buyer's stores matters least is not something
/// the delegate can know.
pub(crate) const MAX_KNOWN_STORES: usize = 1024;

pub(crate) fn known_store_key(store_code: &str) -> Vec<u8> {
    format!("{KNOWN_STORE_PREFIX}{store_code}").into_bytes()
}

#[derive(Serialize, Deserialize, Default)]
struct Record {
    archived: bool,
}

fn refuse(message: impl Into<String>) -> HarvestDelegateResponse {
    HarvestDelegateResponse::Error {
        message: message.into(),
    }
}

/// `None` when `store_code` is a store code, or the refusal to answer.
fn refuse_unless_code(store_code: &str) -> Option<HarvestDelegateResponse> {
    match StoreParameters::from_code(store_code) {
        Some(_) => None,
        None => Some(refuse(format!(
            "{store_code:?} is not a store code, so there is nothing to remember"
        ))),
    }
}

/// Write `archived` for `store_code`, creating the record if it is new.
/// `keep_archived` leaves an existing record's flag alone, which is how a
/// visit remembers a store without un-archiving it.
fn upsert<S: SecretStore>(
    store: &mut S,
    store_code: &str,
    archived: bool,
    keep_archived: bool,
) -> HarvestDelegateResponse {
    if let Some(refusal) = refuse_unless_code(store_code) {
        return refusal;
    }
    let key = known_store_key(store_code);
    let record = match store
        .get_secret(&key)
        .map(|bytes| from_cbor::<Record>(&bytes))
    {
        Some(Ok(record)) if keep_archived => record,
        Some(Ok(_)) => Record { archived },
        // A record that is there and does not decode is damage, which `list`
        // hides rather than guesses about. A visit must not guess either:
        // reading it as "not archived" would quietly un-archive a store the
        // buyer archived. An explicit archive or unarchive is a real answer,
        // so that one replaces it.
        Some(Err(_)) if keep_archived => {
            return refuse(
                "this store's saved record could not be read, so it was left as it is; \
                 archiving or unarchiving the store replaces it",
            )
        }
        Some(Err(_)) => Record { archived },
        None => {
            if store.list_secrets(KNOWN_STORE_PREFIX.as_bytes()).len() >= MAX_KNOWN_STORES {
                return refuse(format!(
                    "this node already remembers {MAX_KNOWN_STORES} stores, the most it keeps; \
                     this one was opened but will not be listed after the tab closes"
                ));
            }
            Record { archived }
        }
    };
    let bytes = match to_cbor(&record) {
        Ok(bytes) => bytes,
        Err(e) => return refuse(format!("could not encode the store record: {e}")),
    };
    if !store.set_secret(&key, &bytes) {
        return refuse("the node refused to save the store record");
    }
    list(store)
}

/// `RememberStore`: remember a visited store, leaving an archived one
/// archived.
pub(crate) fn remember<S: SecretStore>(store: &mut S, store_code: &str) -> HarvestDelegateResponse {
    upsert(store, store_code, false, true)
}

/// `SetStoreArchived`.
pub(crate) fn set_archived<S: SecretStore>(
    store: &mut S,
    store_code: &str,
    archived: bool,
) -> HarvestDelegateResponse {
    upsert(store, store_code, archived, false)
}

/// `ListRememberedStores`: every remembered store, sorted by code.
///
/// A key whose suffix is not a valid code, or whose value does not decode,
/// is skipped rather than answered: this module never writes one, so it can
/// only be damage, and handing it to the UI would put a link to nowhere in
/// the buyer's list.
pub(crate) fn list<S: SecretStore>(store: &S) -> HarvestDelegateResponse {
    let mut stores: Vec<RememberedStore> = store
        .list_secrets(KNOWN_STORE_PREFIX.as_bytes())
        .into_iter()
        .filter_map(|key| {
            let code = std::str::from_utf8(key.strip_prefix(KNOWN_STORE_PREFIX.as_bytes())?)
                .ok()?
                .to_string();
            StoreParameters::from_code(&code)?;
            let record = from_cbor::<Record>(&store.get_secret(&key)?).ok()?;
            Some(RememberedStore {
                store_code: code,
                archived: record.archived,
            })
        })
        .collect();
    stores.sort_by(|a, b| a.store_code.cmp(&b.store_code));
    HarvestDelegateResponse::RememberedStores { stores }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemSecrets;

    const CODE_A: &str = "3Bn8xWqLd6Tz9Kf2";
    const CODE_B: &str = "Qp5vMe7RkT2cHw4n";

    fn stores(response: HarvestDelegateResponse) -> Vec<RememberedStore> {
        match response {
            HarvestDelegateResponse::RememberedStores { stores } => stores,
            other => panic!("expected the store list, got {other:?}"),
        }
    }

    fn entry(code: &str, archived: bool) -> RememberedStore {
        RememberedStore {
            store_code: code.to_string(),
            archived,
        }
    }

    #[test]
    fn a_visited_store_is_remembered_and_listed() {
        let mut secrets = MemSecrets::default();
        assert!(stores(list(&secrets)).is_empty());
        assert_eq!(
            stores(remember(&mut secrets, CODE_B)),
            vec![entry(CODE_B, false)]
        );
        assert_eq!(
            stores(remember(&mut secrets, CODE_A)),
            vec![entry(CODE_A, false), entry(CODE_B, false)],
            "sorted by code"
        );
        assert_eq!(
            stores(remember(&mut secrets, CODE_A)).len(),
            2,
            "idempotent"
        );
    }

    #[test]
    fn archiving_hides_without_deleting_and_is_reversible() {
        let mut secrets = MemSecrets::default();
        remember(&mut secrets, CODE_A);
        assert_eq!(
            stores(set_archived(&mut secrets, CODE_A, true)),
            vec![entry(CODE_A, true)]
        );
        assert!(
            secrets.has_secret(&known_store_key(CODE_A)),
            "archived, not removed"
        );
        assert_eq!(
            stores(set_archived(&mut secrets, CODE_A, false)),
            vec![entry(CODE_A, false)]
        );
    }

    /// Following an archived store's link again shows the store; it does not
    /// quietly reverse the buyer's decision to archive it.
    #[test]
    fn visiting_an_archived_store_leaves_it_archived() {
        let mut secrets = MemSecrets::default();
        set_archived(&mut secrets, CODE_A, true);
        assert_eq!(
            stores(remember(&mut secrets, CODE_A)),
            vec![entry(CODE_A, true)]
        );
    }

    #[test]
    fn archiving_a_store_never_visited_remembers_it() {
        let mut secrets = MemSecrets::default();
        assert_eq!(
            stores(set_archived(&mut secrets, CODE_B, true)),
            vec![entry(CODE_B, true)]
        );
    }

    /// The code is written into the key, so a caller-sized code would be a
    /// caller-sized key and the cap would stop bounding bytes.
    #[test]
    fn a_string_that_is_not_a_store_code_is_refused() {
        let mut secrets = MemSecrets::default();
        for bad in [
            "",
            "3Bn8xWqLd6Tz9Kf",
            "3Bn8xWqLd6Tz9Kf2z",
            "3Bn8xWqLd6Tz9Kf0",
            "3Bn8xWqLd6Tz",
            "harvest:rsa_sk",
        ] {
            assert!(
                matches!(
                    remember(&mut secrets, bad),
                    HarvestDelegateResponse::Error { .. }
                ),
                "{bad:?}"
            );
            assert!(matches!(
                set_archived(&mut secrets, bad, true),
                HarvestDelegateResponse::Error { .. }
            ));
        }
        assert!(secrets.list_secrets(b"").is_empty(), "nothing was written");
    }

    #[test]
    fn past_the_cap_a_new_store_is_refused_and_a_known_one_still_changes() {
        let mut secrets = MemSecrets::default();
        let alphabet: Vec<char> = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            .chars()
            .collect();
        let code = |n: usize| -> String {
            let mut s = String::from("zzzzzzzzzzzzz");
            let mut n = n;
            for _ in 0..3 {
                s.push(alphabet[n % alphabet.len()]);
                n /= alphabet.len();
            }
            s
        };
        for n in 0..MAX_KNOWN_STORES {
            assert!(matches!(
                remember(&mut secrets, &code(n)),
                HarvestDelegateResponse::RememberedStores { .. }
            ));
        }
        let refused = remember(&mut secrets, &code(MAX_KNOWN_STORES));
        assert!(
            matches!(refused, HarvestDelegateResponse::Error { .. }),
            "{refused:?}"
        );
        assert!(!secrets.has_secret(&known_store_key(&code(MAX_KNOWN_STORES))));
        // A store already held is not a new one.
        assert!(matches!(
            set_archived(&mut secrets, &code(0), true),
            HarvestDelegateResponse::RememberedStores { .. }
        ));
    }

    /// A secret store with no way to remove anything: `SecretStore` and
    /// nothing else. That this module's functions accept it is the structural
    /// half of "archive, never delete"; the key count never falling across a
    /// run of every operation is the behavioural half.
    struct NoRemoval(MemSecrets);

    impl SecretStore for NoRemoval {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.0.list_secrets(prefix)
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get_secret(key)
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.0.has_secret(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.set_secret(key, value)
        }
    }

    #[test]
    fn nothing_here_can_delete_a_record() {
        let mut secrets = NoRemoval(MemSecrets::default());
        let codes = [CODE_A, CODE_B];
        let mut seen = 0;
        for step in 0u32..60 {
            let code = codes[(step % 2) as usize];
            match step % 3 {
                0 => remember(&mut secrets, code),
                1 => set_archived(&mut secrets, code, step % 4 == 1),
                _ => list(&secrets),
            };
            let held = secrets.list_secrets(KNOWN_STORE_PREFIX.as_bytes()).len();
            assert!(held >= seen, "a record went away at step {step}");
            seen = held;
        }
        assert_eq!(seen, 2);
    }

    /// An unreadable record is not read as "not archived" by a visit, which
    /// would un-archive it; an explicit choice replaces it.
    #[test]
    fn a_visit_does_not_guess_about_an_unreadable_record() {
        let mut secrets = MemSecrets::default();
        let key = known_store_key(CODE_A);
        secrets.set_secret(&key, b"not cbor at all");
        assert!(matches!(
            remember(&mut secrets, CODE_A),
            HarvestDelegateResponse::Error { .. }
        ));
        assert_eq!(
            secrets.get_secret(&key).as_deref(),
            Some(&b"not cbor at all"[..]),
            "left as it was"
        );
        assert!(
            stores(list(&secrets)).is_empty(),
            "and still hidden, as list hides damage"
        );
        assert_eq!(
            stores(set_archived(&mut secrets, CODE_A, true)),
            vec![entry(CODE_A, true)],
            "an explicit choice replaces it"
        );
    }

    #[test]
    fn a_refused_write_is_reported() {
        let mut secrets = MemSecrets::default();
        secrets.writes_fail = true;
        assert!(matches!(
            remember(&mut secrets, CODE_A),
            HarvestDelegateResponse::Error { .. }
        ));
    }
}
