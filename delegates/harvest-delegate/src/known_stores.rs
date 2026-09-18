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
//! is offered is "archive".

use freenet_migrate::SecretStore;
use harvest_common::delegate::{HarvestDelegateResponse, RememberedStore};
use harvest_common::store::StoreParameters;
use harvest_common::{from_cbor, to_cbor};
use serde::{Deserialize, Serialize};

/// Where every remembered store's secret lives.
pub(crate) const KNOWN_STORE_PREFIX: &str = "harvest:known_store:";

/// How many stores one node remembers.
///
/// Each record is a fixed-size key (a validated twelve-character code) and a
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
    let existing = store
        .get_secret(&key)
        .map(|bytes| from_cbor::<Record>(&bytes).unwrap_or_default());
    let record = match existing {
        Some(record) if keep_archived => record,
        Some(_) => Record { archived },
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

    const CODE_A: &str = "3Bn8xWqLd6Tz";
    const CODE_B: &str = "Qp5vMe7RkT2c";

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
            "3Bn8xWqLd6T",
            "3Bn8xWqLd6Tzz",
            "3Bn8xWqLd6T0",
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
            let mut s = String::from("zzzzzzzzz");
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
