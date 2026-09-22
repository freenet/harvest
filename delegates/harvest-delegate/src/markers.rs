//! The durable "this migration finished" marker, and why it lives here.
//!
//! # Why not `localStorage`
//!
//! The obvious home for a client-side repeat gate is the browser's own
//! storage, and in the deployed gateway that home does not exist. Freenet
//! serves a webapp inside an iframe with **no `allow-same-origin`**
//! (`crates/core/src/server/path_handlers.rs` and its `shell_bridge.js`), so
//! the app frame has an opaque origin and `window.localStorage` throws
//! `SecurityError`. A marker kept there works under `dx serve` and is a no-op
//! the moment it is published -- the failure is silent, and it fails in the
//! *safe* direction (unreadable reads as "not migrated", so the walk repeats
//! rather than being skipped), which is exactly why nothing would ever report
//! it. River moved its own migration markers into the delegate KV store for
//! this reason (`freenet/river`, `delegate_migration.rs`).
//!
//! # The namespace, and why the caller does not choose the key
//!
//! A marker id from the UI is **not** a secret key. It is concatenated onto
//! [`MARKER_KEY_PREFIX`] here, so the whole of the delegate's key space
//! outside `harvest:migrate:` is unreachable through these two requests. That
//! matters more than it looks: the same store holds `harvest:rsa_sk:*`, and a
//! request that took a raw key would let any caller the runtime attests as
//! the Harvest web app overwrite a reputation private key with a migration
//! note.
//!
//! Marker ids are additionally required to be **ASCII** ([`is_valid_marker`]).
//! The UI mints them as hex, so this rejects nothing it sends; it is here
//! because a key that survives a lossy UTF-8 conversion somewhere in the host
//! is a key that cannot alias with another, and River lost a marker slot to
//! exactly that (`String::from_utf8_lossy` maps every invalid byte to U+FFFD,
//! collapsing two distinct ids onto one slot). Enforcing it at the boundary
//! makes the property the delegate's, rather than a habit of today's caller.
//!
//! # Markers are inside the export prefix, deliberately
//!
//! [`MARKER_KEY_PREFIX`] starts with `harvest:`, so a marker is carried to the
//! successor by [`crate::migration`]'s export. That is right, and it is the
//! opposite of River's choice, because the two markers say different things.
//! River's names a predecessor **delegate**, so copying it forward would forge
//! migration state for the new one. Harvest's names a **contract** generation
//! -- "the predecessors of store contract X were folded into it" -- a fact
//! about contracts that no delegate re-key changes. Carrying it forward is
//! therefore accurate, and costs nothing extra to arrange.
//!
//! Since harvest#123 the successor does import (`ui/src/delegate_migrate.rs`,
//! with the successor side in [`crate::import`]), so markers now actually
//! travel. A marker that does not -- from V1-V4, which cannot export, or from a
//! generation the node never ran -- costs one extra probe of that contract.
//! That is safe: the fold only ever adds.

use freenet_migrate::SecretStore;
use harvest_common::HarvestDelegateResponse;

/// The namespace every migration marker is stored under.
///
/// Inside `harvest_common::migration::SECRET_KEY_PREFIX`, so an export carries
/// markers forward -- see the module docs for why that is correct here and
/// wrong in River.
pub(crate) const MARKER_KEY_PREFIX: &[u8] = b"harvest:migrate:";

/// The secret key a marker id is stored under.
///
/// Concatenation onto a fixed prefix, so no marker id can name a key outside
/// the migration namespace however it is chosen.
pub(crate) fn marker_secret_key(marker: &str) -> Vec<u8> {
    let mut key = MARKER_KEY_PREFIX.to_vec();
    key.extend_from_slice(marker.as_bytes());
    key
}

/// Whether a marker id is one this delegate will store.
///
/// Non-empty and ASCII. See the module docs: ASCII is what makes two distinct
/// ids impossible to alias through a lossy UTF-8 conversion.
pub(crate) fn is_valid_marker(marker: &str) -> bool {
    !marker.is_empty() && marker.is_ascii()
}

/// Answer whether a marker is recorded.
///
/// A malformed marker answers `present: false` rather than erroring, and that
/// choice is the fail-safe one on purpose: the caller's next step on `false`
/// is to run the migration again, which is wasteful and correct, whereas an
/// error it mishandled could be read as "nothing to do".
pub(crate) fn get_marker<S: SecretStore>(store: &S, marker: &str) -> HarvestDelegateResponse {
    let present = is_valid_marker(marker) && store.has_secret(&marker_secret_key(marker));
    HarvestDelegateResponse::MigrationMarker {
        marker: marker.to_string(),
        present,
    }
}

/// Record a marker. A malformed id, or a host that refuses the write, is
/// reported as `recorded: false` and nothing else happens -- the walk simply
/// runs again on the next load.
pub(crate) fn set_marker<S: SecretStore>(
    store: &mut S,
    marker: &str,
    note: &str,
) -> HarvestDelegateResponse {
    let recorded =
        is_valid_marker(marker) && store.set_secret(&marker_secret_key(marker), note.as_bytes());
    HarvestDelegateResponse::MigrationMarkerRecorded {
        marker: marker.to_string(),
        recorded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harvest_common::migration::SECRET_KEY_PREFIX;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemStore {
        map: BTreeMap<Vec<u8>, Vec<u8>>,
        /// Set to make every write fail, standing in for a host that refuses.
        writes_fail: bool,
    }

    impl SecretStore for MemStore {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.map
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.map.get(key).cloned()
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.map.contains_key(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            if self.writes_fail {
                return false;
            }
            self.map.insert(key.to_vec(), value.to_vec());
            true
        }
    }

    fn present(response: &HarvestDelegateResponse) -> bool {
        match response {
            HarvestDelegateResponse::MigrationMarker { present, .. } => *present,
            other => panic!("expected a MigrationMarker, got {other:?}"),
        }
    }

    fn recorded(response: &HarvestDelegateResponse) -> bool {
        match response {
            HarvestDelegateResponse::MigrationMarkerRecorded { recorded, .. } => *recorded,
            other => panic!("expected a MigrationMarkerRecorded, got {other:?}"),
        }
    }

    /// The whole point: a marker written through the delegate is readable back
    /// through it, and an unwritten one is not.
    ///
    /// Mutated red by having `set_marker` drop the write.
    #[test]
    fn a_marker_round_trips_through_the_store() {
        let mut store = MemStore::default();
        let marker = "v1.store.aabb.ccdd";

        assert!(
            !present(&get_marker(&store, marker)),
            "a marker nothing wrote must not read as done"
        );

        assert!(recorded(&set_marker(
            &mut store,
            marker,
            "recovered state from predecessor"
        )));
        assert!(
            present(&get_marker(&store, marker)),
            "a written marker must read back as done"
        );

        assert!(
            !present(&get_marker(&store, "v1.store.aabb.eeff")),
            "a different marker must not be sealed by this one"
        );
    }

    /// A store that cannot answer reports "not migrated", so the probe repeats.
    ///
    /// This is the direction the whole scheme depends on. `localStorage` in the
    /// gateway iframe threw, and the reason that was merely wasteful rather
    /// than data-losing is that an unreadable marker reads as absent. The
    /// delegate has to keep that property.
    ///
    /// Mutated red by having `get_marker` answer `present: true` when the
    /// store cannot say.
    #[test]
    fn an_unreadable_store_reads_as_not_migrated() {
        /// A store where every read fails, as a host with no secret access
        /// would behave.
        struct Unreadable;
        impl SecretStore for Unreadable {
            fn list_secrets(&self, _prefix: &[u8]) -> Vec<Vec<u8>> {
                Vec::new()
            }
            fn get_secret(&self, _key: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn has_secret(&self, _key: &[u8]) -> bool {
                false
            }
            fn set_secret(&mut self, _key: &[u8], _value: &[u8]) -> bool {
                false
            }
        }

        assert!(
            !present(&get_marker(&Unreadable, "v1.store.aabb.ccdd")),
            "an unreadable marker must never read as done"
        );
    }

    /// A refused write is reported, and leaves nothing sealed.
    #[test]
    fn a_refused_write_seals_nothing() {
        let mut store = MemStore {
            writes_fail: true,
            ..MemStore::default()
        };
        let marker = "v1.store.aabb.ccdd";
        assert!(!recorded(&set_marker(&mut store, marker, "note")));
        assert!(!present(&get_marker(&store, marker)));
    }

    /// A marker id can never name a key outside the migration namespace, so
    /// these two requests cannot touch `harvest:rsa_sk:*`.
    ///
    /// Mutated red by having `marker_secret_key` return the marker's own bytes.
    #[test]
    fn a_marker_id_cannot_address_another_secret() {
        let mut store = MemStore::default();
        store.set_secret(b"harvest:rsa_sk:fp1", b"private");

        // The id a caller would choose to try to overwrite the RSA key.
        set_marker(&mut store, "../harvest:rsa_sk:fp1", "overwritten");
        set_marker(&mut store, "harvest:rsa_sk:fp1", "overwritten");

        assert_eq!(
            store.get_secret(b"harvest:rsa_sk:fp1").as_deref(),
            Some(b"private".as_slice()),
            "a marker write reached a key outside the migration namespace"
        );
        assert!(
            store
                .list_secrets(MARKER_KEY_PREFIX)
                .iter()
                .all(|k| k.starts_with(MARKER_KEY_PREFIX)),
            "a marker landed outside its own namespace"
        );
    }

    /// A non-ASCII marker is refused rather than stored, so no two ids can
    /// collapse onto one slot through a lossy UTF-8 conversion.
    #[test]
    fn a_non_ascii_marker_is_refused() {
        let mut store = MemStore::default();
        assert!(!recorded(&set_marker(&mut store, "v1.st\u{f8}re", "note")));
        assert!(!recorded(&set_marker(&mut store, "", "note")));
        assert!(store.map.is_empty());
    }

    /// Markers fall inside the exported prefix, so they travel with the
    /// secrets they describe when a successor imports.
    ///
    /// See the module docs for why that is the right answer here and the wrong
    /// one in River.
    #[test]
    fn markers_are_inside_the_exported_prefix() {
        assert!(
            MARKER_KEY_PREFIX.starts_with(SECRET_KEY_PREFIX),
            "a marker outside the export prefix is dropped on every delegate re-key"
        );
        assert!(marker_secret_key("v1.store.aa.bb").starts_with(SECRET_KEY_PREFIX));
    }
}
