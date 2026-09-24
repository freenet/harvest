//! Answering a successor delegate's request to export this generation's
//! secrets.
//!
//! # What this buys, and when
//!
//! The delegate's secrets are node-local: they live at
//! `secrets_dir/<delegate-key>/`, encrypted under the node's own KEK, and are
//! never replicated. A re-key -- which any change to the compiled bytes causes
//! -- moves that directory out of reach, and there is no second copy anywhere
//! to recover from. Only the OLD delegate can hand them over, and only if it
//! shipped with the code to do so.
//!
//! Since harvest#123 a successor asks (`ui/src/delegate_migrate.rs`), and
//! [`crate::import`] is the half that takes what this answers. Generations V1 to V4 in
//! `legacy/harvest_delegate.toml` do not have it, and no change made now can
//! give it to them: their WASM is already deployed and its `handle_request`
//! rejects anything that is neither a `HarvestDelegateRequest` nor a
//! `BitcoinDelegateRequest`. Secrets held under those four generations are lost.
//!
//! It is what makes the NEXT re-key survivable, and every release shipped
//! without it adds one more unrecoverable generation. That is the whole
//! argument for landing it in the same change that re-keys the delegate again.
//!
//! # Two things it deliberately does not do
//!
//! * **It never answers an unattested caller.** `OriginPolicy::authorize`
//!   fails closed on `origin: None`, which the runtime supplies when it cannot
//!   attest who is asking. These are private keys; guessing is not an option.
//! * **It exports by PREFIX, not the whole scope.** A delegate's secret
//!   namespace is shared by every web app that uses it, and the host does not
//!   slice it per origin -- so a whole-scope export hands the requester
//!   everything, and `freenet-migrate` gates it behind an explicit
//!   single-app acknowledgement for that reason. Harvest's delegate does serve
//!   one app, but the prefix is free and stays correct if that changes.

use freenet_migrate::{ExportRequest, ExportScope, OriginPolicy, SecretStore};
use freenet_stdlib::prelude::{DelegateCtx, DelegateError, MessageOrigin, OutboundDelegateMsg};
use harvest_common::migration::{HarvestMigrationRequest, SECRET_KEY_PREFIX};

/// Who this delegate will export to.
///
/// The crate-wide policy from [`crate::origin`], unchanged: `SameWebApp` pinned
/// to the Harvest container's contract id. It lives there rather than here
/// because it is no longer this module's alone -- every request family is
/// gated on it now -- and two copies of an authorization rule are two rules
/// that can drift apart.
fn origin_policy() -> Result<OriginPolicy, DelegateError> {
    crate::origin::harvest_webapp_policy()
}

/// How much of the secret store an export covers.
///
/// A function rather than an inline expression at the one call site, because
/// the tests below assert what it returns. Written inline, the scope guard
/// would be untestable without a live `DelegateCtx`, and a test that builds
/// its own `ExportScope` proves only that `freenet-migrate` honours a prefix
/// -- not that THIS delegate asks for one. That distinction is not academic:
/// the first version of these tests passed unchanged with the scope switched
/// to `EntireDelegate`, which is precisely the "guard that cannot fail" shape.
fn export_scope() -> ExportScope {
    ExportScope::Prefix(SECRET_KEY_PREFIX.to_vec())
}

/// The secret store as an export sees it: everything but the store keys.
///
/// A store key signs for a whole store (harvest#93), and handing its seed to
/// a successor generation would be the one place it leaves this delegate.
/// Phase 1b recovers store keys from their wrapped copies in store state
/// instead, so nothing needs it exported. `freenet-migrate` scopes an export
/// by prefix only, and store keys share Harvest's prefix, so they are hidden
/// here: absent from every listing and unreadable, which is exactly what the
/// export can reach.
struct WithoutStoreKeys<'a, S>(&'a S);

/// Store keys, which custody recovers, and instant checkout's state that
/// describes only this node (its arms, which the UI re-arms, its tip cache and
/// its exported marker). Instant checkout's LEDGERS do go: they hold the
/// sales whose payments are still to come off the stock
/// (`auto_invoice::Ledger::sales`).
fn is_store_key(key: &[u8]) -> bool {
    key.starts_with(crate::store_keys::STORE_KEY_PREFIX.as_bytes())
        || (key.starts_with(crate::auto_invoice::AUTO_PREFIX.as_bytes())
            && !crate::auto_invoice::is_ledger_key(key))
}

impl<S: SecretStore> SecretStore for WithoutStoreKeys<'_, S> {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        let mut keys = self.0.list_secrets(prefix);
        keys.retain(|key| !is_store_key(key));
        keys
    }

    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        if is_store_key(key) {
            return None;
        }
        self.0.get_secret(key)
    }

    fn has_secret(&self, key: &[u8]) -> bool {
        !is_store_key(key) && self.0.has_secret(key)
    }

    fn set_secret(&mut self, _key: &[u8], _value: &[u8]) -> bool {
        false
    }
}

/// Export this generation's secrets to `origin`, if it may have them. The one
/// path an export takes, so the tests drive exactly what `handle` does.
///
/// A successful export also disarms instant checkout here
/// (`auto_invoice::disarm_all`): the successor is about to run with a copy of
/// this generation's address counter, and two delegates answering the same
/// store from two counters could hand one address to two buyers.
fn export<S: SecretStore + crate::secrets::RemovableSecrets>(
    store: &mut S,
    origin: Option<&MessageOrigin>,
    source_generation: u32,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let policy = origin_policy()?;
    let out = freenet_migrate::handle_export_request(
        &WithoutStoreKeys(&*store),
        origin,
        &policy,
        &export_scope(),
        &ExportRequest { source_generation },
    )
    .map_err(|e| DelegateError::Other(format!("export refused: {e:?}")))?;
    crate::auto_invoice::disarm_all(store);
    Ok(out)
}

/// Handle a migration request from a successor generation.
pub fn handle(
    ctx: &mut DelegateCtx,
    origin: Option<&MessageOrigin>,
    request: HarvestMigrationRequest,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    match request {
        HarvestMigrationRequest::ExportSecrets { source_generation } => export(
            &mut crate::secrets::CtxSecrets(ctx),
            origin,
            source_generation,
        ),
        // `HarvestMigrationRequest` is `#[non_exhaustive]`, and a variant this
        // build does not know about must be refused rather than absorbed: an
        // unrecognised migration request answered with success is a migration
        // that reports having moved secrets it never touched.
        _ => Err(DelegateError::Other(
            "unsupported migration request variant for this delegate version".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_migrate::MigrateError;
    use freenet_stdlib::prelude::ContractInstanceId;
    use std::collections::BTreeMap;

    /// The host's secret store, stood in for so the policy and scope can be
    /// exercised without a node.
    #[derive(Default)]
    struct MemStore(BTreeMap<Vec<u8>, Vec<u8>>);

    impl SecretStore for MemStore {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.0
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get(key).cloned()
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.0.contains_key(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.insert(key.to_vec(), value.to_vec());
            true
        }
    }

    impl crate::secrets::RemovableSecrets for MemStore {
        fn remove_secret(&mut self, key: &[u8]) -> bool {
            self.0.remove(key);
            true
        }
    }

    fn store() -> MemStore {
        let mut s = MemStore::default();
        s.set_secret(b"harvest:rsa_sk:fp1", b"private");
        s.set_secret(b"harvest:rsa_pk:fp1", b"public");
        s.set_secret(b"harvest:stores:fp1", b"registry");
        s.set_secret(b"harvest:bitcoin:watches:v1", b"watches");
        // Another app's secret in the same delegate namespace. Nothing writes
        // this today; it is here because the prefix scope is what keeps it out
        // of the export, and a scope guard nothing can violate is a guard that
        // cannot be shown to work.
        s.set_secret(b"someotherapp:key", b"not ours");
        s
    }

    use crate::origin::test_origins::harvest as harvest_origin;

    fn exported(msgs: &[OutboundDelegateMsg]) -> freenet_migrate::ExportedSecrets {
        let payload = match &msgs[0] {
            OutboundDelegateMsg::ApplicationMessage(m) => m.payload.clone(),
            other => panic!("expected an application message, got {other:?}"),
        };
        freenet_migrate::ExportedSecrets::from_bytes(&payload).expect("decode exported secrets")
    }

    /// The whole point: the successor's origin gets this generation's secrets.
    #[test]
    fn the_successors_web_app_gets_every_harvest_secret() {
        let msgs = freenet_migrate::handle_export_request(
            &store(),
            Some(&harvest_origin()),
            &origin_policy().expect("policy"),
            &export_scope(),
            &ExportRequest {
                source_generation: 4,
            },
        )
        .expect("the harvest web app must be authorized");

        let secrets = exported(&msgs);
        assert_eq!(secrets.source_generation, 4);
        let keys: Vec<String> = secrets
            .secrets
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
            .collect();
        for expected in [
            "harvest:rsa_sk:fp1",
            "harvest:rsa_pk:fp1",
            "harvest:stores:fp1",
            "harvest:bitcoin:watches:v1",
        ] {
            assert!(
                keys.contains(&expected.to_string()),
                "{expected} not exported"
            );
        }
    }

    /// A store key never leaves this delegate, not even to its own successor
    /// (harvest#93 review, Should Fix 4): the export path hides the family.
    ///
    /// Mutated red by exporting through the raw store instead of
    /// `WithoutStoreKeys`.
    #[test]
    fn a_store_key_is_never_exported() {
        let mut s = store();
        s.set_secret(b"harvest:store_sk:3Bn8xWqLd6Tz9Kf2", b"seed");
        let msgs = export(&mut s, Some(&harvest_origin()), 4).expect("authorized");
        let keys: Vec<Vec<u8>> = exported(&msgs)
            .secrets
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(keys.iter().all(|k| !is_store_key(k)), "{keys:?}");
        assert!(
            keys.iter().any(|k| k == b"harvest:rsa_sk:fp1"),
            "and everything else still goes"
        );
    }

    /// Exporting to a successor disarms instant checkout here, and never
    /// carries an arm. Mutated red by dropping the `disarm_all` call.
    #[test]
    fn an_export_disarms_instant_checkout() {
        let mut s = store();
        let arm = crate::auto_invoice::arm_key(&[5u8; 32]);
        let ledger = crate::auto_invoice::ledger_key(&[5u8; 32]);
        s.set_secret(&arm, b"an arm");
        s.set_secret(&ledger, b"a ledger");
        let msgs = export(&mut s, Some(&harvest_origin()), 4).expect("authorized");
        let keys: Vec<Vec<u8>> = exported(&msgs)
            .secrets
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(!keys.contains(&arm), "the arm stays behind");
        assert!(
            keys.contains(&ledger),
            "the ledger's sales go to the successor"
        );
        assert!(!s.has_secret(&arm), "the arm is gone");
        assert!(
            s.has_secret(crate::auto_invoice::EXPORTED_KEY),
            "and none is taken again"
        );
    }

    /// The prefix scope is load-bearing, not decoration.
    ///
    /// Mutated red by switching the scope to `EntireDelegate`: the foreign key
    /// is then exported too.
    #[test]
    fn the_export_is_confined_to_harvests_own_prefix() {
        let msgs = freenet_migrate::handle_export_request(
            &store(),
            Some(&harvest_origin()),
            &origin_policy().expect("policy"),
            &export_scope(),
            &ExportRequest {
                source_generation: 4,
            },
        )
        .expect("authorized");
        let keys: Vec<Vec<u8>> = exported(&msgs)
            .secrets
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(
            keys.iter().all(|k| k.starts_with(SECRET_KEY_PREFIX)),
            "a secret outside Harvest's prefix was exported: {keys:?}"
        );
    }

    /// An unattested caller is refused. The runtime supplies `None` when it
    /// cannot say who is asking, and these are private keys.
    ///
    /// Mutated red by switching the policy to `OriginPolicy::Any`.
    #[test]
    fn an_unattested_caller_gets_nothing() {
        let err = freenet_migrate::handle_export_request(
            &store(),
            None,
            &origin_policy().expect("policy"),
            &export_scope(),
            &ExportRequest {
                source_generation: 4,
            },
        )
        .expect_err("an unattested origin must be refused");
        assert!(matches!(err, MigrateError::UnauthorizedOrigin));
    }

    /// So is a different web app the user happens to have granted access to.
    #[test]
    fn another_web_app_gets_nothing() {
        let other = MessageOrigin::WebApp(ContractInstanceId::new([9u8; 32]));
        let err = freenet_migrate::handle_export_request(
            &store(),
            Some(&other),
            &origin_policy().expect("policy"),
            &export_scope(),
            &ExportRequest {
                source_generation: 4,
            },
        )
        .expect_err("a foreign web app must be refused");
        assert!(matches!(err, MigrateError::UnauthorizedOrigin));
    }

    /// No payload decodes as more than one of the three request enums.
    ///
    /// `handle_request` picks between them by trying each decode in turn,
    /// which is sound only while no variant name is shared: externally-tagged
    /// CBOR puts the variant name in the encoding, so a payload for one enum
    /// fails to decode as another with "unknown variant" instead of
    /// misparsing into the wrong shape. Adding a colliding name would silently
    /// route requests to the wrong handler -- and for the migration enum that
    /// means routing something to the branch that hands out private keys.
    ///
    /// Mutated red by renaming a `HarvestDelegateRequest` variant to
    /// `ExportSecrets`.
    #[test]
    fn no_payload_decodes_as_two_different_request_enums() {
        use harvest_common::{from_cbor, to_cbor, BitcoinDelegateRequest, HarvestDelegateRequest};

        let migration = to_cbor(&HarvestMigrationRequest::ExportSecrets {
            source_generation: 3,
        })
        .expect("cbor");
        let harvest = to_cbor(&HarvestDelegateRequest::ListStores {
            ghostkey_fingerprint: "fp".into(),
        })
        .expect("cbor");
        let harvest_unit = to_cbor(&HarvestDelegateRequest::ListRememberedStores).expect("cbor");
        // The migration-marker pair. They live on `HarvestDelegateRequest`
        // rather than on the migration enum, so they are ordinary requests --
        // but they are the newest names in the file, and a name that collided
        // with `ExportSecrets` would route a marker query to the branch that
        // hands out private keys.
        let marker_get = to_cbor(&HarvestDelegateRequest::GetMigrationMarker {
            marker: "v1.store.aa.bb".into(),
        })
        .expect("cbor");
        let marker_set = to_cbor(&HarvestDelegateRequest::SetMigrationMarker {
            marker: "v1.store.aa.bb".into(),
            note: "recovered".into(),
        })
        .expect("cbor");
        let bitcoin = to_cbor(&BitcoinDelegateRequest::ListWatched).expect("cbor");
        // The messaging family, added after this rule was written down. A
        // `DeriveConversationKeys` misrouted into the migration branch would
        // reach the code that exports this delegate's private keys.
        let init_encryption_key = to_cbor(&HarvestDelegateRequest::InitEncryptionKey {
            ghostkey_fingerprint: "fp".into(),
            recall_only: false,
        })
        .expect("cbor");
        let derive_keys = to_cbor(&HarvestDelegateRequest::DeriveConversationKeys {
            request_id: 1,
            ghostkey_fingerprint: "fp".into(),
            peer_public_keys: vec![vec![1u8; 32]],
            store_verifying_key: None,
        })
        .expect("cbor");

        assert!(from_cbor::<HarvestDelegateRequest>(&migration).is_err());
        assert!(from_cbor::<BitcoinDelegateRequest>(&migration).is_err());

        for other in [
            &harvest,
            &harvest_unit,
            &marker_get,
            &marker_set,
            &bitcoin,
            &init_encryption_key,
            &derive_keys,
        ] {
            assert!(
                from_cbor::<HarvestMigrationRequest>(other).is_err(),
                "a non-migration payload decoded as a migration request, which \
                 would route it to the branch that exports private keys"
            );
        }
    }

    /// Every key the delegate writes falls under the exported prefix.
    ///
    /// The export is defined by a prefix, so a key builder that ever stopped
    /// starting with `harvest:` would be silently left behind by every future
    /// migration -- no error, no warning, just a secret that does not arrive.
    /// This pins the two together.
    ///
    /// Mutated red by changing one key builder's prefix.
    #[test]
    fn every_secret_the_delegate_writes_is_under_the_exported_prefix() {
        for key in crate::handlers::all_secret_key_shapes("fp") {
            assert!(
                key.starts_with(SECRET_KEY_PREFIX),
                "the delegate writes {} , which no export would carry",
                String::from_utf8_lossy(&key)
            );
        }
    }
}
