//! The delegate host's secret store, behind a trait the handlers can be tested
//! against.
//!
//! # Why the handlers do not take a `DelegateCtx`
//!
//! Off the `wasm32` target, `DelegateCtx::get_secret` answers `None` and
//! `set_secret` answers `false` (freenet-stdlib's `delegate_host.rs`,
//! `#[cfg(not(target_family = "wasm"))]` branch). A handler that takes a
//! `DelegateCtx` therefore cannot be exercised under `cargo test` at all: every
//! read misses and every write is refused, so a test can only ever observe the
//! failure path.
//!
//! That is not a cosmetic inconvenience. It is why the authorization hole this
//! module's sibling [`crate::origin`] closes was untestable before: the only
//! statement a test could make about `bitcoin::handle` was "it returned
//! something", never "the seller's payment key is still the seller's". Taking
//! `impl SecretStore` instead lets a test hold a real store, run a hostile
//! request against it, and assert on the bytes that are still in it afterwards.
//!
//! [`SecretStore`] is `freenet-migrate`'s trait rather than a new one, because
//! `crate::migration` and `crate::markers` already speak it. One vocabulary for
//! "the delegate's secret store" across the crate.

use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::DelegateCtx;

/// Removal, which [`SecretStore`] does not have and the host does.
///
/// # Why this trait exists at all
///
/// `freenet-migrate`'s `SecretStore` is `list`/`get`/`has`/`set` and nothing
/// else, so code written against it can only ever EMPTY a value. That is not
/// good enough for one caller: `messaging::forget_buyer_conversation` is the
/// buyer's control over the record their node keeps of who they messaged, and
/// a key left behind with an empty value still says "this node held a
/// conversation with that store" for as long as the delegate lives.
///
/// The platform can genuinely delete. `DelegateCtx::remove_secret`
/// (freenet-stdlib 0.8.5, `delegate_host.rs:424`) reaches
/// `__frnt__delegate__remove_secret`, and the node's implementation
/// (freenet-core `wasm_runtime/secrets_store/store.rs::remove_secret`)
/// removes the encrypted blob, removes its snapshot history, drops the key
/// from the persistent index, and de-registers the raw key from the
/// enumeration registry that backs `list_secrets`. So the deletion is real at
/// every layer this application can see.
///
/// It is a separate trait rather than an addition to `SecretStore` because
/// `SecretStore` belongs to another crate, and separate because most of this
/// delegate genuinely does not need removal: only the code that must be able
/// to promise a buyer something is gone takes the extra bound.
///
/// **Not exercisable off wasm32.** Like every other `DelegateCtx` secret
/// method, `remove_secret` is a `false`-returning stub on native
/// (`delegate_host.rs:424`, the `#[cfg(not(target_family = "wasm"))]` arm),
/// so [`MemSecrets`] is what the tests drive. What the tests can therefore
/// state is that this crate asks for removal and reports honestly on the
/// answer -- not that the node performed it.
pub(crate) trait RemovableSecrets {
    /// Remove `key` outright. Answers whether the key is gone afterwards.
    fn remove_secret(&mut self, key: &[u8]) -> bool;
}

/// The host's secret store, with writes enabled.
///
/// Distinct from `migration::CtxStore`, whose `set_secret` is deliberately
/// inert because an export must never write.
pub(crate) struct CtxSecrets<'a>(pub(crate) &'a mut DelegateCtx);

impl SecretStore for CtxSecrets<'_> {
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

impl RemovableSecrets for CtxSecrets<'_> {
    fn remove_secret(&mut self, key: &[u8]) -> bool {
        self.0.remove_secret(key)
    }
}

/// An in-memory stand-in for the host's store, for tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemSecrets {
    map: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    /// Set to make every write fail, standing in for a host that refuses.
    pub(crate) writes_fail: bool,
    /// Set to make every removal fail, standing in for a host that refuses --
    /// the case where "forget this conversation" must report a failure rather
    /// than a success the buyer would rely on.
    pub(crate) removals_fail: bool,
    /// Set to make writes of keys under this prefix fail, and only those:
    /// a host that refuses one write of several.
    pub(crate) refused_prefix: Option<Vec<u8>>,
    /// How many reads were asked of it, for tests that bound a call's work.
    pub(crate) reads: std::cell::Cell<usize>,
    /// Every key read, in order.
    pub(crate) read_log: std::cell::RefCell<Vec<Vec<u8>>>,
}

#[cfg(test)]
impl SecretStore for MemSecrets {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.map
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.reads.set(self.reads.get() + 1);
        self.read_log.borrow_mut().push(key.to_vec());
        self.map.get(key).cloned()
    }

    fn has_secret(&self, key: &[u8]) -> bool {
        self.map.contains_key(key)
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        if self.writes_fail
            || self
                .refused_prefix
                .as_ref()
                .is_some_and(|prefix| key.starts_with(prefix))
        {
            return false;
        }
        self.map.insert(key.to_vec(), value.to_vec());
        true
    }
}

/// Removal, standing in for the host's. `removals_fail` is the counterpart of
/// [`MemSecrets::writes_fail`]: a host that refuses is the case where a
/// "forget" must not report success.
#[cfg(test)]
impl RemovableSecrets for MemSecrets {
    fn remove_secret(&mut self, key: &[u8]) -> bool {
        if self.removals_fail {
            return false;
        }
        self.map.remove(key);
        !self.map.contains_key(key)
    }
}

#[cfg(test)]
impl MemSecrets {
    /// A store whose host refuses every write.
    pub(crate) fn refusing_writes() -> Self {
        Self {
            writes_fail: true,
            ..Self::default()
        }
    }

    /// How many reads of keys under `prefix` were asked of it.
    pub(crate) fn reads_under(&self, prefix: &[u8]) -> usize {
        self.read_log
            .borrow()
            .iter()
            .filter(|k| k.starts_with(prefix))
            .count()
    }

    /// A store whose host refuses writes of keys under `prefix` only.
    pub(crate) fn refusing_writes_under(prefix: Vec<u8>) -> Self {
        Self {
            refused_prefix: Some(prefix),
            ..Self::default()
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
