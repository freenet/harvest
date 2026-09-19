//! Build-time codegen for the UI.
//!
//! Two jobs: stamp the build timestamp the footer shows, and turn the
//! predecessor registries under `../legacy/` into the lineage consts
//! `src/migrate.rs` walks.
//!
//! Codegen rather than hand-written constants so the TOML is the single source
//! of truth: a hash recorded there cannot fail to reach the probe because
//! somebody forgot to copy it into Rust.

use std::path::{Path, PathBuf};

/// One artifact's registry: the file under `legacy/`, the file emitted into
/// `$OUT_DIR`, and the name of the const `src/migrate.rs` imports.
///
/// Keep in step with `legacy/` and with the artifact list in
/// `scripts/build-contract-wasm.sh`. An artifact missing from this table is an
/// artifact whose predecessors nothing probes.
const CONTRACT_REGISTRIES: &[(&str, &str, &str)] = &[
    (
        "store_contract.toml",
        "legacy_store_contract.rs",
        "LEGACY_STORE_CONTRACT",
    ),
    (
        "reputation_contract.toml",
        "legacy_reputation_contract.rs",
        "LEGACY_REPUTATION_CONTRACT",
    ),
    (
        "mailbox_contract.toml",
        "legacy_mailbox_contract.rs",
        "LEGACY_MAILBOX_CONTRACT",
    ),
    (
        "index_contract.toml",
        "legacy_index_contract.rs",
        "LEGACY_INDEX_CONTRACT",
    ),
];

/// Registries that may have no rows yet, and why. An artifact belongs here
/// only while it genuinely has no predecessor generation: the Ghost Key index
/// is new in harvest#93 phase 1c, so nothing was ever published at an
/// earlier address. Its FIRST superseded generation must be recorded as a
/// row, and this entry removed, in the change that supersedes it.
const MAY_BE_EMPTY: &[&str] = &["index_contract.toml"];

const DELEGATE_REGISTRY: (&str, &str, &str) = (
    "harvest_delegate.toml",
    "legacy_harvest_delegate.rs",
    "LEGACY_HARVEST_DELEGATE",
);

fn main() {
    let now = chrono::Utc::now();
    let timestamp = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    println!("cargo:rustc-env=BUILD_TIMESTAMP_ISO={timestamp}");

    let legacy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ui/ has a parent")
        .join("legacy");

    for (file, out, const_name) in CONTRACT_REGISTRIES {
        let path = legacy.join(file);
        if !MAY_BE_EMPTY.contains(file) {
            require_entries(&path);
        }
        freenet_migrate_build::codegen()
            .entry_registry(&path, freenet_migrate_build::Component::Contract)
            .out_file(*out)
            .contract_const_name(*const_name)
            .emit()
            .unwrap_or_else(|e| panic!("codegen for {}: {e}", path.display()));
    }

    let (file, out, const_name) = DELEGATE_REGISTRY;
    let path = legacy.join(file);
    require_entries(&path);
    freenet_migrate_build::codegen()
        .entry_registry(&path, freenet_migrate_build::Component::Delegate)
        .out_file(out)
        .delegate_const_name(const_name)
        .emit()
        .unwrap_or_else(|e| panic!("codegen for {}: {e}", path.display()));

    // `emit()` already prints `cargo:rerun-if-changed` for each registry it
    // reads. This one is for the script itself -- the tables above live here,
    // so editing them has to invalidate the cache too.
    //
    // Note what printing ANY `rerun-if-changed` costs: it replaces cargo's
    // "re-run when anything in the package changes" default, so
    // BUILD_TIMESTAMP_ISO above is stamped when this script re-runs and not on
    // every build. That was already true before the registries were added
    // (this line predates them), and the alternative -- dropping every
    // `rerun-if-changed` to keep the timestamp live -- would take the lineage
    // staleness guard with it. A footer showing an older timestamp is a
    // cosmetic defect; a stale lineage silently probes nothing.
    println!("cargo:rerun-if-changed=build.rs");
}

/// Fail the build on a registry that is absent or holds no rows.
///
/// This is the guard the whole mechanism rests on, so it must be able to go
/// red: an empty lineage probes nothing, finds nothing, and reports success --
/// data loss that looks exactly like a healthy migration. `cargo:warning` is
/// not an option here, and not only because a warning is ignorable:
/// `freenet_migrate_build`'s own missing-registry fallback emits one, and a
/// `cargo:warning` printed from a build script that then succeeds is easy to
/// miss in a wall of build output.
///
/// The `[[entry]]` check is deliberately cruder than parsing the TOML: it
/// catches a file emptied by a bad merge or truncated by a failed edit, which
/// a parse would accept as a valid empty registry.
fn require_entries(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "cannot read migration registry {}: {e}\n\
             Every predecessor generation of this artifact is listed there. \
             Without it the probe has nothing to walk and would report a clean \
             migration having looked at nothing.",
            path.display()
        )
    });
    assert!(
        text.contains("[[entry]]"),
        "migration registry {} has no [[entry]] rows. An empty lineage probes \
         nothing and reports success. If this artifact genuinely has no \
         predecessors, say so with an explicit comment and remove this guard \
         deliberately.",
        path.display()
    );
}
