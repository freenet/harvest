//! Mirrors `ui/build.rs`'s registry codegen so the real `ui/src/migrate.rs`
//! compiles here unchanged, against the same `legacy/*.toml` the app ships.
use std::path::PathBuf;

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

const DELEGATE_REGISTRY: (&str, &str, &str) = (
    "harvest_delegate.toml",
    "legacy_harvest_delegate.rs",
    "LEGACY_HARVEST_DELEGATE",
);

fn main() {
    let legacy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../legacy")
        .canonicalize()
        .expect("legacy/ registries are two directories up from tests/rehearsal");

    for (file, out, const_name) in CONTRACT_REGISTRIES {
        let path = legacy.join(file);
        freenet_migrate_build::codegen()
            .entry_registry(&path, freenet_migrate_build::Component::Contract)
            .out_file(*out)
            .contract_const_name(*const_name)
            .emit()
            .unwrap_or_else(|e| panic!("codegen for {}: {e}", path.display()));
    }

    let (file, out, const_name) = DELEGATE_REGISTRY;
    let path = legacy.join(file);
    freenet_migrate_build::codegen()
        .entry_registry(&path, freenet_migrate_build::Component::Delegate)
        .out_file(out)
        .delegate_const_name(const_name)
        .emit()
        .unwrap_or_else(|e| panic!("codegen for {}: {e}", path.display()));

    println!("cargo:rerun-if-changed=build.rs");
}
