//! Print the network ADDRESS of every Harvest contract and delegate.
//!
//! # Why an address and not a code hash
//!
//! A contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, and a delegate
//! likewise. Harvest's two drift guards -- `scripts/check-code-hashes.sh` and
//! `.github/workflows/contract-drift.yml` -- used to compare the compiled WASM
//! and nothing else, so a change to a *parameter struct* moved every published
//! instance while both guards reported "unchanged". The WASM was genuinely
//! byte-identical; the address was not.
//!
//! That is how `StoreParameters` shedding two fields nearly shipped: its CBOR
//! went from 109 bytes to 56, every published store re-keyed, and the only
//! symptom would have been a migration probe walking addresses that never
//! existed and reporting a clean "nothing to migrate". This binary is the
//! missing half.
//!
//! # Where each half comes from
//!
//! * **The code hash** is `BLAKE3` of the built `.wasm`, via stdlib's own
//!   [`ContractKey`] / [`Delegate`] constructors rather than a re-derivation
//!   here. The address a node computes and the address printed here are then
//!   the same function by construction.
//! * **The parameter bytes** come from the live parameter structs in
//!   `harvest-common`, filled with fixed placeholders
//!   (`harvest_common::address`) and encoded with the same `to_cbor` the app
//!   publishes with. Nothing about the encoding is transcribed here, so nothing
//!   here can drift away from what the app does.
//!
//! The placeholders are constant on purpose: the question is whether the
//! parameter *encoding* moved, not whose key is in it.
//!
//! # Being called from a worktree that is not this one
//!
//! `contract-drift.yml` copies THIS file into the merge-base worktree and runs
//! it there, so both sides of a PR are measured by the same procedure while
//! each side's own parameter structs supply the shape. That only works because
//! this file names no struct *fields* -- it asks each type for its placeholder.
//! Keep it that way: a field named here would fail to compile against the other
//! side of any PR that adds or removes one, turning a clean "MOVED" report into
//! a build error.
//!
//! # Usage
//!
//! ```text
//! cargo run -q -p harvest-common --bin harvest-addresses -- [WASM_DIR]
//! ```
//!
//! `WASM_DIR` defaults to `target/wasm32-unknown-unknown/release`. Output is
//! one TSV row per artifact, with a `#` comment header:
//!
//! ```text
//! artifact  kind  code_hash(hex)  params_len  params(hex)  address(base58)
//! ```

use std::path::{Path, PathBuf};

use freenet_stdlib::prelude::{ContractCode, ContractKey, Delegate, DelegateCode, Parameters};
use harvest_common::address::placeholder_params_cbor;
use harvest_common::delegate::DELEGATE_PARAMETERS;
use harvest_common::mailbox::MailboxParameters;
use harvest_common::reputation::ReputationParameters;
use harvest_common::store::StoreParameters;

const DEFAULT_WASM_DIR: &str = "target/wasm32-unknown-unknown/release";

/// Which stdlib addressing scheme an artifact uses. Both are
/// `BLAKE3(code_hash || params)`, but each goes through its own stdlib type so
/// that neither is a re-derivation maintained here.
enum Kind {
    Contract,
    Delegate,
}

impl Kind {
    fn label(&self) -> &'static str {
        match self {
            Kind::Contract => "contract",
            Kind::Delegate => "delegate",
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let dir = PathBuf::from(args.next().unwrap_or_else(|| DEFAULT_WASM_DIR.into()));
    if args.next().is_some() {
        return Err(format!(
            "unexpected extra argument; usage: harvest-addresses [WASM_DIR] (default {DEFAULT_WASM_DIR})"
        ));
    }

    // Keep in step with the artifact list in `scripts/build-contract-wasm.sh`
    // and with the registries under `legacy/`. An artifact missing here is an
    // artifact whose address nothing watches -- the same failure this binary
    // exists to close, one level up.
    //
    // `ghostkey_delegate.wasm` is absent because this binary answers "did THIS
    // pull request move an address", and nothing in this workspace can move a
    // vendored artifact. That is true, and it is also the wrong question to
    // stop at.
    //
    // The risk for a vendored delegate is not that WE move it -- it is that
    // freenet/ghostkeys moves and we do not follow. A delegate's identity is
    // BLAKE3(BLAKE3(wasm) || params), so falling behind puts Harvest on a
    // DIFFERENT delegate instance with its own, empty secret store, while the
    // user's ghostkeys stay under the current one.
    //
    // That happened, and nothing here noticed for six generations (harvest#5).
    // The symptom was not an error: the vendored delegate could not even
    // deserialize `RequestAnyAccess`, so it never replied, and "Connect a
    // ghostkey" spun on "Waiting for vault..." indefinitely.
    //
    // A relative HEAD-vs-base comparison structurally cannot catch this,
    // because both sides are equally stale. Catching it needs an ABSOLUTE
    // check against upstream -- ghostkeys publishes a pointer record naming
    // its current delegate code hash, at HYBCmCSGKjr4jUUoTzivZ48UynjLscwA3nvnpKQAwi3a,
    // readable over the node like any other contract. Resolving that instead
    // of vendoring is harvest#5's actual fix.
    let artifacts: Vec<(&str, Kind, Vec<u8>)> = vec![
        (
            "reputation_contract",
            Kind::Contract,
            placeholder_params_cbor::<ReputationParameters>()?,
        ),
        (
            "store_contract",
            Kind::Contract,
            placeholder_params_cbor::<StoreParameters>()?,
        ),
        (
            "mailbox_contract",
            Kind::Contract,
            placeholder_params_cbor::<MailboxParameters>()?,
        ),
        (
            "harvest_delegate",
            Kind::Delegate,
            DELEGATE_PARAMETERS.to_vec(),
        ),
    ];

    println!("# artifact\tkind\tcode_hash\tparams_len\tparams_hex\taddress");
    for (name, kind, params) in artifacts {
        let wasm = read_wasm(&dir, name)?;
        let (code_hash, address) = derive(&kind, &wasm, &params);
        println!(
            "{name}\t{}\t{code_hash}\t{}\t{}\t{address}",
            kind.label(),
            params.len(),
            hex::encode(&params),
        );
    }
    Ok(())
}

fn read_wasm(dir: &Path, artifact: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(format!("{artifact}.wasm"));
    // A missing artifact is a failure, never a skip. "No file, nothing to
    // check" is exactly how a guard stops being able to fail.
    std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// `(code hash hex, address base58)`, both from stdlib's own constructors.
fn derive(kind: &Kind, wasm: &[u8], params: &[u8]) -> (String, String) {
    let params = Parameters::from(params.to_vec());
    match kind {
        Kind::Contract => {
            let key = ContractKey::from_params_and_code(&params, ContractCode::from(wasm.to_vec()));
            (hex::encode(key.code_hash().as_ref()), key.id().encode())
        }
        Kind::Delegate => {
            // The same call `ui/src/gateway/delegate_api.rs::register_delegate`
            // makes, so the key printed here is the key the node is asked for.
            let code = DelegateCode::from(wasm.to_vec());
            let key = Delegate::from((&code, &params)).key().clone();
            (hex::encode(key.code_hash().as_ref()), key.encode())
        }
    }
}
