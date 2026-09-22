# Predecessor generations

A Freenet contract lives at `BLAKE3(BLAKE3(wasm) || parameters)` and a delegate
at `BLAKE3(BLAKE3(wasm) || parameters)`. **The compiled bytes are the address.**
Any change to codegen -- a source edit, a direct or transitive dependency bump,
a rustc upgrade, a `cargo fmt` that moves a panic location -- moves every
instance to a new address, and the new address starts empty while the user's
data sits at the old one.

Each file here lists the **superseded** code hashes of one artifact, oldest
first. `ui/src/migrate.rs` walks them, derives each predecessor's instance id
from `(code_hash, parameters)`, probes it, and folds what it finds into the
current generation.

Note "parameters", not "current parameters". A contract's address is
`BLAKE3(code_hash || parameter_bytes)`, so changing a parameter STRUCT re-keys
every generation's derivation as surely as changing the WASM does -- and
`freenet_migrate` derives every predecessor from a single set of parameter
bytes, so it cannot notice on its own. `StoreParameters` has already changed
once (the Bitcoin bridge list moved onto `Order`); `store_candidates` handles
that split, and `store_contract.toml`'s header records where the boundary
falls. **If you edit a parameter struct, that split is part of the change**,
and skipping it fails silently: every probe comes back `NotFound` and the
sweep reports a clean migration having looked at addresses that never existed.

CI will now tell you when that happens. `contract-drift.yml` compares the
derived ADDRESS on both sides of a PR, not just the compiled WASM, so a
parameters-only change is a red check naming the artifact and the byte counts
(`56 -> 69 bytes`) instead of nothing at all. It used to be nothing at all:
both guards compared the WASM, so the `StoreParameters` change above passed
them both, truthfully, and was caught only because someone measured the CBOR by
hand. The derivation lives in `common/src/bin/harvest-addresses.rs`, which
encodes the live parameter structs with the same encoder the app publishes
with; `cargo make code-hashes` prints the same addresses locally.

Note what the red check does NOT do for you: it says the address moved, and
the split in `ui/src/migrate.rs` is still yours to write.

## Rules

* **Superseded hashes only.** The current generation is derived at runtime from
  the WASM this build ships and is deliberately never written down -- a
  hardcoded "current" hash goes stale silently on the next rebuild.
* **Record the outgoing hash BEFORE rebuilding.** `cargo make code-hashes`
  prints the current hash; append it here, then rebuild. That task also *fails*
  if the current hash already appears in a registry, which is the sign that a
  rebuild happened without the entry being appended.
* **Never delete a row.** A removed generation is a generation nothing probes.
* **Record what reached `main`, not every build.** A row is for WASM that
  was committed on `main` (and so could have been published, or run by
  anyone building `main`), recorded when a later change supersedes it. An
  intermediate build that existed only on an open PR branch, rebuilt before
  that PR merged, never held anyone's data and gets no row; a stack of PRs
  merged and published together records only the generation it replaces
  on `main`.
* **A new generation must be migratable from every generation that has held
  user data.** Appending a row here is not enough on its own: if the change
  also alters how a record's identity or signature preimage is derived, the
  predecessor's records stop verifying and the fold discards that generation
  **in full** -- listings, orders and the store's own details together, and
  refuses it again on every walk -- and it spends the property that **any UI can
  migrate a contract**, which holds only while new versions accept old state.
  See [`docs/design/migratability.md`](../docs/design/migratability.md) for the
  requirement, what one such change cost, and why the owner-assisted re-issue
  fallback is an escape hatch rather than the answer.
* **Verify a hash rather than copying it.** Every hash below was produced by
  hashing the committed artifact out of git history:
  `git show <commit>:ui/public/contracts/<artifact>.wasm | b3sum --no-names`.
  That works because the UI embeds these files with `include_bytes!`, so the
  committed bytes at a commit *are* the bytes that were deployed from it.

## Why the files live at the repo root, and the codegen in `ui/build.rs`

The probe runs client-side in the UI, so `harvest-ui` is the crate that needs
the generated consts and the crate whose `build.rs` emits them.

The TOML itself sits at the repo root rather than under `ui/` for one reason
that matters: `harvest-common` is compiled *into* all three contracts, so
anything codegen'd there would make **editing a registry re-key every contract
it describes** -- a migration registry that causes the migration it records.
The root keeps the registries visibly outside the contract build graph, and
lets `cargo make code-hashes` and CI read them without reaching into a crate.
