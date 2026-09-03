# Harvest

**Harvest** is a decentralized marketplace application for [Freenet](https://freenet.org). It enables peer-to-peer commerce with anonymous, donation-backed identities and a novel accountability mechanism based on blind-signature feedback tokens.

Harvest joins the family of Freenet apps alongside [River](https://github.com/freenet/river) (group chat) and [Delta](https://github.com/freenet/delta) (wiki/CMS).

## Status

Early design / scaffolding. The protocol is described in [`docs/design.md`](docs/design.md). Code lives in this workspace but the subsystems are not yet implemented.

## Architecture

Harvest is built on two layers:

1. **Ghostkeys** (via [`ghostkey-common`](https://crates.io/crates/ghostkey-common)) — anonymous identities backed by Freenet donations, providing Sybil-resistant pseudonyms with verifiable economic stake.
2. **Harvest** — this repository. Stores, encrypted buyer-seller messaging, and a reputation contract with blind-signature feedback tokens.

## Workspace layout

```
harvest/
├── common/          # harvest-common: wire types shared across contracts, delegate, UI
├── contracts/       # Freenet contracts: store, mailbox, reputation
├── delegates/       # Freenet delegates: harvest delegate (feedback-token RSA keypair, transaction state)
├── ui/              # Dioxus web UI
└── docs/
    └── design.md    # Full design document
```

## Building

```bash
cargo check --workspace
```

The contract and delegate WASMs are built by one script, and only by it:

```bash
./scripts/build-contract-wasm.sh          # build, print BLAKE3 code hashes
./scripts/build-contract-wasm.sh --sync   # also refresh ui/public/contracts/
```

A Freenet contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, so the
compiled bytes are the address. The script pins the flags that keep the build
byte-reproducible across machines, and CI runs the same script on both sides of
every pull request and fails it when an address moves — including when the
cause is only a transitive dependency bump in `Cargo.lock`. If a re-key is
intended, label the PR `contract-rekey-acknowledged` after planning the
migration.

`Cargo.lock` is committed for the same reason: the resolved dependency versions
are an input to the address, so leaving them to float means the contracts have
no stable identity.

## License

MIT OR Apache-2.0
