//! Well-known Bitcoin contract configuration.
//!
//! # Why this file exists and why it is empty today
//!
//! The first-run Bitcoin panel needs to subscribe to a network's
//! `BitcoinTipContract` before the user has watched anything or connected a
//! Ghost Key -- that is the whole point of showing live chain data with no
//! credential. Subscribing needs that contract's `ContractInstanceId`, which
//! is a hash over its WASM code plus its `BitcoinTipParameters` (network +
//! trusted bridge keys).
//!
//! A bridge now exists (`freenet-bitcoin/bridge`, deployed on nova against
//! signet), but its tip-contract id deliberately stays OUT of this file.
//!
//! A `BitcoinTipContract`'s id is a hash over its WASM plus its parameters,
//! and its parameters include `trusted_bridges`, which is per-deployment
//! rather than a fixed per-network constant. A compiled-in id would therefore
//! go stale on any re-key -- including a bare version bump -- and the failure
//! is silent: every read comes back looking like "this network has no data
//! yet". So the id is fetched at runtime from the bridge's unauthenticated
//! `GET /v1/status`, which reports it (see `bitcoin_bridge_http`).
//!
//! ## Why runtime discovery over HTTP does NOT work, and this file matters again
//!
//! The plan was for the browser to fetch `<bridge>/v1/status` and read the id
//! from there. **The gateway's Content-Security-Policy forbids it.** A webapp
//! is served with `connect-src http://127.0.0.1:7509 blob: data:`, so it may
//! talk to its own gateway and nothing else. The fetch is refused:
//!
//! ```text
//! Refused to connect to 'http://127.0.0.1:8431/v1/status' because it
//! violates the document's Content Security Policy.
//! ```
//!
//! That is not a bug to route around -- it is the sandbox doing its job. A
//! Freenet webapp reaches the network through its node, not through arbitrary
//! HTTP. So the values below are build-time configuration, and the HTTP path
//! is kept only for a non-gateway context (local `dx serve`) where CSP does
//! not apply.
//!
//! **This is a stopgap and it has the exact staleness problem the constant was
//! meant to avoid**: a contract rebuild re-keys the tip contract and this file
//! goes quietly wrong.
//!
//! That is not a warning about the future. It HAPPENED, and was found on
//! 2026-09-06 (harvest#30): both constants below were stale, one of them by
//! five generations. Record what the failure actually looked like, because it
//! is not what this file predicted:
//!
//!   * It did NOT report "this network has no data yet". The superseded tip
//!     contract still exists on the network and still holds the last state it
//!     was given, so the published app rendered a chain tip ~400 blocks old,
//!     frozen three days, indistinguishable from live data.
//!   * The stale address code hash was stamped onto every invoice issued,
//!     naming an address contract that was never published -- so a payment
//!     could never be observed, and nothing about the invoice looked wrong.
//!   * The trusted-bridge constant was CORRECT throughout. Trust was right and
//!     addressing was wrong, which is why nothing errored: the app believed the
//!     right signer and looked in the wrong places.
//!
//! **A stale content-addressed constant does not fail quiet, it fails
//! plausible.** The old address is a real contract holding real, once-valid
//! state. That is worse than an empty panel and is the reason "only
//! well-formedness is asserted" was an expensive gap.
//!
//! The durable fix is a POINTER RECORD -- a fixed-address, author-signed
//! contract naming the current code hash, read over the WebSocket like any
//! other contract, which is what `freenet-migrate`'s pointer mechanism exists
//! for and what ghostkeys already does. Ghostkeys is a working reference: it
//! carries `pointer-records.toml`, `scripts/sign-pointer-records.sh`, and a CI
//! `check-pointer-freshness` job that fails the PR when an artifact's WASM
//! changed and no new record was signed. That CI gate is precisely what is
//! missing here. `freenet-bitcoin` already ships `generation/pointer-v1.wasm`
//! but has no records config yet.
//!
//! Until that is in place, treat the constants below as needing an update
//! whenever `freenet-bitcoin`'s `legacy/` registries gain an entry -- and note
//! that appending to those registries is exactly what a re-key does, so an
//! entry appearing there IS the signal that this file is now wrong.

use freenet_bitcoin_common::BitcoinNetwork;

/// bs58 `ContractInstanceId` of the network-wide `BitcoinTipContract`, or
/// `None` if no deployment is known for that network yet.
pub fn well_known_tip_contract_id(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Bitcoin => None,
        BitcoinNetwork::Testnet4 => None,
        // The bridge deployed on nova, observing signet. Derived from
        // BitcoinTipParameters { network: Signet, trusted_bridges: [that
        // bridge] } plus the tip contract's code hash.
        //
        // Re-derive with: curl -s <bridge>/v1/status
        //
        // UPDATED 2026-09-06. The previous value, B24HMUFasG3Yd1EJxfzb3qTPos1t
        // LMiKo5gYiKwaihqT, had been superseded and the failure was NOT the
        // "this network has no data yet" the module docs predicted. That old
        // contract still exists on the network and still holds the last state
        // it was given, so the published app rendered a chain tip ~400 blocks
        // stale, frozen three days, as if it were current -- while the bridge
        // was at height 320955. See harvest#30.
        //
        // A stale address here does not go quiet. It points at a real contract
        // holding real, once-valid, now-frozen state, and confirmation depth is
        // measured against that tip.
        BitcoinNetwork::Signet => Some("FXFgLKfuMm3NPtzWg3Ghgt5otv4Yo7N4CWGDvHpVeZMm"),
        BitcoinNetwork::Regtest => None,
    }
}

/// The network the first-run panel defaults to showing before the user has
/// picked one. Signet for the same reason as above: it's where a demo
/// deployment would live.
pub fn default_network() -> BitcoinNetwork {
    BitcoinNetwork::Signet
}

/// The bridge to ask before the user has configured one.
///
/// # Why localhost, and not a freenet.org URL
///
/// Defaulting to the user's own machine matches what the architecture actually
/// recommends: running your own bridge is the real answer to bridge-operator
/// correlation, because an operator necessarily learns which scripts it has
/// been asked to synchronize. A default that points everyone at one operator
/// would quietly make the privacy-worst option the path of least resistance.
///
/// It also fails honestly. If no local bridge is running the fetch simply
/// fails and the UI says no bridge is configured, rather than showing data
/// from a service the user never chose.
///
/// A hosted freenet.org bridge is a genuine product decision that has not been
/// made: it needs a published URL, a decision about who signs for it, and --
/// because it would be internet-facing rather than loopback -- the Ghost Key
/// authorization policy switched on and rate limiting configured. Until then,
/// pointing the default at a URL that does not exist would be worse than
/// pointing it at one that might.
pub fn default_bridge_url() -> &'static str {
    "http://127.0.0.1:8431"
}

/// Signing key of the bridge whose observations this build accepts.
///
/// This is trust policy, not addressing: it says whose signature on a Bitcoin
/// fact this app will believe. It is deliberately a build-time constant
/// because changing it changes who you trust, which should never happen
/// silently at runtime.
pub const TRUSTED_BRIDGE_ID_BS58: &str = "4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL";

/// Code hash of the `BitcoinAddressContract` build this app derives keys from.
///
/// Needed to compute a watched address's contract id locally, since the
/// gateway CSP rules out asking the bridge. Goes stale on any contract
/// rebuild -- see the module docs on the pointer-record fix.
///
/// UPDATED 2026-09-06 from `3b5f1df2...`, which `freenet-bitcoin`'s
/// `legacy/address_contract.toml` lists as generation **A3** -- a file whose
/// header states it records ONLY superseded generations. The deployed bridge
/// reports A8. So this build was stamping five-generations-old code hashes
/// onto every invoice it issued, naming an address contract that was never
/// published. See harvest#30.
pub const ADDRESS_CONTRACT_CODE_HASH_HEX: &str =
    "cd2ae7418e3b29c2770fab549763b8a268d54787a86a9bfad5b59ca3d2023555";

/// Which networks this build can actually settle a payment on.
///
/// [`TRUSTED_BRIDGE_ID_BS58`] is one bridge observing ONE network. Naming it
/// on an invoice for any other network produces an order that can never be
/// proven paid: `verify_payment_proof` measures depth against a signed tip for
/// the order's own network, and no signature from a signet observer will ever
/// satisfy a mainnet order. The invoice would look entirely normal.
///
/// Returned as a list rather than a single value because a build could ship
/// more than one bridge; today it ships one.
pub fn settleable_networks() -> &'static [BitcoinNetwork] {
    // The nova deployment observes signet, and it is the only bridge this
    // build trusts. Add a network here only alongside a bridge that watches
    // it -- an entry with no observer is an unpayable invoice waiting to be
    // issued.
    &[BitcoinNetwork::Signet]
}

/// The bridge set a freshly-issued invoice names, as an `Order` carries it.
///
/// An `Order::trusted_bridges` that is empty can never be proven paid --
/// `verify_payment_proof` returns `NoTrustedBridges` outright -- so an invoice
/// issued without this would be unpayable from the moment it was signed, and
/// nothing about it would look wrong. That is exactly what happened while the
/// bridge list was a store parameter: every store the UI created was published
/// with an empty list and was permanently incapable of accepting a payment.
///
/// Returning a `Result` rather than defaulting to an empty list is the point:
/// a malformed constant must stop an invoice being issued, not quietly issue
/// one that cannot be settled. **A network with no bridge is the same failure
/// wearing a different hat** -- a non-empty list of observers that watch some
/// other chain is no better than an empty one, and worse to diagnose, so it is
/// refused here rather than stamped onto the order.
pub fn default_trusted_bridges(
    network: BitcoinNetwork,
) -> Result<Vec<freenet_bitcoin_common::BridgeId>, String> {
    if !settleable_networks().contains(&network) {
        return Err(format!(
            "this build knows no Bitcoin bridge that watches {}, so an invoice for it \
             could never be shown to have been paid. It settles payments on: {}.",
            network.as_str(),
            settleable_networks()
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    freenet_bitcoin_common::BridgeId::from_bs58(TRUSTED_BRIDGE_ID_BS58)
        .map(|id| vec![id])
        .map_err(|e| format!("the build's trusted bridge id is unusable: {e}"))
}

/// [`ADDRESS_CONTRACT_CODE_HASH_HEX`] as the 32 bytes an `Order` carries.
///
/// `None` for a malformed constant rather than an error, because this field is
/// genuinely optional: it drives only the store contract's additive-only
/// related-contract cross-check, and `None` skips that check and forfeits
/// nothing else (the embedded payment proof stays authoritative either way).
/// So an unusable constant must not block issuing an invoice -- unlike the
/// bridge list above, which decides whether the invoice can ever be settled.
pub fn address_contract_code_hash() -> Option<[u8; 32]> {
    let bytes = hex::decode(ADDRESS_CONTRACT_CODE_HASH_HEX).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both constants are hand-maintained (see the module docs on why they
    /// cannot be discovered at runtime), so a typo in either is a real
    /// possibility -- and the consequence of a bad bridge id is an invoice
    /// that can never be proven paid.
    ///
    /// Note what this does NOT check: that
    /// `ADDRESS_CONTRACT_CODE_HASH_HEX` is the hash of the address contract
    /// actually deployed. That is the way it really goes wrong -- silently, on
    /// a rebuild of a contract this workspace does not build -- and it cannot
    /// be checked here, because the artifact is not bundled. Only well-formedness
    /// is asserted.
    ///
    /// **That gap was not hypothetical and it has since been paid.** On
    /// 2026-09-06 both constants were found stale against the deployed bridge
    /// (harvest#30) -- well-formed throughout, so this test passed the entire
    /// time. The paragraph above described the failure accurately in advance
    /// and nothing acted on it, which is the argument for closing it with a
    /// pointer record rather than a sharper comment.
    ///
    /// Do not be tempted to "fix" this by asserting the constants equal
    /// specific literals: that tests the file against itself and would also
    /// have passed. The check has to compare against something outside this
    /// repository -- the bridge, or a pointer record resolved over the node.
    #[test]
    fn the_builds_bitcoin_constants_parse() {
        let bridges = default_trusted_bridges(default_network())
            .expect("the trusted bridge id must parse for the default network");
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges[0].to_bs58(), TRUSTED_BRIDGE_ID_BS58);

        assert!(
            address_contract_code_hash().is_some(),
            "the address contract code hash must be 32 hex-encoded bytes"
        );
    }

    /// An invoice for a network no bridge watches can never be shown to have
    /// been paid, and looks entirely normal. Refusing to build one is the only
    /// point at which that is visible.
    #[test]
    fn a_network_with_no_bridge_cannot_be_invoiced_for() {
        for network in [
            BitcoinNetwork::Bitcoin,
            BitcoinNetwork::Testnet4,
            BitcoinNetwork::Regtest,
        ] {
            let err = default_trusted_bridges(network)
                .expect_err("a network with no bridge must be refused");
            assert!(
                err.contains(network.as_str()),
                "the error must name the network: {err}"
            );
        }
    }

    /// The default network has to be one the build can settle on, or the form
    /// opens pre-set to a choice that cannot produce a payable invoice.
    #[test]
    fn the_default_network_is_one_this_build_can_settle() {
        assert!(settleable_networks().contains(&default_network()));
    }

    /// A network we can settle on must also have a tip contract to measure
    /// confirmations against; without one the bridge's observations cannot be
    /// dated. The two lists are maintained separately, so this is the check
    /// that they agree.
    #[test]
    fn every_settleable_network_has_a_tip_contract() {
        for network in settleable_networks() {
            assert!(
                well_known_tip_contract_id(*network).is_some(),
                "{} is offered for settlement but has no tip contract",
                network.as_str()
            );
        }
    }
}
