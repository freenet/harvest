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
//! The durable fix is a POINTER RECORD: a fixed-address, bridge-signed
//! contract naming the current code hash, read over the WebSocket like any
//! other contract. For the ADDRESS contract that fix is now in place. The code
//! hash an invoice carries comes from the bridge's signed pointer, resolved in
//! `crate::bitcoin_generation`, and the constant that used to live here is
//! gone rather than kept as a fallback: on 2026-09-16 it named the generation
//! replaced on nova that day, and a fallback would have stamped exactly that
//! onto invoices.
//!
//! The TIP contract's id below is still a build-time constant, with the
//! staleness problem described above. It is correct today, and it will go
//! quietly wrong on the next re-key of the tip contract. Resolving it needs
//! the tip contract's parameters derived here as well as its pointer; that is
//! the remaining half of harvest#30.

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The trusted bridge id is hand-maintained, so a typo is a real
    /// possibility, and the consequence of a bad one is an invoice that can
    /// never be proven paid.
    ///
    /// This used to assert the address contract's code hash was well-formed
    /// too. That check passed the whole time the hash was stale (harvest#30),
    /// which is why the hash is now resolved from the bridge's signed pointer
    /// instead of carried here, and the assertion went with it.
    ///
    /// Do not be tempted to "fix" a constant check by asserting it equals a
    /// specific literal: that tests the file against itself and would also
    /// have passed. A check that means anything compares against something
    /// outside this repository, the bridge or a pointer resolved over the node.
    #[test]
    fn the_builds_bitcoin_constants_parse() {
        let bridges = default_trusted_bridges(default_network())
            .expect("the trusted bridge id must parse for the default network");
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges[0].to_bs58(), TRUSTED_BRIDGE_ID_BS58);
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
