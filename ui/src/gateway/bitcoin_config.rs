//! Bitcoin trust policy for this build: whose signatures on Bitcoin facts it
//! accepts, and which networks it can settle a payment on.
//!
//! # What is NOT here any more, and why
//!
//! This file used to carry ADDRESSING constants too: the address contract's
//! code hash and the signet tip contract's id. A contract's address is
//! `BLAKE3(BLAKE3(wasm) || parameters)`, so both went quietly wrong whenever
//! the bridge was redeployed with different bytes, and they did (harvest#30).
//! Once they were found five generations stale, with the published app
//! rendering a chain tip ~400 blocks old as though it were live; and on
//! 2026-09-16 the address hash named the generation replaced on nova that day,
//! so every invoice would have named a contract the bridge no longer wrote to.
//!
//! A stale content-addressed constant does not fail quiet, it fails
//! plausible: the old address is a real contract holding real, once-valid
//! state. So neither is compiled in now. Both come from the pointers the
//! bridge signs, resolved at runtime in `crate::bitcoin_generation` and
//! `gateway::bitcoin_generation_ops`. The bridge's HTTP status endpoint, which
//! a plan once relied on and the gateway's content-security policy forbade,
//! no longer exists either.
//!
//! What remains is trust, not addressing. The bridge id below says whose
//! signature this app believes, which is a policy decision a rebuild does not
//! change, so it can go stale only by a deliberate change of bridge.

use freenet_bitcoin_common::BitcoinNetwork;

/// The network the first-run panel defaults to showing before the user has
/// picked one. Signet, because that is where the bridge this build trusts is
/// deployed.
pub fn default_network() -> BitcoinNetwork {
    BitcoinNetwork::Signet
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
    /// confirmations against, or the bridge's observations cannot be dated.
    /// Its id is derived at runtime from the tip pointer's code hash and that
    /// network's trusted bridges, so what this checks is that the derivation
    /// succeeds for every settleable network. The glue registers a tip for
    /// each of them, not only the default one.
    #[test]
    fn every_settleable_network_can_derive_a_tip_contract() {
        for network in settleable_networks() {
            let bridges =
                default_trusted_bridges(*network).expect("a settleable network names a bridge");
            assert!(
                crate::bitcoin_generation::tip_contract_id(&[7u8; 32], *network, &bridges).is_ok(),
                "{} is offered for settlement but no tip contract derives for it",
                network.as_str()
            );
        }
    }
}
