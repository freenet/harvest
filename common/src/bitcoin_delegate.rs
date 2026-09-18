//! The Harvest delegate's Bitcoin payment surface.
//!
//! # Why the watch list lives here and nowhere else
//!
//! Everything in this module is **private local state on the user's own
//! machine**. None of it is ever written to a Freenet contract.
//!
//! The tempting alternative is a `WatchRegistry` contract listing the scripts
//! people want synchronized, which would make the bridge's job trivial. It is
//! also the one thing this design refuses to build: Freenet contracts are
//! reachable by anyone who knows the key and are replicated indefinitely, so
//! such a registry would be a permanent, globally enumerable index of who
//! cares about which Bitcoin address. Merely *watching* an address must never
//! make that interest public.
//!
//! An order's payment destination IS public, in the Harvest store contract —
//! but for a different and legitimate reason: decentralized payment
//! verification is impossible unless everyone can see what was owed and where.
//! That is application semantics requiring publication. It is not the same as
//! publishing a user's arbitrary list of interests, and the two must not be
//! allowed to blur together.
//!
//! # What the bridge unavoidably learns
//!
//! To synchronize script X, the bridge has to be told about X. So the operator
//! of a bridge you use knows that *somebody it authorized* asked about X, and
//! — because a Ghost Key certificate is a stable identifier reused across
//! requests — can link a single user's requests to each other. That is real,
//! it is not fixed by anything in this file, and it is written up honestly in
//! `docs/privacy.md` along with the mitigations available to a user who cares.

use serde::{Deserialize, Serialize};

use freenet_bitcoin_common::{BitcoinNetwork, BridgeId};

use crate::payment::OrderId;

/// One script the user is privately watching.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WatchedPayment {
    pub network: BitcoinNetwork,
    /// Canonical `scriptPubKey`. The identity; the address string is display.
    pub script_pubkey: Vec<u8>,
    /// Human-readable address, for display only.
    pub address: String,
    /// The user's private label. Never leaves this machine.
    pub label: Option<String>,
    /// Set when this watch exists because of a Harvest order rather than a
    /// manual request. Both kinds share the same machinery and the same
    /// privacy properties; this only drives how the UI groups them.
    pub order_id: Option<OrderId>,
    pub expected_amount_sats: Option<u64>,
    /// Freenet contract instance id (bs58) of the address contract, so the UI
    /// can subscribe without recomputing the key.
    pub contract_id: Option<String>,
    /// Milliseconds since the Unix epoch, taken from the UI at the moment of
    /// the request. Delegates may read a clock; contracts may not, and none of
    /// this value ever reaches one.
    pub added_at_ms: u64,
    /// Whether a bridge has confirmed it is synchronizing this script.
    pub bridge_synced: bool,
    /// Why the last bridge request failed, if it did. Surfaced so the UI can
    /// say "needs a Ghost Key" rather than silently showing nothing.
    pub last_error: Option<String>,
}

impl WatchedPayment {
    /// Stable key for this watch: network plus script.
    pub fn key(&self) -> String {
        format!(
            "{}:{}",
            self.network.as_str(),
            hex::encode(&self.script_pubkey)
        )
    }
}

/// How the delegate should authorize itself to a bridge.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BridgeAuthMode {
    /// The bridge serves anyone; send no credential.
    Open,
    /// Authorize with the user's Ghost Key.
    ///
    /// The delegate holds the credential; it is never handed to a Harvest
    /// contract, and never to the UI in a form the UI could replay elsewhere.
    GhostKey { fingerprint: String },
}

/// A bridge the user's delegate will talk to.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BridgeEndpoint {
    /// HTTPS base URL of the bridge service.
    pub url: String,
    /// The bridge's signing key, so observations can be verified.
    ///
    /// Separate from anything about authorization: this is "whose signature do
    /// I accept on Bitcoin facts", not "may I ask this bridge for work".
    pub bridge_id: BridgeId,
    pub network: BitcoinNetwork,
    pub auth: BridgeAuthMode,
}

/// The seller's account-level extended public key, and how far the per-order
/// derivation has got through it.
///
/// # Why an xpub and not a key the delegate generates
///
/// An extended PUBLIC key can derive receiving addresses and nothing else, so
/// the delegate never holds anything that could move a coin and there is no
/// private key for the UI to leak. The corresponding private key stays in the
/// seller's own wallet, which is also the only thing that makes the payments
/// SPENDABLE: an invoice paid to a key Harvest generated internally and never
/// disclosed would be money nobody could ever retrieve.
///
/// This is the same arrangement a merchant already runs with any watch-only
/// point-of-sale setup, and the one-time cost is pasting one string.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PaymentXpubStatus {
    /// The account xpub as the seller pasted it. Public by construction --
    /// this is not a secret in the sense a signing key is, but it IS a
    /// privacy fact (it links every address it derives), so it is never
    /// written to a contract. See this module's header.
    pub xpub: String,
    /// The network its addresses belong to. Checked against the xpub's own
    /// version prefix when it is set, so a mainnet key cannot be filed as a
    /// signet one.
    pub network: BitcoinNetwork,
    /// The next child index `DeriveOrderAddress` will hand out. Monotonic:
    /// an index is consumed when it is handed out, never when the invoice
    /// that asked for it succeeds, because an address that reached the UI
    /// may already have been shown to a buyer.
    pub next_index: u32,
}

/// One freshly-derived payment destination for a single order.
///
/// The delegate returns the script AND the address string it encodes, rather
/// than letting the caller re-derive one from the other: verification uses the
/// script and humans use the address, and the two going out of step is a class
/// of bug where a buyer pays somewhere the order cannot recognise.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct DerivedAddress {
    /// Child index within the external chain, i.e. `m/0/index` below the
    /// account xpub. Carried so a seller can tell their wallet which address
    /// an invoice used.
    pub index: u32,
    pub network: BitcoinNetwork,
    pub script_pubkey: Vec<u8>,
    pub address: String,
}

/// How many consecutive derivation indices past the last published order the
/// delegate scans before concluding there are none further up. Shared so the
/// UI knows when an unmatched script may have come within reach again; see
/// the delegate's `apply_published_floor`.
pub const PUBLISHED_INDEX_GAP: u32 = 100;

/// Requests the UI sends the delegate about Bitcoin payments.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BitcoinDelegateRequest {
    /// Start watching a script. Purely local until the delegate asks a bridge
    /// to synchronize it.
    Watch {
        request_id: u64,
        watch: WatchedPayment,
    },
    /// Stop watching. Also asks the bridge to drop its interest, though the
    /// bridge may keep synchronizing for other users — and deliberately does
    /// not say whether it will, since that would leak whether anybody else
    /// is watching the same address.
    Unwatch {
        request_id: u64,
        network: BitcoinNetwork,
        script_pubkey: Vec<u8>,
    },
    /// The user's private watch list.
    ListWatched,
    /// Attach a watch to an order, so the UI can group it under Payments.
    AssociateOrder {
        request_id: u64,
        network: BitcoinNetwork,
        script_pubkey: Vec<u8>,
        order_id: OrderId,
        expected_amount_sats: u64,
    },
    /// Configure which bridge to use and how to authorize to it.
    ConfigureBridge {
        request_id: u64,
        endpoint: BridgeEndpoint,
    },
    /// The configured bridge, if any. The UI needs this to render the
    /// public status panel before the user has authenticated with anything.
    GetBridge,

    /// Record the seller's account xpub, so invoices can be given a fresh
    /// payment address each.
    ///
    /// Replacing an existing xpub resets `next_index` to 0 (then raised past
    /// any published order it derives, see `published_scripts`): indices are only
    /// meaningful relative to the key they were derived under, so carrying a
    /// counter across a key change would skip addresses in the new wallet for
    /// no reason. It does NOT invalidate invoices already issued -- those name
    /// a script, not a key.
    SetPaymentXpub {
        request_id: u64,
        /// The account-level extended public key, base58check-encoded.
        xpub: String,
        /// The network the seller says it is for. Rejected if the xpub's own
        /// version prefix disagrees.
        network: BitcoinNetwork,
        /// See [`Self::DeriveOrderAddress`]'s field of the same name. Carried
        /// here too so the count the payments panel shows straight after the
        /// key is entered already accounts for the store's own orders.
        #[serde(default)]
        published_scripts: Vec<Vec<u8>>,
    },

    /// The configured payment xpub, if any, and how far derivation has got.
    GetPaymentXpub,

    /// Hand out the next unused payment address, consuming its index.
    ///
    /// The network comes from the stored xpub rather than from the caller, so
    /// there is no way to ask for an address on a network the key does not
    /// belong to.
    DeriveOrderAddress {
        request_id: u64,
        /// The payment scripts of every order the seller's own stores have
        /// published, as the UI last read them from the network.
        ///
        /// The delegate's counter lives on one device, and a new device (or a
        /// reinstall) starts it at 0 while the same wallet key's low addresses
        /// already carry published, possibly paid, orders (harvest#77). The
        /// delegate derives forward from its counter and moves it past the
        /// highest index whose script appears here, so the count follows the
        /// public record rather than the device. Public data: every script
        /// here is already in a store contract.
        #[serde(default)]
        published_scripts: Vec<Vec<u8>>,
    },
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BitcoinDelegateResponse {
    Watched {
        request_id: u64,
        result: Result<WatchedPayment, String>,
    },
    Unwatched {
        request_id: u64,
        result: Result<(), String>,
    },
    WatchList {
        watches: Vec<WatchedPayment>,
    },
    OrderAssociated {
        request_id: u64,
        result: Result<(), String>,
    },
    BridgeConfigured {
        request_id: u64,
        result: Result<(), String>,
    },
    Bridge {
        endpoint: Option<BridgeEndpoint>,
    },
    PaymentXpubSet {
        request_id: u64,
        result: Result<PaymentXpubStatus, String>,
        /// The request's `published_scripts` that the delegate matched to an
        /// index of this key. See `DeriveOrderAddress`.
        #[serde(default)]
        matched_scripts: Vec<Vec<u8>>,
    },
    /// `None` means no xpub is configured, which is the honest first-run
    /// answer -- distinct from "we have not asked yet", which the UI tracks
    /// separately so it does not prompt before it knows.
    PaymentXpub {
        status: Option<PaymentXpubStatus>,
    },
    OrderAddress {
        request_id: u64,
        result: Result<DerivedAddress, String>,
        /// The request's `published_scripts` that the delegate matched to an
        /// index of the stored key, i.e. that its counter now accounts for.
        /// A script sent but not listed here was foreign, already below the
        /// counter, or past the scan's gap, and the UI may offer it again.
        #[serde(default)]
        matched_scripts: Vec<Vec<u8>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch() -> WatchedPayment {
        WatchedPayment {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xde, 0xad],
            address: "tb1qexample".into(),
            label: Some("rent".into()),
            order_id: None,
            expected_amount_sats: Some(50_000),
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    #[test]
    fn watch_key_separates_networks_for_one_script() {
        let mut a = watch();
        let mut b = watch();
        a.network = BitcoinNetwork::Bitcoin;
        b.network = BitcoinNetwork::Signet;
        assert_ne!(a.key(), b.key());
    }

    #[test]
    fn requests_roundtrip_through_cbor() {
        let req = BitcoinDelegateRequest::Watch {
            request_id: 7,
            watch: watch(),
        };
        let bytes = crate::to_cbor(&req).unwrap();
        assert_eq!(
            crate::from_cbor::<BitcoinDelegateRequest>(&bytes).unwrap(),
            req
        );
    }

    /// The private label must not be something the UI can accidentally leak
    /// into a bridge request: the bridge protocol has no field for it.
    #[test]
    fn the_bridge_watch_request_has_nowhere_to_put_a_private_label() {
        let w = watch();
        let req = freenet_bitcoin_common::WatchRequest {
            network: w.network,
            script_pubkey: w.script_pubkey.clone(),
            scan_from_height: None,
        };
        let encoded = crate::to_cbor(&req).unwrap();
        let haystack = String::from_utf8_lossy(&encoded).to_string();
        assert!(
            !haystack.contains("rent"),
            "a private label reached the bridge wire format"
        );
    }
}
