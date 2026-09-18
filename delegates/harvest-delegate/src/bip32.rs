//! Deriving a fresh Bitcoin payment address per order, from a seller's
//! account extended PUBLIC key.
//!
//! # Why address reuse is the thing this exists to prevent
//!
//! Two invoices sharing one script share one payment history, and the
//! evidence a payment carries is scoped to a script rather than to an order:
//! `freenet_bitcoin_common`'s claims name an outpoint paying a script, and
//! `harvest_common::payment::verify_payment_proof` folds every claim it is
//! handed for that script. So a single 50,000-sat payment presented against
//! two 50,000-sat invoices on the SAME address satisfies both, and nothing in
//! either order can tell that it was one payment. A fresh script per invoice
//! removes the ambiguity at the source; no amount of checking downstream can
//! reconstruct it once two invoices share an address.
//!
//! # Public derivation only, deliberately
//!
//! Everything here operates on an *extended public key*. There is no private
//! key anywhere in Harvest, which is why nothing here can leak one -- and,
//! more importantly, it is what makes the coins spendable: the matching
//! private key lives in the seller's own wallet, so a payment lands somewhere
//! they can actually reach. A key generated inside the delegate and never
//! disclosed would produce invoices whose proceeds nobody could ever spend.
//!
//! # What is accepted, and what is refused
//!
//! Only BIP-84 account keys (`zpub` on mainnet, `vpub` on the test networks),
//! which unambiguously denote native-SegWit P2WPKH. A bare `xpub`/`tpub`
//! carries no script-type information at all, so deriving P2WPKH from one
//! would be a guess -- and a wrong guess produces addresses the seller's
//! wallet is not watching, which looks exactly like a payment that never
//! arrived. Those are refused with a message naming what to paste instead.
//!
//! Derivation is `m/0/index` below the account key: the external (receiving)
//! chain, per BIP-44/84. Every wallet that exports a BIP-84 account key
//! watches that chain by default.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

use freenet_bitcoin_common::BitcoinNetwork;

/// `zpub`: BIP-84 account key on mainnet.
const VERSION_ZPUB: u32 = 0x04b2_4746;
/// `vpub`: BIP-84 account key on the test networks (testnet4, signet, regtest
/// all share it -- Bitcoin's test networks deliberately reuse one encoding).
const VERSION_VPUB: u32 = 0x045f_1cf6;
/// `xpub`: BIP-32/44 mainnet, script type unspecified.
const VERSION_XPUB: u32 = 0x0488_b21e;
/// `tpub`: BIP-32/44 testnet, script type unspecified.
const VERSION_TPUB: u32 = 0x0435_87cf;
/// `ypub`: BIP-49 mainnet, P2SH-wrapped SegWit.
const VERSION_YPUB: u32 = 0x049d_7cb2;
/// `upub`: BIP-49 testnet, P2SH-wrapped SegWit.
const VERSION_UPUB: u32 = 0x044a_5262;

/// The external (receiving) chain. BIP-44's `change` level, 0 for addresses
/// handed to somebody else and 1 for change coming back to the wallet.
const EXTERNAL_CHAIN: u32 = 0;

/// A parsed BIP-84 account extended public key.
///
/// Holds only public material: a compressed point and a chain code. Neither
/// can produce a signature, so this type is incapable of spending anything it
/// derives.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountXpub {
    /// Compressed SEC1 point, 33 bytes.
    public_key: [u8; 33],
    chain_code: [u8; 32],
    /// Whether this key belongs to mainnet. The test networks share one
    /// encoding, so this is the only network fact an xpub actually carries --
    /// see [`AccountXpub::accepts_network`].
    mainnet: bool,
}

impl AccountXpub {
    /// Parse a base58check-encoded BIP-84 account key.
    pub fn parse(xpub: &str) -> Result<Self, String> {
        let xpub = xpub.trim();
        if xpub.is_empty() {
            return Err("enter your wallet's account public key".to_string());
        }
        let bytes = bs58::decode(xpub)
            .with_check(None)
            .into_vec()
            .map_err(|e| format!("that is not a valid extended public key: {e}"))?;
        if bytes.len() != 78 {
            return Err(format!(
                "an extended key is 78 bytes; this decoded to {}",
                bytes.len()
            ));
        }

        let version = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mainnet = match version {
            VERSION_ZPUB => true,
            VERSION_VPUB => false,
            // Named individually rather than lumped into one "unrecognised"
            // message: a seller who pasted an `xpub` has done something
            // reasonable and needs to be told which export to pick, not told
            // their key is invalid.
            VERSION_XPUB | VERSION_TPUB => {
                return Err(
                    "that is a legacy account key (xpub/tpub), which does not say which \
                     address type it is for. Export the native SegWit (BIP-84) account \
                     key instead -- it starts with \"zpub\" on mainnet or \"vpub\" on \
                     signet and testnet."
                        .to_string(),
                )
            }
            VERSION_YPUB | VERSION_UPUB => {
                return Err(
                    "that is a wrapped-SegWit account key (ypub/upub). Harvest issues \
                     native SegWit addresses, so export the BIP-84 account key instead \
                     -- it starts with \"zpub\" on mainnet or \"vpub\" on signet and \
                     testnet."
                        .to_string(),
                )
            }
            other => {
                return Err(format!(
                    "unrecognised extended-key version {other:#010x}. Harvest wants a \
                     native SegWit (BIP-84) account key, starting with \"zpub\" or \
                     \"vpub\"."
                ))
            }
        };

        // An ACCOUNT key sits at m/84'/coin'/account', i.e. depth 3. Checking
        // it catches the two mistakes that would otherwise be silent: pasting
        // the wallet's master key (depth 0), or pasting a single address's key
        // (depth 5). Both parse and both derive perfectly valid addresses --
        // for a wallet that is not watching them.
        let depth = bytes[4];
        if depth != 3 {
            return Err(format!(
                "that key is at depth {depth}, but an account key is at depth 3 \
                 (m/84'/coin'/account'). Export the ACCOUNT public key rather than the \
                 master key or a single address's key."
            ));
        }

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&bytes[13..45]);
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&bytes[45..78]);

        // Reject anything that is not a point on the curve here, once, rather
        // than at each derivation: an unparseable key would otherwise fail
        // only when the seller tried to issue their first invoice.
        //
        // The compressed-form check comes FIRST so it can give its own
        // message. After `decode_point` it would be unreachable: a 33-byte
        // buffer only decodes at all with an 0x02/0x03 tag, so any other tag
        // would already have been reported as "not a valid point".
        if public_key[0] != 0x02 && public_key[0] != 0x03 {
            return Err("that key's public point is not in compressed form".to_string());
        }
        if decode_point(&public_key).is_none() {
            return Err("that key's public point is not a valid secp256k1 point".to_string());
        }

        Ok(Self {
            public_key,
            chain_code,
            mainnet,
        })
    }

    /// Whether this key may be used for `network`.
    ///
    /// Mainnet is distinguishable and enforced. Testnet4, signet and regtest
    /// are NOT distinguishable from one another -- they share the `vpub`
    /// version exactly as they share address encodings (see
    /// `harvest-ui`'s `gateway::bitcoin_address` for the same limitation on
    /// the address side). So this catches a mainnet/test mix-up, which is the
    /// one that costs real money, and cannot catch signet-vs-testnet4.
    pub fn accepts_network(&self, network: BitcoinNetwork) -> bool {
        matches!(network, BitcoinNetwork::Bitcoin) == self.mainnet
    }

    /// The `scriptPubKey` and address for order index `index`, i.e. `m/0/index`.
    pub fn order_address(
        &self,
        index: u32,
        network: BitcoinNetwork,
    ) -> Result<(Vec<u8>, String), String> {
        if !self.accepts_network(network) {
            return Err(format!(
                "this account key is for {}, not {}",
                if self.mainnet {
                    "mainnet"
                } else {
                    "a test network"
                },
                network.as_str()
            ));
        }
        let leaf_key = self.external_chain()?.leaf_key(index)?;
        let script = p2wpkh_script_pubkey(&leaf_key);
        let address = p2wpkh_address(&leaf_key, network)?;
        Ok((script, address))
    }

    /// The external chain `m/0`, derived once.
    ///
    /// [`Self::order_address`] goes through this too, so a scan over many
    /// indices and the address handed to a buyer cannot come from two
    /// derivations that disagree.
    pub fn external_chain(&self) -> Result<ExternalChain, String> {
        // Non-hardened only, which public derivation is limited to anyway.
        let (key, chain_code) = derive_child(&self.public_key, &self.chain_code, EXTERNAL_CHAIN)?;
        Ok(ExternalChain { key, chain_code })
    }
}

/// The receiving chain below an account key, from which each order's key is
/// one more derivation.
///
/// Exists so that recovering the derivation counter from a store's published
/// orders (see `crate::bitcoin::apply_published_floor`) pays one child
/// derivation per index scanned instead of two.
pub struct ExternalChain {
    key: [u8; 33],
    chain_code: [u8; 32],
}

impl ExternalChain {
    /// The `scriptPubKey` for order index `index`, i.e. `m/0/index`.
    ///
    /// Network-free on purpose: a P2WPKH script is the same bytes on every
    /// network, which is also why the recovery scan can compare it against
    /// published orders without knowing which network they were for.
    pub fn script_at(&self, index: u32) -> Result<Vec<u8>, String> {
        Ok(p2wpkh_script_pubkey(&self.leaf_key(index)?))
    }

    fn leaf_key(&self, index: u32) -> Result<[u8; 33], String> {
        // `index` stays under 2^31: the delegate refuses to run past
        // `MAX_ORDER_INDEX`, and `derive_child` refuses a hardened index.
        let (leaf_key, _) = derive_child(&self.key, &self.chain_code, index)?;
        Ok(leaf_key)
    }
}

/// The highest child index this module will derive.
///
/// Public derivation is defined only for indices below 2^31; at or above that
/// the index means "hardened", which needs the private key. Refusing rather
/// than wrapping means a seller who somehow reached the end is told so instead
/// of silently being handed address 0 again -- which is the address-reuse this
/// whole module exists to prevent.
///
/// In practice a wallet's gap limit (typically 20 unused addresses) bites
/// unimaginably sooner; this bound is about the arithmetic, not the wallet.
///
/// One below `0x7fff_ffff` rather than equal to it, so that `index + 1` in
/// `apply_derive_order_address` cannot reach the hardened range even at the
/// last valid index. The cost is forfeiting one address out of two billion.
pub const MAX_ORDER_INDEX: u32 = 0x7fff_ffff - 1;

/// BIP-32 CKDpub: derive the public child at non-hardened `index`.
fn derive_child(
    parent_key: &[u8; 33],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 33], [u8; 32]), String> {
    if index >= 0x8000_0000 {
        return Err(format!(
            "index {index} is hardened, which cannot be derived from a public key"
        ));
    }

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(parent_chain_code)
        .map_err(|e| format!("chain code rejected by HMAC: {e}"))?;
    mac.update(parent_key);
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();

    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);

    // BIP-32: if IL is not a valid scalar, or the resulting point is the
    // identity, the child is invalid and the caller should move to index+1.
    // Both happen with probability around 2^-127, so this is reported rather
    // than handled -- an automatic skip would be untested code guarding an
    // event that will not occur, and a wrong-address bug if it were wrong.
    let scalar = Option::<Scalar>::from(Scalar::from_repr(il.into()))
        .ok_or_else(|| format!("child {index} is invalid (IL is not a scalar); use {index}+1"))?;
    let parent_point = decode_point(parent_key)
        .ok_or_else(|| "parent key is not a valid secp256k1 point".to_string())?;

    let child = ProjectivePoint::GENERATOR * scalar + ProjectivePoint::from(parent_point);
    let child = child.to_affine();
    if child.is_identity().into() {
        return Err(format!(
            "child {index} is invalid (point at infinity); use {index}+1"
        ));
    }

    let encoded = child.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(format!("compressed point is {} bytes, not 33", bytes.len()));
    }
    let mut key = [0u8; 33];
    key.copy_from_slice(bytes);
    Ok((key, chain_code))
}

fn decode_point(key: &[u8; 33]) -> Option<AffinePoint> {
    let point = EncodedPoint::from_bytes(key).ok()?;
    Option::from(AffinePoint::from_encoded_point(&point))
}

/// `RIPEMD160(SHA256(data))`, Bitcoin's HASH160.
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(sha));
    out
}

/// `OP_0 PUSH20 <hash160(pubkey)>` -- a P2WPKH output, BIP-141.
fn p2wpkh_script_pubkey(public_key: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(20);
    script.extend_from_slice(&hash160(public_key));
    script
}

fn p2wpkh_address(public_key: &[u8; 33], network: BitcoinNetwork) -> Result<String, String> {
    let hrp = bech32::Hrp::parse(segwit_hrp(network))
        .map_err(|e| format!("invalid address prefix for {}: {e}", network.as_str()))?;
    bech32::segwit::encode_v0(hrp, &hash160(public_key))
        .map_err(|e| format!("could not encode the payment address: {e}"))
}

/// Bech32 human-readable prefix per network. Mirrors the decoder in
/// `harvest-ui`'s `gateway::bitcoin_address`; the two must agree, which the
/// round-trip test in that module's crate and `encodes_a_round_trippable_address`
/// here both pin from their own side.
fn segwit_hrp(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Bitcoin => "bc",
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Signet => "tb",
        BitcoinNetwork::Regtest => "bcrt",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BIP-84 specification's own test vector: the account key for
    /// `m/84'/0'/0'` under the "abandon abandon ... about" mnemonic.
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn derives_the_bip84_specification_vectors() {
        let account = AccountXpub::parse(BIP84_ZPUB).expect("the BIP-84 account key must parse");

        // BIP-84's "First Address" and "Second Address", m/84'/0'/0'/0/0 and
        // .../0/1. If either of these ever changes, the addresses Harvest
        // hands buyers are not the ones the seller's wallet is watching.
        let (script, address) = account
            .order_address(0, BitcoinNetwork::Bitcoin)
            .expect("index 0");
        assert_eq!(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(script[0], 0x00, "witness v0");
        assert_eq!(script[1], 20, "P2WPKH program length");

        let (_, address) = account
            .order_address(1, BitcoinNetwork::Bitcoin)
            .expect("index 1");
        assert_eq!(address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    }

    /// The whole point: two orders must never land on one script. Sharing an
    /// address would let one payment satisfy two invoices, because payment
    /// evidence is scoped to a script rather than to an order -- see this
    /// module's header.
    /// The scan and the address handed out are one derivation, not two
    /// that could drift: a scan that disagreed with `order_address` would
    /// look for scripts no invoice ever named, find none, and hand out an
    /// address already on a published order.
    #[test]
    fn the_chain_scan_derives_the_same_scripts_as_order_address() {
        let account = AccountXpub::parse(BIP84_ZPUB).expect("parse");
        let chain = account.external_chain().expect("chain");
        for index in [0u32, 1, 2, 17, 1000] {
            let (script, _) = account
                .order_address(index, BitcoinNetwork::Bitcoin)
                .expect("derive");
            assert_eq!(
                chain.script_at(index).expect("scan"),
                script,
                "index {index}"
            );
        }
    }

    #[test]
    fn consecutive_indices_give_distinct_scripts() {
        let account = AccountXpub::parse(BIP84_ZPUB).expect("parse");
        let mut seen = std::collections::HashSet::new();
        for index in 0..32 {
            let (script, address) = account
                .order_address(index, BitcoinNetwork::Bitcoin)
                .expect("derive");
            assert!(seen.insert(script), "index {index} reused a script");
            assert!(
                address.starts_with("bc1q"),
                "not a P2WPKH address: {address}"
            );
        }
    }

    /// The address string and the script must denote the same output. They
    /// are carried separately on an `Order` (one for humans, one for
    /// verification), so a mismatch would send a buyer's coin somewhere the
    /// order could not recognise.
    #[test]
    fn the_address_and_the_script_agree() {
        let account = AccountXpub::parse(BIP84_ZPUB).expect("parse");
        let (script, address) = account
            .order_address(7, BitcoinNetwork::Bitcoin)
            .expect("derive");

        let (hrp, version, program) =
            bech32::segwit::decode(&address).expect("the address must decode");
        assert_eq!(hrp.as_str(), "bc");
        assert_eq!(version.to_u8(), 0);
        assert_eq!(script, {
            let mut expected = vec![0x00, 20];
            expected.extend_from_slice(&program);
            expected
        });
    }

    /// A mainnet key filed as a signet one would produce invoices demanding
    /// real bitcoin while the seller believed they were testing.
    #[test]
    fn a_mainnet_key_is_refused_for_a_test_network() {
        let account = AccountXpub::parse(BIP84_ZPUB).expect("parse");
        assert!(account.accepts_network(BitcoinNetwork::Bitcoin));
        assert!(!account.accepts_network(BitcoinNetwork::Signet));
        let err = account
            .order_address(0, BitcoinNetwork::Signet)
            .expect_err("must refuse");
        assert!(err.contains("mainnet"), "unhelpful error: {err}");
    }

    /// Bitcoin's test networks share one extended-key version, so this is
    /// the limit of what any parser can enforce. Pinned so nobody later
    /// "fixes" it into a check that cannot work.
    #[test]
    fn the_test_networks_are_not_distinguishable_from_one_another() {
        // A vpub built by re-encoding the BIP-84 vector under the test
        // version, which is exactly what a testnet wallet would export.
        let vpub = reencode_version(BIP84_ZPUB, VERSION_VPUB);
        let account = AccountXpub::parse(&vpub).expect("parse");
        for network in [
            BitcoinNetwork::Testnet4,
            BitcoinNetwork::Signet,
            BitcoinNetwork::Regtest,
        ] {
            assert!(account.accepts_network(network), "{network:?} refused");
        }
        assert!(!account.accepts_network(BitcoinNetwork::Bitcoin));
    }

    #[test]
    fn a_vpub_derives_test_network_addresses() {
        let vpub = reencode_version(BIP84_ZPUB, VERSION_VPUB);
        let account = AccountXpub::parse(&vpub).expect("parse");
        let (_, signet) = account
            .order_address(0, BitcoinNetwork::Signet)
            .expect("derive");
        assert!(signet.starts_with("tb1q"), "not a signet address: {signet}");
        let (_, regtest) = account
            .order_address(0, BitcoinNetwork::Regtest)
            .expect("derive");
        assert!(
            regtest.starts_with("bcrt1q"),
            "not a regtest address: {regtest}"
        );
    }

    /// A legacy `xpub` says nothing about script type, so deriving P2WPKH
    /// from one is a guess -- and a wrong guess is invisible until a buyer
    /// pays an address the seller's wallet never showed them.
    #[test]
    fn a_legacy_account_key_is_refused_with_advice() {
        let xpub = reencode_version(BIP84_ZPUB, VERSION_XPUB);
        let err = AccountXpub::parse(&xpub).expect_err("must refuse");
        assert!(
            err.contains("zpub"),
            "the error must say what to paste: {err}"
        );
    }

    #[test]
    fn a_wrapped_segwit_account_key_is_refused_with_advice() {
        let ypub = reencode_version(BIP84_ZPUB, VERSION_YPUB);
        let err = AccountXpub::parse(&ypub).expect_err("must refuse");
        assert!(
            err.contains("zpub"),
            "the error must say what to paste: {err}"
        );
    }

    /// The master key parses and derives perfectly good addresses -- for a
    /// derivation path no wallet watches. Depth is the only thing that
    /// distinguishes it.
    #[test]
    fn a_key_at_the_wrong_depth_is_refused() {
        let root = reencode_depth(BIP84_ZPUB, 0);
        let err = AccountXpub::parse(&root).expect_err("must refuse a master key");
        assert!(err.contains("depth 0"), "unhelpful error: {err}");

        let leaf = reencode_depth(BIP84_ZPUB, 5);
        let err = AccountXpub::parse(&leaf).expect_err("must refuse an address key");
        assert!(err.contains("depth 5"), "unhelpful error: {err}");
    }

    #[test]
    fn garbage_is_refused() {
        assert!(AccountXpub::parse("").is_err());
        assert!(AccountXpub::parse("not a key").is_err());
        // Valid base58check, wrong length.
        assert!(
            AccountXpub::parse(&bs58::encode(vec![0u8; 40]).with_check().into_string()).is_err()
        );
    }

    #[test]
    fn hardened_indices_cannot_be_derived_publicly() {
        let account = AccountXpub::parse(BIP84_ZPUB).expect("parse");
        let err = account
            .order_address(0x8000_0000, BitcoinNetwork::Bitcoin)
            .expect_err("must refuse");
        assert!(err.contains("hardened"), "unhelpful error: {err}");
    }

    /// Re-encode the test vector under a different version prefix, so the
    /// version-specific branches are exercised without hard-coding six more
    /// key strings that nothing verifies.
    fn reencode_version(xpub: &str, version: u32) -> String {
        let mut bytes = bs58::decode(xpub)
            .with_check(None)
            .into_vec()
            .expect("decode");
        bytes[..4].copy_from_slice(&version.to_be_bytes());
        bs58::encode(bytes).with_check().into_string()
    }

    fn reencode_depth(xpub: &str, depth: u8) -> String {
        let mut bytes = bs58::decode(xpub)
            .with_check(None)
            .into_vec()
            .expect("decode");
        bytes[4] = depth;
        bs58::encode(bytes).with_check().into_string()
    }
}
