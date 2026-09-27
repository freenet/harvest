//! Does a published Ghost Key certificate actually mean anything?
//!
//! Every backing and every listing carries a `certificate_pem`, and nothing
//! in the contracts parses one: a contract has no view of Freenet's master
//! key, and whether a certificate holds up is a reader's question
//! (`harvest_common::backing`, "What the contract checks, and what it leaves
//! to readers").
//!
//! # What a certificate is for, and what it is not for
//!
//! Harvest already proves *this key signed this record*: the store contract
//! verifies every listing, order and store-info signature against the
//! store's own key, and every backing against both the Ghost Key it names and
//! the store key (harvest#93). That is authentication, and it works without
//! any certificate at all.
//!
//! What it does not establish is that the Ghost Key behind the store means
//! anything. A Ghost Key is minted by donating to Freenet, so it is *scarce*,
//! and scarcity is the foundation the incentive design rests on (see
//! `docs/design/incentive-mechanism.md`, Part 2). A backing by a key somebody
//! generated has no bond behind it. The certificate is the only thing that
//! separates the two.
//!
//! # The check that matters most
//!
//! Certificates are **public**. Alice's certificate is handed to every buyer
//! who opens her store, so the easy attack is not forging one, it is copying
//! hers: a scammer backs their store with their own throwaway key and pastes
//! Alice's certificate into the backing. Chain verification alone passes.
//! So verification is two questions, and the second is the load-bearing one:
//!
//! 1. Does the certificate chain to Freenet's master key?
//! 2. Is the key it certifies the key that signed the backing?
//!
//! The contract has already checked that the backing key signed its backing
//! statement, so (2) is a comparison of two keys, with no dependence on any
//! contract address or code hash. Before revision 2 the same question had to
//! be answered by re-deriving the store's address from the certified key,
//! which could not tell a store published by a newer build from a stolen
//! certificate; a backing needs none of that.
//!
//! # What is deliberately NOT read here
//!
//! The donation *amount*. `GhostkeyCertificateV1::verify` returns the notary
//! info string, which encodes the tier, and this module throws it away. The
//! amount is the seller's bond, and turning a bond into a number a buyer acts
//! on is the whole of the standing mechanism, none of which is designed yet
//! (#8). A half-read tier displayed next to a store would be acted on as if
//! it were.

use ed25519_dalek::VerifyingKey;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;

/// What a reader concluded about one published certificate.
///
/// Three outcomes rather than a `bool`, because "no certificate" and "a
/// certificate that does not verify" are different things to tell a buyer:
/// the first is an unfinished store, the second is a store actively claiming
/// a bond it does not have.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum CertificateStatus {
    /// Nothing was published. The seller has no verifiable identity here.
    #[default]
    Absent,
    /// Chains to Freenet's master key, and certifies this store's own key.
    Verified,
    /// Published, and does not hold up. The string says how, for display.
    Invalid(String),
}

impl CertificateStatus {
    pub fn is_verified(&self) -> bool {
        matches!(self, CertificateStatus::Verified)
    }

    /// The short line a reader sees.
    pub fn label(&self) -> &'static str {
        match self {
            CertificateStatus::Absent => "No ghostkey certificate",
            CertificateStatus::Verified => "Ghostkey verified",
            CertificateStatus::Invalid(_) => "Ghostkey certificate does not verify",
        }
    }

    /// The longer explanation, or `None` when the label says it all.
    pub fn detail(&self) -> Option<&str> {
        match self {
            CertificateStatus::Invalid(why) => Some(why.as_str()),
            _ => None,
        }
    }
}

/// Freenet's master verifying key, as `ghostkey_lib` knows it: `None` here
/// means "the production key", which is the only one a shipped build uses.
const PRODUCTION_MASTER: Option<VerifyingKey> = None;

/// The certificate a reputation record may carry, from whatever `pem` was
/// offered: the canonical armour of a genuine Ghost Key certificate, or the
/// empty string.
///
/// The reputation contract accepts exactly these two (harvest#53 Phase C,
/// review round 1 P1-4: `reputation_contract::check_owner_certificate`), so
/// everything that writes the field goes through here first -- store
/// creation, and the migration carrying a predecessor's certificate forward.
/// A certificate that does not verify, or verifies but was armoured some
/// other way, would otherwise make the contract refuse the whole write.
pub fn record_certificate(pem: &str) -> String {
    record_certificate_under(pem, &PRODUCTION_MASTER)
}

fn record_certificate_under(pem: &str, master: &Option<VerifyingKey>) -> String {
    if pem.trim().is_empty() {
        return String::new();
    }
    GhostkeyCertificateV1::from_armored_string(pem)
        .ok()
        .filter(|cert| cert.verify(master).is_ok())
        .and_then(|cert| cert.to_armored_string().ok())
        .unwrap_or_default()
}

/// The key a certificate certifies, if it chains to `master` (the production
/// master key when `None`).
fn certified_key(pem: &str, master: &Option<VerifyingKey>) -> Result<VerifyingKey, String> {
    let cert = GhostkeyCertificateV1::from_armored_string(pem)
        .map_err(|e| format!("not a readable Ghost Key certificate: {e}"))?;
    cert.verify(master)
        .map_err(|e| format!("does not chain to Freenet's master key: {e}"))?;
    Ok(cert.verifying_key)
}

/// The verdict on a backing's certificate: it chains to Freenet's master key
/// AND certifies `backer`, the Ghost Key that signed the backing.
pub fn verify_backing_certificate(pem: &str, backer: &VerifyingKey) -> CertificateStatus {
    certificate_naming_one_of(pem, std::slice::from_ref(backer), &PRODUCTION_MASTER)
}

/// The verdict on a certificate a record carries (a listing's): it chains to
/// Freenet's master key AND certifies one of `backers`, the Ghost Keys that
/// have backed the store.
///
/// Any of them, retired or current: a listing published while an earlier
/// Ghost Key backed the store carries that key's certificate, and it is no
/// less the store's listing for the backing having moved on. The store key
/// signed it either way.
pub fn verify_record_certificate(pem: &str, backers: &[VerifyingKey]) -> CertificateStatus {
    certificate_naming_one_of(pem, backers, &PRODUCTION_MASTER)
}

fn certificate_naming_one_of(
    pem: &str,
    keys: &[VerifyingKey],
    master: &Option<VerifyingKey>,
) -> CertificateStatus {
    if pem.trim().is_empty() {
        return CertificateStatus::Absent;
    }
    match certified_key(pem, master) {
        Err(why) => CertificateStatus::Invalid(why),
        Ok(key) if keys.contains(&key) => CertificateStatus::Verified,
        Ok(_) => CertificateStatus::Invalid(
            "genuine, but not the certificate of the Ghost Key that backs this store".to_string(),
        ),
    }
}

/// Whether `voucher` vouches for the conversation tagged `tag`: its
/// certificate chains to Freenet's master key, the Ghost Key it certifies
/// signed the voucher, and what was signed is this conversation's terms under
/// Harvest's requestor pin. Returns the vouching Ghost Key.
///
/// The certified key and the signing key are the same key by construction
/// here, which is the copied-certificate check: the signature is verified
/// under the key the certificate names, so a genuine certificate pasted
/// beside a throwaway key's signature fails.
pub fn verify_voucher(
    voucher: &harvest_common::sealed::MessageVoucher,
    tag: &[u8; 32],
) -> Result<VerifyingKey, String> {
    verify_voucher_under(voucher, tag, &PRODUCTION_MASTER)
}

pub(crate) fn verify_voucher_under(
    voucher: &harvest_common::sealed::MessageVoucher,
    tag: &[u8; 32],
    master: &Option<VerifyingKey>,
) -> Result<VerifyingKey, String> {
    let key = certified_key(&voucher.certificate_pem, master)?;
    harvest_common::listing::verify_scoped_signature(
        &voucher.scoped_payload,
        &voucher.signature,
        &key,
        &harvest_common::sealed::voucher_terms(tag),
    )?;
    Ok(key)
}

/// The key a verdict on `voucher` for the conversation `tag` is remembered
/// under (`AppState::voucher_verifies`): every field, length-prefixed, so two
/// different vouchers cannot share a verdict.
pub(crate) fn voucher_verdict_key(
    voucher: &harvest_common::sealed::MessageVoucher,
    tag: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"harvest/voucher-verdict");
    hasher.update(tag);
    for part in [
        voucher.certificate_pem.as_bytes(),
        &voucher.scoped_payload,
        &voucher.signature,
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ghostkey_lib::notary_certificate::NotaryCertificateV1;

    /// One notary, minted once.
    ///
    /// `NotaryCertificateV1::new` generates a 2048-bit RSA keypair, which is
    /// seconds of work in a debug build. Every test below issues ghostkeys
    /// under the same notary rather than paying for that again.
    struct TestAuthority {
        master: SigningKey,
        notary: NotaryCertificateV1,
        notary_key: blind_rsa_signatures::SecretKey,
    }

    fn authority() -> &'static TestAuthority {
        static AUTHORITY: std::sync::LazyLock<TestAuthority> = std::sync::LazyLock::new(|| {
            // A fixed seed rather than an RNG: `SigningKey::generate` needs
            // ed25519-dalek's `rand_core` feature, which the workspace does
            // not enable, and a test authority gains nothing from being
            // unpredictable.
            let master = SigningKey::from_bytes(&[0x11; 32]);
            let (notary, notary_key) =
                NotaryCertificateV1::new(&master, &"Test Notary".to_string())
                    .expect("mint a notary certificate");
            TestAuthority {
                master,
                notary,
                notary_key,
            }
        });
        &AUTHORITY
    }

    /// A fresh ghostkey certificate under the shared test authority, and the
    /// PEM a seller would publish for it.
    fn issue_ghostkey() -> (VerifyingKey, String) {
        let a = authority();
        let (cert, _signing_key) = GhostkeyCertificateV1::new(&a.notary, &a.notary_key);
        let pem = cert.to_armored_string().expect("armor the certificate");
        (cert.verifying_key, pem)
    }

    fn verdict(
        pem: &str,
        backers: &[VerifyingKey],
        master: &Option<VerifyingKey>,
    ) -> CertificateStatus {
        certificate_naming_one_of(pem, backers, master)
    }

    pub(crate) fn test_master() -> Option<VerifyingKey> {
        Some(authority().master.verifying_key())
    }

    #[test]
    fn a_genuine_certificate_verifies_for_the_key_that_backs_the_store() {
        let (key, pem) = issue_ghostkey();
        assert_eq!(
            verdict(&pem, &[key], &test_master()),
            CertificateStatus::Verified
        );
    }

    /// The copied-certificate attack: a scammer backs a store with their own
    /// key and pastes Alice's genuine certificate into the backing.
    #[test]
    fn a_genuine_certificate_for_another_key_does_not_vouch_for_this_backing() {
        let (alice, alice_pem) = issue_ghostkey();
        let (scammer, _) = issue_ghostkey();
        assert!(matches!(
            verdict(&alice_pem, &[scammer], &test_master()),
            CertificateStatus::Invalid(_)
        ));
        assert_eq!(
            verdict(&alice_pem, &[alice], &test_master()),
            CertificateStatus::Verified,
            "the same certificate still verifies for the key it certifies"
        );
    }

    /// A listing's certificate may be any backer's, current or retired.
    #[test]
    fn a_record_certificate_verifies_against_any_of_the_stores_backers() {
        let (earlier, earlier_pem) = issue_ghostkey();
        let (current, _) = issue_ghostkey();
        let (stranger, stranger_pem) = issue_ghostkey();
        assert_eq!(
            verdict(&earlier_pem, &[current, earlier], &test_master()),
            CertificateStatus::Verified
        );
        assert!(matches!(
            verdict(&stranger_pem, &[current, earlier], &test_master()),
            CertificateStatus::Invalid(_)
        ));
        let _ = stranger;
        assert!(matches!(
            verdict(&earlier_pem, &[], &test_master()),
            CertificateStatus::Invalid(_)
        ));
    }

    #[test]
    fn a_certificate_from_another_authority_is_rejected() {
        let (key, pem) = issue_ghostkey();
        let stranger = SigningKey::from_bytes(&[0x22; 32]).verifying_key();
        assert!(matches!(
            verdict(&pem, &[key], &Some(stranger)),
            CertificateStatus::Invalid(_)
        ));
    }

    /// The production entry points use Freenet's master key and nothing else.
    /// A locally minted chain is exactly what a forged one looks like, so it
    /// must fail there even though it passes with the test authority.
    #[test]
    fn the_production_check_uses_freenets_master_key() {
        let (key, pem) = issue_ghostkey();
        assert_eq!(
            verdict(&pem, &[key], &test_master()),
            CertificateStatus::Verified
        );
        assert!(matches!(
            verify_backing_certificate(&pem, &key),
            CertificateStatus::Invalid(_)
        ));
        assert!(matches!(
            verify_record_certificate(&pem, &[key]),
            CertificateStatus::Invalid(_)
        ));
    }

    #[test]
    fn text_that_is_not_a_certificate_is_rejected() {
        let (key, _) = issue_ghostkey();
        for pem in [
            "-----BEGIN CERT-----",
            "-----BEGIN GHOSTKEY CERTIFICATE-----rehearsal-----END-----",
            "not a certificate at all",
            "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nbm90IGNib3I=\n-----END GHOSTKEY_CERTIFICATE_V1-----\n",
        ] {
            assert!(
                matches!(verdict(pem, &[key], &test_master()), CertificateStatus::Invalid(_)),
                "{pem:?} is not a certificate and must not verify"
            );
        }
    }

    /// An unpublished certificate is its own outcome. Folding it into
    /// `Invalid` would tell a buyer a store is claiming a bond it does not
    /// have, when it is claiming nothing at all.
    #[test]
    fn an_absent_certificate_is_absent_rather_than_invalid() {
        let (key, _) = issue_ghostkey();
        for pem in ["", "   \n "] {
            assert_eq!(
                verdict(pem, &[key], &test_master()),
                CertificateStatus::Absent
            );
        }
    }

    /// **What store creation and the migration write to a reputation record
    /// is what its contract accepts** (review round 1, P1-4): a genuine
    /// certificate in canonical armour, reflowed or not; nothing for text or
    /// a certificate that does not chain. Red if `record_certificate` passes
    /// its input through.
    #[test]
    fn a_record_certificate_is_canonical_and_genuine_or_empty() {
        let (_, pem) = issue_ghostkey();
        let master = test_master();
        assert_eq!(record_certificate_under(&pem, &master), pem);
        let reflowed = pem.replace('\n', "\r\n");
        assert_eq!(
            record_certificate_under(&reflowed, &master),
            pem,
            "a genuine certificate is re-armoured into the one canonical form"
        );
        for junk in ["Contact me off-platform", "-----BEGIN CERT-----", ""] {
            assert_eq!(record_certificate_under(junk, &master), "", "{junk:?}");
        }
        assert_eq!(
            record_certificate_under(&pem, &PRODUCTION_MASTER),
            "",
            "a certificate that does not chain to the master key is dropped"
        );
        // The contract's own fixture, under the production key.
        let fixture = include_str!("../../tests/fixtures/ghostkey-certificate.pem");
        assert_eq!(record_certificate(fixture), fixture);
    }

    // ---- Buyer vouchers ----

    use harvest_common::sealed::MessageVoucher;

    const TAG: [u8; 32] = [9; 32];

    /// What the vault's `SignMessage` returns for the voucher terms of `tag`,
    /// asked by `requestor`.
    pub(crate) fn sign_as_vault(
        key: &SigningKey,
        requestor: ghostkey_common::SignatureRequestor,
        tag: &[u8; 32],
    ) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer;
        let scoped_payload = ghostkey_common::to_cbor(&ghostkey_common::ScopedPayload {
            requestor,
            payload: harvest_common::sealed::voucher_message(tag).unwrap(),
        })
        .unwrap();
        let signature = key.sign(&scoped_payload).to_bytes().to_vec();
        (scoped_payload, signature)
    }

    /// A voucher for `tag`, signed as the vault signs: the terms wrapped in a
    /// `ScopedPayload` under Harvest's requestor, by a Ghost Key issued under
    /// the test authority. Returns the key and the PEM too.
    pub(crate) fn vouch(tag: &[u8; 32]) -> (MessageVoucher, VerifyingKey, SigningKey) {
        let a = authority();
        let (cert, signing_key) = GhostkeyCertificateV1::new(&a.notary, &a.notary_key);
        let pem = cert.to_armored_string().expect("armor the certificate");
        let (scoped_payload, signature) = sign_as_vault(
            &signing_key,
            harvest_common::expected_harvest_requestor(),
            tag,
        );
        (
            MessageVoucher {
                certificate_pem: pem,
                scoped_payload,
                signature,
            },
            cert.verifying_key,
            signing_key,
        )
    }

    #[test]
    fn a_voucher_verifies_for_its_own_conversation() {
        let (voucher, key, _) = vouch(&TAG);
        assert_eq!(
            verify_voucher_under(&voucher, &TAG, &test_master()),
            Ok(key)
        );
    }

    /// A voucher is for one conversation. Moved to another, it vouches for
    /// nothing.
    #[test]
    fn a_voucher_for_another_conversation_is_refused() {
        let (voucher, _, _) = vouch(&TAG);
        assert!(verify_voucher_under(&voucher, &[10; 32], &test_master()).is_err());
    }

    /// A certificate from anywhere but Freenet's master key vouches for
    /// nothing, and neither does the production check with a test chain.
    #[test]
    fn a_voucher_whose_certificate_does_not_chain_is_refused() {
        let (voucher, _, _) = vouch(&TAG);
        let stranger = Some(SigningKey::from_bytes(&[0x22; 32]).verifying_key());
        assert!(verify_voucher_under(&voucher, &TAG, &stranger).is_err());
        assert!(verify_voucher(&voucher, &TAG).is_err());
    }

    /// The copied-certificate attack: a genuine certificate beside a
    /// signature by some other key.
    #[test]
    fn a_voucher_signed_by_a_key_other_than_the_certified_one_is_refused() {
        let (genuine, _, _) = vouch(&TAG);
        let throwaway = SigningKey::from_bytes(&[0x33; 32]);
        let (scoped_payload, signature) = sign_as_vault(
            &throwaway,
            harvest_common::expected_harvest_requestor(),
            &TAG,
        );
        let forged = MessageVoucher {
            certificate_pem: genuine.certificate_pem,
            scoped_payload,
            signature,
        };
        assert!(verify_voucher_under(&forged, &TAG, &test_master()).is_err());
    }

    /// Signed by the right key over the right terms, but for another webapp:
    /// a site the buyer granted Ghost Key access must not mint Harvest
    /// vouchers.
    #[test]
    fn a_voucher_signed_for_another_requestor_is_refused() {
        let (genuine, _, signing_key) = vouch(&TAG);
        let (scoped_payload, signature) = sign_as_vault(
            &signing_key,
            ghostkey_common::SignatureRequestor::WebApp(
                freenet_stdlib::prelude::ContractInstanceId::new([0x44; 32]),
            ),
            &TAG,
        );
        let other_app = MessageVoucher {
            certificate_pem: genuine.certificate_pem,
            scoped_payload,
            signature,
        };
        assert!(verify_voucher_under(&other_app, &TAG, &test_master()).is_err());
    }
}
