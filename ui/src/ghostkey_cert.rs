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

#[cfg(test)]
mod tests {
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

    fn test_master() -> Option<VerifyingKey> {
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
}
