//! Does a published ghostkey certificate actually mean anything?
//!
//! Every store and every listing carries a `certificate_pem`, and until this
//! module existed nothing ever parsed one. A seller could put arbitrary text
//! there -- or, worse, somebody else's perfectly genuine certificate -- and
//! every part of Harvest would carry it around and display it unexamined.
//!
//! # What a certificate is for, and what it is not for
//!
//! Harvest already proves *this key signed this record*: the store contract
//! verifies every listing, order and store-info signature against the
//! store's owner, whose key must begin with the store code frozen into the
//! store's address. That is authentication, and it works without any
//! certificate at all.
//!
//! What it does not establish is that the key means anything. A ghostkey is
//! minted by donating to Freenet, so it is *scarce* -- and scarcity is the
//! foundation the whole incentive design rests on (see
//! `docs/design/incentive-mechanism.md`, Part 2). A store whose key is just a
//! key somebody generated has no bond behind it. The certificate is the only
//! thing that separates the two, so a certificate nobody checks leaves the
//! design's own premise unenforced.
//!
//! # The check that matters most
//!
//! Certificates are **public**. Alice's certificate is handed to every buyer
//! who opens her store, so the easy attack is not forging one -- it is
//! copying hers. A scammer publishes their own store, signs everything with
//! their own throwaway key, and pastes Alice's certificate into
//! `certificate_pem`. Chain verification alone passes: the certificate really
//! is genuine, really does chain to Freenet's master key, and really does
//! attest a donation. It just is not *this seller's*.
//!
//! So verification here is two questions, and the second is the load-bearing
//! one:
//!
//! 1. Does the certificate chain to Freenet's master key?
//! 2. Is the key it certifies the key this store is addressed by?
//!
//! # How (2) is answered since the store code (harvest#52)
//!
//! A store's parameter is now a sixteen-character CODE, a prefix of its
//! owner's key, and a prefix names many keys. So the address alone no longer
//! says whose store it is; the state does, in `StoreStateV1::owner`, and the
//! contract verifies every record against that owner. For a store at the
//! current generation the question is therefore two checks: the certified
//! key's code derives this address (so the code at that address is the
//! genuine Harvest store contract), AND the certified key IS the store's
//! owner. The second is what a key sharing the seller's code, or a copied
//! certificate, fails. A superseded generation was addressed by the whole
//! key, so for those the address check below still settles it alone.
//!
//! # How the address is checked without the contract's parameters
//!
//! A Freenet contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, and a
//! store's only parameter is derived from the seller's verifying key. The node's GET
//! response does carry the contract container, but Harvest discards it (see
//! `gateway::response_handler`), so the reader holds the instance id and
//! nothing else.
//!
//! That is enough, because the derivation runs forwards: take the key the
//! certificate certifies, encode it as `StoreParameters`, hash it against the
//! store contract this build bundles, and see whether the answer is the
//! contract id actually being read. A match proves three things at once --
//! the certified key *is* the parameter key, the parameters are what we think
//! they are, and the code at that address is the genuine Harvest store
//! contract rather than a permissive lookalike. Everything the contract
//! validated, it validated against the certified key.
//!
//! Superseded generations are included ([`crate::migrate`] derives them),
//! because a store published under an older contract build lives at a
//! different address and is not therefore fraudulent.
//!
//! # The limitation this approach has, and cannot fix
//!
//! Running the derivation forwards means enumerating the code hashes this
//! build knows about: today's, and every one in `legacy/store_contract.toml`.
//! A store published by a *newer* build of Harvest than the one reading it
//! lives at an address derived from a code hash this build has never heard
//! of, and is indistinguishable here from a certificate issued to somebody
//! else. Both are "no id matches".
//!
//! That is not hypothetical -- the store contract has already been through
//! several generations, and a rustc or stdlib bump is enough to move it. So
//! `CertificateStatus::Invalid` names the benign explanation alongside the
//! hostile one, and the storefront's wording declines to credit the seller
//! rather than accusing them, which is the right response either way: a
//! reader that cannot verify a bond should not act as though it had.
//!
//! Removing it means reading the contract's PARAMETERS instead of deriving
//! its address. The node's GET response carries them, and
//! `gateway::response_handler` currently discards the container; recovering
//! them would let the check be `certificate.verifying_key ==
//! parameters.seller_verifying_key` with no dependence on any code hash. The
//! cost is that it no longer establishes, in the same step, that the code at
//! that address is the real Harvest store contract -- that becomes a separate
//! check against the same list of known hashes, and so carries the same
//! staleness, but as a weaker and separately-reportable signal rather than as
//! a false accusation.
//!
//! # What is deliberately NOT read here
//!
//! The donation *amount*. `GhostkeyCertificateV1::verify` returns the notary
//! info string, which encodes the tier, and this module throws it away. The
//! amount is the seller's bond, and turning a bond into a number a buyer acts
//! on is the whole of the standing mechanism -- weighting, open orders,
//! complaint multipliers. None of that is designed yet, and a half-read tier
//! displayed next to a store would be acted on as if it were.
//!

use ed25519_dalek::VerifyingKey;
use freenet_stdlib::prelude::ContractInstanceId;
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

/// The code hash of the store contract this build bundles.
fn store_code_hash() -> [u8; 32] {
    crate::gateway::store_ops::store_code_hash()
}

/// Every store instance id the holder of `key` could have published at: this
/// build's, plus every superseded generation.
///
/// The legacy ids come from [`crate::migrate::store_candidate_ids`], which
/// already knows which generations were published under a *different*
/// `StoreParameters` encoding -- a middle BAND, V2..=V5, not everything below
/// a threshold: V1 predates the two Bitcoin fields and V6 onwards postdates
/// them, so both sit on the current encoding. See
/// `migrate::published_under_legacy_store_params`.
///
/// Re-deriving them here would be a second copy of that fact, and the first
/// one was got wrong once already -- twice, in fact. The comment this replaced
/// said "at or below `LAST_LEGACY_STORE_PARAM_GENERATION`", which was the
/// same off-by-one that made the probe derive V1 -- the only generation ever
/// published -- at an address it never had. Delegating rather than
/// re-deriving is what kept that bug out of this file.
fn store_instance_ids(key: &VerifyingKey) -> Result<Vec<ContractInstanceId>, String> {
    let mut ids = vec![current_store_id(key)?];
    ids.extend(crate::migrate::store_candidate_ids(key)?);
    Ok(ids)
}

/// The id of the store `key`'s code opens under this build: the one address
/// that a prefix, not the whole key, derives -- so the one where the owner
/// has to be checked as well. See the module docs.
fn current_store_id(key: &VerifyingKey) -> Result<ContractInstanceId, String> {
    let params = crate::migrate::encode_params(&crate::migrate::store_params(key))?;
    Ok(crate::migrate::current_id(&store_code_hash(), &params))
}

/// Parse a certificate and check its chain, returning the key it certifies.
///
/// `master` is `None` in every non-test caller, which means "Freenet's
/// published master key", the one compiled into `ghostkey_lib`. It is a
/// parameter only so the tests can mint a chain of their own; it is not
/// reachable from outside this module, because which authority a certificate
/// is checked against is not a caller's decision to make. The ghostkey
/// delegate removed exactly this knob from its own wire protocol for the same
/// reason (see `ghostkey_common::GhostkeyRequest::ImportGhostKey`).
fn certified_key(pem: &str, master: &Option<VerifyingKey>) -> Result<VerifyingKey, String> {
    let cert = GhostkeyCertificateV1::from_armored_string(pem)
        .map_err(|e| format!("not a readable ghostkey certificate: {e}"))?;
    // `verify` returns the notary info string, which encodes the donation
    // tier. Dropped on purpose -- see the module docs.
    cert.verify(master)
        .map_err(|e| format!("does not chain to Freenet's master key: {e}"))?;
    Ok(cert.verifying_key)
}

/// Verify a certificate published by, or inside, the store at
/// `store_contract_id`, whose state names `owner` (`StoreStateV1::owner`).
pub fn verify_store_certificate(
    pem: &str,
    store_contract_id: &[u8],
    owner: Option<&VerifyingKey>,
) -> CertificateStatus {
    verify_store_certificate_against(pem, store_contract_id, owner, &None).0
}

/// The seller's Ed25519 verifying key, but ONLY when the store's certificate
/// verifies against this store.
///
/// # Why this is not a convenience accessor
///
/// It is how a buyer finds the seller's mailbox. A mailbox lives at
/// `BLAKE3(code_hash || cbor(MailboxParameters { owner_verifying_key }))`, and
/// nothing publishes that address -- the store contract's state does not carry
/// it. So the address is DERIVED from this key, which means a wrong key sends
/// the buyer's message into a stranger's mailbox.
///
/// "Wrong" here is not hypothetical carelessness. Certificates are public, so
/// the cheapest attack on this whole module is a scammer publishing a store
/// carrying somebody else's genuine certificate (see
/// [`verify_store_certificate`]). Reading the key out of a certificate that
/// merely *parses* would hand every such buyer's message to whoever the
/// certificate actually belongs to -- with the buyer's browser reporting a
/// successful send. Returning `None` unless the certificate is
/// [`CertificateStatus::Verified`] is what makes the derived address the
/// address of the store the buyer is looking at.
///
/// `None` therefore covers three genuinely different situations -- no
/// certificate, a certificate that does not hold up, and a store published by
/// a newer build of Harvest than this one. The caller cannot distinguish
/// them here and should say the truthful thing that covers all three: this
/// store cannot be messaged from this build.
pub fn store_verifying_key(
    pem: &str,
    store_contract_id: &[u8],
    owner: Option<&VerifyingKey>,
) -> Option<VerifyingKey> {
    store_verifying_key_against(pem, store_contract_id, owner, &None)
}

/// [`store_verifying_key`] with the authority named, so the tests can mint a
/// chain of their own. Not reachable from outside this module, for the same
/// reason [`certified_key`] is not: which authority a certificate is checked
/// against is not a caller's decision.
fn store_verifying_key_against(
    pem: &str,
    store_contract_id: &[u8],
    owner: Option<&VerifyingKey>,
    master: &Option<VerifyingKey>,
) -> Option<VerifyingKey> {
    match verify_store_certificate_against(pem, store_contract_id, owner, master) {
        (CertificateStatus::Verified, key) => key,
        _ => None,
    }
}

/// The verdict, and the key it was reached about.
///
/// One function rather than two because the membership check IS the thing
/// that makes the key trustworthy: a second entry point that re-derived the
/// key without re-running the check is exactly the shape that ends up
/// weaker than the first.
fn verify_store_certificate_against(
    pem: &str,
    store_contract_id: &[u8],
    owner: Option<&VerifyingKey>,
    master: &Option<VerifyingKey>,
) -> (CertificateStatus, Option<VerifyingKey>) {
    if pem.trim().is_empty() {
        return (CertificateStatus::Absent, None);
    }

    let key = match certified_key(pem, master) {
        Ok(key) => key,
        Err(why) => return (CertificateStatus::Invalid(why), None),
    };

    let Ok(bytes) = <[u8; 32]>::try_from(store_contract_id) else {
        return (
            CertificateStatus::Invalid(format!(
                "store contract id is {} bytes, not 32",
                store_contract_id.len()
            )),
            None,
        );
    };
    let id = ContractInstanceId::new(bytes);

    // At the current generation the address pins only the key's CODE, so a
    // certificate for any key sharing it would pass the membership check
    // below. The store's owner is the key the contract verified everything
    // against, and it has to be this one. Superseded generations were
    // addressed by the whole key and carry no owner, so the address is the
    // whole check there.
    match current_store_id(&key) {
        Ok(current) if current == id => {
            return if owner == Some(&key) {
                (CertificateStatus::Verified, Some(key))
            } else {
                (
                    CertificateStatus::Invalid(
                        "genuine, but not the key this store belongs to".to_string(),
                    ),
                    None,
                )
            };
        }
        Ok(_) => {}
        Err(e) => return (CertificateStatus::Invalid(e), None),
    }
    match store_instance_ids(&key) {
        Ok(ids) if ids.contains(&id) => (CertificateStatus::Verified, Some(key)),
        // The attack this whole module is for: a genuine certificate, issued
        // to somebody else, pasted onto this store. The other explanation is
        // benign and is named too -- see the module docs.
        Ok(_) => (
            CertificateStatus::Invalid(
                "genuine, but not this store's identity; or this store was published by a \
                 newer build of Harvest than yours"
                    .to_string(),
            ),
            None,
        ),
        Err(e) => (CertificateStatus::Invalid(e), None),
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

    /// The verdict alone, since most tests here are about the verdict.
    /// `store_verifying_key`'s own tests use the pair.
    ///
    /// The store is taken to be owned by `owner`, which for a real store is
    /// the key in its state. Most tests pass the certificate's own key, as an
    /// honest seller's store would.
    fn verdict(
        pem: &str,
        store_contract_id: &[u8],
        owner: Option<&VerifyingKey>,
        master: &Option<VerifyingKey>,
    ) -> CertificateStatus {
        verify_store_certificate_against(pem, store_contract_id, owner, master).0
    }

    fn test_master() -> Option<VerifyingKey> {
        Some(authority().master.verifying_key())
    }

    /// The store id a seller holding `key` would publish at with this build.
    fn store_id_for(key: &VerifyingKey) -> Vec<u8> {
        store_instance_ids(key).expect("derive store ids")[0]
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn a_genuine_certificate_verifies_for_its_own_store() {
        let (key, pem) = issue_ghostkey();
        assert_eq!(
            verdict(&pem, &store_id_for(&key), Some(&key), &test_master()),
            CertificateStatus::Verified
        );
    }

    /// The attack the module exists for, and the one a chain-only check waves
    /// straight through. Certificates are public, so a scammer can always
    /// obtain a *genuine* one; what they cannot obtain is the private key
    /// behind it, and the store address is what ties the two together.
    ///
    /// Delete the `store_instance_ids` membership check in
    /// `verify_store_certificate_against` and this is the test that fails.
    #[test]
    fn a_valid_certificate_for_another_identity_does_not_authenticate_this_store() {
        let (victim_key, victim_pem) = issue_ghostkey();
        let (scammer_key, _scammer_pem) = issue_ghostkey();

        // The scammer's own store, carrying the victim's real certificate.
        let status = verdict(
            &victim_pem,
            &store_id_for(&scammer_key),
            Some(&scammer_key),
            &test_master(),
        );

        assert!(
            matches!(status, CertificateStatus::Invalid(_)),
            "a certificate issued to somebody else must not authenticate this store, got {status:?}"
        );
        // And the certificate itself is genuine -- the rejection is about
        // identity, not about the chain.
        assert_eq!(
            verdict(
                &victim_pem,
                &store_id_for(&victim_key),
                Some(&victim_key),
                &test_master()
            ),
            CertificateStatus::Verified,
            "the same certificate must still verify for the store it belongs to"
        );
    }

    /// A store published under a superseded contract build lives at a
    /// different address, and is not thereby fraudulent.
    #[test]
    fn a_certificate_verifies_at_a_superseded_generation() {
        let (key, pem) = issue_ghostkey();
        let ids = store_instance_ids(&key).expect("derive store ids");
        assert!(
            ids.len() > 1,
            "the store lineage should carry at least one superseded generation; \
             without one this test proves nothing"
        );
        for id in ids.iter().skip(1) {
            assert_eq!(
                // A superseded generation's state has no owner field.
                verdict(&pem, id.as_bytes(), None, &test_master()),
                CertificateStatus::Verified,
                "a store at a superseded generation must still verify"
            );
        }
    }

    /// The known limitation, pinned so it stays visible. A store at an
    /// address this build cannot derive -- a future contract generation --
    /// reads exactly like a stolen certificate, because in both cases no
    /// known code hash produces the id. See the module docs for what fixing
    /// it would take.
    #[test]
    fn a_store_at_an_unknown_contract_generation_cannot_be_verified() {
        let (key, pem) = issue_ghostkey();
        let params = crate::migrate::encode_params(&crate::migrate::store_params(&key))
            .expect("encode store parameters");
        // The seller's own key, under a code hash this build knows nothing of.
        let future = crate::migrate::current_id(&[0xAB; 32], &params);

        assert!(
            matches!(
                verdict(&pem, future.as_bytes(), Some(&key), &test_master()),
                CertificateStatus::Invalid(_)
            ),
            "a generation this build cannot derive cannot be verified either"
        );
    }

    /// A verified store yields the key its mailbox address is derived from.
    #[test]
    fn a_verified_store_yields_the_sellers_key() {
        let (key, pem) = issue_ghostkey();
        assert_eq!(
            store_verifying_key_against(&pem, &store_id_for(&key), Some(&key), &test_master()),
            Some(key),
            "a verified store must yield the key it is addressed by"
        );
    }

    /// **The one that matters.** A scammer's store carrying the victim's
    /// genuine certificate must yield no key at all.
    ///
    /// If it yielded the victim's key, a buyer messaging the scammer's store
    /// would derive the VICTIM's mailbox address and deposit their message
    /// there -- reporting a successful send, into a mailbox belonging to
    /// someone they were never talking to, while the scammer they actually
    /// contacted receives nothing.
    ///
    /// Mutated red by making `store_verifying_key_against` return
    /// `certified_key(pem, master).ok()`, i.e. trusting a certificate that
    /// merely parses and chains.
    #[test]
    fn a_stolen_certificate_yields_no_key_to_derive_a_mailbox_from() {
        let (victim_key, victim_pem) = issue_ghostkey();
        let (scammer_key, _) = issue_ghostkey();

        assert_eq!(
            store_verifying_key_against(
                &victim_pem,
                &store_id_for(&scammer_key),
                Some(&scammer_key),
                &test_master()
            ),
            None,
            "a certificate issued to somebody else must not name this store's mailbox"
        );
        // The same certificate on its OWN store still works, so the assertion
        // above is about identity rather than about a broken fixture.
        assert_eq!(
            store_verifying_key_against(
                &victim_pem,
                &store_id_for(&victim_key),
                Some(&victim_key),
                &test_master()
            ),
            Some(victim_key)
        );
    }

    /// A store with no certificate names no mailbox either. There is no
    /// weaker fallback: the address has to come from a key, and an
    /// unverified store supplies none.
    #[test]
    fn a_store_without_a_certificate_yields_no_key() {
        assert_eq!(
            store_verifying_key_against("", &[7u8; 32], None, &test_master()),
            None
        );
    }

    #[test]
    fn a_certificate_from_another_authority_is_rejected() {
        let (key, pem) = issue_ghostkey();
        let stranger = SigningKey::from_bytes(&[0x22; 32]).verifying_key();

        let status = verdict(&pem, &store_id_for(&key), Some(&key), &Some(stranger));
        assert!(
            matches!(status, CertificateStatus::Invalid(_)),
            "a chain to the wrong master key must not verify, got {status:?}"
        );
    }

    /// The production entry point uses Freenet's master key and nothing else.
    /// A locally minted chain is exactly what a forged one looks like, so it
    /// must fail here even though it passes with the test authority.
    #[test]
    fn the_production_check_uses_freenets_master_key() {
        let (key, pem) = issue_ghostkey();
        let id = store_id_for(&key);

        assert_eq!(
            verdict(&pem, &id, Some(&key), &test_master()),
            CertificateStatus::Verified,
            "the fixture must be a valid chain under its own authority"
        );
        assert!(
            matches!(
                verify_store_certificate(&pem, &id, Some(&key)),
                CertificateStatus::Invalid(_)
            ),
            "a certificate minted outside Freenet's PKI must not verify in production"
        );
    }

    #[test]
    fn text_that_is_not_a_certificate_is_rejected() {
        for pem in [
            "-----BEGIN CERT-----",
            "-----BEGIN GHOSTKEY CERTIFICATE-----rehearsal-----END-----",
            "not a certificate at all",
            "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nbm90IGNib3I=\n-----END GHOSTKEY_CERTIFICATE_V1-----\n",
        ] {
            assert!(
                matches!(
                    verdict(pem, &[7u8; 32], None, &test_master()),
                    CertificateStatus::Invalid(_)
                ),
                "{pem:?} is not a certificate and must not verify"
            );
        }
    }

    /// An unpublished certificate is its own outcome. Folding it into
    /// `Invalid` would tell a buyer a store is claiming a bond it does not
    /// have, when it is claiming nothing at all.
    #[test]
    fn an_absent_certificate_is_absent_rather_than_invalid() {
        for pem in ["", "   \n "] {
            assert_eq!(
                verdict(pem, &[7u8; 32], None, &test_master()),
                CertificateStatus::Absent
            );
        }
    }

    #[test]
    fn a_contract_id_of_the_wrong_length_does_not_verify() {
        let (_key, pem) = issue_ghostkey();
        assert!(matches!(
            verdict(&pem, &[1u8; 31], None, &test_master()),
            CertificateStatus::Invalid(_)
        ));
    }

    /// **harvest#52.** A store's address now pins only its owner's CODE, so
    /// a genuine certificate for a key sharing that code derives this very
    /// address. What it cannot do is be the store's owner: the contract
    /// verified every record against the key in the state, and that key is
    /// not this certificate's.
    ///
    /// Grinding a real sixteen-character collision is out of reach, so the
    /// shared code is modelled the other way round: the certificate's own
    /// store, whose state names a different owner.
    #[test]
    fn a_certificate_whose_key_is_not_the_stores_owner_does_not_verify() {
        let (key, pem) = issue_ghostkey();
        let (other, _) = issue_ghostkey();
        let id = store_id_for(&key);
        for owner in [Some(&other), None] {
            assert!(
                matches!(
                    verdict(&pem, &id, owner, &test_master()),
                    CertificateStatus::Invalid(_)
                ),
                "owner {owner:?} is not the certified key"
            );
            assert_eq!(
                store_verifying_key_against(&pem, &id, owner, &test_master()),
                None,
                "and no mailbox is derived from it"
            );
        }
        assert_eq!(
            verdict(&pem, &id, Some(&key), &test_master()),
            CertificateStatus::Verified,
            "the same certificate on the store it owns still verifies"
        );
    }
}
